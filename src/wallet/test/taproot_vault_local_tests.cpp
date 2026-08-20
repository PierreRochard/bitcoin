// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/multisig.h>
#include <wallet/wallet.h>

#include <test/util/setup_common.h>
#include <wallet/test/util.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(taproot_vault_local_tests, BasicTestingSetup)

using common::PSBTError;

//! All-local Taproot vault (bitcoin#24861) through CreateMultisigDescriptor:
//! n computer HD seeds, n-of-n MuSig2 key-path now, m-of-n after older(N).

static std::shared_ptr<CWallet> MakeWallet()
{
    auto wallet = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "vault_local", CreateMockableWalletDatabase()));
    wallet->m_keypool_size = 8;
    wallet->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
    return wallet;
}

static CExtKey RandomMaster()
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    return master;
}

static std::vector<uint32_t> Bip48TaprootPath()
{
    std::vector<uint32_t> path;
    BOOST_REQUIRE(ParseHDKeypath(DefaultMultisigPath(OutputType::BECH32M, /*account=*/0), path));
    return path;
}

static std::string PathStr()
{
    return WriteHDKeypath(Bip48TaprootPath());
}

static std::string MasterFpr(const CExtKey& master)
{
    const std::string hex = HexStr(master.id_key_fingerprint());
    return hex.size() == 8 ? hex : hex.substr(0, 8);
}

static CExtPubKey XpubAt(const CExtKey& master, const std::vector<uint32_t>& path)
{
    auto child = DeriveExtKey(master, path);
    BOOST_REQUIRE(child);
    return child->first.Neuter();
}

static void AddUnused(CWallet& wallet, const CExtKey& master)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::string unused = "unused(" + EncodeExtKey(master) + ")";
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(unused, keys, error, false);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), error);
    WalletDescriptor w(std::move(descs.at(0)), 1, 0, 0, 0);
    BOOST_REQUIRE(wallet.AddWalletDescriptor(w, keys, "", false));
}

static MultisigKeySpec LocalSpec(const CExtKey& master)
{
    MultisigKeySpec spec;
    spec.hdkey = EncodeExtPubKey(master.Neuter());
    spec.path = PathStr();
    spec.label = "computer";
    return spec;
}

static MultisigKeySpec XpubSpec(const CExtKey& master)
{
    MultisigKeySpec spec;
    spec.fingerprint = MasterFpr(master);
    spec.path = PathStr();
    spec.xpub = EncodeExtPubKey(XpubAt(master, Bip48TaprootPath()));
    spec.label = "lost-computer";
    return spec;
}

struct SignOut {
    std::optional<PSBTError> error;
    bool complete{false};
    bool input_signed{false};
    size_t witness_stack{0};
    size_t tap_key_sig{0};
    CMutableTransaction extracted;
};

static SignOut SignSpk(CWallet& wallet, const CScript& spk, uint32_t sequence)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CMutableTransaction prev_tx;
    prev_tx.version = 2;
    prev_tx.vin.emplace_back();
    prev_tx.vout.emplace_back(COIN, spk);

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{prev_tx.GetHash(), 0}, CScript(), sequence);
    tx.vout.emplace_back(COIN - 10000, spk);

    PartiallySignedTransaction psbt(tx, /*version=*/0);
    BOOST_REQUIRE_EQUAL(psbt.inputs.size(), 1U);
    psbt.inputs[0].non_witness_utxo = MakeTransactionRef(prev_tx);
    psbt.inputs[0].witness_utxo = CTxOut{COIN, spk};

    SignOut out;
    bool complete = false;
    BOOST_REQUIRE(!wallet.FillPSBT(psbt, {.sign = false, .bip32_derivs = true}, complete));
    out.error = wallet.FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete);
    out.complete = complete;
    out.input_signed = PSBTInputSigned(psbt.inputs[0]);
    out.tap_key_sig = psbt.inputs[0].m_tap_key_sig.size();
    if (complete || out.input_signed) {
        FinalizeAndExtractPSBT(psbt, out.extracted);
        if (!out.extracted.vin.empty()) {
            out.witness_stack = out.extracted.vin[0].scriptWitness.stack.size();
        }
    } else {
        out.witness_stack = psbt.inputs[0].final_script_witness.stack.size();
    }
    return out;
}

static void ExpectKeypath(const SignOut& out, const std::string& ctx)
{
    BOOST_REQUIRE_MESSAGE(!out.error, ctx + " unexpected FillPSBT error");
    BOOST_REQUIRE_MESSAGE(out.complete, ctx + " expected complete key-path");
    BOOST_CHECK_MESSAGE(out.input_signed, ctx);
    BOOST_CHECK_EQUAL(out.witness_stack, 1U);
}

static void ExpectScriptpath(const SignOut& out, const std::string& ctx)
{
    BOOST_REQUIRE_MESSAGE(!out.error, ctx + " unexpected FillPSBT error");
    BOOST_REQUIRE_MESSAGE(out.complete, ctx + " expected complete script-path");
    BOOST_CHECK_MESSAGE(out.input_signed, ctx);
    BOOST_CHECK_GT(out.witness_stack, 1U);
}

static void ExpectIncomplete(const SignOut& out, const std::string& ctx)
{
    BOOST_REQUIRE_MESSAGE(!out.error, ctx + " unexpected FillPSBT error");
    BOOST_CHECK_MESSAGE(!out.complete, ctx + " expected incomplete");
}

struct VaultWallets {
    std::shared_ptr<CWallet> full;
    std::shared_ptr<CWallet> recover;
    CScript spk;
    std::vector<std::string> descs;
};

static VaultWallets MakeVault(int m, int n, uint32_t older, const std::set<int>& recover_priv)
{
    BOOST_REQUIRE(n >= 2);
    BOOST_REQUIRE(m >= 1 && m <= n);
    const std::vector<uint32_t> path{Bip48TaprootPath()};
    std::vector<CExtKey> masters;
    masters.reserve(n);
    for (int i = 0; i < n; ++i) masters.push_back(RandomMaster());

    VaultWallets out;
    out.full = MakeWallet();
    out.recover = MakeWallet();

    std::vector<MultisigKeySpec> full_specs, rec_specs;
    {
        LOCK(out.full->cs_wallet);
        for (int i = 0; i < n; ++i) {
            AddUnused(*out.full, masters[i]);
            full_specs.push_back(LocalSpec(masters[i]));
        }
        auto created = CreateMultisigDescriptor(*out.full, m, full_specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, older});
        BOOST_REQUIRE_MESSAGE(created, strprintf("%d-of-%d create: %s", m, n, util::ErrorString(created).original));
        BOOST_REQUIRE_EQUAL(created->descs.size(), 2U);
        BOOST_CHECK(created->descs[0].find("tr(musig(") != std::string::npos);
        BOOST_CHECK(created->descs[0].find(strprintf("older(%u)", older)) != std::string::npos);
        BOOST_CHECK(created->descs[0].find(strprintf("multi_a(%d,", m)) != std::string::npos);
        out.descs = created->descs;
        const CTxDestination dest = *Assert(out.full->GetNewDestination(OutputType::BECH32M, ""));
        BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));
        out.spk = GetScriptForDestination(dest);
    }
    {
        LOCK(out.recover->cs_wallet);
        for (int i = 0; i < n; ++i) {
            if (recover_priv.count(i)) {
                AddUnused(*out.recover, masters[i]);
                rec_specs.push_back(LocalSpec(masters[i]));
            } else {
                rec_specs.push_back(XpubSpec(masters[i]));
            }
        }
        auto created = CreateMultisigDescriptor(*out.recover, m, rec_specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, older});
        BOOST_REQUIRE_MESSAGE(created, strprintf("%d-of-%d recover create: %s", m, n, util::ErrorString(created).original));
        const CTxDestination dest = *Assert(out.recover->GetNewDestination(OutputType::BECH32M, ""));
        BOOST_CHECK_MESSAGE(GetScriptForDestination(dest) == out.spk,
                            strprintf("%d-of-%d recovery wallet derived a different address", m, n));
    }
    return out;
}

static void CheckPolicy(int m, int n, uint32_t older)
{
    const std::string ctx = strprintf("%d-of-%d older(%u)", m, n, older);
    std::set<int> first_m;
    for (int i = 0; i < m; ++i) first_m.insert(i);
    auto vault = MakeVault(m, n, older, first_m);

    {
        LOCK(vault.full->cs_wallet);
        // Key-path does not need a relative lock. send() uses SEQUENCE_FINAL
        // (or RBF) even after the UTXO is old enough for recovery.
        ExpectKeypath(SignSpk(*vault.full, vault.spk, CTxIn::SEQUENCE_FINAL), ctx + " full MuSig2 key-path");
    }

    {
        LOCK(vault.recover->cs_wallet);
        if (m < n) {
            ExpectIncomplete(SignSpk(*vault.recover, vault.spk, CTxIn::SEQUENCE_FINAL), ctx + " recover too soon");
            ExpectScriptpath(SignSpk(*vault.recover, vault.spk, older), ctx + " recover script-path");
        } else {
            // m == n: every seed is still present, so MuSig2 key-path works.
            ExpectKeypath(SignSpk(*vault.recover, vault.spk, CTxIn::SEQUENCE_FINAL), ctx + " n-of-n recover key-path");
        }
    }

    if (m >= 2) {
        std::set<int> too_few;
        for (int i = 0; i < m - 1; ++i) too_few.insert(i);
        auto short_vault = MakeVault(m, n, older, too_few);
        LOCK(short_vault.recover->cs_wallet);
        ExpectIncomplete(SignSpk(*short_vault.recover, short_vault.spk, older), ctx + " m-1 keys after delay");
    }

    if (m < n && n >= 3 && m >= 2) {
        std::set<int> last_m;
        for (int i = n - m; i < n; ++i) last_m.insert(i);
        auto alt = MakeVault(m, n, older, last_m);
        LOCK(alt.recover->cs_wallet);
        ExpectIncomplete(SignSpk(*alt.recover, alt.spk, CTxIn::SEQUENCE_FINAL), ctx + " last-m too soon");
        ExpectScriptpath(SignSpk(*alt.recover, alt.spk, older), ctx + " last-m script-path");
    }
}

BOOST_AUTO_TEST_CASE(create_rejects_bad_fallback)
{
    auto wallet = MakeWallet();
    CExtKey a = RandomMaster(), b = RandomMaster();
    LOCK(wallet->cs_wallet);
    AddUnused(*wallet, a);
    AddUnused(*wallet, b);
    std::vector<MultisigKeySpec> specs{LocalSpec(a), LocalSpec(b)};
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32, 0, {}, 1}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 0}));
}

BOOST_AUTO_TEST_CASE(all_local_vault_matrix_older_1)
{
    const std::pair<int, int> policies[] = {
        {1, 2}, {2, 2},
        {1, 3}, {2, 3}, {3, 3},
        {1, 4}, {2, 4}, {3, 4}, {4, 4},
    };
    for (const auto& [m, n] : policies) {
        CheckPolicy(m, n, /*older=*/1);
    }
}

BOOST_AUTO_TEST_CASE(all_local_vault_2of3_older_144)
{
    CheckPolicy(/*m=*/2, /*n=*/3, /*older=*/144);
    auto vault = MakeVault(2, 3, 144, {0, 1});
    LOCK(vault.recover->cs_wallet);
    ExpectIncomplete(SignSpk(*vault.recover, vault.spk, 143), "2-of-3 older(144) with nSequence=143");
    ExpectScriptpath(SignSpk(*vault.recover, vault.spk, 144), "2-of-3 older(144) with nSequence=144");
}

BOOST_AUTO_TEST_CASE(split_wallets_vault_keypath)
{
    // Three computers, one seed each: n-of-n MuSig2 key-path of a 2-of-3 vault.
    constexpr int n = 3;
    constexpr int m = 2;
    constexpr uint32_t older = 1;
    std::vector<CExtKey> masters{RandomMaster(), RandomMaster(), RandomMaster()};
    std::vector<std::shared_ptr<CWallet>> wallets;
    CScript spk;
    for (int i = 0; i < n; ++i) {
        auto w = MakeWallet();
        LOCK(w->cs_wallet);
        std::vector<MultisigKeySpec> specs;
        for (int j = 0; j < n; ++j) {
            if (j == i) {
                AddUnused(*w, masters[j]);
                specs.push_back(LocalSpec(masters[j]));
            } else {
                specs.push_back(XpubSpec(masters[j]));
            }
        }
        auto created = CreateMultisigDescriptor(*w, m, specs, MultisigOptions{OutputType::BECH32M, 0, {}, older});
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        const CTxDestination dest = *Assert(w->GetNewDestination(OutputType::BECH32M, ""));
        if (spk.empty()) spk = GetScriptForDestination(dest);
        else BOOST_CHECK(GetScriptForDestination(dest) == spk);
        wallets.push_back(std::move(w));
    }

    CMutableTransaction prev_tx;
    prev_tx.version = 2;
    prev_tx.vin.emplace_back();
    prev_tx.vout.emplace_back(COIN, spk);
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{prev_tx.GetHash(), 0});
    tx.vout.emplace_back(COIN - 10000, spk);
    PartiallySignedTransaction unsigned_psbt(tx, /*version=*/0);
    unsigned_psbt.inputs[0].non_witness_utxo = MakeTransactionRef(prev_tx);
    unsigned_psbt.inputs[0].witness_utxo = CTxOut{COIN, spk};
    {
        bool complete = false;
        LOCK(wallets[0]->cs_wallet);
        BOOST_REQUIRE(!wallets[0]->FillPSBT(unsigned_psbt, {.sign = false, .bip32_derivs = true}, complete));
    }

    std::vector<PartiallySignedTransaction> nonce_psbts;
    for (auto& w : wallets) {
        auto psbt = unsigned_psbt;
        bool complete = false;
        LOCK(w->cs_wallet);
        BOOST_REQUIRE(!w->FillPSBT(psbt, {.sign = true, .finalize = false, .bip32_derivs = false}, complete));
        BOOST_CHECK(!complete);
        nonce_psbts.push_back(std::move(psbt));
    }
    auto all_nonces = CombinePSBTs(nonce_psbts);
    BOOST_REQUIRE(all_nonces);

    std::vector<PartiallySignedTransaction> partials;
    for (auto& w : wallets) {
        auto psbt = *all_nonces;
        bool complete = false;
        LOCK(w->cs_wallet);
        BOOST_REQUIRE(!w->FillPSBT(psbt, {.sign = true, .finalize = false, .bip32_derivs = false}, complete));
        partials.push_back(std::move(psbt));
    }
    auto combined = CombinePSBTs(partials);
    BOOST_REQUIRE(combined);
    BOOST_CHECK(FinalizePSBT(*combined));
    CMutableTransaction mtx;
    BOOST_CHECK(FinalizeAndExtractPSBT(*combined, mtx));
    BOOST_CHECK_EQUAL(mtx.vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(split_wallets_vault_recovery)
{
    // Two computers hold seeds; the third is xpub-only. After older(1), 2-of-3 spends.
    std::vector<CExtKey> masters{RandomMaster(), RandomMaster(), RandomMaster()};
    std::vector<std::shared_ptr<CWallet>> wallets;
    CScript spk;
    for (int i = 0; i < 2; ++i) {
        auto w = MakeWallet();
        LOCK(w->cs_wallet);
        std::vector<MultisigKeySpec> specs;
        for (int j = 0; j < 3; ++j) {
            if (j == i) {
                AddUnused(*w, masters[j]);
                specs.push_back(LocalSpec(masters[j]));
            } else {
                specs.push_back(XpubSpec(masters[j]));
            }
        }
        auto created = CreateMultisigDescriptor(*w, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 1});
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        const CTxDestination dest = *Assert(w->GetNewDestination(OutputType::BECH32M, ""));
        if (spk.empty()) spk = GetScriptForDestination(dest);
        else BOOST_CHECK(GetScriptForDestination(dest) == spk);
        wallets.push_back(std::move(w));
    }

    CMutableTransaction prev_tx;
    prev_tx.version = 2;
    prev_tx.vin.emplace_back();
    prev_tx.vout.emplace_back(COIN, spk);
    auto make_psbt = [&](uint32_t sequence) {
        CMutableTransaction tx;
        tx.version = 2;
        tx.vin.emplace_back(COutPoint{prev_tx.GetHash(), 0}, CScript(), sequence);
        tx.vout.emplace_back(COIN - 10000, spk);
        PartiallySignedTransaction psbt(tx, /*version=*/0);
        psbt.inputs[0].non_witness_utxo = MakeTransactionRef(prev_tx);
        psbt.inputs[0].witness_utxo = CTxOut{COIN, spk};
        bool complete = false;
        LOCK(wallets[0]->cs_wallet);
        BOOST_REQUIRE(!wallets[0]->FillPSBT(psbt, {.sign = false, .bip32_derivs = true}, complete));
        return psbt;
    };

    {
        auto too_soon = make_psbt(CTxIn::SEQUENCE_FINAL);
        std::vector<PartiallySignedTransaction> parts;
        for (auto& w : wallets) {
            auto psbt = too_soon;
            bool complete = false;
            LOCK(w->cs_wallet);
            BOOST_REQUIRE(!w->FillPSBT(psbt, {.sign = true, .finalize = false, .bip32_derivs = false}, complete));
            parts.push_back(std::move(psbt));
        }
        auto combined = CombinePSBTs(parts);
        BOOST_REQUIRE(combined);
        BOOST_CHECK(!FinalizePSBT(*combined));
    }

    auto ready = make_psbt(/*older=*/1);
    std::vector<PartiallySignedTransaction> parts;
    for (auto& w : wallets) {
        auto psbt = ready;
        bool complete = false;
        LOCK(w->cs_wallet);
        BOOST_REQUIRE(!w->FillPSBT(psbt, {.sign = true, .finalize = false, .bip32_derivs = false}, complete));
        parts.push_back(std::move(psbt));
    }
    auto combined = CombinePSBTs(parts);
    BOOST_REQUIRE(combined);
    BOOST_CHECK(FinalizePSBT(*combined));
    CMutableTransaction mtx;
    BOOST_CHECK(FinalizeAndExtractPSBT(*combined, mtx));
    BOOST_CHECK_GT(mtx.vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
