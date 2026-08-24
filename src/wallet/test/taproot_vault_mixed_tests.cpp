// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <common/args.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <hwi/mock.h>
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

#include <array>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(taproot_vault_mixed_tests, BasicTestingSetup)

using common::PSBTError;

//! Same Scrooge vault matrix as taproot_vault_local_tests, but key 0 is a
//! computer HD seed and keys 1…n-1 are C++ mock hardware wallets.

static std::shared_ptr<CWallet> MakeMixedWallet()
{
    auto wallet = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "vault_mixed", CreateMockableWalletDatabase()));
    wallet->m_keypool_size = 8;
    wallet->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_EXTERNAL_SIGNER | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
    return wallet;
}

static CExtKey RandomMaster()
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    return master;
}

static CExtKey UniqueMockMaster()
{
    static int next = 1;
    const int n = next++;
    std::array<std::byte, 16> seed{};
    seed[12] = std::byte((n >> 24) & 0xff);
    seed[13] = std::byte((n >> 16) & 0xff);
    seed[14] = std::byte((n >> 8) & 0xff);
    seed[15] = std::byte(n & 0xff);
    return hwi::MakeMockMaster(seed);
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
    spec.label = "this-computer";
    return spec;
}

static MultisigKeySpec HwSpec(const hwi::MockRegistration& mock)
{
    MultisigKeySpec spec;
    spec.fingerprint = mock.Fingerprint();
    spec.path = PathStr();
    spec.label = "mock-hww";
    return spec;
}

static MultisigKeySpec XpubSpec(const CExtKey& master)
{
    MultisigKeySpec spec;
    spec.fingerprint = MasterFpr(master);
    spec.path = PathStr();
    spec.xpub = EncodeExtPubKey(XpubAt(master, Bip48TaprootPath()));
    spec.label = "offline";
    return spec;
}

struct SignOut {
    std::optional<PSBTError> error;
    bool complete{false};
    bool input_signed{false};
    size_t witness_stack{0};
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
    BOOST_REQUIRE_MESSAGE(!out.error, ctx + strprintf(" unexpected FillPSBT error %d", out.error ? static_cast<int>(*out.error) : -1));
    BOOST_REQUIRE_MESSAGE(out.complete, ctx + " expected complete key-path");
    BOOST_CHECK_MESSAGE(out.input_signed, ctx);
    BOOST_CHECK_EQUAL(out.witness_stack, 1U);
}

static void ExpectScriptpath(const SignOut& out, const std::string& ctx)
{
    BOOST_REQUIRE_MESSAGE(!out.error, ctx + strprintf(" unexpected FillPSBT error %d", out.error ? static_cast<int>(*out.error) : -1));
    BOOST_REQUIRE_MESSAGE(out.complete, ctx + " expected complete script-path");
    BOOST_CHECK_MESSAGE(out.input_signed, ctx);
    BOOST_CHECK_GT(out.witness_stack, 1U);
}

static void ExpectIncomplete(const SignOut& out, const std::string& ctx)
{
    if (out.error) {
        BOOST_CHECK_MESSAGE(*out.error == PSBTError::EXTERNAL_SIGNER_NOT_FOUND ||
                                *out.error == PSBTError::INCOMPLETE,
                            ctx + strprintf(" unexpected error %d", static_cast<int>(*out.error)));
    }
    BOOST_CHECK_MESSAGE(!out.complete, ctx + " expected incomplete");
}

struct MixedVault {
    std::shared_ptr<CWallet> full;
    std::shared_ptr<CWallet> recover;
    CScript spk;
    std::vector<std::unique_ptr<hwi::MockRegistration>> mocks;
};

//! n keys: index 0 is local, 1…n-1 are mock hardware. recover_priv is the
//! subset that still has a signing secret (local xprv and/or plugged-in mock).
static MixedVault MakeVault(int m, int n, uint32_t older, const std::set<int>& recover_priv)
{
    BOOST_REQUIRE(n >= 2);
    BOOST_REQUIRE(m >= 1 && m <= n);
    gArgs.ForceSetArg("-signer", "internal");

    CExtKey local = RandomMaster();
    std::vector<CExtKey> hw_masters;
    MixedVault out;
    hw_masters.reserve(n - 1);
    for (int i = 1; i < n; ++i) {
        hw_masters.push_back(UniqueMockMaster());
        out.mocks.push_back(std::make_unique<hwi::MockRegistration>(hw_masters.back()));
    }

    auto spec_at = [&](int i, bool want_priv) {
        if (i == 0) return want_priv ? LocalSpec(local) : XpubSpec(local);
        const int hi = i - 1;
        return want_priv ? HwSpec(*out.mocks[hi]) : XpubSpec(hw_masters[hi]);
    };

    out.full = MakeMixedWallet();
    {
        LOCK(out.full->cs_wallet);
        AddUnused(*out.full, local);
        std::vector<MultisigKeySpec> specs;
        specs.push_back(LocalSpec(local));
        for (int i = 1; i < n; ++i) specs.push_back(HwSpec(*out.mocks[i - 1]));
        auto created = CreateMultisigDescriptor(*out.full, m, specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, older});
        BOOST_REQUIRE_MESSAGE(created, strprintf("mixed %d-of-%d create: %s", m, n, util::ErrorString(created).original));
        BOOST_CHECK(created->descs[0].find("tr(musig(") != std::string::npos);
        BOOST_CHECK(created->descs[0].find(strprintf("older(%u)", older)) != std::string::npos);
        BOOST_CHECK(created->descs[0].find(strprintf("multi_a(%d,", m)) != std::string::npos);
        const CTxDestination dest = *Assert(out.full->GetNewDestination(OutputType::BECH32M, ""));
        BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));
        out.spk = GetScriptForDestination(dest);
    }

    out.recover = MakeMixedWallet();
    {
        LOCK(out.recover->cs_wallet);
        std::vector<MultisigKeySpec> specs;
        for (int i = 0; i < n; ++i) {
            const bool keep = recover_priv.count(i) > 0;
            if (i == 0 && keep) AddUnused(*out.recover, local);
            specs.push_back(spec_at(i, keep));
        }
        auto created = CreateMultisigDescriptor(*out.recover, m, specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, older});
        BOOST_REQUIRE_MESSAGE(created, strprintf("mixed %d-of-%d recover create: %s", m, n, util::ErrorString(created).original));
        const CTxDestination dest = *Assert(out.recover->GetNewDestination(OutputType::BECH32M, ""));
        BOOST_CHECK_MESSAGE(GetScriptForDestination(dest) == out.spk,
                            strprintf("mixed %d-of-%d recovery address mismatch", m, n));
    }
    return out;
}

//! Lost hardware must be unplugged. A still-registered mock will SignTx even
//! if the recovery wallet only imported its xpub.
static void UnplugLost(MixedVault& vault, int n, const std::set<int>& recover_priv)
{
    for (int i = 1; i < n; ++i) {
        if (!recover_priv.count(i)) vault.mocks[i - 1].reset();
    }
}

static void CheckPolicy(int m, int n, uint32_t older)
{
    const std::string ctx = strprintf("mixed %d-of-%d older(%u)", m, n, older);
    std::set<int> first_m;
    for (int i = 0; i < m; ++i) first_m.insert(i);
    auto vault = MakeVault(m, n, older, first_m);

    {
        LOCK(vault.full->cs_wallet);
        ExpectKeypath(SignSpk(*vault.full, vault.spk, CTxIn::SEQUENCE_FINAL), ctx + " full MuSig2 key-path");
    }
    UnplugLost(vault, n, first_m);

    {
        LOCK(vault.recover->cs_wallet);
        if (m < n) {
            ExpectIncomplete(SignSpk(*vault.recover, vault.spk, CTxIn::SEQUENCE_FINAL), ctx + " recover too soon");
            ExpectScriptpath(SignSpk(*vault.recover, vault.spk, older), ctx + " recover script-path");
        } else {
            ExpectKeypath(SignSpk(*vault.recover, vault.spk, CTxIn::SEQUENCE_FINAL), ctx + " n-of-n recover key-path");
        }
    }

    if (m >= 2) {
        std::set<int> too_few;
        for (int i = 0; i < m - 1; ++i) too_few.insert(i);
        auto short_vault = MakeVault(m, n, older, too_few);
        UnplugLost(short_vault, n, too_few);
        LOCK(short_vault.recover->cs_wallet);
        ExpectIncomplete(SignSpk(*short_vault.recover, short_vault.spk, older), ctx + " m-1 keys after delay");
    }

    if (m < n && n >= 3 && m >= 2) {
        std::set<int> last_m;
        for (int i = n - m; i < n; ++i) last_m.insert(i);
        auto alt = MakeVault(m, n, older, last_m);
        UnplugLost(alt, n, last_m);
        LOCK(alt.recover->cs_wallet);
        ExpectIncomplete(SignSpk(*alt.recover, alt.spk, CTxIn::SEQUENCE_FINAL), ctx + " last-m too soon");
        ExpectScriptpath(SignSpk(*alt.recover, alt.spk, older), ctx + " last-m script-path");
    }
}

BOOST_AUTO_TEST_CASE(mixed_vault_matrix_older_1)
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

BOOST_AUTO_TEST_CASE(mixed_vault_2of3_older_144)
{
    CheckPolicy(/*m=*/2, /*n=*/3, /*older=*/144);
    auto vault = MakeVault(2, 3, 144, {0, 1});
    UnplugLost(vault, 3, {0, 1});
    LOCK(vault.recover->cs_wallet);
    ExpectIncomplete(SignSpk(*vault.recover, vault.spk, 143), "mixed 2-of-3 older(144) nSequence=143");
    ExpectScriptpath(SignSpk(*vault.recover, vault.spk, 144), "mixed 2-of-3 older(144) nSequence=144");
}

BOOST_AUTO_TEST_CASE(mixed_vault_unplug_blocks_keypath)
{
    gArgs.ForceSetArg("-signer", "internal");
    auto vault = MakeVault(2, 3, /*older=*/1, {0, 1, 2});
    BOOST_REQUIRE_EQUAL(vault.mocks.size(), 2U);
    vault.mocks.back().reset();
    LOCK(vault.full->cs_wallet);
    ExpectIncomplete(SignSpk(*vault.full, vault.spk, CTxIn::SEQUENCE_FINAL), "unplugged mock blocks n-of-n key-path");
}

BOOST_AUTO_TEST_CASE(fixed_vault_native_default_signs_without_signer_option)
{
    BOOST_REQUIRE(!gArgs.IsArgSet("-signer"));
    const CExtKey local{RandomMaster()};
    const CExtKey hardware_a{UniqueMockMaster()};
    const CExtKey hardware_b{UniqueMockMaster()};
    hwi::MockRegistration mock_a{hardware_a};
    hwi::MockRegistration mock_b{hardware_b};
    auto wallet{MakeMixedWallet()};

    CScript spk;
    {
        LOCK(wallet->cs_wallet);
        AddUnused(*wallet, local);
        std::vector<MultisigKeySpec> specs{
            LocalSpec(local),
            XpubSpec(hardware_a),
            XpubSpec(hardware_b),
        };
        MultisigOptions options;
        options.type = OutputType::BECH32M;
        options.fallback_older = 4320;
        options.fallback_older_one_key = 8640;
        auto created{CreateMultisigDescriptor(*wallet, /*nrequired=*/2, specs, options)};
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        BOOST_REQUIRE(IsFixedStagedVault(*wallet));
        const CTxDestination dest{*Assert(wallet->GetNewDestination(OutputType::BECH32M, ""))};
        spk = GetScriptForDestination(dest);
        ExpectKeypath(SignSpk(*wallet, spk, CTxIn::SEQUENCE_FINAL), "fixed native-default key-path");
    }

    // An explicitly empty option is a deliberate disable, never an implicit
    // request to fall back to native hardware discovery.
    gArgs.ForceSetArg("-signer", "");
    LOCK(wallet->cs_wallet);
    ExpectIncomplete(SignSpk(*wallet, spk, CTxIn::SEQUENCE_FINAL), "explicitly disabled native signer");
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
