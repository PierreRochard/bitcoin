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
#include <util/rbf.h>
#include <wallet/coincontrol.h>
#include <wallet/multisig.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <test/util/setup_common.h>
#include <wallet/test/util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(taproot_vault_local_tests, BasicTestingSetup)

using common::PSBTError;

//! All-local Scrooge vault (bitcoin#24861) through CreateMultisigDescriptor:
//! n computer HD seeds, n-of-n MuSig2 key-path now, m-of-n after older(N).

static std::shared_ptr<CWallet> MakeWallet(uint64_t extra_flags = 0)
{
    auto wallet = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "vault_local", CreateMockableWalletDatabase()));
    wallet->m_keypool_size = 8;
    wallet->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED | extra_flags);
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

static VaultWallets MakeVault(int m, int n, uint32_t older, const std::set<int>& recover_priv,
                              std::optional<uint32_t> fallback_older_one_key = {})
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
                                                MultisigOptions{OutputType::BECH32M, 0, {}, older, {}, fallback_older_one_key});
        BOOST_REQUIRE_MESSAGE(created, strprintf("%d-of-%d create: %s", m, n, util::ErrorString(created).original));
        BOOST_REQUIRE_EQUAL(created->descs.size(), 2U);
        BOOST_CHECK(created->descs[0].find("tr(musig(") != std::string::npos);
        BOOST_CHECK(created->descs[0].find(strprintf("older(%u)", older)) != std::string::npos);
        BOOST_CHECK(created->descs[0].find(strprintf("multi_a(%d,", m)) != std::string::npos);
        if (fallback_older_one_key) {
            BOOST_CHECK(created->descs[0].find(strprintf("older(%u)", *fallback_older_one_key)) != std::string::npos);
            BOOST_CHECK(created->descs[0].find("multi_a(1,") != std::string::npos);
        }
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
                                                MultisigOptions{OutputType::BECH32M, 0, {}, older, {}, fallback_older_one_key});
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
        // Key-path does not need a relative lock. send() uses RBF nSequence
        // (MAX_BIP125_RBF_SEQUENCE) even after the UTXO is old enough for recovery.
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
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::UNKNOWN}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32, 0, {}, 1}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 0}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, /*fallback_older=*/1, /*fallback_after=*/50}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, {}, uint32_t{0}}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 1u << 31}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 65536}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, {}, {}, 4}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 2, {}, 2}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 2, {}, 65536}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 1, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 2, {}, 4}));
    auto heir = LocalSpec(a);
    heir.recovery_only = true;
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 1, {LocalSpec(a), heir}, MultisigOptions{OutputType::BECH32M}));
    auto bad_path = LocalSpec(a);
    bad_path.path = "not-a-path";
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, {bad_path, LocalSpec(b)}, MultisigOptions{OutputType::BECH32M, 0, {}, 1}));
    auto air = XpubSpec(b);
    air.fingerprint.reset();
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, {LocalSpec(a), air}, MultisigOptions{OutputType::BECH32M, 0, {}, 1}));
    auto soft = LocalSpec(a);
    soft.path = "m/48/0/0/3";
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, {soft, LocalSpec(b)}, MultisigOptions{OutputType::BECH32M, 0, {}, 1}));
    auto recv_only = MakeWallet();
    LOCK(recv_only->cs_wallet);
    AddUnused(*recv_only, a);
    AddUnused(*recv_only, b);
    auto recv = CreateMultisigDescriptor(*recv_only, 1, {LocalSpec(a), LocalSpec(b)},
                                         MultisigOptions{OutputType::BECH32M, 0, /*internal_only=*/false, 1});
    BOOST_REQUIRE_MESSAGE(recv, util::ErrorString(recv).original);
    BOOST_CHECK_EQUAL(recv->descs.size(), 1U);
    auto watch = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "vault_wo", CreateMockableWalletDatabase()));
    watch->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
    LOCK(watch->cs_wallet);
    BOOST_CHECK(!CreateMultisigDescriptor(*watch, 2, {LocalSpec(a), LocalSpec(b)}, MultisigOptions{OutputType::BECH32M, 0, {}, 1}));
    auto xpubs = CreateMultisigDescriptor(*watch, 1, {XpubSpec(a), XpubSpec(b)}, MultisigOptions{OutputType::BECH32M, 0, {}, 1});
    BOOST_REQUIRE_MESSAGE(xpubs, util::ErrorString(xpubs).original);
    BOOST_CHECK(!ValidateMultisigPolicy(2, 2, OutputType::BECH32M, /*fallback_older=*/1, /*fallback_after=*/1).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(1, 0).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(0, 2).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(1, 1, OutputType::BECH32M, /*fallback_older=*/1).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(1, 1, OutputType::BECH32M, {}, /*fallback_after=*/10).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(2, 2, OutputType::BECH32M, 2, {}, 2, /*fallback_older_one_key=*/2).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(2, 2, OutputType::BECH32M, {}, {}, 2, /*fallback_older_one_key=*/4).empty());
    BOOST_CHECK(WrapSortedMulti(OutputType::UNKNOWN, 1, {"x"}).empty());
    BOOST_CHECK(WrapSortedMulti(OutputType::BECH32M, 1, {}).empty());
    BOOST_CHECK(WrapSortedMulti(OutputType::BECH32M, 1, {"a", "b"}, /*fallback_older=*/1, /*fallback_after=*/2).empty());
    BOOST_CHECK(WrapSortedMulti(OutputType::BECH32M, 1, {"only"}, /*fallback_older=*/1).empty());
    BOOST_CHECK(WrapSortedMulti(OutputType::BECH32M, 2, {"a", "b"}, /*fallback_older=*/65536).empty());
    BOOST_CHECK(WrapSortedMulti(OutputType::BECH32M, 2, {"a", "b"}, 2, {}, {}, /*fallback_older_one_key=*/65536).empty());
    BOOST_CHECK_EQUAL(WrapSortedMulti(OutputType::LEGACY, 1, {"k"}), "sh(sortedmulti(1,k))");
    BOOST_CHECK_EQUAL(WrapSortedMulti(OutputType::P2SH_SEGWIT, 1, {"k"}), "sh(wsh(sortedmulti(1,k)))");
    BOOST_CHECK_EQUAL(WrapSortedMulti(OutputType::BECH32, 2, {"a", "b"}), "wsh(sortedmulti(2,a,b))");
    const auto rec_wrap = WrapSortedMulti(OutputType::BECH32M, 1, {"act1", "act2"}, /*fallback_older=*/6, {}, {"act1", "act2", "heir"});
    BOOST_CHECK(rec_wrap.find("musig(act1,act2)") != std::string::npos);
    BOOST_CHECK(rec_wrap.find("older(6)") != std::string::npos);
    BOOST_CHECK(rec_wrap.find("multi_a(1,act1,act2,heir)") != std::string::npos);
    const auto staged_wrap = WrapSortedMulti(OutputType::BECH32M, 2, {"act1", "act2"}, 2, {}, {"act1", "act2", "heir"}, 4);
    BOOST_CHECK_EQUAL(staged_wrap,
        "tr(musig(act1,act2),{and_v(v:older(2),multi_a(2,act1,act2,heir)),and_v(v:older(4),multi_a(1,act1,act2,heir))})");
    BOOST_CHECK_EQUAL(DefaultMultisigPath(OutputType::LEGACY, 0), "m/48h/0h/0h/0h");
    BOOST_CHECK_EQUAL(DefaultMultisigPath(OutputType::P2SH_SEGWIT, 0), "m/48h/0h/0h/1h");
    BOOST_CHECK_EQUAL(DefaultMultisigPath(OutputType::UNKNOWN, 0), "m/48h/0h/0h/2h");
}

BOOST_AUTO_TEST_CASE(vault_infer_and_duplicate_edges)
{
    BOOST_CHECK(!InferVaultPolicy("tr(musig(a,b)/<0;1>/*)").is_vault);
    BOOST_CHECK(!InferVaultPolicy("tr(musig(a,b),and_v(v:older(0),multi_a(1,a,b)))").older);
    BOOST_CHECK(!InferVaultPolicy("tr(musig(a,b),and_v(v:after(2147483648),multi_a(1,a,b)))").after);
    BOOST_CHECK(!InferVaultPolicy("tr(musig(a,b),and_v(v:older(").older);
    BOOST_CHECK(!InferVaultPolicy("wsh(sortedmulti(2,a,b))").is_vault);
    BOOST_CHECK(!InferVaultPolicy("tr(pk(a),and_v(v:older(1),multi_a(1,a)))").is_vault);
    BOOST_CHECK(!InferVaultPolicy("tr(musig(a,b),and_v(v:after(10),pk(a)))").is_vault);
    BOOST_CHECK(!InferVaultPolicy("tr(musig(a,b),and_v(v:after(),multi_a(1,a,b)))").after);

    InferredVaultPolicy unlocked;
    unlocked.is_vault = true;
    BOOST_CHECK(IsVaultUtxoMature(unlocked, /*depth=*/0, /*tip=*/0));

    std::vector<MultisigKeySpec> same_xpub(2);
    same_xpub[0].xpub = "tpub1";
    same_xpub[1].xpub = "tpub1";
    BOOST_CHECK(!DuplicateSignerWarning(same_xpub).empty());
    same_xpub[1].xpub = "tpub2";
    BOOST_CHECK(DuplicateSignerWarning(same_xpub).empty());
    BOOST_CHECK(DuplicateSignerWarning({}).empty());
    BOOST_CHECK(DuplicateSignerWarning({same_xpub[0]}).empty());

    auto plain = MakeWallet();
    LOCK(plain->cs_wallet);
    CCoinControl cc;
    BOOST_REQUIRE(ApplyVaultRecoveryToCoinControl(*plain, cc));
    BOOST_CHECK(!ApplyVaultRecoveryToCoinControl(*plain, cc, 4));
    BOOST_CHECK(!cc.m_nSequence);
    BOOST_CHECK(!cc.m_locktime);
    BOOST_CHECK(!cc.m_script_path);
    BOOST_CHECK(!InferWalletVaultPolicy(*plain).is_vault);
}

BOOST_AUTO_TEST_CASE(generated_local_keys_are_distinct_and_spend)
{
    auto wallet = MakeWallet(WALLET_FLAG_BLANK_WALLET);
    LOCK(wallet->cs_wallet);
    BOOST_REQUIRE(wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));

    std::vector<MultisigKeySpec> specs(3);
    for (size_t i = 0; i < specs.size(); ++i) {
        specs[i].generate_local = true;
        specs[i].label = strprintf("computer-%u", i + 1);
    }
    auto created = CreateMultisigDescriptor(*wallet, /*nrequired=*/2, specs,
                                            MultisigOptions{OutputType::BECH32M, 0, {}, /*fallback_older=*/2, {}, {}});
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_REQUIRE_EQUAL(created->recovery.size(), 3U);
    std::set<std::string> unique_xpubs;
    for (const GeneratedMnemonic& record : created->recovery) {
        BOOST_CHECK(unique_xpubs.insert(record.xpub).second);
    }

    BOOST_REQUIRE_EQUAL(created->descs.size(), 2U);
    BOOST_CHECK(created->descs[0] != created->descs[1]);
    for (const std::string& desc : created->descs) {
        BOOST_CHECK(desc.find("xprv") == std::string::npos);
        BOOST_CHECK(desc.find("tprv") == std::string::npos);

        FlatSigningProvider public_keys;
        std::string error;
        auto parsed = Parse(desc, public_keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
        BOOST_CHECK(public_keys.keys.empty());
        std::string private_desc;
        BOOST_CHECK(!parsed.front()->ToPrivateString(public_keys, private_desc));
    }

    FlatSigningProvider parsed_keys;
    std::string parse_error;
    auto parsed = Parse(created->descs.front(), parsed_keys, parse_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), parse_error);
    std::vector<CScript> scripts;
    FlatSigningProvider expanded_keys;
    BOOST_REQUIRE(parsed.front()->Expand(/*pos=*/0, parsed_keys, scripts, expanded_keys));
    BOOST_REQUIRE_EQUAL(expanded_keys.aggregate_pubkeys.size(), 1U);
    const auto& participants = expanded_keys.aggregate_pubkeys.begin()->second;
    BOOST_REQUIRE_EQUAL(participants.size(), 3U);
    const std::set<CPubKey> unique_participants{participants.begin(), participants.end()};
    BOOST_CHECK_EQUAL(unique_participants.size(), participants.size());

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::BECH32M, ""));
    ExpectKeypath(SignSpk(*wallet, GetScriptForDestination(dest), CTxIn::SEQUENCE_FINAL),
                  "three generated local keys");
}

BOOST_AUTO_TEST_CASE(generated_local_rejects_conflicts_and_duplicate_explicit_key)
{
    auto conflict_wallet = MakeWallet(WALLET_FLAG_BLANK_WALLET);
    LOCK(conflict_wallet->cs_wallet);

    std::vector<MultisigKeySpec> conflicts(3);
    for (auto& spec : conflicts) spec.generate_local = true;
    conflicts[0].fingerprint = "aabbccdd";
    conflicts[1].hdkey = "not-an-hd-key";
    conflicts[2].xpub = "not-an-xpub";
    for (const auto& spec : conflicts) {
        auto rejected = CreateMultisigDescriptor(*conflict_wallet, /*nrequired=*/1, {spec},
                                                 MultisigOptions{OutputType::BECH32, 0, {}, {}, {}, {}});
        BOOST_REQUIRE(!rejected);
        BOOST_CHECK_EQUAL(util::ErrorString(rejected).original,
                          "A mnemonic local key cannot also specify another key source");
    }
    BOOST_CHECK(conflict_wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    BOOST_CHECK(conflict_wallet->GetActiveScriptPubKeyMans().empty());

    auto duplicate_wallet = MakeWallet(WALLET_FLAG_BLANK_WALLET);
    LOCK(duplicate_wallet->cs_wallet);
    MultisigKeySpec duplicate;
    duplicate.path = PathStr();
    duplicate.hdkey = EncodeExtKey(RandomMaster());
    auto rejected = CreateMultisigDescriptor(*duplicate_wallet, /*nrequired=*/2, {duplicate, duplicate},
                                             MultisigOptions{OutputType::BECH32M, 0, {}, {}, {}, {}});
    BOOST_REQUIRE(!rejected);
    BOOST_CHECK_EQUAL(util::ErrorString(rejected).original,
                      "Each multisig participant must use a distinct key");
    BOOST_CHECK(!DuplicateSignerWarning({duplicate, duplicate}).empty());
    BOOST_CHECK(duplicate_wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    BOOST_CHECK(duplicate_wallet->GetActiveScriptPubKeyMans().empty());
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

BOOST_AUTO_TEST_CASE(vault_two_stage_2of3_then_any_one)
{
    auto vault = MakeVault(/*m=*/2, /*n=*/3, /*older=*/2, /*recover_priv=*/{0}, /*fallback_older_one_key=*/4);
    {
        LOCK(vault.full->cs_wallet);
        const auto policy = InferWalletVaultPolicy(*vault.full);
        BOOST_REQUIRE(policy.is_vault);
        BOOST_REQUIRE_EQUAL(policy.recovery_stages.size(), 2U);
        BOOST_CHECK_EQUAL(policy.recovery_stages[0].nrequired, 2);
        BOOST_CHECK_EQUAL(*policy.recovery_stages[0].older, 2U);
        BOOST_CHECK_EQUAL(policy.recovery_stages[1].nrequired, 1);
        BOOST_CHECK_EQUAL(*policy.recovery_stages[1].older, 4U);
        const auto pkg = ExportWalletVaultPolicy(*vault.full);
        BOOST_REQUIRE(pkg.fallback_older_one_key);
        BOOST_CHECK_EQUAL(*pkg.fallback_older_one_key, 4U);
        BOOST_REQUIRE_EQUAL(pkg.recovery_stages.size(), 2U);
        const std::string json = FormatVaultPolicyPackage(pkg);
        BOOST_CHECK(json.find("fallback_older_one_key") != std::string::npos);
        BOOST_CHECK(json.find("recovery_stages") != std::string::npos);
        auto parsed = ParseVaultPolicyPackage(json);
        BOOST_REQUIRE_MESSAGE(parsed, util::ErrorString(parsed).original);
        BOOST_REQUIRE_EQUAL(parsed->recovery_stages.size(), 2U);
        VaultPolicyPackage tampered = pkg;
        tampered.fallback_older_one_key = 5;
        BOOST_CHECK(!ParseVaultPolicyPackage(FormatVaultPolicyPackage(tampered)));
        tampered = pkg;
        tampered.recovery_stages[1].nrequired = 2;
        BOOST_CHECK(!ParseVaultPolicyPackage(FormatVaultPolicyPackage(tampered)));
        tampered = pkg;
        tampered.policy_id = "0000000000000000";
        BOOST_CHECK(!ParseVaultPolicyPackage(FormatVaultPolicyPackage(tampered)));
        ExpectKeypath(SignSpk(*vault.full, vault.spk, CTxIn::SEQUENCE_FINAL), "two-stage immediate key-path");
        const auto stage_two = SignSpk(*vault.full, vault.spk, 4);
        ExpectScriptpath(stage_two, "explicit later stage with every recovery key");
        const auto& witness = stage_two.extracted.vin.at(0).scriptWitness.stack;
        BOOST_REQUIRE_EQUAL(witness.size(), 5U); // Three multi_a slots, tapscript, control block.
        BOOST_CHECK_EQUAL(std::count_if(witness.begin(), witness.begin() + 3,
                                        [](const auto& element) { return !element.empty(); }),
                          1U);
    }
    {
        LOCK(vault.recover->cs_wallet);
        ExpectIncomplete(SignSpk(*vault.recover, vault.spk, 2), "one key cannot use 2-of-3 stage");
        ExpectIncomplete(SignSpk(*vault.recover, vault.spk, 3), "1-of-3 stage remains timelocked");
        ExpectScriptpath(SignSpk(*vault.recover, vault.spk, 4), "any one key uses later recovery stage");

        CCoinControl primary;
        BOOST_REQUIRE(ApplyVaultRecoveryToCoinControl(*vault.recover, primary));
        BOOST_REQUIRE(primary.m_nSequence);
        BOOST_CHECK_EQUAL(*primary.m_nSequence, 2U);
        CCoinControl one_key;
        BOOST_REQUIRE(ApplyVaultRecoveryToCoinControl(*vault.recover, one_key, 4));
        BOOST_REQUIRE(one_key.m_nSequence);
        BOOST_CHECK_EQUAL(*one_key.m_nSequence, 4U);
        BOOST_CHECK_EQUAL(one_key.m_min_depth, 4);
        BOOST_CHECK(one_key.m_script_path);
        BOOST_CHECK(!ApplyVaultRecoveryToCoinControl(*vault.recover, one_key, 3));
    }
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

BOOST_AUTO_TEST_CASE(infer_taproot_recovery_delay)
{
    BOOST_CHECK(!InferTaprootRecoveryDelay("tr(musig(a,b)/<0;1>/*)"));
    BOOST_CHECK_EQUAL(*InferTaprootRecoveryDelay("tr(musig(a,b),and_v(v:older(144),multi_a(2,a,b)))"), 144U);
    BOOST_CHECK_EQUAL(*InferTaprootRecoveryDelay("tr(...,and_v(v:older(1),pk(x)))"), 1U);
    BOOST_CHECK(!InferTaprootRecoveryDelay("tr(...,and_v(v:older(0),pk(x)))"));

    const auto rel = InferVaultPolicy("tr(musig(a,b),and_v(v:older(144),multi_a(2,a,b)))");
    BOOST_CHECK(rel.is_vault);
    BOOST_CHECK_EQUAL(*rel.older, 144U);
    BOOST_CHECK(!rel.after);
    BOOST_CHECK_EQUAL(rel.recovery_m, 2);
    BOOST_REQUIRE_EQUAL(rel.recovery_stages.size(), 1U);
    BOOST_CHECK_EQUAL(rel.recovery_stages[0].nrequired, 2);
    const auto staged = InferVaultPolicy(
        "tr(musig(a,b,c),{and_v(v:older(4),multi_a(1,a,b,c)),and_v(v:older(2),multi_a(2,a,b,c))})");
    BOOST_REQUIRE(staged.is_vault);
    BOOST_REQUIRE_EQUAL(staged.recovery_stages.size(), 2U);
    BOOST_CHECK_EQUAL(*staged.older, 2U);
    BOOST_CHECK_EQUAL(staged.recovery_m, 2);
    BOOST_CHECK_EQUAL(*staged.recovery_stages[0].older, 2U);
    BOOST_CHECK_EQUAL(staged.recovery_stages[0].nrequired, 2);
    BOOST_CHECK_EQUAL(*staged.recovery_stages[1].older, 4U);
    BOOST_CHECK_EQUAL(staged.recovery_stages[1].nrequired, 1);
    BOOST_CHECK(!InferVaultPolicy("tr(musig(a,b),and_v(v:older(65536),multi_a(1,a,b)))").is_vault);
    const auto abs = InferVaultPolicy("tr(musig(a,b),and_v(v:after(500),multi_a(1,a,b,c)))");
    BOOST_CHECK(abs.is_vault);
    BOOST_CHECK(!abs.older);
    BOOST_CHECK_EQUAL(*abs.after, 500U);
    BOOST_CHECK_EQUAL(abs.recovery_m, 1);
    BOOST_CHECK(!InferVaultPolicy("tr(musig(a,b)/<0;1>/*)").is_vault);

    const std::string id_a = VaultPolicyId("tr(musig(a,b),and_v(v:older(1),multi_a(1,a,b)))#checksum");
    const std::string id_b = VaultPolicyId("tr(musig(a,b),and_v(v:older(1),multi_a(1,a,b)))#checksum");
    const std::string id_c = VaultPolicyId("tr(musig(a,b),and_v(v:older(2),multi_a(1,a,b)))#checksum");
    BOOST_CHECK_EQUAL(id_a.size(), 16U);
    BOOST_CHECK_EQUAL(id_a, id_b);
    BOOST_CHECK(id_a != id_c);

    std::vector<MultisigKeySpec> dup(2);
    dup[0].fingerprint = "aabbccdd";
    dup[1].fingerprint = "aabbccdd";
    BOOST_CHECK(!DuplicateSignerWarning(dup).empty());
    dup[1].fingerprint = "11223344";
    BOOST_CHECK(DuplicateSignerWarning(dup).empty());
}

BOOST_AUTO_TEST_CASE(vault_recovery_only_key_omitted_from_musig)
{
    auto wallet = MakeWallet();
    LOCK(wallet->cs_wallet);
    CExtKey a = RandomMaster(), b = RandomMaster(), heir = RandomMaster();
    AddUnused(*wallet, a);
    AddUnused(*wallet, b);
    AddUnused(*wallet, heir);
    auto ka = LocalSpec(a);
    auto kb = LocalSpec(b);
    auto kh = LocalSpec(heir);
    kh.recovery_only = true;
    kh.label = "heir";
    auto created = CreateMultisigDescriptor(*wallet, /*nrequired=*/1, {ka, kb, kh},
                                            MultisigOptions{OutputType::BECH32M, 0, {}, /*fallback_older=*/144});
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_REQUIRE(!created->descs.empty());
    const std::string& desc = created->descs[0];
    BOOST_CHECK(desc.find("tr(musig(") != std::string::npos);
    BOOST_CHECK(desc.find("older(144)") != std::string::npos);
    BOOST_CHECK(desc.find("multi_a(1,") != std::string::npos);
    BOOST_CHECK(!created->policy_id.empty());
    BOOST_CHECK_EQUAL(created->policy_id, VaultPolicyId(desc));
    const auto inf = InferVaultPolicy(desc);
    BOOST_CHECK(inf.is_vault);
    BOOST_CHECK_EQUAL(inf.recovery_m, 1);
    BOOST_CHECK_EQUAL(*inf.older, 144U);
    BOOST_CHECK(desc.find("musig(") != std::string::npos);
    BOOST_CHECK(std::count(desc.begin(), desc.end(), ',') >= 2);

    const auto tr = FormatMultisigTranscript("t", "regtest", 1, {ka, kb, kh}, OutputType::BECH32M,
                                             created->descs, /*fallback_older=*/144);
    BOOST_CHECK(tr.find("role=recovery-only") != std::string::npos);
    BOOST_CHECK(tr.find("role=active") != std::string::npos);
    BOOST_CHECK(tr.find("Scrooge vault") != std::string::npos);

    auto after_w = MakeWallet();
    LOCK(after_w->cs_wallet);
    AddUnused(*after_w, a);
    AddUnused(*after_w, b);
    AddUnused(*after_w, heir);
    auto after_created = CreateMultisigDescriptor(*after_w, /*nrequired=*/1, {ka, kb, kh},
                                                  MultisigOptions{OutputType::BECH32M, 0, {}, {}, /*fallback_after=*/500});
    BOOST_REQUIRE_MESSAGE(after_created, util::ErrorString(after_created).original);
    BOOST_CHECK(after_created->descs[0].find("after(500)") != std::string::npos);
    BOOST_CHECK(after_created->descs[0].find("older(") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(vault_after_policy_and_apply_coincontrol)
{
    auto wallet = MakeWallet();
    LOCK(wallet->cs_wallet);
    CExtKey a = RandomMaster(), b = RandomMaster();
    AddUnused(*wallet, a);
    AddUnused(*wallet, b);
    auto created = CreateMultisigDescriptor(*wallet, 1, {LocalSpec(a), LocalSpec(b)},
                                            MultisigOptions{OutputType::BECH32M, 0, {}, {}, /*fallback_after=*/500});
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_CHECK(created->descs[0].find("after(500)") != std::string::npos);
    BOOST_CHECK(created->descs[0].find("older(") == std::string::npos);
    BOOST_CHECK_EQUAL(*created->fallback_after, 500U);
    CCoinControl rec_cc;
    BOOST_REQUIRE(ApplyVaultRecoveryToCoinControl(*wallet, rec_cc));
    BOOST_CHECK(rec_cc.m_script_path);
    BOOST_REQUIRE(rec_cc.m_locktime);
    BOOST_CHECK_EQUAL(*rec_cc.m_locktime, 500U);
    BOOST_CHECK_EQUAL(rec_cc.m_min_depth, std::numeric_limits<int>::max());
    BOOST_CHECK(!rec_cc.m_nSequence);
    const auto inf = InferWalletVaultPolicy(*wallet);
    BOOST_CHECK(inf.is_vault);
    BOOST_CHECK_EQUAL(*inf.after, 500U);
    const auto tr = FormatMultisigTranscript("t", "regtest", 1, {LocalSpec(a), LocalSpec(b)}, OutputType::BECH32M,
                                            created->descs, {}, /*fallback_after=*/500);
    BOOST_CHECK(tr.find("after()") != std::string::npos);
    BOOST_CHECK(tr.find("500") != std::string::npos);
    BOOST_CHECK(tr.find("CLTV") != std::string::npos);
    const auto pkg = ExportWalletVaultPolicy(*wallet);
    BOOST_CHECK_EQUAL(*pkg.fallback_after, 500U);
    BOOST_CHECK(!pkg.fallback_older);
    BOOST_CHECK(FormatVaultPolicyPackage(pkg).find("xprv") == std::string::npos);
    BOOST_CHECK(FormatVaultPolicyPackage(pkg).find("fallback_after") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(vault_policy_package_roundtrip)
{
    BOOST_CHECK(IsVaultUtxoMature(InferredVaultPolicy{}, /*depth=*/0, /*tip=*/0));
    InferredVaultPolicy rel;
    rel.is_vault = true;
    rel.older = 2;
    BOOST_CHECK(!IsVaultUtxoMature(rel, /*depth=*/1, /*tip=*/100));
    BOOST_CHECK(IsVaultUtxoMature(rel, /*depth=*/2, /*tip=*/100));
    InferredVaultPolicy abs;
    abs.is_vault = true;
    abs.after = 50;
    BOOST_CHECK(!IsVaultUtxoMature(abs, /*depth=*/10, /*tip=*/49));
    BOOST_CHECK(IsVaultUtxoMature(abs, /*depth=*/1, /*tip=*/50));

    auto wallet = MakeWallet();
    LOCK(wallet->cs_wallet);
    CExtKey a = RandomMaster(), b = RandomMaster();
    AddUnused(*wallet, a);
    AddUnused(*wallet, b);
    auto created = CreateMultisigDescriptor(*wallet, 1, {LocalSpec(a), LocalSpec(b)},
                                            MultisigOptions{OutputType::BECH32M, 0, {}, 144});
    BOOST_REQUIRE(created);
    auto ordinary = CreateMultisigDescriptor(*wallet, 2, {LocalSpec(a), LocalSpec(b)},
                                             MultisigOptions{OutputType::BECH32});
    BOOST_REQUIRE(ordinary);
    const auto pkg = ExportWalletVaultPolicy(*wallet);
    BOOST_CHECK_EQUAL(pkg.format, "bitcoin-core-vault-policy");
    BOOST_CHECK(!pkg.policy_id.empty());
    BOOST_CHECK_EQUAL(*pkg.fallback_older, 144U);
    BOOST_REQUIRE_EQUAL(pkg.descs.size(), 2U); // Unrelated active bech32 descriptors are excluded.
    const std::string json = FormatVaultPolicyPackage(pkg);
    BOOST_CHECK(json.find("xprv") == std::string::npos);
    auto parsed = ParseVaultPolicyPackage(json);
    BOOST_REQUIRE_MESSAGE(parsed, util::ErrorString(parsed).original);
    BOOST_CHECK_EQUAL(parsed->policy_id, pkg.policy_id);
    BOOST_REQUIRE_EQUAL(parsed->recovery_stages.size(), 1U);
    BOOST_CHECK_EQUAL(parsed->recovery_stages[0].nrequired, 1);
    BOOST_CHECK_EQUAL(*parsed->recovery_stages[0].older, 144U);
    VaultPolicyPackage ordinary_pkg;
    ordinary_pkg.nrequired = 2;
    ordinary_pkg.descs = ordinary->descs;
    auto ordinary_parsed = ParseVaultPolicyPackage(FormatVaultPolicyPackage(ordinary_pkg));
    BOOST_REQUIRE_MESSAGE(ordinary_parsed, util::ErrorString(ordinary_parsed).original);
    BOOST_CHECK_EQUAL(ordinary_parsed->nrequired, 2);
    VaultPolicyPackage single_desc = pkg;
    single_desc.descs.resize(1);
    BOOST_REQUIRE(ParseVaultPolicyPackage(FormatVaultPolicyPackage(single_desc)));
    VaultPolicyPackage wrong_change = pkg;
    wrong_change.descs[1] = wrong_change.descs[0];
    BOOST_CHECK(!ParseVaultPolicyPackage(FormatVaultPolicyPackage(wrong_change)));
    VaultPolicyPackage too_many = pkg;
    too_many.descs.push_back(pkg.descs[0]);
    BOOST_CHECK(!ParseVaultPolicyPackage(FormatVaultPolicyPackage(too_many)));

    auto watch = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "vault_watch", CreateMockableWalletDatabase()));
    watch->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
    LOCK(watch->cs_wallet);
    auto imported = ImportWalletVaultPolicy(*watch, *parsed);
    BOOST_REQUIRE_MESSAGE(imported, util::ErrorString(imported).original);
    const auto again = ExportWalletVaultPolicy(*watch);
    BOOST_CHECK_EQUAL(again.policy_id, pkg.policy_id);

    BOOST_CHECK(!ParseVaultPolicyPackage("not-json"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"other\"}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"descs\":[]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\"}"));
    auto missing_fmt = ParseVaultPolicyPackage("{\"descs\":[\"tr(dummy)\"]}");
    BOOST_REQUIRE(missing_fmt);
    BOOST_CHECK_EQUAL(missing_fmt->format, "bitcoin-core-vault-policy");
    auto auto_id = ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"descs\":[\"tr(dummy)\"]}");
    BOOST_REQUIRE(auto_id);
    BOOST_CHECK_EQUAL(auto_id->policy_id, VaultPolicyId("tr(dummy)"));
    auto versioned = ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"version\":1,\"descs\":[\"d\"]}");
    BOOST_REQUIRE(versioned);
    BOOST_CHECK_EQUAL(versioned->version, 1);
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"version\":2,\"descs\":[\"d\"]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"fallback_older\":-1,\"descs\":[\"d\"]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"recovery_stages\":[{\"nrequired\":1,\"fallback_older\":-1}],\"descs\":[\"d\"]}"));
    // Malformed Recovery Kit field types are ordinary validation failures,
    // never exceptions that can unwind through a Qt restore callback.
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":3,\"descs\":[\"d\"]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"version\":\"one\",\"descs\":[\"d\"]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"fallback_older\":{},\"descs\":[\"d\"]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"recovery_stages\":[{\"nrequired\":[],\"fallback_older\":1}],\"descs\":[\"d\"]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"descs\":[7]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"descs\":[\"tr(musig(a,b),and_v(v:older(65536),multi_a(1,a,b)))\"]}"));
    BOOST_CHECK(!ParseVaultPolicyPackage("{\"format\":\"bitcoin-core-vault-policy\",\"fallback_older\":1,\"fallback_after\":2,\"descs\":[\"x\"]}"));
    VaultPolicyPackage bad_net = *parsed;
    bad_net.network = pkg.network == "main" ? "regtest" : "main";
    BOOST_CHECK(!ImportWalletVaultPolicy(*watch, bad_net));
    VaultPolicyPackage no_csum;
    no_csum.descs = {"tr(musig(a,b))"};
    BOOST_CHECK(!ImportWalletVaultPolicy(*watch, no_csum));
    VaultPolicyPackage empty_net = *parsed;
    empty_net.network.clear();
    auto watch2 = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "vault_watch2", CreateMockableWalletDatabase()));
    watch2->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
    LOCK(watch2->cs_wallet);
    BOOST_REQUIRE(ImportWalletVaultPolicy(*watch2, empty_net));
    BOOST_REQUIRE(ImportWalletVaultPolicy(*watch2, empty_net));
    BOOST_CHECK_EQUAL(ExportWalletVaultPolicy(*watch2).policy_id, pkg.policy_id);
}

BOOST_AUTO_TEST_CASE(vault_fee_uses_script_path_vsize)
{
    auto vault = MakeVault(2, 3, 144, {0, 1});
    LOCK(vault.full->cs_wallet);
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{}, CScript(), MAX_BIP125_RBF_SEQUENCE);
    tx.vout.emplace_back(COIN - 10000, vault.spk);
    const std::vector<CTxOut> prev{CTxOut{COIN, vault.spk}};
    const TxSize keypath = CalculateMaximumSignedTxSize(CTransaction(tx), vault.full.get(), prev, nullptr);
    BOOST_REQUIRE_GT(keypath.vsize, 0);
    tx.vin[0].nSequence = 144;
    const TxSize scriptpath = CalculateMaximumSignedTxSize(CTransaction(tx), vault.full.get(), prev, nullptr);
    BOOST_REQUIRE_GT(scriptpath.vsize, 0);
    BOOST_CHECK_MESSAGE(keypath.vsize < scriptpath.vsize,
                        strprintf("keypath vsize %d !< scriptpath %d", keypath.vsize, scriptpath.vsize));
    BOOST_CHECK_LT(keypath.vsize, 150);
    BOOST_CHECK_GT(scriptpath.vsize, 150);
}

BOOST_AUTO_TEST_CASE(nums_multi_a_fee_is_not_keypath)
{
    FlatSigningProvider provider;
    std::string error;
    const CKey a = GenerateRandomKey();
    const CKey b = GenerateRandomKey();
    const std::string desc = strprintf(
        "tr(%s,sortedmulti_a(1,%s,%s))",
        HexStr(XOnlyPubKey::NUMS_H),
        HexStr(XOnlyPubKey(a.GetPubKey())),
        HexStr(XOnlyPubKey(b.GetPubKey())));
    const auto parsed = Parse(desc, provider, error);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
    const auto w = parsed[0]->MaxSatisfactionWeight(true);
    BOOST_REQUIRE(w);
    BOOST_CHECK_GT(*w, 1 + 65);
    BOOST_CHECK_EQUAL(*parsed[0]->MaxSatisfactionElems(), *parsed[0]->MaxSatisfactionElems(/*script_path=*/true));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
