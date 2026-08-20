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
#include <string>
#include <variant>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(taproot_scale_tests, BasicTestingSetup)

using common::PSBTError;

//! Taproot key-count limits: script-path / vault fallback is BIP 342's 999
//! (MAX_PUBKEYS_PER_MULTI_A). n-of-n MuSig2 key-path has no consensus cap.

static std::shared_ptr<CWallet> MakeWallet()
{
    auto wallet = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "tap_scale", CreateMockableWalletDatabase()));
    wallet->m_keypool_size = 4;
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

static std::string PathStr() { return WriteHDKeypath(Bip48TaprootPath()); }

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

static MultisigKeySpec XprvSpec(const CExtKey& master)
{
    MultisigKeySpec spec;
    spec.hdkey = EncodeExtKey(master);
    spec.path = PathStr();
    spec.label = "xprv";
    return spec;
}

static MultisigKeySpec XpubSpec(const CExtKey& master)
{
    MultisigKeySpec spec;
    spec.fingerprint = MasterFpr(master);
    spec.path = PathStr();
    spec.xpub = EncodeExtPubKey(XpubAt(master, Bip48TaprootPath()));
    spec.label = "xpub";
    return spec;
}

struct SignOut {
    std::optional<PSBTError> error;
    bool complete{false};
    size_t witness_stack{0};
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
    if (complete) {
        CMutableTransaction extracted;
        FinalizeAndExtractPSBT(psbt, extracted);
        if (!extracted.vin.empty()) {
            out.witness_stack = extracted.vin[0].scriptWitness.stack.size();
        }
    } else {
        out.witness_stack = psbt.inputs[0].final_script_witness.stack.size();
    }
    return out;
}

static CScript CreateAndDest(CWallet& wallet, int m, const std::vector<MultisigKeySpec>& specs,
                             std::optional<uint32_t> older = {})
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    auto created = CreateMultisigDescriptor(wallet, m, specs, MultisigOptions{OutputType::BECH32M, 0, {}, older});
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    const CTxDestination dest = *Assert(wallet.GetNewDestination(OutputType::BECH32M, ""));
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));
    return GetScriptForDestination(dest);
}

BOOST_AUTO_TEST_CASE(rejects_over_scriptpath_limit)
{
    BOOST_CHECK(!ValidateMultisigPolicy(1, MAX_PUBKEYS_PER_MULTI_A + 1, OutputType::BECH32M).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(1, MAX_PUBKEYS_PER_MULTI_A + 1, OutputType::BECH32M, 1).empty());

    auto wallet = MakeWallet();
    LOCK(wallet->cs_wallet);
    // Policy is checked before key material is parsed.
    const std::vector<MultisigKeySpec> specs(MAX_PUBKEYS_PER_MULTI_A + 1);
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 1, specs, MultisigOptions{OutputType::BECH32M, 0, {}, {}}));
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 1, specs, MultisigOptions{OutputType::BECH32M, 0, {}, 1}));
}

BOOST_AUTO_TEST_CASE(musig_n_of_n_parses_past_multi_a_cap)
{
    // Key-path MuSig2 is a single 32-byte output key; BIP 342's 999 cap does not apply.
    constexpr unsigned n = MAX_PUBKEYS_PER_MULTI_A + 1;
    std::vector<std::string> exprs;
    exprs.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        exprs.push_back(EncodeExtPubKey(RandomMaster().Neuter()));
    }
    const std::string desc = WrapSortedMulti(OutputType::BECH32M, n, exprs);
    BOOST_REQUIRE(desc.find("tr(musig(") != std::string::npos);
    BOOST_REQUIRE(desc.find("multi_a") == std::string::npos);
    const std::string checksum = GetDescriptorChecksum(desc);
    BOOST_REQUIRE(!checksum.empty());
    std::string with_sum = desc + "#" + checksum;
    FlatSigningProvider keys;
    std::string error;
    auto parsed = Parse(with_sum, keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(parsed[0]->Expand(0, keys, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
}

BOOST_AUTO_TEST_CASE(scriptpath_1_of_max_spend)
{
    constexpr unsigned n = MAX_PUBKEYS_PER_MULTI_A;
    auto wallet = MakeWallet();
    LOCK(wallet->cs_wallet);
    std::vector<MultisigKeySpec> specs;
    specs.reserve(n);
    specs.push_back(XprvSpec(RandomMaster()));
    for (unsigned i = 1; i < n; ++i) specs.push_back(XpubSpec(RandomMaster()));
    const CScript spk = CreateAndDest(*wallet, 1, specs);
    const SignOut out = SignSpk(*wallet, spk, CTxIn::SEQUENCE_FINAL);
    BOOST_REQUIRE_MESSAGE(!out.error, "1-of-999 FillPSBT error");
    BOOST_REQUIRE_MESSAGE(out.complete, "1-of-999 script-path should complete with one xprv");
    // n signatures (one 64-byte, rest empty) + tapscript + control block.
    BOOST_CHECK_EQUAL(out.witness_stack, n + 2);
}

BOOST_AUTO_TEST_CASE(musig_64_of_64_keypath_spend)
{
    constexpr int n = 64;
    auto wallet = MakeWallet();
    LOCK(wallet->cs_wallet);
    std::vector<MultisigKeySpec> specs;
    specs.reserve(n);
    for (int i = 0; i < n; ++i) specs.push_back(XprvSpec(RandomMaster()));
    const CScript spk = CreateAndDest(*wallet, n, specs);
    const SignOut out = SignSpk(*wallet, spk, CTxIn::SEQUENCE_FINAL);
    BOOST_REQUIRE_MESSAGE(!out.error, "64-of-64 MuSig2 FillPSBT error");
    BOOST_REQUIRE_MESSAGE(out.complete, "64-of-64 MuSig2 key-path should complete");
    BOOST_CHECK_EQUAL(out.witness_stack, 1U);
}

BOOST_AUTO_TEST_CASE(vault_1_of_max_recovers)
{
    constexpr unsigned n = MAX_PUBKEYS_PER_MULTI_A;
    constexpr uint32_t older = 1;
    auto wallet = MakeWallet();
    LOCK(wallet->cs_wallet);
    std::vector<MultisigKeySpec> specs;
    specs.reserve(n);
    specs.push_back(XprvSpec(RandomMaster()));
    for (unsigned i = 1; i < n; ++i) specs.push_back(XpubSpec(RandomMaster()));
    const CScript spk = CreateAndDest(*wallet, 1, specs, older);
    const SignOut too_soon = SignSpk(*wallet, spk, CTxIn::SEQUENCE_FINAL);
    BOOST_CHECK_MESSAGE(!too_soon.complete, "1-of-999 vault key-path incomplete without every participant");
    const SignOut rec = SignSpk(*wallet, spk, older);
    BOOST_REQUIRE_MESSAGE(!rec.error, "1-of-999 vault recovery FillPSBT error");
    BOOST_REQUIRE_MESSAGE(rec.complete, "1-of-999 vault recovers on script-path after older(1)");
    BOOST_CHECK_GT(rec.witness_stack, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
