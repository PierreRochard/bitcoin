// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <wallet/bip39.h>
#include <wallet/db.h>
#include <wallet/multisig.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {
BOOST_AUTO_TEST_SUITE(bip39_tests)

static constexpr std::string_view ZERO_ENTROPY_MNEMONIC{
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art"};

static constexpr std::string_view ZERO_ENTROPY_TREZOR_SEED{
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097"
    "170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"};

static std::string ToString(const SecureString& value)
{
    return {value.begin(), value.end()};
}

static std::shared_ptr<CWallet> MakeMnemonicWallet(const std::string& name)
{
    auto wallet = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, name, CreateMockableWalletDatabase()));
    wallet->m_keypool_size = 8;
    wallet->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED |
                            WALLET_FLAG_BLANK_WALLET);
    return wallet;
}

static std::shared_ptr<CWallet> OpenPersistentMnemonicWallet(const std::string& name, bool create)
{
    DatabaseOptions options;
    options.require_create = create;
    options.require_existing = !create;
    options.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus status;
    bilingual_str error;
    auto database{MakeWalletDatabase(name, options, status, error)};
    BOOST_REQUIRE_MESSAGE(database, error.original);

    auto wallet{std::make_shared<CWallet>(/*chain=*/nullptr, name, std::move(database))};
    wallet->m_keypool_size = 8;
    if (create) {
        wallet->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED |
                                WALLET_FLAG_BLANK_WALLET);
    } else {
        std::vector<bilingual_str> warnings;
        BOOST_REQUIRE(wallet->PopulateWalletFromDB(error, warnings) == DBErrors::LOAD_OK);
    }
    return wallet;
}

struct SpendAttempt {
    bool complete{false};
    size_t witness_stack{0};
};

static SpendAttempt TrySpend(CWallet& wallet, const CScript& script_pub_key, uint32_t sequence)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CMutableTransaction previous;
    previous.version = 2;
    previous.vin.emplace_back();
    previous.vout.emplace_back(COIN, script_pub_key);

    CMutableTransaction spending;
    spending.version = 2;
    spending.vin.emplace_back(COutPoint{previous.GetHash(), 0}, CScript(), sequence);
    spending.vout.emplace_back(COIN - 10000, script_pub_key);

    PartiallySignedTransaction psbt{spending, /*version=*/0};
    psbt.inputs.at(0).non_witness_utxo = MakeTransactionRef(previous);
    psbt.inputs.at(0).witness_utxo = CTxOut{COIN, script_pub_key};
    bool complete{false};
    BOOST_REQUIRE(!wallet.FillPSBT(psbt, {.sign = false, .bip32_derivs = true}, complete));
    BOOST_REQUIRE(!wallet.FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete));
    if (!complete) return {};

    CMutableTransaction extracted;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, extracted));
    BOOST_REQUIRE_EQUAL(extracted.vin.size(), 1U);
    return {true, extracted.vin.front().scriptWitness.stack.size()};
}

static void CheckUnmodifiedBlankWallet(const CWallet& wallet)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    BOOST_CHECK(wallet.GetActiveScriptPubKeyMans().empty());
    BOOST_CHECK(ExportWalletVaultPolicy(wallet).descs.empty());
}

static MultisigKeySpec FixedPublicParticipant()
{
    std::array<std::byte, 32> seed{};
    seed.fill(std::byte{0x42});
    CExtKey master;
    master.SetSeed(seed);

    const std::string path_string{DefaultMultisigPath(OutputType::BECH32M, /*account=*/0)};
    std::vector<uint32_t> path;
    BOOST_REQUIRE(ParseHDKeypath(path_string, path));
    const auto account{DeriveExtKey(master, path)};
    BOOST_REQUIRE(account);

    MultisigKeySpec spec;
    spec.fingerprint = HexStr(account->second.fingerprint);
    spec.path = path_string;
    spec.xpub = EncodeExtPubKey(account->first.Neuter());
    spec.label = "public-device";
    return spec;
}

BOOST_AUTO_TEST_CASE(official_256_bit_zero_vector)
{
    const std::array<unsigned char, BIP39_ENTROPY_SIZE> entropy{};
    const SecureString mnemonic{EncodeBIP39Mnemonic(entropy)};
    BOOST_CHECK_EQUAL(ToString(mnemonic), ZERO_ENTROPY_MNEMONIC);
    BOOST_CHECK(IsValidBIP39Mnemonic(ZERO_ENTROPY_MNEMONIC));

    const auto decoded{DecodeBIP39Mnemonic(ZERO_ENTROPY_MNEMONIC)};
    BOOST_REQUIRE(decoded);
    BOOST_REQUIRE_EQUAL(decoded->size(), entropy.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded->begin(), decoded->end(), entropy.begin(), entropy.end());

    const auto seed{BIP39MnemonicToSeed(ZERO_ENTROPY_MNEMONIC, "TREZOR")};
    BOOST_REQUIRE(seed);
    BOOST_REQUIRE_EQUAL(seed->size(), BIP39_SEED_SIZE);
    BOOST_CHECK_EQUAL(HexStr(*seed), ZERO_ENTROPY_TREZOR_SEED);
}

BOOST_AUTO_TEST_CASE(entropy_roundtrip)
{
    std::vector<std::array<unsigned char, BIP39_ENTROPY_SIZE>> vectors(4);
    vectors[1].fill(0x7f);
    vectors[2].fill(0xff);
    for (size_t i = 0; i < vectors[3].size(); ++i) {
        vectors[3][i] = static_cast<unsigned char>(i);
    }

    std::set<std::string> mnemonics;
    for (const auto& entropy : vectors) {
        const SecureString encoded{EncodeBIP39Mnemonic(entropy)};
        const std::string mnemonic{ToString(encoded)};
        BOOST_CHECK_EQUAL(std::count(mnemonic.begin(), mnemonic.end(), ' '), 23);
        BOOST_CHECK(IsValidBIP39Mnemonic(mnemonic));
        BOOST_CHECK(mnemonics.insert(mnemonic).second);

        const auto decoded{DecodeBIP39Mnemonic(mnemonic)};
        BOOST_REQUIRE(decoded);
        BOOST_REQUIRE_EQUAL(decoded->size(), entropy.size());
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded->begin(), decoded->end(), entropy.begin(), entropy.end());
    }
}

BOOST_AUTO_TEST_CASE(validation_failures)
{
    const std::string too_short{"abandon abandon abandon abandon abandon abandon "
                                "abandon abandon abandon abandon abandon about"};
    const std::string bad_checksum{"abandon abandon abandon abandon abandon abandon "
                                   "abandon abandon abandon abandon abandon abandon "
                                   "abandon abandon abandon abandon abandon abandon "
                                   "abandon abandon abandon abandon abandon abandon"};
    std::string unknown_word{ZERO_ENTROPY_MNEMONIC};
    unknown_word.replace(unknown_word.rfind("art"), 3, "notaword");
    const std::string too_many{std::string{ZERO_ENTROPY_MNEMONIC} + " abandon"};

    for (const std::string& invalid : std::vector<std::string>{
             "",
             too_short,
             bad_checksum,
             unknown_word,
             too_many,
         }) {
        BOOST_CHECK(!IsValidBIP39Mnemonic(invalid));
        BOOST_CHECK(!DecodeBIP39Mnemonic(invalid));
        BOOST_CHECK(!BIP39MnemonicToSeed(invalid));
    }

    std::string uppercase{ZERO_ENTROPY_MNEMONIC};
    uppercase[0] = 'A';
    BOOST_CHECK(!IsValidBIP39Mnemonic(uppercase));
}

BOOST_AUTO_TEST_CASE(canonical_whitespace_and_passphrase)
{
    std::string spaced{"\n\t"};
    for (const char ch : ZERO_ENTROPY_MNEMONIC) {
        if (ch == ' ') {
            spaced += " \t\n ";
        } else {
            spaced += ch;
        }
    }
    spaced += "\r\n";

    const auto decoded{DecodeBIP39Mnemonic(spaced)};
    BOOST_REQUIRE(decoded);
    const auto canonical_seed{BIP39MnemonicToSeed(ZERO_ENTROPY_MNEMONIC, "TREZOR")};
    const auto spaced_seed{BIP39MnemonicToSeed(spaced, "TREZOR")};
    const auto wrong_passphrase_seed{BIP39MnemonicToSeed(ZERO_ENTROPY_MNEMONIC, "TREZ0R")};
    BOOST_REQUIRE(canonical_seed);
    BOOST_REQUIRE(spaced_seed);
    BOOST_REQUIRE(wrong_passphrase_seed);
    BOOST_CHECK_EQUAL_COLLECTIONS(canonical_seed->begin(), canonical_seed->end(),
                                  spaced_seed->begin(), spaced_seed->end());
    BOOST_CHECK(!std::equal(canonical_seed->begin(), canonical_seed->end(),
                            wrong_passphrase_seed->begin(), wrong_passphrase_seed->end()));
}

BOOST_AUTO_TEST_CASE(english_wordlist)
{
    const auto words{BIP39EnglishWords()};
    BOOST_REQUIRE_EQUAL(words.size(), 2048U);
    BOOST_CHECK_EQUAL(words.front(), "abandon");
    BOOST_CHECK_EQUAL(words.back(), "zoo");

    const std::set<std::string_view> unique{words.begin(), words.end()};
    BOOST_CHECK_EQUAL(unique.size(), words.size());
    BOOST_CHECK(std::is_sorted(words.begin(), words.end()));
    for (const std::string_view word : words) {
        BOOST_CHECK(!word.empty());
        BOOST_CHECK(std::all_of(word.begin(), word.end(), [](const unsigned char ch) {
            return ch >= 'a' && ch <= 'z';
        }));
    }
}

BOOST_FIXTURE_TEST_CASE(fixed_staged_policy_validation, BasicTestingSetup)
{
    const auto make_package = [&](const std::string& name,
                                  const uint32_t primary_delay,
                                  const uint32_t final_delay,
                                  const bool recovery_only) {
        auto wallet{MakeMnemonicWallet(name)};
        std::vector<MultisigKeySpec> specs(3);
        for (auto& spec : specs) spec.generate_local = true;
        specs.back().recovery_only = recovery_only;
        MultisigOptions options;
        options.type = OutputType::BECH32M;
        options.fallback_older = primary_delay;
        options.fallback_older_one_key = final_delay;
        LOCK(wallet->cs_wallet);
        auto created{CreateMultisigDescriptor(*wallet, /*nrequired=*/2, specs, options)};
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        return ExportWalletVaultPolicy(*wallet);
    };

    const VaultPolicyPackage fixed{make_package("fixed_policy", 4320, 8640, /*recovery_only=*/false)};
    const auto valid{ValidateFixedStagedVaultPolicy(fixed)};
    BOOST_REQUIRE_MESSAGE(valid, util::ErrorString(valid).original);

    const VaultPolicyPackage wrong_delays{make_package("wrong_delays", 2, 4, /*recovery_only=*/false)};
    const auto invalid_delays{ValidateFixedStagedVaultPolicy(wrong_delays)};
    BOOST_REQUIRE(!invalid_delays);
    BOOST_CHECK(util::ErrorString(invalid_delays).original.find("4,320") != std::string::npos);

    const VaultPolicyPackage recovery_only{make_package("recovery_only", 4320, 8640, /*recovery_only=*/true)};
    const auto invalid_roster{ValidateFixedStagedVaultPolicy(recovery_only)};
    BOOST_REQUIRE(!invalid_roster);
    BOOST_CHECK(util::ErrorString(invalid_roster).original.find("same three participants") != std::string::npos);

    // Preserve every participant's aggregate occurrence count while omitting
    // one from the 2-of-3 stage and moving it into a third Taproot leaf. This
    // must not pass as the canonical two-stage fixed policy.
    VaultPolicyPackage extra_leaf{fixed};
    for (std::string& descriptor : extra_leaf.descs) {
        const size_t checksum_marker{descriptor.find('#')};
        BOOST_REQUIRE_NE(checksum_marker, std::string::npos);
        descriptor.resize(checksum_marker);
        static constexpr std::string_view PRIMARY{"and_v(v:older(4320),multi_a(2,"};
        const size_t primary_keys{descriptor.find(PRIMARY)};
        BOOST_REQUIRE_NE(primary_keys, std::string::npos);
        const size_t primary_end{descriptor.find("))", primary_keys + PRIMARY.size())};
        BOOST_REQUIRE_NE(primary_end, std::string::npos);
        const size_t omitted_key_begin{descriptor.rfind(',', primary_end)};
        BOOST_REQUIRE_NE(omitted_key_begin, std::string::npos);
        const std::string omitted_key{descriptor.substr(omitted_key_begin + 1, primary_end - omitted_key_begin - 1)};
        descriptor.erase(omitted_key_begin, primary_end - omitted_key_begin);

        static constexpr std::string_view FINAL_SEPARATOR{",and_v(v:older(8640),multi_a(1,"};
        const size_t final_separator{descriptor.find(FINAL_SEPARATOR, primary_keys)};
        BOOST_REQUIRE_NE(final_separator, std::string::npos);
        descriptor.replace(final_separator, 1, ",{");
        const size_t outer_tree_close{descriptor.rfind("})")};
        BOOST_REQUIRE_NE(outer_tree_close, std::string::npos);
        descriptor.insert(outer_tree_close, ",pk(" + omitted_key + ")}");

        const std::string checksum{GetDescriptorChecksum(descriptor)};
        BOOST_REQUIRE(!checksum.empty());
        descriptor += "#" + checksum;
    }
    extra_leaf.policy_id = VaultPolicyId(extra_leaf.descs.front());
    const auto invalid_shape{ValidateFixedStagedVaultPolicy(extra_leaf)};
    BOOST_REQUIRE(!invalid_shape);
    BOOST_CHECK(util::ErrorString(invalid_shape).original.find("canonical fixed staged vault construction") != std::string::npos);

    VaultPolicyPackage missing_change{fixed};
    missing_change.descs.resize(1);
    const auto invalid_pair{ValidateFixedStagedVaultPolicy(missing_change)};
    BOOST_REQUIRE(!invalid_pair);
    BOOST_CHECK(util::ErrorString(invalid_pair).original.find("receive and change") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(multisig_candidate_prepared_before_wallet_commit, BasicTestingSetup)
{
    std::vector<MultisigKeySpec> candidate_specs(3);
    for (auto& spec : candidate_specs) spec.generate_local = true;
    MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.fallback_older = 4320;
    options.fallback_older_one_key = 8640;

    auto prepared{PrepareMultisigDescriptor(/*nrequired=*/2, candidate_specs, options)};
    BOOST_REQUIRE_MESSAGE(prepared, util::ErrorString(prepared).original);
    BOOST_REQUIRE_EQUAL(prepared->descs.size(), 2U);
    BOOST_REQUIRE_EQUAL(prepared->recovery.size(), 3U);
    BOOST_CHECK_EQUAL(prepared->policy_id, VaultPolicyId(prepared->descs.front()));
    for (const std::string& descriptor : prepared->descs) {
        BOOST_CHECK(descriptor.find("xprv") == std::string::npos);
        BOOST_CHECK(descriptor.find("tprv") == std::string::npos);
        for (const auto& recovery : prepared->recovery) {
            BOOST_CHECK(descriptor.find(std::string{recovery.mnemonic}) == std::string::npos);
        }
    }

    VaultPolicyPackage package;
    package.network = Params().GetChainTypeString();
    package.nrequired = 2;
    package.fallback_older = 4320;
    package.fallback_older_one_key = 8640;
    package.recovery_stages = {{2, 4320, {}}, {1, 8640, {}}};
    package.descs = prepared->descs;
    package.policy_id = prepared->policy_id;
    const auto fixed{ValidateFixedStagedVaultPolicy(package)};
    BOOST_REQUIRE_MESSAGE(fixed, util::ErrorString(fixed).original);

    // Commit the already printed phrases into a wallet only after the public
    // candidate has been fixed. The resulting descriptors must be byte-for-
    // byte identical, and committing must not mint replacement mnemonics.
    std::vector<MultisigKeySpec> commit_specs(3);
    for (const auto& recovery : prepared->recovery) {
        BOOST_REQUIRE_LT(recovery.key_index, commit_specs.size());
        commit_specs[recovery.key_index].recovery_mnemonic.emplace(
            recovery.mnemonic.begin(), recovery.mnemonic.end());
    }
    auto wallet{MakeMnemonicWallet("prepared_candidate_commit")};
    auto committed{[&] {
        LOCK(wallet->cs_wallet);
        return CreateMultisigDescriptor(*wallet, /*nrequired=*/2, commit_specs, options);
    }()};
    BOOST_REQUIRE_MESSAGE(committed, util::ErrorString(committed).original);
    BOOST_CHECK(committed->recovery.empty());
    BOOST_CHECK(committed->descs == prepared->descs);
    BOOST_CHECK_EQUAL(committed->policy_id, prepared->policy_id);

    std::vector<MultisigKeySpec> implicit_specs(3);
    auto implicit{PrepareMultisigDescriptor(/*nrequired=*/2, implicit_specs, options)};
    BOOST_REQUIRE(!implicit);
    BOOST_CHECK(util::ErrorString(implicit).original.find("explicit") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(generated_mnemonics_restore_public_policy, BasicTestingSetup)
{
    auto source{MakeMnemonicWallet("mnemonic_source")};
    std::vector<MultisigKeySpec> generated_specs(3);
    for (auto& spec : generated_specs)
        spec.generate_local = true;
    MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.fallback_older = 2;
    options.fallback_older_one_key = 4;

    auto generated{[&] {
        LOCK(source->cs_wallet);
        return CreateMultisigDescriptor(*source, /*nrequired=*/2, generated_specs, options);
    }()};
    BOOST_REQUIRE_MESSAGE(generated, util::ErrorString(generated).original);
    BOOST_REQUIRE_EQUAL(generated->recovery.size(), 3U);
    BOOST_REQUIRE_EQUAL(generated->descs.size(), 2U);

    std::set<std::string> unique_mnemonics;
    std::set<std::string> unique_xpubs;
    const std::string expected_path{DefaultMultisigPath(OutputType::BECH32M, /*account=*/0)};
    for (size_t index = 0; index < generated->recovery.size(); ++index) {
        const GeneratedMnemonic& record{generated->recovery[index]};
        BOOST_CHECK_EQUAL(record.key_index, index);
        BOOST_CHECK_EQUAL(record.path, expected_path);
        BOOST_CHECK_EQUAL(record.fingerprint.size(), 8U);
        BOOST_CHECK(IsHex(record.fingerprint));
        BOOST_CHECK(DecodeExtPubKey(record.xpub).pubkey.IsValid());
        BOOST_CHECK(unique_mnemonics.insert(ToString(record.mnemonic)).second);
        BOOST_CHECK(unique_xpubs.insert(record.xpub).second);

        const auto seed{BIP39MnemonicToSeed(
            std::string_view{record.mnemonic.data(), record.mnemonic.size()})};
        BOOST_REQUIRE(seed);
        CExtKey master;
        master.SetSeed(std::as_bytes(std::span{*seed}));
        std::vector<uint32_t> path;
        BOOST_REQUIRE(ParseHDKeypath(record.path, path));
        const auto derived{DeriveExtKey(master, path)};
        BOOST_REQUIRE(derived);
        BOOST_CHECK_EQUAL(HexStr(derived->second.fingerprint), record.fingerprint);
        BOOST_CHECK_EQUAL(WriteHDKeypath(derived->second.path), record.path);
        BOOST_CHECK_EQUAL(EncodeExtPubKey(derived->first.Neuter()), record.xpub);
        BOOST_CHECK(generated->descs.front().find(record.fingerprint) != std::string::npos);
        BOOST_CHECK(generated->descs.front().find(record.xpub) != std::string::npos);
    }

    VaultPolicyPackage package;
    {
        LOCK(source->cs_wallet);
        package = ExportWalletVaultPolicy(*source);
    }
    BOOST_CHECK(generated->descs == package.descs);
    BOOST_CHECK_EQUAL(generated->policy_id, package.policy_id);
    const std::string public_json{FormatVaultPolicyPackage(package)};
    BOOST_CHECK(public_json.find("xprv") == std::string::npos);
    BOOST_CHECK(public_json.find("tprv") == std::string::npos);
    for (const GeneratedMnemonic& record : generated->recovery) {
        BOOST_CHECK(public_json.find(ToString(record.mnemonic)) == std::string::npos);
    }

    std::vector<SecureString> shuffled;
    for (const size_t index : {2U, 0U, 1U}) {
        const SecureString& mnemonic{generated->recovery.at(index).mnemonic};
        shuffled.emplace_back(mnemonic.begin(), mnemonic.end());
    }
    auto validated{ValidateVaultPolicyMnemonics(package, shuffled)};
    BOOST_REQUIRE_MESSAGE(validated, util::ErrorString(validated).original);
    BOOST_REQUIRE_EQUAL(validated->size(), shuffled.size());
    for (const VaultMnemonicMatch& match : *validated) {
        BOOST_REQUIRE_LT(match.mnemonic_index, shuffled.size());
        const auto record = std::find_if(generated->recovery.begin(), generated->recovery.end(), [&](const GeneratedMnemonic& item) {
            return ToString(item.mnemonic) == ToString(shuffled.at(match.mnemonic_index));
        });
        BOOST_REQUIRE(record != generated->recovery.end());
        BOOST_CHECK_EQUAL(match.fingerprint, record->fingerprint);
        BOOST_CHECK_EQUAL(match.path, record->path);
        BOOST_CHECK_EQUAL(match.xpub, record->xpub);
    }

    auto restored{MakeMnemonicWallet("mnemonic_restored")};
    auto restored_matches{[&] {
        LOCK(restored->cs_wallet);
        CheckUnmodifiedBlankWallet(*restored);
        return RestoreWalletVaultPolicy(*restored, package, shuffled);
    }()};
    BOOST_REQUIRE_MESSAGE(restored_matches, util::ErrorString(restored_matches).original);
    BOOST_REQUIRE_EQUAL(restored_matches->size(), validated->size());
    for (size_t index = 0; index < validated->size(); ++index) {
        BOOST_CHECK_EQUAL(restored_matches->at(index).mnemonic_index, validated->at(index).mnemonic_index);
        BOOST_CHECK_EQUAL(restored_matches->at(index).fingerprint, validated->at(index).fingerprint);
        BOOST_CHECK_EQUAL(restored_matches->at(index).path, validated->at(index).path);
        BOOST_CHECK_EQUAL(restored_matches->at(index).xpub, validated->at(index).xpub);
    }

    VaultPolicyPackage restored_package;
    {
        LOCK(restored->cs_wallet);
        BOOST_CHECK(restored->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
        BOOST_CHECK(restored->m_lost_signers.empty());
        restored_package = ExportWalletVaultPolicy(*restored);
    }
    BOOST_CHECK_EQUAL(FormatVaultPolicyPackage(restored_package), public_json);

    CTxDestination source_destination;
    CTxDestination restored_destination;
    {
        LOCK(source->cs_wallet);
        auto destination{source->GetNewDestination(OutputType::BECH32M, "")};
        BOOST_REQUIRE(destination);
        source_destination = *destination;
    }
    {
        LOCK(restored->cs_wallet);
        auto destination{restored->GetNewDestination(OutputType::BECH32M, "")};
        BOOST_REQUIRE(destination);
        restored_destination = *destination;
    }
    BOOST_CHECK(source_destination == restored_destination);
    const CScript script_pub_key{GetScriptForDestination(restored_destination)};
    {
        LOCK(restored->cs_wallet);
        const SpendAttempt keypath{TrySpend(*restored, script_pub_key, CTxIn::SEQUENCE_FINAL)};
        BOOST_REQUIRE(keypath.complete);
        BOOST_CHECK_EQUAL(keypath.witness_stack, 1U);
    }

    const auto rejected_without_mutation = [&](const std::string& name,
                                               std::vector<SecureString> phrases,
                                               const std::string& error_fragment) {
        auto validation{ValidateVaultPolicyMnemonics(package, phrases)};
        BOOST_REQUIRE(!validation);
        BOOST_CHECK(util::ErrorString(validation).original.find(error_fragment) != std::string::npos);

        auto wallet{MakeMnemonicWallet(name)};
        LOCK(wallet->cs_wallet);
        CheckUnmodifiedBlankWallet(*wallet);
        auto restore{RestoreWalletVaultPolicy(*wallet, package, phrases)};
        BOOST_REQUIRE(!restore);
        BOOST_CHECK(util::ErrorString(restore).original.find(error_fragment) != std::string::npos);
        CheckUnmodifiedBlankWallet(*wallet);
    };

    SecureString invalid{generated->recovery.front().mnemonic.begin(), generated->recovery.front().mnemonic.end()};
    invalid.replace(0, invalid.find(' '), "notaword");
    rejected_without_mutation("mnemonic_invalid", {invalid}, "not a valid 24-word");

    SecureString duplicate{generated->recovery.front().mnemonic.begin(), generated->recovery.front().mnemonic.end()};
    rejected_without_mutation("mnemonic_duplicate", {duplicate, duplicate}, "different vault participant");

    SecureString unmatched{ZERO_ENTROPY_MNEMONIC.begin(), ZERO_ENTROPY_MNEMONIC.end()};
    BOOST_REQUIRE(unique_mnemonics.count(ToString(unmatched)) == 0);
    rejected_without_mutation("mnemonic_unmatched", {unmatched}, "does not match any participant");
}

BOOST_FIXTURE_TEST_CASE(partial_mnemonic_restore_signing_boundaries, BasicTestingSetup)
{
    auto source{MakeMnemonicWallet("mnemonic_partial_source")};
    std::vector<MultisigKeySpec> specs(3);
    for (auto& spec : specs)
        spec.generate_local = true;
    MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.fallback_older = 2;
    options.fallback_older_one_key = 4;

    auto generated{[&] {
        LOCK(source->cs_wallet);
        return CreateMultisigDescriptor(*source, /*nrequired=*/2, specs, options);
    }()};
    BOOST_REQUIRE_MESSAGE(generated, util::ErrorString(generated).original);
    BOOST_REQUIRE_EQUAL(generated->recovery.size(), 3U);

    VaultPolicyPackage package;
    CTxDestination expected_destination;
    {
        LOCK(source->cs_wallet);
        package = ExportWalletVaultPolicy(*source);
        expected_destination = *Assert(source->GetNewDestination(OutputType::BECH32M, ""));
    }

    const std::array<std::array<size_t, 2>, 3> pairs{{{0, 1}, {0, 2}, {1, 2}}};
    for (const auto& pair : pairs) {
        std::vector<SecureString> phrases;
        for (const size_t index : pair) {
            const SecureString& mnemonic{generated->recovery.at(index).mnemonic};
            phrases.emplace_back(mnemonic.begin(), mnemonic.end());
        }
        std::reverse(phrases.begin(), phrases.end());

        auto wallet{MakeMnemonicWallet("mnemonic_pair_" + std::to_string(pair[0]) + std::to_string(pair[1]))};
        LOCK(wallet->cs_wallet);
        auto restored{RestoreWalletVaultPolicy(*wallet, package, phrases)};
        BOOST_REQUIRE_MESSAGE(restored, util::ErrorString(restored).original);
        BOOST_REQUIRE_EQUAL(restored->size(), 2U);
        std::set<std::string> expected_unavailable;
        for (size_t index = 0; index < generated->recovery.size(); ++index) {
            if (std::find(pair.begin(), pair.end(), index) == pair.end()) {
                expected_unavailable.insert(generated->recovery[index].fingerprint);
            }
        }
        BOOST_CHECK(wallet->m_lost_signers == expected_unavailable);
        const CTxDestination destination{*Assert(wallet->GetNewDestination(OutputType::BECH32M, ""))};
        BOOST_CHECK(destination == expected_destination);
        const CScript script_pub_key{GetScriptForDestination(destination)};
        BOOST_CHECK(!TrySpend(*wallet, script_pub_key, CTxIn::SEQUENCE_FINAL).complete);
        const SpendAttempt recovered{TrySpend(*wallet, script_pub_key, /*sequence=*/2)};
        BOOST_REQUIRE(recovered.complete);
        BOOST_CHECK_GT(recovered.witness_stack, 1U);
    }

    for (size_t index = 0; index < generated->recovery.size(); ++index) {
        const SecureString& mnemonic{generated->recovery.at(index).mnemonic};
        std::vector<SecureString> phrase{SecureString{mnemonic.begin(), mnemonic.end()}};
        auto wallet{MakeMnemonicWallet("mnemonic_single_" + std::to_string(index))};
        LOCK(wallet->cs_wallet);
        auto restored{RestoreWalletVaultPolicy(*wallet, package, phrase)};
        BOOST_REQUIRE_MESSAGE(restored, util::ErrorString(restored).original);
        BOOST_REQUIRE_EQUAL(restored->size(), 1U);
        std::set<std::string> expected_unavailable;
        for (size_t other = 0; other < generated->recovery.size(); ++other) {
            if (other != index) expected_unavailable.insert(generated->recovery[other].fingerprint);
        }
        BOOST_CHECK(wallet->m_lost_signers == expected_unavailable);
        const CTxDestination destination{*Assert(wallet->GetNewDestination(OutputType::BECH32M, ""))};
        BOOST_CHECK(destination == expected_destination);
        const CScript script_pub_key{GetScriptForDestination(destination)};
        BOOST_CHECK(!TrySpend(*wallet, script_pub_key, CTxIn::SEQUENCE_FINAL).complete);
        BOOST_CHECK(!TrySpend(*wallet, script_pub_key, /*sequence=*/2).complete);
        const SpendAttempt recovered{TrySpend(*wallet, script_pub_key, /*sequence=*/4)};
        BOOST_REQUIRE(recovered.complete);
        BOOST_CHECK_GT(recovered.witness_stack, 1U);
    }

    const std::string persistent_name{"mnemonic_partial_persistence"};
    std::set<std::string> expected_unavailable;
    for (size_t index = 1; index < generated->recovery.size(); ++index) {
        expected_unavailable.insert(generated->recovery[index].fingerprint);
    }
    {
        auto wallet{OpenPersistentMnemonicWallet(persistent_name, /*create=*/true)};
        const SecureString& mnemonic{generated->recovery.front().mnemonic};
        std::vector<SecureString> phrase{SecureString{mnemonic.begin(), mnemonic.end()}};
        LOCK(wallet->cs_wallet);
        auto restored{RestoreWalletVaultPolicy(*wallet, package, phrase)};
        BOOST_REQUIRE_MESSAGE(restored, util::ErrorString(restored).original);
        BOOST_CHECK(wallet->m_lost_signers == expected_unavailable);
    }
    {
        auto reloaded{OpenPersistentMnemonicWallet(persistent_name, /*create=*/false)};
        LOCK(reloaded->cs_wallet);
        BOOST_CHECK(reloaded->m_lost_signers == expected_unavailable);
        BOOST_CHECK_EQUAL(FormatVaultPolicyPackage(ExportWalletVaultPolicy(*reloaded)),
                          FormatVaultPolicyPackage(package));
        const CTxDestination destination{*Assert(reloaded->GetNewDestination(OutputType::BECH32M, ""))};
        BOOST_CHECK(destination == expected_destination);
        const CScript script_pub_key{GetScriptForDestination(destination)};
        BOOST_CHECK(!TrySpend(*reloaded, script_pub_key, /*sequence=*/2).complete);
        const SpendAttempt recovered{TrySpend(*reloaded, script_pub_key, /*sequence=*/4)};
        BOOST_REQUIRE(recovered.complete);
        BOOST_CHECK_GT(recovered.witness_stack, 1U);
    }
}

BOOST_FIXTURE_TEST_CASE(mixed_public_and_mnemonic_restore, BasicTestingSetup)
{
    auto source{MakeMnemonicWallet("mnemonic_mixed_source")};
    std::vector<MultisigKeySpec> specs(3);
    specs[0].generate_local = true;
    specs[1] = FixedPublicParticipant();
    specs[2].generate_local = true;
    MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.fallback_older = 2;
    options.fallback_older_one_key = 4;

    auto generated{[&] {
        LOCK(source->cs_wallet);
        return CreateMultisigDescriptor(*source, /*nrequired=*/2, specs, options);
    }()};
    BOOST_REQUIRE_MESSAGE(generated, util::ErrorString(generated).original);
    BOOST_REQUIRE_EQUAL(generated->recovery.size(), 2U);
    BOOST_CHECK_EQUAL(generated->recovery[0].key_index, 0U);
    BOOST_CHECK_EQUAL(generated->recovery[1].key_index, 2U);

    VaultPolicyPackage package;
    CTxDestination expected_destination;
    {
        LOCK(source->cs_wallet);
        package = ExportWalletVaultPolicy(*source);
        expected_destination = *Assert(source->GetNewDestination(OutputType::BECH32M, ""));
    }
    std::vector<SecureString> phrases;
    for (auto it = generated->recovery.rbegin(); it != generated->recovery.rend(); ++it) {
        phrases.emplace_back(it->mnemonic.begin(), it->mnemonic.end());
    }

    auto restored{MakeMnemonicWallet("mnemonic_mixed_restored")};
    LOCK(restored->cs_wallet);
    auto matches{RestoreWalletVaultPolicy(*restored, package, phrases)};
    BOOST_REQUIRE_MESSAGE(matches, util::ErrorString(matches).original);
    BOOST_REQUIRE_EQUAL(matches->size(), 2U);
    BOOST_REQUIRE(specs[1].fingerprint);
    BOOST_CHECK(restored->m_lost_signers == std::set<std::string>{*specs[1].fingerprint});
    const CTxDestination destination{*Assert(restored->GetNewDestination(OutputType::BECH32M, ""))};
    BOOST_CHECK(destination == expected_destination);
    const CScript script_pub_key{GetScriptForDestination(destination)};
    BOOST_CHECK(!TrySpend(*restored, script_pub_key, CTxIn::SEQUENCE_FINAL).complete);
    const SpendAttempt recovered{TrySpend(*restored, script_pub_key, /*sequence=*/2)};
    BOOST_REQUIRE(recovered.complete);
    BOOST_CHECK_GT(recovered.witness_stack, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
