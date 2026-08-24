// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/sha256.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <wallet/bip39.h>
#include <wallet/db.h>
#include <wallet/multisig.h>
#include <wallet/test/util.h>
#include <wallet/vault_policy_qr.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {
namespace {

struct PolicyData {
    std::string json;
    MultisigDescriptorResult descriptor;
};

PolicyData MakePolicy(const std::string& name)
{
    auto wallet{std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, name, CreateMockableWalletDatabase()))};
    wallet->m_keypool_size = 8;
    wallet->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED |
                            WALLET_FLAG_BLANK_WALLET);

    std::vector<MultisigKeySpec> specs(3);
    for (auto& spec : specs)
        spec.generate_local = true;
    MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.fallback_older = 4320;
    options.fallback_older_one_key = 8640;

    LOCK(wallet->cs_wallet);
    auto created{CreateMultisigDescriptor(*wallet, /*nrequired=*/2, specs, options)};
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    const VaultPolicyPackage package{ExportWalletVaultPolicy(*wallet)};
    return {FormatVaultPolicyPackage(package), std::move(*created)};
}

std::array<unsigned char, CSHA256::OUTPUT_SIZE> Sha256(std::string_view input)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(input.data()), input.size()).Finalize(digest.data());
    return digest;
}

std::string Sha256Hex(std::string_view input)
{
    return HexStr(Sha256(input));
}

std::vector<std::string> Split(std::string_view encoded)
{
    std::vector<std::string> fields;
    size_t begin{0};
    while (true) {
        const size_t separator{encoded.find('|', begin)};
        fields.emplace_back(encoded.substr(begin, separator == std::string_view::npos ? encoded.size() - begin : separator - begin));
        if (separator == std::string_view::npos) break;
        begin = separator + 1;
    }
    return fields;
}

std::string JoinBody(const std::vector<std::string>& fields)
{
    BOOST_REQUIRE_EQUAL(fields.size(), 7U);
    std::string body{fields[0]};
    for (size_t index = 1; index < 6; ++index)
        body += "|" + fields[index];
    return body;
}

std::string RewritePart(std::string_view encoded, size_t field_index, std::string value)
{
    auto fields{Split(encoded)};
    BOOST_REQUIRE_EQUAL(fields.size(), 7U);
    BOOST_REQUIRE_LT(field_index, 6U);
    fields[field_index] = std::move(value);
    const std::string body{JoinBody(fields)};
    const auto checksum{Sha256(body)};
    return body + "|" + HexStr(std::span{checksum}.first(16));
}

void ReplaceAll(std::string& target, std::string_view from, std::string_view to)
{
    BOOST_REQUIRE(!from.empty());
    size_t position{0};
    while ((position = target.find(from, position)) != std::string::npos) {
        target.replace(position, from.size(), to);
        position += to.size();
    }
}

std::string PrivatePolicyJson(const PolicyData& policy)
{
    BOOST_REQUIRE(!policy.descriptor.recovery.empty());
    const GeneratedMnemonic& recovery{policy.descriptor.recovery.front()};
    auto seed{BIP39MnemonicToSeed(std::string_view{recovery.mnemonic.data(), recovery.mnemonic.size()})};
    BOOST_REQUIRE(seed);
    CExtKey master;
    master.SetSeed(std::as_bytes(std::span{*seed}));
    std::vector<uint32_t> path;
    BOOST_REQUIRE(ParseHDKeypath(recovery.path, path));
    auto account{DeriveExtKey(master, path)};
    BOOST_REQUIRE(account);
    const std::string xprv{EncodeExtKey(account->first)};

    auto parsed{ParseVaultPolicyPackage(policy.json)};
    BOOST_REQUIRE(parsed);
    parsed->descs.resize(1);
    std::string descriptor{parsed->descs.front()};
    const size_t checksum_marker{descriptor.rfind('#')};
    BOOST_REQUIRE_NE(checksum_marker, std::string::npos);
    descriptor.resize(checksum_marker);
    ReplaceAll(descriptor, recovery.xpub, xprv);
    const std::string checksum{GetDescriptorChecksum(descriptor)};
    BOOST_REQUIRE(!checksum.empty());
    parsed->descs.front() = descriptor + "#" + checksum;
    parsed->policy_id.clear();
    return FormatVaultPolicyPackage(*parsed);
}

std::string WithExtraSecretField(std::string json, std::string_view field, std::string_view value)
{
    const size_t object_end{json.rfind("\n}")};
    BOOST_REQUIRE_NE(object_end, std::string::npos);
    json.insert(object_end, ",\n  \"" + std::string{field} + "\": \"" + std::string{value} + "\"");
    return json;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(vault_policy_qr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(deterministic_roundtrip_and_metadata)
{
    const PolicyData policy{MakePolicy("vault_policy_qr_roundtrip")};
    auto encoded{EncodeVaultPolicyQrParts(policy.json)};
    BOOST_REQUIRE_MESSAGE(encoded, util::ErrorString(encoded).original);
    BOOST_REQUIRE_GT(encoded->size(), 1U);

    auto encoded_again{EncodeVaultPolicyQrParts(policy.json)};
    BOOST_REQUIRE(encoded_again);
    BOOST_CHECK(*encoded == *encoded_again);

    const std::string expected_hash{Sha256Hex(policy.json)};
    for (size_t index = 0; index < encoded->size(); ++index) {
        BOOST_CHECK_LE(encoded->at(index).size(), VAULT_POLICY_QR_MAX_PART_SIZE);
        auto info{InspectVaultPolicyQrPart(encoded->at(index))};
        BOOST_REQUIRE_MESSAGE(info, util::ErrorString(info).original);
        BOOST_CHECK_EQUAL(info->policy_sha256, expected_hash);
        BOOST_CHECK_EQUAL(info->index, index + 1);
        BOOST_CHECK_EQUAL(info->total, encoded->size());
    }

    auto decoded{ReassembleVaultPolicyQrParts(*encoded)};
    BOOST_REQUIRE_MESSAGE(decoded, util::ErrorString(decoded).original);
    BOOST_CHECK_EQUAL(*decoded, policy.json);

    std::reverse(encoded->begin(), encoded->end());
    auto reordered{ReassembleVaultPolicyQrParts(*encoded)};
    BOOST_REQUIRE(!reordered);
    BOOST_CHECK(util::ErrorString(reordered).original.find("out of order") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_incomplete_duplicate_mixed_and_inconsistent_sets)
{
    const PolicyData first{MakePolicy("vault_policy_qr_set_a")};
    const PolicyData second{MakePolicy("vault_policy_qr_set_b")};
    auto first_parts{EncodeVaultPolicyQrParts(first.json)};
    auto second_parts{EncodeVaultPolicyQrParts(second.json)};
    BOOST_REQUIRE(first_parts);
    BOOST_REQUIRE(second_parts);
    BOOST_REQUIRE_GT(first_parts->size(), 1U);

    std::vector<std::string> empty;
    BOOST_CHECK(!ReassembleVaultPolicyQrParts(empty));

    auto missing{*first_parts};
    missing.erase(missing.begin() + missing.size() / 2);
    auto missing_result{ReassembleVaultPolicyQrParts(missing)};
    BOOST_REQUIRE(!missing_result);
    BOOST_CHECK(util::ErrorString(missing_result).original.find("incomplete") != std::string::npos);

    auto duplicate{*first_parts};
    duplicate.push_back(duplicate.front());
    auto duplicate_result{ReassembleVaultPolicyQrParts(duplicate)};
    BOOST_REQUIRE(!duplicate_result);
    BOOST_CHECK(util::ErrorString(duplicate_result).original.find("duplicated") != std::string::npos);

    std::vector<std::string> mixed{first_parts->front(), second_parts->back()};
    auto mixed_result{ReassembleVaultPolicyQrParts(mixed)};
    BOOST_REQUIRE(!mixed_result);
    BOOST_CHECK(util::ErrorString(mixed_result).original.find("different policies") != std::string::npos);

    auto inconsistent{*first_parts};
    auto first_fields{Split(inconsistent.front())};
    BOOST_REQUIRE_EQUAL(first_fields.size(), 7U);
    inconsistent.front() = RewritePart(inconsistent.front(), /*total=*/4,
                                       std::to_string(first_parts->size() + 1));
    auto inconsistent_result{ReassembleVaultPolicyQrParts(inconsistent)};
    BOOST_REQUIRE(!inconsistent_result);
    BOOST_CHECK(util::ErrorString(inconsistent_result).original.find("total part count") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_malformed_out_of_range_and_corrupt_parts)
{
    const PolicyData policy{MakePolicy("vault_policy_qr_corruption")};
    auto parts{EncodeVaultPolicyQrParts(policy.json)};
    BOOST_REQUIRE(parts);
    BOOST_REQUIRE_GT(parts->size(), 1U);

    BOOST_CHECK(!InspectVaultPolicyQrPart("not-a-part"));
    BOOST_CHECK(!InspectVaultPolicyQrPart(parts->front() + "|extra"));
    BOOST_CHECK(!InspectVaultPolicyQrPart(RewritePart(parts->front(), /*format=*/0, "OTHER")));
    BOOST_CHECK(!InspectVaultPolicyQrPart(RewritePart(parts->front(), /*version=*/1, "2")));
    BOOST_CHECK(!InspectVaultPolicyQrPart(RewritePart(parts->front(), /*index=*/3, "0")));
    BOOST_CHECK(!InspectVaultPolicyQrPart(RewritePart(parts->front(), /*total=*/4, "999999")));
    BOOST_CHECK(!InspectVaultPolicyQrPart(RewritePart(parts->front(), /*payload=*/5, "*")));

    auto bad_part_checksum{parts->front()};
    bad_part_checksum.back() = bad_part_checksum.back() == '0' ? '1' : '0';
    auto checksum_result{InspectVaultPolicyQrPart(bad_part_checksum)};
    BOOST_REQUIRE(!checksum_result);
    BOOST_CHECK(util::ErrorString(checksum_result).original.find("checksum does not match") != std::string::npos);

    auto corrupt_set{*parts};
    auto fields{Split(corrupt_set.front())};
    BOOST_REQUIRE_EQUAL(fields.size(), 7U);
    BOOST_REQUIRE(!fields[5].empty());
    fields[5][0] = fields[5][0] == 'A' ? 'B' : 'A';
    corrupt_set.front() = RewritePart(corrupt_set.front(), /*payload=*/5, fields[5]);
    auto corrupt_result{ReassembleVaultPolicyQrParts(corrupt_set)};
    BOOST_REQUIRE(!corrupt_result);
    BOOST_CHECK(util::ErrorString(corrupt_result).original.find("checksum does not match") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_noncanonical_and_private_policy_data)
{
    const PolicyData policy{MakePolicy("vault_policy_qr_private")};

    auto wrong_type_result{EncodeVaultPolicyQrParts(
        "{\"format\":1,\"version\":1,\"policy_id\":\"\",\"network\":\"regtest\","
        "\"nrequired\":1,\"descs\":[]}\n")};
    BOOST_REQUIRE(!wrong_type_result);
    BOOST_CHECK(util::ErrorString(wrong_type_result).original.find("malformed") != std::string::npos);

    std::string noncanonical{policy.json};
    BOOST_REQUIRE(!noncanonical.empty());
    noncanonical.pop_back();
    auto noncanonical_result{EncodeVaultPolicyQrParts(noncanonical)};
    BOOST_REQUIRE(!noncanonical_result);
    BOOST_CHECK(util::ErrorString(noncanonical_result).original.find("canonical") != std::string::npos);

    static constexpr std::string_view MNEMONIC{
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"};
    auto mnemonic_result{EncodeVaultPolicyQrParts(WithExtraSecretField(policy.json, "mnemonic", MNEMONIC))};
    BOOST_REQUIRE(!mnemonic_result);
    BOOST_CHECK(util::ErrorString(mnemonic_result).original.find("extra fields") != std::string::npos);

    auto xprv_field_result{EncodeVaultPolicyQrParts(WithExtraSecretField(policy.json, "xprv", "tprv-secret"))};
    BOOST_REQUIRE(!xprv_field_result);
    BOOST_CHECK(util::ErrorString(xprv_field_result).original.find("extra fields") != std::string::npos);

    auto private_descriptor_result{EncodeVaultPolicyQrParts(PrivatePolicyJson(policy))};
    BOOST_REQUIRE(!private_descriptor_result);

    auto public_parts{EncodeVaultPolicyQrParts(policy.json)};
    BOOST_REQUIRE(public_parts);
    for (const std::string& part : *public_parts) {
        BOOST_CHECK(part.find("mnemonic") == std::string::npos);
        BOOST_CHECK(part.find("xprv") == std::string::npos);
        BOOST_CHECK(part.find("tprv") == std::string::npos);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
