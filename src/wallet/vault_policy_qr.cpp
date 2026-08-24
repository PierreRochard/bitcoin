// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/vault_policy_qr.h>

#include <crypto/sha256.h>
#include <script/descriptor.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/multisig.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {
namespace {

constexpr size_t CHUNK_BYTES{72};
constexpr size_t PART_CHECKSUM_BYTES{16};
constexpr size_t MAX_POLICY_BYTES{1U << 20};
constexpr uint32_t MAX_PARTS{static_cast<uint32_t>((MAX_POLICY_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES)};
constexpr size_t FIELD_COUNT{7};

struct ParsedPart {
    VaultPolicyQrPartInfo info;
    std::vector<unsigned char> chunk;
};

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

std::string PartChecksum(std::string_view body)
{
    const auto digest{Sha256(body)};
    return HexStr(std::span{digest}.first(PART_CHECKSUM_BYTES));
}

bool IsLowerHex(std::string_view value, size_t expected_size)
{
    return value.size() == expected_size && IsHex(value) &&
           std::none_of(value.begin(), value.end(), [](char ch) { return ch >= 'A' && ch <= 'F'; });
}

util::Result<void> ValidateCanonicalPublicPolicy(std::string_view policy_json)
{
    if (policy_json.empty() || policy_json.size() > MAX_POLICY_BYTES) {
        return util::Error{Untranslated("Vault policy QR input size is out of range")};
    }

    auto parse_package{[&]() -> util::Result<VaultPolicyPackage> {
        try {
            return ParseVaultPolicyPackage(std::string{policy_json});
        } catch (const std::exception&) {
            return util::Error{Untranslated("Vault policy QR input is malformed")};
        }
    }};
    auto package{parse_package()};
    if (!package) return util::Error{util::ErrorString(package)};

    for (const std::string& descriptor : package->descs) {
        FlatSigningProvider keys;
        std::string error;
        auto parsed{Parse(descriptor, keys, error, /*require_checksum=*/true)};
        if (parsed.empty()) {
            return util::Error{Untranslated(strprintf("Vault policy QR descriptor is invalid: %s", error))};
        }
        for (const auto& item : parsed) {
            std::string private_descriptor;
            if (item->ToPrivateString(keys, private_descriptor)) {
                return util::Error{Untranslated("Vault policy QR input contains private key material")};
            }
        }
        if (!keys.keys.empty()) {
            return util::Error{Untranslated("Vault policy QR input contains private keys")};
        }
    }

    if (FormatVaultPolicyPackage(*package) != policy_json) {
        return util::Error{Untranslated("Vault policy QR input must be canonical policy JSON without extra fields")};
    }
    return {};
}

util::Result<std::array<std::string_view, FIELD_COUNT>> SplitFields(std::string_view encoded)
{
    std::array<std::string_view, FIELD_COUNT> fields;
    size_t begin{0};
    for (size_t field_index = 0; field_index < FIELD_COUNT; ++field_index) {
        const size_t separator{encoded.find('|', begin)};
        const bool last{field_index + 1 == FIELD_COUNT};
        if ((!last && separator == std::string_view::npos) ||
            (last && separator != std::string_view::npos)) {
            return util::Error{Untranslated("Malformed vault policy QR part")};
        }
        const size_t end{last ? encoded.size() : separator};
        fields[field_index] = encoded.substr(begin, end - begin);
        if (fields[field_index].empty()) {
            return util::Error{Untranslated("Malformed vault policy QR part")};
        }
        begin = end + 1;
    }
    return fields;
}

util::Result<ParsedPart> ParsePart(std::string_view encoded)
{
    if (encoded.empty() || encoded.size() > VAULT_POLICY_QR_MAX_PART_SIZE) {
        return util::Error{Untranslated("Vault policy QR part size is out of range")};
    }
    auto fields_result{SplitFields(encoded)};
    if (!fields_result) return util::Error{util::ErrorString(fields_result)};
    const auto& fields{*fields_result};

    if (fields[0] != VAULT_POLICY_QR_FORMAT) {
        return util::Error{Untranslated("Unknown vault policy QR format")};
    }
    const auto version{ToIntegral<uint32_t>(fields[1])};
    if (!version || *version != VAULT_POLICY_QR_VERSION || std::to_string(*version) != fields[1]) {
        return util::Error{Untranslated("Unsupported vault policy QR version")};
    }
    if (!IsLowerHex(fields[2], CSHA256::OUTPUT_SIZE * 2)) {
        return util::Error{Untranslated("Malformed vault policy QR policy checksum")};
    }
    const auto index{ToIntegral<uint32_t>(fields[3])};
    const auto total{ToIntegral<uint32_t>(fields[4])};
    if (!index || !total || *index == 0 || *index > *total || *total > MAX_PARTS ||
        std::to_string(*index) != fields[3] || std::to_string(*total) != fields[4]) {
        return util::Error{Untranslated("Vault policy QR part index or total is out of range")};
    }
    if (!IsLowerHex(fields[6], PART_CHECKSUM_BYTES * 2)) {
        return util::Error{Untranslated("Malformed vault policy QR part checksum")};
    }
    const size_t checksum_separator{encoded.rfind('|')};
    if (checksum_separator == std::string_view::npos ||
        PartChecksum(encoded.substr(0, checksum_separator)) != fields[6]) {
        return util::Error{Untranslated("Vault policy QR part checksum does not match")};
    }

    auto chunk{DecodeBase64(fields[5])};
    if (!chunk || chunk->empty() || chunk->size() > CHUNK_BYTES || EncodeBase64(*chunk) != fields[5]) {
        return util::Error{Untranslated("Vault policy QR part payload is malformed")};
    }
    if (*index < *total && chunk->size() != CHUNK_BYTES) {
        return util::Error{Untranslated("Vault policy QR non-final part has the wrong size")};
    }

    ParsedPart out;
    out.info.policy_sha256 = std::string{fields[2]};
    out.info.index = *index;
    out.info.total = *total;
    out.chunk = std::move(*chunk);
    return out;
}

} // namespace

util::Result<std::vector<std::string>> EncodeVaultPolicyQrParts(std::string_view canonical_policy_json)
{
    auto valid{ValidateCanonicalPublicPolicy(canonical_policy_json)};
    if (!valid) return util::Error{util::ErrorString(valid)};

    const std::string policy_hash{Sha256Hex(canonical_policy_json)};
    const size_t part_count{(canonical_policy_json.size() + CHUNK_BYTES - 1) / CHUNK_BYTES};
    if (part_count == 0 || part_count > MAX_PARTS || part_count > std::numeric_limits<uint32_t>::max()) {
        return util::Error{Untranslated("Vault policy QR requires too many parts")};
    }

    std::vector<std::string> parts;
    parts.reserve(part_count);
    for (size_t part_index = 0; part_index < part_count; ++part_index) {
        const size_t offset{part_index * CHUNK_BYTES};
        const std::string_view chunk{canonical_policy_json.substr(offset, CHUNK_BYTES)};
        const std::string body{strprintf("%s|%u|%s|%u|%u|%s",
                                         VAULT_POLICY_QR_FORMAT,
                                         VAULT_POLICY_QR_VERSION,
                                         policy_hash,
                                         part_index + 1,
                                         part_count,
                                         EncodeBase64(chunk))};
        std::string encoded{body + "|" + PartChecksum(body)};
        if (encoded.size() > VAULT_POLICY_QR_MAX_PART_SIZE) {
            return util::Error{Untranslated("Vault policy QR part exceeds the supported QR payload size")};
        }
        parts.push_back(std::move(encoded));
    }
    return parts;
}

util::Result<VaultPolicyQrPartInfo> InspectVaultPolicyQrPart(std::string_view encoded_part)
{
    auto parsed{ParsePart(encoded_part)};
    if (!parsed) return util::Error{util::ErrorString(parsed)};
    return parsed->info;
}

util::Result<std::string> ReassembleVaultPolicyQrParts(std::span<const std::string> encoded_parts)
{
    if (encoded_parts.empty() || encoded_parts.size() > MAX_PARTS) {
        return util::Error{Untranslated("Vault policy QR part set is empty or too large")};
    }

    std::string policy_hash;
    uint32_t expected_total{0};
    std::map<uint32_t, std::vector<unsigned char>> chunks;
    std::vector<uint32_t> input_order;
    input_order.reserve(encoded_parts.size());
    for (const std::string& encoded : encoded_parts) {
        auto part{ParsePart(encoded)};
        if (!part) return util::Error{util::ErrorString(part)};
        if (policy_hash.empty()) {
            policy_hash = part->info.policy_sha256;
            expected_total = part->info.total;
        } else if (part->info.policy_sha256 != policy_hash) {
            return util::Error{Untranslated("Vault policy QR parts belong to different policies")};
        } else if (part->info.total != expected_total) {
            return util::Error{Untranslated("Vault policy QR parts disagree on the total part count")};
        }
        if (chunks.contains(part->info.index)) {
            return util::Error{Untranslated("Vault policy QR part index is duplicated")};
        }
        input_order.push_back(part->info.index);
        chunks.emplace(part->info.index, std::move(part->chunk));
    }

    if (chunks.size() != expected_total) {
        return util::Error{Untranslated("Vault policy QR part set is incomplete")};
    }
    for (size_t position = 0; position < input_order.size(); ++position) {
        if (input_order[position] != position + 1) {
            return util::Error{Untranslated("Vault policy QR parts are out of order")};
        }
    }
    std::string policy_json;
    policy_json.reserve(std::min<size_t>(MAX_POLICY_BYTES, expected_total * CHUNK_BYTES));
    for (uint32_t index = 1; index <= expected_total; ++index) {
        const auto it{chunks.find(index)};
        if (it == chunks.end()) {
            return util::Error{Untranslated("Vault policy QR part set is incomplete")};
        }
        policy_json.append(reinterpret_cast<const char*>(it->second.data()), it->second.size());
        if (policy_json.size() > MAX_POLICY_BYTES) {
            return util::Error{Untranslated("Reassembled vault policy QR is too large")};
        }
    }
    if (Sha256Hex(policy_json) != policy_hash) {
        return util::Error{Untranslated("Reassembled vault policy QR checksum does not match")};
    }
    auto valid{ValidateCanonicalPublicPolicy(policy_json)};
    if (!valid) return util::Error{util::ErrorString(valid)};
    return policy_json;
}

} // namespace wallet
