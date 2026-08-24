// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_VAULT_POLICY_QR_H
#define BITCOIN_WALLET_VAULT_POLICY_QR_H

#include <util/result.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {

//! Stable identifier for the multipart public-policy QR transport.
inline constexpr std::string_view VAULT_POLICY_QR_FORMAT{"BCVP"};
inline constexpr uint32_t VAULT_POLICY_QR_VERSION{1};

//! Kept below QRImageWidget's 255-character limit. The encoder currently
//! produces at most 213 characters, including worst-case part counters.
inline constexpr size_t VAULT_POLICY_QR_MAX_PART_SIZE{220};

struct VaultPolicyQrPartInfo {
    std::string policy_sha256;
    uint32_t index{0}; //!< One-based part index.
    uint32_t total{0};
};

/** Encode canonical, public-only vault policy JSON as deterministic QR parts.
 *
 * The input must be byte-for-byte equal to FormatVaultPolicyPackage() output.
 * This prevents ignored JSON fields or alternate encodings from carrying
 * mnemonic/private-key material alongside an otherwise valid policy.
 */
util::Result<std::vector<std::string>> EncodeVaultPolicyQrParts(std::string_view canonical_policy_json);

//! Validate one part's syntax and checksum and return progress metadata.
util::Result<VaultPolicyQrPartInfo> InspectVaultPolicyQrPart(std::string_view encoded_part);

/** Reassemble QR parts in arbitrary input order and return the exact canonical
 * policy bytes supplied to EncodeVaultPolicyQrParts().
 */
util::Result<std::string> ReassembleVaultPolicyQrParts(std::span<const std::string> encoded_parts);

} // namespace wallet

#endif // BITCOIN_WALLET_VAULT_POLICY_QR_H
