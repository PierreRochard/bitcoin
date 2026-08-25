// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RECOVERY_VAULT_KIT_H
#define BITCOIN_WALLET_RECOVERY_VAULT_KIT_H

#include <support/allocators/secure.h>
#include <util/fs.h>
#include <util/result.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {

/** Return true only for a bounded wallet name with no path or control characters. */
bool IsValidRecoveryVaultWalletName(std::string_view name);

struct RecoveryVaultKitSummary {
    fs::path path;
    std::string wallet_name;
    std::string network;
    std::string policy_id;
    std::string policy_commitment;
    std::string kit_commitment;
    std::string canonical_policy;
    size_t software_key_count{0};
};

struct RecoveryVaultKitMaterial {
    RecoveryVaultKitSummary summary;
    std::vector<SecureString> mnemonics;

    RecoveryVaultKitMaterial() = default;
    RecoveryVaultKitMaterial(RecoveryVaultKitMaterial&&) = default;
    RecoveryVaultKitMaterial& operator=(RecoveryVaultKitMaterial&&) = default;
    RecoveryVaultKitMaterial(const RecoveryVaultKitMaterial&) = delete;
    RecoveryVaultKitMaterial& operator=(const RecoveryVaultKitMaterial&) = delete;
    ~RecoveryVaultKitMaterial();
};

/**
 * Generate the current three-software-key 90/180 Recovery Vault candidate and
 * persist its complete human-readable Recovery Kit into a new private
 * directory. No wallet database is created. The target must be absolute,
 * outside forbidden_root, and must not already exist.
 */
util::Result<RecoveryVaultKitSummary> PrepareRecoveryVaultKit(
    const fs::path& target,
    const std::string& wallet_name,
    const std::string& network,
    const fs::path& forbidden_root);

/**
 * Reopen a prepared kit without returning its phrases to RPC callers. Every
 * file, permission, public-policy field, phrase-to-xpub match, and the caller's
 * full kit commitment is validated before material is returned in locked,
 * cleansing memory.
 */
util::Result<RecoveryVaultKitMaterial> ReadRecoveryVaultKit(
    const fs::path& target,
    const std::string& expected_kit_commitment,
    const std::string& expected_network,
    const fs::path& forbidden_root);

} // namespace wallet

#endif // BITCOIN_WALLET_RECOVERY_VAULT_KIT_H
