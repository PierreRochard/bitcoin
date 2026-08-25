// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_FIXED_VAULT_WALLET_H
#define BITCOIN_WALLET_FIXED_VAULT_WALLET_H

#include <support/allocators/secure.h>
#include <util/result.h>
#include <util/translation.h>
#include <wallet/multisig.h>
#include <wallet/vault_state.h>

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace wallet {

class CWallet;
struct WalletContext;

enum class FixedVaultWalletInstallMode {
    CREATE,
    RESTORE,
};

struct FixedVaultWalletInstallResult {
    std::shared_ptr<CWallet> wallet;
    std::vector<VaultMnemonicMatch> mnemonic_matches;
    std::optional<std::string> first_receive_address;
};

/** Metadata that must be durable before an RPC-created wallet is published. */
struct FixedVaultWalletInitialMetadata {
    VaultSetupState setup_state;
    VaultVerificationState verification_state;
    std::optional<VaultParticipantType> mnemonic_participant_type;
    bool create_receive_address{false};
};

/**
 * Validate and install one canonical consumer Recovery Vault through an
 * owner-controlled SQLite staging wallet. The final wallet name is published
 * atomically only after every descriptor, mnemonic, and durable incomplete
 * setup marker has been written and revalidated.
 */
util::Result<FixedVaultWalletInstallResult> InstallFixedVaultWallet(
    WalletContext& context,
    const std::string& name,
    const std::string& canonical_package,
    std::span<const SecureString> mnemonics,
    FixedVaultWalletInstallMode mode,
    std::vector<bilingual_str>& warnings,
    bool enable_external_signing = false,
    std::optional<FixedVaultWalletInitialMetadata> initial_metadata = std::nullopt);

} // namespace wallet

#endif // BITCOIN_WALLET_FIXED_VAULT_WALLET_H
