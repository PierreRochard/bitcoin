// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_VAULT_STATE_H
#define BITCOIN_WALLET_VAULT_STATE_H

#include <cstdint>
#include <set>
#include <string>

namespace wallet {

/** Durable progress through the consumer Recovery Vault setup journey. */
enum class VaultSetupState : uint8_t {
    NOT_RECORDED = 0,
    RECOVERY_KIT_REQUIRED = 1,
    ADDRESS_VERIFICATION_REQUIRED = 2,
    COMPLETE = 3,
};

/** Durable truth about the receive-address verification performed by a user. */
enum class VaultVerificationState : uint8_t {
    NOT_RECORDED = 0,
    PENDING = 1,
    RECOVERY_KIT_MATCHED = 2,
    INDEPENDENTLY_VERIFIED = 3,
    FINISHED_UNVERIFIED = 4,
};

/** Durable source classification for a Recovery Vault participant. */
enum class VaultParticipantType : uint8_t {
    UNKNOWN = 0,
    LOCAL_SOFTWARE = 1,
    HARDWARE = 2,
    AIR_GAPPED = 3,
};

/** Fresh runtime availability. This value is deliberately never persisted. */
enum class VaultSignerAvailability : uint8_t {
    UNKNOWN = 0,
    AVAILABLE = 1,
    UNAVAILABLE = 2,
};

/**
 * Safety-relevant Recovery Vault state captured while a transaction is
 * signed and compared again, under the wallet lock, before it is committed.
 */
struct VaultCommitState {
    std::string policy_commitment;
    std::set<std::string> manually_lost_signers;

    friend bool operator==(const VaultCommitState&, const VaultCommitState&) = default;
};

constexpr bool IsValidVaultSetupState(VaultSetupState state)
{
    return state >= VaultSetupState::NOT_RECORDED && state <= VaultSetupState::COMPLETE;
}

constexpr bool IsValidVaultVerificationState(VaultVerificationState state)
{
    return state >= VaultVerificationState::NOT_RECORDED &&
           state <= VaultVerificationState::FINISHED_UNVERIFIED;
}

constexpr bool IsValidVaultParticipantType(VaultParticipantType type)
{
    return type >= VaultParticipantType::UNKNOWN && type <= VaultParticipantType::AIR_GAPPED;
}

constexpr bool IsConsistentVaultState(VaultSetupState setup, VaultVerificationState verification)
{
    switch (setup) {
    case VaultSetupState::NOT_RECORDED:
        return verification == VaultVerificationState::NOT_RECORDED;
    case VaultSetupState::RECOVERY_KIT_REQUIRED:
        return verification == VaultVerificationState::PENDING;
    case VaultSetupState::ADDRESS_VERIFICATION_REQUIRED:
        return verification == VaultVerificationState::PENDING ||
               verification == VaultVerificationState::RECOVERY_KIT_MATCHED;
    case VaultSetupState::COMPLETE:
        return verification == VaultVerificationState::INDEPENDENTLY_VERIFIED ||
               verification == VaultVerificationState::FINISHED_UNVERIFIED;
    }
    return false;
}

} // namespace wallet

#endif // BITCOIN_WALLET_VAULT_STATE_H
