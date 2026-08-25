// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_VAULT_RENEWAL_H
#define BITCOIN_WALLET_VAULT_RENEWAL_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <util/result.h>
#include <wallet/multisig.h>
#include <wallet/vault_state.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wallet {

class CCoinControl;
class CWallet;

/** Fourteen approximate days at Bitcoin's target block interval. */
inline constexpr uint32_t VAULT_RENEWAL_WARNING_BLOCKS{2'016};

enum class VaultRenewalScope : uint8_t {
    DUE,
    ALL,
    SELECTED,
    EARLY_OLDEST,
};

struct VaultRenewalExcludedAmount {
    size_t coin_count{0};
    CAmount value{0};
};

/**
 * Mutually exclusive reasons why active-policy coins are not eligible for a
 * protection-renewal transaction. Uneconomic coins are known only after a
 * feerate-specific batch has been prepared.
 */
struct VaultRenewalExclusions {
    VaultRenewalExcludedAmount locked;
    VaultRenewalExcludedAmount unsafe;
    VaultRenewalExcludedAmount unconfirmed;
    VaultRenewalExcludedAmount uneconomic;
};

/** Public, privacy-preserving summary of one existing address-linkage cluster. */
struct VaultRenewalCluster {
    std::string id;
    CAmount value{0};
    size_t coin_count{0};
    bool due{false};
    bool recovery_enabled{false};
    int blocks_until_primary{0};
};

struct VaultRenewalStatus {
    bool supported{false};
    FixedVaultSchedule schedule{FixedVaultSchedule::CUSTOM};
    uint32_t primary_delay{0};
    uint32_t final_delay{0};
    std::string policy_commitment;

    //! Confirmed active-policy value grouped by on-chain authorization state.
    CAmount three_key_only{0};
    CAmount recovery_enabled{0};
    CAmount warning{0};
    CAmount unconfirmed{0};
    std::optional<int> next_expansion_blocks;

    std::vector<VaultRenewalCluster> clusters;
    VaultRenewalExclusions exclusions;
    //! Empty when no privacy cluster is due. Otherwise commits to the policy
    //! and every eligible outpoint in the current due-cluster set.
    std::string due_set_digest;
};

struct VaultRenewalRequest {
    VaultRenewalScope scope{VaultRenewalScope::DUE};
    //! Opaque ids returned by VaultRenewalStatus. Used only for SELECTED.
    std::vector<std::string> cluster_ids;
};

/** Internal inputs remain opaque to the GUI, but travel with the guarded plan. */
struct VaultRenewalPlanCluster {
    VaultRenewalCluster summary;
    std::vector<COutPoint> inputs;
};

struct VaultRenewalPlan {
    VaultRenewalRequest request;
    std::string policy_commitment;
    VaultCommitState expected_vault_state;
    //! Commits to the request and exact selected privacy-cluster membership.
    std::string source_digest;
    std::string due_set_digest;
    CAmount selected_value{0};
    size_t selected_coin_count{0};
    std::vector<VaultRenewalPlanCluster> clusters;
    VaultRenewalExclusions exclusions;
};

struct VaultRenewalTransaction {
    std::string cluster_id;
    std::vector<COutPoint> inputs;
    CTransactionRef tx;
    CAmount input_value{0};
    CAmount fee{0};
    CAmount output_value{0};
    bool signed_complete{false};
    std::optional<VaultCommitState> signed_vault_state;
};

struct VaultRenewalBatch {
    VaultRenewalRequest request;
    std::string policy_commitment;
    VaultCommitState expected_vault_state;
    std::string source_digest;
    std::string due_set_digest;
    //! Commits to every unsigned transaction and its cluster/input mapping.
    std::string batch_digest;
    std::vector<VaultRenewalTransaction> transactions;
    VaultRenewalExclusions exclusions;
    CAmount input_value{0};
    CAmount fee{0};
    CAmount output_value{0};
};

enum class VaultRenewalCommitOutcome : uint8_t {
    RELAYED,
    STORED_NOT_RELAYED,
    FAILED,
    ALREADY_ACCEPTED,
    NOT_ATTEMPTED,
};

struct VaultRenewalCommitItem {
    std::string cluster_id;
    Txid txid;
    VaultRenewalCommitOutcome outcome{VaultRenewalCommitOutcome::NOT_ATTEMPTED};
    std::string error;
};

struct VaultRenewalCommitResult {
    std::vector<VaultRenewalCommitItem> transactions;
};

/** Read current protection amounts, exclusions, privacy clusters, and reminder identity. */
VaultRenewalStatus GetVaultRenewalStatus(const CWallet& wallet);

/** Select a whole-cluster scope without reserving keys or creating transactions. */
util::Result<VaultRenewalPlan> PlanVaultRenewal(
    const CWallet& wallet, const VaultRenewalRequest& request);

/**
 * Revalidate a plan, split only for transaction weight, reserve one fresh
 * internal active-policy destination per transaction, and create an unsigned
 * exact-input batch whose fee is subtracted from its sole output.
 */
util::Result<VaultRenewalBatch> CreateVaultRenewalBatch(
    CWallet& wallet, const VaultRenewalPlan& plan, const CCoinControl& fee_control);

/** Directly sign one batch item through the immediate all-participant key path. */
util::Result<void> SignVaultRenewalTransaction(
    CWallet& wallet, VaultRenewalBatch& batch, size_t transaction_index);

/**
 * Revalidate the complete, fully signed batch before committing any item.
 * Relay failures are reported per transaction and do not obscure transactions
 * already stored in the wallet.
 */
util::Result<VaultRenewalCommitResult> CommitVaultRenewalBatch(
    CWallet& wallet, const VaultRenewalBatch& batch);

} // namespace wallet

#endif // BITCOIN_WALLET_VAULT_RENEWAL_H
