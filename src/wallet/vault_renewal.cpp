// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/vault_renewal.h>

#include <addresstype.h>
#include <common/messages.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <node/types.h>
#include <outputtype.h>
#include <policy/policy.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <functional>
#include <map>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <utility>

namespace wallet {
namespace {

struct RenewalCoin {
    COutput output;
    CTxDestination destination;
    int blocks_until_primary{0};
};

struct RenewalClusterInternal {
    VaultRenewalCluster summary;
    std::vector<RenewalCoin> coins;
};

struct RenewalSnapshot {
    VaultRenewalStatus status;
    VaultCommitState state;
    std::vector<RenewalClusterInternal> clusters;
};

std::string DigestOutpoints(std::string_view tag, const std::string& policy_commitment,
                            const std::vector<COutPoint>& outpoints)
{
    return (HashWriter{} << std::string{tag} << policy_commitment << outpoints).GetHash().GetHex();
}

VaultCommitState CurrentVaultState(const CWallet& wallet, const std::string& policy_commitment)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    VaultCommitState state;
    state.policy_commitment = policy_commitment;
    if (wallet.m_vault_metadata_policy_commitment == policy_commitment) {
        state.manually_lost_signers = wallet.m_manually_lost_signers;
    }
    return state;
}

void AddExcluded(VaultRenewalExcludedAmount& excluded, CAmount value)
{
    ++excluded.coin_count;
    excluded.value += value;
}

bool HasActiveReplacement(const CWallet& wallet, const CWalletTx& transaction)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    // A replacement marker is historical metadata. If the original is later
    // reaccepted or confirmed it is authoritative again, even if the marker
    // remains in the wallet database.
    if (transaction.isConfirmed() ||
        wallet.chain().isInMempool(transaction.GetHash())) {
        return false;
    }
    if (!transaction.m_replaced_by_txid) return false;
    const auto replacement{wallet.mapWallet.find(*transaction.m_replaced_by_txid)};
    return replacement != wallet.mapWallet.end() &&
           !replacement->second.isAbandoned() &&
           !replacement->second.isBlockConflicted() &&
           !replacement->second.isMempoolConflicted();
}

std::string GroupingKey(const std::set<CTxDestination>& grouping)
{
    std::vector<CScript> scripts;
    scripts.reserve(grouping.size());
    for (const CTxDestination& destination : grouping) {
        scripts.push_back(GetScriptForDestination(destination));
    }
    return (HashWriter{} << std::string{"vault-renewal-address-group-v1"} << scripts).GetHash().GetHex();
}

std::string ClusterId(const std::string& policy_commitment, const std::string& grouping_key,
                      const std::vector<RenewalCoin>& coins)
{
    std::vector<COutPoint> outpoints;
    outpoints.reserve(coins.size());
    for (const RenewalCoin& coin : coins)
        outpoints.push_back(coin.output.outpoint);
    std::ranges::sort(outpoints, std::less<>{});
    return (HashWriter{} << std::string{"vault-renewal-cluster-v1"} << policy_commitment << grouping_key << outpoints).GetHash().GetHex();
}

RenewalSnapshot BuildSnapshot(const CWallet& wallet)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    RenewalSnapshot snapshot;
    const VaultPolicyPackage package{ExportWalletVaultPolicy(wallet)};
    const InferredVaultPolicy policy{InferWalletVaultPolicy(wallet)};
    snapshot.status.schedule = ClassifyFixedVaultSchedule(package);
    if (!package.policy_id.empty()) {
        snapshot.status.policy_commitment = VaultPolicyCommitment(package);
    }
    snapshot.state = CurrentVaultState(wallet, snapshot.status.policy_commitment);

    if (!policy.is_vault || policy.recovery_stages.empty() ||
        !policy.recovery_stages.front().older || snapshot.status.policy_commitment.empty()) {
        return snapshot;
    }
    snapshot.status.primary_delay = *policy.recovery_stages.front().older;
    if (policy.recovery_stages.size() > 1 && policy.recovery_stages[1].older) {
        snapshot.status.final_delay = *policy.recovery_stages[1].older;
    }
    snapshot.status.supported =
        snapshot.status.schedule == FixedVaultSchedule::CURRENT_90_180 &&
        bool(ValidateFixedStagedVaultPolicy(package));
    if (!wallet.HaveChain() || !wallet.HasProcessedBlock()) return snapshot;

    // Include unsafe and locked confirmed coins so eligibility reasons can be
    // distinguished without ever widening the eventual transaction boundary.
    CCoinControl broad_control;
    broad_control.m_min_depth = 1;
    broad_control.m_include_unsafe_inputs = true;
    broad_control.m_avoid_address_reuse = false;
    CoinFilterParams broad_params;
    broad_params.skip_locked = false;
    std::map<COutPoint, COutput> confirmed_candidates;
    for (COutput& coin : AvailableCoins(wallet, &broad_control, /*feerate=*/std::nullopt,
                                        broad_params)
                             .All()) {
        confirmed_candidates.emplace(coin.outpoint, std::move(coin));
    }

    const auto address_groupings{GetAddressGroupings(wallet)};
    std::map<CTxDestination, std::string> address_group_keys;
    for (const auto& grouping : address_groupings) {
        const std::string key{GroupingKey(grouping)};
        for (const CTxDestination& destination : grouping) {
            address_group_keys.emplace(destination, key);
        }
    }

    std::map<std::string, std::vector<RenewalCoin>> grouped_coins;
    const int primary_delay{static_cast<int>(snapshot.status.primary_delay)};
    for (const auto& [outpoint, txo] : wallet.GetTXOs()) {
        // An abandoned self-transfer no longer spends its parents and its
        // outputs have no prospect of confirmation. Ignore those outputs so
        // the original coins immediately regain their truthful protection
        // state instead of being double counted as pending renewal value.
        const CWalletTx& transaction{txo.GetWalletTx()};
        if (!IsActiveVaultOutput(wallet, txo.GetTxOut()) ||
            transaction.isAbandoned() ||
            HasActiveReplacement(wallet, transaction) ||
            wallet.IsSpent(outpoint)) {
            continue;
        }
        if (transaction.isMempoolConflicted()) {
            if (snapshot.status.supported) {
                AddExcluded(snapshot.status.exclusions.unsafe,
                            txo.GetTxOut().nValue);
            }
            continue;
        }
        const int depth{wallet.GetTxDepthInMainChain(transaction)};
        if (depth < 0) {
            if (snapshot.status.supported) {
                AddExcluded(snapshot.status.exclusions.unsafe, txo.GetTxOut().nValue);
            }
            continue;
        }

        if (depth == 0) {
            snapshot.status.unconfirmed += txo.GetTxOut().nValue;
            AddExcluded(snapshot.status.exclusions.unconfirmed, txo.GetTxOut().nValue);
            continue;
        }

        const int primary_remaining{std::max(0, primary_delay - depth)};
        if (primary_remaining == 0) {
            snapshot.status.recovery_enabled += txo.GetTxOut().nValue;
        } else {
            snapshot.status.three_key_only += txo.GetTxOut().nValue;
            if (primary_remaining <= static_cast<int>(VAULT_RENEWAL_WARNING_BLOCKS)) {
                snapshot.status.warning += txo.GetTxOut().nValue;
            }
        }
        int next_expansion{primary_remaining};
        if (next_expansion == 0 && snapshot.status.final_delay > 0) {
            next_expansion = std::max(0, static_cast<int>(snapshot.status.final_delay) - depth);
        }
        if (next_expansion > 0 &&
            (!snapshot.status.next_expansion_blocks ||
             next_expansion < *snapshot.status.next_expansion_blocks)) {
            snapshot.status.next_expansion_blocks = next_expansion;
        }

        if (!snapshot.status.supported) continue;
        const auto candidate{confirmed_candidates.find(outpoint)};
        if (candidate == confirmed_candidates.end()) {
            AddExcluded(snapshot.status.exclusions.unsafe, txo.GetTxOut().nValue);
            continue;
        }
        if (wallet.IsLockedCoin(outpoint)) {
            AddExcluded(snapshot.status.exclusions.locked, txo.GetTxOut().nValue);
            continue;
        }
        if (!candidate->second.safe) {
            AddExcluded(snapshot.status.exclusions.unsafe, txo.GetTxOut().nValue);
            continue;
        }

        CTxDestination destination;
        if (!ExtractDestination(txo.GetTxOut().scriptPubKey, destination)) {
            AddExcluded(snapshot.status.exclusions.unsafe, txo.GetTxOut().nValue);
            continue;
        }
        auto group_key{address_group_keys.find(destination)};
        const std::string key{group_key != address_group_keys.end() ? group_key->second : GroupingKey(std::set<CTxDestination>{destination})};
        grouped_coins[key].push_back({candidate->second, std::move(destination), primary_remaining});
    }

    std::vector<COutPoint> due_outpoints;
    for (auto& [grouping_key, coins] : grouped_coins) {
        std::ranges::sort(coins, std::less<>{}, [](const RenewalCoin& coin) { return coin.output.outpoint; });
        RenewalClusterInternal cluster;
        cluster.summary.id = ClusterId(snapshot.status.policy_commitment, grouping_key, coins);
        cluster.coins = std::move(coins);
        cluster.summary.coin_count = cluster.coins.size();
        cluster.summary.blocks_until_primary = primary_delay;
        for (const RenewalCoin& coin : cluster.coins) {
            cluster.summary.value += coin.output.txout.nValue;
            cluster.summary.blocks_until_primary =
                std::min(cluster.summary.blocks_until_primary, coin.blocks_until_primary);
            cluster.summary.recovery_enabled |= coin.blocks_until_primary == 0;
            cluster.summary.due |= coin.blocks_until_primary <=
                                   static_cast<int>(VAULT_RENEWAL_WARNING_BLOCKS);
        }
        if (cluster.summary.due) {
            for (const RenewalCoin& coin : cluster.coins)
                due_outpoints.push_back(coin.output.outpoint);
        }
        snapshot.clusters.push_back(std::move(cluster));
    }
    std::ranges::sort(snapshot.clusters, {},
                      [](const RenewalClusterInternal& cluster) { return cluster.summary.id; });
    snapshot.status.clusters.reserve(snapshot.clusters.size());
    for (const auto& cluster : snapshot.clusters)
        snapshot.status.clusters.push_back(cluster.summary);
    if (!due_outpoints.empty()) {
        std::ranges::sort(due_outpoints, std::less<>{});
        snapshot.status.due_set_digest = DigestOutpoints(
            "vault-renewal-due-set-v1", snapshot.status.policy_commitment, due_outpoints);
    }
    return snapshot;
}

std::string PlanDigest(const VaultRenewalPlan& plan)
{
    HashWriter digest;
    digest << std::string{"vault-renewal-plan-v1"}
           << plan.policy_commitment
           << static_cast<uint8_t>(plan.request.scope)
           << plan.request.cluster_ids
           << plan.expected_vault_state.policy_commitment
           << plan.expected_vault_state.manually_lost_signers
           << plan.selected_value
           << static_cast<uint64_t>(plan.selected_coin_count);
    // The due-set changes a DUE selection and crossing into the warning window
    // invalidates EARLY_OLDEST. ALL and explicit SELECTED plans are committed
    // solely to their exact selected membership, so a new block cannot stale
    // an otherwise unchanged review.
    if (plan.request.scope == VaultRenewalScope::DUE ||
        plan.request.scope == VaultRenewalScope::EARLY_OLDEST) {
        digest << plan.due_set_digest;
    }
    // Global exclusions are display context, not selected membership. A new
    // unrelated unconfirmed coin or a lock on an unselected cluster must not
    // invalidate a reviewed batch. Each chosen input is revalidated at sign
    // and commit time.
    for (const VaultRenewalPlanCluster& cluster : plan.clusters) {
        digest << cluster.summary.id
               << cluster.summary.value
               << static_cast<uint64_t>(cluster.summary.coin_count)
               << cluster.inputs;
    }
    return digest.GetHash().GetHex();
}

util::Result<VaultRenewalPlan> PlanVaultRenewalLocked(
    const CWallet& wallet, const VaultRenewalRequest& request)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const RenewalSnapshot snapshot{BuildSnapshot(wallet)};
    if (!snapshot.status.supported) {
        return util::Error{Untranslated(
            "Three-key protection renewal is available only for the current 90/180-day Recovery Vault policy")};
    }

    std::vector<const RenewalClusterInternal*> selected;
    switch (request.scope) {
    case VaultRenewalScope::DUE:
        for (const auto& cluster : snapshot.clusters) {
            if (cluster.summary.due) selected.push_back(&cluster);
        }
        if (selected.empty()) {
            return util::Error{Untranslated("No Recovery Vault privacy cluster is due for protection renewal")};
        }
        break;
    case VaultRenewalScope::ALL:
        for (const auto& cluster : snapshot.clusters)
            selected.push_back(&cluster);
        if (selected.empty()) {
            return util::Error{Untranslated("No confirmed, safe, unlocked Recovery Vault coins are available to renew")};
        }
        break;
    case VaultRenewalScope::SELECTED: {
        if (request.cluster_ids.empty()) {
            return util::Error{Untranslated("Select at least one Recovery Vault privacy cluster")};
        }
        const std::set<std::string> wanted{request.cluster_ids.begin(), request.cluster_ids.end()};
        if (wanted.size() != request.cluster_ids.size()) {
            return util::Error{Untranslated("A Recovery Vault privacy cluster was selected more than once")};
        }
        for (const auto& cluster : snapshot.clusters) {
            if (wanted.contains(cluster.summary.id)) selected.push_back(&cluster);
        }
        if (selected.size() != wanted.size()) {
            return util::Error{Untranslated("A selected Recovery Vault privacy cluster is no longer available")};
        }
        break;
    }
    case VaultRenewalScope::EARLY_OLDEST: {
        if (std::ranges::any_of(snapshot.clusters,
                                [](const auto& cluster) { return cluster.summary.due; })) {
            return util::Error{Untranslated(
                "One or more Recovery Vault privacy clusters are already due; renew those clusters instead")};
        }
        if (snapshot.clusters.empty()) {
            return util::Error{Untranslated("No confirmed, safe, unlocked Recovery Vault coins are available to renew")};
        }
        selected.push_back(&*std::ranges::min_element(
            snapshot.clusters, [](const auto& left, const auto& right) {
                return std::tie(left.summary.blocks_until_primary, left.summary.id) <
                       std::tie(right.summary.blocks_until_primary, right.summary.id);
            }));
        break;
    }
    }

    VaultRenewalPlan plan;
    plan.request = request;
    if (plan.request.scope == VaultRenewalScope::SELECTED) {
        std::ranges::sort(plan.request.cluster_ids);
    } else {
        plan.request.cluster_ids.clear();
    }
    plan.policy_commitment = snapshot.status.policy_commitment;
    plan.expected_vault_state = snapshot.state;
    plan.due_set_digest = snapshot.status.due_set_digest;
    plan.exclusions = snapshot.status.exclusions;
    for (const RenewalClusterInternal* cluster : selected) {
        VaultRenewalPlanCluster planned;
        planned.summary = cluster->summary;
        planned.inputs.reserve(cluster->coins.size());
        for (const RenewalCoin& coin : cluster->coins) {
            planned.inputs.push_back(coin.output.outpoint);
        }
        plan.selected_value += planned.summary.value;
        plan.selected_coin_count += planned.summary.coin_count;
        plan.clusters.push_back(std::move(planned));
    }
    std::ranges::sort(plan.clusters, {},
                      [](const VaultRenewalPlanCluster& cluster) { return cluster.summary.id; });
    plan.source_digest = PlanDigest(plan);
    return plan;
}

bool SamePlan(const VaultRenewalPlan& expected, const VaultRenewalPlan& current)
{
    return expected.policy_commitment == current.policy_commitment &&
           expected.expected_vault_state == current.expected_vault_state &&
           expected.source_digest == current.source_digest;
}

CCoinControl RenewalCoinControl(const CCoinControl& requested,
                                const std::vector<COutPoint>& inputs)
{
    // Copy fee choices only. Recovery sequences, external solving data,
    // selections, change destinations, and unsafe-input relaxations are never
    // inherited from another send flow.
    CCoinControl control;
    control.fOverrideFeeRate = requested.fOverrideFeeRate;
    control.m_feerate = requested.m_feerate;
    control.m_confirm_target = requested.m_confirm_target;
    control.m_fee_mode = requested.m_fee_mode;
    control.m_signal_bip125_rbf = requested.m_signal_bip125_rbf;
    control.m_max_tx_weight = requested.m_max_tx_weight;
    control.m_change_type = OutputType::BECH32M;
    control.m_min_depth = 1;
    control.m_include_unsafe_inputs = false;
    control.m_avoid_address_reuse = false;
    control.m_allow_other_inputs = false;
    control.m_allowed_inputs = std::set<COutPoint>{inputs.begin(), inputs.end()};
    for (const COutPoint& input : inputs)
        control.Select(input);
    return control;
}

util::Result<std::vector<std::vector<COutPoint>>> SplitForWeight(
    const CWallet& wallet, const std::vector<COutPoint>& inputs,
    const CCoinControl& requested)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (inputs.empty()) return util::Error{Untranslated("A protection-renewal cluster has no inputs")};
    std::vector<std::vector<COutPoint>> pending{inputs};
    std::vector<std::vector<COutPoint>> result;
    const int max_weight{requested.m_max_tx_weight.value_or(MAX_STANDARD_TX_WEIGHT)};
    if (max_weight <= 0 || max_weight > MAX_STANDARD_TX_WEIGHT) {
        return util::Error{Untranslated("The requested protection-renewal transaction weight limit is invalid")};
    }

    while (!pending.empty()) {
        std::vector<COutPoint> chunk{std::move(pending.back())};
        pending.pop_back();
        CMutableTransaction probe;
        std::vector<CTxOut> previous_outputs;
        CAmount value{0};
        for (const COutPoint& input : chunk) {
            const auto txo{wallet.GetTXO(input)};
            if (!txo) return util::Error{Untranslated("A protection-renewal input is no longer in the wallet")};
            probe.vin.emplace_back(input, CScript{}, CTxIn::MAX_SEQUENCE_NONFINAL);
            previous_outputs.push_back(txo->GetTxOut());
            value += txo->GetTxOut().nValue;
        }
        probe.vout.emplace_back(value, previous_outputs.front().scriptPubKey);
        CCoinControl control{RenewalCoinControl(requested, chunk)};
        const TxSize size{CalculateMaximumSignedTxSize(CTransaction{probe}, &wallet,
                                                       previous_outputs, &control)};
        if (size.weight < 0) {
            return util::Error{Untranslated("Unable to estimate the immediate-key-path renewal transaction size")};
        }
        if (size.weight <= max_weight) {
            result.push_back(std::move(chunk));
            continue;
        }
        if (chunk.size() == 1) {
            return util::Error{Untranslated("A single Recovery Vault input exceeds the transaction weight limit")};
        }
        const auto middle{chunk.begin() + chunk.size() / 2};
        pending.emplace_back(chunk.begin(), middle);
        pending.emplace_back(middle, chunk.end());
    }
    std::ranges::sort(result, std::less<>{}, [](const std::vector<COutPoint>& chunk) { return chunk.front(); });
    return result;
}

bool IsUneconomicError(const bilingual_str& error)
{
    return error.original.find("too small") != std::string::npos;
}

std::set<COutPoint> InputSet(const CTransaction& tx)
{
    std::set<COutPoint> inputs;
    for (const CTxIn& input : tx.vin)
        inputs.insert(input.prevout);
    return inputs;
}

util::Result<void> ValidateTransactionShape(
    const CWallet& wallet, const VaultRenewalTransaction& item, bool require_key_path_witness)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!item.tx || item.tx->vin.empty() || item.tx->vout.size() != 1) {
        return util::Error{Untranslated("A protection-renewal transaction does not have the required one-output shape")};
    }
    const std::set<COutPoint> expected{item.inputs.begin(), item.inputs.end()};
    if (expected.size() != item.inputs.size() || InputSet(*item.tx) != expected ||
        item.tx->vin.size() != expected.size()) {
        return util::Error{Untranslated("A protection-renewal transaction input set changed after review")};
    }
    CAmount input_value{0};
    for (const CTxIn& input : item.tx->vin) {
        const auto txo{wallet.GetTXO(input.prevout)};
        if (!txo || !IsActiveVaultOutput(wallet, txo->GetTxOut())) {
            return util::Error{Untranslated("A protection-renewal input no longer belongs to the active Recovery Vault policy")};
        }
        if ((input.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0) {
            return util::Error{Untranslated("Protection renewal must use the immediate key path, not a delayed recovery sequence")};
        }
        if (!input.scriptSig.empty()) {
            return util::Error{Untranslated("A protection-renewal input contains an unexpected script signature")};
        }
        if (require_key_path_witness) {
            if (input.scriptWitness.stack.size() != 1 ||
                (input.scriptWitness.stack.front().size() != 64 &&
                 input.scriptWitness.stack.front().size() != 65)) {
                return util::Error{Untranslated("Protection renewal was not signed through the immediate Taproot key path")};
            }
        } else if (!input.scriptWitness.IsNull()) {
            return util::Error{Untranslated("An unsigned protection-renewal transaction already contains witness data")};
        }
        input_value += txo->GetTxOut().nValue;
    }

    ScriptPubKeyMan* const internal_manager{
        wallet.GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true)};
    const CTxOut& output{item.tx->vout.front()};
    if (!internal_manager || !internal_manager->IsMine(output.scriptPubKey) ||
        !IsActiveVaultOutput(wallet, output)) {
        return util::Error{Untranslated("Protection renewal must return funds to one fresh internal address under the same policy")};
    }
    if (input_value != item.input_value || output.nValue != item.output_value ||
        item.fee < 0 || input_value - output.nValue != item.fee) {
        return util::Error{Untranslated("A protection-renewal transaction amount or fee changed after review")};
    }
    return {};
}

util::Result<void> VerifySignedTransactionInputs(
    const CWallet& wallet, const VaultRenewalTransaction& item)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(item.tx->vin.size());
    for (const CTxIn& input : item.tx->vin) {
        const auto txo{wallet.GetTXO(input.prevout)};
        if (!txo) {
            return util::Error{Untranslated(
                "A protection-renewal input disappeared before signature verification")};
        }
        spent_outputs.push_back(txo->GetTxOut());
    }

    PrecomputedTransactionData txdata;
    auto precomputed_outputs{spent_outputs};
    txdata.Init(*item.tx, std::move(precomputed_outputs), /*force=*/true);
    for (size_t index{0}; index < item.tx->vin.size(); ++index) {
        const CTxIn& input{item.tx->vin[index]};
        ScriptError error{SCRIPT_ERR_OK};
        if (!VerifyScript(
                input.scriptSig, spent_outputs[index].scriptPubKey,
                &input.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS,
                TransactionSignatureChecker(
                    item.tx.get(), index, spent_outputs[index].nValue,
                    txdata, MissingDataBehavior::FAIL),
                &error)) {
            return util::Error{Untranslated(
                "A protection-renewal input failed cryptographic signature verification: " +
                ScriptErrorString(error))};
        }
    }
    return {};
}

std::string BatchDigest(const VaultRenewalBatch& batch)
{
    const auto write_excluded = [](HashWriter& digest,
                                   const VaultRenewalExcludedAmount& excluded) {
        digest << static_cast<uint64_t>(excluded.coin_count) << excluded.value;
    };
    HashWriter digest;
    digest << std::string{"vault-renewal-batch-v1"}
           << batch.policy_commitment
           << batch.source_digest
           << static_cast<uint8_t>(batch.request.scope)
           << batch.request.cluster_ids
           << batch.due_set_digest
           << batch.expected_vault_state.policy_commitment
           << batch.expected_vault_state.manually_lost_signers
           << batch.input_value
           << batch.fee
           << batch.output_value;
    write_excluded(digest, batch.exclusions.locked);
    write_excluded(digest, batch.exclusions.unsafe);
    write_excluded(digest, batch.exclusions.unconfirmed);
    write_excluded(digest, batch.exclusions.uneconomic);
    for (const VaultRenewalTransaction& item : batch.transactions) {
        digest << item.cluster_id << item.inputs
               << (item.tx ? item.tx->GetHash() : Txid{})
               << item.input_value << item.fee << item.output_value;
    }
    return digest.GetHash().GetHex();
}

util::Result<void> CheckCurrentPolicyAndState(
    const CWallet& wallet, const std::string& policy_commitment,
    const VaultCommitState& expected_state)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const VaultPolicyPackage package{ExportWalletVaultPolicy(wallet)};
    if (package.policy_id.empty() || ClassifyFixedVaultSchedule(package) != FixedVaultSchedule::CURRENT_90_180 ||
        !ValidateFixedStagedVaultPolicy(package) ||
        VaultPolicyCommitment(package) != policy_commitment) {
        return util::Error{Untranslated("The active Recovery Vault policy changed; create and review a new renewal")};
    }
    if (CurrentVaultState(wallet, policy_commitment) != expected_state) {
        return util::Error{Untranslated("Recovery Vault participant loss state changed; create and review a new renewal")};
    }
    return {};
}

util::Result<void> CheckDirectSignerPolicy(const CWallet& wallet,
                                           const VaultPolicyPackage& package)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const std::string commitment{VaultPolicyCommitment(package)};
    if (wallet.m_vault_metadata_policy_commitment != commitment) {
        return util::Error{Untranslated("Recovery Vault participant sources are not bound to the active policy")};
    }
    const auto participants{FixedVaultParticipants(package)};
    if (!participants) return util::Error{util::ErrorString(participants)};
    for (const FixedVaultParticipant& participant : *participants) {
        if (wallet.m_lost_signers.contains(participant.fingerprint)) {
            return util::Error{Untranslated("All three Recovery Vault participants must be available for protection renewal")};
        }
        const auto type{wallet.m_vault_participant_types.find(participant.fingerprint)};
        if (type == wallet.m_vault_participant_types.end() ||
            (type->second != VaultParticipantType::LOCAL_SOFTWARE &&
             type->second != VaultParticipantType::HARDWARE)) {
            return util::Error{Untranslated(
                "Every Recovery Vault participant must be a directly available software or hardware signer")};
        }
    }
    return {};
}

util::Result<void> ValidateUnstoredInputs(const CWallet& wallet,
                                          const VaultRenewalTransaction& item)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CCoinControl control;
    control.m_min_depth = 1;
    control.m_include_unsafe_inputs = true;
    control.m_avoid_address_reuse = false;
    CoinFilterParams params;
    params.skip_locked = false;
    const auto candidates{AvailableCoins(wallet, &control, /*feerate=*/std::nullopt, params).All()};
    std::map<COutPoint, COutput> by_outpoint;
    for (const COutput& output : candidates)
        by_outpoint.emplace(output.outpoint, output);
    for (const COutPoint& input : item.inputs) {
        const auto coin{by_outpoint.find(input)};
        if (coin == by_outpoint.end() || coin->second.depth <= 0 || !coin->second.safe ||
            wallet.IsLockedCoin(input) || wallet.IsSpent(input) ||
            !IsActiveVaultOutput(wallet, coin->second.txout)) {
            return util::Error{Untranslated("A protection-renewal input is no longer confirmed, safe, unlocked, and unspent")};
        }
    }
    return {};
}

util::Result<void> ValidateStoredRenewalState(const CWallet& wallet,
                                              const CWalletTx& transaction)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (transaction.isAbandoned()) {
        return util::Error{Untranslated(
            "A retained protection-renewal transaction was abandoned; create and review a new renewal")};
    }
    if (transaction.isBlockConflicted() || transaction.isMempoolConflicted()) {
        return util::Error{Untranslated(
            "A retained protection-renewal transaction is conflicted; create and review a new renewal")};
    }
    if (HasActiveReplacement(wallet, transaction)) {
        return util::Error{Untranslated(
            "A retained protection-renewal transaction has an active replacement and cannot be retried")};
    }
    return {};
}

} // namespace

VaultRenewalStatus GetVaultRenewalStatus(const CWallet& wallet)
{
    LOCK(wallet.cs_wallet);
    return BuildSnapshot(wallet).status;
}

util::Result<VaultRenewalPlan> PlanVaultRenewal(
    const CWallet& wallet, const VaultRenewalRequest& request)
{
    LOCK(wallet.cs_wallet);
    return PlanVaultRenewalLocked(wallet, request);
}

util::Result<VaultRenewalBatch> CreateVaultRenewalBatch(
    CWallet& wallet, const VaultRenewalPlan& plan, const CCoinControl& fee_control)
{
    LOCK(wallet.cs_wallet);
    if (plan.source_digest != PlanDigest(plan)) {
        return util::Error{Untranslated("The protection-renewal plan changed after it was prepared")};
    }
    const auto current_plan{PlanVaultRenewalLocked(wallet, plan.request)};
    if (!current_plan) return util::Error{util::ErrorString(current_plan)};
    if (!SamePlan(plan, *current_plan)) {
        return util::Error{Untranslated("Recovery Vault coins or privacy clusters changed; create and review a new renewal")};
    }
    if (auto checked{CheckCurrentPolicyAndState(
            wallet, plan.policy_commitment, plan.expected_vault_state)};
        !checked) {
        return util::Error{util::ErrorString(checked)};
    }

    VaultRenewalBatch batch;
    batch.request = current_plan->request;
    batch.policy_commitment = current_plan->policy_commitment;
    batch.expected_vault_state = current_plan->expected_vault_state;
    batch.source_digest = current_plan->source_digest;
    batch.due_set_digest = current_plan->due_set_digest;
    batch.exclusions = current_plan->exclusions;

    for (const VaultRenewalPlanCluster& cluster : current_plan->clusters) {
        auto chunks{SplitForWeight(wallet, cluster.inputs, fee_control)};
        if (!chunks) return util::Error{util::ErrorString(chunks)};
        std::vector<VaultRenewalTransaction> cluster_transactions;
        bool cluster_uneconomic{false};
        for (const std::vector<COutPoint>& inputs : *chunks) {
            CAmount input_value{0};
            for (const COutPoint& input : inputs) {
                const auto txo{wallet.GetTXO(input)};
                if (!txo) return util::Error{Untranslated("A protection-renewal input disappeared while creating the batch")};
                input_value += txo->GetTxOut().nValue;
            }

            auto destination{wallet.GetNewChangeDestination(OutputType::BECH32M)};
            if (!destination) return util::Error{util::ErrorString(destination)};
            CCoinControl control{RenewalCoinControl(fee_control, inputs)};
            std::vector<CRecipient> recipients{{*destination, input_value, /*fSubtractFeeFromAmount=*/true}};
            auto created{CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt,
                                           control, /*sign=*/false)};
            if (!created) {
                if (IsUneconomicError(util::ErrorString(created))) {
                    cluster_uneconomic = true;
                    break;
                }
                return util::Error{util::ErrorString(created)};
            }

            VaultRenewalTransaction item;
            item.cluster_id = cluster.summary.id;
            item.inputs = inputs;
            std::ranges::sort(item.inputs, std::less<>{});
            item.tx = created->tx;
            item.input_value = input_value;
            item.fee = created->fee;
            item.output_value = item.tx->vout.empty() ? 0 : item.tx->vout.front().nValue;
            if (auto valid{ValidateTransactionShape(wallet, item, /*require_key_path_witness=*/false)};
                !valid) {
                return util::Error{util::ErrorString(valid)};
            }
            cluster_transactions.push_back(std::move(item));
        }
        if (cluster_uneconomic) {
            batch.exclusions.uneconomic.coin_count += cluster.summary.coin_count;
            batch.exclusions.uneconomic.value += cluster.summary.value;
            continue;
        }
        for (auto& item : cluster_transactions) {
            batch.input_value += item.input_value;
            batch.fee += item.fee;
            batch.output_value += item.output_value;
            batch.transactions.push_back(std::move(item));
        }
    }
    batch.batch_digest = BatchDigest(batch);
    return batch;
}

util::Result<void> SignVaultRenewalTransaction(
    CWallet& wallet, VaultRenewalBatch& batch, size_t transaction_index)
{
    VaultRenewalTransaction unsigned_item;
    std::string expected_policy_commitment;
    VaultCommitState expected_vault_state;
    {
        LOCK(wallet.cs_wallet);
        if (transaction_index >= batch.transactions.size()) {
            return util::Error{Untranslated("Protection-renewal transaction index is out of range")};
        }
        if (batch.batch_digest != BatchDigest(batch)) {
            return util::Error{Untranslated("The protection-renewal batch changed after review")};
        }
        if (auto checked{CheckCurrentPolicyAndState(
                wallet, batch.policy_commitment, batch.expected_vault_state)};
            !checked) {
            return util::Error{util::ErrorString(checked)};
        }
        auto current_plan{PlanVaultRenewalLocked(wallet, batch.request)};
        if (!current_plan || current_plan->source_digest != batch.source_digest) {
            return util::Error{Untranslated("Recovery Vault coins or privacy clusters changed; create and review a new renewal")};
        }
        const VaultPolicyPackage package{ExportWalletVaultPolicy(wallet)};
        if (auto direct{CheckDirectSignerPolicy(wallet, package)}; !direct) {
            return util::Error{util::ErrorString(direct)};
        }

        VaultRenewalTransaction& item{batch.transactions[transaction_index]};
        if (item.signed_complete) {
            if (item.signed_vault_state == batch.expected_vault_state &&
                ValidateTransactionShape(wallet, item, /*require_key_path_witness=*/true)) {
                if (auto verified{VerifySignedTransactionInputs(wallet, item)};
                    verified) {
                    return {};
                }
            }
            return util::Error{Untranslated("The signed protection-renewal transaction is inconsistent with its batch")};
        }
        if (auto valid{ValidateTransactionShape(wallet, item, /*require_key_path_witness=*/false)};
            !valid) {
            return util::Error{util::ErrorString(valid)};
        }
        if (auto inputs{ValidateUnstoredInputs(wallet, item)}; !inputs) {
            return util::Error{util::ErrorString(inputs)};
        }
        unsigned_item = item;
        expected_policy_commitment = batch.policy_commitment;
        expected_vault_state = batch.expected_vault_state;
    }

    // Keep every intermediate nonce and partial signature in a private PSBT.
    // In particular, an unavailable or misbehaving hardware signer must not
    // partially mutate the caller's reviewed batch.
    PartiallySignedTransaction psbt{CMutableTransaction{*unsigned_item.tx}};
    bool complete{false};
    if (const auto error{wallet.FillPSBT(
            psbt,
            {.sign = false,
             .finalize = false,
             .bip32_derivs = true,
             .expected_vault_policy_commitment = expected_policy_commitment},
            complete)}) {
        return util::Error{common::PSBTErrorString(*error)};
    }
    std::optional<VaultCommitState> signed_state;
    if (const auto error{wallet.FillPSBT(
            psbt,
            {.sign = true,
             .finalize = true,
             .bip32_derivs = true,
             .expected_vault_policy_commitment = expected_policy_commitment},
            complete, /*n_signed=*/nullptr, &signed_state)}) {
        return util::Error{common::PSBTErrorString(*error)};
    }
    CMutableTransaction mutable_tx;
    if (!complete || !signed_state || *signed_state != expected_vault_state ||
        !FinalizeAndExtractPSBT(psbt, mutable_tx)) {
        return util::Error{Untranslated(
            "All three directly available Recovery Vault participants could not sign the renewal transaction")};
    }

    const CTransactionRef signed_tx{MakeTransactionRef(std::move(mutable_tx))};
    {
        LOCK(wallet.cs_wallet);
        if (transaction_index >= batch.transactions.size() ||
            batch.batch_digest != BatchDigest(batch) ||
            batch.policy_commitment != expected_policy_commitment ||
            batch.expected_vault_state != expected_vault_state) {
            return util::Error{Untranslated("The protection-renewal batch changed while signing")};
        }
        if (auto checked{CheckCurrentPolicyAndState(
                wallet, expected_policy_commitment, expected_vault_state)};
            !checked) {
            return util::Error{util::ErrorString(checked)};
        }
        auto current_plan{PlanVaultRenewalLocked(wallet, batch.request)};
        if (!current_plan || current_plan->source_digest != batch.source_digest) {
            return util::Error{Untranslated("Recovery Vault coins or privacy clusters changed while signing; create and review a new renewal")};
        }

        VaultRenewalTransaction& item{batch.transactions[transaction_index]};
        if (item.signed_complete || item.signed_vault_state || !item.tx ||
            !unsigned_item.tx || *item.tx != *unsigned_item.tx) {
            return util::Error{Untranslated("The protection-renewal transaction changed while signing")};
        }
        if (auto valid{ValidateTransactionShape(wallet, item, /*require_key_path_witness=*/false)};
            !valid) {
            return util::Error{util::ErrorString(valid)};
        }
        if (auto inputs{ValidateUnstoredInputs(wallet, item)}; !inputs) {
            return util::Error{util::ErrorString(inputs)};
        }

        VaultRenewalTransaction signed_item{item};
        signed_item.tx = signed_tx;
        signed_item.signed_vault_state = signed_state;
        signed_item.signed_complete = true;
        if (signed_item.tx->GetHash() != item.tx->GetHash()) {
            return util::Error{Untranslated(
                "Signing changed non-witness protection-renewal transaction data")};
        }
        if (auto valid{ValidateTransactionShape(
                wallet, signed_item, /*require_key_path_witness=*/true)};
            !valid) {
            return util::Error{util::ErrorString(valid)};
        }
        if (auto verified{VerifySignedTransactionInputs(wallet, signed_item)};
            !verified) {
            return util::Error{util::ErrorString(verified)};
        }
        // Publish only after the PSBT is finalized and every state, shape, and
        // cryptographic invariant passes.
        item = std::move(signed_item);
        if (batch.batch_digest != BatchDigest(batch)) {
            return util::Error{Untranslated("Signing unexpectedly changed the reviewed protection-renewal transaction")};
        }
    }
    return {};
}

util::Result<VaultRenewalCommitResult> CommitVaultRenewalBatch(
    CWallet& wallet, const VaultRenewalBatch& batch)
{
    LOCK(wallet.cs_wallet);
    if (batch.transactions.empty()) {
        return util::Error{Untranslated("The protection-renewal batch has no economic transactions")};
    }
    if (batch.batch_digest != BatchDigest(batch)) {
        return util::Error{Untranslated("The protection-renewal batch changed after review")};
    }
    if (auto checked{CheckCurrentPolicyAndState(
            wallet, batch.policy_commitment, batch.expected_vault_state)};
        !checked) {
        return util::Error{util::ErrorString(checked)};
    }

    bool any_already_stored{false};
    std::set<COutPoint> batch_inputs;
    std::set<COutPoint> stored_outputs;
    std::map<std::string, std::set<COutPoint>> unstored_by_cluster;
    for (const VaultRenewalTransaction& item : batch.transactions) {
        if (!item.signed_complete || item.signed_vault_state != batch.expected_vault_state) {
            return util::Error{Untranslated("Every protection-renewal transaction must be signed before any are broadcast")};
        }
        if (auto valid{ValidateTransactionShape(wallet, item, /*require_key_path_witness=*/true)};
            !valid) {
            return util::Error{util::ErrorString(valid)};
        }
        if (auto verified{VerifySignedTransactionInputs(wallet, item)};
            !verified) {
            return util::Error{util::ErrorString(verified)};
        }
        for (const COutPoint& input : item.inputs) {
            if (!batch_inputs.insert(input).second) {
                return util::Error{Untranslated("A protection-renewal input appears in more than one transaction")};
            }
        }
        const auto existing{wallet.mapWallet.find(item.tx->GetHash())};
        if (existing != wallet.mapWallet.end()) {
            if (*existing->second.GetTx() != *item.tx) {
                return util::Error{Untranslated("A wallet transaction has the same id but different renewal data")};
            }
            if (auto state{ValidateStoredRenewalState(wallet, existing->second)};
                !state) {
                return util::Error{util::ErrorString(state)};
            }
            any_already_stored = true;
            for (size_t index{0}; index < item.tx->vout.size(); ++index) {
                stored_outputs.emplace(item.tx->GetHash(),
                                       static_cast<uint32_t>(index));
            }
        } else {
            if (auto inputs{ValidateUnstoredInputs(wallet, item)}; !inputs) {
                return util::Error{util::ErrorString(inputs)};
            }
            unstored_by_cluster[item.cluster_id].insert(item.inputs.begin(),
                                                        item.inputs.end());
        }
    }

    // On the first attempt, the opaque plan must still describe the complete
    // due/all/selected cluster set. Once an exact transaction from the signed
    // batch is already stored, a previous batch attempt has begun: its inputs
    // necessarily disappear from a freshly reconstructed plan. In that mixed
    // stored/unstored retry state, the unchanged signed batch plus the exact
    // stored transaction, full policy/loss CAS, and revalidated remaining
    // inputs are authoritative.
    if (!any_already_stored) {
        const auto current_plan{PlanVaultRenewalLocked(wallet, batch.request)};
        if (!current_plan || current_plan->source_digest != batch.source_digest) {
            return util::Error{Untranslated("Recovery Vault coins or privacy clusters changed; create and review a new renewal")};
        }
    } else if (!unstored_by_cluster.empty()) {
        // A prior attempt may have stored only part of the batch. The original
        // source digest can no longer be reconstructed because those inputs
        // are now spent, but privacy-cluster completeness must still hold for
        // everything not yet stored. Union weight-split chunks by their
        // original cluster, remove outputs already created by stored items,
        // and require each remaining union to equal one complete current
        // eligible cluster. A newly linked/eligible member therefore stales
        // the retry instead of being silently left behind.
        const RenewalSnapshot current{BuildSnapshot(wallet)};
        std::vector<std::set<COutPoint>> current_clusters;
        for (const RenewalClusterInternal& cluster : current.clusters) {
            std::set<COutPoint> inputs;
            for (const RenewalCoin& coin : cluster.coins) {
                if (!stored_outputs.contains(coin.output.outpoint)) {
                    inputs.insert(coin.output.outpoint);
                }
            }
            if (!inputs.empty()) current_clusters.push_back(std::move(inputs));
        }
        std::set<size_t> matched_current;
        for (const auto& [cluster_id, expected_inputs] : unstored_by_cluster) {
            const auto match{std::ranges::find(current_clusters, expected_inputs)};
            if (match == current_clusters.end()) {
                return util::Error{Untranslated(
                    "A remaining Recovery Vault privacy cluster changed after a partial commit; create and review a new renewal")};
            }
            const size_t match_index{static_cast<size_t>(
                std::distance(current_clusters.begin(), match))};
            if (!matched_current.insert(match_index).second) {
                return util::Error{Untranslated(
                    "Remaining protection-renewal transactions no longer map to distinct privacy clusters")};
            }
            (void)cluster_id;
        }
    }

    VaultRenewalCommitResult result;
    result.transactions.reserve(batch.transactions.size());
    bool fatal_failure{false};
    for (const VaultRenewalTransaction& item : batch.transactions) {
        VaultRenewalCommitItem committed;
        committed.cluster_id = item.cluster_id;
        committed.txid = item.tx->GetHash();
        if (fatal_failure) {
            committed.outcome = VaultRenewalCommitOutcome::NOT_ATTEMPTED;
            committed.error = "Skipped after an earlier wallet commit failure";
            result.transactions.push_back(std::move(committed));
            continue;
        }

        auto existing{wallet.mapWallet.find(item.tx->GetHash())};
        if (existing != wallet.mapWallet.end() &&
            (existing->second.isConfirmed() ||
             wallet.chain().isInMempool(item.tx->GetHash()))) {
            committed.outcome = VaultRenewalCommitOutcome::ALREADY_ACCEPTED;
            result.transactions.push_back(std::move(committed));
            continue;
        }

        bool attempted{false};
        bool relayed{false};
        std::string relay_error;
        try {
            if (existing == wallet.mapWallet.end()) {
                if (!wallet.CommitTransaction(
                        item.tx, /*replaces_txid=*/std::nullopt,
                        /*comment=*/std::string{"Recovery Vault protection renewal"},
                        /*comment_to=*/std::nullopt, /*messages=*/{},
                        /*payment_requests=*/{}, batch.expected_vault_state,
                        &attempted, &relayed, &relay_error)) {
                    committed.outcome = VaultRenewalCommitOutcome::FAILED;
                    committed.error = "Recovery Vault policy or participant loss state changed before commit";
                    fatal_failure = true;
                }
            } else {
                attempted = wallet.GetBroadcastTransactions();
                if (attempted) {
                    relayed = wallet.SubmitTxMemoryPoolAndRelay(
                        existing->second, relay_error,
                        node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL);
                } else {
                    relay_error = "Wallet transaction broadcasting is disabled";
                }
            }
        } catch (const std::exception& error) {
            committed.outcome = VaultRenewalCommitOutcome::FAILED;
            committed.error = error.what();
            fatal_failure = true;
        }
        if (committed.outcome != VaultRenewalCommitOutcome::FAILED) {
            committed.outcome = attempted && relayed ? VaultRenewalCommitOutcome::RELAYED : VaultRenewalCommitOutcome::STORED_NOT_RELAYED;
            committed.error = std::move(relay_error);
        }
        result.transactions.push_back(std::move(committed));
    }
    return result;
}

} // namespace wallet
