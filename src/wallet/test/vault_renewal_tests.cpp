// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <hwi/mock.h>
#include <kernel/chain.h>
#include <kernel/types.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/rbf.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/multisig.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/vault_renewal.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(vault_renewal_tests, TestChain100Setup)

static constexpr CAmount VAULT_VALUE{10 * COIN};
static constexpr CFeeRate RENEWAL_FEE_RATE{10'000};

static CExtKey RandomMaster()
{
    CExtKey master;
    master.SetSeed(GenerateRandomKey());
    return master;
}

static std::string PathStr()
{
    return DefaultMultisigPath(OutputType::BECH32M, /*account=*/0);
}

static std::string MasterFingerprint(const CExtKey& master)
{
    return HexStr(master.id_key_fingerprint());
}

static void AddUnused(CWallet& wallet, const CExtKey& master)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    FlatSigningProvider keys;
    std::string error;
    auto descriptors{Parse("unused(" + EncodeExtKey(master) + ")", keys, error,
                           /*require_checksum=*/false)};
    BOOST_REQUIRE_MESSAGE(descriptors.size() == 1, error);
    WalletDescriptor descriptor(std::move(descriptors.front()), /*creation_time=*/1,
                                /*range_start=*/0, /*range_end=*/0, /*next_index=*/0);
    BOOST_REQUIRE(wallet.AddWalletDescriptor(descriptor, keys, "", /*internal=*/false));
}

static MultisigKeySpec LocalSpec(const CExtKey& master)
{
    MultisigKeySpec spec;
    spec.hdkey = EncodeExtPubKey(master.Neuter());
    spec.path = PathStr();
    return spec;
}

static MultisigKeySpec HardwareSpec(const CExtKey& master)
{
    std::vector<uint32_t> path;
    BOOST_REQUIRE(ParseHDKeypath(PathStr(), path));
    const auto account{DeriveExtKey(master, path)};
    BOOST_REQUIRE(account);
    MultisigKeySpec spec;
    spec.fingerprint = MasterFingerprint(master);
    spec.path = PathStr();
    spec.xpub = EncodeExtPubKey(account->first.Neuter());
    return spec;
}

static CScript AddImportedSingleKeyDescriptor(CWallet& wallet, const CKey& key)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const CScript script{GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()))};
    FlatSigningProvider provider;
    std::string error;
    auto descriptors{Parse("wpkh(" + EncodeSecret(key) + ")", provider, error,
                           /*require_checksum=*/false)};
    BOOST_REQUIRE_MESSAGE(descriptors.size() == 1, error);
    WalletDescriptor descriptor(std::move(descriptors.front()), /*creation_time=*/1,
                                /*range_start=*/0, /*range_end=*/0,
                                /*next_index=*/0);
    auto manager{wallet.AddWalletDescriptor(descriptor, provider, "", /*internal=*/false)};
    BOOST_REQUIRE_MESSAGE(manager, util::ErrorString(manager).original);
    BOOST_REQUIRE(manager->get().IsMine(script));
    return script;
}

static std::shared_ptr<CWallet> MakeWallet(interfaces::Chain& chain, std::string name,
                                           bool external_signer = false)
{
    auto wallet{std::make_shared<CWallet>(&chain, std::move(name), CreateMockableWalletDatabase())};
    wallet->m_keypool_size = 16;
    wallet->m_default_address_type = OutputType::BECH32M;
    uint64_t flags{WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED};
    if (external_signer) flags |= WALLET_FLAG_EXTERNAL_SIGNER;
    wallet->InitWalletFlags(flags);
    wallet->SetBroadcastTransactions(true);
    return wallet;
}

static void ScanWallet(CWallet& wallet, ChainstateManager& chainman)
{
    const uint256 genesis{WITH_LOCK(::cs_main, return chainman.ActiveChain().Genesis()->GetBlockHash())};
    {
        LOCK2(wallet.cs_wallet, ::cs_main);
        wallet.SetLastBlockProcessed(chainman.ActiveChain().Height(),
                                     chainman.ActiveChain().Tip()->GetBlockHash());
    }
    WalletRescanReserver reserver(wallet);
    BOOST_REQUIRE(reserver.reserve());
    const auto result{wallet.ScanForWalletTransactions(
        genesis, /*start_height=*/0, /*max_height=*/{}, reserver, /*save_progress=*/false)};
    BOOST_REQUIRE_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
}

struct FundedVault {
    std::shared_ptr<CWallet> wallet;
    COutPoint outpoint;
    CScript receive_script;
    int confirmed_height{0};
    int actual_tip_height{0};
    uint256 actual_tip_hash;
    std::string policy_commitment;
    std::vector<std::string> fingerprints;
};

struct MixedFundedVault {
    FundedVault vault;
    std::vector<std::unique_ptr<hwi::MockRegistration>> devices;
};

static FundedVault MakeFundedVault(TestChain100Setup& test, uint32_t primary,
                                   uint32_t final, size_t coinbase_index = 0,
                                   CAmount value = VAULT_VALUE)
{
    FundedVault result;
    result.wallet = MakeWallet(*test.m_node.chain, "renewal_vault");
    std::vector<CExtKey> masters{RandomMaster(), RandomMaster(), RandomMaster()};
    {
        LOCK(result.wallet->cs_wallet);
        std::vector<MultisigKeySpec> specs;
        for (const CExtKey& master : masters) {
            AddUnused(*result.wallet, master);
            specs.push_back(LocalSpec(master));
        }
        auto created{CreateMultisigDescriptor(
            *result.wallet, /*nrequired=*/2, specs,
            MultisigOptions{OutputType::BECH32M, /*account=*/0, {}, primary, {}, final})};
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        result.receive_script = GetScriptForDestination(
            *Assert(result.wallet->GetNewDestination(OutputType::BECH32M, "")));
    }

    const int input_height{static_cast<int>(coinbase_index) + 1};
    CMutableTransaction funding{test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.at(coinbase_index), /*input_vout=*/0, input_height,
        test.coinbaseKey, result.receive_script, value, /*submit=*/false)};
    test.CreateAndProcessBlock({funding}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    result.outpoint = COutPoint{funding.GetHash(), 0};
    ScanWallet(*result.wallet, *Assert(test.m_node.chainman));

    {
        LOCK2(result.wallet->cs_wallet, ::cs_main);
        const CWalletTx* wtx{result.wallet->GetWalletTx(result.outpoint.hash)};
        BOOST_REQUIRE(wtx);
        const auto confirmed{wtx->state<TxStateConfirmed>()};
        BOOST_REQUIRE(confirmed);
        result.confirmed_height = confirmed->confirmed_block_height;
        result.actual_tip_height = test.m_node.chainman->ActiveChain().Height();
        result.actual_tip_hash = test.m_node.chainman->ActiveChain().Tip()->GetBlockHash();

        const VaultPolicyPackage package{ExportWalletVaultPolicy(*result.wallet)};
        result.policy_commitment = VaultPolicyCommitment(package);
        BOOST_REQUIRE(result.wallet->BindVaultMetadataToActivePolicy());
        auto participants{FixedVaultParticipants(package)};
        BOOST_REQUIRE_MESSAGE(participants, util::ErrorString(participants).original);
        for (const FixedVaultParticipant& participant : *participants) {
            result.fingerprints.push_back(participant.fingerprint);
            BOOST_REQUIRE(result.wallet->SetVaultParticipantType(
                participant.fingerprint, VaultParticipantType::LOCAL_SOFTWARE,
                result.policy_commitment));
        }
    }
    return result;
}

static MixedFundedVault MakeMixedFundedVault(TestChain100Setup& test)
{
    gArgs.ForceSetArg("-signer", "internal");
    MixedFundedVault result;
    const CExtKey local{RandomMaster()};
    const CExtKey hardware_a{RandomMaster()};
    const CExtKey hardware_b{RandomMaster()};
    result.devices.push_back(std::make_unique<hwi::MockRegistration>(
        hardware_a, ChainType::REGTEST));
    result.devices.push_back(std::make_unique<hwi::MockRegistration>(
        hardware_b, ChainType::REGTEST));
    result.vault.wallet = MakeWallet(*test.m_node.chain, "mixed_renewal_vault",
                                     /*external_signer=*/true);
    {
        LOCK(result.vault.wallet->cs_wallet);
        AddUnused(*result.vault.wallet, local);
        const std::vector<MultisigKeySpec> specs{
            LocalSpec(local), HardwareSpec(hardware_a), HardwareSpec(hardware_b)};
        auto created{CreateMultisigDescriptor(
            *result.vault.wallet, /*nrequired=*/2, specs,
            MultisigOptions{OutputType::BECH32M, /*account=*/0, {}, FIXED_VAULT_CURRENT_PRIMARY_DELAY, {}, FIXED_VAULT_CURRENT_FINAL_DELAY})};
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        result.vault.receive_script = GetScriptForDestination(
            *Assert(result.vault.wallet->GetNewDestination(OutputType::BECH32M, "")));
    }

    CMutableTransaction funding{test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.at(0), /*input_vout=*/0, /*input_height=*/1,
        test.coinbaseKey, result.vault.receive_script, VAULT_VALUE,
        /*submit=*/false)};
    test.CreateAndProcessBlock({funding},
                               GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    result.vault.outpoint = COutPoint{funding.GetHash(), 0};
    ScanWallet(*result.vault.wallet, *Assert(test.m_node.chainman));

    {
        LOCK2(result.vault.wallet->cs_wallet, ::cs_main);
        const CWalletTx* wtx{result.vault.wallet->GetWalletTx(
            result.vault.outpoint.hash)};
        BOOST_REQUIRE(wtx);
        const auto confirmed{wtx->state<TxStateConfirmed>()};
        BOOST_REQUIRE(confirmed);
        result.vault.confirmed_height = confirmed->confirmed_block_height;
        result.vault.actual_tip_height = test.m_node.chainman->ActiveChain().Height();
        result.vault.actual_tip_hash =
            test.m_node.chainman->ActiveChain().Tip()->GetBlockHash();

        const VaultPolicyPackage package{
            ExportWalletVaultPolicy(*result.vault.wallet)};
        result.vault.policy_commitment = VaultPolicyCommitment(package);
        BOOST_REQUIRE(result.vault.wallet->BindVaultMetadataToActivePolicy());
        auto participants{FixedVaultParticipants(package)};
        BOOST_REQUIRE_MESSAGE(participants,
                              util::ErrorString(participants).original);
        for (const FixedVaultParticipant& participant : *participants) {
            result.vault.fingerprints.push_back(participant.fingerprint);
            const VaultParticipantType type{
                participant.fingerprint == MasterFingerprint(local) ? VaultParticipantType::LOCAL_SOFTWARE : VaultParticipantType::HARDWARE};
            BOOST_REQUIRE(result.vault.wallet->SetVaultParticipantType(
                participant.fingerprint, type,
                result.vault.policy_commitment));
        }
    }
    return result;
}

struct FundedOutput {
    COutPoint outpoint;
    int confirmed_height{0};
};

static CCoinControl FeeControl();

static void RecordActualTip(FundedVault& vault, ChainstateManager& chainman)
{
    LOCK(::cs_main);
    vault.actual_tip_height = chainman.ActiveChain().Height();
    vault.actual_tip_hash = chainman.ActiveChain().Tip()->GetBlockHash();
}

static CScript NewVaultScript(FundedVault& vault)
{
    LOCK(vault.wallet->cs_wallet);
    return GetScriptForDestination(
        *Assert(vault.wallet->GetNewDestination(OutputType::BECH32M, "")));
}

static FundedOutput FundConfirmed(TestChain100Setup& test, FundedVault& vault,
                                  const CScript& script, CAmount value,
                                  size_t coinbase_index)
{
    CMutableTransaction funding{test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.at(coinbase_index), /*input_vout=*/0,
        static_cast<int>(coinbase_index) + 1, test.coinbaseKey, script, value,
        /*submit=*/false)};
    test.CreateAndProcessBlock({funding}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    ScanWallet(*vault.wallet, *Assert(test.m_node.chainman));
    RecordActualTip(vault, *Assert(test.m_node.chainman));
    FundedOutput result{COutPoint{funding.GetHash(), 0}};
    {
        LOCK(vault.wallet->cs_wallet);
        const CWalletTx* wtx{vault.wallet->GetWalletTx(result.outpoint.hash)};
        BOOST_REQUIRE(wtx);
        const auto confirmed{wtx->state<TxStateConfirmed>()};
        BOOST_REQUIRE(confirmed);
        result.confirmed_height = confirmed->confirmed_block_height;
    }
    return result;
}

static COutPoint FundUnconfirmed(TestChain100Setup& test, FundedVault& vault,
                                 const CScript& script, CAmount value,
                                 size_t coinbase_index)
{
    CMutableTransaction funding{test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.at(coinbase_index), /*input_vout=*/0,
        static_cast<int>(coinbase_index) + 1, test.coinbaseKey, script, value,
        /*submit=*/true)};
    vault.wallet->transactionAddedToMempool(MakeTransactionRef(funding));
    return COutPoint{funding.GetHash(), 0};
}

static void SpendTogether(TestChain100Setup& test, FundedVault& vault,
                          const std::vector<COutPoint>& inputs, CAmount value)
{
    CCoinControl control{FeeControl()};
    control.m_allow_other_inputs = false;
    control.m_allowed_inputs = std::set<COutPoint>{inputs.begin(), inputs.end()};
    for (const COutPoint& input : inputs)
        control.Select(input);
    const CTxDestination destination{WitnessV1Taproot{
        XOnlyPubKey{GenerateRandomKey().GetPubKey()}}};
    auto created{CreateTransaction(
        *vault.wallet, {{destination, value, /*fSubtractFeeFromAmount=*/true}},
        /*change_pos=*/std::nullopt, control, /*sign=*/true)};
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_REQUIRE_EQUAL(created->tx->vin.size(), inputs.size());
    BOOST_REQUIRE_EQUAL(created->tx->vout.size(), 1U);
    test.CreateAndProcessBlock({CMutableTransaction{*created->tx}},
                               GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    ScanWallet(*vault.wallet, *Assert(test.m_node.chainman));
    RecordActualTip(vault, *Assert(test.m_node.chainman));
}

static void SetSyntheticTipForDepth(FundedVault& vault, int confirmed_height,
                                    int depth)
{
    BOOST_REQUIRE_GT(depth, 0);
    LOCK(vault.wallet->cs_wallet);
    vault.wallet->SetLastBlockProcessed(confirmed_height + depth - 1,
                                        vault.actual_tip_hash);
}

static void SetSyntheticDepth(FundedVault& vault, int depth)
{
    BOOST_REQUIRE_GT(depth, 0);
    LOCK(vault.wallet->cs_wallet);
    vault.wallet->SetLastBlockProcessed(
        vault.confirmed_height + depth - 1, vault.actual_tip_hash);
}

static void RestoreActualTip(FundedVault& vault)
{
    LOCK(vault.wallet->cs_wallet);
    vault.wallet->SetLastBlockProcessed(vault.actual_tip_height,
                                        vault.actual_tip_hash);
}

static CCoinControl FeeControl()
{
    CCoinControl control;
    control.fOverrideFeeRate = true;
    control.m_feerate = RENEWAL_FEE_RATE;
    control.m_signal_bip125_rbf = true;
    return control;
}

BOOST_AUTO_TEST_CASE(status_warning_boundary_and_legacy_compatibility)
{
    auto current{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                                 FIXED_VAULT_CURRENT_FINAL_DELAY)};
    SetSyntheticDepth(current, FIXED_VAULT_CURRENT_PRIMARY_DELAY -
                                   VAULT_RENEWAL_WARNING_BLOCKS - 1);
    auto before{GetVaultRenewalStatus(*current.wallet)};
    BOOST_REQUIRE(before.supported);
    BOOST_CHECK(before.warning == 0);
    BOOST_REQUIRE_EQUAL(before.clusters.size(), 1U);
    BOOST_CHECK(!before.clusters.front().due);
    BOOST_CHECK_EQUAL(before.clusters.front().blocks_until_primary,
                      static_cast<int>(VAULT_RENEWAL_WARNING_BLOCKS + 1));
    BOOST_CHECK(before.due_set_digest.empty());

    SetSyntheticDepth(current, FIXED_VAULT_CURRENT_PRIMARY_DELAY -
                                   VAULT_RENEWAL_WARNING_BLOCKS);
    auto boundary{GetVaultRenewalStatus(*current.wallet)};
    BOOST_CHECK_EQUAL(boundary.warning, VAULT_VALUE);
    BOOST_REQUIRE_EQUAL(boundary.clusters.size(), 1U);
    BOOST_CHECK(boundary.clusters.front().due);
    BOOST_CHECK_EQUAL(boundary.clusters.front().blocks_until_primary,
                      static_cast<int>(VAULT_RENEWAL_WARNING_BLOCKS));
    BOOST_CHECK(!boundary.due_set_digest.empty());

    SetSyntheticDepth(current, FIXED_VAULT_CURRENT_PRIMARY_DELAY);
    auto primary_mature{GetVaultRenewalStatus(*current.wallet)};
    BOOST_CHECK_EQUAL(primary_mature.recovery_enabled, VAULT_VALUE);
    BOOST_REQUIRE(primary_mature.next_expansion_blocks);
    BOOST_CHECK_EQUAL(*primary_mature.next_expansion_blocks,
                      static_cast<int>(FIXED_VAULT_CURRENT_FINAL_DELAY -
                                       FIXED_VAULT_CURRENT_PRIMARY_DELAY));

    SetSyntheticDepth(current, FIXED_VAULT_CURRENT_FINAL_DELAY - 1);
    auto just_before_final{GetVaultRenewalStatus(*current.wallet)};
    BOOST_REQUIRE(just_before_final.next_expansion_blocks);
    BOOST_CHECK_EQUAL(*just_before_final.next_expansion_blocks, 1);
    SetSyntheticDepth(current, FIXED_VAULT_CURRENT_FINAL_DELAY);
    auto final_mature{GetVaultRenewalStatus(*current.wallet)};
    BOOST_CHECK(!final_mature.next_expansion_blocks);
    BOOST_CHECK_EQUAL(final_mature.recovery_enabled, VAULT_VALUE);

    auto legacy{MakeFundedVault(*this, FIXED_VAULT_LEGACY_PRIMARY_DELAY,
                                FIXED_VAULT_LEGACY_FINAL_DELAY, /*coinbase_index=*/1)};
    auto legacy_status{GetVaultRenewalStatus(*legacy.wallet)};
    BOOST_CHECK(legacy_status.schedule == FixedVaultSchedule::LEGACY_30_60);
    BOOST_CHECK(!legacy_status.supported);
    auto rejected{PlanVaultRenewal(*legacy.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_CHECK(!rejected);
}

BOOST_AUTO_TEST_CASE(cluster_scopes_select_due_all_and_early_oldest)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    const CScript second_script{NewVaultScript(vault)};
    const FundedOutput second{FundConfirmed(
        *this, vault, second_script, 2 * COIN, /*coinbase_index=*/1)};

    auto initial_status{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_REQUIRE_EQUAL(initial_status.clusters.size(), 2U);
    auto early{PlanVaultRenewal(
        *vault.wallet, {VaultRenewalScope::EARLY_OLDEST, {}})};
    BOOST_REQUIRE_MESSAGE(early, util::ErrorString(early).original);
    BOOST_REQUIRE_EQUAL(early->clusters.size(), 1U);
    BOOST_REQUIRE_EQUAL(early->clusters.front().inputs.size(), 1U);
    BOOST_CHECK(early->clusters.front().inputs.front() == vault.outpoint);

    auto all{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(all, util::ErrorString(all).original);
    BOOST_CHECK_EQUAL(all->clusters.size(), 2U);
    BOOST_CHECK_EQUAL(all->selected_coin_count, 2U);
    BOOST_CHECK_EQUAL(all->selected_value, VAULT_VALUE + 2 * COIN);

    SetSyntheticTipForDepth(
        vault, vault.confirmed_height,
        FIXED_VAULT_CURRENT_PRIMARY_DELAY - VAULT_RENEWAL_WARNING_BLOCKS);
    auto boundary{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_REQUIRE_EQUAL(boundary.clusters.size(), 2U);
    BOOST_CHECK_EQUAL(std::ranges::count_if(
                          boundary.clusters,
                          [](const VaultRenewalCluster& cluster) {
                              return cluster.due;
                          }),
                      1);
    auto due{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::DUE, {}})};
    BOOST_REQUIRE_MESSAGE(due, util::ErrorString(due).original);
    BOOST_REQUIRE_EQUAL(due->clusters.size(), 1U);
    BOOST_REQUIRE_EQUAL(due->clusters.front().inputs.size(), 1U);
    BOOST_CHECK(due->clusters.front().inputs.front() == vault.outpoint);
    BOOST_CHECK_EQUAL(due->selected_value, VAULT_VALUE);

    auto selected{PlanVaultRenewal(
        *vault.wallet,
        {VaultRenewalScope::SELECTED, {boundary.clusters.back().id}})};
    BOOST_REQUIRE_MESSAGE(selected, util::ErrorString(selected).original);
    BOOST_REQUIRE_EQUAL(selected->clusters.size(), 1U);
    BOOST_CHECK_EQUAL(selected->selected_coin_count, 1U);
    BOOST_CHECK(selected->clusters.front().inputs.front() == vault.outpoint ||
                selected->clusters.front().inputs.front() == second.outpoint);

    auto early_while_due{PlanVaultRenewal(
        *vault.wallet, {VaultRenewalScope::EARLY_OLDEST, {}})};
    BOOST_CHECK(!early_while_due);
}

BOOST_AUTO_TEST_CASE(whole_privacy_cluster_expands_and_splits_only_for_weight)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    const CScript first_script{vault.receive_script};
    const CScript second_script{NewVaultScript(vault)};
    const FundedOutput second_seed{FundConfirmed(
        *this, vault, second_script, VAULT_VALUE, /*coinbase_index=*/1)};
    SpendTogether(*this, vault, {vault.outpoint, second_seed.outpoint},
                  2 * VAULT_VALUE);

    const FundedOutput first{FundConfirmed(
        *this, vault, first_script, 4 * COIN, /*coinbase_index=*/2)};
    const FundedOutput second{FundConfirmed(
        *this, vault, second_script, 6 * COIN, /*coinbase_index=*/3)};
    SetSyntheticTipForDepth(
        vault, first.confirmed_height,
        FIXED_VAULT_CURRENT_PRIMARY_DELAY - VAULT_RENEWAL_WARNING_BLOCKS);

    auto status{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_REQUIRE_EQUAL(status.clusters.size(), 1U);
    BOOST_CHECK(status.clusters.front().due);
    BOOST_CHECK_EQUAL(status.clusters.front().coin_count, 2U);
    BOOST_CHECK_EQUAL(status.clusters.front().value, 10 * COIN);

    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::DUE, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    BOOST_REQUIRE_EQUAL(plan->clusters.size(), 1U);
    BOOST_REQUIRE_EQUAL(plan->clusters.front().inputs.size(), 2U);
    const std::set<COutPoint> selected{plan->clusters.front().inputs.begin(),
                                       plan->clusters.front().inputs.end()};
    const std::set<COutPoint> expected{first.outpoint, second.outpoint};
    BOOST_CHECK(selected == expected);

    auto unsplit{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(unsplit, util::ErrorString(unsplit).original);
    BOOST_REQUIRE_EQUAL(unsplit->transactions.size(), 1U);

    int one_input_weight{-1};
    int two_input_weight{-1};
    {
        LOCK(vault.wallet->cs_wallet);
        std::vector<CTxOut> previous_outputs;
        for (const COutPoint& input : unsplit->transactions.front().inputs) {
            previous_outputs.push_back(
                Assert(vault.wallet->GetTXO(input))->GetTxOut());
        }
        const TxSize two{CalculateMaximumSignedTxSize(
            *unsplit->transactions.front().tx, vault.wallet.get(),
            previous_outputs, /*coin_control=*/nullptr)};
        CMutableTransaction one{*unsplit->transactions.front().tx};
        one.vin.resize(1);
        previous_outputs.resize(1);
        const TxSize one_size{CalculateMaximumSignedTxSize(
            CTransaction{one}, vault.wallet.get(), previous_outputs,
            /*coin_control=*/nullptr)};
        one_input_weight = one_size.weight;
        two_input_weight = two.weight;
    }
    BOOST_REQUIRE_GT(one_input_weight, 0);
    BOOST_REQUIRE_GT(two_input_weight, one_input_weight);
    CCoinControl split_control{FeeControl()};
    split_control.m_max_tx_weight = one_input_weight;
    auto split{CreateVaultRenewalBatch(*vault.wallet, *plan, split_control)};
    BOOST_REQUIRE_MESSAGE(split, util::ErrorString(split).original);
    BOOST_REQUIRE_EQUAL(split->transactions.size(), 2U);
    for (const VaultRenewalTransaction& item : split->transactions) {
        BOOST_CHECK_EQUAL(item.inputs.size(), 1U);
        BOOST_CHECK_EQUAL(item.tx->vin.size(), 1U);
        BOOST_CHECK_EQUAL(item.tx->vout.size(), 1U);
        BOOST_CHECK_EQUAL(item.cluster_id, plan->clusters.front().summary.id);
    }

    for (size_t index{0}; index < split->transactions.size(); ++index) {
        BOOST_REQUIRE(SignVaultRenewalTransaction(
            *vault.wallet, *split, index));
    }
    vault.wallet->SetBroadcastTransactions(false);
    BOOST_REQUIRE(vault.wallet->CommitTransaction(
        split->transactions.front().tx, /*replaces_txid=*/std::nullopt,
        /*comment=*/std::string{"Recovery Vault protection renewal"},
        /*comment_to=*/std::nullopt, /*messages=*/{},
        /*payment_requests=*/{}, split->expected_vault_state));
    RestoreActualTip(vault);
    const CBlock stored_block{CreateAndProcessBlock(
        {CMutableTransaction{*split->transactions.front().tx}},
        GetScriptForRawPubKey(coinbaseKey.GetPubKey()))};
    CBlockIndex* stored_index{WITH_LOCK(
        ::cs_main,
        return Assert(m_node.chainman)->m_blockman.LookupBlockIndex(stored_block.GetHash()))};
    BOOST_REQUIRE(stored_index);
    vault.wallet->blockConnected(
        kernel::ChainstateRole{},
        kernel::MakeBlockInfo(stored_index, &stored_block));
    ScanWallet(*vault.wallet, *Assert(m_node.chainman));
    {
        LOCK(vault.wallet->cs_wallet);
        const CWalletTx* stored{vault.wallet->GetWalletTx(
            split->transactions.front().tx->GetHash())};
        BOOST_REQUIRE(stored);
        BOOST_REQUIRE(stored->isConfirmed());
    }

    auto split_retry{CommitVaultRenewalBatch(*vault.wallet, *split)};
    BOOST_REQUIRE_MESSAGE(split_retry,
                          util::ErrorString(split_retry).original);
    BOOST_REQUIRE_EQUAL(split_retry->transactions.size(), 2U);
    BOOST_CHECK(split_retry->transactions.front().outcome ==
                VaultRenewalCommitOutcome::ALREADY_ACCEPTED);
    BOOST_CHECK(split_retry->transactions.back().outcome ==
                VaultRenewalCommitOutcome::STORED_NOT_RELAYED);
}

BOOST_AUTO_TEST_CASE(mixed_descriptors_and_unconfirmed_value_never_expand_scope)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    CScript ordinary_script;
    {
        LOCK(vault.wallet->cs_wallet);
        ordinary_script = AddImportedSingleKeyDescriptor(
            *vault.wallet, GenerateRandomKey());
    }
    FundConfirmed(*this, vault, ordinary_script, 7 * COIN,
                  /*coinbase_index=*/1);
    const CScript pending_script{NewVaultScript(vault)};
    FundUnconfirmed(*this, vault, pending_script, 3 * COIN,
                    /*coinbase_index=*/2);

    auto status{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(status.three_key_only, VAULT_VALUE);
    BOOST_CHECK_EQUAL(status.unconfirmed, 3 * COIN);
    BOOST_CHECK_EQUAL(status.exclusions.unconfirmed.coin_count, 1U);
    BOOST_CHECK_EQUAL(status.exclusions.unconfirmed.value, 3 * COIN);
    BOOST_REQUIRE_EQUAL(status.clusters.size(), 1U);
    BOOST_CHECK_EQUAL(status.clusters.front().coin_count, 1U);
    BOOST_CHECK_EQUAL(status.clusters.front().value, VAULT_VALUE);

    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    BOOST_CHECK_EQUAL(plan->selected_coin_count, 1U);
    BOOST_CHECK_EQUAL(plan->selected_value, VAULT_VALUE);
    BOOST_CHECK(plan->clusters.front().inputs.front() == vault.outpoint);
}

BOOST_AUTO_TEST_CASE(uneconomic_cluster_is_reported_without_partial_creation)
{
    constexpr CAmount TINY_VAULT_VALUE{500};
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY,
                               /*coinbase_index=*/0, TINY_VAULT_VALUE)};
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    CCoinControl expensive{FeeControl()};
    expensive.m_feerate = CFeeRate{100'000};
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, expensive)};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    BOOST_CHECK(batch->transactions.empty());
    BOOST_CHECK_EQUAL(batch->exclusions.uneconomic.coin_count, 1U);
    BOOST_CHECK_EQUAL(batch->exclusions.uneconomic.value, TINY_VAULT_VALUE);
}

BOOST_AUTO_TEST_CASE(plan_excludes_locked_and_detects_source_changes)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->LockCoin(vault.outpoint, /*persist=*/false));
    }
    auto locked_status{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(locked_status.exclusions.locked.coin_count, 1U);
    BOOST_CHECK_EQUAL(locked_status.exclusions.locked.value, VAULT_VALUE);
    BOOST_CHECK(locked_status.clusters.empty());
    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->UnlockCoin(vault.outpoint));
    }

    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    BOOST_CHECK_EQUAL(plan->selected_coin_count, 1U);
    BOOST_CHECK_EQUAL(plan->selected_value, VAULT_VALUE);
    BOOST_REQUIRE_EQUAL(plan->clusters.size(), 1U);
    BOOST_CHECK_EQUAL(plan->clusters.front().inputs.size(), 1U);

    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->LockCoin(vault.outpoint, /*persist=*/false));
    }
    auto stale{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_CHECK(!stale);
    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->UnlockCoin(vault.outpoint));
    }

    VaultRenewalPlan tampered{*plan};
    tampered.clusters.front().inputs.clear();
    auto rejected_tamper{CreateVaultRenewalBatch(*vault.wallet, tampered, FeeControl())};
    BOOST_CHECK(!rejected_tamper);
}

BOOST_AUTO_TEST_CASE(new_block_does_not_invalidate_unchanged_reviewed_membership)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    SetSyntheticDepth(vault, FIXED_VAULT_CURRENT_PRIMARY_DELAY -
                                 VAULT_RENEWAL_WARNING_BLOCKS - 1);
    const auto before{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_REQUIRE_EQUAL(before.clusters.size(), 1U);
    BOOST_CHECK(!before.clusters.front().due);
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);

    // Cross the 2,016-block warning boundary and receive an unrelated
    // unconfirmed vault output. Neither event changes the exact confirmed
    // outpoints reviewed by an ALL request.
    SetSyntheticDepth(vault, FIXED_VAULT_CURRENT_PRIMARY_DELAY -
                                 VAULT_RENEWAL_WARNING_BLOCKS);
    FundUnconfirmed(*this, vault, NewVaultScript(vault), 2 * COIN,
                    /*coinbase_index=*/1);
    const auto after{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_REQUIRE_EQUAL(after.clusters.size(), 1U);
    BOOST_CHECK(after.clusters.front().due);
    BOOST_CHECK_EQUAL(after.exclusions.unconfirmed.coin_count, 1U);
    auto signed_result{SignVaultRenewalTransaction(*vault.wallet, *batch, 0)};
    BOOST_REQUIRE_MESSAGE(signed_result, util::ErrorString(signed_result).original);
    vault.wallet->SetBroadcastTransactions(false);
    auto committed{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(committed, util::ErrorString(committed).original);
    BOOST_CHECK(committed->transactions.front().outcome ==
                VaultRenewalCommitOutcome::STORED_NOT_RELAYED);
}

BOOST_AUTO_TEST_CASE(conflicted_active_coin_is_reported_unsafe)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    {
        LOCK(vault.wallet->cs_wallet);
        auto tx{vault.wallet->mapWallet.find(vault.outpoint.hash)};
        BOOST_REQUIRE(tx != vault.wallet->mapWallet.end());
        tx->second.m_state = TxStateBlockConflicted{vault.actual_tip_hash,
                                                    vault.actual_tip_height};
        tx->second.MarkDirty();
    }
    auto status{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(status.exclusions.unsafe.coin_count, 1U);
    BOOST_CHECK_EQUAL(status.exclusions.unsafe.value, VAULT_VALUE);
    BOOST_CHECK(status.clusters.empty());
}

BOOST_AUTO_TEST_CASE(create_sign_and_guarded_commit_use_immediate_path)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    RestoreActualTip(vault);
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    BOOST_REQUIRE_EQUAL(batch->transactions.size(), 1U);
    const VaultRenewalTransaction& unsigned_tx{batch->transactions.front()};
    BOOST_REQUIRE_EQUAL(unsigned_tx.tx->vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(unsigned_tx.tx->vout.size(), 1U);
    BOOST_CHECK(unsigned_tx.tx->vin.front().nSequence &
                CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG);
    BOOST_CHECK_EQUAL(unsigned_tx.tx->vin.front().nSequence,
                      MAX_BIP125_RBF_SEQUENCE);
    BOOST_CHECK(unsigned_tx.tx->vin.front().scriptWitness.IsNull());
    BOOST_CHECK_EQUAL(unsigned_tx.input_value - unsigned_tx.output_value,
                      unsigned_tx.fee);
    BOOST_CHECK_GT(unsigned_tx.fee, 0);

    auto unsigned_commit{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_CHECK(!unsigned_commit);

    VaultRenewalBatch tampered_aggregate{*batch};
    ++tampered_aggregate.fee;
    auto tampered_sign{SignVaultRenewalTransaction(
        *vault.wallet, tampered_aggregate, 0)};
    BOOST_CHECK(!tampered_sign);
    BOOST_CHECK(!tampered_aggregate.transactions.front().signed_complete);

    // Compatibility metadata unrelated to the exact three policy
    // participants must not disable an otherwise valid direct renewal.
    {
        LOCK(vault.wallet->cs_wallet);
        vault.wallet->m_lost_signers.insert("deadbeef");
    }
    auto signed_result{SignVaultRenewalTransaction(*vault.wallet, *batch, 0)};
    BOOST_REQUIRE_MESSAGE(signed_result, util::ErrorString(signed_result).original);
    BOOST_REQUIRE(batch->transactions.front().signed_complete);
    BOOST_REQUIRE_EQUAL(batch->transactions.front().tx->vin.front().scriptWitness.stack.size(), 1U);

    VaultRenewalBatch signed_tampered_aggregate{*batch};
    ++signed_tampered_aggregate.output_value;
    auto tampered_commit{CommitVaultRenewalBatch(
        *vault.wallet, signed_tampered_aggregate)};
    BOOST_CHECK(!tampered_commit);
    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_CHECK(!vault.wallet->mapWallet.contains(
            batch->transactions.front().tx->GetHash()));
    }

    auto committed{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(committed, util::ErrorString(committed).original);
    BOOST_REQUIRE_EQUAL(committed->transactions.size(), 1U);
    BOOST_CHECK(committed->transactions.front().outcome ==
                VaultRenewalCommitOutcome::RELAYED);

    auto retry{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(retry, util::ErrorString(retry).original);
    BOOST_REQUIRE_EQUAL(retry->transactions.size(), 1U);
    BOOST_CHECK(retry->transactions.front().outcome ==
                VaultRenewalCommitOutcome::ALREADY_ACCEPTED);
}

BOOST_AUTO_TEST_CASE(mixed_local_and_exact_hardware_signers_complete_atomically)
{
    hwi::UsbEnumerateSuppress suppress_usb;
    auto mixed{MakeMixedFundedVault(*this)};
    auto plan{PlanVaultRenewal(
        *mixed.vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(
        *mixed.vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    BOOST_REQUIRE_EQUAL(batch->transactions.size(), 1U);
    VaultRenewalBatch unavailable_batch{*batch};
    const CTransactionRef unavailable_unsigned{
        unavailable_batch.transactions.front().tx};

    auto signed_result{SignVaultRenewalTransaction(
        *mixed.vault.wallet, *batch, 0)};
    BOOST_REQUIRE_MESSAGE(signed_result,
                          util::ErrorString(signed_result).original);
    BOOST_REQUIRE(batch->transactions.front().signed_complete);
    BOOST_REQUIRE_EQUAL(
        batch->transactions.front().tx->vin.front().scriptWitness.stack.size(),
        1U);

    // Durable HARDWARE provenance is not availability. Removing one exact
    // device must fail closed, and the private PSBT signing attempt must leave
    // the reviewed caller-owned batch untouched.
    BOOST_REQUIRE_EQUAL(mixed.devices.size(), 2U);
    mixed.devices.back().reset();
    auto unavailable{SignVaultRenewalTransaction(
        *mixed.vault.wallet, unavailable_batch, 0)};
    BOOST_CHECK(!unavailable);
    BOOST_CHECK(!unavailable_batch.transactions.front().signed_complete);
    BOOST_CHECK(!unavailable_batch.transactions.front().signed_vault_state);
    BOOST_CHECK(unavailable_batch.transactions.front().tx ==
                unavailable_unsigned);
    BOOST_CHECK(unavailable_batch.transactions.front().tx->vin.front().scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(active_replacement_is_truthful_and_historical_marker_allows_retry)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    BOOST_REQUIRE(SignVaultRenewalTransaction(*vault.wallet, *batch, 0));
    const CTransactionRef original{batch->transactions.front().tx};
    auto committed{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(committed, util::ErrorString(committed).original);
    BOOST_REQUIRE(committed->transactions.front().outcome ==
                  VaultRenewalCommitOutcome::RELAYED);
    BOOST_REQUIRE(feebumper::TransactionCanBeBumped(
        *vault.wallet, original->GetHash()));

    CCoinControl bump_control;
    bump_control.m_feerate = CFeeRate{50'000};
    bump_control.fOverrideFeeRate = true;
    bump_control.m_signal_bip125_rbf = true;
    std::vector<bilingual_str> errors;
    CAmount old_fee{0};
    CAmount new_fee{0};
    CMutableTransaction mutable_replacement;
    BOOST_REQUIRE(feebumper::CreateRateBumpTransaction(
                      *vault.wallet, original->GetHash(), bump_control, errors,
                      old_fee, new_fee, mutable_replacement,
                      /*require_mine=*/true, /*outputs=*/{},
                      /*original_change_index=*/0) ==
                  feebumper::Result::OK);
    BOOST_CHECK_GT(new_fee, old_fee);
    std::optional<VaultCommitState> replacement_state;
    BOOST_REQUIRE(feebumper::SignTransaction(
        *vault.wallet, mutable_replacement, &replacement_state));
    BOOST_REQUIRE(replacement_state == batch->expected_vault_state);
    const CTransactionRef replacement{
        MakeTransactionRef(mutable_replacement)};
    Txid replacement_txid;
    errors.clear();
    BOOST_REQUIRE(feebumper::CommitTransaction(
                      *vault.wallet, original->GetHash(),
                      std::move(mutable_replacement), errors, replacement_txid,
                      replacement_state) == feebumper::Result::OK);
    BOOST_CHECK(replacement_txid == replacement->GetHash());
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const auto replaced_status{GetVaultRenewalStatus(*vault.wallet)};
    CAmount replacement_vault_value{0};
    {
        LOCK(vault.wallet->cs_wallet);
        for (const CTxOut& output : replacement->vout) {
            if (IsActiveVaultOutput(*vault.wallet, output)) {
                replacement_vault_value += output.nValue;
            }
        }
    }
    BOOST_CHECK_GT(replacement_vault_value, 0);
    BOOST_CHECK_EQUAL(replaced_status.unconfirmed, replacement_vault_value);
    BOOST_CHECK_EQUAL(replaced_status.three_key_only, 0);
    const auto rejected_retry{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_CHECK(!rejected_retry);

    // Once the replacement is abandoned, its relationship marker is merely
    // history. The exact retained original may be resubmitted, and its output
    // becomes the one truthful pending candidate again.
    WITH_LOCK(m_node.mempool->cs,
              m_node.mempool->removeRecursive(
                  *replacement, MemPoolRemovalReason::REORG));
    vault.wallet->transactionRemovedFromMempool(
        replacement, MemPoolRemovalReason::REORG);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE(vault.wallet->AbandonTransaction(replacement_txid));
    auto retried{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(retried, util::ErrorString(retried).original);
    BOOST_REQUIRE(retried->transactions.front().outcome ==
                  VaultRenewalCommitOutcome::RELAYED);
    const auto reaccepted{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(reaccepted.unconfirmed,
                      original->vout.front().nValue);
    BOOST_CHECK_EQUAL(reaccepted.three_key_only, 0);

    WITH_LOCK(m_node.mempool->cs,
              m_node.mempool->removeRecursive(
                  *original, MemPoolRemovalReason::BLOCK));
    const CBlock block{CreateAndProcessBlock(
        {CMutableTransaction{*original}},
        GetScriptForRawPubKey(coinbaseKey.GetPubKey()))};
    (void)block;
    ScanWallet(*vault.wallet, *Assert(m_node.chainman));
    const auto confirmed{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(confirmed.unconfirmed, 0);
    BOOST_CHECK_EQUAL(confirmed.three_key_only,
                      original->vout.front().nValue);
}

BOOST_AUTO_TEST_CASE(direct_signing_refuses_missing_airgapped_and_lost_sources)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    auto make_batch = [&]() {
        auto plan{PlanVaultRenewal(
            *vault.wallet, {VaultRenewalScope::ALL, {}})};
        BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
        auto batch{CreateVaultRenewalBatch(
            *vault.wallet, *plan, FeeControl())};
        BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
        return *batch;
    };

    VaultRenewalBatch batch{make_batch()};
    BOOST_REQUIRE(!vault.fingerprints.empty());
    const std::string participant{vault.fingerprints.front()};
    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->SetVaultParticipantType(
            participant, VaultParticipantType::UNKNOWN,
            vault.policy_commitment));
    }
    const CTransactionRef original{batch.transactions.front().tx};
    auto missing{SignVaultRenewalTransaction(*vault.wallet, batch, 0)};
    BOOST_CHECK(!missing);
    BOOST_CHECK(!batch.transactions.front().signed_complete);
    BOOST_CHECK(batch.transactions.front().tx == original);

    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->SetVaultParticipantType(
            participant, VaultParticipantType::AIR_GAPPED,
            vault.policy_commitment));
    }
    auto airgapped{SignVaultRenewalTransaction(*vault.wallet, batch, 0)};
    BOOST_CHECK(!airgapped);
    BOOST_CHECK(!batch.transactions.front().signed_complete);
    BOOST_CHECK(batch.transactions.front().tx == original);

    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->SetVaultParticipantType(
            participant, VaultParticipantType::LOCAL_SOFTWARE,
            vault.policy_commitment));
        BOOST_REQUIRE(vault.wallet->SetLostSigner(
            participant, /*lost=*/true, vault.policy_commitment));
    }
    VaultRenewalBatch lost_batch{make_batch()};
    auto lost{SignVaultRenewalTransaction(*vault.wallet, lost_batch, 0)};
    BOOST_CHECK(!lost);
    BOOST_CHECK(!lost_batch.transactions.front().signed_complete);
}

BOOST_AUTO_TEST_CASE(mixed_stored_and_unstored_batch_retries_exact_remaining_transactions)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    FundConfirmed(*this, vault, NewVaultScript(vault), 2 * COIN,
                  /*coinbase_index=*/1);
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    BOOST_REQUIRE_EQUAL(batch->transactions.size(), 2U);
    for (size_t index{0}; index < batch->transactions.size(); ++index) {
        auto signed_result{SignVaultRenewalTransaction(
            *vault.wallet, *batch, index)};
        BOOST_REQUIRE_MESSAGE(signed_result,
                              util::ErrorString(signed_result).original);
    }

    vault.wallet->SetBroadcastTransactions(false);
    BOOST_REQUIRE(vault.wallet->CommitTransaction(
        batch->transactions.front().tx, /*replaces_txid=*/std::nullopt,
        /*comment=*/std::string{"Recovery Vault protection renewal"},
        /*comment_to=*/std::nullopt, /*messages=*/{},
        /*payment_requests=*/{}, batch->expected_vault_state));
    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->mapWallet.contains(
            batch->transactions.front().tx->GetHash()));
        BOOST_CHECK(!vault.wallet->mapWallet.contains(
            batch->transactions.back().tx->GetHash()));
    }

    auto resumed{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(resumed, util::ErrorString(resumed).original);
    BOOST_REQUIRE_EQUAL(resumed->transactions.size(), 2U);
    {
        LOCK(vault.wallet->cs_wallet);
        for (const VaultRenewalCommitItem& item : resumed->transactions) {
            BOOST_CHECK(item.outcome ==
                        VaultRenewalCommitOutcome::STORED_NOT_RELAYED);
            BOOST_CHECK(vault.wallet->mapWallet.contains(item.txid));
        }
    }
}

BOOST_AUTO_TEST_CASE(partial_retry_rejects_expanded_remaining_privacy_cluster)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    FundConfirmed(*this, vault, NewVaultScript(vault), 2 * COIN,
                  /*coinbase_index=*/1);
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    BOOST_REQUIRE_EQUAL(batch->transactions.size(), 2U);
    for (size_t index{0}; index < batch->transactions.size(); ++index) {
        BOOST_REQUIRE(SignVaultRenewalTransaction(
            *vault.wallet, *batch, index));
    }

    vault.wallet->SetBroadcastTransactions(false);
    BOOST_REQUIRE(vault.wallet->CommitTransaction(
        batch->transactions.front().tx, /*replaces_txid=*/std::nullopt,
        /*comment=*/std::string{"Recovery Vault protection renewal"},
        /*comment_to=*/std::nullopt, /*messages=*/{},
        /*payment_requests=*/{}, batch->expected_vault_state));

    CScript remaining_script;
    {
        LOCK(vault.wallet->cs_wallet);
        remaining_script = Assert(vault.wallet->GetTXO(
                                      batch->transactions.back().inputs.front()))
                               ->GetTxOut()
                               .scriptPubKey;
    }
    FundConfirmed(*this, vault, remaining_script, 3 * COIN,
                  /*coinbase_index=*/2);

    const auto rejected{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_CHECK(!rejected);
    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_CHECK(!vault.wallet->mapWallet.contains(
            batch->transactions.back().tx->GetHash()));
    }
}

BOOST_AUTO_TEST_CASE(tampered_later_witness_rejects_entire_batch_before_storage)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    FundConfirmed(*this, vault, NewVaultScript(vault), 2 * COIN,
                  /*coinbase_index=*/1);
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    BOOST_REQUIRE_EQUAL(batch->transactions.size(), 2U);
    for (size_t index{0}; index < batch->transactions.size(); ++index) {
        auto signed_result{SignVaultRenewalTransaction(
            *vault.wallet, *batch, index)};
        BOOST_REQUIRE_MESSAGE(signed_result,
                              util::ErrorString(signed_result).original);
    }

    CMutableTransaction tampered{*batch->transactions.back().tx};
    BOOST_REQUIRE_EQUAL(tampered.vin.front().scriptWitness.stack.size(), 1U);
    BOOST_REQUIRE(!tampered.vin.front().scriptWitness.stack.front().empty());
    tampered.vin.front().scriptWitness.stack.front().front() ^= 1;
    batch->transactions.back().tx = MakeTransactionRef(std::move(tampered));

    const auto idempotent_sign_rejected{SignVaultRenewalTransaction(
        *vault.wallet, *batch, batch->transactions.size() - 1)};
    BOOST_CHECK(!idempotent_sign_rejected);
    const auto rejected{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_CHECK(!rejected);
    {
        LOCK(vault.wallet->cs_wallet);
        for (const VaultRenewalTransaction& item : batch->transactions) {
            BOOST_CHECK(!vault.wallet->mapWallet.contains(item.tx->GetHash()));
        }
    }
    for (const VaultRenewalTransaction& item : batch->transactions) {
        BOOST_CHECK(!vault.wallet->chain().isInMempool(item.tx->GetHash()));
    }
}

BOOST_AUTO_TEST_CASE(pending_and_abandon_restore_truthful_prior_state)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    auto signed_result{SignVaultRenewalTransaction(*vault.wallet, *batch, 0)};
    BOOST_REQUIRE_MESSAGE(signed_result, util::ErrorString(signed_result).original);
    const CTransactionRef abandoned_renewal{batch->transactions.front().tx};
    const CAmount abandoned_value{batch->transactions.front().output_value};

    vault.wallet->SetBroadcastTransactions(false);
    auto stored{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(stored, util::ErrorString(stored).original);
    BOOST_CHECK(stored->transactions.front().outcome ==
                VaultRenewalCommitOutcome::STORED_NOT_RELAYED);
    auto pending{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(pending.unconfirmed, abandoned_value);
    BOOST_CHECK_EQUAL(pending.three_key_only, 0);
    BOOST_CHECK(!pending.next_expansion_blocks);

    BOOST_REQUIRE(vault.wallet->AbandonTransaction(
        abandoned_renewal->GetHash()));
    auto abandoned{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(abandoned.unconfirmed, 0);
    BOOST_CHECK_EQUAL(abandoned.three_key_only, VAULT_VALUE);
    BOOST_REQUIRE_EQUAL(abandoned.clusters.size(), 1U);
    BOOST_CHECK(abandoned.clusters.front().coin_count == 1U);
    const auto abandoned_retry{
        CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_CHECK(!abandoned_retry);
}

BOOST_AUTO_TEST_CASE(conflicted_stored_renewal_restores_source_and_rejects_retry)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    BOOST_REQUIRE(SignVaultRenewalTransaction(*vault.wallet, *batch, 0));
    vault.wallet->SetBroadcastTransactions(false);
    auto stored{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(stored, util::ErrorString(stored).original);
    BOOST_REQUIRE(stored->transactions.front().outcome ==
                  VaultRenewalCommitOutcome::STORED_NOT_RELAYED);

    {
        LOCK(vault.wallet->cs_wallet);
        auto transaction{vault.wallet->mapWallet.find(
            batch->transactions.front().tx->GetHash())};
        BOOST_REQUIRE(transaction != vault.wallet->mapWallet.end());
        transaction->second.m_state = TxStateBlockConflicted{
            vault.actual_tip_hash, vault.actual_tip_height};
        transaction->second.MarkDirty();
    }
    const auto status{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(status.unconfirmed, 0);
    BOOST_CHECK_EQUAL(status.three_key_only, VAULT_VALUE);
    const auto retry{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_CHECK(!retry);
}

BOOST_AUTO_TEST_CASE(confirmation_reorg_and_abandon_restore_truthful_clocks)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    auto signature{SignVaultRenewalTransaction(*vault.wallet, *batch, 0)};
    BOOST_REQUIRE_MESSAGE(signature, util::ErrorString(signature).original);
    const CTransactionRef renewal{batch->transactions.front().tx};
    const CAmount renewed_value{batch->transactions.front().output_value};
    vault.wallet->SetBroadcastTransactions(true);
    auto relayed{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_REQUIRE_MESSAGE(relayed, util::ErrorString(relayed).original);
    BOOST_CHECK(relayed->transactions.front().outcome ==
                VaultRenewalCommitOutcome::RELAYED);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    WITH_LOCK(m_node.mempool->cs,
              m_node.mempool->removeRecursive(
                  *renewal, MemPoolRemovalReason::BLOCK));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const CBlock renewal_block{CreateAndProcessBlock(
        {CMutableTransaction{*renewal}},
        GetScriptForRawPubKey(coinbaseKey.GetPubKey()))};
    ScanWallet(*vault.wallet, *Assert(m_node.chainman));
    auto confirmed{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(confirmed.unconfirmed, 0);
    BOOST_CHECK_EQUAL(confirmed.three_key_only, renewed_value);
    BOOST_REQUIRE(confirmed.next_expansion_blocks);
    BOOST_CHECK_EQUAL(*confirmed.next_expansion_blocks,
                      static_cast<int>(FIXED_VAULT_CURRENT_PRIMARY_DELAY - 1));

    CBlockIndex* renewal_index{WITH_LOCK(
        ::cs_main, return Assert(m_node.chainman)->m_blockman.LookupBlockIndex(renewal_block.GetHash()))};
    BOOST_REQUIRE(renewal_index);
    BlockValidationState state;
    BOOST_REQUIRE(Assert(m_node.chainman)->ActiveChainstate().InvalidateBlock(state, renewal_index));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    const uint256 renewal_hash{renewal_block.GetHash()};
    const uint256 previous_hash{renewal_block.hashPrevBlock};
    interfaces::BlockInfo disconnected{renewal_hash};
    disconnected.prev_hash = &previous_hash;
    disconnected.height = renewal_index->nHeight;
    disconnected.data = &renewal_block;
    vault.wallet->blockDisconnected(disconnected);
    auto reorged{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(reorged.unconfirmed, renewed_value);
    BOOST_CHECK_EQUAL(reorged.three_key_only, 0);

    WITH_LOCK(m_node.mempool->cs,
              m_node.mempool->removeRecursive(
                  *renewal, MemPoolRemovalReason::REORG));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_REQUIRE(vault.wallet->AbandonTransaction(renewal->GetHash()));
    auto restored{GetVaultRenewalStatus(*vault.wallet)};
    BOOST_CHECK_EQUAL(restored.unconfirmed, 0);
    BOOST_CHECK_EQUAL(restored.three_key_only, VAULT_VALUE);
    BOOST_REQUIRE_EQUAL(restored.clusters.size(), 1U);
}

BOOST_AUTO_TEST_CASE(policy_loss_cas_rejects_stale_batch)
{
    auto vault{MakeFundedVault(*this, FIXED_VAULT_CURRENT_PRIMARY_DELAY,
                               FIXED_VAULT_CURRENT_FINAL_DELAY)};
    auto plan{PlanVaultRenewal(*vault.wallet, {VaultRenewalScope::ALL, {}})};
    BOOST_REQUIRE_MESSAGE(plan, util::ErrorString(plan).original);
    auto batch{CreateVaultRenewalBatch(*vault.wallet, *plan, FeeControl())};
    BOOST_REQUIRE_MESSAGE(batch, util::ErrorString(batch).original);
    VaultRenewalBatch unsigned_batch{*batch};
    BOOST_REQUIRE(SignVaultRenewalTransaction(*vault.wallet, *batch, 0));
    const Txid signed_txid{batch->transactions.front().tx->GetHash()};
    BOOST_REQUIRE(!vault.fingerprints.empty());
    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->SetLostSigner(
            vault.fingerprints.front(), /*lost=*/true, vault.policy_commitment));
    }
    auto stale_sign{SignVaultRenewalTransaction(
        *vault.wallet, unsigned_batch, 0)};
    BOOST_CHECK(!stale_sign);
    auto stale_loss_commit{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_CHECK(!stale_loss_commit);
    BOOST_CHECK(!WITH_LOCK(vault.wallet->cs_wallet,
                           return vault.wallet->mapWallet.contains(signed_txid)));

    {
        LOCK(vault.wallet->cs_wallet);
        BOOST_REQUIRE(vault.wallet->SetLostSigner(
            vault.fingerprints.front(), /*lost=*/false,
            vault.policy_commitment));
        std::vector<MultisigKeySpec> replacement_specs;
        for (int index{0}; index < 3; ++index) {
            const CExtKey master{RandomMaster()};
            AddUnused(*vault.wallet, master);
            replacement_specs.push_back(LocalSpec(master));
        }
        const auto replacement{CreateMultisigDescriptor(
            *vault.wallet, /*nrequired=*/2, replacement_specs,
            MultisigOptions{OutputType::BECH32M, /*account=*/0, {}, FIXED_VAULT_CURRENT_PRIMARY_DELAY, {}, FIXED_VAULT_CURRENT_FINAL_DELAY})};
        BOOST_REQUIRE_MESSAGE(replacement,
                              util::ErrorString(replacement).original);
        BOOST_REQUIRE_NE(
            VaultPolicyCommitment(ExportWalletVaultPolicy(*vault.wallet)),
            batch->policy_commitment);
    }
    auto stale_policy_commit{CommitVaultRenewalBatch(*vault.wallet, *batch)};
    BOOST_CHECK(!stale_policy_commit);
    BOOST_CHECK(!WITH_LOCK(vault.wallet->cs_wallet,
                           return vault.wallet->mapWallet.contains(signed_txid)));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
