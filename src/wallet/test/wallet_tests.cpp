// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <interfaces/chain.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/types.h>
#include <policy/policy.h>
#include <psbt.h>
#include <rpc/server.h>
#include <script/solver.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/readwritefile.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/multisig.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

using node::MAX_BLOCKFILE_SIZE;

namespace wallet {

// Ensure that fee levels defined in the wallet are at least as high
// as the default levels for node policy.
static_assert(DEFAULT_TRANSACTION_MINFEE >= DEFAULT_MIN_RELAY_TX_FEE, "wallet minimum fee is smaller than default relay fee");
static_assert(WALLET_INCREMENTAL_RELAY_FEE >= DEFAULT_INCREMENTAL_RELAY_FEE, "wallet incremental fee is smaller than default incremental relay fee");

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

struct FixedVaultCandidate {
    std::string package;
    std::vector<SecureString> mnemonics;
};

static CMutableTransaction TestSimpleSpend(const CTransaction& from, uint32_t index, const CKey& key, const CScript& pubkey);

static FixedVaultCandidate PrepareFixedVaultCandidate()
{
    std::vector<MultisigKeySpec> specs(3);
    for (auto& spec : specs) spec.generate_local = true;
    MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.fallback_older = FIXED_VAULT_LEGACY_PRIMARY_DELAY;
    options.fallback_older_one_key = FIXED_VAULT_LEGACY_FINAL_DELAY;
    auto prepared{PrepareMultisigDescriptor(/*nrequired=*/2, specs, options)};
    BOOST_REQUIRE_MESSAGE(prepared, util::ErrorString(prepared).original);

    VaultPolicyPackage policy;
    policy.network = Params().GetChainTypeString();
    policy.nrequired = 2;
    policy.fallback_older = FIXED_VAULT_LEGACY_PRIMARY_DELAY;
    policy.fallback_older_one_key = FIXED_VAULT_LEGACY_FINAL_DELAY;
    policy.recovery_stages = {
        {2, FIXED_VAULT_LEGACY_PRIMARY_DELAY, {}},
        {1, FIXED_VAULT_LEGACY_FINAL_DELAY, {}},
    };
    policy.descs = prepared->descs;
    policy.policy_id = prepared->policy_id;

    FixedVaultCandidate candidate{FormatVaultPolicyPackage(policy), {}};
    for (auto& recovery : prepared->recovery) {
        candidate.mnemonics.push_back(std::move(recovery.mnemonic));
    }
    return candidate;
}

static void CheckNoFixedVaultStages(const fs::path& wallet_dir)
{
    std::error_code error;
    for (fs::directory_iterator it{wallet_dir, error}; !error && it != fs::directory_iterator{}; it.increment(error)) {
        BOOST_CHECK(!fs::PathToString(it->path().filename()).starts_with(".bitcoin-fixed-vault-stage-"));
    }
    BOOST_CHECK(!error);
}

static void CheckVaultDescriptorTimestamps(interfaces::Wallet& wallet, uint64_t expected)
{
    CWallet& internal{*Assert(wallet.wallet())};
    LOCK(internal.cs_wallet);
    const auto managers{internal.GetActiveScriptPubKeyMans()};
    BOOST_REQUIRE_EQUAL(managers.size(), 2U);
    for (ScriptPubKeyMan* manager : managers) {
        auto* descriptor{dynamic_cast<DescriptorScriptPubKeyMan*>(manager)};
        BOOST_REQUIRE(descriptor);
        LOCK(descriptor->cs_desc_man);
        BOOST_CHECK_EQUAL(descriptor->GetWalletDescriptor().creation_time, expected);
    }
}

static CScript FirstFixedVaultScript(const FixedVaultCandidate& candidate)
{
    const auto package{ParseVaultPolicyPackage(candidate.package)};
    BOOST_REQUIRE_MESSAGE(package, util::ErrorString(package).original);
    BOOST_REQUIRE(!package->descs.empty());
    FlatSigningProvider public_keys;
    std::string error;
    auto descriptors{Parse(package->descs.front(), public_keys, error, /*require_checksum=*/true)};
    BOOST_REQUIRE_MESSAGE(descriptors.size() == 1, error);
    std::vector<CScript> scripts;
    FlatSigningProvider expanded_keys;
    BOOST_REQUIRE(descriptors.front()->Expand(/*pos=*/0, public_keys, scripts, expanded_keys));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    return scripts.front();
}

class FailingWriteBatch final : public MockableSQLiteBatch
{
public:
    FailingWriteBatch(SQLiteDatabase& database, bool& fail_writes)
        : MockableSQLiteBatch(database), m_fail_writes(fail_writes)
    {
    }

protected:
    bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite = true) override
    {
        if (m_fail_writes) return false;
        return MockableSQLiteBatch::WriteKey(std::move(key), std::move(value), overwrite);
    }

private:
    bool& m_fail_writes;
};

class FailingWriteDatabase final : public MockableSQLiteDatabase
{
public:
    bool fail_writes{false};

    std::unique_ptr<DatabaseBatch> MakeBatch() override
    {
        return std::make_unique<FailingWriteBatch>(*this, fail_writes);
    }
};

BOOST_AUTO_TEST_CASE(wallet_flag_write_failure_never_changes_live_safety_state)
{
    auto database{std::make_unique<FailingWriteDatabase>()};
    auto* const failure_control{database.get()};
    CWallet wallet{/*chain=*/nullptr, "wallet_flag_atomicity", std::move(database)};

    wallet.SetWalletFlag(WALLET_FLAG_GENESIS_RESCAN_REQUIRED);
    BOOST_REQUIRE(wallet.IsWalletFlagSet(WALLET_FLAG_GENESIS_RESCAN_REQUIRED));

    failure_control->fail_writes = true;
    BOOST_CHECK_THROW(wallet.UnsetWalletFlag(WALLET_FLAG_GENESIS_RESCAN_REQUIRED), std::runtime_error);
    BOOST_CHECK(wallet.IsWalletFlagSet(WALLET_FLAG_GENESIS_RESCAN_REQUIRED));

    // The inverse operation is atomic too: a failed durable set must not
    // publish an in-memory flag that disappears after restart.
    failure_control->fail_writes = false;
    wallet.UnsetWalletFlag(WALLET_FLAG_GENESIS_RESCAN_REQUIRED);
    BOOST_REQUIRE(!wallet.IsWalletFlagSet(WALLET_FLAG_GENESIS_RESCAN_REQUIRED));
    failure_control->fail_writes = true;
    BOOST_CHECK_THROW(wallet.SetWalletFlag(WALLET_FLAG_GENESIS_RESCAN_REQUIRED), std::runtime_error);
    BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_GENESIS_RESCAN_REQUIRED));
}

BOOST_FIXTURE_TEST_CASE(check_rescan_from_genesis_rejects_missing_blocks_without_wallet_creation, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    BOOST_CHECK(loader->getWallets().empty());
    const auto ready{loader->checkRescanFromGenesis()};
    BOOST_REQUIRE_MESSAGE(ready, util::ErrorString(ready).original);

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        const CChain& active{Assert(m_node.chainman)->ActiveChain()};
        BOOST_REQUIRE_GT(active.Height(), 5);
        active[5]->nStatus &= ~BLOCK_HAVE_DATA;
    }

    const auto blocked{loader->checkRescanFromGenesis()};
    BOOST_REQUIRE(!blocked);
    BOOST_CHECK(util::ErrorString(blocked).original.find("unpruned block data back to genesis") != std::string::npos);
    BOOST_CHECK(loader->getWallets().empty());
}

BOOST_FIXTURE_TEST_CASE(fixed_vault_public_only_restore_is_atomic_and_timestamp_zero, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_public_only"};
    const fs::path final_path{GetWalletDir() / fs::PathFromString(name)};
    BOOST_CHECK(!fs::exists(final_path));

    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, /*mnemonics=*/{},
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE_MESSAGE(installed, util::ErrorString(installed).original);
    BOOST_REQUIRE(installed->wallet);
    BOOST_CHECK(installed->matches.empty());
    BOOST_CHECK(installed->wallet->privateKeysDisabled());
    BOOST_CHECK(installed->wallet->hasExternalSigner());
    BOOST_CHECK_EQUAL(installed->wallet->exportVaultPolicy(), candidate.package);
    const auto public_status{installed->wallet->getVaultStatus()};
    BOOST_CHECK_EQUAL(public_status.participants.size(), 3U);
    BOOST_CHECK_EQUAL(public_status.lost_signers.size(), 3U);
    BOOST_CHECK(public_status.setup_state == interfaces::Wallet::VaultSetupState::RECOVERY_KIT_REQUIRED);
    BOOST_CHECK(public_status.verification_state == interfaces::Wallet::VaultVerificationState::PENDING);
    BOOST_CHECK(public_status.genesis_rescan_required);
    BOOST_CHECK(fs::is_regular_file(final_path));
    CheckVaultDescriptorTimestamps(*installed->wallet, /*expected=*/0);
    CheckNoFixedVaultStages(GetWalletDir());

    const auto listed{loader->listWalletDir()};
    BOOST_CHECK(std::ranges::find(listed, std::pair{name, std::string{"sqlite"}}) != listed.end());

    const auto rescanned{installed->wallet->rescanFromGenesis()};
    BOOST_REQUIRE_MESSAGE(rescanned, util::ErrorString(rescanned).original);
    BOOST_CHECK(!installed->wallet->getVaultStatus().genesis_rescan_required);

    // The same public package can be committed with all matching phrases. The
    // create flow stores the current timestamp and needs no external signer.
    static constexpr uint64_t CREATE_TIME{1700000000};
    loader->setMockTime(CREATE_TIME);
    auto private_install{loader->installFixedVault(
        "fixed_vault_private_create", candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::CREATE, warnings)};
    BOOST_REQUIRE_MESSAGE(private_install, util::ErrorString(private_install).original);
    BOOST_REQUIRE(private_install->wallet);
    BOOST_CHECK_EQUAL(private_install->matches.size(), 3U);
    BOOST_CHECK(!private_install->wallet->privateKeysDisabled());
    BOOST_CHECK(!private_install->wallet->hasExternalSigner());
    BOOST_CHECK_EQUAL(private_install->wallet->exportVaultPolicy(), candidate.package);
    const auto private_status{private_install->wallet->getVaultStatus()};
    BOOST_CHECK(private_status.lost_signers.empty());
    BOOST_CHECK(!private_status.genesis_rescan_required);
    BOOST_CHECK(private_status.setup_state == interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED);
    BOOST_CHECK(private_status.verification_state == interfaces::Wallet::VaultVerificationState::PENDING);
    {
        CWallet* internal{Assert(private_install->wallet->wallet())};
        LOCK(internal->cs_wallet);
        const auto package{ParseVaultPolicyPackage(candidate.package)};
        BOOST_REQUIRE(package);
        BOOST_CHECK_EQUAL(internal->m_vault_metadata_policy_commitment,
                          VaultPolicyCommitment(*package));
    }
    CheckVaultDescriptorTimestamps(*private_install->wallet, CREATE_TIME);
    CheckNoFixedVaultStages(GetWalletDir());
}

BOOST_FIXTURE_TEST_CASE(fixed_vault_incomplete_rescan_blocks_backend_spending, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        "fixed_vault_rescan_spend_guard", candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE_MESSAGE(installed, util::ErrorString(installed).original);
    BOOST_REQUIRE(installed->wallet);
    BOOST_CHECK(installed->wallet->getVaultStatus().genesis_rescan_required);

    CWallet& wallet{*Assert(installed->wallet->wallet())};
    const CScript vault_script{FirstFixedVaultScript(candidate)};
    CMutableTransaction previous;
    previous.version = 2;
    previous.vin.emplace_back();
    previous.vout.emplace_back(10 * COIN, vault_script);
    const CTransactionRef previous_ref{MakeTransactionRef(previous)};

    uint256 tip_hash;
    int tip_height;
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        const CBlockIndex* tip{Assert(m_node.chainman)->ActiveChain().Tip()};
        tip_hash = tip->GetBlockHash();
        tip_height = tip->nHeight;
    }
    {
        LOCK(wallet.cs_wallet);
        BOOST_REQUIRE(wallet.AddToWallet(previous_ref, TxStateConfirmed{tip_hash, tip_height, /*index=*/0}));
    }

    CKey destination_key;
    destination_key.MakeNewKey(/*fCompressed=*/true);
    const CRecipient recipient{PKHash{destination_key.GetPubKey()}, COIN, /*fSubtractFeeFromAmount=*/false};
    CCoinControl coin_control;
    coin_control.m_feerate = CFeeRate{1000};
    coin_control.fOverrideFeeRate = true;
    auto blocked_create{CreateTransaction(wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control)};
    BOOST_REQUIRE(!blocked_create);
    BOOST_CHECK(util::ErrorString(blocked_create).original.find("rescanning from genesis") != std::string::npos);

    CMutableTransaction spending;
    spending.version = 2;
    spending.vin.emplace_back(COutPoint{previous.GetHash(), 0});
    spending.vout.emplace_back(9 * COIN, GetScriptForDestination(recipient.dest));

    PartiallySignedTransaction blocked_psbt{spending, /*version=*/0};
    blocked_psbt.inputs[0].non_witness_utxo = previous_ref;
    blocked_psbt.inputs[0].witness_utxo = previous.vout[0];
    bool complete{false};
    BOOST_CHECK(!wallet.FillPSBT(blocked_psbt, {.sign = false, .bip32_derivs = true}, complete));
    const auto blocked_psbt_error{wallet.FillPSBT(
        blocked_psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete)};
    BOOST_REQUIRE(blocked_psbt_error);
    BOOST_CHECK(*blocked_psbt_error == PSBTError::WALLET_RESCAN_REQUIRED);
    BOOST_CHECK(!complete);
    BOOST_CHECK(!PSBTInputSigned(blocked_psbt.inputs[0]));

    CMutableTransaction direct_spend{spending};
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(!wallet.SignTransaction(direct_spend));
    }
    std::map<COutPoint, Coin> coins{{spending.vin[0].prevout, Coin{previous.vout[0], tip_height, /*coinbase=*/false}}};
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!wallet.SignTransaction(direct_spend, coins, SIGHASH_DEFAULT, input_errors));
    BOOST_REQUIRE_EQUAL(input_errors.size(), 1U);
    BOOST_CHECK(input_errors.begin()->second.original.find("rescanning from genesis") != std::string::npos);

    const auto rescanned{installed->wallet->rescanFromGenesis()};
    BOOST_REQUIRE_MESSAGE(rescanned, util::ErrorString(rescanned).original);
    BOOST_CHECK(!installed->wallet->getVaultStatus().genesis_rescan_required);

    auto created{CreateTransaction(wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control)};
    if (!created) {
        BOOST_CHECK(util::ErrorString(created).original.find("rescanning from genesis") == std::string::npos);
    }
    PartiallySignedTransaction signed_psbt{spending, /*version=*/0};
    signed_psbt.inputs[0].non_witness_utxo = previous_ref;
    signed_psbt.inputs[0].witness_utxo = previous.vout[0];
    complete = false;
    BOOST_CHECK(!wallet.FillPSBT(signed_psbt, {.sign = false, .bip32_derivs = true}, complete));
    BOOST_CHECK(!wallet.FillPSBT(signed_psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete));
    BOOST_CHECK(complete);
}

BOOST_FIXTURE_TEST_CASE(fixed_vault_incomplete_rescan_marker_survives_reload, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_rescan_retry"};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, /*mnemonics=*/{},
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE_MESSAGE(installed, util::ErrorString(installed).original);
    BOOST_REQUIRE(installed->wallet);
    BOOST_CHECK(installed->wallet->getVaultStatus().genesis_rescan_required);

    // The resumable scan uses a vault-specific checkpoint rather than the
    // ordinary best-block locator, which can advance independently from
    // historical scan completeness.
    {
        CWallet& internal{*Assert(installed->wallet->wallet())};
        LOCK(internal.cs_wallet);
        const uint256 checkpoint_hash{m_node.chain->getBlockHash(5)};
        const std::string policy_commitment{VaultPolicyCommitment(ExportWalletVaultPolicy(internal))};
        WalletBatch batch{internal.GetDatabase()};
        BOOST_REQUIRE(batch.WriteVaultRescanProgress(5, checkpoint_hash, policy_commitment));
        int checkpoint_height{-1};
        uint256 reloaded_hash;
        std::string reloaded_commitment;
        BOOST_REQUIRE(batch.ReadVaultRescanProgress(checkpoint_height, reloaded_hash, reloaded_commitment));
        BOOST_CHECK_EQUAL(checkpoint_height, 5);
        BOOST_CHECK(reloaded_hash == checkpoint_hash);
        BOOST_CHECK_EQUAL(reloaded_commitment, policy_commitment);
        BOOST_REQUIRE(batch.EraseVaultRescanProgress());
    }
    installed->wallet->remove();
    installed->wallet.reset();

    CBlockIndex* unavailable_block{nullptr};
    uint32_t original_status{0};
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        const CChain& active{Assert(m_node.chainman)->ActiveChain()};
        BOOST_REQUIRE_GT(active.Height(), 5);
        unavailable_block = active[5];
        original_status = unavailable_block->nStatus;
        unavailable_block->nStatus &= ~BLOCK_HAVE_DATA;
    }

    warnings.clear();
    auto incomplete{loader->loadWallet(name, warnings)};
    BOOST_REQUIRE_MESSAGE(incomplete, util::ErrorString(incomplete).original);
    BOOST_CHECK((*incomplete)->getVaultStatus().genesis_rescan_required);
    BOOST_CHECK(std::ranges::any_of(warnings, [](const bilingual_str& warning) {
        return warning.original.find("remains marked as requiring a genesis rescan") != std::string::npos;
    }));
    (*incomplete)->remove();
    incomplete->reset();

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        unavailable_block->nStatus = original_status;
    }
    warnings.clear();
    auto completed{loader->loadWallet(name, warnings)};
    BOOST_REQUIRE_MESSAGE(completed, util::ErrorString(completed).original);
    BOOST_CHECK(!(*completed)->getVaultStatus().genesis_rescan_required);
    (*completed)->remove();
}

BOOST_FIXTURE_TEST_CASE(fixed_vault_setup_truth_and_manual_loss_survive_reload, TestChain100Setup)
{
    using ParticipantType = interfaces::Wallet::VaultParticipantType;
    using SetupState = interfaces::Wallet::VaultSetupState;
    using VerificationState = interfaces::Wallet::VaultVerificationState;

    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_setup_truth"};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::CREATE, warnings)};
    BOOST_REQUIRE_MESSAGE(installed, util::ErrorString(installed).original);
    BOOST_REQUIRE(installed->wallet);

    // The fixed installer publishes only after binding a truthful incomplete
    // state to the exact policy. Participant sources may be recorded later,
    // but a new wallet can never be mistaken for a pristine legacy wallet.
    auto status{installed->wallet->getVaultStatus()};
    BOOST_CHECK(status.setup_state == SetupState::ADDRESS_VERIFICATION_REQUIRED);
    BOOST_CHECK(status.verification_state == VerificationState::PENDING);
    BOOST_REQUIRE_EQUAL(status.participants.size(), 3U);
    for (const auto& participant : status.participants) {
        BOOST_CHECK(participant.type == ParticipantType::LOCAL_SOFTWARE);
        BOOST_CHECK(participant.availability == interfaces::Wallet::VaultSignerAvailability::AVAILABLE);
        BOOST_CHECK(!participant.is_lost);
    }

    // Inconsistent combinations are rejected atomically and leave the prior
    // state untouched.
    BOOST_CHECK(!installed->wallet->setVaultSetupState(
        SetupState::COMPLETE, VerificationState::PENDING));
    status = installed->wallet->getVaultStatus();
    BOOST_CHECK(status.setup_state == SetupState::ADDRESS_VERIFICATION_REQUIRED);
    BOOST_CHECK(status.verification_state == VerificationState::PENDING);

    BOOST_REQUIRE(installed->wallet->setVaultSetupState(
        SetupState::RECOVERY_KIT_REQUIRED, VerificationState::PENDING));
    BOOST_REQUIRE(installed->wallet->setVaultSetupState(
        SetupState::ADDRESS_VERIFICATION_REQUIRED, VerificationState::PENDING));
    BOOST_REQUIRE(installed->wallet->setVaultSetupState(
        SetupState::ADDRESS_VERIFICATION_REQUIRED, VerificationState::RECOVERY_KIT_MATCHED));
    BOOST_REQUIRE(installed->wallet->setVaultSetupState(
        SetupState::COMPLETE, VerificationState::INDEPENDENTLY_VERIFIED));
    status = installed->wallet->getVaultStatus();
    BOOST_CHECK(status.setup_state == SetupState::COMPLETE);
    BOOST_CHECK(status.verification_state == VerificationState::INDEPENDENTLY_VERIFIED);

    // Exercise the explicit-unverified terminal state as a separate durable
    // truth, not a synonym for independent verification.
    BOOST_REQUIRE(installed->wallet->setVaultSetupState(
        SetupState::COMPLETE, VerificationState::FINISHED_UNVERIFIED));
    const std::string fingerprint{status.participants.front().fingerprint};
    BOOST_REQUIRE(installed->wallet->setVaultParticipantType(fingerprint, ParticipantType::HARDWARE));

    // A fresh exact discovery may clear only automatically inferred loss.
    // Once the user or RPC marks the signer lost, the same operation must
    // fail atomically and preserve that deliberate decision.
    {
        auto* internal_wallet{Assert(installed->wallet->wallet())};
        LOCK(internal_wallet->cs_wallet);
        BOOST_REQUIRE(internal_wallet->SetLostSigners({fingerprint}));
    }
    BOOST_REQUIRE(installed->wallet->clearAutomaticallyLostSigner(fingerprint));
    status = installed->wallet->getVaultStatus();
    BOOST_CHECK(!status.participants.front().is_lost);
    BOOST_CHECK(status.manually_lost_signers.empty());

    BOOST_REQUIRE(installed->wallet->setLostSigner(fingerprint, /*lost=*/true));
    BOOST_CHECK(!installed->wallet->clearAutomaticallyLostSigner(fingerprint));
    status = installed->wallet->getVaultStatus();
    BOOST_CHECK(status.participants.front().type == ParticipantType::HARDWARE);
    BOOST_CHECK(status.participants.front().is_lost);
    BOOST_CHECK(std::ranges::find(status.manually_lost_signers, fingerprint) != status.manually_lost_signers.end());

    installed->wallet->remove();
    installed->wallet.reset();
    warnings.clear();
    auto reloaded{loader->loadWallet(name, warnings)};
    BOOST_REQUIRE_MESSAGE(reloaded, util::ErrorString(reloaded).original);
    status = (*reloaded)->getVaultStatus();
    BOOST_CHECK(status.setup_state == SetupState::COMPLETE);
    BOOST_CHECK(status.verification_state == VerificationState::FINISHED_UNVERIFIED);
    BOOST_REQUIRE_EQUAL(status.participants.size(), 3U);
    BOOST_CHECK(status.participants.front().type == ParticipantType::HARDWARE);
    BOOST_CHECK(status.participants.front().is_lost);
    BOOST_CHECK(std::ranges::find(status.manually_lost_signers, fingerprint) != status.manually_lost_signers.end());

    BOOST_REQUIRE((*reloaded)->setLostSigner(fingerprint, /*lost=*/false));
    BOOST_REQUIRE((*reloaded)->setVaultParticipantType(fingerprint, ParticipantType::UNKNOWN));
    BOOST_REQUIRE((*reloaded)->setVaultSetupState(
        SetupState::NOT_RECORDED, VerificationState::NOT_RECORDED));
    status = (*reloaded)->getVaultStatus();
    BOOST_CHECK(status.setup_state == SetupState::NOT_RECORDED);
    BOOST_CHECK(status.verification_state == VerificationState::NOT_RECORDED);
    BOOST_CHECK(status.manually_lost_signers.empty());
    BOOST_CHECK(status.participants.front().type == ParticipantType::LOCAL_SOFTWARE);
    (*reloaded)->remove();
}

BOOST_FIXTURE_TEST_CASE(fixed_vault_metadata_never_crosses_policy_identity, TestChain100Setup)
{
    using ParticipantType = interfaces::Wallet::VaultParticipantType;
    using SetupState = interfaces::Wallet::VaultSetupState;
    using VerificationState = interfaces::Wallet::VaultVerificationState;

    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate first{PrepareFixedVaultCandidate()};
    FixedVaultCandidate replacement{PrepareFixedVaultCandidate()};
    const auto first_package{ParseVaultPolicyPackage(first.package)};
    const auto replacement_package{ParseVaultPolicyPackage(replacement.package)};
    BOOST_REQUIRE(first_package);
    BOOST_REQUIRE(replacement_package);
    BOOST_REQUIRE_NE(first_package->policy_id, replacement_package->policy_id);
    const std::string first_commitment{VaultPolicyCommitment(*first_package)};
    const std::string replacement_commitment{VaultPolicyCommitment(*replacement_package)};
    BOOST_REQUIRE_NE(first_commitment, replacement_commitment);

    const std::string name{"fixed_vault_policy_bound_truth"};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, first.package, first.mnemonics,
        interfaces::FixedVaultInstallMode::CREATE, warnings)};
    BOOST_REQUIRE_MESSAGE(installed, util::ErrorString(installed).original);
    BOOST_REQUIRE(installed->wallet);

    auto status{installed->wallet->getVaultStatus()};
    BOOST_REQUIRE_EQUAL(status.participants.size(), 3U);
    const std::string old_fingerprint{status.participants.front().fingerprint};
    BOOST_REQUIRE(installed->wallet->setVaultSetupState(
        SetupState::COMPLETE, VerificationState::INDEPENDENTLY_VERIFIED));
    BOOST_REQUIRE(installed->wallet->setVaultParticipantType(old_fingerprint, ParticipantType::HARDWARE));
    BOOST_REQUIRE(installed->wallet->setLostSigner(old_fingerprint, /*lost=*/true));

    // Put replacement-policy history below a deliberately stale checkpoint.
    // The replacement is not active yet, so normal notifications cannot add
    // this transaction to the wallet.
    const CMutableTransaction replacement_funding{TestSimpleSpend(
        *m_coinbase_txns.at(0), /*index=*/0, coinbaseKey,
        FirstFixedVaultScript(replacement))};
    CreateAndProcessBlock({replacement_funding}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    {
        CWallet* internal{Assert(installed->wallet->wallet())};
        LOCK(internal->cs_wallet);
        const int checkpoint_height{internal->GetLastBlockHeight()};
        BOOST_REQUIRE_GT(checkpoint_height, 0);
        const uint256 checkpoint_hash{internal->GetLastBlockHash()};
        BOOST_CHECK_EQUAL(VaultPolicyCommitment(ExportWalletVaultPolicy(*internal)), first_commitment);
        BOOST_REQUIRE(WalletBatch{internal->GetDatabase()}.WriteVaultRescanProgress(
            checkpoint_height, checkpoint_hash, first_commitment));
    }

    // Advanced/RPC policy import can replace the active Taproot descriptors.
    // The new address must not inherit verification, loss, or a participant
    // source merely because an old 32-bit fingerprint happens to collide.
    {
        CWallet* internal{Assert(installed->wallet->wallet())};
        LOCK(internal->cs_wallet);
        const auto imported{ImportWalletVaultPolicy(*internal, *replacement_package)};
        BOOST_REQUIRE_MESSAGE(imported, util::ErrorString(imported).original);
    }
    status = installed->wallet->getVaultStatus();
    BOOST_CHECK(status.is_fixed_staged_vault);
    BOOST_CHECK(status.setup_state == SetupState::NOT_RECORDED);
    BOOST_CHECK(status.verification_state == VerificationState::NOT_RECORDED);
    BOOST_CHECK(status.lost_signers.empty());
    BOOST_CHECK(status.manually_lost_signers.empty());
    for (const auto& participant : status.participants) {
        BOOST_CHECK(participant.type == ParticipantType::UNKNOWN);
        BOOST_CHECK(!participant.is_lost);
    }

    // Transaction construction and PSBT filling carry the same immutable
    // full-policy token as setup state. A draft captured for policy A must be
    // rejected under cs_wallet after policy B becomes active, before coin
    // selection, PSBT enrichment, or signing can use B's managers.
    CCoinControl stale_coin_control;
    const auto stale_create{installed->wallet->createTransaction(
        {}, stale_coin_control, /*sign=*/false, /*change_pos=*/std::nullopt,
        first_commitment)};
    BOOST_CHECK(!stale_create);
    PartiallySignedTransaction stale_psbt{CMutableTransaction{}};
    bool stale_complete{false};
    const auto stale_fill{installed->wallet->fillPSBT(
        {.sign = false, .expected_vault_policy_commitment = first_commitment},
        /*n_signed=*/nullptr, stale_psbt, stale_complete)};
    BOOST_REQUIRE(stale_fill);
    BOOST_CHECK(*stale_fill == common::PSBTError::VAULT_POLICY_MISMATCH);
    BOOST_CHECK(!stale_complete);

    // A device callback or Recovery Kit comparison that started for policy A
    // must not bind or write its stale evidence after policy B becomes active.
    // Both mutations compare the complete package commitment under cs_wallet,
    // before BindVaultMetadataToActivePolicy can change any durable metadata.
    BOOST_REQUIRE(!status.participants.empty());
    const std::string replacement_fingerprint{status.participants.front().fingerprint};
    BOOST_CHECK(!installed->wallet->setVaultSetupState(
        SetupState::COMPLETE, VerificationState::INDEPENDENTLY_VERIFIED,
        first_commitment));
    BOOST_CHECK(!installed->wallet->setVaultParticipantType(
        replacement_fingerprint, ParticipantType::HARDWARE,
        first_commitment));
    status = installed->wallet->getVaultStatus();
    BOOST_CHECK(status.setup_state == SetupState::NOT_RECORDED);
    BOOST_CHECK(status.verification_state == VerificationState::NOT_RECORDED);
    BOOST_CHECK(status.participants.front().type == ParticipantType::UNKNOWN);
    {
        CWallet* internal{Assert(installed->wallet->wallet())};
        LOCK(internal->cs_wallet);
        BOOST_CHECK_EQUAL(internal->m_vault_metadata_policy_commitment, first_commitment);
    }

    // A checkpoint for policy A is never reused for policy B. The rescan must
    // restart at genesis and discover B's transaction below that checkpoint.
    const auto rescanned{installed->wallet->rescanFromGenesis()};
    BOOST_REQUIRE_MESSAGE(rescanned, util::ErrorString(rescanned).original);
    {
        CWallet* internal{Assert(installed->wallet->wallet())};
        LOCK(internal->cs_wallet);
        BOOST_CHECK(internal->mapWallet.contains(replacement_funding.GetHash()));
    }

    // The next explicit state write atomically rebinds all metadata to the
    // replacement policy. That safe result survives reload.
    BOOST_REQUIRE(installed->wallet->setVaultSetupState(
        SetupState::ADDRESS_VERIFICATION_REQUIRED, VerificationState::PENDING,
        replacement_commitment));
    BOOST_REQUIRE(installed->wallet->setLostSigner(
        replacement_fingerprint, /*lost=*/true, replacement_commitment));
    BOOST_CHECK(!installed->wallet->setLostSigner(
        replacement_fingerprint, /*lost=*/false, first_commitment));
    status = installed->wallet->getVaultStatus();
    BOOST_CHECK(std::ranges::find(status.manually_lost_signers,
                                  replacement_fingerprint) !=
                status.manually_lost_signers.end());
    BOOST_REQUIRE(installed->wallet->setLostSigner(
        replacement_fingerprint, /*lost=*/false, replacement_commitment));
    installed->wallet->remove();
    installed->wallet.reset();
    warnings.clear();
    auto reloaded{loader->loadWallet(name, warnings)};
    BOOST_REQUIRE_MESSAGE(reloaded, util::ErrorString(reloaded).original);
    status = (*reloaded)->getVaultStatus();
    BOOST_CHECK(status.setup_state == SetupState::ADDRESS_VERIFICATION_REQUIRED);
    BOOST_CHECK(status.verification_state == VerificationState::PENDING);
    BOOST_CHECK(status.lost_signers.empty());
    BOOST_CHECK(status.manually_lost_signers.empty());
    (*reloaded)->remove();
}

BOOST_FIXTURE_TEST_CASE(legacy_lost_signer_is_conservatively_bound_to_active_policy, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_legacy_lost_binding"};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::CREATE, warnings)};
    BOOST_REQUIRE_MESSAGE(installed, util::ErrorString(installed).original);
    auto status{installed->wallet->getVaultStatus()};
    BOOST_REQUIRE_EQUAL(status.participants.size(), 3U);
    const std::string fingerprint{status.participants.front().fingerprint};
    std::string unrelated{"deadbeef"};
    if (std::ranges::any_of(status.participants, [&](const auto& participant) {
            return participant.fingerprint == unrelated;
        })) {
        unrelated = "cafebabe";
    }

    // Simulate a pre-migration wallet: `lostsigner` existed before policy
    // commitments and explicit/manual provenance did.
    {
        CWallet* internal{Assert(installed->wallet->wallet())};
        LOCK(internal->cs_wallet);
        BOOST_REQUIRE(WalletBatch{internal->GetDatabase()}.WriteLostSigner(fingerprint));
        BOOST_REQUIRE(WalletBatch{internal->GetDatabase()}.WriteLostSigner(unrelated));
        BOOST_REQUIRE(WalletBatch{internal->GetDatabase()}.EraseVaultState());
        BOOST_REQUIRE(WalletBatch{internal->GetDatabase()}.EraseVaultMetadataPolicy());
    }
    installed->wallet->remove();
    installed->wallet.reset();

    warnings.clear();
    auto migrated{loader->loadWallet(name, warnings)};
    BOOST_REQUIRE_MESSAGE(migrated, util::ErrorString(migrated).original);
    status = (*migrated)->getVaultStatus();
    BOOST_CHECK(status.setup_state == interfaces::Wallet::VaultSetupState::NOT_RECORDED);
    BOOST_CHECK(status.verification_state == interfaces::Wallet::VaultVerificationState::NOT_RECORDED);
    BOOST_CHECK(std::ranges::find(status.lost_signers, fingerprint) != status.lost_signers.end());
    BOOST_CHECK(std::ranges::find(status.manually_lost_signers, fingerprint) != status.manually_lost_signers.end());
    BOOST_CHECK(std::ranges::find(status.lost_signers, unrelated) == status.lost_signers.end());
    BOOST_CHECK(std::ranges::find(status.manually_lost_signers, unrelated) == status.manually_lost_signers.end());
    BOOST_CHECK(std::ranges::any_of(status.participants, [&](const auto& participant) {
        return participant.fingerprint == fingerprint && participant.is_lost;
    }));
    {
        CWallet* internal{Assert((*migrated)->wallet())};
        LOCK(internal->cs_wallet);
        BOOST_CHECK_EQUAL(internal->m_vault_metadata_policy_commitment.size(), 64U);
    }
    (*migrated)->remove();
}

BOOST_FIXTURE_TEST_CASE(ordinary_legacy_lost_marker_remains_loadable, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    const std::string name{"ordinary_legacy_lost_marker"};
    std::vector<bilingual_str> warnings;
    auto created{loader->createWallet(
        name, SecureString{}, WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET,
        warnings)};
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    auto ordinary_wallet{std::move(*created)};
    const std::string fingerprint{"deadbeef"};
    BOOST_REQUIRE(ordinary_wallet->setLostSigner(fingerprint, /*lost=*/true));
    ordinary_wallet->remove();
    ordinary_wallet.reset();

    warnings.clear();
    auto reloaded{loader->loadWallet(name, warnings)};
    BOOST_REQUIRE_MESSAGE(reloaded, util::ErrorString(reloaded).original);
    {
        CWallet* internal{Assert((*reloaded)->wallet())};
        LOCK(internal->cs_wallet);
        BOOST_CHECK(internal->m_lost_signers.contains(fingerprint));
        BOOST_CHECK(internal->m_manually_lost_signers.empty());
        BOOST_CHECK(internal->m_vault_metadata_policy_commitment.empty());
    }
    BOOST_REQUIRE((*reloaded)->setLostSigner(fingerprint, /*lost=*/false));
    (*reloaded)->remove();
}

BOOST_FIXTURE_TEST_CASE(custom_vault_legacy_loss_is_not_discarded, TestChain100Setup)
{
    std::vector<MultisigKeySpec> specs(3);
    for (auto& spec : specs)
        spec.generate_local = true;
    MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.fallback_older = 2;
    auto prepared{PrepareMultisigDescriptor(/*nrequired=*/2, specs, options)};
    BOOST_REQUIRE_MESSAGE(prepared, util::ErrorString(prepared).original);
    BOOST_REQUIRE_EQUAL(prepared->recovery.size(), 3U);

    VaultPolicyPackage policy;
    policy.network = Params().GetChainTypeString();
    policy.nrequired = 2;
    policy.fallback_older = 2;
    policy.recovery_stages = {{2, 2, {}}};
    policy.descs = prepared->descs;
    policy.policy_id = prepared->policy_id;

    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    const std::string name{"custom_vault_legacy_loss"};
    std::vector<bilingual_str> warnings;
    auto created{loader->createWallet(
        name, SecureString{},
        WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS |
            WALLET_FLAG_BLANK_WALLET,
        warnings)};
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    auto custom_wallet{std::move(*created)};
    BOOST_REQUIRE(custom_wallet->importVaultPolicy(FormatVaultPolicyPackage(policy)));
    const std::string fingerprint{prepared->recovery.front().fingerprint};
    {
        CWallet* internal{Assert(custom_wallet->wallet())};
        LOCK(internal->cs_wallet);
        BOOST_REQUIRE(WalletBatch{internal->GetDatabase()}.WriteLostSigner(fingerprint));
    }
    custom_wallet->remove();
    custom_wallet.reset();

    warnings.clear();
    auto migrated{loader->loadWallet(name, warnings)};
    BOOST_REQUIRE_MESSAGE(migrated, util::ErrorString(migrated).original);
    const auto status{(*migrated)->getVaultStatus()};
    BOOST_CHECK(status.is_vault);
    BOOST_CHECK(std::ranges::find(status.lost_signers, fingerprint) !=
                status.lost_signers.end());
    BOOST_CHECK(std::ranges::find(status.manually_lost_signers, fingerprint) !=
                status.manually_lost_signers.end());
    (*migrated)->remove();
}

BOOST_FIXTURE_TEST_CASE(corrupt_manual_lost_provenance_aborts_wallet_load, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_corrupt_manual_loss"};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::CREATE, warnings)};
    BOOST_REQUIRE_MESSAGE(installed, util::ErrorString(installed).original);
    auto status{installed->wallet->getVaultStatus()};
    BOOST_REQUIRE_EQUAL(status.participants.size(), 3U);
    const std::string fingerprint{status.participants.front().fingerprint};
    BOOST_REQUIRE(installed->wallet->setLostSigner(fingerprint, /*lost=*/true));

    // A valid manual marker is always paired atomically with LOST_SIGNER.
    // Simulate database corruption that removes only that required partner.
    {
        CWallet* internal{Assert(installed->wallet->wallet())};
        LOCK(internal->cs_wallet);
        BOOST_REQUIRE(WalletBatch{internal->GetDatabase()}.EraseLostSigner(fingerprint));
    }
    installed->wallet->remove();
    installed->wallet.reset();

    warnings.clear();
    const auto corrupted{loader->loadWallet(name, warnings)};
    BOOST_CHECK(!corrupted);
    BOOST_CHECK(loader->getWallets().empty());
}

BOOST_FIXTURE_TEST_CASE(manual_loss_without_policy_binding_aborts_wallet_load, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_missing_loss_binding"};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::CREATE, warnings)};
    BOOST_REQUIRE_MESSAGE(installed, util::ErrorString(installed).original);
    const auto status{installed->wallet->getVaultStatus()};
    BOOST_REQUIRE_EQUAL(status.participants.size(), 3U);
    BOOST_REQUIRE(installed->wallet->setLostSigner(
        status.participants.front().fingerprint, /*lost=*/true));

    // A manual marker without its full active-policy trust anchor is neither
    // valid current metadata nor a legacy LOST_SIGNER-only wallet.
    {
        CWallet* internal{Assert(installed->wallet->wallet())};
        LOCK(internal->cs_wallet);
        BOOST_REQUIRE(WalletBatch{internal->GetDatabase()}.EraseVaultMetadataPolicy());
    }
    installed->wallet->remove();
    installed->wallet.reset();

    warnings.clear();
    const auto corrupted{loader->loadWallet(name, warnings)};
    BOOST_CHECK(!corrupted);
    BOOST_CHECK(loader->getWallets().empty());
}

BOOST_FIXTURE_TEST_CASE(fixed_vault_install_failures_never_publish_final_name, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    std::vector<bilingual_str> warnings;

    const std::string noncanonical_name{"fixed_vault_noncanonical"};
    auto noncanonical{loader->installFixedVault(
        noncanonical_name, candidate.package + "\n", candidate.mnemonics,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE(!noncanonical);
    BOOST_CHECK(!fs::exists(GetWalletDir() / fs::PathFromString(noncanonical_name)));

    const std::string invalid_phrase_name{"fixed_vault_invalid_phrase"};
    const std::string invalid_text{"not a valid recovery phrase"};
    std::vector<SecureString> invalid_phrases{
        SecureString{invalid_text.begin(), invalid_text.end()},
    };
    auto invalid_phrase{loader->installFixedVault(
        invalid_phrase_name, candidate.package, invalid_phrases,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE(!invalid_phrase);
    BOOST_CHECK(!fs::exists(GetWalletDir() / fs::PathFromString(invalid_phrase_name)));

    // Force loading the atomically published database to fail. Publication
    // rollback must remove the final hard link before returning the error.
    const std::string load_failure_name{"fixed_vault_load_failure"};
    auto throwing_load_handler{loader->handleLoadWallet([](std::unique_ptr<interfaces::Wallet>) {
        throw std::runtime_error{"injected fixed vault load failure"};
    })};
    auto load_failure{loader->installFixedVault(
        load_failure_name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE(!load_failure);
    BOOST_CHECK(!fs::exists(GetWalletDir() / fs::PathFromString(load_failure_name)));
    throwing_load_handler.reset();

    // AddWallet() registers the wallet before it emits this signal. A signal
    // exception must still unregister the wallet before publication rollback.
    const std::string add_failure_name{"fixed_vault_add_failure"};
    std::unique_ptr<interfaces::Handler> add_thrower;
    auto add_load_handler{loader->handleLoadWallet([&](std::unique_ptr<interfaces::Wallet> wallet) {
        add_thrower = wallet->handleCanGetAddressesChanged([] {
            throw std::runtime_error{"injected fixed vault AddWallet failure"};
        });
    })};
    auto add_failure{loader->installFixedVault(
        add_failure_name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE(!add_failure);
    BOOST_CHECK(util::ErrorString(add_failure).original.find("injected fixed vault AddWallet failure") != std::string::npos);
    add_thrower.reset();
    add_load_handler.reset();
    BOOST_CHECK(!fs::exists(GetWalletDir() / fs::PathFromString(add_failure_name)));
    BOOST_CHECK(loader->getWallets().empty());

    // Force the atomic no-overwrite publication step to lose a race after the
    // staging wallet has been completed. The existing final path must survive.
    const std::string collision_name{"fixed_vault_collision"};
    const fs::path collision_path{GetWalletDir() / fs::PathFromString(collision_name)};
    BOOST_REQUIRE(fs::create_directory(collision_path));
    auto collision{loader->installFixedVault(
        collision_name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE(!collision);
    BOOST_CHECK(fs::is_directory(collision_path));
    BOOST_CHECK(fs::is_empty(collision_path));
    CheckNoFixedVaultStages(GetWalletDir());
}

BOOST_FIXTURE_TEST_CASE(fixed_vault_post_init_failure_unregisters_and_rolls_back, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_post_init_failure"};
    const fs::path final_path{GetWalletDir() / fs::PathFromString(name)};

    // postInitProcess() asks the chain for current mempool transactions after
    // AddWallet() has registered the wallet. A relevant transaction lets this
    // callback inject a failure at that exact boundary.
    const CMutableTransaction mempool_tx{TestSimpleSpend(
        *m_coinbase_txns.front(), 0, coinbaseKey, FirstFixedVaultScript(candidate))};
    std::string broadcast_error;
    BOOST_REQUIRE(m_node.chain->broadcastTransaction(
        MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE,
        node::TxBroadcast::MEMPOOL_NO_BROADCAST, broadcast_error));

    std::unique_ptr<interfaces::Handler> post_init_thrower;
    auto load_handler{loader->handleLoadWallet([&](std::unique_ptr<interfaces::Wallet> wallet) {
        post_init_thrower = wallet->handleTransactionChanged([](const Txid&, ChangeType) {
            throw std::runtime_error{"injected fixed vault post-init failure"};
        });
    })};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE(!installed);
    BOOST_CHECK(util::ErrorString(installed).original.find("injected fixed vault post-init failure") != std::string::npos);
    post_init_thrower.reset();
    load_handler.reset();

    BOOST_CHECK(!fs::exists(final_path));
    BOOST_CHECK(loader->getWallets().empty());
    CheckNoFixedVaultStages(GetWalletDir());
}

#ifndef WIN32
BOOST_FIXTURE_TEST_CASE(fixed_vault_rollback_refuses_replaced_final_path, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_replaced_during_rollback"};
    const fs::path final_path{GetWalletDir() / fs::PathFromString(name)};

    auto load_handler{loader->handleLoadWallet([&](std::unique_ptr<interfaces::Wallet>) {
        std::error_code error;
        if (!fs::remove(final_path, error) || error) {
            throw std::runtime_error{strprintf("unable to inject final-path replacement: %s", error.message())};
        }
        if (!fs::create_directory(final_path, error) || error) {
            throw std::runtime_error{strprintf("unable to inject replacement directory: %s", error.message())};
        }
        throw std::runtime_error{"injected fixed vault load failure after path replacement"};
    })};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE(!installed);
    const std::string install_error{util::ErrorString(installed).original};
    BOOST_CHECK(install_error.find("final-name publication rollback failed") != std::string::npos);
    BOOST_CHECK(install_error.find("refusing to remove it") != std::string::npos);
    BOOST_CHECK(fs::is_directory(final_path));
    BOOST_CHECK(loader->getWallets().empty());
    CheckNoFixedVaultStages(GetWalletDir());

    load_handler.reset();
    std::error_code cleanup_error;
    BOOST_CHECK(fs::remove(final_path, cleanup_error));
    BOOST_CHECK(!cleanup_error);
}

BOOST_FIXTURE_TEST_CASE(fixed_vault_rollback_refuses_replaced_regular_file, TestChain100Setup)
{
    auto loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))};
    FixedVaultCandidate candidate{PrepareFixedVaultCandidate()};
    const std::string name{"fixed_vault_regular_replacement"};
    const fs::path final_path{GetWalletDir() / fs::PathFromString(name)};
    const std::string replacement_contents{"unrelated replacement file\n"};

    auto load_handler{loader->handleLoadWallet([&](std::unique_ptr<interfaces::Wallet>) {
        std::error_code error;
        if (!fs::remove(final_path, error) || error) {
            throw std::runtime_error{strprintf("unable to inject final-path replacement: %s", error.message())};
        }
        if (!WriteBinaryFile(final_path, replacement_contents)) {
            throw std::runtime_error{"unable to inject replacement regular file"};
        }
        throw std::runtime_error{"injected fixed vault load failure after regular-file replacement"};
    })};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        name, candidate.package, candidate.mnemonics,
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    BOOST_REQUIRE(!installed);
    const std::string install_error{util::ErrorString(installed).original};
    BOOST_CHECK(install_error.find("final-name publication rollback failed") != std::string::npos);
    BOOST_CHECK(install_error.find("different regular file") != std::string::npos);
    const auto [read_ok, contents]{ReadBinaryFile(final_path)};
    BOOST_REQUIRE(read_ok);
    BOOST_CHECK_EQUAL(contents, replacement_contents);
    BOOST_CHECK(loader->getWallets().empty());
    CheckNoFixedVaultStages(GetWalletDir());

    load_handler.reset();
    std::error_code cleanup_error;
    BOOST_CHECK(fs::remove(final_path, cleanup_error));
    BOOST_CHECK(!cleanup_error);
}
#endif // WIN32

static CMutableTransaction TestSimpleSpend(const CTransaction& from, uint32_t index, const CKey& key, const CScript& pubkey)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(from.vout[index].nValue - DEFAULT_TRANSACTION_MAXFEE, pubkey);
    mtx.vin.push_back({CTxIn{from.GetHash(), index}});
    FillableSigningProvider keystore;
    keystore.AddKey(key);
    std::map<COutPoint, Coin> coins;
    coins[mtx.vin[0].prevout].out = from.vout[index];
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(mtx, &keystore, coins, {.sighash_type = SIGHASH_ALL}, input_errors));
    return mtx;
}

static void AddKey(CWallet& wallet, const CKey& key)
{
    LOCK(wallet.cs_wallet);
    FlatSigningProvider provider;
    std::string error;
    auto descs = Parse("combo(" + EncodeSecret(key) + ")", provider, error, /* require_checksum=*/ false);
    assert(descs.size() == 1);
    auto& desc = descs.at(0);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    Assert(wallet.AddWalletDescriptor(w_desc, provider, "", false));
}

BOOST_FIXTURE_TEST_CASE(update_non_range_descriptor, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        auto key{GenerateRandomKey()};
        auto desc_str{"combo(" + EncodeSecret(key) + ")"};
        FlatSigningProvider provider;
        std::string error;
        auto descs{Parse(desc_str, provider, error, /* require_checksum=*/ false)};
        auto& desc{descs.at(0)};
        WalletDescriptor w_desc{std::move(desc), 0, 0, 0, 0};
        BOOST_CHECK(wallet.AddWalletDescriptor(w_desc, provider, "", false));
        // Wallet should update the non-range descriptor successfully
        BOOST_CHECK(wallet.AddWalletDescriptor(w_desc, provider, "", false));
    }
}

BOOST_FIXTURE_TEST_CASE(scan_for_wallet_transactions, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());

    // Verify ScanForWalletTransactions fails to read an unknown start block.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/{}, /*start_height=*/0, /*max_height=*/{}, reserver, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(newTip->nHeight, newTip->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        std::chrono::steady_clock::time_point fake_time;
        reserver.setNow([&] { fake_time += 60s; return fake_time; });
        reserver.reserve();

        {
            CBlockLocator locator;
            BOOST_CHECK(WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_REQUIRE(!locator.IsNull());
            BOOST_CHECK(locator.vHave.front() == newTip->GetBlockHash());
        }

        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*save_progress=*/true);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 100 * COIN);

        {
            CBlockLocator locator;
            BOOST_CHECK(WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_REQUIRE(!locator.IsNull());
            BOOST_CHECK(locator.vHave.front() == newTip->GetBlockHash());
        }
    }

    // Prune the older block file.
    int file_number;
    {
        LOCK(cs_main);
        file_number = oldTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file_number});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, oldTip->GetBlockHash());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 50 * COIN);
    }

    // Prune the remaining block file.
    {
        LOCK(cs_main);
        file_number = newTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file_number});

    // Verify ScanForWalletTransactions scans no blocks.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, newTip->GetBlockHash());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }
}

BOOST_FIXTURE_TEST_CASE(scan_for_wallet_transactions_abort, TestChain100Setup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    uint256 genesis_hash;
    {
        LOCK(wallet.cs_wallet);
        LOCK(Assert(m_node.chainman)->GetMutex());
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        genesis_hash = m_node.chainman->ActiveChain().Genesis()->GetBlockHash();
    }

    // An abort requested while no rescan is held is stale and must
    // not cancel a later scan.
    wallet.AbortRescan();
    WalletRescanReserver reserver(wallet);
    BOOST_CHECK(reserver.reserve());
    BOOST_CHECK(!wallet.IsAbortingRescan());

    // An abort requested after the reservation but before the scan starts
    // (e.g. while importdescriptors is still deriving keys) must cancel the
    // scan.
    wallet.AbortRescan();
    CWallet::ScanResult result = wallet.ScanForWalletTransactions(genesis_hash, /*start_height=*/0, /*max_height=*/{}, reserver, /*save_progress=*/false);
    BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::USER_ABORT);
    BOOST_CHECK(result.last_scanned_block.IsNull());
    BOOST_CHECK(!result.last_scanned_height);
    BOOST_CHECK(result.last_failed_block.IsNull());
}

// This test verifies that wallet settings can be added and removed
// concurrently, ensuring no race conditions occur during either process.
BOOST_FIXTURE_TEST_CASE(write_wallet_settings_concurrently, TestingSetup)
{
    auto chain = m_node.chain.get();
    const auto NUM_WALLETS{5};

    // Since we're counting the number of wallets, ensure we start without any.
    BOOST_REQUIRE(chain->getRwSetting("wallet").isNull());

    const auto& check_concurrent_wallet = [&](const auto& settings_function, int num_expected_wallets) {
        std::vector<std::thread> threads;
        threads.reserve(NUM_WALLETS);
        for (auto i{0}; i < NUM_WALLETS; ++i) threads.emplace_back(settings_function, i);
        for (auto& t : threads) t.join();

        auto wallets = chain->getRwSetting("wallet");
        BOOST_CHECK_EQUAL(wallets.getValues().size(), num_expected_wallets);
    };

    // Add NUM_WALLETS wallets concurrently, ensure we end up with NUM_WALLETS stored.
    check_concurrent_wallet([&chain](int i) {
        Assert(AddWalletSetting(*chain, strprintf("wallet_%d", i)));
    },
                            /*num_expected_wallets=*/NUM_WALLETS);

    // Remove NUM_WALLETS wallets concurrently, ensure we end up with 0 wallets.
    check_concurrent_wallet([&chain](int i) {
        Assert(RemoveWalletSetting(*chain, strprintf("wallet_%d", i)));
    },
                            /*num_expected_wallets=*/0);
}

static int64_t AddTx(ChainstateManager& chainman, CWallet& wallet, uint32_t lockTime, std::chrono::seconds mock_time, int64_t blockTime)
{
    CMutableTransaction tx;
    TxState state = TxStateInactive{};
    tx.nLockTime = lockTime;
    FakeNodeClock clock{mock_time};
    CBlockIndex* block = nullptr;
    if (blockTime > 0) {
        LOCK(cs_main);
        auto inserted = chainman.BlockIndex().emplace(std::piecewise_construct, std::make_tuple(GetRandHash()), std::make_tuple());
        assert(inserted.second);
        const uint256& hash = inserted.first->first;
        block = &inserted.first->second;
        block->nTime = blockTime;
        block->phashBlock = &hash;
        state = TxStateConfirmed{hash, block->nHeight, /*index=*/0};
    }
    return wallet.AddToWallet(MakeTransactionRef(tx), state, [&](CWalletTx& wtx, bool /* new_tx */) {
        // Assign wtx.m_state to simplify test and avoid the need to simulate
        // reorg events. Without this, AddToWallet asserts false when the same
        // transaction is confirmed in different blocks.
        wtx.m_state = state;
        return true;
    })->nTimeSmart;
}

// Simple test to verify assignment of CWalletTx::nSmartTime value. Could be
// expanded to cover more corner cases of smart time logic.
BOOST_AUTO_TEST_CASE(ComputeTimeSmart)
{
    // New transaction should use clock time if lower than block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 100s, 120), 100);

    // Test that updating existing transaction does not change smart time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 200s, 220), 100);

    // New transaction should use clock time if there's no block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 2, 300s, 0), 300);

    // New transaction should use block time if lower than clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 3, 420s, 400), 400);

    // New transaction should use latest entry time if higher than
    // min(block time, clock time).
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 4, 500s, 390), 400);

    // If there are future entries, new transaction should use time of the
    // newest entry that is no more than 300 seconds ahead of the clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 5, 50s, 600), 300);
}

void TestLoadWallet(const std::string& name, DatabaseFormat format, std::function<void(std::shared_ptr<CWallet>)> f)
{
    node::NodeContext node;
    auto chain{interfaces::MakeChain(node)};
    DatabaseOptions options;
    options.require_format = format;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database{MakeWalletDatabase(name, options, status, error)};
    auto wallet{std::make_shared<CWallet>(chain.get(), "", std::move(database))};
    BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::LOAD_OK);
    WITH_LOCK(wallet->cs_wallet, f(wallet));
}

BOOST_FIXTURE_TEST_CASE(LoadReceiveRequests, TestingSetup)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("receive-requests-%i", format)};
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(PKHash()));
            WalletBatch batch{wallet->GetDatabase()};
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(PKHash(), true));
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(ScriptHash(), true));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "0", "val_rr00"));
            BOOST_CHECK(wallet->EraseAddressReceiveRequest(batch, PKHash(), "0"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "1", "val_rr10"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "1", "val_rr11"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, ScriptHash(), "2", "val_rr20"));
        });
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(wallet->IsAddressPreviouslySpent(PKHash()));
            BOOST_CHECK(wallet->IsAddressPreviouslySpent(ScriptHash()));
            auto requests = wallet->GetAddressReceiveRequests();
            auto erequests = {"val_rr11", "val_rr20"};
            BOOST_CHECK_EQUAL_COLLECTIONS(requests.begin(), requests.end(), std::begin(erequests), std::end(erequests));
            RunWithinTxn(wallet->GetDatabase(), /*process_desc=*/"test", [](WalletBatch& batch){
                BOOST_CHECK(batch.WriteAddressPreviouslySpent(PKHash(), false));
                BOOST_CHECK(batch.EraseAddressData(ScriptHash()));
                return true;
            });
        });
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(PKHash()));
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(ScriptHash()));
            auto requests = wallet->GetAddressReceiveRequests();
            auto erequests = {"val_rr11"};
            BOOST_CHECK_EQUAL_COLLECTIONS(requests.begin(), requests.end(), std::begin(erequests), std::end(erequests));
        });
    }
}

class ListCoinsTestingSetup : public TestChain100Setup
{
public:
    ListCoinsTestingSetup()
    {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    }

    ~ListCoinsTestingSetup()
    {
        wallet.reset();
    }

    CWalletTx& AddTx(CRecipient recipient)
    {
        CTransactionRef tx;
        CCoinControl dummy;
        {
            auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, dummy);
            BOOST_CHECK(res);
            tx = res->tx;
        }
        wallet->CommitTransaction(tx);
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx = CMutableTransaction(*wallet->mapWallet.at(tx->GetHash()).GetTx());
        }
        CreateAndProcessBlock({CMutableTransaction(blocktx)}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

        LOCK(wallet->cs_wallet);
        LOCK(Assert(m_node.chainman)->GetMutex());
        wallet->SetLastBlockProcessed(wallet->GetLastBlockHeight() + 1, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        auto it = wallet->mapWallet.find(tx->GetHash());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.m_state = TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/1};
        return it->second;
    }

    std::unique_ptr<CWallet> wallet;
};

BOOST_FIXTURE_TEST_CASE(ListCoinsTest, ListCoinsTestingSetup)
{
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    // Confirm ListCoins initially returns 1 coin grouped under coinbaseKey
    // address.
    std::map<CTxDestination, std::vector<COutput>> list;
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 1U);

    // Check initial balance from one mature coinbase transaction.
    BOOST_CHECK_EQUAL(50 * COIN, WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet).GetTotalAmount()));

    // Add a transaction creating a change address, and confirm ListCoins still
    // returns the coin associated with the change address underneath the
    // coinbaseKey pubkey, even though the change address has a different
    // pubkey.
    AddTx(CRecipient{PubKeyDestination{{}}, 1 * COIN, /*subtract_fee=*/false});
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);

    // Lock both coins. Confirm number of available coins drops to 0.
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoins(*wallet).Size(), 2U);
    }
    for (const auto& group : list) {
        for (const auto& coin : group.second) {
            LOCK(wallet->cs_wallet);
            wallet->LockCoin(coin.outpoint, /*persist=*/false);
        }
    }
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoins(*wallet).Size(), 0U);
    }
    // Confirm ListCoins still returns same result as before, despite coins
    // being locked.
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);
}

void TestCoinsResult(ListCoinsTest& context, OutputType out_type, CAmount amount,
                     std::map<OutputType, size_t>& expected_coins_sizes)
{
    LOCK(context.wallet->cs_wallet);
    util::Result<CTxDestination> dest = Assert(context.wallet->GetNewDestination(out_type, ""));
    CWalletTx& wtx = context.AddTx(CRecipient{*dest, amount, /*fSubtractFeeFromAmount=*/true});
    CoinFilterParams filter;
    filter.skip_locked = false;
    CoinsResult available_coins = AvailableCoins(*context.wallet, nullptr, std::nullopt, filter);
    // Lock outputs so they are not spent in follow-up transactions
    for (uint32_t i = 0; i < wtx.GetTx()->vout.size(); i++) context.wallet->LockCoin({wtx.GetHash(), i}, /*persist=*/false);
    for (const auto& [type, size] : expected_coins_sizes) BOOST_CHECK_EQUAL(size, available_coins.coins[type].size());
}

BOOST_FIXTURE_TEST_CASE(BasicOutputTypesTest, ListCoinsTest)
{
    std::map<OutputType, size_t> expected_coins_sizes;
    for (const auto& out_type : OUTPUT_TYPES) { expected_coins_sizes[out_type] = 0U; }

    // Verify our wallet has one usable coinbase UTXO before starting
    // This UTXO is a P2PK, so it should show up in the Other bucket
    expected_coins_sizes[OutputType::UNKNOWN] = 1U;
    CoinsResult available_coins = WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet));
    BOOST_CHECK_EQUAL(available_coins.Size(), expected_coins_sizes[OutputType::UNKNOWN]);
    BOOST_CHECK_EQUAL(available_coins.coins[OutputType::UNKNOWN].size(), expected_coins_sizes[OutputType::UNKNOWN]);

    // We will create a self transfer for each of the OutputTypes and
    // verify it is put in the correct bucket after running GetAvailablecoins
    //
    // For each OutputType, We expect 2 UTXOs in our wallet following the self transfer:
    //   1. One UTXO as the recipient
    //   2. One UTXO from the change, due to payment address matching logic

    for (const auto& out_type : OUTPUT_TYPES) {
        if (out_type == OutputType::UNKNOWN) continue;
        expected_coins_sizes[out_type] = 2U;
        TestCoinsResult(*this, out_type, 1 * COIN, expected_coins_sizes);
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_disableprivkeys, TestChain100Setup)
{
    const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
}

// Explicit calculation which is used to test the wallet constant
// We get the same virtual size due to rounding(weight/4) for both use_max_sig values
static size_t CalculateNestedKeyhashInputSize(bool use_max_sig)
{
    // Generate ephemeral valid pubkey
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();

    // Generate pubkey hash
    uint160 key_hash(Hash160(pubkey));

    // Create inner-script to enter into keystore. Key hash can't be 0...
    CScript inner_script = CScript() << OP_0 << std::vector<unsigned char>(key_hash.begin(), key_hash.end());

    // Create outer P2SH script for the output
    uint160 script_id(Hash160(inner_script));
    CScript script_pubkey = CScript() << OP_HASH160 << std::vector<unsigned char>(script_id.begin(), script_id.end()) << OP_EQUAL;

    // Add inner-script to key store and key to watchonly
    FillableSigningProvider keystore;
    keystore.AddCScript(inner_script);
    keystore.AddKeyPubKey(key, pubkey);

    // Fill in dummy signatures for fee calculation.
    SignatureData sig_data;

    if (!ProduceSignature(keystore, use_max_sig ? DUMMY_MAXIMUM_SIGNATURE_CREATOR : DUMMY_SIGNATURE_CREATOR, script_pubkey, sig_data)) {
        // We're hand-feeding it correct arguments; shouldn't happen
        assert(false);
    }

    CTxIn tx_in;
    UpdateInput(tx_in, sig_data);
    return (size_t)GetVirtualTransactionInputSize(tx_in);
}

BOOST_FIXTURE_TEST_CASE(dummy_input_size_test, TestChain100Setup)
{
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(false), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(true), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
}

bool malformed_descriptor(std::ios_base::failure e)
{
    std::string s(e.what());
    return s.find("Missing checksum") != std::string::npos;
}

BOOST_FIXTURE_TEST_CASE(wallet_descriptor_test, BasicTestingSetup)
{
    std::vector<unsigned char> malformed_record;
    VectorWriter vw{malformed_record, 0};
    vw << std::string("notadescriptor");
    vw << uint64_t{0};
    vw << int32_t{0};
    vw << int32_t{0};
    vw << int32_t{1};

    SpanReader vr{malformed_record};
    WalletDescriptor w_desc;
    BOOST_CHECK_EXCEPTION(vr >> w_desc, std::ios_base::failure, malformed_descriptor);
}

//! Test CWallet::CreateNew() and its behavior handling potential race
//! conditions if it's called the same time an incoming transaction shows up in
//! the mempool or a new block.
//!
//! It isn't possible to verify there aren't race condition in every case, so
//! this test just checks two specific cases and ensures that timing of
//! notifications in these cases doesn't prevent the wallet from detecting
//! transactions.
//!
//! In the first case, block and mempool transactions are created before the
//! wallet is loaded, but notifications about these transactions are delayed
//! until after it is loaded. The notifications are superfluous in this case, so
//! the test verifies the transactions are detected before they arrive.
//!
//! In the second case, block and mempool transactions are created after the
//! wallet rescan and notifications are immediately synced, to verify the wallet
//! must already have a handler in place for them, and there's no gap after
//! rescanning where new transactions in new blocks could be lost.
BOOST_FIXTURE_TEST_CASE(CreateWallet, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    // Create new wallet with known key and unload it.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);
    CKey key = GenerateRandomKey();
    AddKey(*wallet, key);
    TestUnloadWallet(std::move(wallet));


    // Add log hook to detect AddToWallet events from rescans, blockConnected,
    // and transactionAddedToMempool notifications
    int addtx_count = 0;
    DebugLogHelper addtx_counter("[default wallet] AddToWallet", [&](const std::string* s) {
        if (s) ++addtx_count;
        return false;
    });


    bool rescan_completed = false;
    DebugLogHelper rescan_check("[default wallet] Rescan completed", [&](const std::string* s) {
        if (s) rescan_completed = true;
        return false;
    });


    // Block the queue to prevent the wallet receiving blockConnected and
    // transactionAddedToMempool notifications, and create block and mempool
    // transactions paying to the wallet
    std::promise<void> promise;
    m_node.validation_signals->CallFunctionInValidationInterfaceQueue([&promise] {
        promise.get_future().wait();
    });
    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto mempool_tx = TestSimpleSpend(*m_coinbase_txns[1], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, node::TxBroadcast::MEMPOOL_NO_BROADCAST, error));


    // Reload wallet and make sure new transactions are detected despite events
    // being blocked
    // Loading will also ask for current mempool transactions
    wallet = TestLoadWallet(context);
    BOOST_CHECK(rescan_completed);
    // AddToWallet events for block_tx and mempool_tx (x2)
    BOOST_CHECK_EQUAL(addtx_count, 3);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->mapWallet.contains(block_tx.GetHash()));
        BOOST_CHECK(wallet->mapWallet.contains(mempool_tx.GetHash()));
    }


    // Unblock notification queue and make sure stale blockConnected and
    // transactionAddedToMempool events are processed
    promise.set_value();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    // AddToWallet events for block_tx and mempool_tx events are counted a
    // second time as the notification queue is processed
    BOOST_CHECK_EQUAL(addtx_count, 5);


    TestUnloadWallet(std::move(wallet));


    // Load wallet again, this time creating new block and mempool transactions
    // paying to the wallet as the wallet finishes loading and syncing the
    // queue so the events have to be handled immediately. Releasing the wallet
    // lock during the sync is a little artificial but is needed to avoid a
    // deadlock during the sync and simulates a new block notification happening
    // as soon as possible.
    addtx_count = 0;
    auto handler = HandleLoadWallet(context, [&](std::unique_ptr<interfaces::Wallet> wallet) {
            BOOST_CHECK(rescan_completed);
            m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            block_tx = TestSimpleSpend(*m_coinbase_txns[2], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            mempool_tx = TestSimpleSpend(*m_coinbase_txns[3], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, node::TxBroadcast::MEMPOOL_NO_BROADCAST, error));
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
        });
    wallet = TestLoadWallet(context);
    // Since mempool transactions are requested at the end of loading, there will
    // be 2 additional AddToWallet calls, one from the previous test, and a duplicate for mempool_tx
    BOOST_CHECK_EQUAL(addtx_count, 2 + 2);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->mapWallet.contains(block_tx.GetHash()));
        BOOST_CHECK(wallet->mapWallet.contains(mempool_tx.GetHash()));
    }


    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(CreateWalletWithoutChain, BasicTestingSetup)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    BOOST_CHECK(wallet);
    WaitForDeleteWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(RemoveTxs, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestCreateWallet(context);
    CKey key = GenerateRandomKey();
    AddKey(*wallet, key);

    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    {
        auto block_hash = block_tx.GetHash();
        auto prev_tx = m_coinbase_txns[0];

        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->HasWalletSpend(prev_tx));
        BOOST_CHECK(wallet->mapWallet.contains(block_hash));

        std::vector<Txid> vHashIn{ block_hash };
        BOOST_CHECK(wallet->RemoveTxs(vHashIn));

        BOOST_CHECK(!wallet->HasWalletSpend(prev_tx));
        BOOST_CHECK(!wallet->mapWallet.contains(block_hash));
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
