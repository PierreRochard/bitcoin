// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/fixed_vault_wallet.h>

#include <common/args.h>
#include <key_io.h>
#include <random.h>
#include <util/fs.h>
#include <util/time.h>
#include <wallet/context.h>
#include <wallet/recovery_vault_kit.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <system_error>

namespace wallet {

util::Result<FixedVaultWalletInstallResult> InstallFixedVaultWallet(
    WalletContext& context,
    const std::string& name,
    const std::string& canonical_package,
    const std::span<const SecureString> mnemonics,
    const FixedVaultWalletInstallMode mode,
    std::vector<bilingual_str>& warnings,
    const bool enable_external_signing,
    const std::optional<FixedVaultWalletInitialMetadata> initial_metadata)
{
    VaultPolicyPackage package;
    try {
        auto parsed{ParseVaultPolicyPackage(canonical_package)};
        if (!parsed) return util::Error{util::ErrorString(parsed)};
        package = std::move(*parsed);
    } catch (const std::exception& e) {
        return util::Error{Untranslated(strprintf("Invalid fixed vault policy package: %s", e.what()))};
    }
    if (FormatVaultPolicyPackage(package) != canonical_package) {
        return util::Error{Untranslated("Fixed vault installation requires the exact canonical public policy package")};
    }
    if (auto fixed{ValidateFixedStagedVaultPolicy(package)}; !fixed) {
        return util::Error{util::ErrorString(fixed)};
    }

    if (!IsValidRecoveryVaultWalletName(name)) {
        return util::Error{Untranslated("Fixed vault installation requires a bounded simple wallet name without path components or control characters")};
    }
    const fs::path wallet_dir{GetWalletDir()};
    const std::string stage_name{".bitcoin-fixed-vault-stage-" + GetRandHash().GetHex()};
    const fs::path stage_dir{fsbridge::AbsPathJoin(wallet_dir, fs::PathFromString(stage_name))};
    struct StageCleanup {
        fs::path path;
        ~StageCleanup()
        {
            std::error_code error;
            fs::remove_all(path, error);
        }
    } stage_cleanup{stage_dir};

    uint64_t flags{WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET};
    if (mnemonics.size() < 3 && enable_external_signing) {
        flags |= WALLET_FLAG_EXTERNAL_SIGNER;
    }
    if (mnemonics.empty()) flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;

    DatabaseOptions options;
    ReadDatabaseArgs(*Assert(context.args), options);
    options.require_create = true;
    options.require_format = DatabaseFormat::SQLITE;
    options.create_flags = flags;
    DatabaseStatus status;
    bilingual_str error;
    std::unique_ptr<WalletDatabase> database{MakeWalletDatabase(stage_name, options, status, error)};
    if (!database) {
        return util::Error{Untranslated("Unable to create fixed vault staging database: ") + error};
    }
    const fs::path stage_database{fs::PathFromString(database->Filename())};
    // The staged wallet must stay detached: registering validation callbacks
    // would retain a shared pointer and keep SQLite's exclusive lock alive
    // across publication.
    WalletContext staging_context;
    staging_context.args = context.args;
    std::shared_ptr<CWallet> staged{CWallet::CreateNew(
        staging_context, stage_name, std::move(database), flags, /*born_encrypted=*/false,
        error, warnings)};
    if (!staged) {
        return util::Error{Untranslated("Unable to initialize fixed vault staging wallet: ") + error};
    }

    const uint64_t creation_time{mode == FixedVaultWalletInstallMode::RESTORE ? uint64_t{0} : static_cast<uint64_t>(GetTime())};
    const FixedVaultWalletInitialMetadata metadata{initial_metadata.value_or(
        FixedVaultWalletInitialMetadata{
            mode == FixedVaultWalletInstallMode::CREATE ? VaultSetupState::ADDRESS_VERIFICATION_REQUIRED : VaultSetupState::RECOVERY_KIT_REQUIRED,
            VaultVerificationState::PENDING,
            std::nullopt,
            false})};
    if (!IsConsistentVaultState(metadata.setup_state, metadata.verification_state)) {
        return util::Error{Untranslated("Fixed vault initial setup and verification states are inconsistent")};
    }
    std::optional<std::string> first_receive_address;
    auto installed = [&]() -> util::Result<std::vector<VaultMnemonicMatch>> {
        LOCK(staged->cs_wallet);
        auto result{InstallFixedVaultPolicy(
            *staged, package, mnemonics, creation_time,
            /*persist_unavailable_as_lost=*/mode == FixedVaultWalletInstallMode::RESTORE)};
        if (!result) return result;
        if (mode == FixedVaultWalletInstallMode::RESTORE) {
            staged->SetWalletFlag(WALLET_FLAG_GENESIS_RESCAN_REQUIRED);
        }
        const std::string policy_commitment{VaultPolicyCommitment(package)};
        if (metadata.mnemonic_participant_type) {
            for (const VaultMnemonicMatch& match : *result) {
                if (!staged->SetVaultParticipantType(
                        match.fingerprint, *metadata.mnemonic_participant_type,
                        policy_commitment)) {
                    return util::Error{Untranslated(
                        "Fixed vault staging wallet could not persist participant provenance")};
                }
            }
        }
        if (!staged->SetVaultSetupState(
                metadata.setup_state, metadata.verification_state,
                policy_commitment)) {
            return util::Error{Untranslated(
                "Fixed vault staging wallet could not bind its incomplete setup state to the installed policy")};
        }
        if (metadata.create_receive_address) {
            auto destination{staged->GetNewDestination(OutputType::BECH32M, "")};
            if (!destination) return util::Error{util::ErrorString(destination)};
            first_receive_address = EncodeDestination(*destination);
        }
        return result;
    }();
    if (!installed) return util::Error{util::ErrorString(installed)};
    if (installed->size() != mnemonics.size()) {
        return util::Error{Untranslated("Fixed vault staging wallet did not install every validated recovery key")};
    }
    {
        LOCK(staged->cs_wallet);
        if (FormatVaultPolicyPackage(ExportWalletVaultPolicy(*staged)) != canonical_package) {
            return util::Error{Untranslated("Fixed vault staging wallet does not reproduce the canonical recovery policy")};
        }
    }
    staged.reset();

    std::shared_ptr<CWallet> published{PublishStagedVaultWallet(
        context, stage_dir, stage_database, name, /*load_on_start=*/true,
        status, error, warnings)};
    if (!published) return util::Error{error};

    return FixedVaultWalletInstallResult{
        std::move(published),
        std::move(*installed),
        std::move(first_receive_address),
    };
}

} // namespace wallet
