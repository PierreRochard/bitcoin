// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MULTISIGWIZARD_H
#define BITCOIN_QT_MULTISIGWIZARD_H

#include <addresstype.h>
#include <interfaces/external_signer.h>
#include <outputtype.h>
#include <util/result.h>
#include <util/translation.h>
#include <wallet/multisig.h>
#include <wallet/vault_state.h>

#include <QPointer>
#include <QString>
#include <QWizard>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

class WalletController;
class WalletModel;
class MultisigWizardTests;
class QCloseEvent;
class QLockFile;

namespace interfaces {
class Node;
class Wallet;
} // namespace interfaces

/** Guided staged Scrooge-vault setup: three keys, backup, and verification.
 *
 * Modeled on Sparrow's keystore list, Specter's device-then-wallet flow, and
 * BlueWallet's plain-language vault copy. Bech32m with a recovery delay is a
 * Scrooge vault (bitcoin#24861). The wallet itself is Core's mixed-key
 * descriptor wallet plus createmultisigdescriptor.
 */
class MultisigWizard : public QWizard
{
    Q_OBJECT

public:
    enum PageId {
        Page_Intro,
        Page_Template,
        Page_Setup,
        Page_Keys,
        Page_Threshold,
        Page_Backup,
        Page_Verify,
        Page_Done,
    };

    enum class VaultTemplate {
        RecoverOneLost,
        StagedRecovery,
        Maximum,
        HardwareCoordinator,
        Inheritance,
        Custom,
    };

    //! Calendar dates derived from block delays are estimates.
    static constexpr uint32_t kDefaultVaultDelay{wallet::FIXED_VAULT_CURRENT_PRIMARY_DELAY};
    static constexpr uint32_t kCurrentPrimaryVaultDelay{wallet::FIXED_VAULT_CURRENT_PRIMARY_DELAY};
    static constexpr uint32_t kCurrentFinalVaultDelay{wallet::FIXED_VAULT_CURRENT_FINAL_DELAY};
    static constexpr int kStagedVaultKeyCount{3};
    static constexpr int kMaxLocalSoftwareKeys{3};

    explicit MultisigWizard(interfaces::Node& node, WalletController* wallet_controller, QWidget* parent = nullptr);
    ~MultisigWizard() override;

    QString walletName() const { return m_wallet_name; }
    int nrequired() const { return m_nrequired; }
    std::optional<uint32_t> fallbackOlder() const { return m_fallback_older; }
    std::optional<uint32_t> fallbackOlderOneKey() const { return m_fallback_older_one_key; }
    std::optional<uint32_t> fallbackAfter() const { return m_fallback_after; }
    VaultTemplate vaultTemplate() const { return m_template; }
    bool preferNMinus1() const { return m_prefer_n_minus_1; }
    const std::vector<wallet::MultisigKeySpec>& keys() const { return m_keys; }
    int nActiveKeys() const;
    OutputType outputType() const { return m_type; }
    int localKeyCount() const { return m_local_key_count; }
    bool includeLocalKey() const { return m_local_key_count > 0; }
    bool advancedFlow() const { return m_advanced_flow; }
    WalletModel* createdWallet() const { return m_wallet_model.data(); }

    /** Open the Recovery Kit restore journey. A first-class File-menu launch
     * closes this otherwise unused setup host when the nested journey ends;
     * callers never need to enter the creation journey first. */
    void startRestore(bool standalone = false);
    //! Continue the non-destructive verification/finish portion of setup for
    //! an already-created Recovery Vault. This never recreates the wallet or
    //! changes its descriptors.
    bool resumeSetup(WalletModel* wallet_model);

    void setWalletName(const QString& name);
    void setLocalKeyCount(int count);
    void setIncludeLocalKey(bool include);
    void setOutputType(OutputType type);
    void setNRequired(int n);
    void setFallbackOlder(std::optional<uint32_t> blocks);
    void setFallbackOlderOneKey(std::optional<uint32_t> blocks);
    void setFallbackAfter(std::optional<uint32_t> height);
    void setVaultTemplate(VaultTemplate tmpl);
    void applyTemplate();
    void setReceiveAddress(const QString& address) { m_receive_address = address; }
    void addHardwareKey(const std::string& fingerprint, const std::string& label);
    void addAirgappedKey(const std::string& fingerprint, const std::string& path, const std::string& xpub, const std::string& label, bool recovery_only = false);
    void rebuildKeyList();
    void refreshHardware();

    QString transcript() const;
    bilingual_str policyError() const;

    //! Prepare and validate the fixed-flow policy and recovery material in
    //! memory. Advanced flows retain their established create-on-commit path.
    bool createWallet();
    //! Persist the already prepared fixed-flow candidate. This is called only
    //! after Secure Recovery has deleted its managed temporary PDF.
    bool commitWalletCandidate();
    bool restoreFromRecoverySheets(const QString& wallet_name, const QString& policy_json,
                                   const std::vector<SecureString>& mnemonics, QString& error,
                                   std::set<std::string> matched_hardware = {},
                                   bool enable_external_signing = false);
    bool retryRecoveryRescan(WalletModel* wallet_model, QString& error);
    //! Validate a proposed wallet name without creating or loading anything.
    QString walletNameError(const QString& name) const;
    QString createError() const { return m_create_error; }
    util::Result<CTxDestination> firstReceiveAddress();
    util::Result<void> verifyOnDevice(const std::string& fingerprint);

    interfaces::Node& node() const { return m_node; }

Q_SIGNALS:
    void created(WalletModel* wallet_model);
    void receiveRequested(WalletModel* wallet_model, const QString& address);
    void restoreCompleted();
    void restoreInstalled(WalletModel* wallet_model);
    void restoreRescanStarted(WalletModel* wallet_model);
    void restoreAttemptFailed(const QString& error);
    void restoreRescanRetryRequired(WalletModel* wallet_model, const QString& error);

public Q_SLOTS:
    void accept() override;
    void reject() override;

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    friend class MultisigIntroPage;
    friend class MultisigTemplatePage;
    friend class MultisigSetupPage;
    friend class MultisigKeysPage;
    friend class MultisigThresholdPage;
    friend class MultisigBackupPage;
    friend class MultisigVerifyPage;
    friend class MultisigDonePage;
    friend class MultisigWizardTests;

    void refreshSidebar();
    void cleanupPrivatePrintOnClose();
    void retainPrivatePrintCleanup(QString path, std::unique_ptr<QLockFile> lock);
    void verifyOnDeviceAsync(
        const std::string& fingerprint,
        std::function<void(util::Result<interfaces::ExternalSignerAddressVerification>)> callback);
    void enableAdvancedFlow();
    void lockCommittedJourney();
    void configureNavigation(int page_id);
    bool persistSetupState(int setup_state, int verification_state);
    bool persistParticipantTypes();
    void publishCreatedWallet();
    void clearSoftwareRecovery();
    void completeRecoveryRestore(WalletModel* wallet_model);
    bool removePrivatePrintPath(const QString& path) const;
    QString privateRecoveryKitHtml() const;
    QString suggestedWalletName(const QString& base) const;

    interfaces::Node& m_node;
    WalletController* m_wallet_controller;
    QString m_wallet_name{"Vault"};
    OutputType m_type{OutputType::BECH32M};
    int m_local_key_count{kStagedVaultKeyCount};
    int m_last_local_key_count{kStagedVaultKeyCount};
    bool m_last_airgap_recovery_only{false};
    bool m_prefer_n_minus_1{false};
    VaultTemplate m_template{VaultTemplate::StagedRecovery};
    std::vector<wallet::MultisigKeySpec> m_hardware;
    //! Fixed-flow hardware identity binding: fingerprint -> {account path,
    //! account xpub}. Hardware specs intentionally remain distinct from
    //! advanced-flow air-gapped xpubs so address display is still required.
    std::map<std::string, std::pair<std::string, std::string>> m_fixed_hardware_accounts;
    //! Fixed-flow devices that explicitly support a physical multisig address
    //! display. Other connected devices remain valid signing participants but
    //! cannot turn Review into independent verification.
    std::set<std::string> m_fixed_address_display_devices;
    //! Focused-test seam for the asynchronous post-install rescan. Production
    //! leaves this empty and always invokes interfaces::Wallet directly.
    std::function<util::Result<void>(interfaces::Wallet&)> m_restore_rescan_override;
    std::optional<wallet::VaultPolicyPackage> m_pending_restore_package;
    QString m_pending_restore_name;
    size_t m_pending_restore_recovered_count{0};
    std::vector<wallet::MultisigKeySpec> m_airgapped;
    std::vector<wallet::MultisigKeySpec> m_keys;
    int m_nrequired{2};
    std::optional<uint32_t> m_fallback_older{kCurrentPrimaryVaultDelay};
    std::optional<uint32_t> m_fallback_older_one_key{kCurrentFinalVaultDelay};
    std::optional<uint32_t> m_fallback_after;
    std::vector<std::string> m_public_descs;
    //! Fully resolved public key sources for the fixed in-memory candidate.
    //! Generated software slots remain marked generate_local until commit,
    //! when their already printed mnemonics are supplied instead.
    std::vector<wallet::MultisigKeySpec> m_candidate_keys;
    QPointer<WalletModel> m_wallet_model;
    QString m_create_error;
    QString m_receive_address;
    QString m_policy_id;
    QString m_policy_package;
    //! Full canonical public-policy commitment captured before any
    //! asynchronous verification or installation work. Durable state writes
    //! compare-and-set against it under the wallet lock.
    std::optional<std::string> m_expected_policy_commitment;
    //! Whether the policy prepared and reviewed by this wizard is a Recovery
    //! Vault. Ordinary advanced multisig policies have no vault setup metadata
    //! to persist, while a prepared vault must still fail closed if the active
    //! wallet policy is replaced with an ordinary descriptor.
    bool m_prepared_policy_is_vault{false};
    //! Source records that still need durable persistence after the wallet is
    //! committed. Partial failures keep setup incomplete and can be retried
    //! without retaining mnemonic material.
    std::map<std::string, wallet::VaultParticipantType> m_pending_participant_types;
    //! One locked-memory BIP39 phrase for every generated software-key slot.
    //! These never enter the public package, transcript, clipboard, or logs.
    std::vector<wallet::GeneratedMnemonic> m_software_recovery;
    bool m_setup_committed{false};
    bool m_created_emitted{false};
    bool m_address_independently_verified{false};
    bool m_recovery_kit_matched{false};
    bool m_finished_without_verification{false};
    bool m_previously_finished_unverified{false};
    bool m_resuming_setup{false};
    bool m_setup_status_not_recorded{false};
    bool m_recovery_kit_status_missing{false};
    bool m_participant_sources_incomplete{false};
    bool m_advanced_flow{false};
    //! Injectable filesystem boundary used by deterministic private-PDF
    //! cleanup tests. Production removal uses QFile::remove().
    std::function<bool(const QString&)> m_private_print_remover;
};

#endif // BITCOIN_QT_MULTISIGWIZARD_H
