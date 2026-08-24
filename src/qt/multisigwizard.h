// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MULTISIGWIZARD_H
#define BITCOIN_QT_MULTISIGWIZARD_H

#include <addresstype.h>
#include <cstdint>
#include <optional>
#include <outputtype.h>
#include <util/result.h>
#include <util/translation.h>
#include <wallet/multisig.h>

#include <QString>
#include <QWizard>

#include <vector>

class WalletController;
class WalletModel;
class MultisigWizardTests;
class QCloseEvent;

namespace interfaces {
class Node;
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

    //! ~90 days at 10-minute blocks. Calendar dates derived from this are estimates.
    static constexpr uint32_t kDefaultVaultDelay{12960};
    //! Approximate 30/60-day relative-delay stages at 144 blocks per day.
    static constexpr uint32_t kThirtyDayVaultDelay{4320};
    static constexpr uint32_t kSixtyDayVaultDelay{8640};
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
    WalletModel* createdWallet() const { return m_wallet_model; }

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

    bool createWallet();
    bool restoreFromRecoverySheets(const QString& wallet_name, const QString& policy_json,
                                   const std::vector<SecureString>& mnemonics, QString& error);
    QString createError() const { return m_create_error; }
    util::Result<CTxDestination> firstReceiveAddress();
    util::Result<void> verifyOnDevice(const std::string& fingerprint);

    interfaces::Node& node() const { return m_node; }

Q_SIGNALS:
    void created(WalletModel* wallet_model);

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
    void lockCommittedJourney();
    void publishCreatedWallet();
    void clearSoftwareRecovery();
    QString privateRecoveryKitHtml() const;
    QString walletNameError(const QString& name) const;
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
    std::vector<wallet::MultisigKeySpec> m_airgapped;
    std::vector<wallet::MultisigKeySpec> m_keys;
    int m_nrequired{2};
    std::optional<uint32_t> m_fallback_older{kThirtyDayVaultDelay};
    std::optional<uint32_t> m_fallback_older_one_key{kSixtyDayVaultDelay};
    std::optional<uint32_t> m_fallback_after;
    std::vector<std::string> m_public_descs;
    WalletModel* m_wallet_model{nullptr};
    QString m_create_error;
    QString m_receive_address;
    QString m_policy_id;
    QString m_policy_package;
    //! One locked-memory BIP39 phrase for every generated software-key slot.
    //! These never enter the public package, transcript, clipboard, or logs.
    std::vector<wallet::GeneratedMnemonic> m_software_recovery;
    bool m_setup_committed{false};
    bool m_created_emitted{false};
    bool m_advanced_flow{false};
};

#endif // BITCOIN_QT_MULTISIGWIZARD_H
