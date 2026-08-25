// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include <interfaces/wallet.h>

#include <QString>
#include <QWidget>

#include <memory>
#include <string>

class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;
class MultisigWizardTests;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QLabel;
class QHBoxLayout;
class QModelIndex;
class QPushButton;
class QVBoxLayout;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

    friend class MultisigWizardTests;

public:
    struct VaultRenewalReminderDecision {
        bool notify{false};
        bool clear{false};
    };

    explicit OverviewPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~OverviewPage();

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);
    void showOutOfSyncWarning(bool fShow);
    static VaultRenewalReminderDecision vaultRenewalReminderDecision(
        const std::string& due_set_digest, const QString& previous_digest,
        bool privacy, bool initial_block_download, bool supported = true);

public Q_SLOTS:
    void setBalance(const interfaces::WalletBalances& balances);
    void setPrivacy(bool privacy);

Q_SIGNALS:
    void transactionClicked(const QModelIndex& index);
    void outOfSyncWarningClicked();
    void delayedRecoveryRequested();
    void vaultRenewalRequested(bool due);
    void vaultRenewalReminderRequested(const QString& title, const QString& message);
    void finishVaultSetupRequested();
    void recoveryKitRequested();
    void retryVaultRescanRequested();

protected:
    void changeEvent(QEvent* e) override;

private:
    Ui::OverviewPage *ui;
    ClientModel* clientModel{nullptr};
    WalletModel* walletModel{nullptr};
    bool m_privacy{false};
    interfaces::WalletBalances m_balances;
    interfaces::Wallet::VaultStatus m_vault_status;
    wallet::VaultRenewalStatus m_vault_renewal_status;

    QWidget* m_vault_dashboard{nullptr};
    QWidget* m_vault_setup_card{nullptr};
    QWidget* m_vault_rescan_card{nullptr};
    QWidget* m_vault_protection_card{nullptr};
    QWidget* m_vault_actions{nullptr};
    QWidget* m_vault_protected_stat{nullptr};
    QWidget* m_vault_recovery_enabled_stat{nullptr};
    QWidget* m_vault_due_stat{nullptr};
    QWidget* m_vault_unconfirmed_stat{nullptr};
    QLabel* m_vault_total_amount{nullptr};
    QLabel* m_vault_balance_status{nullptr};
    QLabel* m_vault_immediate_amount{nullptr};
    QLabel* m_vault_immediate_quorum{nullptr};
    QLabel* m_vault_protected_amount{nullptr};
    QLabel* m_vault_recovery_enabled_amount{nullptr};
    QLabel* m_vault_due_amount{nullptr};
    QLabel* m_vault_unconfirmed_amount{nullptr};
    QLabel* m_vault_next_expansion{nullptr};
    QLabel* m_vault_protection_explanation{nullptr};
    QPushButton* m_vault_renewal_button{nullptr};
    QPushButton* m_vault_access_details{nullptr};
    QLabel* m_vault_setup_heading{nullptr};
    QLabel* m_vault_setup_status{nullptr};
    QLabel* m_vault_verification_status{nullptr};
    QPushButton* m_finish_vault_setup{nullptr};
    QPushButton* m_retry_vault_rescan{nullptr};
    QPushButton* m_refresh_participants{nullptr};
    QPushButton* m_start_delayed_recovery{nullptr};
    QLabel* m_delayed_recovery_availability{nullptr};
    QHBoxLayout* m_vault_stages_layout{nullptr};
    QVBoxLayout* m_vault_participants_layout{nullptr};

    const PlatformStyle* m_platform_style;

    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;

    void buildVaultDashboard();
    void updateVaultDashboard();
    void rebuildVaultStages();
    void rebuildVaultParticipants();
    void updateVaultProtectionCard();
    void checkVaultRenewalReminder();
    void setVaultSignerLost(const std::string& fingerprint, bool lost,
                            const std::optional<std::string>& expected_policy_commitment);

private Q_SLOTS:
    void LimitTransactionRows();
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void updateAlerts(const QString &warnings);
    void setMonospacedFont(const QFont&);
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
