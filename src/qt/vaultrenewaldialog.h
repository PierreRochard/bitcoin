// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_VAULTRENEWALDIALOG_H
#define BITCOIN_QT_VAULTRENEWALDIALOG_H

#include <consensus/amount.h>
#include <interfaces/wallet.h>
#include <qt/bitcoinunits.h>

#include <QDialog>
#include <QString>
#include <QStringList>

#include <cstddef>
#include <optional>
#include <vector>

class PlatformStyle;

QT_BEGIN_NAMESPACE
class QCheckBox;
class QFrame;
class QLabel;
class QProgressBar;
class QPushButton;
class QStackedWidget;
class QVBoxLayout;
QT_END_NAMESPACE

/** One selectable whole privacy group from the read-only wallet status. The
 * identifier is opaque and is never presented to the user. */
struct VaultRenewalGroupPresentation {
    QString identifier;
    CAmount value{0};
    std::size_t coin_count{0};
    bool due{false};
    bool recovery_enabled{false};
    int blocks_until_primary{0};
};

/** Qt-owned presentation data. Coin selection and transaction construction
 * remain authoritative in the wallet backend. */
struct VaultRenewalBatchPresentation {
    QString identifier;
    std::size_t input_count{0};
    CAmount selected{0};
    CAmount fee{0};
    CAmount returned{0};
};

struct VaultRenewalPlanPresentation {
    bool supported{false};
    bool has_due{false};
    bool signers_ready{false};
    bool fees_ready{false};
    QString unavailable_reason;
    QStringList signer_lines;
    QString plan_token;
    std::size_t cluster_count{0};
    std::size_t coin_count{0};
    CAmount selected{0};
    CAmount total_fee{0};
    CAmount returned{0};
    std::size_t excluded_locked_count{0};
    std::size_t excluded_unsafe_count{0};
    std::size_t excluded_unconfirmed_count{0};
    std::size_t excluded_uneconomic_count{0};
    CAmount excluded_locked{0};
    CAmount excluded_unsafe{0};
    CAmount excluded_unconfirmed{0};
    CAmount excluded_uneconomic{0};
    std::vector<VaultRenewalBatchPresentation> batches;
};

struct VaultRenewalResultPresentation {
    std::size_t relayed{0};
    std::size_t stored_not_relayed{0};
    std::size_t failed{0};
    std::size_t already_accepted{0};
    std::size_t not_attempted{0};
    QStringList transaction_ids;
    QStringList failures;
    QString terminal_error;
    bool retry_available{false};
};

struct VaultRenewalSignerPresentation {
    bool ready{false};
    QString reason;
    QStringList roster;
};

/** Translate truthful persisted/fresh signer states into direct-renewal
 * readiness without collapsing UNKNOWN, offline, unavailable, and lost. */
VaultRenewalSignerPresentation PresentVaultRenewalSigners(
    const interfaces::Wallet::VaultStatus& status);

/** Purpose-built, presentation-only surface for renewing a current 90/180
 * Recovery Vault. WalletView coordinates asynchronous backend work. */
class VaultRenewalDialog : public QDialog
{
    Q_OBJECT

public:
    explicit VaultRenewalDialog(const PlatformStyle* platform_style, QWidget* parent = nullptr);

    void setAvailableGroups(
        const std::vector<VaultRenewalGroupPresentation>& groups, bool due,
        const std::optional<QStringList>& selected_ids = std::nullopt);
    void start(bool due);
    void setDisplayUnit(BitcoinUnit unit) { m_display_unit = unit; }
    void setPrivacy(bool privacy);
    void setPlanLoading();
    void setPlan(const VaultRenewalPlanPresentation& plan);
    void setBatch(const VaultRenewalPlanPresentation& batch);
    void setSignerReadiness(bool ready, const QString& reason, const QStringList& roster = {});
    void setPlanError(const QString& error);
    void setSigningProgress(std::size_t completed, std::size_t total, const QString& detail);
    void setBroadcastProgress(std::size_t completed, std::size_t total, const QString& detail);
    void setCancellationPending();
    void setResult(const VaultRenewalResultPresentation& result);
    QStringList selectedGroupIds() const;
    QString currentPlanToken() const { return m_plan.plan_token; }

Q_SIGNALS:
    void planRequested(const QStringList& cluster_ids);
    void batchRequested(const QString& plan_token);
    void signingRequested(const QString& plan_token);
    void cancellationRequested();
    void retryRequested();
    void renewalFinished();

protected:
    void reject() override;

private:
    enum class Page {
        PLAN,
        REVIEW,
        PROGRESS,
        RESULT,
    };

    const PlatformStyle* const m_platform_style;
    VaultRenewalPlanPresentation m_plan;
    std::vector<VaultRenewalGroupPresentation> m_available_groups;
    std::vector<QCheckBox*> m_group_checks;
    QStackedWidget* m_pages{nullptr};
    QFrame* m_scope_card{nullptr};
    QVBoxLayout* m_group_layout{nullptr};
    QPushButton* m_select_default_groups{nullptr};
    QPushButton* m_select_all_groups{nullptr};
    QFrame* m_plan_card{nullptr};
    QLabel* m_plan_privacy_notice{nullptr};
    QLabel* m_plan_status{nullptr};
    QLabel* m_plan_summary{nullptr};
    QLabel* m_plan_exclusions{nullptr};
    QVBoxLayout* m_batch_layout{nullptr};
    QLabel* m_signer_status{nullptr};
    QLabel* m_signer_roster{nullptr};
    QPushButton* m_review_button{nullptr};
    QPushButton* m_refresh_button{nullptr};
    QLabel* m_review_summary{nullptr};
    QFrame* m_review_card{nullptr};
    QLabel* m_review_privacy_notice{nullptr};
    QVBoxLayout* m_review_batch_layout{nullptr};
    QPushButton* m_sign_button{nullptr};
    QLabel* m_progress_headline{nullptr};
    QLabel* m_progress_detail{nullptr};
    QProgressBar* m_progress{nullptr};
    QPushButton* m_cancel_progress{nullptr};
    QLabel* m_result_headline{nullptr};
    QLabel* m_result_detail{nullptr};
    QPushButton* m_retry_button{nullptr};
    std::optional<VaultRenewalResultPresentation> m_last_result;
    QString m_progress_unmasked_detail;
    bool m_operation_started{false};
    bool m_broadcast_started{false};
    bool m_cancellation_pending{false};
    bool m_started{false};
    bool m_default_due{false};
    bool m_privacy{false};
    BitcoinUnit m_display_unit{BitcoinUnit::BTC};

    void showPage(Page page);
    void requestSelectedPlan();
    void rebuildGroupChoices(const QStringList& selected_ids);
    void updateDefaultSelectionCopy();
    void selectDefaultGroups();
    void selectAllGroups();
    void updatePlanPresentation();
    void renderResult();
    void rebuildBatches(QVBoxLayout* layout, bool detailed);
    QString amountText(CAmount amount) const;
};

#endif // BITCOIN_QT_VAULTRENEWALDIALOG_H
