// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletview.h>

#include <interfaces/node.h>
#include <node/interface_ui.h>
#include <qt/addressbookpage.h>
#include <qt/askpassphrasedialog.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/receivecoinsdialog.h>
#include <qt/sendcoinsdialog.h>
#include <qt/signverifymessagedialog.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/vaultrenewaldialog.h>
#include <qt/walletmodel.h>
#include <util/strencodings.h>
#include <wallet/coincontrol.h>
#include <wallet/vault_renewal.h>

#include <QAction>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QProgressDialog>
#include <QPushButton>
#include <QSaveFile>
#include <QThreadPool>
#include <QVBoxLayout>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <set>
#include <utility>

enum class VaultRenewalOperationPhase : int {
    SIGNING,
    CANCELLED,
    COMMITTING,
};

class VaultRenewalCoordinator
{
public:
    VaultRenewalCoordinator()
    {
        // Serialize plan, address reservation, signing, and commit work for a
        // wallet. Destruction joins this pool before dependencies disappear.
        workers.setMaxThreadCount(1);
    }

    QPointer<VaultRenewalDialog> dialog;
    std::optional<wallet::VaultRenewalPlan> plan;
    std::optional<wallet::VaultRenewalBatch> batch;
    VaultRenewalPlanPresentation presentation;
    std::optional<VaultRenewalResultPresentation> last_result;
    std::shared_ptr<std::atomic<int>> operation_phase;
    std::unique_ptr<WalletModel::UnlockContext> unlock;
    QString pending_sign_batch_token;
    uint64_t generation{0};
    QThreadPool workers;
};

namespace {
wallet::VaultRenewalRequest BackendRenewalRequest(const QStringList& cluster_ids)
{
    wallet::VaultRenewalRequest request;
    request.scope = wallet::VaultRenewalScope::SELECTED;
    request.cluster_ids.reserve(cluster_ids.size());
    for (const QString& identifier : cluster_ids) {
        request.cluster_ids.push_back(identifier.toStdString());
    }
    return request;
}

std::vector<VaultRenewalGroupPresentation> PresentRenewalGroups(
    const wallet::VaultRenewalStatus& status)
{
    std::vector<VaultRenewalGroupPresentation> groups;
    groups.reserve(status.clusters.size());
    for (const auto& group : status.clusters) {
        groups.push_back({
            QString::fromStdString(group.id),
            group.value,
            group.coin_count,
            group.due,
            group.recovery_enabled,
            group.blocks_until_primary,
        });
    }
    return groups;
}

QStringList ReconcileRenewalGroups(
    const QStringList& requested, const wallet::VaultRenewalStatus& status)
{
    QStringList selected;
    for (const auto& group : status.clusters) {
        const QString identifier{QString::fromStdString(group.id)};
        if (requested.contains(identifier)) selected << identifier;
    }
    if (!selected.empty()) return selected;

    if (!status.due_set_digest.empty()) {
        for (const auto& group : status.clusters) {
            if (group.due) selected << QString::fromStdString(group.id);
        }
        if (!selected.empty()) return selected;
    }
    if (status.clusters.empty()) return {};
    const auto oldest{std::ranges::min_element(
        status.clusters, {}, &wallet::VaultRenewalCluster::blocks_until_primary)};
    selected << QString::fromStdString(oldest->id);
    return selected;
}

void ApplyExclusions(VaultRenewalPlanPresentation& presentation,
                     const wallet::VaultRenewalExclusions& exclusions)
{
    presentation.excluded_locked_count = exclusions.locked.coin_count;
    presentation.excluded_unsafe_count = exclusions.unsafe.coin_count;
    presentation.excluded_unconfirmed_count = exclusions.unconfirmed.coin_count;
    presentation.excluded_uneconomic_count = exclusions.uneconomic.coin_count;
    presentation.excluded_locked = exclusions.locked.value;
    presentation.excluded_unsafe = exclusions.unsafe.value;
    presentation.excluded_unconfirmed = exclusions.unconfirmed.value;
    presentation.excluded_uneconomic = exclusions.uneconomic.value;
}

VaultRenewalResultPresentation PresentRenewalCommit(
    const wallet::VaultRenewalCommitResult& result)
{
    VaultRenewalResultPresentation presentation;
    for (std::size_t index{0}; index < result.transactions.size(); ++index) {
        const auto& item{result.transactions[index]};
        const QString txid{QString::fromStdString(item.txid.ToString())};
        const QString identity{item.txid.IsNull() ? WalletView::tr("Transaction %1").arg(index + 1) : txid};
        QString state;
        switch (item.outcome) {
        case wallet::VaultRenewalCommitOutcome::RELAYED:
            ++presentation.relayed;
            state = WalletView::tr("relayed");
            break;
        case wallet::VaultRenewalCommitOutcome::STORED_NOT_RELAYED:
            ++presentation.stored_not_relayed;
            presentation.retry_available = true;
            state = WalletView::tr("stored, not relayed");
            break;
        case wallet::VaultRenewalCommitOutcome::FAILED:
            ++presentation.failed;
            presentation.retry_available = true;
            state = WalletView::tr("failed");
            break;
        case wallet::VaultRenewalCommitOutcome::ALREADY_ACCEPTED:
            ++presentation.already_accepted;
            state = WalletView::tr("already accepted");
            break;
        case wallet::VaultRenewalCommitOutcome::NOT_ATTEMPTED:
            ++presentation.not_attempted;
            presentation.retry_available = true;
            state = WalletView::tr("not attempted");
            break;
        }
        if (!item.txid.IsNull()) presentation.transaction_ids << txid;
        QString detail{WalletView::tr("%1: %2").arg(identity, state)};
        if (!item.error.empty()) {
            detail += WalletView::tr(" — %1").arg(QString::fromStdString(item.error));
        }
        presentation.failures << detail;
    }
    return presentation;
}
} // namespace

WalletView::WalletView(WalletModel* wallet_model, const PlatformStyle* _platformStyle, QWidget* parent)
    : QStackedWidget(parent),
      walletModel(wallet_model),
      platformStyle(_platformStyle),
      m_vault_renewal{std::make_unique<VaultRenewalCoordinator>()}
{
    assert(walletModel);
    m_privacy = walletModel->getOptionsModel()
                    ->getOption(OptionsModel::OptionID::MaskValues)
                    .toBool();

    // Create tabs
    overviewPage = new OverviewPage(platformStyle);
    overviewPage->setWalletModel(walletModel);

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(platformStyle, this);
    transactionView->setModel(walletModel);

    vbox->addWidget(transactionView);
    QPushButton *exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }
    hbox_buttons->addStretch();
    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);

    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);
    receiveCoinsPage->setModel(walletModel);

    sendCoinsPage = new SendCoinsDialog(platformStyle);
    sendCoinsPage->setModel(walletModel);

    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedSendingAddressesPage->setModel(walletModel->getAddressTableModel());

    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);
    usedReceivingAddressesPage->setModel(walletModel->getAddressTableModel());

    addWidget(overviewPage);
    addWidget(transactionsPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);

    connect(overviewPage, &OverviewPage::transactionClicked, this, &WalletView::transactionClicked);
    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, &OverviewPage::transactionClicked, transactionView, qOverload<const QModelIndex&>(&TransactionView::focusTransaction));

    connect(overviewPage, &OverviewPage::outOfSyncWarningClicked, this, &WalletView::outOfSyncWarningClicked);
    connect(overviewPage, &OverviewPage::delayedRecoveryRequested, this, [this] {
        gotoSendCoinsPage();
        sendCoinsPage->startDelayedRecovery();
    });
    connect(overviewPage, &OverviewPage::vaultRenewalRequested,
            this, &WalletView::showVaultRenewal);
    connect(overviewPage, &OverviewPage::vaultRenewalReminderRequested,
            this, [this](const QString& title, const QString& reminder) {
                Q_EMIT message(title, reminder, CClientUIInterface::MSG_INFORMATION);
            });
    connect(overviewPage, &OverviewPage::finishVaultSetupRequested, this, [this] {
        Q_EMIT finishVaultSetupRequested(walletModel);
    });
    connect(overviewPage, &OverviewPage::retryVaultRescanRequested, this, [this] {
        Q_EMIT retryVaultRescanRequested(walletModel);
    });
    connect(overviewPage, &OverviewPage::recoveryKitRequested, this, &WalletView::showRecoveryKit);

    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, this, &WalletView::coinsSent);
    // Highlight transaction after send
    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, transactionView, qOverload<const Txid&>(&TransactionView::focusTransaction));

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, &QPushButton::clicked, transactionView, &TransactionView::exportClicked);

    // Pass through messages from sendCoinsPage
    connect(sendCoinsPage, &SendCoinsDialog::message, this, &WalletView::message);
    // Pass through messages from transactionView
    connect(transactionView, &TransactionView::message, this, &WalletView::message);

    connect(this, &WalletView::setPrivacy, overviewPage, &OverviewPage::setPrivacy);
    connect(this, &WalletView::setPrivacy, this, &WalletView::disableTransactionView);
    connect(this, &WalletView::setPrivacy, this, [this](bool privacy) {
        m_privacy = privacy;
    });

    // Receive and pass through messages from wallet model
    connect(walletModel, &WalletModel::message, this, &WalletView::message);

    // Handle changes in encryption status
    connect(walletModel, &WalletModel::encryptionStatusChanged, this, &WalletView::encryptionStatusChanged);

    // Balloon pop-up for new transaction
    connect(walletModel->getTransactionTableModel(), &TransactionTableModel::rowsInserted, this, &WalletView::processNewTransaction);

    // Ask for passphrase if needed
    connect(walletModel, &WalletModel::requireUnlock, this, &WalletView::unlockWallet);

    connect(walletModel, &WalletModel::vaultSignerStatusChanged, this, [this] {
        if (!m_vault_renewal->dialog) return;
        const auto signer{PresentVaultRenewalSigners(walletModel->vaultStatus())};
        m_vault_renewal->presentation.signers_ready = signer.ready;
        m_vault_renewal->presentation.unavailable_reason = signer.reason;
        m_vault_renewal->presentation.signer_lines = signer.roster;
        m_vault_renewal->dialog->setSignerReadiness(
            signer.ready, signer.reason, signer.roster);
    });
    connect(walletModel, &WalletModel::vaultSignerStatusRefreshFinished, this, [this] {
        if (m_vault_renewal->pending_sign_batch_token.isEmpty()) return;
        beginVaultRenewalSigning(
            std::exchange(m_vault_renewal->pending_sign_batch_token, {}));
    });

    // Show progress dialog
    connect(walletModel, &WalletModel::showProgress, this, &WalletView::showProgress);
}

WalletView::~WalletView()
{
    ++m_vault_renewal->generation;
    if (m_vault_renewal->operation_phase) {
        int expected{static_cast<int>(VaultRenewalOperationPhase::SIGNING)};
        m_vault_renewal->operation_phase->compare_exchange_strong(
            expected, static_cast<int>(VaultRenewalOperationPhase::CANCELLED));
    }
    if (m_vault_renewal->dialog) {
        QObject::disconnect(m_vault_renewal->dialog, nullptr, this, nullptr);
        delete m_vault_renewal->dialog;
        m_vault_renewal->dialog = nullptr;
    }
    // Jobs hold the shared wallet and may still be inside chain or signer
    // code. Join before releasing the unlock context or allowing the owning
    // model/controller to tear down their backends.
    m_vault_renewal->workers.waitForDone();
    m_vault_renewal->unlock.reset();
}

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(_clientModel);
    sendCoinsPage->setClientModel(_clientModel);
    walletModel->setClientModel(_clientModel);
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!clientModel || clientModel->node().isInitialBlockDownload()) {
        return;
    }

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toLongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = GUIUtil::HtmlEscape(ttm->data(index, TransactionTableModel::LabelRole).toString());

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label, GUIUtil::HtmlEscape(walletModel->getWalletName()));
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::showReceiveRequest(const QString& address)
{
    gotoReceiveCoinsPage();
    receiveCoinsPage->showRequestForAddress(address);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty())
        sendCoinsPage->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    return sendCoinsPage->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::showRecoveryKit()
{
    if (!walletModel->vaultStatus().is_vault) return;

    QMessageBox explanation{
        QMessageBox::Information,
        tr("Recovery Kit"),
        tr("Bitcoin Core can export the exact public policy for this Recovery Vault. It deliberately does not retain the private mnemonic pages from the original printed kit, so those pages cannot be recreated here."),
        QMessageBox::Cancel,
        this};
    auto* export_button = explanation.addButton(tr("Export Public Policy…"), QMessageBox::ActionRole);
    explanation.setInformativeText(tr("Keep the original printed Recovery Kit offline. The public policy cannot spend bitcoin by itself, but it can reveal the vault structure and transaction history."));
    explanation.exec();
    if (explanation.clickedButton() != export_button) return;

    const QString destination = GUIUtil::getSaveFileName(
        this,
        tr("Export Recovery Vault Public Policy"),
        QStringLiteral("recovery-vault-policy.json"),
        tr("Recovery Vault policy (*.json);;All Files (*)"),
        nullptr);
    if (destination.isEmpty()) return;

    const QByteArray policy = QByteArray::fromStdString(walletModel->wallet().exportVaultPolicy());
    QSaveFile output{destination};
    if (policy.isEmpty() || !output.open(QIODevice::WriteOnly) ||
        output.write(policy) != policy.size() || !output.commit()) {
        QMessageBox::critical(this, tr("Export failed"), tr("The public Recovery Vault policy could not be written to that file."));
        return;
    }
    QMessageBox::information(this, tr("Public policy exported"), tr("The exact public Recovery Vault policy was exported successfully."));
}

void WalletView::showVaultRenewal(bool /*due*/)
{
    if (m_vault_renewal->dialog) {
        GUIUtil::bringToFront(m_vault_renewal->dialog);
        return;
    }

    ++m_vault_renewal->generation;
    m_vault_renewal->plan.reset();
    m_vault_renewal->batch.reset();
    m_vault_renewal->presentation = {};
    m_vault_renewal->last_result.reset();
    m_vault_renewal->operation_phase.reset();
    m_vault_renewal->unlock.reset();
    m_vault_renewal->pending_sign_batch_token.clear();

    auto* dialog{new VaultRenewalDialog(platformStyle, this)};
    m_vault_renewal->dialog = dialog;
    dialog->setDisplayUnit(walletModel->getOptionsModel()->getDisplayUnit());
    dialog->setPrivacy(m_privacy);
    const auto renewal_status{walletModel->vaultRenewalStatus()};
    const bool current_due{!renewal_status.due_set_digest.empty()};
    dialog->setAvailableGroups(
        PresentRenewalGroups(renewal_status),
        /*due=*/current_due);
    connect(this, &WalletView::setPrivacy, dialog, &VaultRenewalDialog::setPrivacy);
    connect(dialog, &VaultRenewalDialog::planRequested,
            this, &WalletView::requestVaultRenewalPlan);
    connect(dialog, &VaultRenewalDialog::batchRequested,
            this, &WalletView::createVaultRenewalBatch);
    connect(dialog, &VaultRenewalDialog::signingRequested,
            this, &WalletView::startVaultRenewalSigning);
    connect(dialog, &VaultRenewalDialog::cancellationRequested, this, [this] {
        if (!m_vault_renewal->operation_phase) return;
        int expected{static_cast<int>(VaultRenewalOperationPhase::SIGNING)};
        if (m_vault_renewal->operation_phase->compare_exchange_strong(
                expected, static_cast<int>(VaultRenewalOperationPhase::CANCELLED)) &&
            m_vault_renewal->dialog) {
            m_vault_renewal->dialog->setCancellationPending();
        } else if (expected == static_cast<int>(VaultRenewalOperationPhase::COMMITTING) &&
                   m_vault_renewal->dialog && m_vault_renewal->batch) {
            // The worker won the single atomic commitment boundary. Reflect
            // that immediately if a click raced the queued progress update.
            m_vault_renewal->dialog->setBroadcastProgress(
                0, m_vault_renewal->batch->transactions.size(),
                tr("Every transaction is signed and final broadcast revalidation has begun. This step can no longer be canceled."));
        }
    });
    connect(dialog, &VaultRenewalDialog::retryRequested,
            this, &WalletView::retryVaultRenewalCommit);
    connect(dialog, &QObject::destroyed, this, [this] {
        ++m_vault_renewal->generation;
        if (m_vault_renewal->operation_phase) {
            int expected{static_cast<int>(VaultRenewalOperationPhase::SIGNING)};
            m_vault_renewal->operation_phase->compare_exchange_strong(
                expected, static_cast<int>(VaultRenewalOperationPhase::CANCELLED));
        }
        m_vault_renewal->dialog = nullptr;
        m_vault_renewal->plan.reset();
        m_vault_renewal->batch.reset();
        m_vault_renewal->last_result.reset();
        m_vault_renewal->operation_phase.reset();
        m_vault_renewal->unlock.reset();
        m_vault_renewal->pending_sign_batch_token.clear();
    });

    // This immediately publishes UNKNOWN for hardware participants and then
    // performs exact discovery off the GUI thread. The review action stays
    // disabled until the fresh result establishes all-three availability.
    walletModel->refreshVaultSignerStatus();
    dialog->start(current_due);
    GUIUtil::ShowModalDialogAsynchronously(dialog);
}

void WalletView::requestVaultRenewalPlan(const QStringList& cluster_ids)
{
    if (!m_vault_renewal->dialog) return;
    const uint64_t generation{++m_vault_renewal->generation};
    m_vault_renewal->plan.reset();
    m_vault_renewal->batch.reset();
    m_vault_renewal->presentation = {};
    m_vault_renewal->last_result.reset();
    if (cluster_ids.empty()) {
        m_vault_renewal->dialog->setPlanError(
            tr("Select at least one whole privacy group to continue."));
        return;
    }
    const std::shared_ptr<interfaces::Wallet> wallet_interface{walletModel->walletShared()};
    QPointer<WalletView> guard{this};
    m_vault_renewal->workers.start([guard, wallet_interface, cluster_ids, generation] {
        std::optional<wallet::VaultRenewalPlan> plan;
        wallet::VaultRenewalStatus status;
        QStringList selected_ids;
        QString error;
        try {
            // Refresh the group graph before every plan, including retries
            // after an actionable error. Preserve still-valid selections;
            // if all disappeared, restore the current due/oldest default.
            status = wallet_interface->getVaultRenewalStatus();
            selected_ids = ReconcileRenewalGroups(cluster_ids, status);
            if (!status.supported) {
                error = WalletView::tr(
                    "Guided protection renewal is no longer available for this vault policy.");
            } else if (selected_ids.empty()) {
                error = WalletView::tr(
                    "No confirmed, safe, unlocked vault privacy groups are currently eligible.");
            } else {
                auto result{wallet_interface->planVaultRenewal(
                    BackendRenewalRequest(selected_ids))};
                if (result) {
                    plan.emplace(std::move(*result));
                } else {
                    error = QString::fromStdString(util::ErrorString(result).original);
                }
            }
        } catch (const std::exception& e) {
            error = QString::fromLocal8Bit(e.what());
        } catch (...) {
            error = WalletView::tr("The renewal plan could not be created.");
        }
        if (!guard) return;
        auto groups{PresentRenewalGroups(status)};
        const bool due{!status.due_set_digest.empty()};
        QMetaObject::invokeMethod(guard, [guard, generation, plan = std::move(plan), groups = std::move(groups), selected_ids = std::move(selected_ids), due, error = std::move(error)]() mutable {
            if (!guard || generation != guard->m_vault_renewal->generation ||
                !guard->m_vault_renewal->dialog) {
                return;
            }
            guard->m_vault_renewal->dialog->setAvailableGroups(
                groups, due, selected_ids);
            if (!plan) {
                guard->m_vault_renewal->dialog->setPlanError(error);
                return;
            }

            guard->m_vault_renewal->plan = *plan;
            VaultRenewalPlanPresentation presentation;
            presentation.supported = true;
            presentation.has_due = !plan->due_set_digest.empty();
            presentation.fees_ready = false;
            presentation.plan_token = QString::fromStdString(plan->source_digest);
            presentation.cluster_count = plan->clusters.size();
            presentation.coin_count = plan->selected_coin_count;
            presentation.selected = plan->selected_value;
            presentation.returned = plan->selected_value;
            ApplyExclusions(presentation, plan->exclusions);
            for (const auto& cluster : plan->clusters) {
                presentation.batches.push_back({
                    QString::fromStdString(cluster.summary.id),
                    cluster.summary.coin_count,
                    cluster.summary.value,
                    0,
                    cluster.summary.value,
                });
            }
            const auto signer{PresentVaultRenewalSigners(guard->walletModel->vaultStatus())};
            presentation.signers_ready = signer.ready;
            presentation.unavailable_reason = signer.reason;
            presentation.signer_lines = signer.roster;
            guard->m_vault_renewal->presentation = presentation;
            guard->m_vault_renewal->dialog->setPlan(presentation); }, Qt::QueuedConnection);
    });
}

void WalletView::createVaultRenewalBatch(const QString& plan_token)
{
    if (!m_vault_renewal->dialog || !m_vault_renewal->plan ||
        plan_token != QString::fromStdString(m_vault_renewal->plan->source_digest)) {
        if (m_vault_renewal->dialog) {
            m_vault_renewal->dialog->setPlanError(
                tr("The selected vault coins changed. Refresh and review a new plan."));
        }
        return;
    }

    const uint64_t generation{++m_vault_renewal->generation};
    const wallet::VaultRenewalPlan plan{*m_vault_renewal->plan};
    const std::shared_ptr<interfaces::Wallet> wallet_interface{walletModel->walletShared()};
    QPointer<WalletView> guard{this};
    m_vault_renewal->workers.start([guard, wallet_interface, plan, generation] {
        std::optional<wallet::VaultRenewalBatch> batch;
        QString error;
        try {
            wallet::CCoinControl fee_control;
            auto result{wallet_interface->createVaultRenewalBatch(plan, fee_control)};
            if (result) {
                batch.emplace(std::move(*result));
            } else {
                error = QString::fromStdString(util::ErrorString(result).original);
            }
        } catch (const std::exception& e) {
            error = QString::fromLocal8Bit(e.what());
        } catch (...) {
            error = WalletView::tr("Exact renewal transactions could not be created.");
        }
        if (!guard) return;
        QMetaObject::invokeMethod(guard, [guard, generation, batch = std::move(batch), error = std::move(error)]() mutable {
            if (!guard || generation != guard->m_vault_renewal->generation ||
                !guard->m_vault_renewal->dialog) {
                return;
            }
            if (!batch) {
                guard->m_vault_renewal->dialog->setPlanError(error);
                return;
            }

            guard->m_vault_renewal->batch = *batch;
            VaultRenewalPlanPresentation presentation{guard->m_vault_renewal->presentation};
            presentation.fees_ready = true;
            presentation.plan_token = QString::fromStdString(batch->batch_digest);
            presentation.selected = batch->input_value;
            presentation.total_fee = batch->fee;
            presentation.returned = batch->output_value;
            presentation.batches.clear();
            presentation.coin_count = 0;
            ApplyExclusions(presentation, batch->exclusions);
            std::set<std::string> renewed_groups;
            for (const auto& tx : batch->transactions) {
                renewed_groups.insert(tx.cluster_id);
                presentation.coin_count += tx.inputs.size();
                presentation.batches.push_back({
                    QString::fromStdString(tx.cluster_id),
                    tx.inputs.size(),
                    tx.input_value,
                    tx.fee,
                    tx.output_value,
                });
            }
            presentation.cluster_count = renewed_groups.size();
            const auto signer{PresentVaultRenewalSigners(guard->walletModel->vaultStatus())};
            presentation.signers_ready = signer.ready;
            presentation.unavailable_reason = signer.reason;
            presentation.signer_lines = signer.roster;
            guard->m_vault_renewal->presentation = presentation;
            guard->m_vault_renewal->dialog->setBatch(presentation);
        }, Qt::QueuedConnection);
    });
}

void WalletView::startVaultRenewalSigning(const QString& batch_token)
{
    if (!m_vault_renewal->dialog || !m_vault_renewal->batch ||
        batch_token != QString::fromStdString(m_vault_renewal->batch->batch_digest)) {
        VaultRenewalResultPresentation result;
        result.failed = 1;
        result.failures << tr("The reviewed transaction batch changed. Nothing was signed or broadcast.");
        if (m_vault_renewal->dialog) m_vault_renewal->dialog->setResult(result);
        return;
    }

    m_vault_renewal->operation_phase = std::make_shared<std::atomic<int>>(
        static_cast<int>(VaultRenewalOperationPhase::SIGNING));
    m_vault_renewal->pending_sign_batch_token = batch_token;
    m_vault_renewal->dialog->setSigningProgress(
        0, m_vault_renewal->batch->transactions.size(),
        tr("Checking that every local key and exact hardware participant is freshly available…"));
    // A request made while the opening refresh is still running is coalesced
    // into a follow-up check. The finished signal is emitted only for the
    // newest requested check, including fail-closed discovery failures.
    walletModel->refreshVaultSignerStatus();
}

void WalletView::beginVaultRenewalSigning(const QString& batch_token)
{
    if (!m_vault_renewal->dialog || !m_vault_renewal->batch ||
        batch_token != QString::fromStdString(m_vault_renewal->batch->batch_digest) ||
        !m_vault_renewal->operation_phase) {
        VaultRenewalResultPresentation result;
        result.failed = 1;
        result.failures << tr("The reviewed transaction batch changed. Nothing was signed or broadcast.");
        m_vault_renewal->operation_phase.reset();
        if (m_vault_renewal->dialog) m_vault_renewal->dialog->setResult(result);
        return;
    }
    if (m_vault_renewal->operation_phase->load() ==
        static_cast<int>(VaultRenewalOperationPhase::CANCELLED)) {
        m_vault_renewal->operation_phase.reset();
        m_vault_renewal->batch.reset();
        VaultRenewalResultPresentation result;
        result.failed = 1;
        result.failures << tr("Signing was canceled before any key was used. Nothing was broadcast.");
        m_vault_renewal->dialog->setResult(result);
        return;
    }
    const auto signer{PresentVaultRenewalSigners(walletModel->vaultStatus())};
    if (!signer.ready) {
        m_vault_renewal->operation_phase.reset();
        VaultRenewalResultPresentation result;
        result.failed = 1;
        result.failures << signer.reason << tr("Nothing was signed or broadcast.");
        m_vault_renewal->dialog->setResult(result);
        return;
    }

    m_vault_renewal->unlock.reset(
        new WalletModel::UnlockContext(walletModel->requestUnlock()));
    if (!m_vault_renewal->unlock->isValid()) {
        m_vault_renewal->unlock.reset();
        m_vault_renewal->operation_phase.reset();
        VaultRenewalResultPresentation result;
        result.failed = 1;
        result.failures << tr("Wallet unlock was canceled. Nothing was signed or broadcast.");
        m_vault_renewal->dialog->setResult(result);
        return;
    }

    const uint64_t generation{++m_vault_renewal->generation};
    wallet::VaultRenewalBatch batch{*m_vault_renewal->batch};
    const std::shared_ptr<interfaces::Wallet> wallet_interface{walletModel->walletShared()};
    const auto operation_phase{m_vault_renewal->operation_phase};
    const interfaces::Wallet::VaultStatus signer_status{walletModel->vaultStatus()};
    QStringList hardware;
    int local_count{0};
    for (const auto& participant : signer_status.participants) {
        if (participant.type == interfaces::Wallet::VaultParticipantType::HARDWARE) {
            hardware << QString::fromStdString(participant.fingerprint).toUpper();
        } else if (participant.type == interfaces::Wallet::VaultParticipantType::LOCAL_SOFTWARE) {
            ++local_count;
        }
    }
    QPointer<WalletView> guard{this};
    m_vault_renewal->workers.start(
        [guard, wallet_interface, batch = std::move(batch), operation_phase, generation,
         hardware = std::move(hardware), local_count]() mutable {
            QString error;
            bool canceled{false};
            const std::size_t total{batch.transactions.size()};
            for (std::size_t index{0}; index < total; ++index) {
                if (operation_phase->load() ==
                    static_cast<int>(VaultRenewalOperationPhase::CANCELLED)) {
                    canceled = true;
                    break;
                }
                if (guard) {
                    QMetaObject::invokeMethod(guard, [guard, generation, index, total, hardware, local_count] {
                        if (!guard || generation != guard->m_vault_renewal->generation ||
                            !guard->m_vault_renewal->dialog) {
                            return;
                        }
                        QString detail;
                        if (hardware.isEmpty()) {
                            const QString participants{
                                local_count == 1
                                    ? WalletView::tr("%n local participant", nullptr, local_count)
                                    : WalletView::tr("%n local participants", nullptr, local_count)};
                            detail = WalletView::tr("Transaction %1 of %2 is being signed by %3.")
                                         .arg(static_cast<qulonglong>(index + 1))
                                         .arg(static_cast<qulonglong>(total))
                                         .arg(participants);
                        } else {
                            detail = WalletView::tr("Transaction %1 of %2: local keys are available; waiting for confirmations from connected hardware participants %3.")
                                         .arg(static_cast<qulonglong>(index + 1))
                                         .arg(static_cast<qulonglong>(total))
                                         .arg(hardware.join(QStringLiteral(", ")));
                        }
                        guard->m_vault_renewal->dialog->setSigningProgress(index, total, detail);
                    }, Qt::QueuedConnection);
                }

                try {
                    auto result{wallet_interface->signVaultRenewalTransaction(batch, index)};
                    if (!result) {
                        error = QString::fromStdString(util::ErrorString(result).original);
                        break;
                    }
                } catch (const std::exception& e) {
                    error = QString::fromLocal8Bit(e.what());
                    break;
                } catch (...) {
                    error = WalletView::tr("A renewal transaction could not be signed.");
                    break;
                }
                if (operation_phase->load() ==
                    static_cast<int>(VaultRenewalOperationPhase::CANCELLED)) {
                    canceled = true;
                    break;
                }
                if (guard) {
                    QMetaObject::invokeMethod(guard, [guard, generation, index, total] {
                        if (!guard || generation != guard->m_vault_renewal->generation ||
                            !guard->m_vault_renewal->dialog) {
                            return;
                        }
                        guard->m_vault_renewal->dialog->setSigningProgress(
                            index + 1, total,
                            WalletView::tr("Transaction %1 of %2 is fully signed. No transaction has been broadcast yet.")
                                .arg(static_cast<qulonglong>(index + 1))
                                .arg(static_cast<qulonglong>(total))); }, Qt::QueuedConnection);
                }
            }

            std::optional<wallet::VaultRenewalCommitResult> committed;
            if (!canceled && error.isEmpty()) {
                int expected{static_cast<int>(VaultRenewalOperationPhase::SIGNING)};
                if (!operation_phase->compare_exchange_strong(
                        expected,
                        static_cast<int>(VaultRenewalOperationPhase::COMMITTING))) {
                    canceled = true;
                }
            }
            if (!canceled && error.isEmpty()) {
                if (guard) {
                    QMetaObject::invokeMethod(guard, [guard, generation, total] {
                        if (!guard || generation != guard->m_vault_renewal->generation ||
                            !guard->m_vault_renewal->dialog) {
                            return;
                        }
                        guard->m_vault_renewal->dialog->setBroadcastProgress(
                            0, total,
                            WalletView::tr("Every transaction is signed. Revalidating the complete batch before broadcast…")); }, Qt::QueuedConnection);
                }
                try {
                    auto result{wallet_interface->commitVaultRenewalBatch(batch)};
                    if (result) {
                        committed.emplace(std::move(*result));
                    } else {
                        error = QString::fromStdString(util::ErrorString(result).original);
                    }
                } catch (const std::exception& e) {
                    error = QString::fromLocal8Bit(e.what());
                } catch (...) {
                    error = WalletView::tr("The signed renewal batch could not be committed.");
                }
            }

            if (!guard) return;
            QMetaObject::invokeMethod(guard, [guard, generation, batch = std::move(batch), committed = std::move(committed), error = std::move(error), canceled]() mutable {
                if (!guard || generation != guard->m_vault_renewal->generation ||
                    !guard->m_vault_renewal->dialog) {
                    return;
                }
                guard->m_vault_renewal->unlock.reset();
                guard->m_vault_renewal->operation_phase.reset();
                VaultRenewalResultPresentation presentation;
                if (committed) {
                    guard->m_vault_renewal->batch = batch;
                    presentation = PresentRenewalCommit(*committed);
                    guard->m_vault_renewal->last_result = presentation;
                } else {
                    // Cancellation or any signing failure discards every
                    // in-memory signature and never reaches broadcast.
                    guard->m_vault_renewal->batch.reset();
                    guard->m_vault_renewal->last_result.reset();
                    presentation.failed = 1;
                    presentation.failures << (canceled
                                                   ? WalletView::tr("Signing was canceled. The entire in-memory signed batch was discarded; nothing was broadcast.")
                                                   : (error.isEmpty() ? WalletView::tr("Renewal failed before broadcast.") : error));
                }
                guard->m_vault_renewal->dialog->setResult(presentation);
                guard->walletModel->updateTransaction();
                guard->walletModel->pollBalanceChanged();
                guard->walletModel->refreshVaultRenewalStatus(); }, Qt::QueuedConnection);
        });
}

void WalletView::retryVaultRenewalCommit()
{
    if (!m_vault_renewal->dialog || !m_vault_renewal->batch) return;
    const uint64_t generation{++m_vault_renewal->generation};
    const wallet::VaultRenewalBatch batch{*m_vault_renewal->batch};
    const std::shared_ptr<interfaces::Wallet> wallet_interface{walletModel->walletShared()};
    const std::size_t total{batch.transactions.size()};
    m_vault_renewal->dialog->setBroadcastProgress(
        0, total, tr("Retrying only the unchanged, fully signed batch. Nothing will be rebuilt or resigned."));
    QPointer<WalletView> guard{this};
    m_vault_renewal->workers.start([guard, wallet_interface, batch, generation] {
        std::optional<wallet::VaultRenewalCommitResult> committed;
        QString error;
        try {
            auto result{wallet_interface->commitVaultRenewalBatch(batch)};
            if (result) {
                committed.emplace(std::move(*result));
            } else {
                error = QString::fromStdString(util::ErrorString(result).original);
            }
        } catch (const std::exception& e) {
            error = QString::fromLocal8Bit(e.what());
        } catch (...) {
            error = WalletView::tr("The retained signed batch could not be retried.");
        }
        if (!guard) return;
        QMetaObject::invokeMethod(guard, [guard, generation, committed = std::move(committed), error = std::move(error)]() mutable {
            if (!guard || generation != guard->m_vault_renewal->generation ||
                !guard->m_vault_renewal->dialog) {
                return;
            }
            VaultRenewalResultPresentation presentation;
            if (committed) {
                presentation = PresentRenewalCommit(*committed);
                guard->m_vault_renewal->last_result = presentation;
            } else {
                // Preserve the exact per-transaction history from the prior
                // attempt. A top-level retry failure means the retained batch
                // is no longer safe to keep retrying (for example after a CAS
                // policy/input/loss-state change), not that earlier accepted
                // or stored outcomes disappeared.
                presentation = guard->m_vault_renewal->last_result.value_or(
                    VaultRenewalResultPresentation{});
                presentation.terminal_error =
                    error.isEmpty()
                        ? WalletView::tr("The retained signed batch is no longer valid for relay.")
                        : error;
                presentation.retry_available = false;
                guard->m_vault_renewal->last_result = presentation;
                guard->m_vault_renewal->batch.reset();
            }
            guard->m_vault_renewal->dialog->setResult(presentation);
            guard->walletModel->updateTransaction();
            guard->walletModel->pollBalanceChanged();
            guard->walletModel->refreshVaultRenewalStatus();
        }, Qt::QueuedConnection);
    });
}

void WalletView::encryptWallet()
{
    auto dlg = new AskPassphraseDialog(AskPassphraseDialog::Encrypt, this);
    dlg->setModel(walletModel);
    connect(dlg, &QDialog::finished, this, &WalletView::encryptionStatusChanged);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        //: Name of the wallet data file format.
        tr("Wallet Data") + QLatin1String(" (*.dat)"), nullptr);

    if (filename.isEmpty())
        return;

    if (!walletModel->wallet().backupWallet(filename.toLocal8Bit().data())) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::changePassphrase()
{
    auto dlg = new AskPassphraseDialog(AskPassphraseDialog::ChangePass, this);
    dlg->setModel(walletModel);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

void WalletView::unlockWallet()
{
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        // A modal dialog must be synchronous here as expected
        // in the WalletModel::requestUnlock() function.
        dlg.exec();
    }
}

void WalletView::usedSendingAddresses()
{
    GUIUtil::bringToFront(usedSendingAddressesPage);
}

void WalletView::usedReceivingAddresses()
{
    GUIUtil::bringToFront(usedReceivingAddressesPage);
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0) {
        const bool recovery_vault_rescan{
            walletModel->wallet().getVaultStatus().genesis_rescan_required};
        progressDialog = new QProgressDialog(
            recovery_vault_rescan ? tr("Scanning blockchain history. You can continue using Bitcoin Core, but spending from this Recovery Vault remains blocked until the scan finishes.") : title,
            recovery_vault_rescan ? tr("Pause") : tr("Cancel"), 0, 100, this);
        progressDialog->setObjectName(recovery_vault_rescan ? QStringLiteral("recoveryVaultRescanProgress") : QStringLiteral("walletProgressDialog"));
        progressDialog->setAccessibleName(recovery_vault_rescan ? tr("Recovery Vault blockchain scan") : title);
        GUIUtil::PolishProgressDialog(progressDialog);
        progressDialog->setWindowModality(recovery_vault_rescan ? Qt::NonModal : Qt::ApplicationModal);
        if (recovery_vault_rescan) {
            progressDialog->setWindowTitle(tr("Restore Recovery Vault"));
            progressDialog->setMinimumDuration(0);
            connect(progressDialog, &QProgressDialog::canceled, this, [this] {
                // A paused vault scan has its own durable checkpoint. Abort
                // immediately instead of waiting for another progress tick
                // before the worker observes the user's decision.
                getWalletModel()->wallet().abortRescan();
            });
            progressDialog->show();
        }
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    } else if (nProgress == 100) {
        if (progressDialog) {
            progressDialog->close();
            progressDialog->deleteLater();
            progressDialog = nullptr;
        }
    } else if (progressDialog) {
        if (progressDialog->wasCanceled()) {
            getWalletModel()->wallet().abortRescan();
        } else {
            progressDialog->setValue(nProgress);
        }
    }
}

void WalletView::disableTransactionView(bool disable)
{
    transactionView->setDisabled(disable);
}
