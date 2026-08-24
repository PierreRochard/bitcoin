// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/overviewpage.h>
#include <qt/forms/ui_overviewpage.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactionoverviewwidget.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>

#include <QAbstractItemDelegate>
#include <QApplication>
#include <QDateTime>
#include <QFrame>
#include <QGridLayout>
#include <QLabel>
#include <QPainter>
#include <QStatusTipEvent>

#include <map>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5

Q_DECLARE_METATYPE(interfaces::WalletBalances)

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle* _platformStyle, QObject* parent = nullptr)
        : QAbstractItemDelegate(parent), platformStyle(_platformStyle)
    {
        connect(this, &TxViewDelegate::width_changed, this, &TxViewDelegate::sizeHintChanged);
    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const override
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon = platformStyle->SingleColorIcon(icon);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter, address, &boundingRect);

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::SeparatorStyle::ALWAYS);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }

        QRect amount_bounding_rect;
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText, &amount_bounding_rect);

        painter->setPen(option.palette.color(QPalette::Text));
        QRect date_bounding_rect;
        painter->drawText(amountRect, Qt::AlignLeft | Qt::AlignVCenter, GUIUtil::dateTimeStr(date), &date_bounding_rect);

        // 0.4*date_bounding_rect.width() is used to visually distinguish a date from an amount.
        const int minimum_width = 1.4 * date_bounding_rect.width() + amount_bounding_rect.width();
        const auto search = m_minimum_width.find(index.row());
        if (search == m_minimum_width.end() || search->second != minimum_width) {
            m_minimum_width[index.row()] = minimum_width;
            Q_EMIT width_changed(index);
        }

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        const auto search = m_minimum_width.find(index.row());
        const int minimum_text_width = search == m_minimum_width.end() ? 0 : search->second;
        return {DECORATION_SIZE + 8 + minimum_text_width, DECORATION_SIZE};
    }

    BitcoinUnit unit{BitcoinUnit::BTC};

Q_SIGNALS:
    //! An intermediate signal for emitting from the `paint() const` member function.
    void width_changed(const QModelIndex& index) const;

private:
    const PlatformStyle* platformStyle;
    mutable std::map<int, int> m_minimum_width;
};

#include <qt/overviewpage.moc>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    m_platform_style{platformStyle},
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    ui->setupUi(this);

    // use a SingleColorIcon for the "out of sync warning" icon
    QIcon icon = m_platform_style->SingleColorIcon(QStringLiteral(":/icons/warning"));
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, &TransactionOverviewWidget::clicked, this, &OverviewPage::handleTransactionClicked);

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, &QPushButton::clicked, this, &OverviewPage::outOfSyncWarningClicked);
    connect(ui->labelTransactionsStatus, &QPushButton::clicked, this, &OverviewPage::outOfSyncWarningClicked);

    if (auto* grid = ui->frame->findChild<QGridLayout*>("gridLayout")) {
        auto* sep = new QFrame;
        sep->setObjectName("vaultAvailabilitySeparator");
        sep->setFrameShape(QFrame::HLine);
        sep->setVisible(false);
        auto* immediate_option = new QLabel(tr("Available now:"));
        immediate_option->setObjectName("vaultImmediateOptionLabel");
        immediate_option->setVisible(false);
        auto* immediate_status = new QLabel;
        immediate_status->setObjectName("vaultImmediateStatusLabel");
        immediate_status->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
        immediate_status->setVisible(false);
        auto* recovery_option = new QLabel;
        recovery_option->setObjectName("vaultRecoveryOptionLabel");
        recovery_option->setVisible(false);
        auto* recovery_status = new QLabel;
        recovery_status->setObjectName("vaultRecoveryStatusLabel");
        recovery_status->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
        recovery_status->setVisible(false);
        auto* final_option = new QLabel;
        final_option->setObjectName("vaultFinalOptionLabel");
        final_option->setVisible(false);
        auto* final_status = new QLabel;
        final_status->setObjectName("vaultFinalStatusLabel");
        final_status->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
        final_status->setVisible(false);
        grid->addWidget(sep, 5, 0, 1, 2);
        grid->addWidget(immediate_option, 6, 0);
        grid->addWidget(immediate_status, 6, 1);
        grid->addWidget(recovery_option, 7, 0);
        grid->addWidget(recovery_status, 7, 1);
        grid->addWidget(final_option, 8, 0);
        grid->addWidget(final_status, 8, 1);
    }
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::setPrivacy(bool privacy)
{
    m_privacy = privacy;
    clientModel->getOptionsModel()->setOption(OptionsModel::OptionID::MaskValues, privacy);
    const auto& balances = walletModel->getCachedBalance();
    if (balances.balance != -1) {
        setBalance(balances);
    }

    ui->listTransactions->setVisible(!m_privacy);

    const QString status_tip = m_privacy ? tr("Privacy mode activated for the Overview tab. To unmask the values, uncheck Settings->Mask values.") : "";
    setStatusTip(status_tip);
    QStatusTipEvent event(status_tip);
    QApplication::sendEvent(this, &event);
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(const interfaces::WalletBalances& balances)
{
    BitcoinUnit unit = walletModel->getOptionsModel()->getDisplayUnit();
    ui->labelBalance->setText(BitcoinUnits::formatWithPrivacy(unit, balances.balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithPrivacy(unit, balances.unconfirmed_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelImmature->setText(BitcoinUnits::formatWithPrivacy(unit, balances.immature_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    ui->labelTotal->setText(BitcoinUnits::formatWithPrivacy(unit, balances.balance + balances.unconfirmed_balance + balances.immature_balance, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = balances.immature_balance != 0;

    ui->labelBalance->setVisible(!balances.is_vault);
    ui->labelBalanceText->setVisible(!balances.is_vault);
    ui->labelUnconfirmed->setVisible(!balances.is_vault);
    ui->labelPendingText->setVisible(!balances.is_vault);
    ui->labelImmature->setVisible(!balances.is_vault && showImmature);
    ui->labelImmatureText->setVisible(!balances.is_vault && showImmature);
    ui->line->setVisible(!balances.is_vault);

    if (balances.is_vault) {
        ui->labelTotalText->setText(tr("Total balance:"));
        ui->labelTotal->setToolTip(tr("Confirmed, pending, and immature bitcoin in this vault."));
    } else {
        ui->labelBalanceText->setText(tr("Available:"));
        ui->labelBalance->setToolTip(tr("Your current spendable balance"));
        ui->labelTotalText->setText(tr("Total:"));
        ui->labelTotal->setToolTip(QString());
    }

    if (auto* immediate_status = findChild<QLabel*>("vaultImmediateStatusLabel")) {
        auto* immediate_option = findChild<QLabel*>("vaultImmediateOptionLabel");
        auto* recovery_option = findChild<QLabel*>("vaultRecoveryOptionLabel");
        auto* recovery_status = findChild<QLabel*>("vaultRecoveryStatusLabel");
        auto* final_option = findChild<QLabel*>("vaultFinalOptionLabel");
        auto* final_status = findChild<QLabel*>("vaultFinalStatusLabel");
        auto* sep = findChild<QFrame*>("vaultAvailabilitySeparator");
        const bool show_vault = balances.is_vault;
        immediate_status->setVisible(show_vault);
        if (immediate_option) immediate_option->setVisible(show_vault);
        if (recovery_option) recovery_option->setVisible(show_vault);
        if (recovery_status) recovery_status->setVisible(show_vault);
        if (sep) sep->setVisible(show_vault);
        const auto status = show_vault ? walletModel->reconcileVaultHardwareSigners() : interfaces::Wallet::VaultStatus{};
        if (show_vault) {
            immediate_status->setText(!status.lost_signers.empty()
                ? tr("All keys · Reconnect a signer")
                : balances.vault_immediate > 0 ? tr("All keys · Ready") : tr("All keys · No confirmed funds"));
            const auto stage_label = [](const interfaces::Wallet::VaultStatus::VaultRecoveryStage& stage) -> QString {
                const QString quorum = stage.nrequired == 1 ? tr("Any 1 key") : tr("Any %1 keys").arg(stage.nrequired);
                if (stage.older) {
                    const QString delay = *stage.older == 1
                        ? tr("After ~1 block:")
                        : *stage.older < 144
                            ? tr("After ~%1 blocks:").arg(*stage.older)
                            : tr("After ~%1 days:").arg((*stage.older + 72) / 144);
                    return delay + QStringLiteral(" ") + quorum;
                }
                if (stage.after) return tr("At block %1:").arg(*stage.after) + QStringLiteral(" ") + quorum;
                return tr("Recovery:") + QStringLiteral(" ") + quorum;
            };
            const auto stage_state = [](const interfaces::Wallet::VaultStatus::VaultRecoveryStage& stage) -> QString {
                if (stage.recoverable_now > 0) {
                    if (stage.awaiting_maturity > 0 && stage.earliest_blocks_remaining) {
                        return tr("Ready · newer deposits in ~%1 blocks").arg(*stage.earliest_blocks_remaining);
                    }
                    return tr("Ready");
                }
                if (stage.earliest_blocks_remaining) {
                    return *stage.earliest_blocks_remaining == 1
                        ? tr("Available in ~1 block")
                        : tr("Available in ~%1 blocks").arg(*stage.earliest_blocks_remaining);
                }
                return stage.awaiting_maturity > 0 ? tr("Waiting for maturity") : tr("No confirmed funds");
            };
            if (!status.recovery_stages.empty()) {
                if (recovery_option) recovery_option->setText(stage_label(status.recovery_stages[0]));
                if (recovery_status) recovery_status->setText(stage_state(status.recovery_stages[0]));
            } else {
                if (recovery_option) recovery_option->setText(tr("Recovery:"));
                if (recovery_status) recovery_status->setText(tr("Unavailable"));
            }
        }
        const bool show_final = show_vault && status.recovery_stages.size() > 1;
        if (final_option) final_option->setVisible(show_final);
        if (final_status) final_status->setVisible(show_final);
        if (show_final) {
            const auto& stage = status.recovery_stages[1];
            const QString quorum = stage.nrequired == 1 ? tr("Any 1 key") : tr("Any %1 keys").arg(stage.nrequired);
            if (stage.older) {
                const QString delay = *stage.older == 1
                    ? tr("After ~1 block:")
                    : *stage.older < 144
                        ? tr("After ~%1 blocks:").arg(*stage.older)
                        : tr("After ~%1 days:").arg((*stage.older + 72) / 144);
                if (final_option) final_option->setText(delay + QStringLiteral(" ") + quorum);
            } else if (stage.after) {
                if (final_option) final_option->setText(tr("At block %1:").arg(*stage.after) + QStringLiteral(" ") + quorum);
            }
            if (final_status) {
                if (stage.recoverable_now > 0) {
                    final_status->setText(stage.awaiting_maturity > 0 && stage.earliest_blocks_remaining
                        ? tr("Ready · newer deposits in ~%1 blocks").arg(*stage.earliest_blocks_remaining)
                        : tr("Ready"));
                } else if (stage.earliest_blocks_remaining) {
                    final_status->setText(*stage.earliest_blocks_remaining == 1
                        ? tr("Available in ~1 block")
                        : tr("Available in ~%1 blocks").arg(*stage.earliest_blocks_remaining));
                } else {
                    final_status->setText(stage.awaiting_maturity > 0 ? tr("Waiting for maturity") : tr("No confirmed funds"));
                }
            }
        }
    }
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model) {
        // Show warning, for example if this is a prerelease version
        connect(model, &ClientModel::alertsChanged, this, &OverviewPage::updateAlerts);
        updateAlerts(model->getStatusBarWarnings());

        connect(model->getOptionsModel(), &OptionsModel::fontForMoneyChanged, this, &OverviewPage::setMonospacedFont);
        setMonospacedFont(clientModel->getOptionsModel()->getFontForMoney());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        connect(filter.get(), &TransactionFilterProxy::rowsInserted, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &TransactionFilterProxy::rowsRemoved, this, &OverviewPage::LimitTransactionRows);
        connect(filter.get(), &TransactionFilterProxy::rowsMoved, this, &OverviewPage::LimitTransactionRows);
        LimitTransactionRows();
        // Keep up to date with wallet
        setBalance(model->getCachedBalance());
        connect(model, &WalletModel::balanceChanged, this, &OverviewPage::setBalance);

        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &OverviewPage::updateDisplayUnit);
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void OverviewPage::changeEvent(QEvent* e)
{
    if (e->type() == QEvent::PaletteChange) {
        QIcon icon = m_platform_style->SingleColorIcon(QStringLiteral(":/icons/warning"));
        ui->labelTransactionsStatus->setIcon(icon);
        ui->labelWalletStatus->setIcon(icon);
    }

    QWidget::changeEvent(e);
}

// Only show most recent NUM_ITEMS rows
void OverviewPage::LimitTransactionRows()
{
    if (filter && ui->listTransactions && ui->listTransactions->model() && filter.get() == ui->listTransactions->model()) {
        for (int i = 0; i < filter->rowCount(); ++i) {
            ui->listTransactions->setRowHidden(i, i >= NUM_ITEMS);
        }
    }
}

void OverviewPage::updateDisplayUnit()
{
    if (walletModel && walletModel->getOptionsModel()) {
        const auto& balances = walletModel->getCachedBalance();
        if (balances.balance != -1) {
            setBalance(balances);
        }

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}

void OverviewPage::setMonospacedFont(const QFont& f)
{
    ui->labelBalance->setFont(f);
    ui->labelUnconfirmed->setFont(f);
    ui->labelImmature->setFont(f);
    ui->labelTotal->setFont(f);
}
