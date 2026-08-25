// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/overviewpage.h>

#include <chainparams.h>
#include <interfaces/node.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/forms/ui_overviewpage.h>
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
#include <QCryptographicHash>
#include <QDateTime>
#include <QEvent>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPainter>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSizePolicy>
#include <QStatusTipEvent>
#include <QVBoxLayout>

#include <algorithm>
#include <map>
#include <optional>
#include <tuple>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5

Q_DECLARE_METATYPE(interfaces::WalletBalances)

namespace {

BitcoinUnit VaultDisplayUnit(BitcoinUnit configured, CAmount total)
{
    // Tiny vault balances are much easier to scan as whole satoshis than as a
    // long run of leading BTC zeroes. Preserve every other explicit unit.
    if (configured == BitcoinUnit::BTC && total > 0 && total < COIN / 100) {
        return BitcoinUnit::SAT;
    }
    return configured;
}

QString VaultFriendlyDuration(int64_t seconds)
{
    if (seconds < 0) seconds = 0;
    constexpr int64_t day = 24 * 60 * 60;
    if (seconds < day) {
        return GUIUtil::formatNiceTimeOffset(seconds);
    }
    const int days = static_cast<int>((seconds + day / 2) / day);
    return days == 1 ? QObject::tr("1 day") : QObject::tr("%1 days").arg(days);
}

} // namespace

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

    buildVaultDashboard();
}

void OverviewPage::buildVaultDashboard()
{
    auto* scroll = new QScrollArea(ui->frame);
    scroll->setObjectName("vaultDashboardScroll");
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    scroll->setAutoFillBackground(false);
    scroll->viewport()->setAutoFillBackground(false);

    m_vault_dashboard = new QWidget;
    m_vault_dashboard->setObjectName("vaultDashboard");
    m_vault_dashboard->setAutoFillBackground(false);
    auto* outer = new QVBoxLayout(m_vault_dashboard);
    outer->setContentsMargins(4, 2, 8, 8);
    outer->setSpacing(0);
    auto* content = new QWidget(m_vault_dashboard);
    content->setObjectName("vaultDashboardContent");
    content->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    outer->addWidget(content);
    outer->addStretch();

    auto* dashboard = new QVBoxLayout(content);
    dashboard->setContentsMargins(0, 0, 0, 0);
    dashboard->setSpacing(10);
    m_vault_dashboard->setStyleSheet(QStringLiteral(
        "#vaultDashboard, #vaultDashboardContent { background: transparent; }"
        "QFrame[vaultCard=\"true\"] { background: transparent; border: none; border-top: 1px solid palette(mid); border-radius: 0px; }"
        "QFrame[vaultCard=\"true\"] QLabel { background: transparent; border: none; }"
        "QLabel[vaultEyebrow=\"true\"] { font-weight: 600; }"
        "QFrame[vaultDivider=\"true\"] { background: palette(mid); border: none; min-width: 1px; max-width: 1px; min-height: 36px; }"));

    const auto make_card = [](const char* name) {
        auto* card = new QFrame;
        card->setObjectName(QString::fromLatin1(name));
        card->setProperty("vaultCard", true);
        card->setFrameShape(QFrame::NoFrame);
        card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        return card;
    };
    const auto make_heading = [](const QString& text, QWidget* parent = nullptr) {
        auto* label = new QLabel(text, parent);
        QFont font = label->font();
        font.setBold(true);
        label->setFont(font);
        return label;
    };
    const auto make_amount = [](const QString& object_name, QWidget* parent = nullptr) {
        auto* label = new QLabel(parent);
        label->setObjectName(object_name);
        QFont font = label->font();
        font.setBold(true);
        font.setPointSize(font.pointSize() + 2);
        label->setFont(font);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        return label;
    };

    auto* total_card = new QWidget(content);
    total_card->setObjectName("vaultTotalCard");
    auto* total_layout = new QHBoxLayout(total_card);
    total_layout->setContentsMargins(0, 2, 0, 4);
    auto* balance_block = new QVBoxLayout;
    balance_block->setSpacing(2);
    auto* balance_caption = new QLabel(tr("TOTAL BALANCE"), total_card);
    balance_caption->setProperty("vaultEyebrow", true);
    balance_block->addWidget(balance_caption);
    m_vault_total_amount = make_amount("vaultTotalAmount", total_card);
    QFont total_font = m_vault_total_amount->font();
    total_font.setPointSize(total_font.pointSize() + 7);
    total_font.setWeight(QFont::DemiBold);
    m_vault_total_amount->setFont(total_font);
    m_vault_total_amount->setAccessibleName(tr("Total in Recovery Vault"));
    balance_block->addWidget(m_vault_total_amount);
    total_layout->addLayout(balance_block, 1);
    m_vault_balance_status = new QLabel(total_card);
    m_vault_balance_status->setObjectName("vaultBalanceStatus");
    m_vault_balance_status->setProperty("vaultSecondary", true);
    m_vault_balance_status->setWordWrap(true);
    m_vault_balance_status->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    m_vault_balance_status->setMaximumWidth(360);
    total_layout->addWidget(m_vault_balance_status);
    dashboard->addWidget(total_card);

    auto* access_card = make_card("vaultAccessCard");
    auto* access_layout = new QVBoxLayout(access_card);
    access_layout->setContentsMargins(0, 10, 0, 2);
    access_layout->setSpacing(6);
    auto* access_header = new QHBoxLayout;
    auto* access_heading = make_heading(tr("Access over time"), access_card);
    access_heading->setObjectName("vaultAccessHeading");
    access_header->addWidget(access_heading);
    access_header->addStretch();
    m_vault_access_details = new QPushButton(tr("Technical Details"), access_card);
    m_vault_access_details->setObjectName("vaultAccessTechnicalButton");
    m_vault_access_details->setCheckable(true);
    m_vault_access_details->setFlat(true);
    m_vault_access_details->setAccessibleDescription(tr("Show exact block-based recovery timing."));
    access_header->addWidget(m_vault_access_details);
    access_layout->addLayout(access_header);
    auto* stages = new QWidget(access_card);
    stages->setObjectName("vaultRecoveryStages");
    m_vault_stages_layout = new QHBoxLayout(stages);
    m_vault_stages_layout->setContentsMargins(0, 0, 0, 0);
    m_vault_stages_layout->setSpacing(12);
    access_layout->addWidget(stages);
    connect(m_vault_access_details, &QPushButton::toggled, this, [this](bool visible) {
        for (QLabel* label : m_vault_dashboard->findChildren<QLabel*>()) {
            const QString name{label->objectName()};
            if ((name == QStringLiteral("vaultImmediateTechnical") ||
                 (name.startsWith(QStringLiteral("vaultRecoveryStage")) &&
                  name.endsWith(QStringLiteral("Technical"))))) {
                label->setVisible(visible && !m_privacy && !label->text().isEmpty());
            }
        }
    });
    dashboard->addWidget(access_card);

    m_vault_protection_card = make_card("vaultThreeKeyProtectionCard");
    auto* protection_layout = new QVBoxLayout(m_vault_protection_card);
    protection_layout->setContentsMargins(0, 10, 0, 2);
    protection_layout->setSpacing(4);
    auto* protection_header = new QHBoxLayout;
    auto* protection_heading = make_heading(tr("Protection renewal"), m_vault_protection_card);
    protection_heading->setObjectName("vaultThreeKeyProtectionHeading");
    protection_header->addWidget(protection_heading);
    protection_header->addStretch();
    m_vault_renewal_button = new QPushButton(tr("Renew Early…"), m_vault_protection_card);
    m_vault_renewal_button->setObjectName("vaultRenewalButton");
    m_vault_renewal_button->setAccessibleDescription(
        tr("Review a self-transfer that restarts the 90/180-day recovery clocks after confirmation."));
    protection_header->addWidget(m_vault_renewal_button);
    protection_layout->addLayout(protection_header);
    m_vault_protection_explanation = new QLabel(
        tr("All three keys always work. Additional recovery paths become available as coins age."),
        m_vault_protection_card);
    m_vault_protection_explanation->setObjectName("vaultThreeKeyProtectionExplanation");
    m_vault_protection_explanation->setProperty("vaultSecondary", true);
    m_vault_protection_explanation->setWordWrap(true);
    protection_layout->addWidget(m_vault_protection_explanation);

    auto* protection_grid = new QHBoxLayout;
    protection_grid->setSpacing(12);
    const auto add_protection_stat = [&](const QString& title, QWidget*& stat, QLabel*& value, const QString& object_name, const QString& accessible_name) {
        stat = new QWidget(m_vault_protection_card);
        auto* stat_layout = new QVBoxLayout(stat);
        stat_layout->setContentsMargins(0, 0, 0, 0);
        stat_layout->setSpacing(2);
        auto* label = new QLabel(title, stat);
        label->setProperty("vaultSecondary", true);
        label->setWordWrap(true);
        value = make_amount(object_name, stat);
        QFont amount_font = value->font();
        amount_font.setPointSize(std::max(1, amount_font.pointSize() - 2));
        value->setFont(amount_font);
        value->setAccessibleName(accessible_name);
        stat_layout->addWidget(label);
        stat_layout->addWidget(value);
        protection_grid->addWidget(stat, 1);
    };
    add_protection_stat(tr("THREE-KEY ONLY"), m_vault_protected_stat, m_vault_protected_amount,
                       QStringLiteral("vaultThreeKeyOnlyAmount"),
                       tr("Amount for which all three keys are the only spending path"));
    add_protection_stat(tr("RECOVERY OPEN"), m_vault_recovery_enabled_stat, m_vault_recovery_enabled_amount,
                       QStringLiteral("vaultRecoveryEnabledAmount"),
                       tr("Amount with an additional recovery path available"));
    add_protection_stat(tr("DUE SOON"), m_vault_due_stat, m_vault_due_amount,
                       QStringLiteral("vaultRenewalDueAmount"),
                       tr("Amount entering the fourteen-day protection renewal window"));
    add_protection_stat(tr("CONFIRMING"), m_vault_unconfirmed_stat, m_vault_unconfirmed_amount,
                       QStringLiteral("vaultUnconfirmedClockAmount"),
                       tr("Unconfirmed amount whose recovery clocks have not started"));
    protection_layout->addLayout(protection_grid);
    m_vault_next_expansion = new QLabel(m_vault_protection_card);
    m_vault_next_expansion->setObjectName("vaultNextAccessExpansion");
    m_vault_next_expansion->setProperty("vaultSecondary", true);
    m_vault_next_expansion->setWordWrap(true);
    m_vault_next_expansion->setAccessibleName(tr("Next additional recovery path availability"));
    protection_layout->addWidget(m_vault_next_expansion);
    connect(m_vault_renewal_button, &QPushButton::clicked, this, [this] {
        Q_EMIT vaultRenewalRequested(m_vault_renewal_button->property("renewalDue").toBool());
    });
    dashboard->addWidget(m_vault_protection_card);

    m_vault_setup_card = make_card("vaultSetupCard");
    auto* setup_layout = new QHBoxLayout(m_vault_setup_card);
    setup_layout->setContentsMargins(0, 10, 0, 4);
    auto* setup_copy = new QVBoxLayout;
    setup_copy->setSpacing(3);
    m_vault_setup_heading = make_heading(tr("Setup & verification"), m_vault_setup_card);
    setup_copy->addWidget(m_vault_setup_heading);
    m_vault_setup_status = new QLabel(m_vault_setup_card);
    m_vault_setup_status->setObjectName("vaultSetupStatus");
    m_vault_setup_status->setProperty("vaultSecondary", true);
    m_vault_setup_status->setWordWrap(true);
    setup_copy->addWidget(m_vault_setup_status);
    m_vault_verification_status = new QLabel(m_vault_setup_card);
    m_vault_verification_status->setObjectName("vaultVerificationStatus");
    m_vault_verification_status->setProperty("vaultSecondary", true);
    m_vault_verification_status->setWordWrap(true);
    setup_copy->addWidget(m_vault_verification_status);
    setup_layout->addLayout(setup_copy, 1);
    m_finish_vault_setup = new QPushButton(tr("Finish Setup…"), m_vault_setup_card);
    m_finish_vault_setup->setObjectName("finishVaultSetupButton");
    m_finish_vault_setup->setAccessibleDescription(tr("Continue the saved Recovery Vault setup journey."));
    setup_layout->addWidget(m_finish_vault_setup, 0, Qt::AlignVCenter);
    connect(m_finish_vault_setup, &QPushButton::clicked, this, &OverviewPage::finishVaultSetupRequested);
    dashboard->addWidget(m_vault_setup_card);

    m_vault_rescan_card = make_card("vaultRescanCard");
    auto* rescan_layout = new QVBoxLayout(m_vault_rescan_card);
    rescan_layout->setContentsMargins(0, 12, 0, 8);
    rescan_layout->addWidget(make_heading(tr("Blockchain scan incomplete"), m_vault_rescan_card));
    auto* rescan_explanation = new QLabel(
        tr("This restored vault cannot report complete balances or send until its required scan from the genesis block finishes. The previous scan did not complete."),
        m_vault_rescan_card);
    rescan_explanation->setObjectName("vaultRescanExplanation");
    rescan_explanation->setWordWrap(true);
    rescan_layout->addWidget(rescan_explanation);
    m_retry_vault_rescan = new QPushButton(tr("Resume Scan…"), m_vault_rescan_card);
    m_retry_vault_rescan->setObjectName("retryVaultRescanButton");
    m_retry_vault_rescan->setAccessibleDescription(tr("Resume the required Recovery Vault scan from its saved checkpoint when available."));
    m_retry_vault_rescan->setMinimumHeight(32);
    rescan_layout->addWidget(m_retry_vault_rescan, 0, Qt::AlignLeft);
    connect(m_retry_vault_rescan, &QPushButton::clicked, this, &OverviewPage::retryVaultRescanRequested);
    dashboard->addWidget(m_vault_rescan_card);

    auto* participants_header = new QHBoxLayout;
    participants_header->setContentsMargins(0, 8, 0, 0);
    auto* participants_heading = make_heading(tr("Keys"));
    participants_heading->setObjectName("vaultParticipantsHeading");
    participants_header->addWidget(participants_heading);
    participants_header->addStretch();
    m_refresh_participants = new QPushButton(tr("Check Status"));
    m_refresh_participants->setObjectName("refreshVaultParticipantsButton");
    m_refresh_participants->setAccessibleDescription(tr("Check connected hardware participants. Until this finishes, their availability remains unknown."));
    m_refresh_participants->setFlat(true);
    participants_header->addWidget(m_refresh_participants);
    dashboard->addLayout(participants_header);

    auto* participants = new QWidget;
    participants->setObjectName("vaultParticipants");
    m_vault_participants_layout = new QVBoxLayout(participants);
    m_vault_participants_layout->setContentsMargins(0, 0, 0, 0);
    m_vault_participants_layout->setSpacing(2);
    dashboard->addWidget(participants);

    m_vault_actions = new QWidget;
    m_vault_actions->setObjectName("vaultDashboardActions");
    auto* actions = new QHBoxLayout(m_vault_actions);
    actions->setContentsMargins(0, 0, 0, 0);
    m_start_delayed_recovery = new QPushButton(tr("Start Delayed Recovery…"));
    m_start_delayed_recovery->setObjectName("startDelayedRecoveryButton");
    m_start_delayed_recovery->setFlat(true);
    m_start_delayed_recovery->setAccessibleDescription(tr("Open a guided recovery flow where you explicitly choose an eligible policy stage."));
    actions->addWidget(m_start_delayed_recovery);
    m_delayed_recovery_availability = new QLabel;
    m_delayed_recovery_availability->setObjectName("delayedRecoveryAvailability");
    m_delayed_recovery_availability->setWordWrap(true);
    actions->addWidget(m_delayed_recovery_availability, 1);
    auto* recovery_kit = new QPushButton(tr("Export Public Policy…"));
    recovery_kit->setObjectName("recoveryKitButton");
    recovery_kit->setAccessibleDescription(tr("Export the public vault policy. This does not reveal or recreate private recovery phrases."));
    recovery_kit->setFlat(true);
    actions->addWidget(recovery_kit);
    connect(m_start_delayed_recovery, &QPushButton::clicked, this, &OverviewPage::delayedRecoveryRequested);
    connect(recovery_kit, &QPushButton::clicked, this, &OverviewPage::recoveryKitRequested);
    dashboard->addWidget(m_vault_actions);
    scroll->setWidget(m_vault_dashboard);
    ui->verticalLayout_4->addWidget(scroll, /*stretch=*/1);
    scroll->hide();
}

void OverviewPage::rebuildVaultStages()
{
    if (!m_vault_stages_layout || !walletModel || !walletModel->getOptionsModel()) return;
    while (QLayoutItem* item = m_vault_stages_layout->takeAt(0)) {
        delete item->widget();
        delete item;
    }
    m_vault_immediate_amount = nullptr;
    m_vault_immediate_quorum = nullptr;

    const CAmount total = m_balances.balance + m_balances.unconfirmed_balance + m_balances.immature_balance;
    const BitcoinUnit unit = VaultDisplayUnit(walletModel->getOptionsModel()->getDisplayUnit(), total);
    const int64_t spacing = Params().GetConsensus().nPowTargetSpacing;
    const auto block_count = [](uint32_t blocks) {
        return blocks == 1 ? tr("1 block") : tr("%1 blocks").arg(blocks);
    };

    const auto add_divider = [&] {
        auto* divider = new QFrame;
        divider->setProperty("vaultDivider", true);
        divider->setFrameShape(QFrame::NoFrame);
        divider->setAccessibleName(tr("Next recovery stage"));
        m_vault_stages_layout->addWidget(divider);
    };
    const auto make_column = [&](const QString& object_name, const QString& phase,
                                 const QString& quorum, const QString& summary,
                                 const QString& technical, int index) {
        auto* column = new QWidget;
        column->setObjectName(object_name);
        column->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        auto* layout = new QVBoxLayout(column);
        layout->setContentsMargins(2, 2, 2, 2);
        layout->setSpacing(4);
        auto* phase_label = new QLabel(phase, column);
        phase_label->setObjectName(object_name + QStringLiteral("Phase"));
        phase_label->setProperty("vaultEyebrow", true);
        phase_label->setWordWrap(true);
        layout->addWidget(phase_label);
        auto* quorum_label = new QLabel(quorum, column);
        QFont quorum_font = quorum_label->font();
        quorum_font.setWeight(QFont::DemiBold);
        quorum_label->setFont(quorum_font);
        quorum_label->setWordWrap(true);
        layout->addWidget(quorum_label);
        auto* summary_label = new QLabel(summary, column);
        summary_label->setProperty("vaultSecondary", true);
        summary_label->setWordWrap(true);
        layout->addWidget(summary_label);
        auto* technical_label = new QLabel(technical, column);
        technical_label->setObjectName(index == 0 ? QStringLiteral("vaultImmediateTechnical") :
                                                    QStringLiteral("vaultRecoveryStage%1Technical").arg(index));
        technical_label->setProperty("vaultSecondary", true);
        technical_label->setWordWrap(true);
        technical_label->setVisible(m_vault_access_details && m_vault_access_details->isChecked() && !m_privacy && !technical.isEmpty());
        layout->addWidget(technical_label);
        return std::tuple{column, quorum_label, summary_label};
    };

    QString immediate_summary;
    if (m_privacy) {
        immediate_summary = tr("Amount hidden");
    } else if (m_balances.vault_immediate > 0) {
        immediate_summary = BitcoinUnits::formatWithUnit(
            unit, m_balances.vault_immediate, false, BitcoinUnits::SeparatorStyle::ALWAYS);
    } else if (m_balances.unconfirmed_balance > 0) {
        immediate_summary = tr("Available after confirmation");
    } else {
        immediate_summary = tr("No confirmed funds");
    }
    const int participant_count = static_cast<int>(m_vault_status.participants.size());
    const QString immediate_quorum = participant_count > 0 ?
        tr("All %1 keys").arg(participant_count) : tr("Every key");
    auto [immediate_column, immediate_quorum_label, immediate_summary_label] = make_column(
        QStringLiteral("vaultImmediateCard"), tr("NOW"), immediate_quorum,
        immediate_summary, tr("Immediate path · no recovery delay"), 0);
    m_vault_immediate_quorum = immediate_quorum_label;
    m_vault_immediate_quorum->setObjectName("vaultImmediateQuorum");
    m_vault_immediate_amount = immediate_summary_label;
    m_vault_immediate_amount->setObjectName("vaultImmediateAmount");
    m_vault_immediate_amount->setAccessibleName(tr("Amount available for immediate spend"));
    m_vault_stages_layout->addWidget(immediate_column, 1);

    for (int index = 0; index < static_cast<int>(m_vault_status.recovery_stages.size()); ++index) {
        const auto& stage = m_vault_status.recovery_stages[index];
        add_divider();
        QString phase = tr("Later");
        if (stage.older) {
            const int64_t seconds{int64_t{*stage.older} * spacing};
            phase = seconds >= 24 * 60 * 60 ?
                tr("About %1").arg(VaultFriendlyDuration(seconds)) :
                tr("After %1").arg(VaultFriendlyDuration(seconds));
        } else if (stage.after) {
            phase = tr("At block %1").arg(*stage.after);
        }
        const QString quorum = stage.nrequired == 1 ? tr("Any 1 key") : tr("Any %1 keys").arg(stage.nrequired);
        QString summary;
        QString exact;
        if (m_privacy) {
            summary = tr("Hidden");
        } else {
            const QString available = BitcoinUnits::formatWithUnit(
                unit, stage.recoverable_now, false, BitcoinUnits::SeparatorStyle::ALWAYS);
            const QString awaiting = BitcoinUnits::formatWithUnit(
                unit, stage.awaiting_maturity, false, BitcoinUnits::SeparatorStyle::ALWAYS);
            if (stage.recoverable_now > 0 && stage.awaiting_maturity > 0) {
                summary = tr("%1 now\n%2 later").arg(available, awaiting);
            } else if (stage.recoverable_now > 0) {
                summary = tr("%1 now").arg(available);
            } else if (stage.awaiting_maturity > 0 && stage.earliest_blocks_remaining) {
                summary = tr("%1 in about %2").arg(
                    awaiting,
                    VaultFriendlyDuration(int64_t{*stage.earliest_blocks_remaining} * spacing));
            } else if (m_balances.unconfirmed_balance > 0) {
                summary = tr("Timing starts after confirmation");
            } else {
                summary = tr("No confirmed funds");
            }
            if (stage.older) {
                exact = tr("Policy delay: %1").arg(block_count(*stage.older)) +
                        (stage.earliest_blocks_remaining ?
                             tr(" · Next eligibility: %1").arg(block_count(*stage.earliest_blocks_remaining)) :
                             QString{});
            } else if (stage.after) {
                exact = tr("Policy height: block %1").arg(*stage.after);
            }
        }
        auto [column, quorum_label, summary_label] = make_column(
            QStringLiteral("vaultRecoveryStage%1Card").arg(index + 1),
            phase, quorum, summary, exact, index + 1);
        quorum_label->setObjectName(QStringLiteral("vaultRecoveryStage%1Quorum").arg(index + 1));
        summary_label->setObjectName(QStringLiteral("vaultRecoveryStage%1Summary").arg(index + 1));
        summary_label->setAccessibleName(tr("Amount eligible at recovery stage %1").arg(index + 1));
        m_vault_stages_layout->addWidget(column, 1);
    }
}

void OverviewPage::rebuildVaultParticipants()
{
    if (!m_vault_participants_layout) return;
    while (QLayoutItem* item = m_vault_participants_layout->takeAt(0)) {
        delete item->widget();
        delete item;
    }

    for (int index = 0; index < static_cast<int>(m_vault_status.participants.size()); ++index) {
        const auto& participant = m_vault_status.participants[index];
        const bool manually_lost = std::ranges::find(m_vault_status.manually_lost_signers, participant.fingerprint) !=
                                   m_vault_status.manually_lost_signers.end();
        auto* row = new QFrame;
        row->setObjectName(QStringLiteral("vaultParticipant%1Row").arg(index + 1));
        row->setFrameShape(QFrame::NoFrame);
        auto* layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 4, 0, 4);
        auto* identity = new QLabel(row);
        identity->setObjectName(QStringLiteral("vaultParticipant%1Identity").arg(index + 1));
        auto* state = new QLabel(row);
        state->setObjectName(QStringLiteral("vaultParticipant%1Status").arg(index + 1));
        state->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

        QString kind;
        QString availability;
        QFont identity_font = identity->font();
        identity_font.setWeight(QFont::DemiBold);
        identity->setFont(identity_font);
        if (m_privacy) {
            identity->setText(tr("Key %1 · Hidden").arg(index + 1));
            availability = tr("Hidden");
        } else {
            switch (participant.type) {
            case interfaces::Wallet::VaultParticipantType::LOCAL_SOFTWARE:
                kind = tr("This device");
                availability = manually_lost ? tr("Marked lost") : tr("Available");
                break;
            case interfaces::Wallet::VaultParticipantType::HARDWARE:
                kind = tr("Hardware");
                if (manually_lost) {
                    availability = tr("Marked lost");
                } else if (participant.availability == interfaces::Wallet::VaultSignerAvailability::AVAILABLE) {
                    availability = tr("Connected");
                } else if (!m_vault_status.signer_discovery_complete) {
                    availability = tr("Unknown");
                } else if (participant.availability == interfaces::Wallet::VaultSignerAvailability::UNAVAILABLE) {
                    availability = tr("Unavailable");
                } else {
                    availability = tr("Unknown");
                }
                break;
            case interfaces::Wallet::VaultParticipantType::AIR_GAPPED:
                kind = tr("Offline signer");
                availability = manually_lost ? tr("Marked lost") : tr("Offline / PSBT");
                break;
            case interfaces::Wallet::VaultParticipantType::UNKNOWN:
                kind = tr("Type unknown");
                availability = manually_lost ? tr("Marked lost") : tr("Unknown");
                break;
            }
            identity->setText(tr("Key %1 · %2").arg(index + 1).arg(kind));
        }
        const QString fingerprint_text = QString::fromStdString(participant.fingerprint).toUpper();
        identity->setToolTip(m_privacy ? QString{} :
            tr("Fingerprint: %1\nPath: %2").arg(fingerprint_text, QString::fromStdString(participant.path)));
        identity->setTextInteractionFlags(m_privacy ? Qt::NoTextInteraction : Qt::TextSelectableByMouse);
        state->setText(availability);
        state->setAccessibleName(tr("Participant %1 status: %2").arg(index + 1).arg(availability));
        layout->addWidget(identity, 1);
        layout->addWidget(state);

        auto* lost_button = new QPushButton(manually_lost ? tr("Mark Found…") : tr("Mark Lost…"), row);
        lost_button->setObjectName(QStringLiteral("vaultParticipant%1LostButton").arg(index + 1));
        lost_button->setVisible(!m_privacy);
        lost_button->setEnabled(!participant.fingerprint.empty());
        lost_button->setAccessibleDescription(manually_lost ? tr("Remove the local lost marker for participant %1.").arg(index + 1) : tr("Persistently mark participant %1 as lost on this device.").arg(index + 1));
        lost_button->setFlat(true);
        const std::string fingerprint = participant.fingerprint;
        const bool mark_lost = !manually_lost;
        const std::optional<std::string> expected_policy_commitment{
            m_vault_status.policy_commitment.empty() ? std::nullopt : std::optional<std::string>{m_vault_status.policy_commitment}};
        connect(lost_button, &QPushButton::clicked, this, [this, fingerprint, mark_lost, expected_policy_commitment] {
            // Leave the clicked button's event stack before a successful
            // update synchronously rebuilds the participant rows.
            QMetaObject::invokeMethod(this, [this, fingerprint, mark_lost, expected_policy_commitment] { setVaultSignerLost(fingerprint, mark_lost, expected_policy_commitment); }, Qt::QueuedConnection);
        });
        layout->addWidget(lost_button);
        m_vault_participants_layout->addWidget(row);
        row->show();
    }

    if (m_vault_status.participants.empty()) {
        auto* empty = new QLabel(m_privacy ? tr("Participant details hidden") : tr("Participant details are unavailable for this vault."));
        empty->setObjectName("vaultParticipantsUnavailable");
        empty->setWordWrap(true);
        m_vault_participants_layout->addWidget(empty);
        empty->show();
    }
}

void OverviewPage::setVaultSignerLost(
    const std::string& fingerprint, bool lost,
    const std::optional<std::string>& expected_policy_commitment)
{
    if (!walletModel || fingerprint.empty()) return;
    const QString fingerprint_text = QString::fromStdString(fingerprint).toUpper();
    const QString title = lost ? tr("Mark participant lost?") : tr("Mark participant found?");
    const QString text = lost ? tr("Immediate spending will be blocked because it requires every participant. This local marker does not change the vault policy. Continue for participant %1?").arg(fingerprint_text) : tr("Remove the local lost marker for participant %1? Only continue if you can use this exact participant again.").arg(fingerprint_text);
    if (QMessageBox::warning(this, title, text, QMessageBox::Cancel | QMessageBox::Yes, QMessageBox::Cancel) != QMessageBox::Yes) return;

    bool saved{false};
    try {
        saved = walletModel->setVaultSignerLost(
            fingerprint, lost, expected_policy_commitment);
    } catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Participant status not saved"), QString::fromLocal8Bit(e.what()));
        return;
    }
    if (!saved) {
        QMessageBox::critical(this, tr("Participant status not saved"), tr("The wallet could not persist this participant status. Nothing was changed."));
        return;
    }
    walletModel->refreshVaultSignerStatus();
}

void OverviewPage::updateVaultDashboard()
{
    if (!walletModel || !walletModel->getOptionsModel() || !m_vault_dashboard) return;
    const bool vault = m_balances.is_vault;
    if (auto* scroll = findChild<QScrollArea*>("vaultDashboardScroll")) scroll->setVisible(vault);
    ui->label_5->setText(vault ? tr("Recovery Vault") : tr("Balances"));
    ui->frame_2->setVisible(!vault);
    ui->frame_2->setMaximumWidth(vault ? 0 : QWIDGETSIZE_MAX);
    ui->frame->setFrameShape(vault ? QFrame::NoFrame : QFrame::StyledPanel);
    ui->horizontalLayout->setStretch(0, 1);
    ui->horizontalLayout->setStretch(1, vault ? 0 : 1);
    ui->verticalLayout_2->setStretch(0, vault ? 1 : 0);
    ui->verticalLayout_2->setStretch(1, vault ? 0 : 1);
    if (vault) {
        ui->verticalSpacer->changeSize(0, 0, QSizePolicy::Ignored, QSizePolicy::Ignored);
        ui->verticalSpacer_2->changeSize(0, 0, QSizePolicy::Ignored, QSizePolicy::Ignored);
        ui->frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        ui->frame_2->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    } else {
        ui->verticalSpacer->changeSize(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);
        ui->verticalSpacer_2->changeSize(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);
        ui->frame->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        ui->frame_2->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    }
    ui->verticalLayout_2->invalidate();
    ui->verticalLayout_3->invalidate();
    ui->horizontalLayout->invalidate();
    if (!vault) return;

    const CAmount total = m_balances.balance + m_balances.unconfirmed_balance + m_balances.immature_balance;
    const BitcoinUnit unit = VaultDisplayUnit(walletModel->getOptionsModel()->getDisplayUnit(), total);
    m_vault_total_amount->setText(BitcoinUnits::formatWithPrivacy(unit, total, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy));
    if (m_privacy) {
        m_vault_balance_status->setText(tr("Vault status hidden"));
        m_vault_setup_status->setText(tr("Setup status hidden"));
        m_vault_verification_status->setText(tr("Verification status hidden"));
    } else {
        if (m_balances.unconfirmed_balance > 0 && m_balances.balance == 0) {
            m_vault_balance_status->setText(tr("Awaiting first confirmation\nRecovery timing has not started"));
        } else if (m_balances.unconfirmed_balance > 0) {
            m_vault_balance_status->setText(tr("Includes funds awaiting confirmation"));
        } else if (total == 0) {
            m_vault_balance_status->setText(tr("No funds received yet"));
        } else {
            m_vault_balance_status->setText(tr("Protected by all three keys"));
        }
        switch (m_vault_status.setup_state) {
        case interfaces::Wallet::VaultSetupState::NOT_RECORDED:
            m_vault_setup_status->setText(tr("Setup status: Not recorded"));
            break;
        case interfaces::Wallet::VaultSetupState::RECOVERY_KIT_REQUIRED:
            m_vault_setup_status->setText(tr("Setup incomplete: Save the Recovery Kit"));
            break;
        case interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED:
            m_vault_setup_status->setText(tr("Setup incomplete: Verify the receive address"));
            break;
        case interfaces::Wallet::VaultSetupState::COMPLETE:
            m_vault_setup_status->setText(tr("Setup complete"));
            break;
        }
        switch (m_vault_status.verification_state) {
        case interfaces::Wallet::VaultVerificationState::NOT_RECORDED:
            m_vault_verification_status->setText(tr("Address verification: Not recorded"));
            break;
        case interfaces::Wallet::VaultVerificationState::PENDING:
            m_vault_verification_status->setText(tr("Address verification: Pending"));
            break;
        case interfaces::Wallet::VaultVerificationState::RECOVERY_KIT_MATCHED:
            m_vault_verification_status->setText(tr("Address verification: Matched Recovery Kit"));
            break;
        case interfaces::Wallet::VaultVerificationState::INDEPENDENTLY_VERIFIED:
            m_vault_verification_status->setText(tr("Address verification: Independently verified"));
            break;
        case interfaces::Wallet::VaultVerificationState::FINISHED_UNVERIFIED:
            m_vault_verification_status->setText(tr("Address verification: Finished without verification"));
            break;
        }
    }

    const bool setup_not_recorded = m_vault_status.setup_state == interfaces::Wallet::VaultSetupState::NOT_RECORDED;
    const bool recovery_kit_needed = m_vault_status.setup_state == interfaces::Wallet::VaultSetupState::RECOVERY_KIT_REQUIRED;
    const bool address_verification_needed = m_vault_status.setup_state == interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED ||
                                             (m_vault_status.setup_state == interfaces::Wallet::VaultSetupState::COMPLETE &&
                                              m_vault_status.verification_state == interfaces::Wallet::VaultVerificationState::FINISHED_UNVERIFIED);
    const bool setup_actionable = setup_not_recorded || recovery_kit_needed || address_verification_needed;
    const bool independently_verified =
        m_vault_status.verification_state == interfaces::Wallet::VaultVerificationState::INDEPENDENTLY_VERIFIED;
    if (setup_not_recorded) {
        m_vault_setup_heading->setText(tr("Setup status not recorded"));
    } else if (recovery_kit_needed ||
               m_vault_status.setup_state == interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED) {
        m_vault_setup_heading->setText(tr("Finish setting up this vault"));
    } else if (!independently_verified) {
        m_vault_setup_heading->setText(tr("Address not independently verified"));
        m_vault_setup_status->hide();
        if (!m_privacy) {
            m_vault_verification_status->setText(
                tr("Verify the receive address independently before treating it as trusted."));
        }
    } else {
        m_vault_setup_heading->setText(tr("Vault ready"));
    }
    if (independently_verified || recovery_kit_needed || setup_not_recorded ||
        m_vault_status.setup_state == interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED || m_privacy) {
        m_vault_setup_status->show();
    }
    m_finish_vault_setup->setText(setup_not_recorded ? tr("Review Setup…") : address_verification_needed ? tr("Verify Address…") :
                                                                                                           tr("Finish Setup…"));
    m_finish_vault_setup->setVisible(setup_actionable && !m_privacy);
    m_vault_setup_card->setVisible(!independently_verified ||
                                   m_vault_status.setup_state != interfaces::Wallet::VaultSetupState::COMPLETE);
    m_vault_rescan_card->setVisible(m_vault_status.genesis_rescan_required && !m_privacy);
    m_retry_vault_rescan->setVisible(m_vault_status.genesis_rescan_required && !m_privacy);
    m_refresh_participants->setVisible(!m_privacy);
    m_vault_actions->setVisible(!m_privacy);
    updateVaultProtectionCard();

    const bool recovery_eligible = std::ranges::any_of(m_vault_status.recovery_stages, [](const auto& stage) {
        return stage.recoverable_now > 0;
    });
    std::optional<int> earliest;
    for (const auto& stage : m_vault_status.recovery_stages) {
        if (stage.earliest_blocks_remaining && (!earliest || *stage.earliest_blocks_remaining < *earliest)) {
            earliest = stage.earliest_blocks_remaining;
        }
    }
    m_start_delayed_recovery->setEnabled(recovery_eligible && !m_vault_status.genesis_rescan_required);
    m_start_delayed_recovery->setVisible(recovery_eligible && !m_vault_status.genesis_rescan_required && !m_privacy);
    if (recovery_eligible) {
        m_delayed_recovery_availability->setText(tr("Recovery available now"));
    } else if (earliest) {
        m_delayed_recovery_availability->setText(tr("Delayed recovery is expected in about %1.")
                                                     .arg(VaultFriendlyDuration(int64_t{*earliest} * Params().GetConsensus().nPowTargetSpacing)));
    } else {
        m_delayed_recovery_availability->setText(tr("No delayed-recovery funds are currently eligible."));
    }
    // The access timeline already communicates unavailable recovery states.
    // Keep this action row for actions, not another paragraph of status copy.
    m_delayed_recovery_availability->hide();
    rebuildVaultStages();
    rebuildVaultParticipants();
}

void OverviewPage::updateVaultProtectionCard()
{
    if (!m_vault_protection_card || !walletModel || !walletModel->getOptionsModel()) return;
    const bool policy_recognized{m_vault_renewal_status.primary_delay > 0};
    m_vault_protection_card->setVisible(policy_recognized);
    if (!policy_recognized) return;

    const CAmount total{m_balances.balance + m_balances.unconfirmed_balance + m_balances.immature_balance};
    const BitcoinUnit unit{VaultDisplayUnit(walletModel->getOptionsModel()->getDisplayUnit(), total)};
    const auto amount = [&](CAmount value) {
        return BitcoinUnits::formatWithPrivacy(
            unit, value, BitcoinUnits::SeparatorStyle::ALWAYS, m_privacy);
    };
    m_vault_protected_amount->setText(amount(m_vault_renewal_status.three_key_only));
    m_vault_recovery_enabled_amount->setText(amount(m_vault_renewal_status.recovery_enabled));
    m_vault_due_amount->setText(amount(m_vault_renewal_status.warning));
    m_vault_unconfirmed_amount->setText(amount(m_vault_renewal_status.unconfirmed));
    const bool mixed_protection = m_vault_renewal_status.recovery_enabled > 0 ||
                                  m_vault_renewal_status.warning > 0 ||
                                  m_vault_renewal_status.unconfirmed > 0;
    m_vault_protected_stat->setVisible(m_privacy || (m_vault_renewal_status.three_key_only > 0 && mixed_protection));
    m_vault_recovery_enabled_stat->setVisible(m_privacy || m_vault_renewal_status.recovery_enabled > 0);
    m_vault_due_stat->setVisible(m_privacy || m_vault_renewal_status.warning > 0);
    m_vault_unconfirmed_stat->setVisible(m_privacy || m_vault_renewal_status.unconfirmed > 0);
    // Empty due sets end a reminder cycle even while privacy mode suppresses
    // presentation. Non-empty sets remain fully suppressed in privacy mode.
    checkVaultRenewalReminder();

    if (m_privacy) {
        m_vault_next_expansion->setText(tr("Protection timing hidden"));
        m_vault_protection_explanation->setText(tr("Protection details hidden"));
        m_vault_next_expansion->show();
        m_vault_renewal_button->hide();
        return;
    }

    if (m_vault_renewal_status.unconfirmed > 0 &&
        m_vault_renewal_status.three_key_only == 0 &&
        m_vault_renewal_status.recovery_enabled == 0) {
        m_vault_protection_explanation->setText(
            tr("Waiting for confirmation. The recovery clocks have not started."));
    } else {
        m_vault_protection_explanation->setText(
            tr("All three keys always work. Renewing restarts the recovery clocks for selected funds."));
    }
    if (m_vault_renewal_status.next_expansion_blocks) {
        const int64_t seconds{
            int64_t{*m_vault_renewal_status.next_expansion_blocks} *
            Params().GetConsensus().nPowTargetSpacing};
        m_vault_next_expansion->setText(
            tr("Next additional recovery path is expected in about %1.")
                .arg(VaultFriendlyDuration(seconds)));
        m_vault_next_expansion->setToolTip({});
        m_vault_next_expansion->show();
    } else if (m_vault_renewal_status.recovery_enabled > 0) {
        m_vault_next_expansion->setText(
            tr("The first additional recovery path is already available for confirmed funds."));
        m_vault_next_expansion->setToolTip({});
        m_vault_next_expansion->show();
    } else if (m_vault_renewal_status.unconfirmed > 0) {
        m_vault_next_expansion->clear();
        m_vault_next_expansion->setToolTip({});
        m_vault_next_expansion->hide();
    } else {
        m_vault_next_expansion->clear();
        m_vault_next_expansion->setToolTip({});
        m_vault_next_expansion->hide();
    }

    if (!m_vault_renewal_status.supported) {
        m_vault_renewal_button->hide();
        QString unsupported;
        switch (m_vault_renewal_status.schedule) {
        case wallet::FixedVaultSchedule::LEGACY_30_60:
            unsupported = tr("This Recovery Vault uses the legacy 30/60-day schedule. Its policy cannot be changed in place. To use the 90/180-day schedule, create a new Recovery Vault and send the funds to it.");
            break;
        case wallet::FixedVaultSchedule::CUSTOM:
            unsupported = tr("Guided protection renewal is not offered for this custom schedule.");
            break;
        case wallet::FixedVaultSchedule::CURRENT_90_180:
            unsupported = tr("Guided protection renewal is unavailable because this is not a complete standard 90/180-day Recovery Vault policy.");
            break;
        }
        m_vault_next_expansion->setText(
            m_vault_next_expansion->text() + QLatin1Char(' ') + unsupported);
        m_vault_next_expansion->show();
        return;
    }

    const bool due{!m_vault_renewal_status.due_set_digest.empty()};
    m_vault_renewal_button->setProperty("renewalDue", due);
    m_vault_renewal_button->setText(
        due ? tr("Renew Three-Key Protection…") : tr("Renew Early…"));
    m_vault_renewal_button->setFlat(!due);
    m_vault_renewal_button->setDefault(due);
    const bool available{!m_vault_renewal_status.clusters.empty() &&
                         !m_vault_status.genesis_rescan_required};
    m_vault_renewal_button->setEnabled(available);
    m_vault_renewal_button->setVisible(available);
    if (m_vault_status.genesis_rescan_required) {
        m_vault_renewal_button->setToolTip(
            tr("Finish the required blockchain scan before renewing protection."));
    } else if (m_vault_renewal_status.clusters.empty()) {
        m_vault_renewal_button->setToolTip(
            tr("No confirmed, safe, unlocked vault coins are available to renew."));
    } else {
        m_vault_renewal_button->setToolTip({});
    }
}

void OverviewPage::checkVaultRenewalReminder()
{
    if (!walletModel) return;

    QSettings settings;
    settings.beginGroup(QStringLiteral("RecoveryVaultRenewalReminder"));
    const QByteArray wallet_key{
        QCryptographicHash::hash(walletModel->getWalletName().toUtf8(),
                                 QCryptographicHash::Sha256)
            .toHex()};
    const QString key{QString::fromLatin1(wallet_key)};
    const QString digest{QString::fromStdString(m_vault_renewal_status.due_set_digest)};
    const auto decision{vaultRenewalReminderDecision(
        m_vault_renewal_status.due_set_digest, settings.value(key).toString(),
        m_privacy, !clientModel || clientModel->node().isInitialBlockDownload(),
        m_vault_renewal_status.supported)};
    if (decision.clear) {
        // End the reminder cycle. If the same set later reappears after a
        // renewal, abandonment, or reorg, it is a new actionable cycle.
        settings.remove(key);
        return;
    }
    if (!decision.notify) return;

    settings.setValue(key, digest);
    Q_EMIT vaultRenewalReminderRequested(
        tr("Recovery Vault protection renewal"),
        tr("One or more vault coin groups are approaching an additional recovery path. Review protection renewal from the Recovery Vault dashboard."));
}

OverviewPage::VaultRenewalReminderDecision OverviewPage::vaultRenewalReminderDecision(
    const std::string& due_set_digest, const QString& previous_digest,
    bool privacy, bool initial_block_download, bool supported)
{
    if (!supported) return {/*notify=*/false, /*clear=*/!previous_digest.isEmpty()};
    if (due_set_digest.empty()) return {/*notify=*/false, /*clear=*/!previous_digest.isEmpty()};
    if (privacy || initial_block_download) return {};
    return {/*notify=*/previous_digest != QString::fromStdString(due_set_digest), /*clear=*/false};
}

void OverviewPage::handleTransactionClicked(const QModelIndex& index)
{
    if (filter)
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
    m_balances = balances;
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
    ui->labelTotal->setVisible(!balances.is_vault);
    ui->labelTotalText->setVisible(!balances.is_vault);

    if (!balances.is_vault) {
        ui->labelBalanceText->setText(tr("Available:"));
        ui->labelBalance->setToolTip(tr("Your current spendable balance"));
        ui->labelTotalText->setText(tr("Total:"));
        ui->labelTotal->setToolTip(QString());
    }
    if (balances.is_vault) {
        walletModel->refreshVaultSignerStatus();
        walletModel->refreshVaultRenewalStatus();
        m_vault_status = walletModel->vaultStatus();
    }
    updateVaultDashboard();
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
        connect(model, &ClientModel::numBlocksChanged, this, [this] {
            // Coin-age warning boundaries and the next access expansion move
            // even when the wallet's aggregate balance does not. The model
            // coalesces overlapping reads and publishes the refreshed status
            // before reminder evaluation.
            if (walletModel) walletModel->refreshVaultRenewalStatus();
        });
        updateVaultDashboard();
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        m_vault_status = model->vaultStatus();
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

        connect(model, &WalletModel::vaultSignerStatusChanged, this, [this] {
            if (!walletModel) return;
            m_vault_status = walletModel->vaultStatus();
            m_refresh_participants->setEnabled(true);
            m_refresh_participants->setText(tr("Check Status"));
            updateVaultDashboard();
        });
        connect(model, &WalletModel::vaultRenewalStatusChanged, this, [this] {
            if (!walletModel) return;
            m_vault_renewal_status = walletModel->vaultRenewalStatus();
            updateVaultDashboard();
        });
        connect(m_refresh_participants, &QPushButton::clicked, this, [this] {
            if (!walletModel) return;
            m_refresh_participants->setEnabled(false);
            m_refresh_participants->setText(tr("Checking…"));
            walletModel->refreshVaultSignerStatus();
        });

        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &OverviewPage::updateDisplayUnit);
        model->refreshVaultSignerStatus();
        model->refreshVaultRenewalStatus();
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
        if (m_vault_dashboard) {
            // Hairlines use palette(mid), which is resolved when the sheet is
            // polished. Re-polish so a live palette change cannot leave the
            // previous theme's borders on the dashboard.
            m_vault_dashboard->setPalette(palette());
            const QString sheet{m_vault_dashboard->styleSheet()};
            m_vault_dashboard->setStyleSheet({});
            m_vault_dashboard->setStyleSheet(sheet);
            if (auto* scroll = findChild<QScrollArea*>("vaultDashboardScroll")) {
                scroll->setPalette(palette());
                scroll->viewport()->setPalette(palette());
                scroll->viewport()->setAutoFillBackground(false);
            }
        }
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
