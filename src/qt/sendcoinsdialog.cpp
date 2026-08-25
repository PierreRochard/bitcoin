// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/sendcoinsdialog.h>

#include <chainparams.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <node/context.h>
#include <node/interface_ui.h>
#include <node/types.h>
#include <policy/fees/block_policy_estimator.h>
#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/coincontroldialog.h>
#include <qt/forms/ui_sendcoinsdialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/sendcoinsentry.h>
#include <txmempool.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>

#include <QButtonGroup>
#include <QCheckBox>
#include <QFontMetrics>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollBar>
#include <QSettings>
#include <QSizePolicy>
#include <QStringList>
#include <QTextDocument>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <vector>

using common::PSBTError;
using wallet::CCoinControl;

static constexpr std::array confTargets{2, 4, 6, 12, 24, 48, 144, 504, 1008};
int getConfTargetForIndex(int index) {
    if (index+1 > static_cast<int>(confTargets.size())) {
        return confTargets.back();
    }
    if (index < 0) {
        return confTargets[0];
    }
    return confTargets[index];
}
int getIndexForConfTarget(int target) {
    for (unsigned int i = 0; i < confTargets.size(); i++) {
        if (confTargets[i] >= target) {
            return i;
        }
    }
    return confTargets.size() - 1;
}

SendCoinsDialog::SendCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent, GUIUtil::dialog_flags),
    ui(new Ui::SendCoinsDialog),
    m_coin_control(new CCoinControl),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);
    ui->sendButton->setText(tr("Review Transaction"));
    ui->sendButton->setAccessibleName(tr("Review Transaction"));
    ui->sendButton->setAccessibleDescription(tr("Review recipients, fees, and signing options before creating the transaction."));

    if (!_platformStyle->getImagesOnButtons()) {
        ui->addButton->setIcon(QIcon());
        ui->clearButton->setIcon(QIcon());
        ui->sendButton->setIcon(QIcon());
    } else {
        ui->addButton->setIcon(_platformStyle->SingleColorIcon(":/icons/add"));
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->sendButton->setIcon(QIcon());
    }

    GUIUtil::setupAddressWidget(ui->lineEditCoinControlChange, this);

    addEntry();

    connect(ui->addButton, &QPushButton::clicked, this, &SendCoinsDialog::addEntry);
    connect(ui->clearButton, &QPushButton::clicked, this, &SendCoinsDialog::clear);

    // Coin Control
    connect(ui->pushButtonCoinControl, &QPushButton::clicked, this, &SendCoinsDialog::coinControlButtonClicked);
#if (QT_VERSION >= QT_VERSION_CHECK(6, 7, 0))
    connect(ui->checkBoxCoinControlChange, &QCheckBox::checkStateChanged, this, &SendCoinsDialog::coinControlChangeChecked);
#else
    connect(ui->checkBoxCoinControlChange, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlChangeChecked);
#endif
    connect(ui->lineEditCoinControlChange, &QValidatedLineEdit::textEdited, this, &SendCoinsDialog::coinControlChangeEdited);

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAfterFee);
    connect(clipboardBytesAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardBytes);
    connect(clipboardChangeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardChange);
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    // init transaction fee section
    QSettings settings;
    if (!settings.contains("fFeeSectionMinimized"))
        settings.setValue("fFeeSectionMinimized", true);
    if (!settings.contains("nFeeRadio") && settings.contains("nTransactionFee") && settings.value("nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("nFeeRadio", 1); // custom
    if (!settings.contains("nFeeRadio"))
        settings.setValue("nFeeRadio", 0); // recommended
    if (!settings.contains("nSmartFeeSliderPosition"))
        settings.setValue("nSmartFeeSliderPosition", 0);
    ui->groupFee->setId(ui->radioSmartFee, 0);
    ui->groupFee->setId(ui->radioCustomFee, 1);
    ui->groupFee->button((int)std::max(0, std::min(1, settings.value("nFeeRadio").toInt())))->setChecked(true);
    ui->customFee->SetAllowEmpty(false);
    ui->customFee->setValue(settings.value("nTransactionFee").toLongLong());
    minimizeFeeSection(settings.value("fFeeSectionMinimized").toBool());

    GUIUtil::ExceptionSafeConnect(ui->sendButton, &QPushButton::clicked, this, &SendCoinsDialog::sendButtonClicked);

    m_vault_notice = new QLabel;
    m_vault_notice->setObjectName("vaultSendNotice");
    m_vault_notice->setTextFormat(Qt::RichText);
    m_vault_notice->setWordWrap(true);
    m_vault_notice->setAccessibleName(tr("Immediate send status"));
    m_vault_notice->setStyleSheet(QStringLiteral("QLabel { background: palette(alternate-base); color: palette(text); padding: 10px; border: 1px solid palette(mid); border-radius: 6px; }"));
    m_vault_notice->hide();

    m_vault_recovery_offer = new QWidget;
    m_vault_recovery_offer->setObjectName("vaultDelayedRecoveryOffer");
    auto* recovery_offer_layout = new QVBoxLayout(m_vault_recovery_offer);
    recovery_offer_layout->setContentsMargins(8, 0, 8, 4);
    recovery_offer_layout->setSpacing(3);
    m_vault_recovery_offer_button = new QPushButton(tr("Start Delayed Recovery…"), m_vault_recovery_offer);
    m_vault_recovery_offer_button->setObjectName("vaultDelayedRecoveryOfferButton");
    m_vault_recovery_offer_button->setMinimumHeight(32);
    m_vault_recovery_offer_button->setAccessibleDescription(tr("Leave standard Send and open the guided delayed-recovery flow. You will choose the exact stage next."));
    recovery_offer_layout->addWidget(m_vault_recovery_offer_button, 0, Qt::AlignLeft);
    m_vault_recovery_offer_availability = new QLabel(m_vault_recovery_offer);
    m_vault_recovery_offer_availability->setObjectName("vaultDelayedRecoveryOfferAvailability");
    m_vault_recovery_offer_availability->setWordWrap(true);
    recovery_offer_layout->addWidget(m_vault_recovery_offer_availability);
    m_vault_recovery_offer->hide();

    m_recovery_panel = new QFrame;
    m_recovery_panel->setObjectName("delayedRecoveryPanel");
    m_recovery_panel->setStyleSheet(QStringLiteral("QFrame#delayedRecoveryPanel { background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; }"));
    auto* recovery_layout = new QVBoxLayout(m_recovery_panel);
    recovery_layout->setSpacing(8);
    auto* recovery_header = new QHBoxLayout;
    auto* recovery_title = new QLabel(tr("Delayed recovery"));
    recovery_title->setObjectName("delayedRecoveryTitle");
    QFont title_font = recovery_title->font();
    title_font.setBold(true);
    title_font.setPointSize(title_font.pointSize() + 2);
    recovery_title->setFont(title_font);
    auto* cancel_recovery = new QPushButton(tr("Cancel Recovery"));
    cancel_recovery->setObjectName("cancelDelayedRecoveryButton");
    cancel_recovery->setAccessibleDescription(tr("Discard this recovery draft and return to the standard immediate send form."));
    cancel_recovery->setMinimumHeight(32);
    recovery_header->addWidget(recovery_title);
    recovery_header->addStretch();
    recovery_header->addWidget(cancel_recovery);
    recovery_layout->addLayout(recovery_header);

    auto* recovery_intro = new QLabel(tr("Choose one policy stage. The wallet will not choose a lower-signature stage for you."));
    recovery_intro->setObjectName("delayedRecoveryIntroduction");
    recovery_intro->setWordWrap(true);
    recovery_layout->addWidget(recovery_intro);

    auto* stages = new QWidget;
    stages->setObjectName("delayedRecoveryStages");
    m_recovery_stages_layout = new QVBoxLayout(stages);
    m_recovery_stages_layout->setContentsMargins(0, 0, 0, 0);
    m_recovery_stages_layout->setSpacing(6);
    m_recovery_stage_group = new QButtonGroup(this);
    m_recovery_stage_group->setExclusive(true);
    recovery_layout->addWidget(stages);

    m_recovery_selection_detail = new QLabel;
    m_recovery_selection_detail->setObjectName("delayedRecoverySelectionDetail");
    m_recovery_selection_detail->setWordWrap(true);
    m_recovery_selection_detail->setAccessibleName(tr("Selected recovery stage details"));
    recovery_layout->addWidget(m_recovery_selection_detail);

    auto* change_warning = new QLabel(tr("The full eligible balance is entered by default. If you reduce it, change may be created. Relative recovery clocks restart on every change output; when a signer is lost, sweep to a newly secured vault."));
    change_warning->setObjectName("delayedRecoveryChangeWarning");
    change_warning->setWordWrap(true);
    change_warning->setAccessibleName(tr("Recovery change warning"));
    recovery_layout->addWidget(change_warning);
    m_recovery_panel->hide();

    const int recipient_row = ui->verticalLayout->indexOf(ui->scrollArea);
    ui->verticalLayout->insertWidget(recipient_row, m_vault_notice);
    ui->verticalLayout->insertWidget(recipient_row + 1, m_vault_recovery_offer);
    ui->verticalLayout->insertWidget(recipient_row + 2, m_recovery_panel);
    connect(m_vault_recovery_offer_button, &QPushButton::clicked, this, &SendCoinsDialog::startDelayedRecovery);
    connect(cancel_recovery, &QPushButton::clicked, this, &SendCoinsDialog::cancelDelayedRecovery);
    connect(m_recovery_stage_group, &QButtonGroup::idClicked, this, &SendCoinsDialog::selectRecoveryStage);
}

void SendCoinsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        // Block-tip notifications can arrive while validation still holds
        // chain and mempool locks. Fee/vault refreshes acquire wallet locks,
        // so defer the UI work until the notification stack has unwound.
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &SendCoinsDialog::updateNumberOfBlocks, Qt::QueuedConnection);
    }
}

void SendCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        for(int i = 0; i < ui->entries->count(); ++i)
        {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if(entry)
            {
                entry->setModel(_model);
            }
        }

        connect(_model, &WalletModel::balanceChanged, this, &SendCoinsDialog::setBalance);
        connect(_model, &WalletModel::vaultSignerStatusChanged, this, [this] {
            updateVaultSendState();
        });
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::refreshBalance);
        refreshBalance();

        // Coin Control
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(_model->getOptionsModel(), &OptionsModel::coinControlFeaturesChanged, this, &SendCoinsDialog::coinControlFeatureChanged);
        ui->frameCoinControl->setVisible(_model->getOptionsModel()->getCoinControlFeatures());
        coinControlUpdateLabels();

        // fee section
        for (const int n : confTargets) {
            ui->confTargetSelector->addItem(tr("%1 (%2 blocks)").arg(GUIUtil::formatNiceTimeOffset(n*Params().GetConsensus().nPowTargetSpacing)).arg(n));
        }
        connect(ui->confTargetSelector, qOverload<int>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->confTargetSelector, qOverload<int>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::coinControlUpdateLabels);

        connect(ui->groupFee, &QButtonGroup::idClicked, this, &SendCoinsDialog::updateFeeSectionControls);
        connect(ui->groupFee, &QButtonGroup::idClicked, this, &SendCoinsDialog::coinControlUpdateLabels);

        connect(ui->customFee, &BitcoinAmountField::valueChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        CAmount requiredFee = model->wallet().getRequiredFee(1000);
        ui->customFee->SetMinValue(requiredFee);
        if (ui->customFee->value() < requiredFee) {
            ui->customFee->setValue(requiredFee);
        }
        ui->customFee->setSingleStep(requiredFee);
        updateFeeSectionControls();
        updateSmartFeeLabel();

        updateVaultSendState();
        _model->refreshVaultSignerStatus();
        refreshBalance();

        // set the smartfee-sliders default value (wallets default conf.target or last stored value)
        QSettings settings;
        if (settings.value("nSmartFeeSliderPosition").toInt() != 0) {
            // migrate nSmartFeeSliderPosition to nConfTarget
            // nConfTarget is available since 0.15 (replaced nSmartFeeSliderPosition)
            int nConfirmTarget = 25 - settings.value("nSmartFeeSliderPosition").toInt(); // 25 == old slider range
            settings.setValue("nConfTarget", nConfirmTarget);
            settings.remove("nSmartFeeSliderPosition");
        }
        if (settings.value("nConfTarget").toInt() == 0)
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(model->wallet().getConfirmTarget()));
        else
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(settings.value("nConfTarget").toInt()));
    }
}

SendCoinsDialog::~SendCoinsDialog()
{
    QSettings settings;
    settings.setValue("fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("nFeeRadio", ui->groupFee->checkedId());
    settings.setValue("nConfTarget", getConfTargetForIndex(ui->confTargetSelector->currentIndex()));
    settings.setValue("nTransactionFee", (qint64)ui->customFee->value());

    delete ui;
}

bool SendCoinsDialog::currentTransactionIsUnsignedForTest() const
{
    if (!m_current_transaction || !m_current_transaction->getWtx()) return false;
    const auto& inputs = m_current_transaction->getWtx()->vin;
    return !inputs.empty() && std::ranges::all_of(inputs, [](const auto& input) {
        return input.scriptSig.empty() && input.scriptWitness.IsNull();
    });
}

void SendCoinsDialog::startDelayedRecovery()
{
    if (!model || !model->getOptionsModel()) return;

    const auto status = model->vaultStatus();
    if (!status.is_vault) {
        Q_EMIT message(tr("Delayed recovery"),
                       tr("Delayed recovery is only available for a Recovery Vault."),
                       CClientUIInterface::MSG_WARNING);
        return;
    }

    // A recovery transaction has different input eligibility and amount
    // semantics. Begin with a clean draft instead of silently reinterpreting a
    // standard-send draft.
    clear();
    m_delayed_recovery = true;
    m_selected_recovery_stage = -1;
    m_recovery_amount_initialized = false;
    m_recovery_panel->show();
    ui->addButton->hide();
    ui->clearButton->setText(tr("Clear Recovery"));
    updateVaultSendState();
    refreshBalance();
    setupTabChain(nullptr);

    if (const auto buttons = m_recovery_stage_group->buttons(); !buttons.empty()) {
        buttons.front()->setFocus();
    }
}

void SendCoinsDialog::cancelDelayedRecovery()
{
    bool has_draft{false};
    for (int i = 0; i < ui->entries->count(); ++i) {
        if (auto* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget())) {
            has_draft |= !entry->isClear();
        }
    }
    if (has_draft && QMessageBox::question(
                         this,
                         tr("Cancel delayed recovery?"),
                         tr("This will discard the recovery destination and amount."),
                         QMessageBox::Cancel | QMessageBox::Discard,
                         QMessageBox::Cancel) != QMessageBox::Discard) {
        return;
    }
    clear();
}

const interfaces::Wallet::VaultStatus::VaultRecoveryStage* SendCoinsDialog::selectedRecoveryStage() const
{
    if (!m_delayed_recovery || m_selected_recovery_stage < 0 ||
        m_selected_recovery_stage >= static_cast<int>(m_vault_status.recovery_stages.size())) {
        return nullptr;
    }
    return &m_vault_status.recovery_stages[m_selected_recovery_stage];
}

void SendCoinsDialog::clearPreparedVaultContext()
{
    m_prepared_vault_policy_commitment.reset();
    m_prepared_delayed_recovery = false;
    m_prepared_recovery_stage = -1;
    m_prepared_recovery_nrequired = -1;
    m_prepared_recovery_older.reset();
    m_prepared_recovery_after.reset();
}

bool SendCoinsDialog::preparedVaultContextStillMatches() const
{
    if (!m_prepared_vault_policy_commitment) return true;
    if (!m_vault_status.is_vault ||
        m_vault_status.policy_commitment != *m_prepared_vault_policy_commitment ||
        m_delayed_recovery != m_prepared_delayed_recovery) {
        return false;
    }
    if (!m_prepared_delayed_recovery) return true;
    const auto* stage{selectedRecoveryStage()};
    return stage &&
           m_selected_recovery_stage == m_prepared_recovery_stage &&
           stage->nrequired == m_prepared_recovery_nrequired &&
           stage->older == m_prepared_recovery_older &&
           stage->after == m_prepared_recovery_after;
}

void SendCoinsDialog::selectRecoveryStage(int index)
{
    if (!m_delayed_recovery || index < 0 ||
        index >= static_cast<int>(m_vault_status.recovery_stages.size())) {
        return;
    }

    m_selected_recovery_stage = index;
    m_recovery_amount_initialized = false;
    updateCoinControlState();
    updateVaultSendState();
    refreshBalance();

    const auto* stage = selectedRecoveryStage();
    if (!stage || stage->recoverable_now <= 0 || m_recovery_amount_initialized) return;
    if (ui->entries->count() > 0) {
        if (auto* entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget())) {
            useAvailableBalance(entry);
            m_recovery_amount_initialized = true;
        }
    }
}

void SendCoinsDialog::rebuildRecoveryStages()
{
    if (!m_recovery_stages_layout || !m_recovery_stage_group || !model || !model->getOptionsModel()) return;

    const bool reuse = !m_vault_status.recovery_stages.empty() &&
                       m_recovery_stage_group->buttons().size() == static_cast<qsizetype>(m_vault_status.recovery_stages.size());
    if (reuse) {
        m_recovery_stage_group->setExclusive(false);
        for (auto* button : m_recovery_stage_group->buttons())
            button->setChecked(false);
        m_recovery_stage_group->setExclusive(true);
    } else {
        for (auto* button : m_recovery_stage_group->buttons()) {
            m_recovery_stage_group->removeButton(button);
        }
        while (QLayoutItem* item = m_recovery_stages_layout->takeAt(0)) {
            if (item->widget()) item->widget()->deleteLater();
            delete item;
        }
    }

    const BitcoinUnit unit = model->getOptionsModel()->getDisplayUnit();
    const int64_t spacing = Params().GetConsensus().nPowTargetSpacing;
    for (int index = 0; index < static_cast<int>(m_vault_status.recovery_stages.size()); ++index) {
        const auto& stage = m_vault_status.recovery_stages[index];
        const QString name = m_vault_status.recovery_stages.size() == 1 ? tr("Recovery stage") : index + 1 == static_cast<int>(m_vault_status.recovery_stages.size()) ? tr("Final recovery") :
                                                                                                                                                                        tr("Recovery stage %1").arg(index + 1);
        const QString quorum = stage.nrequired == 1 ? tr("Any 1 participant") : tr("Any %1 participants").arg(stage.nrequired);

        QString timing;
        QString technical;
        if (stage.older) {
            timing = tr("About %1").arg(GUIUtil::formatNiceTimeOffset(int64_t{*stage.older} * spacing));
            technical = tr("Technical: %1-block relative delay").arg(*stage.older);
        } else if (stage.after) {
            if (stage.earliest_blocks_remaining && *stage.earliest_blocks_remaining > 0) {
                timing = tr("About %1").arg(GUIUtil::formatNiceTimeOffset(int64_t{*stage.earliest_blocks_remaining} * spacing));
            } else {
                timing = tr("Eligible now");
            }
            technical = tr("Technical: absolute block %1").arg(*stage.after);
        } else {
            timing = tr("No delay");
            technical = tr("Technical: no timelock");
        }

        QString maturity;
        if (stage.earliest_blocks_remaining && *stage.earliest_blocks_remaining > 0) {
            maturity = tr(" · next eligibility in about %1 (%2 blocks)")
                           .arg(GUIUtil::formatNiceTimeOffset(int64_t{*stage.earliest_blocks_remaining} * spacing))
                           .arg(*stage.earliest_blocks_remaining);
        }
        const QString amounts = tr("Eligible now: %1 · Awaiting: %2")
                                    .arg(BitcoinUnits::formatWithUnit(unit, stage.recoverable_now),
                                         BitcoinUnits::formatWithUnit(unit, stage.awaiting_maturity));
        if (reuse) {
            auto* option = qobject_cast<QRadioButton*>(m_recovery_stage_group->button(index));
            if (!option) continue;
            option->setText(QStringLiteral("%1 · %2 · %3").arg(name, quorum, timing));
            option->setAccessibleName(name);
            option->setAccessibleDescription(
                tr("%1. %2. %3. No recovery stage is selected automatically.")
                    .arg(quorum, timing, amounts));
            if (auto* amounts_label = option->parentWidget()->findChild<QLabel*>(
                    QStringLiteral("delayedRecoveryStage%1Amounts").arg(index + 1))) {
                amounts_label->setText(amounts);
            }
            if (auto* technical_label = option->parentWidget()->findChild<QLabel*>(
                    QStringLiteral("delayedRecoveryStage%1Technical").arg(index + 1))) {
                technical_label->setText(technical + maturity);
            }
            option->setChecked(index == m_selected_recovery_stage);
            continue;
        }
        auto* stage_card = new QFrame;
        stage_card->setObjectName(QStringLiteral("delayedRecoveryStage%1Card").arg(index + 1));
        stage_card->setFrameShape(QFrame::StyledPanel);
        auto* stage_layout = new QVBoxLayout(stage_card);
        stage_layout->setContentsMargins(10, 8, 10, 8);
        auto* option = new QRadioButton(QStringLiteral("%1 · %2 · %3").arg(name, quorum, timing), stage_card);
        option->setObjectName(QStringLiteral("delayedRecoveryStage%1Button").arg(index + 1));
        option->setAccessibleName(name);
        option->setAccessibleDescription(
            tr("%1. %2. %3. No recovery stage is selected automatically.")
                .arg(quorum, timing, amounts));
        option->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        option->setMinimumHeight(30);
        m_recovery_stage_group->addButton(option, index);
        stage_layout->addWidget(option);
        auto* amounts_label = new QLabel(amounts, stage_card);
        amounts_label->setObjectName(QStringLiteral("delayedRecoveryStage%1Amounts").arg(index + 1));
        amounts_label->setWordWrap(true);
        stage_layout->addWidget(amounts_label);
        auto* technical_label = new QLabel(technical + maturity, stage_card);
        technical_label->setObjectName(QStringLiteral("delayedRecoveryStage%1Technical").arg(index + 1));
        technical_label->setWordWrap(true);
        auto* technical_disclosure = new QPushButton(tr("Technical Details"), stage_card);
        technical_disclosure->setObjectName(QStringLiteral("delayedRecoveryStage%1TechnicalButton").arg(index + 1));
        technical_disclosure->setCheckable(true);
        technical_disclosure->setFlat(true);
        technical_disclosure->setMinimumHeight(30);
        technical_disclosure->setAccessibleDescription(tr("Show exact block-based timing for this recovery stage."));
        stage_layout->addWidget(technical_disclosure, 0, Qt::AlignLeft);
        stage_layout->addWidget(technical_label);
        technical_label->hide();
        connect(technical_disclosure, &QPushButton::toggled, technical_label, &QLabel::setVisible);
        m_recovery_stages_layout->addWidget(stage_card);
        if (index == m_selected_recovery_stage) option->setChecked(true);
    }

    if (m_vault_status.recovery_stages.empty()) {
        auto* empty = new QLabel(tr("This vault policy has no delayed recovery stage."));
        empty->setObjectName("delayedRecoveryNoStages");
        empty->setWordWrap(true);
        m_recovery_stages_layout->addWidget(empty);
    }
}

bool SendCoinsDialog::PrepareSendText(QString& question_string, QString& informative_text, QString& detailed_text)
{
    QList<SendCoinsRecipient> recipients;
    bool valid = true;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            if(entry->validate(model->node()))
            {
                recipients.append(entry->getValue());
            }
            else if (valid)
            {
                ui->scrollArea->ensureWidgetVisible(entry);
                valid = false;
            }
        }
    }

    if(!valid || recipients.isEmpty())
    {
        return false;
    }

    fNewRecipientAllowed = false;
    clearPreparedVaultContext();
    if (m_vault_status.is_vault) {
        if (m_vault_status.policy_commitment.empty()) {
            fNewRecipientAllowed = true;
            Q_EMIT message(
                tr("Send Coins"),
                tr("The active Recovery Vault policy could not be identified. Refresh the wallet and review a new transaction."),
                CClientUIInterface::MSG_WARNING);
            return false;
        }
        m_prepared_vault_policy_commitment = m_vault_status.policy_commitment;
        m_prepared_delayed_recovery = m_delayed_recovery;
        if (m_delayed_recovery) {
            const auto* stage{selectedRecoveryStage()};
            if (!stage) {
                fNewRecipientAllowed = true;
                clearPreparedVaultContext();
                return false;
            }
            m_prepared_recovery_stage = m_selected_recovery_stage;
            m_prepared_recovery_nrequired = stage->nrequired;
            m_prepared_recovery_older = stage->older;
            m_prepared_recovery_after = stage->after;
        }
    }
    // prepare transaction for getting txFee earlier
    m_current_transaction = std::make_unique<WalletModelTransaction>(recipients);
    WalletModel::SendCoinsReturn prepareStatus;

    updateCoinControlState();

    CCoinControl coin_control = *m_coin_control;
    coin_control.m_allow_other_inputs = !coin_control.HasSelected(); // future, could introduce a checkbox to customize this value.
    // Every vault must reach the review surface without invoking any signer.
    // Participant state can change while the confirmation dialog is open, so
    // direct signing happens only after the post-confirmation durable-state
    // check. Ordinary wallets retain their existing prepare-time behavior.
    m_sign_during_prepare = !m_vault_status.is_vault;
    if (m_sign_during_prepare) {
        WalletModel::UnlockContext ctx(model->requestUnlock());
        if (!ctx.isValid()) {
            fNewRecipientAllowed = true;
            return false;
        }
        prepareStatus = model->prepareTransaction(
            *m_current_transaction, coin_control, /*sign_during_prepare=*/true,
            m_prepared_vault_policy_commitment);
    } else {
        prepareStatus = model->prepareTransaction(
            *m_current_transaction, coin_control, /*sign_during_prepare=*/false,
            m_prepared_vault_policy_commitment);
    }

    // process prepareStatus and on error generate message shown to user
    processSendCoinsReturn(prepareStatus,
        BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), m_current_transaction->getTransactionFee()));

    if(prepareStatus.status != WalletModel::OK) {
        fNewRecipientAllowed = true;
        clearPreparedVaultContext();
        return false;
    }

    CAmount txFee = m_current_transaction->getTransactionFee();
    QStringList formatted;
    for (const SendCoinsRecipient &rcp : m_current_transaction->getRecipients())
    {
        // generate amount string with wallet name in case of multiwallet
        QString amount = BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
        if (model->isMultiwallet()) {
            amount = tr("%1 from wallet '%2'").arg(amount, GUIUtil::HtmlEscape(model->getWalletName()));
        }

        // generate address string
        QString address = rcp.address;

        QString recipientElement;

        {
            if(rcp.label.length() > 0) // label with address
            {
                recipientElement.append(tr("%1 to '%2'").arg(amount, GUIUtil::HtmlEscape(rcp.label)));
                recipientElement.append(QString(" (%1)").arg(address));
            }
            else // just address
            {
                recipientElement.append(tr("%1 to %2").arg(amount, address));
            }
        }
        formatted.append(recipientElement);
    }

    /*: Message displayed when attempting to create a transaction. Cautionary text to prompt the user to verify
        that the displayed transaction details represent the transaction the user intends to create. */
    question_string.append(tr("Do you want to create this transaction?"));
    if (m_delayed_recovery) {
        question_string.append("<br /><span style='font-size:10pt;'>");
        const auto* stage = selectedRecoveryStage();
        if (!stage) return false;
        const QString quorum = stage->nrequired == 1 ? tr("any 1 participant") : tr("any %1 participants").arg(stage->nrequired);
        if (stage->older) {
            const int64_t delay_seconds = int64_t{*stage->older} * Params().GetConsensus().nPowTargetSpacing;
            question_string.append(tr("Delayed recovery: the selected stage requires %1 after about %2 of coin age. Any change is a new coin, so its relative recovery clock starts over. Prefer a full sweep to a newly secured vault if a signer is lost.")
                                       .arg(quorum, GUIUtil::formatNiceTimeOffset(delay_seconds)));
        } else if (stage->after) {
            question_string.append(tr("Delayed recovery: the selected stage is eligible now and requires %1. Prefer a full sweep to a newly secured vault if a signer is lost.")
                                       .arg(quorum));
        } else {
            question_string.append(tr("Delayed recovery: the selected stage requires %1. Prefer a full sweep to a newly secured vault if a signer is lost.").arg(quorum));
        }
        question_string.append("</span>");
    }
    question_string.append("<br /><span style='font-size:10pt;'>");
    if (model->wallet().privateKeysDisabled() && !model->wallet().hasExternalSigner()) {
        /*: Text to inform a user attempting to create a transaction of their current options. At this stage,
            a user can only create a PSBT. This string is displayed when private keys are disabled and an external
            signer is not available. */
        question_string.append(tr("Please, review your transaction proposal. This will produce a Partially Signed Bitcoin Transaction (PSBT) which you can save or copy and then sign with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(CLIENT_NAME));
    } else if (model->getOptionsModel()->getEnablePSBTControls()) {
        /*: Text to inform a user attempting to create a transaction of their current options. At this stage,
            a user can send their transaction or create a PSBT. This string is displayed when both private keys
            and PSBT controls are enabled. */
        question_string.append(tr("Please, review your transaction. You can create and send this transaction or create a Partially Signed Bitcoin Transaction (PSBT), which you can save or copy and then sign with, e.g., an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(CLIENT_NAME));
    } else {
        /*: Text to prompt a user to review the details of the transaction they are attempting to send. */
        question_string.append(tr("Please, review your transaction."));
    }
    question_string.append("</span>%1");

    if(txFee > 0)
    {
        // append fee string if a fee is required
        question_string.append("<hr /><b>");
        question_string.append(tr("Transaction fee"));
        question_string.append("</b>");

        // append transaction size
        //: When reviewing a newly created PSBT (via Send flow), the transaction fee is shown, with "virtual size" of the transaction displayed for context
        question_string.append(" (" + tr("%1 kvB", "PSBT transaction creation").arg((double)m_current_transaction->getTransactionSize() / 1000, 0, 'g', 3) + "): ");

        // append transaction fee value
        question_string.append("<span style='color:#aa0000; font-weight:bold;'>");
        question_string.append(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee));
        question_string.append("</span><br />");
    }

    // append RBF message
    question_string.append("<span style='font-size:10pt; font-weight:normal;'>");
    question_string.append(tr("You can increase the fee later."));

    // add total amount in all subdivision units
    question_string.append("<hr />");
    CAmount totalAmount = m_current_transaction->getTotalTransactionAmount() + txFee;
    QStringList alternativeUnits;
    for (const BitcoinUnit u : BitcoinUnits::availableUnits()) {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }
    question_string.append(QString("<b>%1</b>: <b>%2</b>").arg(tr("Total Amount"))
        .arg(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    question_string.append(QString("<br /><span style='font-size:10pt; font-weight:normal;'>(=%1)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + " ")));

    if (formatted.size() > 1) {
        question_string = question_string.arg("");
        informative_text = tr("To review recipient list click \"Show Details…\"");
        detailed_text = formatted.join("\n\n");
    } else {
        question_string = question_string.arg("<br /><br />" + formatted.at(0));
    }

    return true;
}

void SendCoinsDialog::presentPSBT(PartiallySignedTransaction& psbtx)
{
    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;
    GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
    QMessageBox msgBox(this);
    //: Caption of "PSBT has been copied" messagebox
    msgBox.setText(tr("Unsigned Transaction", "PSBT copied"));
    msgBox.setInformativeText(tr("The PSBT has been copied to the clipboard. You can also save it."));
    msgBox.setStandardButtons(QMessageBox::Save | QMessageBox::Discard);
    msgBox.setDefaultButton(QMessageBox::Discard);
    msgBox.setObjectName("psbt_copied_message");
    switch (msgBox.exec()) {
    case QMessageBox::Save: {
        QString selectedFilter;
        QString fileNameSuggestion = "";
        bool first = true;
        for (const SendCoinsRecipient &rcp : m_current_transaction->getRecipients()) {
            if (!first) {
                fileNameSuggestion.append(" - ");
            }
            QString labelOrAddress = rcp.label.isEmpty() ? rcp.address : rcp.label;
            QString amount = BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
            fileNameSuggestion.append(labelOrAddress + "-" + amount);
            first = false;
        }
        fileNameSuggestion.append(".psbt");
        QString filename = GUIUtil::getSaveFileName(this,
            tr("Save Transaction Data"), fileNameSuggestion,
            //: Expanded name of the binary PSBT file format. See: BIP 174.
            tr("Partially Signed Transaction (Binary)") + QLatin1String(" (*.psbt)"), &selectedFilter);
        if (filename.isEmpty()) {
            return;
        }
        std::ofstream out{filename.toLocal8Bit().data(), std::ofstream::out | std::ofstream::binary};
        out << ssTx.str();
        out.close();
        //: Popup message when a PSBT has been saved to a file
        Q_EMIT message(tr("PSBT saved"), tr("PSBT saved to disk"), CClientUIInterface::MSG_INFORMATION);
        break;
    }
    case QMessageBox::Discard:
        break;
    default:
        assert(false);
    } // msgBox.exec()
}

bool SendCoinsDialog::signWithExternalSigner(
    PartiallySignedTransaction& psbtx,
    CMutableTransaction& mtx,
    bool& complete,
    std::optional<wallet::VaultCommitState>& signed_vault_state)
{
    std::optional<PSBTError> err;
    try {
        err = model->wallet().fillPSBT(
            {.sign = true,
             .bip32_derivs = true,
             .expected_vault_policy_commitment = m_prepared_vault_policy_commitment},
            /*n_signed=*/nullptr, psbtx, complete, &signed_vault_state);
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(nullptr, tr("Sign failed"), e.what());
        return false;
    }
    if (err == PSBTError::EXTERNAL_SIGNER_NOT_FOUND) {
        //: "External signer" means using devices such as hardware wallets.
        const QString msg = tr("External signer not found");
        QMessageBox::critical(nullptr, msg, msg);
        return false;
    }
    if (err == PSBTError::EXTERNAL_SIGNER_FAILED) {
        //: "External signer" means using devices such as hardware wallets.
        const QString msg = tr("External signer failure");
        QMessageBox::critical(nullptr, msg, msg);
        return false;
    }
    if (err == PSBTError::VAULT_POLICY_MISMATCH) {
        const QString msg = tr("The active Recovery Vault policy changed. The draft was not signed; review a new transaction.");
        QMessageBox::warning(this, tr("Recovery Vault changed"), msg);
        return false;
    }
    if (err) {
        qWarning() << "Failed to sign PSBT";
        processSendCoinsReturn(WalletModel::TransactionCreationFailed);
        return false;
    }
    // fillPSBT does not always properly finalize
    complete = FinalizeAndExtractPSBT(psbtx, mtx);
    return true;
}

void SendCoinsDialog::sendButtonClicked([[maybe_unused]] bool checked)
{
    if(!model || !model->getOptionsModel())
        return;

    // Recheck the local lost-signer state at action time so a stale view cannot
    // start an immediate spend.
    if (updateVaultSendState(/*fresh_persisted_state=*/true)) {
        Q_EMIT message(tr("Send Coins"),
                       m_vault_send_block_reason,
                       CClientUIInterface::MSG_WARNING);
        return;
    }

    QString question_string, informative_text, detailed_text;
    if (!PrepareSendText(question_string, informative_text, detailed_text)) return;
    assert(m_current_transaction);

    const QString confirmation = tr("Confirm send coins");
    const bool enable_send{m_vault_direct_send_available && (!model->wallet().privateKeysDisabled() || model->wallet().hasExternalSigner())};
    const bool always_show_unsigned{model->getOptionsModel()->getEnablePSBTControls() || !m_vault_direct_send_available};
    auto confirmationDialog = new SendConfirmationDialog(confirmation, question_string, informative_text, detailed_text, SEND_CONFIRM_DELAY, enable_send, always_show_unsigned, this);
    confirmationDialog->setAttribute(Qt::WA_DeleteOnClose);
    // TODO: Replace QDialog::exec() with safer QDialog::show().
    const auto retval = static_cast<QMessageBox::StandardButton>(confirmationDialog->exec());

    if(retval != QMessageBox::Yes && retval != QMessageBox::Save)
    {
        fNewRecipientAllowed = true;
        clearPreparedVaultContext();
        return;
    }

    // The modal confirmation runs a nested event loop. Recheck after the user
    // accepts so a signer marked lost while the dialog was open cannot slip an
    // already-prepared immediate transaction past the action-time guard above.
    const bool post_review_blocked{updateVaultSendState(/*fresh_persisted_state=*/true)};
    const bool prepared_context_changed{!preparedVaultContextStillMatches()};
    if (post_review_blocked || prepared_context_changed) {
        fNewRecipientAllowed = true;
        if (prepared_context_changed) {
            m_vault_send_block_reason = tr("The active Recovery Vault policy or recovery stage changed while this transaction was being reviewed. The draft was discarded; review a new transaction.");
            m_current_transaction.reset();
        }
        Q_EMIT message(tr("Send Coins"),
                       m_vault_send_block_reason,
                       CClientUIInterface::MSG_WARNING);
        clearPreparedVaultContext();
        return;
    }
    if (retval == QMessageBox::Yes && !m_vault_direct_send_available) {
        fNewRecipientAllowed = true;
        Q_EMIT message(tr("Send Coins"),
                       tr("Direct signing is no longer available for the required participants. Review the current participant status, or create an unsigned PSBT instead."),
                       CClientUIInterface::MSG_WARNING);
        clearPreparedVaultContext();
        return;
    }

    bool send_failure = false;
    std::optional<wallet::VaultCommitState> signed_vault_state;
    if (retval == QMessageBox::Save) {
        // "Create Unsigned" clicked
        CMutableTransaction mtx = CMutableTransaction{*(m_current_transaction->getWtx())};
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        // Fill without signing
        const auto err{model->wallet().fillPSBT(
            {.sign = false,
             .bip32_derivs = true,
             .expected_vault_policy_commitment = m_prepared_vault_policy_commitment},
            /*n_signed=*/nullptr, psbtx, complete)};
        if (err) {
            send_failure = true;
            const QString reason = *err == PSBTError::VAULT_POLICY_MISMATCH ? tr("The active Recovery Vault policy changed. The unsigned draft was discarded; review a new transaction.") : tr("The unsigned transaction could not be created.");
            Q_EMIT message(tr("Send Coins"), reason, CClientUIInterface::MSG_WARNING);
        } else {
            assert(!complete);
            // Copy PSBT to clipboard and offer to save
            presentPSBT(psbtx);
        }
    } else {
        // "Send" clicked
        assert(!model->wallet().privateKeysDisabled() || model->wallet().hasExternalSigner());
        bool broadcast = true;
        if (model->wallet().hasExternalSigner() || !m_sign_during_prepare) {
            CMutableTransaction mtx = CMutableTransaction{*(m_current_transaction->getWtx())};
            PartiallySignedTransaction psbtx(mtx);
            bool complete = false;
            // Always fill without signing first. This prevents an external signer
            // from being called prematurely and is not expensive.
            const auto err{model->wallet().fillPSBT(
                {.sign = false,
                 .bip32_derivs = true,
                 .expected_vault_policy_commitment = m_prepared_vault_policy_commitment},
                /*n_signed=*/nullptr, psbtx, complete)};
            if (err) {
                send_failure = true;
                const QString reason = *err == PSBTError::VAULT_POLICY_MISMATCH ? tr("The active Recovery Vault policy changed. The draft was discarded; review a new transaction.") : tr("The transaction could not be prepared for signing.");
                Q_EMIT message(tr("Send Coins"), reason, CClientUIInterface::MSG_WARNING);
            } else {
                assert(!complete);
            }
            if (!send_failure) {
                WalletModel::UnlockContext ctx(model->requestUnlock());
                if (!ctx.isValid()) {
                    send_failure = true;
                } else {
                    const bool final_state_blocked{updateVaultSendState(/*fresh_persisted_state=*/true)};
                    const bool final_context_changed{!preparedVaultContextStillMatches()};
                    if (final_state_blocked || final_context_changed || !m_vault_direct_send_available) {
                        send_failure = true;
                        if (final_context_changed) {
                            m_vault_send_block_reason = tr("The active Recovery Vault policy or recovery stage changed before signing. The draft was discarded; review a new transaction.");
                        }
                        const QString reason = !m_vault_send_block_reason.isEmpty() ? m_vault_send_block_reason : tr("Direct signing is no longer available for the required participants. Create an unsigned PSBT or review participant status before trying again.");
                        Q_EMIT message(tr("Send Coins"), reason, CClientUIInterface::MSG_WARNING);
                    } else {
                        send_failure = !signWithExternalSigner(
                            psbtx, mtx, complete, signed_vault_state);
                    }
                }
            }
            // Don't broadcast when user rejects it on the device or there's a failure:
            broadcast = complete && !send_failure;
            if (!send_failure) {
                // A transaction signed with an external signer is not always complete,
                // e.g. in a multisig wallet.
                if (complete) {
                    // Prepare transaction for broadcast transaction if complete
                    const CTransactionRef tx = MakeTransactionRef(mtx);
                    m_current_transaction->setWtx(tx);
                } else {
                    presentPSBT(psbtx);
                }
            }
        }

        // Broadcast the transaction, unless an external signer was used and it
        // failed, or more signatures are needed.
        if (broadcast) {
            // now send the prepared transaction
            if (!model->sendCoins(*m_current_transaction, signed_vault_state)) {
                send_failure = true;
                Q_EMIT message(
                    tr("Send Coins"),
                    tr("The Recovery Vault policy or participant loss state changed after signing. The transaction was not broadcast; review a new transaction."),
                    CClientUIInterface::MSG_WARNING);
            } else {
                Q_EMIT coinsSent(m_current_transaction->getWtx()->GetHash());
            }
        }
    }
    if (!send_failure) {
        accept();
        m_coin_control->UnSelectAll();
        coinControlUpdateLabels();
    }
    fNewRecipientAllowed = true;
    clearPreparedVaultContext();
    m_current_transaction.reset();
}

void SendCoinsDialog::clear()
{
    m_current_transaction.reset();

    // Clear coin control settings
    m_coin_control->UnSelectAll();
    m_delayed_recovery = false;
    m_selected_recovery_stage = -1;
    m_recovery_amount_initialized = false;
    m_sign_during_prepare = true;
    clearPreparedVaultContext();
    if (m_recovery_panel) m_recovery_panel->hide();
    ui->addButton->show();
    ui->clearButton->setText(tr("Clear All"));
    ui->checkBoxCoinControlChange->setChecked(false);
    ui->lineEditCoinControlChange->clear();
    coinControlUpdateLabels();

    // Remove entries until only one left
    while(ui->entries->count())
    {
        ui->entries->takeAt(0)->widget()->deleteLater();
    }
    addEntry();

    updateTabsAndLabels();
    if (model) {
        updateVaultSendState();
        refreshBalance();
    }
}

void SendCoinsDialog::reject()
{
    clear();
}

void SendCoinsDialog::accept()
{
    clear();
}

SendCoinsEntry *SendCoinsDialog::addEntry()
{
    SendCoinsEntry *entry = new SendCoinsEntry(platformStyle, this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, &SendCoinsEntry::removeEntry, this, &SendCoinsDialog::removeEntry);
    connect(entry, &SendCoinsEntry::useAvailableBalance, this, &SendCoinsDialog::useAvailableBalance);
    connect(entry, &SendCoinsEntry::payAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
    connect(entry, &SendCoinsEntry::subtractFeeFromAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());

    // Scroll to the newly added entry on a QueuedConnection because Qt doesn't
    // adjust the scroll area and scrollbar immediately when the widget is added.
    // Invoking on a DirectConnection will only scroll to the second-to-last entry.
    QMetaObject::invokeMethod(ui->scrollArea, [this] {
        if (ui->scrollArea->verticalScrollBar()) {
            ui->scrollArea->verticalScrollBar()->setValue(ui->scrollArea->verticalScrollBar()->maximum());
        }
    }, Qt::QueuedConnection);

    updateTabsAndLabels();
    return entry;
}

void SendCoinsDialog::updateTabsAndLabels()
{
    setupTabChain(nullptr);
    coinControlUpdateLabels();
}

void SendCoinsDialog::removeEntry(SendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

QWidget *SendCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    if (m_delayed_recovery) {
        for (auto* button : m_recovery_stage_group->buttons()) {
            if (prev) QWidget::setTabOrder(prev, button);
            prev = button;
        }
    }
    if (prev) QWidget::setTabOrder(prev, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return ui->addButton;
}

void SendCoinsDialog::setAddress(const QString &address)
{
    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setAddress(address);
}

void SendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
    updateTabsAndLabels();
}

bool SendCoinsDialog::handlePaymentRequest(const SendCoinsRecipient &rv)
{
    // Just paste the entry, all pre-checks
    // are done in paymentserver.cpp.
    pasteEntry(rv);
    return true;
}

void SendCoinsDialog::setBalance(const interfaces::WalletBalances& balances)
{
    if(model && model->getOptionsModel())
    {
        CAmount balance = balances.balance;
        if (model->wallet().hasExternalSigner()) {
            ui->labelBalanceName->setText(tr("External balance:"));
        }
        if (balances.is_vault) {
            // Refresh the cheap policy/maturity snapshot immediately and let
            // WalletModel discover hardware in the background.
            model->refreshVaultSignerStatus();
            balance = balances.vault_immediate;
            if (m_delayed_recovery) {
                if (const auto* stage = selectedRecoveryStage()) {
                    balance = stage->recoverable_now;
                    ui->labelBalanceName->setText(tr("Eligible at selected stage:"));
                } else {
                    ui->labelBalanceName->setText(tr("Select a recovery stage:"));
                    ui->labelBalance->setText(QStringLiteral("—"));
                    updateVaultSendState();
                    return;
                }
            } else {
                ui->labelBalanceName->setText(tr("Available for immediate send:"));
            }
        }
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balance));
        updateVaultSendState();
    }
}

void SendCoinsDialog::refreshBalance()
{
    setBalance(model->wallet().getBalances());
    ui->customFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    updateSmartFeeLabel();
}

void SendCoinsDialog::processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // All status values are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::DuplicateAddress:
        msgParams.first = tr("Duplicate address found: addresses should only be used once each.");
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), model->wallet().getDefaultMaxTxFee()));
        break;
    case WalletModel::OK:
        return;
    } // no default case, so the compiler can warn about missing cases
    Q_EMIT message(tr("Send Coins"), msgParams.first, msgParams.second);
}

void SendCoinsDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void SendCoinsDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void SendCoinsDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void SendCoinsDialog::useAvailableBalance(SendCoinsEntry* entry)
{
    // Same behavior as send: if we have selected coins, only obtain their available balance.
    // Copy to avoid modifying the member's data.
    CCoinControl coin_control = *m_coin_control;
    coin_control.m_allow_other_inputs = !coin_control.HasSelected();

    // A recovery stage exposes only coins mature for that exact script path.
    // The wallet's ordinary cached balance also includes awaiting coins, so it
    // must never drive the recovery sweep default.
    const auto* recovery_stage = selectedRecoveryStage();
    CAmount amount = recovery_stage && !coin_control.HasSelected() ? recovery_stage->recoverable_now : model->getAvailableBalance(&coin_control);
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* e = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (e && !e->isHidden() && e != entry) {
            amount -= e->getValue().amount;
        }
    }

    if (amount > 0) {
      entry->checkSubtractFeeFromAmount();
      entry->setAmount(amount);
    } else {
      entry->setAmount(0);
    }
}

void SendCoinsDialog::updateFeeSectionControls()
{
    ui->confTargetSelector      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee           ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee2          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee3          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelFeeEstimation      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelCustomFeeWarning   ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelCustomPerKilobyte  ->setEnabled(ui->radioCustomFee->isChecked());
    ui->customFee               ->setEnabled(ui->radioCustomFee->isChecked());
}

void SendCoinsDialog::updateFeeMinimizedLabel()
{
    if(!model || !model->getOptionsModel())
        return;

    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(tr("%1/kvB").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), ui->customFee->value())));
    }
}

namespace {
QString LostSignerLabel(const std::string& fingerprint)
{
    const QString hex = QString::fromStdString(fingerprint);
    return QObject::tr("Participant (%1)").arg(hex);
}

bool SameParticipantIdentity(const interfaces::Wallet::VaultStatus::VaultParticipant& first,
                             const interfaces::Wallet::VaultStatus::VaultParticipant& second)
{
    return first.fingerprint == second.fingerprint && first.path == second.path && first.xpub == second.xpub;
}

interfaces::Wallet::VaultStatus MergeVaultDiscoveryEvidence(
    interfaces::Wallet::VaultStatus persisted,
    const interfaces::Wallet::VaultStatus& observed)
{
    using Availability = interfaces::Wallet::VaultSignerAvailability;
    using ParticipantType = interfaces::Wallet::VaultParticipantType;

    if (persisted.participants.size() != observed.participants.size()) return persisted;
    for (const auto& participant : persisted.participants) {
        if (std::ranges::none_of(observed.participants, [&](const auto& item) {
                return SameParticipantIdentity(participant, item);
            })) {
            return persisted;
        }
    }

    // Durable wallet state wins. Retain only runtime discovery evidence tied
    // to the exact same participant roster, and never let it override a fresh
    // persisted loss or participant-type decision.
    persisted.signer_discovery_complete = observed.signer_discovery_complete;
    for (auto& participant : persisted.participants) {
        const auto evidence = std::ranges::find_if(observed.participants, [&](const auto& item) {
            return SameParticipantIdentity(participant, item);
        });
        if (evidence == observed.participants.end() || participant.is_lost || evidence->is_lost ||
            participant.type == ParticipantType::LOCAL_SOFTWARE || participant.type == ParticipantType::AIR_GAPPED) {
            continue;
        }
        if (evidence->type == ParticipantType::HARDWARE && evidence->availability == Availability::AVAILABLE) {
            participant.type = ParticipantType::HARDWARE;
            participant.availability = Availability::AVAILABLE;
        } else if (observed.signer_discovery_complete && evidence->type == ParticipantType::HARDWARE) {
            participant.type = ParticipantType::HARDWARE;
            participant.availability = evidence->availability;
        }
    }
    return persisted;
}
} // namespace

bool SendCoinsDialog::updateVaultSendState(bool fresh_persisted_state)
{
    if (!model || !model->getOptionsModel()) return false;
    bool persisted_state_failed{false};
    const auto observed_status = model->vaultStatus();
    if (fresh_persisted_state) {
        try {
            m_vault_status = MergeVaultDiscoveryEvidence(model->wallet().getVaultStatus(), observed_status);
        } catch (const std::exception&) {
            m_vault_status = observed_status;
            persisted_state_failed = true;
        } catch (...) {
            m_vault_status = observed_status;
            persisted_state_failed = true;
        }
    } else {
        m_vault_status = observed_status;
    }
    const bool vault = m_vault_status.is_vault;
    if (!vault && m_delayed_recovery) {
        m_delayed_recovery = false;
        m_selected_recovery_stage = -1;
    }
    m_recovery_panel->setVisible(vault && m_delayed_recovery);
    ui->addButton->setVisible(!m_delayed_recovery);

    if (m_delayed_recovery) rebuildRecoveryStages();
    const auto* selected_stage = selectedRecoveryStage();
    if (m_recovery_selection_detail) {
        if (!selected_stage) {
            m_recovery_selection_detail->setText(tr("Select the exact policy stage to continue."));
        } else if (selected_stage->recoverable_now <= 0) {
            if (selected_stage->earliest_blocks_remaining) {
                const int64_t seconds = int64_t{*selected_stage->earliest_blocks_remaining} * Params().GetConsensus().nPowTargetSpacing;
                m_recovery_selection_detail->setText(
                    tr("Nothing is eligible at this stage yet. Next eligibility is expected in about %1.")
                        .arg(GUIUtil::formatNiceTimeOffset(seconds)));
            } else {
                m_recovery_selection_detail->setText(tr("Nothing is eligible at this stage yet."));
            }
        } else {
            m_recovery_selection_detail->setText(
                tr("The full eligible balance, %1, is entered below by default.")
                    .arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), selected_stage->recoverable_now)));
        }
    }

    const auto marker_is_in_current_roster = [&](const std::string& fingerprint) {
        return std::ranges::any_of(m_vault_status.participants, [&](const auto& participant) {
            return participant.fingerprint == fingerprint;
        });
    };
    std::vector<std::string> relevant_manually_lost;
    if (vault && !m_vault_status.is_fixed_staged_vault) {
        // Advanced/custom policies do not expose the fixed consumer roster.
        // Preserve their conservative legacy semantics: a policy-bound manual
        // loss is relevant even when it cannot be mapped to a participant row.
        relevant_manually_lost = m_vault_status.manually_lost_signers;
    } else {
        std::ranges::copy_if(m_vault_status.manually_lost_signers,
                             std::back_inserter(relevant_manually_lost),
                             marker_is_in_current_roster);
    }
    const bool relevant_lost_marker = vault && !m_vault_status.is_fixed_staged_vault ? !m_vault_status.lost_signers.empty() : std::ranges::any_of(m_vault_status.lost_signers, marker_is_in_current_roster);
    const bool hardware_not_available = std::ranges::any_of(m_vault_status.participants, [](const auto& participant) {
        return participant.type == interfaces::Wallet::VaultParticipantType::HARDWARE &&
               participant.availability != interfaces::Wallet::VaultSignerAvailability::AVAILABLE;
    });
    const bool unavailable_marker = vault && (relevant_lost_marker || hardware_not_available);
    const bool manually_lost = vault && !relevant_manually_lost.empty();
    if (m_vault_notice) {
        m_vault_notice->setVisible(vault && !m_delayed_recovery);
        if (m_vault_status.genesis_rescan_required) {
            const QString title = tr("Vault scan incomplete");
            const QString action = tr("Sending is unavailable until the required scan from the genesis block completes. Return to the Recovery Vault dashboard to retry.");
            m_vault_notice->setText(QStringLiteral("<b>%1</b><br>%2").arg(GUIUtil::HtmlEscape(title), GUIUtil::HtmlEscape(action)));
            m_vault_notice->setAccessibleDescription(title + QStringLiteral(". ") + action);
        } else if (manually_lost) {
            QStringList names;
            for (const auto& fpr : relevant_manually_lost) {
                names << LostSignerLabel(fpr);
            }
            const bool one = names.size() == 1;
            const QString title = (one ? tr("Participant marked lost: %1") : tr("Participants marked lost: %1")).arg(names.join(QStringLiteral(", ")));
            const QString action = one ? tr("The immediate path needs every participant. Manage this participant or begin delayed recovery from the Recovery Vault dashboard.") : tr("The immediate path needs every participant. Manage them or begin delayed recovery from the Recovery Vault dashboard.");
            m_vault_notice->setText(QStringLiteral("<b>%1</b><br>%2").arg(GUIUtil::HtmlEscape(title), GUIUtil::HtmlEscape(action)));
            m_vault_notice->setAccessibleDescription(title + QStringLiteral(". ") + action);
        } else if (unavailable_marker) {
            const QString title = m_vault_status.signer_discovery_complete ? tr("Participant unavailable") : tr("Participant availability unknown");
            const QString detail = m_vault_status.signer_discovery_complete ? tr("A restored or external participant was not found. Immediate direct signing is unavailable, but you can still review and create an unsigned PSBT.") : tr("Signer discovery has not completed successfully. Availability remains unknown; you can still review and create an unsigned PSBT.");
            m_vault_notice->setText(QStringLiteral("<b>%1</b><br>%2").arg(GUIUtil::HtmlEscape(title), GUIUtil::HtmlEscape(detail)));
            m_vault_notice->setAccessibleDescription(title + QStringLiteral(". ") + detail);
        } else {
            const int participants = static_cast<int>(m_vault_status.participants.size());
            const QString title = participants > 0 ? tr("Immediate spend · all %1 participants required").arg(participants) : tr("Immediate spend · every participant required");
            const QString detail = tr("This standard Send screen only uses the immediate path. Delayed recovery starts from the Recovery Vault dashboard.");
            m_vault_notice->setText(QStringLiteral("<b>%1</b><br>%2").arg(GUIUtil::HtmlEscape(title), GUIUtil::HtmlEscape(detail)));
            m_vault_notice->setAccessibleDescription(title + QStringLiteral(". ") + detail);
        }
    }

    const bool recovery_eligible = std::ranges::any_of(m_vault_status.recovery_stages, [](const auto& stage) {
        return stage.recoverable_now > 0;
    });
    std::optional<int> earliest_recovery;
    for (const auto& stage : m_vault_status.recovery_stages) {
        if (stage.earliest_blocks_remaining &&
            (!earliest_recovery || *stage.earliest_blocks_remaining < *earliest_recovery)) {
            earliest_recovery = stage.earliest_blocks_remaining;
        }
    }
    const bool immediate_signer_unavailable = manually_lost || std::ranges::any_of(m_vault_status.participants, [](const auto& participant) {
                                                  switch (participant.type) {
                                                  case interfaces::Wallet::VaultParticipantType::LOCAL_SOFTWARE:
                                                      return participant.is_lost;
                                                  case interfaces::Wallet::VaultParticipantType::HARDWARE:
                                                      return participant.availability != interfaces::Wallet::VaultSignerAvailability::AVAILABLE;
                                                  case interfaces::Wallet::VaultParticipantType::AIR_GAPPED:
                                                  case interfaces::Wallet::VaultParticipantType::UNKNOWN:
                                                      return true;
                                                  }
                                                  return true;
                                              });
    const bool show_recovery_offer = immediate_signer_unavailable && !m_delayed_recovery && !m_vault_status.genesis_rescan_required;
    m_vault_recovery_offer->setVisible(show_recovery_offer);
    m_vault_recovery_offer_button->setEnabled(recovery_eligible);
    if (recovery_eligible) {
        m_vault_recovery_offer_availability->setText(tr("Recovery is eligible now. You will choose the exact policy stage next."));
    } else if (earliest_recovery) {
        m_vault_recovery_offer_availability->setText(tr("Delayed recovery is expected in about %1.")
                                                         .arg(GUIUtil::formatNiceTimeOffset(int64_t{*earliest_recovery} * Params().GetConsensus().nPowTargetSpacing)));
    } else {
        m_vault_recovery_offer_availability->setText(tr("No delayed-recovery funds are currently eligible."));
    }

    ui->sendButton->setText(tr("Review Transaction"));
    m_vault_direct_send_available = true;
    if (model->wallet().hasExternalSigner()) {
        if (model->getOptionsModel()->hasSigner(m_vault_status.is_fixed_staged_vault)) {
            ui->sendButton->setToolTip(tr("Review the transaction before signing on a hardware device."));
        } else {
            m_vault_direct_send_available = false;
            ui->sendButton->setToolTip(tr("Review the transaction and create an unsigned PSBT. Configure the external signer to sign directly."));
        }
    } else if (model->wallet().privateKeysDisabled()) {
        m_vault_direct_send_available = false;
        ui->sendButton->setToolTip(tr("Review the transaction before creating a Partially Signed Bitcoin Transaction (PSBT)."));
    } else {
        ui->sendButton->setToolTip(tr("Review recipients, fees, and signing options."));
    }
    if (vault && !m_vault_status.participants.empty()) {
        int directly_available{0};
        for (const auto& participant : m_vault_status.participants) {
            if (participant.is_lost) continue;
            if (participant.type == interfaces::Wallet::VaultParticipantType::LOCAL_SOFTWARE ||
                (participant.type == interfaces::Wallet::VaultParticipantType::HARDWARE &&
                 participant.availability == interfaces::Wallet::VaultSignerAvailability::AVAILABLE)) {
                ++directly_available;
            }
        }
        const int required = m_delayed_recovery && selected_stage ? selected_stage->nrequired : static_cast<int>(m_vault_status.participants.size());
        m_vault_direct_send_available = directly_available >= required;
        if (!m_vault_direct_send_available) {
            ui->sendButton->setToolTip(tr("Direct signing is not currently available for the required participants. You can still review and create an unsigned PSBT."));
        } else {
            ui->sendButton->setToolTip(tr("Review the transaction before signing with the available participants."));
        }
    }
    if (manually_lost && (!m_delayed_recovery || !m_vault_status.is_fixed_staged_vault)) {
        // The wallet signing backend may know keys or enumerate devices beyond
        // the immediate quorum. Never let a normal direct-send action contact
        // a participant the user deliberately marked lost. A selected mature
        // recovery branch may still sign with a sufficient trusted subset;
        // the backend strips the lost participant from both local and exact
        // hardware signing.
        m_vault_direct_send_available = false;
        ui->sendButton->setToolTip(m_vault_status.is_fixed_staged_vault ? tr("A participant is marked lost. Begin delayed recovery from the Recovery Vault dashboard.") : tr("A participant is marked lost in this advanced vault. Review and create an unsigned PSBT for the remaining trusted participants."));
    }

    m_vault_send_block_reason.clear();
    if (persisted_state_failed) {
        m_vault_send_block_reason = tr("The wallet could not refresh its persisted vault state. Sending was stopped so a stale participant status cannot be used.");
    } else if (m_vault_status.genesis_rescan_required) {
        m_vault_send_block_reason = tr("This restored vault must complete its blockchain rescan from genesis before funds can be sent.");
    } else if (!m_delayed_recovery && manually_lost) {
        m_vault_send_block_reason = tr("Immediate send needs every vault participant. A participant is marked lost; manage participants or begin delayed recovery from the Recovery Vault dashboard.");
    } else if (m_delayed_recovery && !selected_stage) {
        m_vault_send_block_reason = tr("Choose a recovery stage before reviewing. The wallet will not select a lower-signature stage automatically.");
    } else if (m_delayed_recovery && selected_stage && selected_stage->recoverable_now == 0) {
        if (selected_stage->earliest_blocks_remaining) {
            const int64_t seconds = int64_t{*selected_stage->earliest_blocks_remaining} * Params().GetConsensus().nPowTargetSpacing;
            m_vault_send_block_reason = tr("This stage is expected to become eligible in about %1.")
                                            .arg(GUIUtil::formatNiceTimeOffset(seconds));
        } else {
            m_vault_send_block_reason = tr("This recovery stage has no eligible funds yet.");
        }
    }
    const bool blocked = !m_vault_send_block_reason.isEmpty();
    ui->sendButton->setEnabled(!blocked);
    if (blocked) ui->sendButton->setToolTip(m_vault_send_block_reason);
    return blocked;
}

void SendCoinsDialog::updateCoinControlState()
{
    if (ui->radioCustomFee->isChecked()) {
        m_coin_control->m_feerate = CFeeRate(ui->customFee->value());
    } else {
        m_coin_control->m_feerate.reset();
    }
    // Avoid using global defaults when sending money from the GUI
    // Either custom fee will be used or if not selected, the confirmation target from dropdown box
    m_coin_control->m_confirm_target = getConfTargetForIndex(ui->confTargetSelector->currentIndex());
    // GUI sends always opt in to RBF so a key-path Scrooge vault spend can be bumped.
    m_coin_control->m_signal_bip125_rbf = true;
    m_coin_control->m_nSequence.reset();
    m_coin_control->m_locktime.reset();
    m_coin_control->m_script_path = false;
    m_coin_control->m_allowed_inputs.reset();
    m_coin_control->m_vault_recovery_sweep = false;
    m_coin_control->m_min_depth = wallet::DEFAULT_MIN_DEPTH;
    if (m_delayed_recovery && model) {
        const auto* stage = selectedRecoveryStage();
        if (!stage) return;
        m_coin_control->m_vault_recovery_sweep = true;
        if (stage->older) {
            m_coin_control->m_nSequence = *stage->older;
            m_coin_control->m_min_depth = static_cast<int>(*stage->older);
            m_coin_control->m_script_path = true;
        } else if (stage->after) {
            m_coin_control->m_locktime = *stage->after;
            m_coin_control->m_script_path = true;
            if (stage->recoverable_now == 0) {
                m_coin_control->m_min_depth = std::numeric_limits<int>::max();
            }
        }
    }
}

void SendCoinsDialog::updateNumberOfBlocks(int count, const QDateTime& blockDate, double nVerificationProgress, SyncType synctype, SynchronizationState sync_state) {
    // During shutdown, clientModel will be nullptr. Attempting to update views at this point may cause a crash
    // due to accessing backend models that might no longer exist.
    if (!clientModel) return;
    // Process event
    if (sync_state == SynchronizationState::POST_INIT) {
        updateSmartFeeLabel();
    }
}

void SendCoinsDialog::updateSmartFeeLabel()
{
    if(!model || !model->getOptionsModel())
        return;
    updateCoinControlState();
    m_coin_control->m_feerate.reset(); // Explicitly use only fee estimation rate for smart fee labels
    int returned_target;
    FeeReason reason;
    CFeeRate feeRate = CFeeRate(model->wallet().getMinimumFee(1000, *m_coin_control, &returned_target, &reason));

    ui->labelSmartFee->setText(tr("%1/kvB").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), feeRate.GetFeePerK())));

    if (reason == FeeReason::FALLBACK) {
        ui->labelSmartFee2->show(); // (Smart fee not initialized yet. This usually takes a few blocks...)
        ui->labelFeeEstimation->setText("");
        ui->fallbackFeeWarningLabel->setVisible(true);
        int lightness = ui->fallbackFeeWarningLabel->palette().color(QPalette::WindowText).lightness();
        QColor warning_colour(255 - (lightness / 5), 176 - (lightness / 3), 48 - (lightness / 14));
        ui->fallbackFeeWarningLabel->setStyleSheet("QLabel { color: " + warning_colour.name() + "; }");
        ui->fallbackFeeWarningLabel->setIndent(GUIUtil::TextWidth(QFontMetrics(ui->fallbackFeeWarningLabel->font()), "x"));
    }
    else
    {
        ui->labelSmartFee2->hide();
        ui->labelFeeEstimation->setText(tr("Estimated to begin confirmation within %n block(s).", "", returned_target));
        ui->fallbackFeeWarningLabel->setVisible(false);
    }

    updateFeeMinimizedLabel();
}

// Coin Control: copy label "Quantity" to clipboard
void SendCoinsDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SendCoinsDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SendCoinsDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void SendCoinsDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void SendCoinsDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Change" to clipboard
void SendCoinsDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void SendCoinsDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && model) { // coin control features disabled
        m_coin_control = std::make_unique<CCoinControl>();
    }

    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void SendCoinsDialog::coinControlButtonClicked()
{
    auto dlg = new CoinControlDialog(*m_coin_control, model, platformStyle);
    connect(dlg, &QDialog::finished, this, &SendCoinsDialog::coinControlUpdateLabels);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

// Coin Control: checkbox custom change address
#if (QT_VERSION >= QT_VERSION_CHECK(6, 7, 0))
void SendCoinsDialog::coinControlChangeChecked(Qt::CheckState state)
#else
void SendCoinsDialog::coinControlChangeChecked(int state)
#endif
{
    if (state == Qt::Unchecked)
    {
        m_coin_control->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    }
    else
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void SendCoinsDialog::coinControlChangeEdited(const QString& text)
{
    if (model && model->getAddressTableModel())
    {
        // Default to no change address until verified
        m_coin_control->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");

        const CTxDestination dest = DecodeDestination(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        }
        else if (!IsValidDestination(dest)) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid Bitcoin address"));
        }
        else // Valid address
        {
            if (!model->wallet().isSpendable(dest)) {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));

                // confirmation dialog
                QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm custom change address"), tr("The address you selected for change is not part of this wallet. Any or all funds in your wallet may be sent to this address. Are you sure?"),
                    QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

                if(btnRetVal == QMessageBox::Yes)
                    m_coin_control->destChange = dest;
                else
                {
                    ui->lineEditCoinControlChange->setText("");
                    ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");
                    ui->labelCoinControlChangeLabel->setText("");
                }
            }
            else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");

                // Query label
                QString associatedLabel = model->getAddressTableModel()->labelForAddress(text);
                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                m_coin_control->destChange = dest;
            }
        }
    }
}

// Coin Control: update labels
void SendCoinsDialog::coinControlUpdateLabels()
{
    if (!model || !model->getOptionsModel())
        return;

    updateCoinControlState();

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    CoinControlDialog::fSubtractFeeFromAmount = false;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry && !entry->isHidden())
        {
            SendCoinsRecipient rcp = entry->getValue();
            CoinControlDialog::payAmounts.append(rcp.amount);
            if (rcp.fSubtractFeeFromAmount)
                CoinControlDialog::fSubtractFeeFromAmount = true;
        }
    }

    if (m_coin_control->HasSelected())
    {
        // actual coin control calculation
        CoinControlDialog::updateLabels(*m_coin_control, model, this);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

SendConfirmationDialog::SendConfirmationDialog(const QString& title, const QString& text, const QString& informative_text, const QString& detailed_text, int _secDelay, bool enable_send, bool always_show_unsigned, QWidget* parent)
    : QMessageBox(parent), secDelay(_secDelay), m_enable_send(enable_send)
{
    setIcon(QMessageBox::Question);
    setWindowTitle(title); // On macOS, the window title is ignored (as required by the macOS Guidelines).
    setText(text);
    setInformativeText(informative_text);
    setDetailedText(detailed_text);
    setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    if (always_show_unsigned || !enable_send) addButton(QMessageBox::Save);
    setDefaultButton(QMessageBox::Cancel);
    yesButton = button(QMessageBox::Yes);
    if (confirmButtonText.isEmpty()) {
        confirmButtonText = yesButton->text();
    }
    m_psbt_button = button(QMessageBox::Save);
    updateButtons();
    connect(&countDownTimer, &QTimer::timeout, this, &SendConfirmationDialog::countDown);
}

int SendConfirmationDialog::exec()
{
    updateButtons();
    countDownTimer.start(1s);
    return QMessageBox::exec();
}

void SendConfirmationDialog::countDown()
{
    secDelay--;
    updateButtons();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void SendConfirmationDialog::updateButtons()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(confirmButtonText + (m_enable_send ? (" (" + QString::number(secDelay) + ")") : QString("")));
        if (m_psbt_button) {
            m_psbt_button->setEnabled(false);
            m_psbt_button->setText(m_psbt_button_text + " (" + QString::number(secDelay) + ")");
        }
    }
    else
    {
        yesButton->setEnabled(m_enable_send);
        yesButton->setText(confirmButtonText);
        if (m_psbt_button) {
            m_psbt_button->setEnabled(true);
            m_psbt_button->setText(m_psbt_button_text);
        }
    }
}
