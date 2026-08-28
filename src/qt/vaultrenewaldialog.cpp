// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/vaultrenewaldialog.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/platformstyle.h>

#include <QCheckBox>
#include <QEvent>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <limits>
#include <ranges>

namespace {
QString ParticipantKind(interfaces::Wallet::VaultParticipantType type)
{
    using Type = interfaces::Wallet::VaultParticipantType;
    switch (type) {
    case Type::LOCAL_SOFTWARE: return VaultRenewalDialog::tr("This device");
    case Type::HARDWARE: return VaultRenewalDialog::tr("Hardware");
    case Type::AIR_GAPPED: return VaultRenewalDialog::tr("Offline signer");
    case Type::UNKNOWN: return VaultRenewalDialog::tr("Key");
    }
    return VaultRenewalDialog::tr("Key");
}

QString ParticipantName(int index, interfaces::Wallet::VaultParticipantType type,
                        const QString& fingerprint)
{
    const QString name{VaultRenewalDialog::tr("Key %1 · %2").arg(index + 1).arg(ParticipantKind(type))};
    return fingerprint.isEmpty() ? name : VaultRenewalDialog::tr("%1 (%2)").arg(name, fingerprint);
}

QLabel* MakeHeadline(const QString& text, QWidget* parent)
{
    auto* label{new QLabel(text, parent)};
    label->setObjectName(QStringLiteral("vaultRenewalHeadline"));
    label->setWordWrap(true);
    QFont font{label->font()};
    font.setBold(true);
    font.setPointSize(font.pointSize() + 4);
    label->setFont(font);
    return label;
}

QWidget* MakeIllustratedHeadline(const QString& text,
                                 GUIUtil::VaultIllustration illustration,
                                 QWidget* parent,
                                 QLabel** headline_out = nullptr)
{
    auto* row{new QWidget(parent)};
    auto* layout{new QHBoxLayout(row)};
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(12);
    auto* headline{MakeHeadline(text, row)};
    if (headline_out) *headline_out = headline;
    layout->addWidget(headline, 1, Qt::AlignVCenter);
    layout->addWidget(
        new GUIUtil::VaultIllustrationLabel(illustration, QSize{120, 80}, row),
        0, Qt::AlignTop);
    return row;
}

QFrame* MakeCard(const QString& name, QWidget* parent)
{
    auto* card{new QFrame(parent)};
    card->setObjectName(name);
    card->setProperty("vaultPaper", true);
    card->setFrameShape(QFrame::NoFrame);
    return card;
}

QLabel* MakeBody(const QString& text, QWidget* parent, const QString& name = {})
{
    auto* label{new QLabel(text, parent)};
    label->setWordWrap(true);
    if (!name.isEmpty()) label->setObjectName(name);
    return label;
}

void ClearLayout(QVBoxLayout* layout)
{
    while (QLayoutItem * item{layout->takeAt(0)}) {
        delete item->widget();
        delete item;
    }
}

int QtCount(std::size_t count)
{
    return static_cast<int>(std::min<std::size_t>(count, std::numeric_limits<int>::max()));
}

QString PrivacyGroupCount(std::size_t count)
{
    const int n{QtCount(count)};
    return count == 1 ? VaultRenewalDialog::tr("%n privacy group", nullptr, n) : VaultRenewalDialog::tr("%n privacy groups", nullptr, n);
}

QString TransactionCount(std::size_t count)
{
    const int n{QtCount(count)};
    return count == 1 ? VaultRenewalDialog::tr("%n transaction", nullptr, n) : VaultRenewalDialog::tr("%n transactions", nullptr, n);
}

QString CoinCount(std::size_t count)
{
    const int n{QtCount(count)};
    return count == 1 ? VaultRenewalDialog::tr("%n coin", nullptr, n) : VaultRenewalDialog::tr("%n coins", nullptr, n);
}

QString InputCount(std::size_t count)
{
    const int n{QtCount(count)};
    return count == 1 ? VaultRenewalDialog::tr("%n input", nullptr, n) : VaultRenewalDialog::tr("%n inputs", nullptr, n);
}
} // namespace

VaultRenewalSignerPresentation PresentVaultRenewalSigners(
    const interfaces::Wallet::VaultStatus& status)
{
    using Availability = interfaces::Wallet::VaultSignerAvailability;
    using Type = interfaces::Wallet::VaultParticipantType;
    VaultRenewalSignerPresentation presentation;
    presentation.ready = status.participants.size() == 3;
    if (!presentation.ready) {
        presentation.reason = VaultRenewalDialog::tr(
            "This vault does not have the exact three-participant roster required for guided renewal.");
    }

    for (int index = 0; index < static_cast<int>(status.participants.size()); ++index) {
        const auto& participant = status.participants[index];
        const QString fingerprint{QString::fromStdString(participant.fingerprint).toUpper()};
        const QString name{ParticipantName(index, participant.type, fingerprint)};
        if (participant.type == Type::HARDWARE) {
            presentation.hardware_participants << name;
        } else if (participant.type == Type::LOCAL_SOFTWARE) {
            ++presentation.local_participant_count;
        }
        QString state;
        QString blocker;
        if (participant.is_lost ||
            std::ranges::find(status.manually_lost_signers, participant.fingerprint) !=
                status.manually_lost_signers.end()) {
            state = VaultRenewalDialog::tr("Marked lost — renewal blocked");
            blocker = VaultRenewalDialog::tr(
                          "%1 is marked lost. Mark it found only after recovering that exact key.")
                          .arg(name);
        } else {
            switch (participant.type) {
            case Type::LOCAL_SOFTWARE:
                if (participant.availability == Availability::AVAILABLE) {
                    state = VaultRenewalDialog::tr("Local key ready");
                } else {
                    state = VaultRenewalDialog::tr("Local key unavailable");
                    blocker = VaultRenewalDialog::tr("%1 is unavailable.").arg(name);
                }
                break;
            case Type::HARDWARE:
                if (!status.signer_discovery_complete) {
                    state = VaultRenewalDialog::tr("Hardware status unknown");
                    blocker = VaultRenewalDialog::tr(
                        "Hardware participant status is not fresh yet. Wait for Check Status to finish.");
                } else if (participant.availability == Availability::AVAILABLE) {
                    state = VaultRenewalDialog::tr(
                        "Hardware connected — approval will be requested");
                } else {
                    state = VaultRenewalDialog::tr("Hardware unavailable");
                    blocker = VaultRenewalDialog::tr(
                                  "Connect %1 and refresh its status.")
                                  .arg(name);
                }
                break;
            case Type::AIR_GAPPED:
                state = VaultRenewalDialog::tr("Offline / PSBT — unsupported for renewal");
                blocker = VaultRenewalDialog::tr(
                              "%1 is configured for offline PSBT signing. Protection renewal requires direct signing and does not export PSBTs.")
                              .arg(name);
                break;
            case Type::UNKNOWN:
                state = VaultRenewalDialog::tr("Signing source unknown");
                blocker = VaultRenewalDialog::tr(
                              "The signing source for %1 is unknown. Review participant setup before renewing.")
                              .arg(name);
                break;
            }
        }
        presentation.roster << VaultRenewalDialog::tr("%1 · %2").arg(name, state);
        if (!blocker.isEmpty()) {
            presentation.ready = false;
            if (presentation.reason.isEmpty()) presentation.reason = blocker;
        }
    }
    return presentation;
}

VaultRenewalDialog::VaultRenewalDialog(const PlatformStyle* platform_style, QWidget* parent)
    : QDialog(parent), m_platform_style{platform_style}
{
    Q_UNUSED(m_platform_style);
    setObjectName(QStringLiteral("vaultRenewalDialog"));
    setWindowTitle(tr("Renew Three-Key Protection"));
    setWindowModality(Qt::WindowModal);
    setMinimumSize(640, 520);
    resize(760, 600);
    GUIUtil::applyRecoveryVaultStyle(this);

    auto* outer{new QVBoxLayout(this)};
    outer->setContentsMargins(18, 16, 18, 16);
    outer->setSpacing(12);

    m_pages = new QStackedWidget(this);
    m_pages->setObjectName(QStringLiteral("vaultRenewalPages"));
    outer->addWidget(m_pages);

    // Scope and planning page.
    auto* plan_scroll{new QScrollArea(m_pages)};
    plan_scroll->setObjectName(QStringLiteral("vaultRenewalPlanScroll"));
    plan_scroll->setFrameShape(QFrame::NoFrame);
    plan_scroll->setWidgetResizable(true);
    plan_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* plan_page{new QWidget(plan_scroll)};
    auto* plan_layout{new QVBoxLayout(plan_page)};
    plan_layout->setContentsMargins(2, 2, 8, 2);
    plan_layout->setSpacing(12);
    auto* plan_heading{new QWidget(plan_page)};
    auto* plan_heading_layout{new QHBoxLayout(plan_heading)};
    plan_heading_layout->setContentsMargins(0, 0, 0, 0);
    plan_heading_layout->setSpacing(12);
    auto* plan_heading_copy{new QVBoxLayout};
    plan_heading_copy->setContentsMargins(0, 0, 0, 0);
    plan_heading_copy->setSpacing(6);
    plan_heading_copy->addWidget(MakeHeadline(tr("Renew three-key protection"), plan_heading));
    plan_heading_copy->addWidget(MakeBody(
        tr("Move selected coins to fresh addresses under this same Recovery Vault policy. All three keys remain able to spend forever; renewal postpones when additional recovery paths become available."),
        plan_heading, QStringLiteral("vaultRenewalIntroduction")));
    plan_heading_layout->addLayout(plan_heading_copy, 1);
    plan_heading_layout->addWidget(
        new GUIUtil::VaultIllustrationLabel(
            GUIUtil::VaultIllustration::PROTECTION_RENEWAL, QSize{120, 80}, plan_heading),
        0, Qt::AlignTop);
    plan_layout->addWidget(plan_heading);
    m_plan_privacy_notice = MakeBody(
        tr("Renewal amounts, eligibility, fund grouping, and participant details are hidden while privacy mode is active."),
        plan_page, QStringLiteral("vaultRenewalPlanPrivacyNotice"));
    m_plan_privacy_notice->setAccessibleName(tr("Renewal details hidden"));
    m_plan_privacy_notice->hide();
    plan_layout->addWidget(m_plan_privacy_notice);

    m_scope_card = MakeCard(QStringLiteral("vaultRenewalScopeCard"), plan_page);
    auto* scope_layout{new QVBoxLayout(m_scope_card)};
    auto* scope_heading{MakeBody(tr("Choose funds"), m_scope_card)};
    QFont scope_font{scope_heading->font()};
    scope_font.setBold(true);
    scope_heading->setFont(scope_font);
    scope_layout->addWidget(scope_heading);
    scope_layout->addWidget(MakeBody(
        tr("Each row is one existing on-chain privacy group. Selecting whole groups avoids linking groups that are not already connected."),
        m_scope_card, QStringLiteral("vaultRenewalGroupExplanation")));
    m_group_layout = new QVBoxLayout;
    m_group_layout->setContentsMargins(0, 0, 0, 0);
    m_group_layout->setSpacing(4);
    scope_layout->addLayout(m_group_layout);
    auto* selection_actions{new QHBoxLayout};
    m_select_default_groups = new QPushButton(m_scope_card);
    m_select_default_groups->setObjectName(QStringLiteral("vaultRenewalSelectDefaultGroups"));
    m_select_default_groups->setFlat(true);
    m_select_all_groups = new QPushButton(tr("Select all"), m_scope_card);
    m_select_all_groups->setObjectName(QStringLiteral("vaultRenewalSelectAllGroups"));
    m_select_all_groups->setAccessibleDescription(
        tr("Select every eligible privacy group in this Recovery Vault."));
    m_select_all_groups->setFlat(true);
    selection_actions->addWidget(m_select_default_groups);
    selection_actions->addWidget(m_select_all_groups);
    selection_actions->addStretch();
    scope_layout->addLayout(selection_actions);
    plan_layout->addWidget(m_scope_card);

    m_plan_card = MakeCard(QStringLiteral("vaultRenewalPlanCard"), plan_page);
    auto* summary_layout{new QVBoxLayout(m_plan_card)};
    m_plan_status = MakeBody({}, m_plan_card, QStringLiteral("vaultRenewalPlanStatus"));
    m_plan_status->setAccessibleName(tr("Renewal plan status"));
    m_plan_summary = MakeBody({}, m_plan_card, QStringLiteral("vaultRenewalPlanSummary"));
    m_plan_summary->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    m_plan_exclusions = MakeBody({}, m_plan_card, QStringLiteral("vaultRenewalPlanExclusions"));
    m_batch_layout = new QVBoxLayout;
    m_batch_layout->setContentsMargins(0, 0, 0, 0);
    m_batch_layout->setSpacing(6);
    summary_layout->addWidget(m_plan_status);
    summary_layout->addWidget(m_plan_summary);
    summary_layout->addLayout(m_batch_layout);
    summary_layout->addWidget(m_plan_exclusions);
    plan_layout->addWidget(m_plan_card);

    m_signer_status = MakeBody({}, plan_page, QStringLiteral("vaultRenewalSignerStatus"));
    m_signer_status->setAccessibleName(tr("Three-key signing readiness"));
    plan_layout->addWidget(m_signer_status);
    m_signer_roster = MakeBody({}, plan_page, QStringLiteral("vaultRenewalSignerRoster"));
    m_signer_roster->setAccessibleName(tr("Renewal participant roster"));
    m_signer_roster->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    plan_layout->addWidget(m_signer_roster);
    plan_layout->addStretch();

    auto* plan_actions{new QHBoxLayout};
    auto* cancel_plan{new QPushButton(tr("Cancel"), plan_page)};
    cancel_plan->setObjectName(QStringLiteral("vaultRenewalCancelButton"));
    m_refresh_button = new QPushButton(tr("Refresh Plan"), plan_page);
    m_refresh_button->setObjectName(QStringLiteral("vaultRenewalRefreshButton"));
    m_refresh_button->setAccessibleDescription(tr("Recheck eligible coins and participant availability."));
    m_review_button = new QPushButton(tr("Review Renewal"), plan_page);
    m_review_button->setObjectName(QStringLiteral("vaultRenewalReviewButton"));
    m_review_button->setAccessibleDescription(
        tr("Create exact unsigned renewal transactions and show their fees before anything is signed."));
    m_review_button->setDefault(true);
    plan_actions->addWidget(cancel_plan);
    plan_actions->addStretch();
    plan_actions->addWidget(m_refresh_button);
    plan_actions->addWidget(m_review_button);
    plan_layout->addLayout(plan_actions);
    plan_scroll->setWidget(plan_page);
    m_pages->addWidget(plan_scroll);

    connect(cancel_plan, &QPushButton::clicked, this, &VaultRenewalDialog::reject);
    connect(m_select_default_groups, &QPushButton::clicked, this, [this] {
        selectDefaultGroups();
        requestSelectedPlan();
    });
    connect(m_select_all_groups, &QPushButton::clicked, this, [this] {
        selectAllGroups();
        requestSelectedPlan();
    });
    connect(m_refresh_button, &QPushButton::clicked, this, &VaultRenewalDialog::requestSelectedPlan);
    connect(m_review_button, &QPushButton::clicked, this, [this] {
        if (m_plan.fees_ready) {
            showPage(Page::REVIEW);
            return;
        }
        m_review_button->setEnabled(false);
        m_refresh_button->setEnabled(false);
        m_plan_status->setText(tr("Preparing exact transactions and fees…"));
        Q_EMIT batchRequested(m_plan.plan_token);
    });

    // Final review page.
    auto* review_scroll{new QScrollArea(m_pages)};
    review_scroll->setObjectName(QStringLiteral("vaultRenewalReviewScroll"));
    review_scroll->setFrameShape(QFrame::NoFrame);
    review_scroll->setWidgetResizable(true);
    review_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* review_page{new QWidget(review_scroll)};
    auto* review_layout{new QVBoxLayout(review_page)};
    review_layout->setContentsMargins(2, 2, 8, 2);
    review_layout->setSpacing(12);
    review_layout->addWidget(MakeIllustratedHeadline(
        tr("Review protection renewal"),
        GUIUtil::VaultIllustration::PROTECTION_RENEWAL, review_page));
    m_review_privacy_notice = MakeBody(
        tr("Transaction amounts, fees, and fund grouping are hidden while privacy mode is active. Turn privacy mode off to sign."),
        review_page, QStringLiteral("vaultRenewalReviewPrivacyNotice"));
    m_review_privacy_notice->setAccessibleName(tr("Renewal transaction details hidden"));
    m_review_privacy_notice->hide();
    review_layout->addWidget(m_review_privacy_notice);
    m_review_summary = MakeBody({}, review_page, QStringLiteral("vaultRenewalReviewSummary"));
    m_review_summary->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    review_layout->addWidget(m_review_summary);
    m_review_card = MakeCard(QStringLiteral("vaultRenewalReviewBatches"), review_page);
    m_review_batch_layout = new QVBoxLayout(m_review_card);
    m_review_batch_layout->setSpacing(7);
    review_layout->addWidget(m_review_card);
    auto* consequences{MakeBody(
        tr("Existing privacy groups are never combined, so renewal does not link groups that are not already connected on-chain. An oversized group may be split into multiple transactions only when transaction weight requires it. Each transaction returns to one fresh internal vault address. Your hardware devices may ask for repeated approvals. Every transaction will be signed before any is broadcast. Fees reduce the returned amount, and the 90/180-day clocks restart only after each new output's first confirmation."),
        review_page, QStringLiteral("vaultRenewalConsequences"))};
    consequences->setAccessibleName(tr("Renewal consequences"));
    review_layout->addWidget(consequences);
    review_layout->addStretch();
    auto* review_actions{new QHBoxLayout};
    auto* cancel_review{new QPushButton(tr("Cancel"), review_page)};
    cancel_review->setObjectName(QStringLiteral("vaultRenewalReviewCancelButton"));
    auto* back{new QPushButton(tr("Back"), review_page)};
    back->setObjectName(QStringLiteral("vaultRenewalBackButton"));
    back->setAccessibleDescription(
        tr("Return to fund selection while retaining this exact reviewed batch."));
    m_sign_button = new QPushButton(tr("Sign All and Broadcast"), review_page);
    m_sign_button->setObjectName(QStringLiteral("vaultRenewalSignButton"));
    m_sign_button->setAccessibleDescription(tr("Sign every renewal transaction with all three participants, then broadcast only after every transaction is complete."));
    m_sign_button->setDefault(true);
    review_actions->addWidget(cancel_review);
    review_actions->addStretch();
    review_actions->addWidget(back);
    review_actions->addWidget(m_sign_button);
    review_layout->addLayout(review_actions);
    review_scroll->setWidget(review_page);
    m_pages->addWidget(review_scroll);
    connect(cancel_review, &QPushButton::clicked, this, &VaultRenewalDialog::reject);
    connect(back, &QPushButton::clicked, this, [this] { showPage(Page::PLAN); });
    connect(m_sign_button, &QPushButton::clicked, this, [this] {
        m_operation_started = true;
        m_broadcast_started = false;
        m_cancellation_pending = false;
        showPage(Page::PROGRESS);
        setSigningProgress(0, m_plan.batches.size(), tr("Preparing every transaction before contacting signers…"));
        Q_EMIT signingRequested(m_plan.plan_token);
    });

    // Progress page.
    auto* progress_scroll{new QScrollArea(m_pages)};
    progress_scroll->setObjectName(QStringLiteral("vaultRenewalProgressScroll"));
    progress_scroll->setFrameShape(QFrame::NoFrame);
    progress_scroll->setWidgetResizable(true);
    progress_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* progress_page{new QWidget(progress_scroll)};
    auto* progress_layout{new QVBoxLayout(progress_page)};
    progress_layout->setContentsMargins(2, 2, 2, 2);
    progress_layout->setSpacing(12);
    auto* progress_headline{MakeIllustratedHeadline(
        tr("Signing renewal transactions"),
        GUIUtil::VaultIllustration::PROTECTION_RENEWAL, progress_page,
        &m_progress_headline)};
    m_progress_detail = MakeBody({}, progress_page, QStringLiteral("vaultRenewalProgressDetail"));
    m_progress_detail->setAccessibleName(tr("Renewal progress detail"));
    m_progress_count = new QLabel(progress_page);
    m_progress_count->setObjectName(QStringLiteral("vaultRenewalProgressCount"));
    m_progress_count->setProperty("vaultEyebrow", true);
    m_progress_count->setAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
    m_progress_count->setAccessibleName(tr("Renewal progress count"));
    m_progress = new QProgressBar(progress_page);
    m_progress->setObjectName(QStringLiteral("vaultRenewalProgress"));
    m_progress->setAccessibleName(tr("Renewal progress"));
    m_progress->setTextVisible(false);
    m_cancel_progress = new QPushButton(tr("Cancel Signing"), progress_page);
    m_cancel_progress->setObjectName(QStringLiteral("vaultRenewalCancelProgressButton"));
    m_cancel_progress->setAccessibleDescription(tr("Stop before broadcast and discard the in-memory signed batch."));
    progress_layout->addStretch();
    progress_layout->addWidget(progress_headline);
    progress_layout->addWidget(m_progress_detail);
    progress_layout->addWidget(m_progress_count);
    progress_layout->addWidget(m_progress);
    progress_layout->addWidget(m_cancel_progress, 0, Qt::AlignLeft);
    progress_layout->addStretch();
    progress_scroll->setWidget(progress_page);
    m_pages->addWidget(progress_scroll);
    connect(m_cancel_progress, &QPushButton::clicked, this, [this] {
        Q_EMIT cancellationRequested();
    });

    // Truthful completion / partial relay page.
    auto* result_scroll{new QScrollArea(m_pages)};
    result_scroll->setObjectName(QStringLiteral("vaultRenewalResultScroll"));
    result_scroll->setFrameShape(QFrame::NoFrame);
    result_scroll->setWidgetResizable(true);
    result_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* result_page{new QWidget(result_scroll)};
    auto* result_layout{new QVBoxLayout(result_page)};
    result_layout->setContentsMargins(2, 2, 2, 2);
    result_layout->setSpacing(12);
    auto* result_headline{MakeIllustratedHeadline(
        {}, GUIUtil::VaultIllustration::PROTECTION_RENEWAL, result_page,
        &m_result_headline)};
    m_result_detail = MakeBody({}, result_page, QStringLiteral("vaultRenewalResultDetail"));
    m_result_detail->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    m_result_detail->setAccessibleName(tr("Renewal result"));
    m_result_list = new QWidget(result_page);
    m_result_list->setObjectName(QStringLiteral("vaultRenewalResultList"));
    m_result_list_layout = new QVBoxLayout(m_result_list);
    m_result_list_layout->setContentsMargins(0, 4, 0, 0);
    m_result_list_layout->setSpacing(4);
    result_layout->addStretch();
    result_layout->addWidget(result_headline);
    result_layout->addWidget(m_result_detail);
    result_layout->addWidget(m_result_list);
    result_layout->addStretch();
    auto* result_actions{new QHBoxLayout};
    m_retry_button = new QPushButton(tr("Retry Remaining"), result_page);
    m_retry_button->setObjectName(QStringLiteral("vaultRenewalRetryButton"));
    m_retry_button->setAccessibleDescription(
        tr("Retry relay of the same fully signed transactions without rebuilding or resigning them."));
    auto* done{new QPushButton(tr("Done"), result_page)};
    done->setObjectName(QStringLiteral("vaultRenewalDoneButton"));
    done->setDefault(true);
    result_actions->addStretch();
    result_actions->addWidget(m_retry_button);
    result_actions->addWidget(done);
    result_layout->addLayout(result_actions);
    result_scroll->setWidget(result_page);
    m_pages->addWidget(result_scroll);
    connect(m_retry_button, &QPushButton::clicked, this, &VaultRenewalDialog::retryRequested);
    connect(done, &QPushButton::clicked, this, [this] {
        Q_EMIT renewalFinished();
        accept();
    });
}

void VaultRenewalDialog::setAvailableGroups(
    const std::vector<VaultRenewalGroupPresentation>& groups, bool due,
    const std::optional<QStringList>& selected_ids)
{
    const QStringList selection{selected_ids.value_or(selectedGroupIds())};
    m_available_groups = groups;
    m_default_due = due;
    updateDefaultSelectionCopy();
    rebuildGroupChoices(selection);
    if (m_started && !selection.empty() && selectedGroupIds().empty()) {
        selectDefaultGroups();
    }
}

void VaultRenewalDialog::start(bool due)
{
    m_operation_started = false;
    m_broadcast_started = false;
    m_cancellation_pending = false;
    m_default_due = due;
    m_started = true;
    updateDefaultSelectionCopy();
    selectDefaultGroups();
    showPage(Page::PLAN);
    requestSelectedPlan();
}

void VaultRenewalDialog::setPrivacy(bool privacy)
{
    if (m_privacy == privacy) return;
    m_privacy = privacy;

    m_plan_privacy_notice->setVisible(privacy);
    m_scope_card->setVisible(!privacy);
    m_plan_card->setVisible(!privacy);
    m_signer_status->setVisible(!privacy);
    m_signer_roster->setVisible(!privacy && !m_plan.signer_lines.isEmpty());
    m_refresh_button->setVisible(!privacy);
    m_review_button->setVisible(!privacy);
    rebuildGroupChoices(selectedGroupIds());

    m_review_privacy_notice->setVisible(privacy);
    m_review_summary->setVisible(!privacy);
    m_review_card->setVisible(!privacy);
    m_sign_button->setVisible(!privacy);
    // The progress bar's numeric range reveals the number of renewal
    // transactions even when its painted label is masked.
    m_progress->setVisible(!privacy);

    if (m_plan.supported) updatePlanPresentation();
    const Page page{static_cast<Page>(m_pages->currentIndex())};
    if (page == Page::REVIEW) showPage(Page::REVIEW);
    if (page == Page::PROGRESS) {
        if (privacy) {
            m_progress_headline->setText(tr("Renewal in progress"));
            m_progress->setFormat(tr("Progress hidden"));
            m_progress_count->setText(tr("Progress hidden"));
            m_progress_detail->setText(tr("Transaction and participant details are hidden while privacy mode is active."));
        } else {
            m_progress_headline->setText(
                m_broadcast_started ? tr("Broadcasting signed transactions") : tr("Signing renewal transactions"));
            const QString count{
                m_broadcast_started ? tr("Broadcast %1 of %2").arg(m_progress->value()).arg(m_progress->maximum()) : tr("Signed %1 of %2").arg(m_progress->value()).arg(m_progress->maximum())};
            m_progress->setFormat(count);
            m_progress_count->setText(count);
            m_progress_detail->setText(m_progress_unmasked_detail);
        }
    }
    if (page == Page::RESULT && m_last_result) renderResult();
}

void VaultRenewalDialog::updateDefaultSelectionCopy()
{
    m_select_default_groups->setText(
        m_default_due ? tr("Select due groups") : tr("Select oldest group"));
    m_select_default_groups->setAccessibleDescription(
        m_default_due ? tr("Restore the recommended selection of every privacy group already in, or approaching, an additional recovery path.") : tr("Restore the recommended early-renewal selection of only the oldest privacy group."));
}

void VaultRenewalDialog::rebuildGroupChoices(const QStringList& selected_ids)
{
    ClearLayout(m_group_layout);
    m_group_checks.clear();
    for (std::size_t index{0}; index < m_available_groups.size(); ++index) {
        const auto& group{m_available_groups[index]};
        QString state;
        if (group.due) {
            state = tr("renewal due");
        } else if (group.recovery_enabled) {
            state = tr("additional recovery path available");
        } else {
            state = tr("three-key-only period");
        }
        auto* choice{new QCheckBox(
            tr("Privacy group %1 · %2 · %3 · %4")
                .arg(static_cast<qulonglong>(index + 1))
                .arg(CoinCount(group.coin_count))
                .arg(amountText(group.value), state),
            m_scope_card)};
        choice->setObjectName(
            QStringLiteral("vaultRenewalGroupCheck%1").arg(index + 1));
        choice->setAccessibleDescription(
            tr("Select this entire existing on-chain privacy group. Renewal never combines separate groups."));
        choice->setChecked(selected_ids.contains(group.identifier));
        connect(choice, &QCheckBox::toggled, this, [this] {
            if (m_started) requestSelectedPlan();
        });
        m_group_checks.push_back(choice);
        m_group_layout->addWidget(choice);
    }
    if (m_available_groups.empty()) {
        m_group_layout->addWidget(MakeBody(
            tr("No confirmed, safe, unlocked vault privacy groups are currently eligible."),
            m_scope_card, QStringLiteral("vaultRenewalNoGroups")));
    }
    const bool have_groups{!m_available_groups.empty()};
    m_select_default_groups->setEnabled(have_groups);
    m_select_all_groups->setEnabled(have_groups);
}

void VaultRenewalDialog::selectDefaultGroups()
{
    std::optional<std::size_t> oldest;
    if (!m_available_groups.empty()) {
        oldest = 0;
        for (std::size_t index{1}; index < m_available_groups.size(); ++index) {
            if (m_available_groups[index].blocks_until_primary <
                m_available_groups[*oldest].blocks_until_primary) {
                oldest = index;
            }
        }
    }
    const bool have_due{std::ranges::any_of(
        m_available_groups, &VaultRenewalGroupPresentation::due)};
    for (std::size_t index{0}; index < m_group_checks.size(); ++index) {
        const QSignalBlocker blocker{m_group_checks[index]};
        m_group_checks[index]->setChecked(
            m_default_due && have_due ? m_available_groups[index].due : oldest && index == *oldest);
    }
}

void VaultRenewalDialog::selectAllGroups()
{
    for (QCheckBox* choice : m_group_checks) {
        const QSignalBlocker blocker{choice};
        choice->setChecked(true);
    }
}

QStringList VaultRenewalDialog::selectedGroupIds() const
{
    QStringList selected;
    for (std::size_t index{0}; index < m_group_checks.size(); ++index) {
        if (m_group_checks[index]->isChecked()) {
            selected << m_available_groups[index].identifier;
        }
    }
    return selected;
}

void VaultRenewalDialog::showPage(Page page)
{
    m_pages->setCurrentIndex(static_cast<int>(page));
    if (page == Page::REVIEW) {
        m_review_summary->setText(
            tr("%1 · %2 · %3 selected · %4 total fee · %5 returned to fresh vault addresses")
                .arg(PrivacyGroupCount(m_plan.cluster_count))
                .arg(TransactionCount(m_plan.batches.size()))
                .arg(amountText(m_plan.selected), amountText(m_plan.total_fee), amountText(m_plan.returned)));
        rebuildBatches(m_review_batch_layout, /*detailed=*/true);
        m_sign_button->setEnabled(
            !m_privacy && m_plan.signers_ready && !m_plan.plan_token.isEmpty() &&
            !m_plan.batches.empty());
        if (!m_privacy) m_sign_button->setFocus();
    }
}

void VaultRenewalDialog::requestSelectedPlan()
{
    setPlanLoading();
    Q_EMIT planRequested(selectedGroupIds());
}

void VaultRenewalDialog::setPlanLoading()
{
    m_plan = {};
    m_plan_status->setText(tr("Checking eligible coins and participant status…"));
    m_plan_summary->clear();
    m_plan_exclusions->clear();
    m_signer_status->setText(tr("Signing readiness is being checked."));
    m_signer_roster->clear();
    m_review_button->setText(tr("Review Renewal"));
    ClearLayout(m_batch_layout);
    m_review_button->setEnabled(false);
    m_refresh_button->setEnabled(false);
}

void VaultRenewalDialog::setPlan(const VaultRenewalPlanPresentation& plan)
{
    m_plan = plan;
    updatePlanPresentation();
}

void VaultRenewalDialog::setBatch(const VaultRenewalPlanPresentation& batch)
{
    m_plan = batch;
    m_plan.fees_ready = true;
    updatePlanPresentation();
    if (!m_plan.batches.empty()) showPage(Page::REVIEW);
}

void VaultRenewalDialog::setSignerReadiness(bool ready, const QString& reason, const QStringList& roster)
{
    m_plan.signers_ready = ready;
    m_plan.unavailable_reason = reason;
    if (!roster.isEmpty()) m_plan.signer_lines = roster;
    if (ready) {
        m_signer_status->setText(tr("All three participants are freshly available for direct signing."));
    } else {
        m_signer_status->setText(
            reason.isEmpty() ? tr("Direct renewal requires all three participants to be local or freshly matched hardware devices.") : reason);
    }
    m_signer_roster->setText(m_plan.signer_lines.join(QLatin1Char('\n')));
    m_signer_roster->setVisible(!m_privacy && !m_plan.signer_lines.isEmpty());
    m_review_button->setEnabled(!m_privacy && ready && !m_plan.plan_token.isEmpty());
    m_sign_button->setEnabled(
        !m_privacy && ready && m_plan.fees_ready && !m_plan.plan_token.isEmpty() &&
        !m_plan.batches.empty());
}

void VaultRenewalDialog::setPlanError(const QString& error)
{
    m_plan = {};
    m_plan_status->setText(error.isEmpty() ? tr("A renewal plan could not be created.") : error);
    m_plan_summary->clear();
    m_plan_exclusions->clear();
    m_signer_status->setText(tr("Nothing has been signed or broadcast."));
    m_signer_roster->clear();
    m_signer_roster->hide();
    ClearLayout(m_batch_layout);
    m_review_button->setEnabled(false);
    m_refresh_button->setEnabled(true);
}

void VaultRenewalDialog::updatePlanPresentation()
{
    m_refresh_button->setEnabled(true);
    if (!m_plan.supported) {
        setPlanError(m_plan.unavailable_reason.isEmpty() ? tr("Guided renewal is available only for Recovery Vaults created with the 90/180-day schedule.") : m_plan.unavailable_reason);
        return;
    }
    QStringList exclusions;
    if (m_plan.excluded_locked_count > 0) {
        exclusions << tr("%1 locked (%2)")
                          .arg(amountText(m_plan.excluded_locked),
                               CoinCount(m_plan.excluded_locked_count));
    }
    if (m_plan.excluded_unsafe_count > 0) {
        exclusions << tr("%1 unsafe (%2)")
                          .arg(amountText(m_plan.excluded_unsafe),
                               CoinCount(m_plan.excluded_unsafe_count));
    }
    if (m_plan.excluded_unconfirmed_count > 0) {
        exclusions << tr("%1 unconfirmed (%2)")
                          .arg(amountText(m_plan.excluded_unconfirmed),
                               CoinCount(m_plan.excluded_unconfirmed_count));
    }
    if (m_plan.excluded_uneconomic_count > 0) {
        exclusions << tr("%1 uneconomic to move (%2)")
                          .arg(amountText(m_plan.excluded_uneconomic),
                               CoinCount(m_plan.excluded_uneconomic_count));
    }
    m_plan_exclusions->setText(
        exclusions.isEmpty() ? tr("Unavailable for renewal: none.") :
                               tr("Unavailable for renewal: %1.").arg(exclusions.join(QStringLiteral(" · "))));

    if (m_plan.batches.empty()) {
        m_plan_status->setText(
            m_plan.excluded_uneconomic_count > 0 ? tr("No economical renewal transaction can be created for this selection.") : tr("No eligible confirmed vault coins are available for this selection."));
        m_plan_summary->clear();
        m_signer_status->setText(tr("Nothing will be signed or broadcast."));
        m_signer_roster->clear();
        m_signer_roster->hide();
        ClearLayout(m_batch_layout);
        m_review_button->setEnabled(false);
        return;
    }

    m_plan_status->setText(tr("Ready for review"));
    m_review_button->setText(
        m_plan.fees_ready ? tr("Return to Review") : tr("Review Renewal"));
    if (m_plan.fees_ready) {
        m_plan_summary->setText(
            tr("%1 · %2 · %3 selected · %4 total fee · %5 returned")
                .arg(PrivacyGroupCount(m_plan.cluster_count))
                .arg(TransactionCount(m_plan.batches.size()))
                .arg(amountText(m_plan.selected), amountText(m_plan.total_fee), amountText(m_plan.returned)));
    } else {
        m_plan_summary->setText(
            tr("%1 · %2 · %3 selected. Exact transactions and fees are calculated only when you continue to final review.")
                .arg(PrivacyGroupCount(m_plan.cluster_count))
                .arg(CoinCount(m_plan.coin_count))
                .arg(amountText(m_plan.selected)));
    }
    rebuildBatches(m_batch_layout, /*detailed=*/false);

    if (m_plan.signers_ready) {
        m_signer_status->setText(tr("All three participants are freshly available for direct signing."));
    } else {
        m_signer_status->setText(
            m_plan.unavailable_reason.isEmpty() ? tr("Direct renewal requires all three participants to be local or freshly matched hardware devices.") : m_plan.unavailable_reason);
    }
    m_signer_roster->setText(m_plan.signer_lines.join(QLatin1Char('\n')));
    m_signer_roster->setVisible(!m_privacy && !m_plan.signer_lines.isEmpty());
    m_review_button->setEnabled(
        !m_privacy && m_plan.signers_ready && !m_plan.plan_token.isEmpty());
}

void VaultRenewalDialog::rebuildBatches(QVBoxLayout* layout, bool detailed)
{
    ClearLayout(layout);
    for (std::size_t index{0}; index < m_plan.batches.size(); ++index) {
        const auto& batch{m_plan.batches[index]};
        auto* row{new QFrame};
        row->setObjectName(QStringLiteral("vaultRenewalBatch%1").arg(index + 1));
        row->setProperty("vaultInset", true);
        row->setFrameShape(QFrame::NoFrame);
        auto* row_layout{new QVBoxLayout(row)};
        row_layout->setContentsMargins(9, 7, 9, 7);
        const int mapped_group{privacyGroupNumber(batch.identifier)};
        const int group_number{mapped_group > 0 ? mapped_group : static_cast<int>(index) + 1};
        const QString title_text{
            m_plan.fees_ready ?
                tr("Transaction %1 · Privacy group %2 · %3")
                    .arg(static_cast<qulonglong>(index + 1))
                    .arg(group_number)
                    .arg(InputCount(batch.input_count)) :
                tr("Privacy group %1 · %2")
                    .arg(group_number)
                    .arg(CoinCount(batch.input_count))};
        auto* title{MakeBody(title_text, row)};
        QFont title_font{title->font()};
        title_font.setBold(true);
        title->setFont(title_font);
        row_layout->addWidget(title);
        const QString amount_text{
            detailed || m_plan.fees_ready ? tr("%1 selected − %2 fee = %3 returned to a fresh vault address")
                                                .arg(amountText(batch.selected), amountText(batch.fee), amountText(batch.returned)) :
                                            tr("%1 selected").arg(amountText(batch.selected))};
        auto* amounts{MakeBody(amount_text, row)};
        amounts->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        row_layout->addWidget(amounts);
        layout->addWidget(row);
    }
}

int VaultRenewalDialog::privacyGroupNumber(const QString& identifier) const
{
    for (std::size_t index{0}; index < m_available_groups.size(); ++index) {
        if (m_available_groups[index].identifier == identifier) {
            return static_cast<int>(index) + 1;
        }
    }
    return 0;
}

QString VaultRenewalDialog::amountText(CAmount amount) const
{
    return GUIUtil::formatVaultAmount(m_display_unit, amount, m_privacy);
}

void VaultRenewalDialog::setSigningProgress(std::size_t completed, std::size_t total, const QString& detail)
{
    m_broadcast_started = false;
    m_progress_unmasked_detail = detail;
    m_progress_headline->setText(
        m_privacy ? tr("Renewal in progress") : tr("Signing renewal transactions"));
    const int maximum{static_cast<int>(std::min<std::size_t>(total, std::numeric_limits<int>::max()))};
    const int value{static_cast<int>(std::min<std::size_t>(completed, static_cast<std::size_t>(maximum)))};
    m_progress->setRange(0, std::max(1, maximum));
    m_progress->setValue(value);
    const QString count{
        m_privacy ? tr("Progress hidden") :
                    tr("Signed %1 of %2").arg(static_cast<qulonglong>(completed)).arg(static_cast<qulonglong>(total))};
    m_progress->setFormat(count);
    m_progress_count->setText(count);
    if (m_cancellation_pending) {
        m_progress_unmasked_detail = tr("Stopping safely before broadcast…");
        m_progress_detail->setText(
            m_privacy ? tr("Renewal is stopping safely before broadcast.") : m_progress_unmasked_detail);
        m_cancel_progress->setText(tr("Stopping…"));
        m_cancel_progress->setEnabled(false);
    } else {
        m_progress_detail->setText(
            m_privacy ? tr("Transaction and participant details are hidden while privacy mode is active.") : detail);
        m_cancel_progress->setText(tr("Cancel Signing"));
        m_cancel_progress->setEnabled(true);
    }
    showPage(Page::PROGRESS);
}

void VaultRenewalDialog::setBroadcastProgress(std::size_t completed, std::size_t total, const QString& detail)
{
    m_operation_started = true;
    m_broadcast_started = true;
    m_cancellation_pending = false;
    m_progress_unmasked_detail = detail;
    m_progress_headline->setText(
        m_privacy ? tr("Renewal in progress") : tr("Broadcasting signed transactions"));
    const int maximum{static_cast<int>(std::min<std::size_t>(total, std::numeric_limits<int>::max()))};
    const int value{static_cast<int>(std::min<std::size_t>(completed, static_cast<std::size_t>(maximum)))};
    m_progress->setRange(0, std::max(1, maximum));
    m_progress->setValue(value);
    const QString count{
        m_privacy ? tr("Progress hidden") :
                    tr("Broadcast %1 of %2").arg(static_cast<qulonglong>(completed)).arg(static_cast<qulonglong>(total))};
    m_progress->setFormat(count);
    m_progress_count->setText(count);
    m_progress_detail->setText(
        m_privacy ? tr("Transaction details are hidden while privacy mode is active.") : detail);
    m_cancel_progress->setText(tr("Broadcast in progress"));
    m_cancel_progress->setEnabled(false);
    showPage(Page::PROGRESS);
}

void VaultRenewalDialog::setCancellationPending()
{
    if (!m_operation_started || m_broadcast_started) return;
    m_cancellation_pending = true;
    m_cancel_progress->setEnabled(false);
    m_cancel_progress->setText(tr("Stopping…"));
    m_progress_unmasked_detail = tr("Stopping safely before broadcast…");
    m_progress_detail->setText(
        m_privacy ? tr("Renewal is stopping safely before broadcast.") : m_progress_unmasked_detail);
}

void VaultRenewalDialog::setResult(const VaultRenewalResultPresentation& result)
{
    m_operation_started = false;
    m_broadcast_started = false;
    m_cancellation_pending = false;
    m_last_result = result;
    renderResult();
}

void VaultRenewalDialog::renderResult()
{
    if (!m_last_result) return;
    const auto& result{*m_last_result};
    ClearLayout(m_result_list_layout);
    m_result_list->hide();
    if (m_privacy) {
        m_result_headline->setText(tr("Renewal finished"));
        m_result_detail->setText(
            tr("Transaction outcomes and pending status are hidden while privacy mode is active. Turn privacy mode off to review the result or retry relay."));
        m_retry_button->hide();
        m_retry_button->setEnabled(false);
        showPage(Page::RESULT);
        return;
    }

    const std::size_t accepted{result.relayed + result.already_accepted};
    const std::size_t unresolved{
        result.stored_not_relayed + result.failed + result.not_attempted};
    if (!result.terminal_error.isEmpty()) {
        QStringList prior;
        if (accepted > 0) {
            prior << tr("%1 accepted or already present")
                         .arg(TransactionCount(accepted));
        }
        if (result.stored_not_relayed > 0) {
            prior << tr("%1 stored but not relayed at that time")
                         .arg(TransactionCount(result.stored_not_relayed));
        }
        if (result.failed > 0) {
            prior << tr("%1 failed").arg(TransactionCount(result.failed));
        }
        if (result.not_attempted > 0) {
            prior << tr("%1 not attempted").arg(TransactionCount(result.not_attempted));
        }
        m_result_headline->setText(tr("Renewal retry stopped"));
        m_result_detail->setText(
            tr("Previous attempt: %1. The retained signed batch can no longer be retried. Accepted transactions keep their recorded outcome; the dashboard shows whether their new outputs are confirmed. Recovery clocks begin only after confirmation.\n\nRetry stopped: %2")
                .arg(prior.isEmpty() ? tr("no transaction outcome was recorded") : prior.join(QStringLiteral(" · ")),
                     result.terminal_error));
    } else if (unresolved == 0 && accepted > 0) {
        m_result_headline->setText(tr("Protection renewal broadcast"));
        m_result_detail->setText(
            tr("%1 accepted or already present. Their recovery clocks reset only if and when the new vault outputs confirm. The dashboard shows their current confirmation state.")
                .arg(TransactionCount(accepted)));
    } else if (accepted > 0) {
        m_result_headline->setText(tr("Some transactions were broadcast"));
        QStringList outcomes;
        outcomes << tr("%1 accepted or already present").arg(TransactionCount(accepted));
        if (result.stored_not_relayed > 0) {
            outcomes << tr("%1 stored but not relayed")
                            .arg(TransactionCount(result.stored_not_relayed));
        }
        if (result.failed > 0) {
            outcomes << tr("%1 failed").arg(TransactionCount(result.failed));
        }
        if (result.not_attempted > 0) {
            outcomes << tr("%1 not attempted").arg(TransactionCount(result.not_attempted));
        }
        m_result_detail->setText(
            tr("%1. For accepted or already-present transactions, the dashboard shows the current confirmation state; their clocks reset only if and when the new outputs confirm. Stored transactions are pending relay and then confirmation. Failed or not-attempted transactions did not renew their portions of the selected funds.")
                .arg(outcomes.join(QStringLiteral(" · "))));
    } else {
        m_result_headline->setText(
            result.stored_not_relayed > 0 ? tr("Renewal pending relay") : tr("Nothing was broadcast"));
        m_result_detail->setText(
            result.stored_not_relayed > 0 ? tr("%1 stored in the wallet and pending relay. Protection has not reset: each new recovery clock begins only after its output confirms. Retry attempts to relay this same signed batch.")
                                                .arg(TransactionCount(result.stored_not_relayed)) :
                                            tr("The signed renewal batch was not broadcast. Existing vault coins and their recovery clocks are unchanged."));
    }
    if (!result.outcomes.empty() || !result.failures.isEmpty()) {
        if (!result.terminal_error.isEmpty()) {
            m_result_detail->setText(
                m_result_detail->text() + QStringLiteral("\n\n") +
                tr("Recorded prior per-transaction outcomes:"));
        }
        int line_index{0};
        const auto add_line = [&](const QString& line) {
            auto* row{new QLabel(line, m_result_list)};
            row->setObjectName(QStringLiteral("vaultRenewalResultLine%1").arg(++line_index));
            row->setWordWrap(true);
            row->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
            m_result_list_layout->addWidget(row);
        };
        for (const auto& outcome : result.outcomes) {
            const int group_number{privacyGroupNumber(outcome.group_identifier)};
            const QString group_name{group_number > 0 ? tr("Privacy group %1").arg(group_number) :
                                                        tr("Selected privacy group")};
            QString line{tr("%1: %2").arg(group_name, outcome.state)};
            if (!outcome.transaction_id.isEmpty()) {
                line += tr(" — transaction %1").arg(outcome.transaction_id);
            }
            if (!outcome.error.isEmpty()) {
                line += tr(" — %1").arg(outcome.error);
            }
            add_line(line);
        }
        for (const QString& failure : result.failures) {
            add_line(failure);
        }
        m_result_list->show();
    }
    const bool can_retry{result.retry_available && result.terminal_error.isEmpty()};
    m_retry_button->setVisible(can_retry);
    m_retry_button->setEnabled(can_retry);
    showPage(Page::RESULT);
}

void VaultRenewalDialog::reject()
{
    if (m_operation_started) {
        if (!m_broadcast_started) {
            Q_EMIT cancellationRequested();
        }
        return;
    }
    QDialog::reject();
}

void VaultRenewalDialog::changeEvent(QEvent* event)
{
    QDialog::changeEvent(event);
    if (event->type() == QEvent::PaletteChange) {
        GUIUtil::applyRecoveryVaultStyle(this);
    }
}
