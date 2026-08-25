// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/test/vaultrenewaltests.h>

#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/vaultrenewaldialog.h>

#include <QAbstractButton>
#include <QAccessible>
#include <QApplication>
#include <QCheckBox>
#include <QColor>
#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QFont>
#include <QFrame>
#include <QLabel>
#include <QPalette>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTest>

#include <algorithm>
#include <memory>
#include <vector>

namespace {
VaultRenewalPlanPresentation ReadOnlyPlan()
{
    VaultRenewalPlanPresentation plan;
    plan.supported = true;
    plan.has_due = false;
    plan.signers_ready = false;
    plan.fees_ready = false;
    plan.unavailable_reason = QStringLiteral("Hardware participant status is not fresh yet.");
    plan.plan_token = QStringLiteral("plan-token");
    plan.cluster_count = 1;
    plan.coin_count = 2;
    plan.selected = 3 * COIN;
    plan.returned = 3 * COIN;
    plan.excluded_locked_count = 1;
    plan.excluded_locked = COIN;
    plan.batches.push_back({QStringLiteral("cluster-a"), 2, 3 * COIN, 0, 3 * COIN});
    return plan;
}

std::vector<VaultRenewalGroupPresentation> Groups(bool due)
{
    return {
        {QStringLiteral("cluster-a"), 3 * COIN, 2, false, false, 5'000},
        {QStringLiteral("cluster-b"), 2 * COIN, 1, due, false, due ? 1'000 : 6'000},
        {QStringLiteral("cluster-c"), 1 * COIN, 1, due, due, due ? 0 : 7'000},
    };
}

VaultRenewalPlanPresentation ExactBatch()
{
    auto batch{ReadOnlyPlan()};
    batch.fees_ready = true;
    batch.signers_ready = true;
    batch.unavailable_reason.clear();
    batch.plan_token = QStringLiteral("batch-token");
    batch.total_fee = 2'000;
    batch.returned = batch.selected - batch.total_fee;
    batch.batches = {{QStringLiteral("cluster-a"), 2, 3 * COIN, 2'000, 3 * COIN - 2'000}};
    return batch;
}

VaultRenewalPlanPresentation DuePlan()
{
    auto plan{ReadOnlyPlan()};
    plan.has_due = true;
    plan.cluster_count = 2;
    plan.coin_count = 2;
    plan.batches = {
        {QStringLiteral("cluster-b"), 1, 2 * COIN, 0, 2 * COIN},
        {QStringLiteral("cluster-c"), 1, COIN, 0, COIN},
    };
    return plan;
}

VaultRenewalPlanPresentation DueExactBatch()
{
    auto batch{DuePlan()};
    batch.fees_ready = true;
    batch.signers_ready = true;
    batch.unavailable_reason.clear();
    batch.plan_token = QStringLiteral("due-batch-token");
    batch.total_fee = 2'000;
    batch.returned = batch.selected - batch.total_fee;
    batch.batches = {
        {QStringLiteral("cluster-b"), 1, 2 * COIN, 1'200, 2 * COIN - 1'200},
        {QStringLiteral("cluster-c"), 1, COIN, 800, COIN - 800},
    };
    return batch;
}

void Show(VaultRenewalDialog& dialog, const QSize& size = {760, 600})
{
    dialog.resize(size);
    dialog.show();
    QApplication::processEvents();
}

interfaces::Wallet::VaultStatus::VaultParticipant Participant(
    const std::string& fingerprint, interfaces::Wallet::VaultParticipantType type,
    interfaces::Wallet::VaultSignerAvailability availability, bool lost = false)
{
    interfaces::Wallet::VaultStatus::VaultParticipant participant;
    participant.fingerprint = fingerprint;
    participant.type = type;
    participant.availability = availability;
    participant.is_lost = lost;
    return participant;
}

QString VisibleText(const QWidget& root)
{
    QStringList text;
    for (const auto* label : root.findChildren<QLabel*>()) {
        if (label->isVisibleTo(&root)) text << label->text();
    }
    for (const auto* button : root.findChildren<QAbstractButton*>()) {
        if (button->isVisibleTo(&root)) text << button->text();
    }
    return text.join(QLatin1Char('\n'));
}
} // namespace

void VaultRenewalTests::guidedPresentation()
{
    std::unique_ptr<const PlatformStyle> style{PlatformStyle::instantiate(QStringLiteral("other"))};
    QVERIFY(style);
    VaultRenewalDialog dialog{style.get()};
    QStringList requested_groups;
    QString requested_plan;
    QString requested_batch;
    int batch_requests{0};
    int cancel_requests{0};
    connect(&dialog, &VaultRenewalDialog::planRequested, this,
            [&](const QStringList& groups) { requested_groups = groups; });
    connect(&dialog, &VaultRenewalDialog::batchRequested, this,
            [&](const QString& token) {
                requested_plan = token;
                ++batch_requests;
            });
    connect(&dialog, &VaultRenewalDialog::signingRequested, this,
            [&](const QString& token) { requested_batch = token; });
    connect(&dialog, &VaultRenewalDialog::cancellationRequested, this,
            [&] { ++cancel_requests; });

    dialog.setAvailableGroups(Groups(/*due=*/false), /*due=*/false);
    dialog.start(/*due=*/false);
    Show(dialog);
    QCOMPARE(requested_groups, QStringList{QStringLiteral("cluster-a")});
    auto* first_group{dialog.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck1"))};
    auto* second_group{dialog.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck2"))};
    auto* third_group{dialog.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck3"))};
    auto* select_all{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalSelectAllGroups"))};
    auto* review{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalReviewButton"))};
    QVERIFY(first_group);
    QVERIFY(second_group);
    QVERIFY(third_group);
    QVERIFY(select_all);
    QVERIFY(review);
    QVERIFY(first_group->isChecked());
    QVERIFY(!second_group->isChecked());
    QVERIFY(!third_group->isChecked());

    select_all->click();
    QCOMPARE(requested_groups,
             (QStringList{QStringLiteral("cluster-a"), QStringLiteral("cluster-b"),
                          QStringLiteral("cluster-c")}));
    second_group->setChecked(false);
    QCOMPARE(requested_groups,
             (QStringList{QStringLiteral("cluster-a"), QStringLiteral("cluster-c")}));
    first_group->setChecked(false);
    QCOMPARE(requested_groups, QStringList{QStringLiteral("cluster-c")});
    third_group->setChecked(false);
    QVERIFY(requested_groups.empty());
    QVERIFY(!review->isEnabled());
    auto* select_default{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalSelectDefaultGroups"))};
    QVERIFY(select_default);
    QCOMPARE(select_default->text(), QStringLiteral("Select oldest group"));
    select_default->click();
    QCOMPARE(requested_groups, QStringList{QStringLiteral("cluster-a")});

    // A due opening recommends every due group, never the early-only oldest
    // preset. Manual changes continue to submit exact whole-group IDs.
    VaultRenewalDialog due_selection{style.get()};
    QStringList due_requested;
    connect(&due_selection, &VaultRenewalDialog::planRequested, this,
            [&](const QStringList& groups) { due_requested = groups; });
    due_selection.setAvailableGroups(Groups(/*due=*/true), /*due=*/true);
    due_selection.start(/*due=*/true);
    Show(due_selection);
    QCOMPARE(due_requested,
             (QStringList{QStringLiteral("cluster-b"), QStringLiteral("cluster-c")}));
    auto* due_first{due_selection.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck1"))};
    auto* due_second{due_selection.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck2"))};
    auto* due_third{due_selection.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck3"))};
    QVERIFY(due_first);
    QVERIFY(due_second);
    QVERIFY(due_third);
    QVERIFY(!due_first->isChecked());
    QVERIFY(due_second->isChecked());
    QVERIFY(due_third->isChecked());
    due_second->setChecked(false);
    QCOMPARE(due_requested, QStringList{QStringLiteral("cluster-c")});
    // A refreshed status preserves still-valid choices by opaque ID.
    due_selection.setAvailableGroups(Groups(/*due=*/true), /*due=*/true);
    QVERIFY(!due_selection.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck2"))->isChecked());
    QVERIFY(due_selection.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck3"))->isChecked());
    auto changed_groups{Groups(/*due=*/true)};
    changed_groups.pop_back();
    due_selection.setAvailableGroups(changed_groups, /*due=*/true);
    QVERIFY(!due_selection.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck1"))->isChecked());
    QVERIFY(due_selection.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck2"))->isChecked());
    due_selection.close();

    dialog.setPlan(ReadOnlyPlan());
    QVERIFY(!review->isEnabled());
    auto* signer_status{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalSignerStatus"))};
    auto* summary{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalPlanSummary"))};
    QVERIFY(signer_status);
    QVERIFY(summary);
    QVERIFY(signer_status->text().contains(QStringLiteral("not fresh"), Qt::CaseInsensitive));
    QVERIFY(summary->text().contains(QStringLiteral("calculated only"), Qt::CaseInsensitive));

    dialog.setSignerReadiness(true, {});
    QVERIFY(review->isEnabled());
    review->click();
    QCOMPARE(requested_plan, QStringLiteral("plan-token"));
    dialog.setBatch(ExactBatch());
    auto* pages{dialog.findChild<QStackedWidget*>(QStringLiteral("vaultRenewalPages"))};
    auto* consequences{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalConsequences"))};
    auto* sign{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalSignButton"))};
    QVERIFY(pages);
    QVERIFY(consequences);
    QVERIFY(sign);
    QCOMPARE(pages->currentIndex(), 1);
    QVERIFY(consequences->text().contains(QStringLiteral("signed before any"), Qt::CaseInsensitive));
    QVERIFY(consequences->text().contains(QStringLiteral("first confirmation"), Qt::CaseInsensitive));
    QVERIFY(consequences->text().contains(QStringLiteral("never combined"), Qt::CaseInsensitive));
    QVERIFY(consequences->text().contains(QStringLiteral("transaction weight"), Qt::CaseInsensitive));
    QVERIFY(!dialog.findChild<QPushButton*>(QStringLiteral("psbtButton")));
    QVERIFY(sign->isEnabled());

    // Back retains the exact batch and its reserved outputs. Returning to
    // review must not request a replacement batch.
    auto* back{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalBackButton"))};
    QVERIFY(back);
    back->click();
    QCOMPARE(pages->currentIndex(), 0);
    QVERIFY(review->isEnabled());
    QCOMPARE(review->text(), QStringLiteral("Return to Review"));
    review->click();
    QCOMPARE(pages->currentIndex(), 1);
    QCOMPARE(batch_requests, 1);

    sign->click();
    QCOMPARE(requested_batch, QStringLiteral("batch-token"));
    QCOMPARE(pages->currentIndex(), 2);

    dialog.setSigningProgress(1, 1, QStringLiteral("Transaction is fully signed."));
    auto* cancel{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalCancelProgressButton"))};
    auto* progress{dialog.findChild<QProgressBar*>(QStringLiteral("vaultRenewalProgress"))};
    QVERIFY(cancel);
    QVERIFY(progress);
    QVERIFY(cancel->isEnabled());
    QCOMPARE(progress->value(), 1);
    cancel->click();
    QCOMPARE(cancel_requests, 1);
    dialog.setCancellationPending();
    QVERIFY(!cancel->isEnabled());
    dialog.setSigningProgress(1, 1, QStringLiteral("Stale worker progress"));
    QVERIFY(!cancel->isEnabled());
    QVERIFY(dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalProgressDetail"))
                ->text()
                .contains(QStringLiteral("Stopping"), Qt::CaseInsensitive));
    dialog.setBroadcastProgress(0, 1, QStringLiteral("Broadcasting"));
    QVERIFY(!cancel->isEnabled());
    dialog.close();
    QApplication::processEvents();
    QVERIFY(dialog.isVisible());

    VaultRenewalResultPresentation result;
    result.stored_not_relayed = 1;
    result.retry_available = true;
    result.failures << QStringLiteral("abc: stored, not relayed");
    dialog.setResult(result);
    QCOMPARE(pages->currentIndex(), 3);
    auto* retry{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalRetryButton"))};
    auto* detail{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalResultDetail"))};
    QVERIFY(retry);
    QVERIFY(detail);
    QVERIFY(retry->isVisible());
    QVERIFY(detail->text().contains(QStringLiteral("stored"), Qt::CaseInsensitive));

    result = {};
    result.relayed = 1;
    result.already_accepted = 1;
    result.stored_not_relayed = 1;
    result.failed = 1;
    result.not_attempted = 1;
    result.retry_available = true;
    result.failures << QStringLiteral("group-c: not attempted");
    dialog.setResult(result);
    QVERIFY(detail->text().contains(QStringLiteral("2 transactions accepted"), Qt::CaseInsensitive));
    QVERIFY(detail->text().contains(QStringLiteral("not attempted"), Qt::CaseInsensitive));
    QVERIFY(detail->text().contains(QStringLiteral("portions"), Qt::CaseInsensitive));
    QVERIFY(detail->text().contains(QStringLiteral("dashboard"), Qt::CaseInsensitive));
    QVERIFY(!detail->text().contains(QStringLiteral("accepted transactions are pending confirmation"), Qt::CaseInsensitive));
    QVERIFY(retry->isVisible());

    // A later top-level retry failure is terminal, but it must not rewrite
    // the prior per-transaction outcomes as if nothing had been broadcast.
    result.terminal_error = QStringLiteral(
        "The policy changed, or a retained transaction was abandoned or replaced.");
    result.retry_available = false;
    dialog.setResult(result);
    QVERIFY(detail->text().contains(QStringLiteral("2 transactions accepted"), Qt::CaseInsensitive));
    QVERIFY(detail->text().contains(QStringLiteral("stored but not relayed at that time"), Qt::CaseInsensitive));
    QVERIFY(detail->text().contains(QStringLiteral("retry stopped"), Qt::CaseInsensitive));
    QVERIFY(detail->text().contains(QStringLiteral("abandoned or replaced"), Qt::CaseInsensitive));
    QVERIFY(!retry->isVisible());
    QVERIFY(!retry->isEnabled());
    dialog.close();

    // Exclusions remain visible when exact creation finds every selected
    // group uneconomic; no misleading Sign action is exposed.
    VaultRenewalDialog uneconomic{style.get()};
    uneconomic.setAvailableGroups(Groups(/*due=*/false), /*due=*/false);
    uneconomic.start(/*due=*/false);
    auto no_batch{ReadOnlyPlan()};
    no_batch.batches.clear();
    no_batch.cluster_count = 0;
    no_batch.coin_count = 0;
    no_batch.selected = 0;
    no_batch.returned = 0;
    no_batch.excluded_uneconomic_count = 2;
    no_batch.excluded_uneconomic = 75'000;
    no_batch.signers_ready = true;
    uneconomic.setBatch(no_batch);
    Show(uneconomic);
    auto* exclusions{uneconomic.findChild<QLabel*>(QStringLiteral("vaultRenewalPlanExclusions"))};
    auto* no_batch_review{uneconomic.findChild<QPushButton*>(QStringLiteral("vaultRenewalReviewButton"))};
    QVERIFY(exclusions);
    QVERIFY(no_batch_review);
    QVERIFY(exclusions->text().contains(QStringLiteral("uneconomic"), Qt::CaseInsensitive));
    QVERIFY(!no_batch_review->isEnabled());

    VaultRenewalDialog split{style.get()};
    split.setAvailableGroups(Groups(/*due=*/false), /*due=*/false);
    split.start(/*due=*/false);
    auto split_batch{ExactBatch()};
    split_batch.cluster_count = 1;
    split_batch.coin_count = 3;
    split_batch.total_fee = 3'000;
    split_batch.returned = split_batch.selected - split_batch.total_fee;
    split_batch.batches = {
        {QStringLiteral("cluster-a"), 2, 2 * COIN, 2'000, 2 * COIN - 2'000},
        {QStringLiteral("cluster-a"), 1, 1 * COIN, 1'000, 1 * COIN - 1'000},
    };
    split.setBatch(split_batch);
    Show(split);
    auto* split_summary{split.findChild<QLabel*>(QStringLiteral("vaultRenewalReviewSummary"))};
    QVERIFY(split_summary);
    QVERIFY(split_summary->text().contains(QStringLiteral("1 privacy group")));
    QVERIFY(split_summary->text().contains(QStringLiteral("2 transactions")));
    QVERIFY(!split_summary->text().contains(QStringLiteral("(s)")));
}

void VaultRenewalTests::privacyPresentation()
{
    std::unique_ptr<const PlatformStyle> style{PlatformStyle::instantiate(QStringLiteral("other"))};
    QVERIFY(style);
    VaultRenewalDialog dialog{style.get()};

    // WalletView applies its cached OptionsModel privacy value before start,
    // so exercise the same open-under-privacy ordering here.
    dialog.setPrivacy(true);
    dialog.setAvailableGroups(Groups(/*due=*/false), /*due=*/false);
    dialog.start(/*due=*/false);
    auto plan{ReadOnlyPlan()};
    plan.signers_ready = true;
    plan.unavailable_reason.clear();
    plan.signer_lines = {
        QStringLiteral("Participant FEEDC0DE · Hardware connected"),
        QStringLiteral("Participant C001D00D · Local key ready"),
        QStringLiteral("Participant 1234ABCD · Local key ready"),
    };
    dialog.setPlan(plan);
    Show(dialog);

    const QString unmasked_amount{BitcoinUnits::formatWithPrivacy(
        BitcoinUnit::BTC, 3 * COIN, BitcoinUnits::SeparatorStyle::ALWAYS,
        /*privacy=*/false)};
    auto* pages{dialog.findChild<QStackedWidget*>(QStringLiteral("vaultRenewalPages"))};
    auto* scope_card{dialog.findChild<QFrame*>(QStringLiteral("vaultRenewalScopeCard"))};
    auto* plan_card{dialog.findChild<QFrame*>(QStringLiteral("vaultRenewalPlanCard"))};
    auto* plan_notice{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalPlanPrivacyNotice"))};
    auto* plan_summary{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalPlanSummary"))};
    auto* signer_status{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalSignerStatus"))};
    auto* signer_roster{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalSignerRoster"))};
    auto* review{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalReviewButton"))};
    QVERIFY(pages);
    QVERIFY(scope_card);
    QVERIFY(plan_card);
    QVERIFY(plan_notice);
    QVERIFY(plan_summary);
    QVERIFY(signer_status);
    QVERIFY(signer_roster);
    QVERIFY(review);
    QCOMPARE(pages->currentIndex(), 0);
    QVERIFY(plan_notice->isVisible());
    QVERIFY(scope_card->isHidden());
    QVERIFY(plan_card->isHidden());
    QVERIFY(signer_status->isHidden());
    QVERIFY(signer_roster->isHidden());
    QVERIFY(review->isHidden());
    QVERIFY(!review->isEnabled());
    auto* plan_accessible{QAccessible::queryAccessibleInterface(plan_card)};
    QVERIFY(plan_accessible);
    QVERIFY(plan_accessible->state().invisible);
    QVERIFY(plan_summary->text().contains(QLatin1Char('#')));
    QVERIFY(!VisibleText(dialog).contains(unmasked_amount));
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("FEEDC0DE")));
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("1 privacy group")));
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("Privacy group 1")));

    // Turning masking off reveals the retained plan without recalculating it.
    dialog.setPrivacy(false);
    QVERIFY(!plan_notice->isVisible());
    QVERIFY(scope_card->isVisible());
    QVERIFY(plan_card->isVisible());
    QVERIFY(signer_roster->isVisible());
    QVERIFY(review->isVisible());
    QVERIFY(review->isEnabled());
    QVERIFY(VisibleText(dialog).contains(unmasked_amount));
    QVERIFY(VisibleText(dialog).contains(QStringLiteral("FEEDC0DE")));

    dialog.setBatch(ExactBatch());
    auto* review_notice{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalReviewPrivacyNotice"))};
    auto* review_summary{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalReviewSummary"))};
    auto* review_card{dialog.findChild<QFrame*>(QStringLiteral("vaultRenewalReviewBatches"))};
    auto* sign{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalSignButton"))};
    QVERIFY(review_notice);
    QVERIFY(review_summary);
    QVERIFY(review_card);
    QVERIFY(sign);
    QCOMPARE(pages->currentIndex(), 1);
    QVERIFY(VisibleText(dialog).contains(unmasked_amount));

    dialog.setPrivacy(true);
    QVERIFY(review_notice->isVisible());
    QVERIFY(review_summary->isHidden());
    QVERIFY(review_card->isHidden());
    QVERIFY(sign->isHidden());
    QVERIFY(!sign->isEnabled());
    QVERIFY(review_summary->text().contains(QLatin1Char('#')));
    QVERIFY(!VisibleText(dialog).contains(unmasked_amount));
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("1 privacy group")));
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("Privacy group 1")));

    dialog.setPrivacy(false);
    QVERIFY(sign->isVisible());
    QVERIFY(sign->isEnabled());
    sign->click();
    QCOMPARE(pages->currentIndex(), 2);
    constexpr auto signer_detail{"Waiting for hardware participant FEEDC0DE."};
    dialog.setSigningProgress(1, 3, QString::fromLatin1(signer_detail));
    auto* progress{dialog.findChild<QProgressBar*>(QStringLiteral("vaultRenewalProgress"))};
    auto* progress_detail{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalProgressDetail"))};
    auto* cancel{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalCancelProgressButton"))};
    QVERIFY(progress);
    QVERIFY(progress_detail);
    QVERIFY(cancel);
    QVERIFY(progress->isVisible());
    QVERIFY(progress_detail->text().contains(QStringLiteral("FEEDC0DE")));

    dialog.setPrivacy(true);
    QVERIFY(progress->isHidden());
    auto* progress_accessible{QAccessible::queryAccessibleInterface(progress)};
    QVERIFY(progress_accessible);
    QVERIFY(progress_accessible->state().invisible);
    QVERIFY(cancel->isVisible());
    QVERIFY(cancel->isEnabled());
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("FEEDC0DE")));
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("1 of 3")));
    dialog.setPrivacy(false);
    QVERIFY(progress->isVisible());
    QVERIFY(progress_detail->text().contains(QStringLiteral("FEEDC0DE")));

    VaultRenewalResultPresentation result;
    result.stored_not_relayed = 1;
    result.not_attempted = 1;
    result.retry_available = true;
    result.transaction_ids << QStringLiteral("deadbeefcafebabe");
    result.failures << QStringLiteral("deadbeefcafebabe: stored, not relayed");
    dialog.setResult(result);
    auto* result_detail{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalResultDetail"))};
    auto* retry{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalRetryButton"))};
    QVERIFY(result_detail);
    QVERIFY(retry);
    QCOMPARE(pages->currentIndex(), 3);
    QVERIFY(result_detail->text().contains(QStringLiteral("deadbeefcafebabe")));
    QVERIFY(retry->isVisible());

    dialog.setPrivacy(true);
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("deadbeefcafebabe")));
    QVERIFY(!VisibleText(dialog).contains(QStringLiteral("2 transactions")));
    QVERIFY(retry->isHidden());
    QVERIFY(!retry->isEnabled());
    dialog.setPrivacy(false);
    QVERIFY(result_detail->text().contains(QStringLiteral("deadbeefcafebabe")));
    QVERIFY(retry->isVisible());
    QVERIFY(retry->isEnabled());
}

void VaultRenewalTests::adaptiveRendering()
{
    std::unique_ptr<const PlatformStyle> style{PlatformStyle::instantiate(QStringLiteral("other"))};
    QVERIFY(style);
    const QByteArray destination{qgetenv("VAULT_RENEWAL_SHOTS")};
    if (!destination.isEmpty()) QVERIFY(QDir().mkpath(QString::fromLocal8Bit(destination)));

    const QPalette original{QApplication::palette()};
    for (const bool dark : {false, true}) {
        QPalette palette{original};
        if (dark) {
            palette.setColor(QPalette::Window, QColor(30, 32, 35));
            palette.setColor(QPalette::WindowText, QColor(236, 238, 241));
            palette.setColor(QPalette::Base, QColor(24, 26, 29));
            palette.setColor(QPalette::AlternateBase, QColor(42, 45, 49));
            palette.setColor(QPalette::Text, QColor(236, 238, 241));
            palette.setColor(QPalette::Button, QColor(48, 51, 56));
            palette.setColor(QPalette::ButtonText, QColor(236, 238, 241));
        }
        QApplication::setPalette(palette);

        for (const QSize size : {QSize{760, 600}, QSize{900, 620}, QSize{1200, 800}}) {
            VaultRenewalDialog dialog{style.get()};
            dialog.setAvailableGroups(Groups(/*due=*/true), /*due=*/true);
            dialog.start(/*due=*/true);
            auto plan{DuePlan()};
            plan.signers_ready = true;
            plan.unavailable_reason.clear();
            dialog.setPlan(plan);
            Show(dialog, size);

            auto* scroll{dialog.findChild<QScrollArea*>(QStringLiteral("vaultRenewalPlanScroll"))};
            auto* review{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalReviewButton"))};
            auto* first_group{dialog.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck1"))};
            auto* second_group{dialog.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck2"))};
            auto* third_group{dialog.findChild<QCheckBox*>(QStringLiteral("vaultRenewalGroupCheck3"))};
            auto* intro{dialog.findChild<QLabel*>(QStringLiteral("vaultRenewalIntroduction"))};
            QVERIFY(scroll);
            QVERIFY(review);
            QVERIFY(first_group);
            QVERIFY(second_group);
            QVERIFY(third_group);
            QVERIFY(intro);
            QVERIFY(!first_group->isChecked());
            QVERIFY(second_group->isChecked());
            QVERIFY(third_group->isChecked());
            QCOMPARE(scroll->horizontalScrollBarPolicy(), Qt::ScrollBarAlwaysOff);
            QVERIFY(!review->accessibleDescription().isEmpty() || !review->accessibleName().isEmpty() || !review->text().isEmpty());
            QVERIFY(!intro->accessibleName().isEmpty() || !intro->text().isEmpty());
            QVERIFY(review->mapTo(&dialog, QPoint{0, review->height()}).y() <= dialog.height());

            second_group->setFocus();
            QWidget* const before_tab{QApplication::focusWidget()};
            QTest::keyClick(second_group, Qt::Key_Tab);
            QVERIFY(QApplication::focusWidget());
            QVERIFY(QApplication::focusWidget() != before_tab);

            if (!destination.isEmpty() && size == QSize{900, 620}) {
                const QString theme{dark ? QStringLiteral("dark") : QStringLiteral("light")};
                const auto capture = [&](QWidget& widget, const QString& state) {
                    widget.show();
                    QCoreApplication::sendPostedEvents(nullptr, QEvent::LayoutRequest);
                    QApplication::processEvents();
                    const QString name{theme + QStringLiteral("-renewal-") + state + QStringLiteral(".png")};
                    const QString path{QDir(QString::fromLocal8Bit(destination)).filePath(name)};
                    QVERIFY2(widget.grab().save(path, "PNG"), qPrintable(path));
                    QVERIFY(QFileInfo(path).size() > 0);
                };

                capture(dialog, QStringLiteral("due-plan"));
                dialog.setSignerReadiness(
                    false, QStringLiteral("Connect the exact hardware participant 33333333."),
                    {QStringLiteral("Participant 11111111 · Local key ready"),
                     QStringLiteral("Participant 22222222 · Local key ready"),
                     QStringLiteral("Participant 33333333 · Hardware unavailable")});
                capture(dialog, QStringLiteral("signer-blocked"));

                dialog.setBatch(DueExactBatch());
                QCoreApplication::sendPostedEvents(nullptr, QEvent::LayoutRequest);
                QApplication::processEvents();
                auto* first_batch{dialog.findChild<QFrame*>(QStringLiteral("vaultRenewalBatch1"))};
                QVERIFY(first_batch);
                QVERIFY(first_batch->height() > 30);
                QVERIFY(VisibleText(*first_batch).contains(QStringLiteral("Transaction 1")));
                capture(dialog, QStringLiteral("exact-review"));
                auto* sign{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalSignButton"))};
                QVERIFY(sign);
                sign->click();
                dialog.setSigningProgress(
                    1, 2, QStringLiteral("Transaction 2 of 2: waiting for connected hardware confirmations."));
                capture(dialog, QStringLiteral("signing-progress"));
                dialog.setCancellationPending();
                capture(dialog, QStringLiteral("cancel-pending"));

                VaultRenewalResultPresentation partial;
                partial.relayed = 1;
                partial.stored_not_relayed = 1;
                partial.not_attempted = 1;
                partial.retry_available = true;
                partial.failures = {
                    QStringLiteral("a1b2c3: relayed"),
                    QStringLiteral("d4e5f6: stored, not relayed"),
                    QStringLiteral("group-c: not attempted"),
                };
                dialog.setResult(partial);
                capture(dialog, QStringLiteral("partial-result"));

                VaultRenewalDialog early{style.get()};
                early.setAvailableGroups(Groups(/*due=*/false), /*due=*/false);
                early.start(/*due=*/false);
                auto early_plan{ReadOnlyPlan()};
                early_plan.signers_ready = true;
                early_plan.unavailable_reason.clear();
                early.setPlan(early_plan);
                Show(early, size);
                capture(early, QStringLiteral("early-plan"));
                early.close();
            }
            dialog.close();
        }
    }
    QApplication::setPalette(original);

    const QFont original_font{QApplication::font()};
    QFont enlarged{original_font};
    enlarged.setPointSize(std::max(14, original_font.pointSize() + 4));
    QApplication::setFont(enlarged);
    {
        VaultRenewalDialog dialog{style.get()};
        dialog.setAvailableGroups(Groups(/*due=*/false), /*due=*/false);
        dialog.start(/*due=*/false);
        dialog.setBatch(ExactBatch());
        Show(dialog, QSize{760, 600});
        auto* sign{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalSignButton"))};
        QVERIFY(sign);
        sign->click();
        dialog.setSigningProgress(
            0, 3,
            QStringLiteral("Waiting for several exact hardware participants with deliberately expanded localized names."));
        auto* progress_scroll{dialog.findChild<QScrollArea*>(QStringLiteral("vaultRenewalProgressScroll"))};
        auto* cancel{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalCancelProgressButton"))};
        QVERIFY(progress_scroll);
        QVERIFY(cancel);
        QCOMPARE(progress_scroll->horizontalScrollBarPolicy(), Qt::ScrollBarAlwaysOff);
        progress_scroll->ensureWidgetVisible(cancel);
        QApplication::processEvents();
        const QPoint cancel_bottom{cancel->mapTo(
            progress_scroll->viewport(), QPoint{0, cancel->height()})};
        QVERIFY(cancel_bottom.y() >= 0);
        QVERIFY(cancel_bottom.y() <= progress_scroll->viewport()->height());

        VaultRenewalResultPresentation result;
        result.stored_not_relayed = 1;
        result.not_attempted = 12;
        result.retry_available = true;
        for (int index{0}; index < 13; ++index) {
            result.failures << QStringLiteral(
                                   "Expanded localized transaction detail %1: this unchanged privacy group remains pending or was not attempted.")
                                   .arg(index + 1);
        }
        dialog.setResult(result);
        auto* result_scroll{dialog.findChild<QScrollArea*>(QStringLiteral("vaultRenewalResultScroll"))};
        auto* retry{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalRetryButton"))};
        auto* done{dialog.findChild<QPushButton*>(QStringLiteral("vaultRenewalDoneButton"))};
        QVERIFY(result_scroll);
        QVERIFY(retry);
        QVERIFY(done);
        QCOMPARE(result_scroll->horizontalScrollBarPolicy(), Qt::ScrollBarAlwaysOff);
        for (QPushButton* action : {retry, done}) {
            result_scroll->ensureWidgetVisible(action);
            action->setFocus();
            QApplication::processEvents();
            const QPoint bottom{action->mapTo(
                result_scroll->viewport(), QPoint{0, action->height()})};
            QVERIFY(bottom.y() >= 0);
            QVERIFY(bottom.y() <= result_scroll->viewport()->height());
            QVERIFY(action->hasFocus());
        }
    }
    QApplication::setFont(original_font);
}

void VaultRenewalTests::reminderDecisions()
{
    using Decision = OverviewPage::VaultRenewalReminderDecision;
    const auto decide = [](const std::string& due, const QString& prior,
                           bool privacy = false, bool ibd = false) {
        return OverviewPage::vaultRenewalReminderDecision(due, prior, privacy, ibd);
    };

    Decision decision{decide("set-a", {})};
    QVERIFY(decision.notify);
    QVERIFY(!decision.clear);
    decision = decide("set-a", QStringLiteral("set-a"));
    QVERIFY(!decision.notify);
    QVERIFY(!decision.clear);
    decision = decide("set-a", {}, /*privacy=*/true);
    QVERIFY(!decision.notify);
    decision = decide("set-a", {}, /*privacy=*/false, /*ibd=*/true);
    QVERIFY(!decision.notify);
    decision = decide({}, QStringLiteral("set-a"), /*privacy=*/true);
    QVERIFY(!decision.notify);
    QVERIFY(decision.clear);
    // Clearing ends the cycle, so the same digest may notify if it becomes
    // actionable again after renewal, abandonment, or reorg.
    decision = decide("set-a", {});
    QVERIFY(decision.notify);

    // Moving to a legacy/custom policy ends the current supported-policy
    // cycle. If the supported policy later returns, the same due set is new.
    decision = OverviewPage::vaultRenewalReminderDecision(
        "set-a", QStringLiteral("set-a"), /*privacy=*/false,
        /*initial_block_download=*/false, /*supported=*/false);
    QVERIFY(!decision.notify);
    QVERIFY(decision.clear);
    decision = decide("set-a", {});
    QVERIFY(decision.notify);
}

void VaultRenewalTests::signerReadiness()
{
    using Availability = interfaces::Wallet::VaultSignerAvailability;
    using Type = interfaces::Wallet::VaultParticipantType;
    interfaces::Wallet::VaultStatus status;
    status.signer_discovery_complete = true;
    status.participants = {
        Participant("11111111", Type::LOCAL_SOFTWARE, Availability::AVAILABLE),
        Participant("22222222", Type::LOCAL_SOFTWARE, Availability::AVAILABLE),
        Participant("33333333", Type::LOCAL_SOFTWARE, Availability::AVAILABLE),
    };

    auto presentation{PresentVaultRenewalSigners(status)};
    QVERIFY(presentation.ready);
    QCOMPARE(presentation.roster.size(), 3);
    QVERIFY(presentation.roster.front().contains(QStringLiteral("Local key ready")));

    status.participants[2] = Participant("33333333", Type::HARDWARE, Availability::AVAILABLE);
    status.signer_discovery_complete = false;
    presentation = PresentVaultRenewalSigners(status);
    QVERIFY(!presentation.ready);
    QVERIFY(presentation.reason.contains(QStringLiteral("not fresh"), Qt::CaseInsensitive));
    QVERIFY(presentation.roster.back().contains(QStringLiteral("unknown"), Qt::CaseInsensitive));

    status.signer_discovery_complete = true;
    presentation = PresentVaultRenewalSigners(status);
    QVERIFY(presentation.ready);
    QVERIFY(presentation.roster.back().contains(QStringLiteral("confirmations"), Qt::CaseInsensitive));

    status.participants[2].availability = Availability::UNAVAILABLE;
    presentation = PresentVaultRenewalSigners(status);
    QVERIFY(!presentation.ready);
    QVERIFY(presentation.reason.contains(QStringLiteral("Connect"), Qt::CaseInsensitive));

    status.participants[2] = Participant("33333333", Type::AIR_GAPPED, Availability::UNAVAILABLE);
    presentation = PresentVaultRenewalSigners(status);
    QVERIFY(!presentation.ready);
    QVERIFY(presentation.reason.contains(QStringLiteral("PSBT"), Qt::CaseInsensitive));

    status.participants[2] = Participant("33333333", Type::UNKNOWN, Availability::UNKNOWN);
    presentation = PresentVaultRenewalSigners(status);
    QVERIFY(!presentation.ready);
    QVERIFY(presentation.reason.contains(QStringLiteral("unknown"), Qt::CaseInsensitive));

    status.participants[2] = Participant("33333333", Type::HARDWARE, Availability::AVAILABLE);
    status.manually_lost_signers = {"33333333"};
    presentation = PresentVaultRenewalSigners(status);
    QVERIFY(!presentation.ready);
    QVERIFY(presentation.reason.contains(QStringLiteral("marked lost"), Qt::CaseInsensitive));
    QVERIFY(presentation.roster.back().contains(QStringLiteral("renewal blocked"), Qt::CaseInsensitive));

    status.manually_lost_signers.clear();
    status.participants.pop_back();
    presentation = PresentVaultRenewalSigners(status);
    QVERIFY(!presentation.ready);
    QVERIFY(presentation.reason.contains(QStringLiteral("three-participant"), Qt::CaseInsensitive));
}
