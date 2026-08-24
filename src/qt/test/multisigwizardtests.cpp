// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/multisigwizardtests.h>

#include <addresstype.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <hwi/mock.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <node/context.h>
#include <outputtype.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <qt/bitcoinamountfield.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/multisigwizard.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/qrimagewidget.h>
#include <qt/receivecoinsdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <psbt.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/test/util.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <span.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <support/allocators/secure.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/rbf.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/multisig.h>
#include <wallet/vault_policy_qr.h>
#include <wallet/walletutil.h>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QItemSelectionModel>
#include <QComboBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QLockFile>
#include <QMessageBox>
#include <QPalette>
#include <QPixmap>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QRadioButton>
#include <QSignalSpy>
#include <QSpinBox>
#include <QTableView>
#include <QTabWidget>
#include <QTest>
#include <QTemporaryDir>
#include <QTextDocument>
#include <QTimer>
#include <QVBoxLayout>
#include <QWizard>

#include <array>
#include <chrono>
#include <limits>
#include <memory>
#include <optional>
#include <set>

namespace {
const QStringList kShotNames = [] {
    const QStringList states{
        QStringLiteral("review-0"),
        QStringLiteral("review-1"),
        QStringLiteral("review-2"),
        QStringLiteral("review-3"),
        QStringLiteral("review-too-many-failure"),
        QStringLiteral("secure-recovery-before-print"),
        QStringLiteral("secure-recovery-after-print"),
        QStringLiteral("confirm-review"),
        QStringLiteral("confirm-verify"),
        QStringLiteral("ready"),
        QStringLiteral("overview"),
        QStringLiteral("send-normal"),
        QStringLiteral("send-first-recovery"),
        QStringLiteral("send-final-recovery"),
        QStringLiteral("send-lost-signer"),
        QStringLiteral("restore-policy"),
        QStringLiteral("restore-key-1"),
        QStringLiteral("restore-key-2"),
        QStringLiteral("restore-key-3"),
        QStringLiteral("restore-rescan"),
        QStringLiteral("restore-public-only"),
        QStringLiteral("restore-error"),
    };
    QStringList names;
    for (const QString& theme : {QStringLiteral("light"), QStringLiteral("dark")}) {
        for (const QString& state : states) names << theme + QLatin1Char('-') + state;
    }
    return names;
}();

bool PublicOnlyDescriptors(const std::vector<std::string>& descriptors, QString& error)
{
    for (const std::string& encoded : descriptors) {
        FlatSigningProvider keys;
        std::string parse_error;
        auto parsed = Parse(encoded, keys, parse_error, /*require_checksum=*/true);
        if (parsed.empty()) {
            error = QStringLiteral("Descriptor did not parse: %1").arg(QString::fromStdString(parse_error));
            return false;
        }
        for (const auto& descriptor : parsed) {
            std::string private_form;
            if (descriptor->ToPrivateString(keys, private_form)) {
                error = QStringLiteral("Policy package contains private key material");
                return false;
            }
        }
        if (!keys.keys.empty()) {
            error = QStringLiteral("Policy package parser recovered private keys");
            return false;
        }
    }
    return true;
}

void ShowSized(MultisigWizard& wizard)
{
    wizard.resize(900, 620);
    wizard.show();
    // The "minimal" QPA used by test_bitcoin-qt does not expose a native
    // window, so qWaitForWindowExposed would time out. grab() still paints.
    QApplication::processEvents();
    QTest::qWait(50);
}

void Grab(QWidget& widget, const QString& dir, const QString& name)
{
    QApplication::processEvents();
    QPixmap pix(widget.size());
    pix.fill(widget.palette().color(QPalette::Window));
    widget.render(&pix);
    QVERIFY2(pix.width() >= 400 && pix.height() >= 300,
             qPrintable(QStringLiteral("%1 grab was %2x%3").arg(name).arg(pix.width()).arg(pix.height())));
    const QString path = dir + QLatin1Char('/') + name + QStringLiteral(".png");
    QVERIFY2(pix.save(path, "PNG"), qPrintable(QStringLiteral("failed to write ") + path));
}

QString VisibleText(const QWidget& root)
{
    QStringList text;
    for (const auto* label : root.findChildren<QLabel*>()) {
        if (label->isVisible()) text << label->text();
    }
    for (const auto* button : root.findChildren<QAbstractButton*>()) {
        if (button->isVisible()) text << button->text();
    }
    return text.join(QLatin1Char('\n'));
}

int OutputTypeIndex(const QComboBox& combo, OutputType type)
{
    for (int i = 0; i < combo.count(); ++i) {
        if (combo.itemData(i).toInt() == static_cast<int>(type)) return i;
    }
    return -1;
}

void AssertBackupPage(MultisigWizard& wizard, std::optional<uint32_t> older = {}, std::optional<uint32_t> after = {},
                      std::optional<uint32_t> one_key_older = {}, bool committed_journey = true)
{
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
    auto* policy = wizard.findChild<QPlainTextEdit*>("policyPackageEdit");
    auto* transcript = wizard.findChild<QPlainTextEdit*>("humanTranscriptEdit");
    auto* tabs = wizard.findChild<QTabWidget*>("backupTabs");
    auto* copy_policy = wizard.findChild<QPushButton*>("copyPolicyButton");
    auto* copy_transcript = wizard.findChild<QPushButton*>("copyTranscriptButton");
    auto* save_transcript = wizard.findChild<QPushButton*>("saveTranscriptButton");
    auto* print_policy = wizard.findChild<QPushButton*>("printPolicyButton");
    auto* policy_path = wizard.findChild<QLabel*>("policyPackagePathLabel");
    auto* retry_policy = wizard.findChild<QPushButton*>("retryPolicySaveButton");
    auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
    auto* wallet_backup = wizard.findChild<QPushButton*>("backupSoftwareWalletButton");
    auto* wallet_backup_status = wizard.findChild<QLabel*>("softwareWalletBackupStatus");
    auto* wallet_backup_ack = wizard.findChild<QCheckBox*>("localWalletBackupAckCheck");
    auto* mnemonic_risk_ack = wizard.findChild<QCheckBox*>("mnemonicPrintRiskAckCheck");
    auto* mnemonic_ack = wizard.findChild<QCheckBox*>("mnemonicPrintAckCheck");
    auto* mnemonic_entry = wizard.findChild<QLineEdit*>("mnemonicVerificationEdit");
    auto* verify_mnemonic = wizard.findChild<QPushButton*>("verifyMnemonicButton");
    QVERIFY(policy);
    QVERIFY(transcript);
    QVERIFY(tabs);
    QVERIFY(copy_policy);
    QVERIFY(copy_transcript);
    QVERIFY(save_transcript);
    QVERIFY(print_policy);
    QVERIFY(policy_path);
    QVERIFY(retry_policy);
    QVERIFY(ack);
    QVERIFY(wallet_backup);
    QVERIFY(wallet_backup_status);
    QVERIFY(wallet_backup_ack);
    QVERIFY(!mnemonic_risk_ack);
    QVERIFY(!mnemonic_ack);
    QVERIFY(!mnemonic_entry);
    QVERIFY(!verify_mnemonic);
    QVERIFY(!wizard.findChild<QPushButton*>("savePolicyButton"));

    const bool fixed_flow = !wizard.advancedFlow();
    if (fixed_flow) {
        QVERIFY(!wizard.createdWallet());
        // The default staged-vault backup is intentionally a single-action
        // page: one Print PDF button, one final acknowledgment, and the
        // wizard's Continue button. The advanced policy tools still exist for
        // the advanced journey, but none may leak into this page.
        QVERIFY(print_policy->isVisible());
        QCOMPARE(print_policy->text(), QStringLiteral("Print PDF…"));
        QVERIFY(print_policy->isEnabled());
        QVERIFY(ack->isVisible());
        QCOMPARE(ack->text(), QStringLiteral("I understand"));
        QVERIFY(!ack->isEnabled());
        QVERIFY(!ack->isChecked());

        QList<QCheckBox*> visible_checks;
        for (auto* checkbox : wizard.currentPage()->findChildren<QCheckBox*>()) {
            if (checkbox->isVisible()) visible_checks.push_back(checkbox);
        }
        QCOMPARE(visible_checks.size(), 1);
        QCOMPARE(visible_checks.front(), ack);
        QList<QPushButton*> visible_actions;
        for (auto* button : wizard.currentPage()->findChildren<QPushButton*>()) {
            if (button->isVisible()) visible_actions.push_back(button);
        }
        QCOMPARE(visible_actions.size(), 1);
        QCOMPARE(visible_actions.front(), print_policy);

        QVERIFY(!tabs->isVisible());
        QVERIFY(!copy_policy->isVisible());
        QVERIFY(!copy_transcript->isVisible());
        QVERIFY(!save_transcript->isVisible());
        QVERIFY(!policy_path->isVisible());
        QVERIFY(!retry_policy->isVisible());
        QVERIFY(!wallet_backup->isVisible());
        QVERIFY(!wallet_backup_status->isVisible());
        QVERIFY(!wallet_backup_ack->isVisible());
        QVERIFY(!wizard.button(QWizard::BackButton)->isVisible());
        QVERIFY(!wizard.button(QWizard::CancelButton)->isVisible());
        QVERIFY(!wizard.button(QWizard::CommitButton)->isVisible());
        QVERIFY(!wizard.button(QWizard::FinishButton)->isVisible());
        QVERIFY(wizard.button(QWizard::NextButton)->isVisible());
        QString continue_text = wizard.button(QWizard::NextButton)->text();
        continue_text.remove(QLatin1Char('&'));
        QCOMPARE(continue_text, QStringLiteral("Continue"));
        QList<QPushButton*> visible_buttons;
        for (auto* button : wizard.findChildren<QPushButton*>()) {
            if (button->isVisible()) visible_buttons.push_back(button);
        }
        QCOMPARE(visible_buttons.size(), 2);
        QVERIFY(visible_buttons.contains(print_policy));
        QVERIFY(visible_buttons.contains(qobject_cast<QPushButton*>(wizard.button(QWizard::NextButton))));
    } else {
        QVERIFY(wizard.createdWallet());
        QVERIFY(tabs->isVisible());
        QVERIFY(copy_policy->isVisible());
        QVERIFY(copy_policy->isEnabled());
        QVERIFY(copy_transcript->isVisible());
        QVERIFY(copy_transcript->isEnabled());
        QVERIFY(save_transcript->isVisible());
        QVERIFY(print_policy->isVisible());
        QVERIFY(print_policy->isEnabled());
        QVERIFY(print_policy->text().contains(QStringLiteral("public"), Qt::CaseInsensitive));
        QVERIFY(ack->isVisible());
        QVERIFY(ack->isEnabled());
        if (wizard.localKeyCount() > 0) {
            QVERIFY(wallet_backup->isVisible());
            QVERIFY(wallet_backup_status->isVisible());
            QVERIFY(wallet_backup_ack->isVisible());
            QVERIFY(!wallet_backup_ack->isEnabled());
            QVERIFY(!wallet_backup_ack->isChecked());
            QVERIFY(wallet_backup_status->text().contains(QStringLiteral("Required"), Qt::CaseInsensitive));
        } else {
            QVERIFY(!wallet_backup->isVisible());
            QVERIFY(!wallet_backup_status->isVisible());
            QVERIFY(!wallet_backup_ack->isVisible());
        }
    }

    const QString package_text = policy->toPlainText();
    const auto parsed = wallet::ParseVaultPolicyPackage(package_text.toStdString());
    QVERIFY2(parsed, qPrintable(QString::fromStdString(util::ErrorString(parsed).original)));
    QCOMPARE(QString::fromStdString(parsed->format), QStringLiteral("bitcoin-core-vault-policy"));
    QCOMPARE(parsed->version, 1);
    QCOMPARE(parsed->fallback_older, older);
    QCOMPARE(parsed->fallback_after, after);
    QCOMPARE(parsed->fallback_older_one_key, one_key_older);
    QCOMPARE(parsed->descs.size(), size_t{2});
    QCOMPARE(QString::fromStdString(parsed->policy_id), QString::fromStdString(wallet::VaultPolicyId(parsed->descs.front())));
    QCOMPARE(QString::fromStdString(parsed->network), QString::fromStdString(Params().GetChainTypeString()));
    QCOMPARE(parsed->nrequired, wizard.nrequired());
    QCOMPARE(package_text.trimmed(), QString::fromStdString(wallet::FormatVaultPolicyPackage(*parsed)).trimmed());
    QString public_error;
    QVERIFY2(PublicOnlyDescriptors(parsed->descs, public_error), qPrintable(public_error));
    QVERIFY(!package_text.contains(QStringLiteral("human transcript"), Qt::CaseInsensitive));
    QVERIFY(parsed->descs.front() != parsed->descs.back());

    // The importable public policy is persisted without a save dialog, under
    // a policy-derived (and therefore path-safe) name in the network datadir.
    QDir network_dir{GUIUtil::PathToQString(gArgs.GetDataDirNet())};
    QVERIFY(network_dir.exists());
    const QString policy_filename = QStringLiteral("vault-policy-%1.json").arg(
        QString::fromStdString(parsed->policy_id));
    const QString saved_policy_path = QFileInfo{network_dir.filePath(policy_filename)}.absoluteFilePath();
    QCOMPARE(QFileInfo{saved_policy_path}.absolutePath(), QFileInfo{network_dir.absolutePath()}.absoluteFilePath());
    QCOMPARE(QFileInfo{saved_policy_path}.fileName(), policy_filename);
    QFile saved_policy{saved_policy_path};
    QVERIFY2(saved_policy.open(QIODevice::ReadOnly), qPrintable(saved_policy.errorString()));
    const QByteArray expected_package = package_text.toUtf8();
    QCOMPARE(saved_policy.readAll(), expected_package);
    QCOMPARE(policy_path->text(), QDir::toNativeSeparators(saved_policy_path));

    const QString human = transcript->toPlainText();
    QVERIFY(human.contains(wizard.walletName()));
    QVERIFY(human.contains(QStringLiteral("## Descriptors")));
    QVERIFY(!human.contains(QStringLiteral("bitcoin-core-vault-policy")));
    if (!fixed_flow) {
        copy_policy->click();
        QCOMPARE(QApplication::clipboard()->text(), package_text);
        copy_transcript->click();
        QCOMPARE(QApplication::clipboard()->text(), human);
    }
    QVERIFY(!ack->isChecked());
    if (!fixed_flow && committed_journey) {
        QVERIFY(wizard.testOption(QWizard::NoCancelButton));
        QVERIFY(!wizard.button(QWizard::CancelButton)->isVisible());
    } else if (fixed_flow) {
        QVERIFY(!wizard.testOption(QWizard::NoCancelButton));
    }
    QApplication::processEvents();
    QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
    if (!fixed_flow && wizard.localKeyCount() > 0) {
        // Automatic public-policy persistence must never be mistaken for the
        // private software-key wallet backup required to spend or recover.
        ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        ack->setChecked(false);
        QApplication::processEvents();
    }
}

void CompleteBackupPage(MultisigWizard& wizard)
{
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
    auto* policy_ack = wizard.findChild<QCheckBox*>("backupAckCheck");
    auto* print = wizard.findChild<QPushButton*>("printPolicyButton");
    auto* wallet_backup = wizard.findChild<QPushButton*>("backupSoftwareWalletButton");
    auto* wallet_backup_ack = wizard.findChild<QCheckBox*>("localWalletBackupAckCheck");
    QVERIFY(policy_ack);
    QVERIFY(print);
    QVERIFY(wallet_backup);
    QVERIFY(wallet_backup_ack);

    if (!wizard.advancedFlow()) {
        // Fixed staged recovery has no alternate wallet-file or inline phrase
        // workflow. A successful one-click aggregate PDF is what unlocks the
        // sole acknowledgment; cleanup is checked when the caller continues.
        MultisigWizardTests url_sink{wizard.node()};
        struct UrlHandlerGuard {
            ~UrlHandlerGuard() { QDesktopServices::unsetUrlHandler(QStringLiteral("file")); }
        } handler_guard;
        QDesktopServices::setUrlHandler(QStringLiteral("file"), &url_sink, "captureRecoveryUrl");
        QString print_error;
        QTimer print_error_closer;
        QObject::connect(&print_error_closer, &QTimer::timeout, [&print_error] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                    print_error = box->text();
                    box->accept();
                }
            }
        });
        print_error_closer.start(10);
        print->click();
        print_error_closer.stop();
        QVERIFY2(print_error.isEmpty(), qPrintable(print_error));
        QTRY_COMPARE_WITH_TIMEOUT(url_sink.m_opened_recovery_count, 1, 5000);
        QVERIFY(url_sink.m_opened_recovery_url.isLocalFile());
        QVERIFY(QFileInfo::exists(url_sink.m_opened_recovery_url.toLocalFile()));
        QVERIFY(policy_ack->isEnabled());
        QVERIFY(!policy_ack->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        policy_ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
        QVERIFY(!wizard.button(QWizard::BackButton)->isVisible());
        QVERIFY(!wizard.button(QWizard::CancelButton)->isVisible());
        return;
    }

    if (wizard.localKeyCount() > 0) {
        QTemporaryDir backup_dir;
        QVERIFY(backup_dir.isValid());
        const QString backup_path = backup_dir.filePath(QStringLiteral("software-keys-wallet.dat"));
        QTimer::singleShot(0, [backup_path] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* dialog = qobject_cast<QFileDialog*>(widget)) {
                    dialog->selectFile(backup_path);
                    QMetaObject::invokeMethod(dialog, "accept", Qt::DirectConnection);
                }
            }
        });
        wallet_backup->click();
        QApplication::processEvents();
        QVERIFY2(QFileInfo::exists(backup_path), qPrintable(backup_path));
        QVERIFY(wallet_backup_ack->isEnabled());
        QVERIFY(!wallet_backup_ack->isChecked());
        wallet_backup_ack->setChecked(true);
    }
    policy_ack->setChecked(true);
    QApplication::processEvents();
    QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
}

void CompleteVerification(MultisigWizard& wizard)
{
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
    auto* devices = wizard.findChild<QListWidget*>("verifyDeviceList");
    auto* show = wizard.findChild<QPushButton*>("showOnDeviceButton");
    auto* status = wizard.findChild<QLabel*>("verifyStatusLabel");
    QVERIFY(devices);
    QVERIFY(show);
    QVERIFY(status);
    for (int row = 0; row < devices->count(); ++row) {
        devices->setCurrentRow(row);
        show->click();
        QApplication::processEvents();
        QVERIFY2(devices->item(row)->text().startsWith(QStringLiteral("✓")),
                 qPrintable(status->text() + QStringLiteral(" | ") + devices->item(row)->text()));
        QVERIFY(status->text().contains(QStringLiteral("physical device matches this wallet"), Qt::CaseInsensitive));
    }
    auto* air = wizard.findChild<QCheckBox*>("airgapVerifyCheck");
    auto* local = wizard.findChild<QCheckBox*>("localOnlyVerifyCheck");
    QVERIFY(air);
    QVERIFY(local);
    if (!air->isHidden()) air->setChecked(true);
    if (wizard.advancedFlow() && !local->isHidden()) local->setChecked(true);
    QApplication::processEvents();
    QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
}

void WalkTo(MultisigWizard& wizard, int page)
{
    int guard = 0;
    while (wizard.currentId() != page && guard++ < 12) {
        if (wizard.currentId() == MultisigWizard::Page_Backup) {
            CompleteBackupPage(wizard);
        }
        if (wizard.currentId() == MultisigWizard::Page_Verify) {
            CompleteVerification(wizard);
        }
        QVERIFY2(wizard.nextId() != -1 || wizard.currentId() == page,
                 "wizard has no next page");
        wizard.next();
    }
    QCOMPARE(wizard.currentId(), page);
}

void ConfirmSend(QString* text = nullptr, QMessageBox::StandardButton confirm_type = QMessageBox::Yes)
{
    QTimer::singleShot(0, [text, confirm_type]() {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog")) {
                auto* dialog = qobject_cast<SendConfirmationDialog*>(widget);
                if (text) *text = dialog->text();
                QAbstractButton* button = dialog->button(confirm_type);
                button->setEnabled(true);
                button->click();
            }
        }
    });
}

void LoseSignerAndConfirm(WalletModel& model, std::string fingerprint)
{
    QTimer::singleShot(0, [&model, fingerprint = std::move(fingerprint)]() {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (!widget->inherits("SendConfirmationDialog")) continue;
            auto* dialog = qobject_cast<SendConfirmationDialog*>(widget);
            model.wallet().setLostSigner(fingerprint, true);
            QAbstractButton* button = dialog->button(QMessageBox::Yes);
            Assert(button);
            button->setEnabled(true);
            button->click();
        }
    });
}

Txid SendFromDialog(SendCoinsDialog& send, const QString& address, CAmount amount, QString* confirm = nullptr)
{
    auto* entries = send.findChild<QVBoxLayout*>("entries");
    Assert(entries);
    auto* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    Assert(entry);
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(address);
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(amount);
    Txid txid;
    QObject::connect(&send, &SendCoinsDialog::coinsSent, [&txid](const Txid& hash) { txid = hash; });
    ConfirmSend(confirm);
    Assert(QMetaObject::invokeMethod(&send, "sendButtonClicked", Q_ARG(bool, false)));
    Assert(!txid.IsNull());
    return txid;
}

QModelIndex FindTx(const QAbstractItemModel& model, const Txid& txid)
{
    const QString hash = QString::fromStdString(txid.ToString());
    for (int row = 0; row < model.rowCount({}); ++row) {
        QModelIndex index = model.index(row, 0, {});
        if (model.data(index, TransactionTableModel::TxHashRole) == hash) return index;
    }
    return {};
}

void BumpFeeView(TransactionView& view, const Txid& txid)
{
    auto* table = view.findChild<QTableView*>("transactionView");
    Assert(table);
    QModelIndex index = FindTx(*table->selectionModel()->model(), txid);
    Assert(index.isValid());
    auto* action = view.findChild<QAction*>("bumpFeeAction");
    Assert(action);
    table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    table->customContextMenuRequested({});
    Assert(action->isEnabled());
    ConfirmSend();
    action->trigger();
}

struct AirKey {
    std::string fpr;
    std::string path;
    std::string xpub;
};

AirKey MakeAirKey()
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    const std::string path_str = wallet::DefaultMultisigPath(OutputType::BECH32M, /*account=*/0);
    std::vector<uint32_t> path;
    Assert(ParseHDKeypath(path_str, path));
    auto child = DeriveExtKey(master, path);
    Assert(child);
    const std::string hex = HexStr(master.id_key_fingerprint());
    return AirKey{
        hex.size() == 8 ? hex : hex.substr(0, 8),
        path_str,
        EncodeExtPubKey(child->first.Neuter()),
    };
}

void ConfigureStagedAirgapPolicy(MultisigWizard& wizard, const QString& wallet_name,
                                 const std::array<AirKey, 3>& keys)
{
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::StagedRecovery);
    wizard.applyTemplate();
    wizard.setWalletName(wallet_name);
    wizard.setLocalKeyCount(0);
    for (size_t i = 0; i < keys.size(); ++i) {
        const auto& key = keys[i];
        wizard.addAirgappedKey(key.fpr, key.path, key.xpub,
                               QStringLiteral("Offline key %1").arg(i + 1).toStdString());
    }
    wizard.rebuildKeyList();
    wizard.setNRequired(2);
    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(MultisigWizard::kThirtyDayVaultDelay);
    wizard.setFallbackOlderOneKey(MultisigWizard::kSixtyDayVaultDelay);
    wizard.setFallbackAfter(std::nullopt);
}

void WalkScroogeToDone(MultisigWizard& wizard, int nrequired, int delay_blocks)
{
    QSignalSpy created_spy(&wizard, &MultisigWizard::created);
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
    wizard.applyTemplate();
    wizard.setFallbackOlderOneKey(std::nullopt);
    QVERIFY(wizard.advancedFlow());
    const bool expect_preserved_off = delay_blocks == 0 && !wizard.fallbackOlder();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Template));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
    auto* name = wizard.findChild<QLineEdit*>("walletNameEdit");
    QVERIFY(name);
    name->setText(wizard.walletName());
    auto* type = wizard.findChild<QComboBox*>("scriptTypeCombo");
    QVERIFY(type);
    const int vault_idx = OutputTypeIndex(*type, OutputType::BECH32M);
    QVERIFY(vault_idx >= 0);
    type->setCurrentIndex(vault_idx);
    QVERIFY(wizard.validateCurrentPage());
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
    auto* local_count = wizard.findChild<QSpinBox*>("localSoftwareKeyCountSpin");
    auto* local_risk = wizard.findChild<QCheckBox*>("localSoftwareKeysRiskCheck");
    QVERIFY(local_count);
    QVERIFY(local_risk);
    QCOMPARE(local_count->value(), wizard.localKeyCount());
    if (local_risk->isVisible()) local_risk->setChecked(true);
    QApplication::processEvents();
    QVERIFY(wizard.validateCurrentPage());
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Threshold));
    auto* req = wizard.findChild<QSpinBox*>("nrequiredSpin");
    auto* older = wizard.findChild<QSpinBox*>("fallbackOlderSpin");
    QVERIFY(req);
    QVERIFY(older);
    if (expect_preserved_off) {
        QCOMPARE(older->value(), 0);
        QVERIFY(!wizard.fallbackOlder());
    }
    req->setValue(nrequired);
    older->setValue(delay_blocks);
    QApplication::processEvents();
    if (delay_blocks == 1) {
        QVERIFY(older->text().contains(QStringLiteral("1 block")));
        QVERIFY(!older->text().contains(QStringLiteral("1 blocks")));
        const QString policy_copy = VisibleText(*wizard.currentPage());
        QVERIFY(policy_copy.contains(QStringLiteral("1 block")));
        QVERIFY(!policy_copy.contains(QStringLiteral("1 blocks")));
    }
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
    QCOMPARE(created_spy.count(), 0);
    AssertBackupPage(wizard, delay_blocks > 0 ? std::optional<uint32_t>{static_cast<uint32_t>(delay_blocks)} : std::nullopt);
    if (delay_blocks == 1) {
        const auto* transcript = wizard.findChild<QPlainTextEdit*>("humanTranscriptEdit");
        QVERIFY(transcript);
        QVERIFY(transcript->toPlainText().contains(QStringLiteral("1 block")));
        QVERIFY(!transcript->toPlainText().contains(QStringLiteral("1 blocks")));
    }
    CompleteBackupPage(wizard);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
    CompleteVerification(wizard);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
    QCOMPARE(created_spy.count(), 1);
    if (delay_blocks == 1) {
        const QString done_copy = VisibleText(*wizard.currentPage());
        QVERIFY(done_copy.contains(QStringLiteral("1 block")));
        QVERIFY(!done_copy.contains(QStringLiteral("1 blocks")));
    }
}

void WalkStagedRecoveryToDone(MultisigWizard& wizard, int first_delay = 4320, int final_delay = 8640)
{
    QSignalSpy created_spy(&wizard, &MultisigWizard::created);
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::StagedRecovery);
    wizard.applyTemplate();
    QVERIFY(wizard.advancedFlow());
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Template));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
    auto* name = wizard.findChild<QLineEdit*>("walletNameEdit");
    auto* type = wizard.findChild<QComboBox*>("scriptTypeCombo");
    QVERIFY(name);
    QVERIFY(type);
    name->setText(wizard.walletName());
    type->setCurrentIndex(OutputTypeIndex(*type, OutputType::BECH32M));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
    auto* local_count = wizard.findChild<QSpinBox*>("localSoftwareKeyCountSpin");
    auto* local_warning = wizard.findChild<QLabel*>("localSoftwareKeysWarningLabel");
    auto* local_risk = wizard.findChild<QCheckBox*>("localSoftwareKeysRiskCheck");
    auto* key_count = wizard.findChild<QLabel*>("vaultKeyCount");
    QVERIFY(local_count);
    QVERIFY(local_warning);
    QVERIFY(local_risk);
    QVERIFY(key_count);
    QCOMPARE(local_count->minimum(), 0);
    QCOMPARE(local_count->maximum(), MultisigWizard::kMaxLocalSoftwareKeys);
    QCOMPARE(local_count->value(), wizard.localKeyCount());
    if (wizard.localKeyCount() > 1) {
        QVERIFY(local_risk->isVisible());
        QVERIFY(!local_risk->isChecked());
        QVERIFY(local_warning->text().contains(QStringLiteral("not independent"), Qt::CaseInsensitive));
        QVERIFY(key_count->text().contains(QStringLiteral("%1 software").arg(wizard.localKeyCount())));
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
    }
    if (local_risk->isVisible()) local_risk->setChecked(true);
    QApplication::processEvents();
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Threshold));
    if (wizard.localKeyCount() > 1) {
        wizard.back();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        QCOMPARE(local_count->value(), wizard.localKeyCount());
        QVERIFY(local_risk->isChecked());
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Threshold));
    }
    auto* required = wizard.findChild<QSpinBox*>("nrequiredSpin");
    auto* first = wizard.findChild<QSpinBox*>("fallbackOlderSpin");
    auto* staged = wizard.findChild<QCheckBox*>("stagedRecoveryCheck");
    auto* final = wizard.findChild<QSpinBox*>("finalRecoveryOlderSpin");
    auto* summary = wizard.findChild<QLabel*>("recoveryStagesSummaryLabel");
    QVERIFY(required);
    QVERIFY(first);
    QVERIFY(staged);
    QVERIFY(final);
    QVERIFY(summary);
    required->setValue(2);
    first->setValue(first_delay);
    staged->setChecked(true);
    final->setValue(final_delay);
    QApplication::processEvents();
    QCOMPARE(wizard.nrequired(), 2);
    QCOMPARE(*wizard.fallbackOlder(), static_cast<uint32_t>(first_delay));
    QCOMPARE(*wizard.fallbackOlderOneKey(), static_cast<uint32_t>(final_delay));
    QVERIFY(summary->text().contains(QString::number(first_delay)));
    QVERIFY(summary->text().contains(QString::number(final_delay)));
    QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
    wizard.next();
    AssertBackupPage(wizard, static_cast<uint32_t>(first_delay), {}, static_cast<uint32_t>(final_delay));
    const auto parsed = wallet::ParseVaultPolicyPackage(
        wizard.findChild<QPlainTextEdit*>("policyPackageEdit")->toPlainText().toStdString());
    QVERIFY(parsed);
    QVERIFY(parsed->descs.front().find("older(" + std::to_string(first_delay) + ")") != std::string::npos);
    QVERIFY(parsed->descs.front().find("older(" + std::to_string(final_delay) + ")") != std::string::npos);
    const QString transcript = wizard.findChild<QPlainTextEdit*>("humanTranscriptEdit")->toPlainText();
    QVERIFY(transcript.contains(QString::number(first_delay)));
    QVERIFY(transcript.contains(QString::number(final_delay)));
    if (wizard.localKeyCount() > 1) {
        QVERIFY(transcript.contains(QStringLiteral("cryptographically distinct")));
        QVERIFY(transcript.contains(QStringLiteral("not provide independent-device protection")));
        std::set<std::string> origins;
        const std::string& descriptor = parsed->descs.front();
        for (size_t pos = descriptor.find('['); pos != std::string::npos; pos = descriptor.find('[', pos + 1)) {
            if (pos + 9 <= descriptor.size()) {
                const std::string fingerprint = descriptor.substr(pos + 1, 8);
                if (IsHex(fingerprint)) origins.insert(fingerprint);
            }
        }
        QCOMPARE(origins.size(), static_cast<size_t>(wizard.localKeyCount()));
    }
    CompleteBackupPage(wizard);
    wizard.next();
    CompleteVerification(wizard);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
    QCOMPARE(created_spy.count(), 1);
    const QString done = VisibleText(*wizard.currentPage());
    QVERIFY(done.contains(QString::number(first_delay)));
    QVERIFY(done.contains(QString::number(final_delay)));
}

void WalkTemplateToDone(MultisigWizard& wizard,
                        MultisigWizard::VaultTemplate preset,
                        OutputType output_type,
                        int expected_keys,
                        int expected_active_keys,
                        int expected_nrequired,
                        std::optional<uint32_t> expected_older = {})
{
    QSignalSpy created_spy(&wizard, &MultisigWizard::created);
    wizard.setVaultTemplate(preset);
    wizard.applyTemplate();
    if (preset == MultisigWizard::VaultTemplate::Custom) {
        wizard.setFallbackOlderOneKey(std::nullopt);
    }
    QVERIFY(wizard.advancedFlow());
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Template));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
    QCOMPARE(wizard.outputType(), output_type);
    auto* name = wizard.findChild<QLineEdit*>("walletNameEdit");
    auto* type = wizard.findChild<QComboBox*>("scriptTypeCombo");
    QVERIFY(name);
    QVERIFY(type);
    name->setText(wizard.walletName());
    const int type_index = OutputTypeIndex(*type, output_type);
    QVERIFY(type_index >= 0);
    QCOMPARE(type->currentIndex(), type_index);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
    QCOMPARE(static_cast<int>(wizard.keys().size()), expected_keys);
    QCOMPARE(wizard.nActiveKeys(), expected_active_keys);
    auto* local_risk = wizard.findChild<QCheckBox*>("localSoftwareKeysRiskCheck");
    QVERIFY(local_risk);
    if (local_risk->isVisible()) local_risk->setChecked(true);
    QApplication::processEvents();
    QVERIFY(wizard.validateCurrentPage());
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Threshold));
    auto* required = wizard.findChild<QSpinBox*>("nrequiredSpin");
    QVERIFY(required);
    QCOMPARE(required->value(), expected_nrequired);
    QCOMPARE(wizard.nrequired(), expected_nrequired);
    QCOMPARE(wizard.fallbackOlder(), expected_older);
    QVERIFY(wizard.policyError().empty());
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
    QCOMPARE(created_spy.count(), 0);
    AssertBackupPage(wizard, expected_older);
    CompleteBackupPage(wizard);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
    CompleteVerification(wizard);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
    QCOMPARE(created_spy.count(), 1);
    QVERIFY(wizard.createdWallet());
}
} // namespace

void MultisigWizardTests::wizardTests()
{
    node::NodeContext context;
    context.args = &gArgs;
    m_node.setContext(&context);
    struct ContextReset {
        interfaces::Node& node;
        ~ContextReset() { node.setContext(nullptr); }
    } context_reset{m_node};
    hwi::UsbEnumerateSuppress suppress_usb;
    gArgs.ForceSetArg("-signer", "internal");

    MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
    QCOMPARE(wizard.startId(), static_cast<int>(MultisigWizard::Page_Keys));
    wizard.show();
    QApplication::processEvents();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
    QCOMPARE(wizard.currentPage()->title(), QStringLiteral("Create a Recovery Vault"));
    QCOMPARE(wizard.nextId(), static_cast<int>(MultisigWizard::Page_Backup));
    QVERIFY(!wizard.findChild<QCheckBox*>("localSoftwareKeysRiskCheck")->isVisible());
    const auto restore_buttons = wizard.findChildren<QPushButton*>("restoreFromMnemonicButton");
    QVERIFY(std::any_of(restore_buttons.begin(), restore_buttons.end(), [](const QPushButton* button) {
        return button->isVisible();
    }));
    QVERIFY(wizard.findChild<QPushButton*>("advancedVaultButton")->isVisible());

    wizard.setWalletName(QStringLiteral("Family"));
    QCOMPARE(wizard.localKeyCount(), MultisigWizard::kStagedVaultKeyCount);
    wizard.setLocalKeyCount(-1);
    QVERIFY(wizard.advancedFlow());
    wizard.restart();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));
    QCOMPARE(wizard.localKeyCount(), 0);
    QVERIFY(wizard.keys().empty());
    wizard.setLocalKeyCount(MultisigWizard::kMaxLocalSoftwareKeys + 1);
    QCOMPARE(wizard.localKeyCount(), MultisigWizard::kMaxLocalSoftwareKeys);
    QCOMPARE(static_cast<int>(wizard.keys().size()), MultisigWizard::kMaxLocalSoftwareKeys);
    QStringList local_labels;
    for (int i = 0; i < MultisigWizard::kMaxLocalSoftwareKeys; ++i) {
        const auto& key = wizard.keys().at(i);
        QVERIFY(key.generate_local);
        QVERIFY(!key.recovery_only);
        QVERIFY(!key.fingerprint);
        QVERIFY(!key.hdkey);
        QVERIFY(!key.xpub);
        const QString expected = QStringLiteral("This computer (software key %1)").arg(i + 1);
        QCOMPARE(QString::fromStdString(key.label), expected);
        QVERIFY(!local_labels.contains(expected));
        local_labels.push_back(expected);
    }
    wizard.setIncludeLocalKey(false);
    QCOMPARE(wizard.localKeyCount(), 0);
    wizard.setIncludeLocalKey(true);
    QCOMPARE(wizard.localKeyCount(), MultisigWizard::kMaxLocalSoftwareKeys);
    wizard.setLocalKeyCount(1);
    wizard.addAirgappedKey("aabbccdd", "m/48h/1h/0h/2h", "tpubDummy", "offline");
    wizard.rebuildKeyList();
    QCOMPARE(static_cast<int>(wizard.keys().size()), 2);
    wizard.setNRequired(2);
    QVERIFY(wizard.policyError().empty());

    const QString transcript = wizard.transcript();
    QVERIFY(transcript.contains(QStringLiteral("Family")));
    QVERIFY(transcript.contains(QStringLiteral("2 of 2")));
    QVERIFY(transcript.contains(QStringLiteral("aabbccdd")));
    QVERIFY(transcript.contains(QStringLiteral("This computer")));

    wallet::MultisigKeySpec private_spec;
    private_spec.label = "local test";
    private_spec.hdkey = "xprv-do-not-print";
    const QString redacted = QString::fromStdString(wallet::FormatMultisigTranscript(
        "redaction", "regtest", 1, {private_spec}, OutputType::BECH32, {}));
    QVERIFY(!redacted.contains(QStringLiteral("xprv-do-not-print")));
    QVERIFY(redacted.contains(QStringLiteral("private key material omitted")));

    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(144);
    const QString tap = wizard.transcript();
    QVERIFY(tap.contains(QStringLiteral("bech32m")));
    QVERIFY(tap.contains(QStringLiteral("Scrooge vault")));
    QVERIFY(tap.contains(QStringLiteral("MuSig2")));
    QVERIFY(tap.contains(QStringLiteral("144")));
    QVERIFY(tap.contains(QStringLiteral("older")));
    QVERIFY(tap.contains(QStringLiteral("role=active")));
    wizard.setFallbackOlder(144);
    wizard.setFallbackAfter(500);
    QVERIFY(!wizard.policyError().empty());
    wizard.setFallbackOlder(std::nullopt);
    wizard.setFallbackAfter(500);
    const QString abs = wizard.transcript();
    QVERIFY(abs.contains(QStringLiteral("after")));
    QVERIFY(abs.contains(QStringLiteral("500")));
    QVERIFY(wizard.policyError().empty());
    wizard.setFallbackAfter(std::nullopt);
    wizard.setFallbackOlder(144);
    wizard.addAirgappedKey("aabbccdd", "m/48h/1h/0h/3h", "tpubDup", "copy");
    wizard.rebuildKeyList();
    QVERIFY(!wallet::DuplicateSignerWarning(wizard.keys()).empty());

    wizard.next();
    wizard.next();
    auto* name = wizard.findChild<QLineEdit*>("walletNameEdit");
    QVERIFY(name);
    name->setText(QStringLiteral("Family"));
    QVERIFY(wizard.validateCurrentPage());
    wizard.close();

    MultisigWizard duplicate(m_node, /*wallet_controller=*/nullptr);
    duplicate.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
    duplicate.applyTemplate();
    duplicate.setLocalKeyCount(0);
    duplicate.addAirgappedKey("aabbccdd", "m/48h/1h/0h/3h", "tpubDuplicate", "offline-a");
    duplicate.addAirgappedKey("eeff0011", "m/48h/1h/0h/3h", "tpubDuplicate", "offline-copy");
    duplicate.rebuildKeyList();
    duplicate.show();
    WalkTo(duplicate, MultisigWizard::Page_Keys);
    QVERIFY(duplicate.button(QWizard::NextButton)->isEnabled());
    QTimer::singleShot(0, [] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* message = qobject_cast<QMessageBox*>(widget)) message->accept();
        }
    });
    QVERIFY(!duplicate.validateCurrentPage());
    QCOMPARE(duplicate.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
    QVERIFY(!duplicate.createdWallet());
    duplicate.close();
}

void MultisigWizardTests::grabPages()
{
    const QByteArray dest = qgetenv("MULTISIG_WIZARD_SHOTS");
    if (dest.isEmpty()) {
        QSKIP("Set MULTISIG_WIZARD_SHOTS to a directory to dump wizard PNGs");
    }
    const QString dir = QString::fromLocal8Bit(dest);
    QVERIFY(QDir().mkpath(dir));

    for (const QString& stale : QDir(dir).entryList({QStringLiteral("*.png")}, QDir::Files)) {
        const QString path = QDir(dir).filePath(stale);
        QVERIFY2(QFile::remove(path), qPrintable(QStringLiteral("failed to remove stale shot ") + path));
    }
    QStringList expected_files;
    for (const QString& name : kShotNames) {
        const QString filename = name + QStringLiteral(".png");
        expected_files << filename;
        QVERIFY(!QFileInfo::exists(QDir(dir).filePath(filename)));
    }
    expected_files.sort();

    // AppTests shuts the GUI node down; use one fixture for the entire capture.
    TestChain100Setup test;
    test.mineBlocks(5);
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    gArgs.ForceSetArg("-fallbackfee", "0.0002");
    hwi::UsbEnumerateSuppress suppress_usb;

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    struct PaletteGuard {
        QPalette original{QApplication::palette()};
        ~PaletteGuard() { QApplication::setPalette(original); }
    } palette_guard;
    const auto explicit_palette = [](bool dark) {
        QPalette palette;
        if (dark) {
            palette.setColor(QPalette::Window, QColor{QStringLiteral("#202124")});
            palette.setColor(QPalette::WindowText, QColor{QStringLiteral("#E8EAED")});
            palette.setColor(QPalette::Base, QColor{QStringLiteral("#292A2D")});
            palette.setColor(QPalette::AlternateBase, QColor{QStringLiteral("#35363A")});
            palette.setColor(QPalette::ToolTipBase, QColor{QStringLiteral("#4A3A12")});
            palette.setColor(QPalette::ToolTipText, QColor{QStringLiteral("#FFE8A3")});
            palette.setColor(QPalette::Text, QColor{QStringLiteral("#E8EAED")});
            palette.setColor(QPalette::Button, QColor{QStringLiteral("#35363A")});
            palette.setColor(QPalette::ButtonText, QColor{QStringLiteral("#E8EAED")});
            palette.setColor(QPalette::BrightText, QColor{QStringLiteral("#F28B82")});
            palette.setColor(QPalette::Highlight, QColor{QStringLiteral("#8AB4F8")});
            palette.setColor(QPalette::HighlightedText, QColor{QStringLiteral("#202124")});
            palette.setColor(QPalette::PlaceholderText, QColor{QStringLiteral("#9AA0A6")});
            palette.setColor(QPalette::Link, QColor{QStringLiteral("#8AB4F8")});
            palette.setColor(QPalette::Mid, QColor{QStringLiteral("#5F6368")});
            palette.setColor(QPalette::Dark, QColor{QStringLiteral("#171717")});
            palette.setColor(QPalette::Light, QColor{QStringLiteral("#4A4D51")});
            palette.setColor(QPalette::Shadow, QColor{QStringLiteral("#000000")});
        } else {
            palette.setColor(QPalette::Window, QColor{QStringLiteral("#F6F8FA")});
            palette.setColor(QPalette::WindowText, QColor{QStringLiteral("#202124")});
            palette.setColor(QPalette::Base, QColor{QStringLiteral("#FFFFFF")});
            palette.setColor(QPalette::AlternateBase, QColor{QStringLiteral("#EDF1F5")});
            palette.setColor(QPalette::ToolTipBase, QColor{QStringLiteral("#FFF1C2")});
            palette.setColor(QPalette::ToolTipText, QColor{QStringLiteral("#3D2B00")});
            palette.setColor(QPalette::Text, QColor{QStringLiteral("#202124")});
            palette.setColor(QPalette::Button, QColor{QStringLiteral("#E8EAED")});
            palette.setColor(QPalette::ButtonText, QColor{QStringLiteral("#202124")});
            palette.setColor(QPalette::BrightText, QColor{QStringLiteral("#B3261E")});
            palette.setColor(QPalette::Highlight, QColor{QStringLiteral("#0B57D0")});
            palette.setColor(QPalette::HighlightedText, QColor{QStringLiteral("#FFFFFF")});
            palette.setColor(QPalette::PlaceholderText, QColor{QStringLiteral("#6B7280")});
            palette.setColor(QPalette::Link, QColor{QStringLiteral("#0B57D0")});
            palette.setColor(QPalette::Mid, QColor{QStringLiteral("#9AA0A6")});
            palette.setColor(QPalette::Dark, QColor{QStringLiteral("#BDC1C6")});
            palette.setColor(QPalette::Light, QColor{QStringLiteral("#FFFFFF")});
            palette.setColor(QPalette::Shadow, QColor{QStringLiteral("#5F6368")});
        }
        palette.setColor(QPalette::Disabled, QPalette::WindowText, palette.color(QPalette::PlaceholderText));
        palette.setColor(QPalette::Disabled, QPalette::Text, palette.color(QPalette::PlaceholderText));
        palette.setColor(QPalette::Disabled, QPalette::ButtonText, palette.color(QPalette::PlaceholderText));
        return palette;
    };

    for (int theme_index = 0; theme_index < 2; ++theme_index) {
        const bool dark = theme_index == 1;
        const QString theme = dark ? QStringLiteral("dark") : QStringLiteral("light");
        const QPalette palette = explicit_palette(dark);
        QApplication::setPalette(palette);
        QApplication::processEvents();
        QCOMPARE(QApplication::palette().color(QPalette::Window), palette.color(QPalette::Window));

        const auto capture = [&](QWidget& widget, const QString& state) {
            QCOMPARE(widget.size(), QSize(900, 620));
            QCOMPARE(widget.palette().color(QPalette::Window), palette.color(QPalette::Window));
            Grab(widget, dir, theme + QLatin1Char('-') + state);
        };
        const auto capture_review = [&](int hardware_count, bool failure) {
            MultisigWizard wizard(m_node, &controller);
            ShowSized(wizard);
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
            QVERIFY(!wizard.advancedFlow());
            auto* name = wizard.findChild<QLineEdit*>("stagedWalletNameEdit");
            auto* authority = wizard.findChild<QLabel*>("fixedAuthorityLabel");
            auto* discovery = wizard.findChild<QLabel*>("hardwareDiscoveryStatus");
            auto* restore = wizard.findChild<QPushButton*>("restoreFromMnemonicButton");
            auto* nav = wizard.findChild<QWidget*>("vaultStepNav");
            QVERIFY(name);
            QVERIFY(authority);
            QVERIFY(discovery);
            QVERIFY(restore);
            QVERIFY(nav);
            name->setText(QStringLiteral("Shot%1Review%2").arg(dark ? QStringLiteral("Dark") : QStringLiteral("Light")).arg(hardware_count));
            QApplication::processEvents();
            QVERIFY(!name->accessibleName().isEmpty());
            QCOMPARE(nav->width(), 188);
            QVERIFY(nav->isVisible());
            QVERIFY(name->mapTo(wizard.currentPage(), QPoint{}).y() < authority->mapTo(wizard.currentPage(), QPoint{}).y());
            QVERIFY(restore->mapTo(wizard.currentPage(), QPoint{0, restore->height()}).y() <= wizard.currentPage()->height());
            if (failure) {
                QCOMPARE(wizard.localKeyCount(), 0);
                QVERIFY(discovery->text().contains(QStringLiteral("4 hardware wallets"), Qt::CaseInsensitive));
                QVERIFY(discovery->text().contains(QStringLiteral("Disconnect extras"), Qt::CaseInsensitive));
                QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
            } else {
                QCOMPARE(wizard.localKeyCount(), MultisigWizard::kStagedVaultKeyCount - hardware_count);
                QCOMPARE(static_cast<int>(wizard.keys().size()), MultisigWizard::kStagedVaultKeyCount);
                QCOMPARE(VisibleText(wizard).count(QStringLiteral("Stored in this wallet on this computer")),
                         MultisigWizard::kStagedVaultKeyCount - hardware_count);
                QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
            }
            capture(wizard, failure ? QStringLiteral("review-too-many-failure")
                                    : QStringLiteral("review-%1").arg(hardware_count));
            wizard.close();
        };

        capture_review(/*hardware_count=*/0, /*failure=*/false);

        QString restore_policy;
        std::vector<SecureString> restore_phrases;
        {
            MultisigWizard wizard(m_node, &controller);
            ShowSized(wizard);
            auto* name = wizard.findChild<QLineEdit*>("stagedWalletNameEdit");
            QVERIFY(name);
            name->setText(QStringLiteral("Shot%1SoftwareVault").arg(dark ? QStringLiteral("Dark") : QStringLiteral("Light")));
            QApplication::processEvents();
            QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
            wizard.next();
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
            QCOMPARE(wizard.currentPage()->title(), QStringLiteral("Secure Recovery"));
            restore_policy = wizard.m_policy_package;
            QCOMPARE(wizard.m_software_recovery.size(), size_t{3});
            for (const auto& recovery : wizard.m_software_recovery) {
                restore_phrases.emplace_back(recovery.mnemonic.begin(), recovery.mnemonic.end());
            }
            auto* print = wizard.findChild<QPushButton*>("printPolicyButton");
            auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
            auto* print_status = wizard.findChild<QLabel*>("printPolicyStatus");
            QVERIFY(print);
            QVERIFY(ack);
            QVERIFY(print_status);
            QVERIFY(print->isVisible());
            QVERIFY(print->isEnabled());
            QTRY_VERIFY(print->isDefault());
            QVERIFY(ack->isVisible());
            QVERIFY(!ack->isEnabled());
            QVERIFY(print->mapTo(wizard.currentPage(), QPoint{}).y() < ack->mapTo(wizard.currentPage(), QPoint{}).y());
            QVERIFY(ack->mapTo(wizard.currentPage(), QPoint{0, ack->height()}).y() <= wizard.currentPage()->height());
            capture(wizard, QStringLiteral("secure-recovery-before-print"));

            CompleteBackupPage(wizard);
            QVERIFY(ack->isChecked());
            QVERIFY(ack->isEnabled());
            QVERIFY(print_status->text().contains(QStringLiteral("validated"), Qt::CaseInsensitive));
            QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
            QVERIFY(qobject_cast<QPushButton*>(wizard.button(QWizard::NextButton))->isDefault());
            QVERIFY(!print->isDefault());
            QVERIFY(!wizard.button(QWizard::BackButton)->isVisible());
            QVERIFY(!wizard.button(QWizard::CancelButton)->isVisible());
            capture(wizard, QStringLiteral("secure-recovery-after-print"));

            wizard.next();
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
            QVERIFY(wizard.createdWallet());
            QCOMPARE(wizard.currentPage()->title(), QStringLiteral("Review Your First Address"));
            auto* qr = wizard.findChild<QRImageWidget*>("verifyQr");
            auto* address = wizard.findChild<QLineEdit*>("verifyAddressEdit");
            auto* independent = wizard.findChild<QLabel*>("independentVerificationState");
            auto* import_policy = wizard.findChild<QPushButton*>("verifyImportedPolicyButton");
            QVERIFY(qr);
            QVERIFY(address);
            QVERIFY(independent);
            QVERIFY(import_policy);
            QVERIFY(qr->isVisible());
            QCOMPARE(qr->size(), QSize(220, 220));
            QVERIFY(!address->text().isEmpty());
            QVERIFY(independent->text().contains(QStringLiteral("Not independently verified"), Qt::CaseInsensitive));
            QCOMPARE(independent->backgroundRole(), QPalette::ToolTipBase);
            QCOMPARE(independent->foregroundRole(), QPalette::ToolTipText);
            QCOMPARE(independent->palette().color(independent->backgroundRole()), palette.color(QPalette::ToolTipBase));
            QCOMPARE(independent->palette().color(independent->foregroundRole()), palette.color(QPalette::ToolTipText));
            QVERIFY(import_policy->isVisible());
            QVERIFY(qr->mapTo(wizard.currentPage(), QPoint{qr->width(), qr->height()}).y() <= wizard.currentPage()->height());
            capture(wizard, QStringLiteral("confirm-review"));

            wizard.next();
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
            auto* summary = wizard.findChild<QLabel*>("doneSummaryLabel");
            auto* policy_id = wizard.findChild<QLineEdit*>("readyPolicyId");
            auto* receive = wizard.findChild<QPushButton*>("receiveTestPaymentButton");
            auto* done = qobject_cast<QPushButton*>(wizard.button(QWizard::FinishButton));
            QVERIFY(summary);
            QVERIFY(policy_id);
            QVERIFY(receive);
            QVERIFY(done);
            QVERIFY(summary->text().contains(QStringLiteral("Vault created"), Qt::CaseInsensitive));
            QVERIFY(!policy_id->text().isEmpty());
            QVERIFY(!policy_id->accessibleName().isEmpty());
            QVERIFY(!receive->accessibleName().isEmpty());
            QTRY_VERIFY(receive->isDefault());
            QVERIFY(!done->isDefault());
            QVERIFY(!wizard.button(QWizard::BackButton)->isVisible());
            QVERIFY(!wizard.button(QWizard::CancelButton)->isVisible());
            QVERIFY(receive->mapTo(wizard.currentPage(), QPoint{0, receive->height()}).y() <= wizard.currentPage()->height());
            capture(wizard, QStringLiteral("ready"));
            wizard.close();
        }

        auto mock_a = std::make_unique<hwi::MockRegistration>(
            hwi::MakeMockMasterFromHex(), ChainType::REGTEST);
        capture_review(/*hardware_count=*/1, /*failure=*/false);
        auto mock_b = std::make_unique<hwi::MockRegistration>(
            hwi::MakeMockMasterFromHex("101112131415161718191a1b1c1d1e1f"), ChainType::REGTEST);
        capture_review(/*hardware_count=*/2, /*failure=*/false);
        auto mock_c = std::make_unique<hwi::MockRegistration>(
            hwi::MakeMockMasterFromHex("202122232425262728292a2b2c2d2e2f"), ChainType::REGTEST);
        capture_review(/*hardware_count=*/3, /*failure=*/false);
        {
            hwi::MockRegistration mock_d{
                hwi::MakeMockMasterFromHex("303132333435363738393a3b3c3d3e3f"), ChainType::REGTEST};
            capture_review(/*hardware_count=*/4, /*failure=*/true);
        }
        mock_c.reset();
        mock_b.reset();

        WalletModel* operational_model{nullptr};
        std::optional<CTxDestination> operational_dest;
        {
            MultisigWizard wizard(m_node, &controller);
            ShowSized(wizard);
            auto* name = wizard.findChild<QLineEdit*>("stagedWalletNameEdit");
            QVERIFY(name);
            name->setText(QStringLiteral("Shot%1HardwareVault").arg(dark ? QStringLiteral("Dark") : QStringLiteral("Light")));
            QApplication::processEvents();
            QCOMPARE(wizard.localKeyCount(), 2);
            QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
            wizard.next();
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
            CompleteBackupPage(wizard);
            wizard.next();
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
            QCOMPARE(wizard.currentPage()->title(), QStringLiteral("Verify Your First Address"));
            auto* devices = wizard.findChild<QListWidget*>("verifyDeviceList");
            auto* show = wizard.findChild<QPushButton*>("showOnDeviceButton");
            auto* independent = wizard.findChild<QLabel*>("independentVerificationState");
            auto* qr = wizard.findChild<QRImageWidget*>("verifyQr");
            QVERIFY(devices);
            QVERIFY(show);
            QVERIFY(independent);
            QVERIFY(qr);
            QCOMPARE(devices->count(), 1);
            QVERIFY(show->isVisible());
            QVERIFY(independent->text().contains(QStringLiteral("Waiting"), Qt::CaseInsensitive));
            QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
            QVERIFY(devices->mapTo(wizard.currentPage(), QPoint{0, devices->height()}).y() <= wizard.currentPage()->height());
            capture(wizard, QStringLiteral("confirm-verify"));
            CompleteVerification(wizard);
            wizard.next();
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
            operational_model = wizard.createdWallet();
            QVERIFY(operational_model);
            const auto dest_result = wizard.firstReceiveAddress();
            QVERIFY(dest_result);
            operational_dest = *dest_result;
            wizard.close();
        }
        QVERIFY(operational_model);
        QVERIFY(operational_dest);

        const int funding_index = theme_index;
        CMutableTransaction fund = test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.at(funding_index), /*input_vout=*/0, /*input_height=*/funding_index + 1,
            test.coinbaseKey, GetScriptForDestination(*operational_dest), 10 * COIN, /*submit=*/false);
        test.CreateAndProcessBlock({fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        operational_model->pollBalanceChanged();
        QApplication::processEvents();

        {
            OverviewPage overview(style.get());
            overview.setClientModel(&client);
            overview.setWalletModel(operational_model);
            overview.setBalance(operational_model->wallet().getBalances());
            overview.resize(900, 620);
            overview.show();
            QApplication::processEvents();
            auto* total = overview.findChild<QLabel*>("labelTotal");
            auto* immediate = overview.findChild<QLabel*>("vaultImmediateStatusLabel");
            auto* first = overview.findChild<QLabel*>("vaultRecoveryStatusLabel");
            auto* final = overview.findChild<QLabel*>("vaultFinalStatusLabel");
            auto* repeated_balance = overview.findChild<QLabel*>("labelBalance");
            QVERIFY(total);
            QVERIFY(immediate);
            QVERIFY(first);
            QVERIFY(final);
            QVERIFY(repeated_balance);
            QVERIFY(total->isVisible());
            QVERIFY(repeated_balance->isHidden());
            QVERIFY(immediate->isVisible());
            QVERIFY(first->isVisible());
            QVERIFY(final->isVisible());
            QVERIFY(!overview.findChild<QLabel*>("labelVaultPathNote"));
            QVERIFY(final->mapTo(&overview, QPoint{0, final->height()}).y() <= overview.height());
            capture(overview, QStringLiteral("overview"));
        }

        {
            SendCoinsDialog send(style.get());
            send.setClientModel(&client);
            send.setModel(operational_model);
            send.resize(900, 620);
            send.show();
            QApplication::processEvents();
            auto* normal = send.findChild<QRadioButton*>("vaultNormalModeButton");
            auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
            auto* stages = send.findChild<QComboBox*>("vaultRecoveryStageCombo");
            auto* fee = send.findChild<QWidget*>("frameFee");
            auto* review = send.findChild<QPushButton*>("sendButton");
            auto* lost = send.findChild<QLabel*>("vaultLostSignerLabel");
            QVERIFY(normal);
            QVERIFY(recovery);
            QVERIFY(stages);
            QVERIFY(fee);
            QVERIFY(review);
            QVERIFY(lost);
            QVERIFY(normal->isChecked());
            QVERIFY(!recovery->isChecked());
            QCOMPARE(stages->count(), 3);
            QCOMPARE(stages->currentIndex(), 0);
            QVERIFY(!stages->isEnabled());
            QCOMPARE(review->text(), QStringLiteral("Review Transaction"));
            QVERIFY(!normal->accessibleName().isEmpty());
            QVERIFY(!recovery->accessibleName().isEmpty());
            QVERIFY(!review->accessibleName().isEmpty());
            QVERIFY(recovery->mapTo(&send, QPoint{}).y() < fee->mapTo(&send, QPoint{}).y());
            QVERIFY(review->mapTo(&send, QPoint{0, review->height()}).y() <= send.height());
            capture(send, QStringLiteral("send-normal"));

            recovery->setChecked(true);
            stages->setCurrentIndex(1);
            QApplication::processEvents();
            QVERIFY(recovery->isChecked());
            QCOMPARE(stages->currentData().toUInt(), MultisigWizard::kThirtyDayVaultDelay);
            QVERIFY(!review->isEnabled());
            capture(send, QStringLiteral("send-first-recovery"));

            stages->setCurrentIndex(2);
            QApplication::processEvents();
            QCOMPARE(stages->currentData().toUInt(), MultisigWizard::kSixtyDayVaultDelay);
            QVERIFY(!review->isEnabled());
            capture(send, QStringLiteral("send-final-recovery"));

            normal->setChecked(true);
            const std::string lost_fingerprint{mock_a->Fingerprint()};
            mock_a.reset();
            operational_model->wallet().setLostSigner(lost_fingerprint, true);
            operational_model->updateTransaction();
            operational_model->pollBalanceChanged();
            QApplication::processEvents();
            QVERIFY(normal->isChecked());
            QVERIFY(lost->isVisible());
            QVERIFY(!lost->accessibleDescription().isEmpty());
            QVERIFY(!review->isEnabled());
            QVERIFY(lost->text().contains(QString::fromStdString(lost_fingerprint), Qt::CaseInsensitive));
            QVERIFY(lost->mapTo(&send, QPoint{0, lost->height()}).y() <= send.height());
            capture(send, QStringLiteral("send-lost-signer"));
            operational_model->wallet().setLostSigner(lost_fingerprint, false);
        }

        {
            MultisigWizard restore_host(m_node, &controller);
            ShowSized(restore_host);
            auto* host_name = restore_host.findChild<QLineEdit*>("stagedWalletNameEdit");
            auto* restore_button = restore_host.findChild<QPushButton*>("restoreFromMnemonicButton");
            QVERIFY(host_name);
            QVERIFY(restore_button);
            host_name->setText(QStringLiteral("Shot%1RestoreHost").arg(dark ? QStringLiteral("Dark") : QStringLiteral("Light")));
            bool restore_ok{true};
            QStringList restore_errors;
            QTimer::singleShot(0, this, [&] {
                QWizard* dialog{nullptr};
                for (QWidget* widget : QApplication::topLevelWidgets()) {
                    auto* candidate = qobject_cast<QWizard*>(widget);
                    if (candidate && candidate != &restore_host && candidate->isVisible()) {
                        dialog = candidate;
                        break;
                    }
                }
                if (!dialog) {
                    restore_ok = false;
                    restore_errors << QStringLiteral("restore dialog did not open");
                    return;
                }
                const auto check = [&](bool condition, const QString& message) {
                    if (!condition) {
                        restore_ok = false;
                        restore_errors << message;
                    }
                };
                dialog->resize(900, 620);
                QApplication::processEvents();
                auto* name = dialog->findChild<QLineEdit*>("restoreWalletNameEdit");
                auto* policy = dialog->findChild<QPlainTextEdit*>("restorePolicyEdit");
                auto* policy_summary = dialog->findChild<QLabel*>("restorePolicySummary");
                auto* policy_status = dialog->findChild<QLabel*>("restorePolicyStatus");
                auto* phrase = dialog->findChild<QWidget*>("restoreMnemonicEdit");
                auto* add = dialog->findChild<QPushButton*>("restoreAddKeyButton");
                auto* keys = dialog->findChild<QListWidget*>("restoreAcceptedKeys");
                auto* key_status = dialog->findChild<QLabel*>("restoreKeyStatus");
                auto* key_authority = dialog->findChild<QLabel*>("restoreIncrementalAuthority");
                auto* authority = dialog->findChild<QLabel*>("restoreAuthoritySummary");
                check(name && policy && policy_summary && policy_status && phrase && add && keys && key_status && key_authority && authority,
                      QStringLiteral("restore controls missing"));
                if (name && policy && policy_summary && policy_status && phrase && add && keys && key_status && key_authority && authority) {
                    name->setText(QStringLiteral("Shot%1RestoredPreview").arg(dark ? QStringLiteral("Dark") : QStringLiteral("Light")));
                    policy->setPlainText(restore_policy);
                    dialog->next();
                    check(dialog->currentId() == 1, QStringLiteral("policy preflight did not advance"));
                    dialog->back();
                    check(dialog->currentId() == 0, QStringLiteral("restore policy page unavailable"));
                    check(!name->accessibleName().isEmpty(), QStringLiteral("restore name lacks accessibility name"));
                    check(policy_summary->text().contains(QStringLiteral("Policy ID")), QStringLiteral("policy summary missing ID"));
                    check(policy_status->text().contains(QStringLiteral("preflight"), Qt::CaseInsensitive), QStringLiteral("policy status missing preflight"));
                    capture(*dialog, QStringLiteral("restore-policy"));

                    dialog->next();
                    check(dialog->currentId() == 1, QStringLiteral("recovery-key page unavailable"));
                    dialog->next();
                    check(dialog->currentId() == 2, QStringLiteral("public-only authority page unavailable"));
                    check(authority->text().contains(QStringLiteral("Public policy only"), Qt::CaseInsensitive), QStringLiteral("public-only authority missing"));
                    capture(*dialog, QStringLiteral("restore-public-only"));
                    dialog->back();

                    QTest::keyClicks(phrase, QStringLiteral("not a valid recovery phrase"));
                    add->click();
                    QTest::keyClick(phrase, Qt::Key_Delete);
                    QApplication::processEvents();
                    check(keys->count() == 0, QStringLiteral("invalid phrase was accepted"));
                    check(!key_status->text().isEmpty(), QStringLiteral("invalid phrase has no error"));
                    check(!phrase->accessibleName().isEmpty(), QStringLiteral("recovery phrase lacks accessibility name"));
                    check(phrase->property("secureMnemonicBacking").toBool(), QStringLiteral("recovery phrase is not held in secure backing memory"));
                    check(qobject_cast<QLineEdit*>(phrase) == nullptr, QStringLiteral("recovery phrase must not use QString/QLineEdit backing storage"));
                    check(add->mapTo(dialog->currentPage(), QPoint{0, add->height()}).y() <= dialog->currentPage()->height(),
                          QStringLiteral("restore key action is clipped"));
                    capture(*dialog, QStringLiteral("restore-error"));

                    for (size_t phrase_index = 0; phrase_index < restore_phrases.size(); ++phrase_index) {
                        const SecureString& value = restore_phrases[phrase_index];
                        QTest::keyClicks(phrase, QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size())));
                        add->click();
                        QApplication::processEvents();
                        check(keys->count() == static_cast<int>(phrase_index + 1),
                              QStringLiteral("recovery key %1 did not match").arg(phrase_index + 1));
                        check(!key_authority->text().isEmpty(), QStringLiteral("incremental authority missing"));
                        capture(*dialog, QStringLiteral("restore-key-%1").arg(phrase_index + 1));
                    }
                    dialog->next();
                    check(dialog->currentId() == 2, QStringLiteral("recovered-authority page unavailable"));
                    dialog->next();
                    check(dialog->currentId() == 3, QStringLiteral("rescan page unavailable"));
                    auto* rescan_summary = dialog->findChild<QLabel*>("restoreRescanSummary");
                    check(rescan_summary && rescan_summary->text().contains(QStringLiteral("policy ID")),
                          QStringLiteral("rescan summary missing policy ID"));
                    capture(*dialog, QStringLiteral("restore-rescan"));
                }
                dialog->reject();
            });
            restore_button->click();
            QVERIFY2(restore_ok, qPrintable(restore_errors.join(QStringLiteral("; "))));
            restore_host.close();
        }

        for (SecureString& phrase : restore_phrases) {
            if (!phrase.empty()) memory_cleanse(phrase.data(), phrase.size());
        }
        std::vector<SecureString>{}.swap(restore_phrases);
        mock_a.reset();
    }

    const QStringList actual_files = QDir(dir).entryList(QStringList{QStringLiteral("*.png")}, QDir::Files, QDir::Name);
    QCOMPARE(actual_files, expected_files);
    for (const QString& filename : actual_files) {
        QVERIFY2(QFileInfo(QDir(dir).filePath(filename)).size() > 0, qPrintable(QStringLiteral("empty shot ") + filename));
    }
}

void MultisigWizardTests::wizardTemplates()
{
    MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
    QCOMPARE(wizard.localKeyCount(), MultisigWizard::kStagedVaultKeyCount);
    wizard.setLocalKeyCount(3);
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Maximum);
    wizard.applyTemplate();
    QCOMPARE(wizard.localKeyCount(), 3);
    QVERIFY(!wizard.fallbackOlder());
    QVERIFY(!wizard.preferNMinus1());
    QCOMPARE(wizard.outputType(), OutputType::BECH32M);

    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::HardwareCoordinator);
    wizard.applyTemplate();
    QCOMPARE(wizard.localKeyCount(), 0);
    QVERIFY(!wizard.includeLocalKey());
    QCOMPARE(*wizard.fallbackOlder(), MultisigWizard::kDefaultVaultDelay);

    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Inheritance);
    wizard.applyTemplate();
    QCOMPARE(wizard.localKeyCount(), 0);
    QCOMPARE(*wizard.fallbackOlder(), MultisigWizard::kDefaultVaultDelay);

    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::RecoverOneLost);
    wizard.applyTemplate();
    QCOMPARE(wizard.localKeyCount(), 3);
    QVERIFY(wizard.includeLocalKey());
    QVERIFY(wizard.preferNMinus1());
    QCOMPARE(*wizard.fallbackOlder(), MultisigWizard::kDefaultVaultDelay);

    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::StagedRecovery);
    wizard.applyTemplate();
    QCOMPARE(wizard.localKeyCount(), 3);
    QVERIFY(wizard.includeLocalKey());
    QCOMPARE(wizard.nrequired(), 2);
    QCOMPARE(*wizard.fallbackOlder(), MultisigWizard::kThirtyDayVaultDelay);
    QCOMPARE(*wizard.fallbackOlderOneKey(), MultisigWizard::kSixtyDayVaultDelay);

    wizard.setNRequired(1);
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
    wizard.applyTemplate();
    QVERIFY(!wizard.preferNMinus1());
    QCOMPARE(wizard.nrequired(), 1);
    QCOMPARE(wizard.localKeyCount(), 3);

    wizard.setLocalKeyCount(1);
    wizard.addAirgappedKey("aabbccdd", "m/48h/1h/0h/3h", "tpubDummyA", "cold-a");
    wizard.addAirgappedKey("11223344", "m/48h/1h/0h/3h", "tpubDummyB", "cold-b", /*recovery_only=*/true);
    wizard.rebuildKeyList();
    QCOMPARE(static_cast<int>(wizard.keys().size()), 3);
    QVERIFY(wizard.keys().back().recovery_only);
    wizard.close();

    MultisigWizard role_templates(m_node, /*wallet_controller=*/nullptr);
    role_templates.setLocalKeyCount(1);
    role_templates.addAirgappedKey("01020304", "m/48h/1h/0h/3h", "tpubTemplateA", "active-a");
    role_templates.addAirgappedKey("05060708", "m/48h/1h/0h/3h", "tpubTemplateB", "active-b");
    role_templates.rebuildKeyList();
    QCOMPARE(role_templates.nActiveKeys(), 3);

    role_templates.setVaultTemplate(MultisigWizard::VaultTemplate::Inheritance);
    role_templates.applyTemplate();
    role_templates.rebuildKeyList();
    QVERIFY(role_templates.keys().back().recovery_only);
    QCOMPARE(role_templates.nActiveKeys(), 2);

    role_templates.setVaultTemplate(MultisigWizard::VaultTemplate::RecoverOneLost);
    role_templates.applyTemplate();
    role_templates.rebuildKeyList();
    QVERIFY(!role_templates.keys().back().recovery_only);
    QCOMPARE(role_templates.nActiveKeys(), 3);

    role_templates.setVaultTemplate(MultisigWizard::VaultTemplate::Inheritance);
    role_templates.applyTemplate();
    role_templates.rebuildKeyList();
    QVERIFY(role_templates.keys().back().recovery_only);
    role_templates.addAirgappedKey("090a0b0c", "m/48h/1h/0h/3h", "tpubTemplateC", "heir-c", /*recovery_only=*/true);
    role_templates.rebuildKeyList();
    QCOMPARE(static_cast<int>(std::count_if(role_templates.keys().begin(), role_templates.keys().end(),
                                            [](const wallet::MultisigKeySpec& key) { return key.recovery_only; })),
             1);
    QVERIFY(role_templates.keys().back().recovery_only);
    role_templates.setVaultTemplate(MultisigWizard::VaultTemplate::Maximum);
    role_templates.applyTemplate();
    role_templates.rebuildKeyList();
    QVERIFY(!role_templates.keys().back().recovery_only);
    QCOMPARE(role_templates.nActiveKeys(), 4);

}

void MultisigWizardTests::createWalletWithController()
{
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    hwi::UsbEnumerateSuppress suppress_usb;

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    // The product entry point is intentionally opinionated: with no connected
    // hardware it creates three software keys and fixes the 30/60-day policy.
    {
        MultisigWizard staged(m_node, &controller);
        QSignalSpy created_spy(&staged, &MultisigWizard::created);
        QVERIFY(!staged.advancedFlow());
        QCOMPARE(staged.outputType(), OutputType::BECH32M);
        QCOMPARE(staged.localKeyCount(), MultisigWizard::kStagedVaultKeyCount);
        QCOMPARE(staged.nrequired(), 2);
        QCOMPARE(staged.fallbackOlder(), std::optional<uint32_t>{MultisigWizard::kThirtyDayVaultDelay});
        QCOMPARE(staged.fallbackOlderOneKey(), std::optional<uint32_t>{MultisigWizard::kSixtyDayVaultDelay});
        QVERIFY(!staged.fallbackAfter());

        staged.show();
        QApplication::processEvents();
        QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        auto* name = staged.findChild<QLineEdit*>("stagedWalletNameEdit");
        QVERIFY(name);
        name->setText(QStringLiteral("DefaultStagedVault"));
        QVERIFY(!staged.advancedFlow());
        QCOMPARE(staged.localKeyCount(), 3);
        QCOMPARE(static_cast<int>(staged.keys().size()), 3);
        QCOMPARE(staged.nActiveKeys(), 3);

        auto* authority = staged.findChild<QLabel*>("fixedAuthorityLabel");
        auto* technical = staged.findChild<QLabel*>("fixedTechnicalDetails");
        auto* local_count = staged.findChild<QSpinBox*>("localSoftwareKeyCountSpin");
        auto* risk = staged.findChild<QCheckBox*>("localSoftwareKeysRiskCheck");
        QVERIFY(authority);
        QVERIFY(technical);
        QVERIFY(local_count);
        QVERIFY(risk);
        QCOMPARE(authority->text(), QStringLiteral("This computer holds all three keys. This wallet or its recovery kit can spend immediately."));
        QVERIFY(technical->text().contains(QStringLiteral("4,320")));
        QVERIFY(technical->text().contains(QStringLiteral("8,640")));
        const QString review_text = VisibleText(staged);
        QCOMPARE(review_text.count(QStringLiteral("Software key")), 3);
        QCOMPARE(review_text.count(QStringLiteral("Stored in this wallet on this computer")), 3);
        QVERIFY(!local_count->isVisible());
        QVERIFY(!risk->isVisible());
        QVERIFY(!risk->isChecked());
        QVERIFY(staged.button(QWizard::NextButton)->isEnabled());
        staged.next();
        QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
        QCOMPARE(created_spy.count(), 0);
        QVERIFY(!staged.createdWallet());
        QVERIFY(controller.listWalletDir().count("DefaultStagedVault") == 0);
        AssertBackupPage(staged, MultisigWizard::kThirtyDayVaultDelay, {}, MultisigWizard::kSixtyDayVaultDelay);
        CompleteBackupPage(staged);
        staged.next();
        QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        QVERIFY(staged.createdWallet());
        QCOMPARE(QString::fromStdString(staged.createdWallet()->wallet().getWalletName()), QStringLiteral("DefaultStagedVault"));
        QTRY_VERIFY_WITH_TIMEOUT(controller.listWalletDir().count("DefaultStagedVault") == 1, 5000);
        auto* local_verify = staged.findChild<QCheckBox*>("localOnlyVerifyCheck");
        QVERIFY(local_verify);
        QVERIFY(local_verify->isHidden());
        QVERIFY(!local_verify->isChecked());
        QVERIFY(staged.button(QWizard::NextButton)->isEnabled());
        auto* verified_address = staged.findChild<QLineEdit*>("verifyAddressEdit");
        auto* import_policy = staged.findChild<QPushButton*>("verifyImportedPolicyButton");
        auto* verify_status = staged.findChild<QLabel*>("verifyStatusLabel");
        auto* independent_state = staged.findChild<QLabel*>("independentVerificationState");
        QVERIFY(verified_address);
        QVERIFY(import_policy);
        QVERIFY(verify_status);
        QVERIFY(independent_state);

        // The optional independent-policy action must derive index zero from
        // the imported public descriptor and compare that result with the
        // address on screen; matching policy metadata alone is insufficient.
        QTemporaryDir independent_dir;
        QVERIFY(independent_dir.isValid());
        const QString independent_path = independent_dir.filePath(QStringLiteral("independent-policy.json"));
        QFile independent_file{independent_path};
        QVERIFY2(independent_file.open(QIODevice::WriteOnly), qPrintable(independent_file.errorString()));
        const QByteArray independent_bytes{staged.m_policy_package.toUtf8()};
        QCOMPARE(independent_file.write(independent_bytes), static_cast<qint64>(independent_bytes.size()));
        independent_file.close();
        const auto choose_independent_policy = [independent_path] {
            QTimer::singleShot(0, [independent_path] {
                for (QWidget* widget : QApplication::topLevelWidgets()) {
                    if (auto* dialog = qobject_cast<QFileDialog*>(widget)) {
                        dialog->selectFile(independent_path);
                        QMetaObject::invokeMethod(dialog, "accept", Qt::DirectConnection);
                    }
                }
            });
        };
        const QString first_address = verified_address->text();
        verified_address->setText(QStringLiteral("different-address"));
        choose_independent_policy();
        import_policy->click();
        QVERIFY(verify_status->text().contains(QStringLiteral("does not derive"), Qt::CaseInsensitive));
        QVERIFY(independent_state->text().contains(QStringLiteral("Not independently verified"), Qt::CaseInsensitive));
        verified_address->setText(first_address);
        choose_independent_policy();
        import_policy->click();
        QVERIFY(independent_state->text().contains(QStringLiteral("Independently verified"), Qt::CaseInsensitive));
        CompleteVerification(staged);
        staged.next();
        QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Done));
        QCOMPARE(created_spy.count(), 1);
        QVERIFY(staged.createdWallet());
        const auto status = staged.createdWallet()->wallet().getVaultStatus();
        QVERIFY(status.is_vault);
        QCOMPARE(status.recovery_stages.size(), size_t{2});
        QCOMPARE(status.recovery_stages[0].nrequired, 2);
        QCOMPARE(status.recovery_stages[0].older, std::optional<uint32_t>{MultisigWizard::kThirtyDayVaultDelay});
        QCOMPARE(status.recovery_stages[1].nrequired, 1);
        QCOMPARE(status.recovery_stages[1].older, std::optional<uint32_t>{MultisigWizard::kSixtyDayVaultDelay});
        auto* receive_test = staged.findChild<QPushButton*>("receiveTestPaymentButton");
        QVERIFY(receive_test);
        QSignalSpy receive_spy(&staged, &MultisigWizard::receiveRequested);
        receive_test->click();
        QCOMPARE(receive_spy.count(), 1);
        QCOMPARE(receive_spy.first().at(1).toString(), verified_address->text());
        staged.close();
    }

    // The default suggestion must not collide with any loaded wallet. An
    // explicitly entered loaded-wallet name is rejected on Review Vault,
    // before key generation or any persistent create attempt. Correcting the
    // name lets the user continue normally.
    {
        const std::string loaded_name{"DefaultStagedVault"};
        const auto wallets_before = controller.listWalletDir();
        QVERIFY(wallets_before.count(loaded_name) == 1);
        QVERIFY(wallets_before.at(loaded_name).first);

        MultisigWizard collision(m_node, &controller);
        QSignalSpy created_spy(&collision, &MultisigWizard::created);
        ShowSized(collision);
        auto* name = collision.findChild<QLineEdit*>("stagedWalletNameEdit");
        auto* name_error = collision.findChild<QLabel*>("walletNameErrorLabel");
        QVERIFY(name);
        QVERIFY(name_error);
        QVERIFY(!name->text().trimmed().isEmpty());
        QVERIFY(wallets_before.count(name->text().trimmed().toStdString()) == 0);

        name->setText(QString::fromStdString(loaded_name));
        QApplication::processEvents();
        QTRY_VERIFY_WITH_TIMEOUT(
            name_error->text().contains(QStringLiteral("already exists"), Qt::CaseInsensitive), 5000);
        QVERIFY(!collision.button(QWizard::NextButton)->isEnabled());
        collision.next();
        QCOMPARE(collision.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        QCOMPARE(created_spy.count(), 0);
        QVERIFY(!collision.createdWallet());
        QCOMPARE(controller.listWalletDir().size(), wallets_before.size());

        name->setText(QStringLiteral("LoadedCollisionRetry"));
        QApplication::processEvents();
        QVERIFY(name_error->text().isEmpty());
        QVERIFY(collision.button(QWizard::NextButton)->isEnabled());
        collision.next();
        QCOMPARE(collision.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
        QCOMPARE(created_spy.count(), 0);
        QVERIFY(!collision.createdWallet());
        collision.close();
    }

    // Wallet-directory collisions matter even when the wallet is not loaded
    // in the GUI. Leave a blank wallet on disk, unload it, and ensure the
    // wizard applies the same Intro-page gate without touching that wallet.
    {
        const std::string unloaded_name{"Vault"};
        std::vector<bilingual_str> warnings;
        auto created = m_node.walletLoader().createWallet(
            unloaded_name, SecureString{},
            wallet::WALLET_FLAG_DESCRIPTORS | wallet::WALLET_FLAG_BLANK_WALLET,
            warnings);
        QVERIFY2(created, qPrintable(QString::fromStdString(util::ErrorString(created).original)));
        WalletModel* const model = controller.getOrCreateWallet(std::move(*created));
        QVERIFY(model);
        model->wallet().remove();
        QTRY_VERIFY_WITH_TIMEOUT(controller.listWalletDir().count(unloaded_name) == 1, 5000);
        QTRY_VERIFY_WITH_TIMEOUT(!controller.listWalletDir().at(unloaded_name).first, 5000);
        const auto wallets_before = controller.listWalletDir();

        MultisigWizard collision(m_node, &controller);
        QSignalSpy created_spy(&collision, &MultisigWizard::created);
        ShowSized(collision);
        auto* name = collision.findChild<QLineEdit*>("stagedWalletNameEdit");
        auto* name_error = collision.findChild<QLabel*>("walletNameErrorLabel");
        QVERIFY(name);
        QVERIFY(name_error);
        QVERIFY(!name->text().trimmed().isEmpty());
        QCOMPARE(name->text(), QStringLiteral("Vault 2"));
        QVERIFY(wallets_before.count(name->text().trimmed().toStdString()) == 0);

        name->setText(QString::fromStdString(unloaded_name));
        QApplication::processEvents();
        QVERIFY(name_error->text().contains(QStringLiteral("already exists"), Qt::CaseInsensitive));
        QVERIFY(!collision.button(QWizard::NextButton)->isEnabled());
        collision.next();
        QCOMPARE(collision.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        QCOMPARE(created_spy.count(), 0);
        QVERIFY(!collision.createdWallet());
        const auto wallets_after = controller.listWalletDir();
        QCOMPARE(wallets_after.size(), wallets_before.size());
        QVERIFY(wallets_after.count(unloaded_name) == 1);
        QVERIFY(!wallets_after.at(unloaded_name).first);
        QCOMPARE(QString::fromStdString(wallets_after.at(unloaded_name).second),
                 QString::fromStdString(wallets_before.at(unloaded_name).second));

        name->setText(QStringLiteral("UnloadedCollisionRetry"));
        QApplication::processEvents();
        QVERIFY(name_error->text().isEmpty());
        QVERIFY(collision.button(QWizard::NextButton)->isEnabled());
        collision.next();
        QCOMPARE(collision.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
        QCOMPARE(created_spy.count(), 0);
        QVERIFY(!collision.createdWallet());
        collision.close();
    }

    // Recheck the name at the commit boundary as well as on Review Vault. Another
    // process may create the wallet after the user entered an available name
    // but before Create wallet is clicked.
    {
        const QString race_name{QStringLiteral("CommitBoundaryCollision")};
        MultisigWizard collision(m_node, &controller);
        QSignalSpy created_spy(&collision, &MultisigWizard::created);
        ShowSized(collision);
        auto* name = collision.findChild<QLineEdit*>("stagedWalletNameEdit");
        auto* name_error = collision.findChild<QLabel*>("walletNameErrorLabel");
        QVERIFY(name);
        QVERIFY(name_error);
        name->setText(race_name);
        QApplication::processEvents();
        QVERIFY(name_error->text().isEmpty());
        collision.next();
        QCOMPARE(collision.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
        QVERIFY(!collision.createdWallet());

        std::vector<bilingual_str> warnings;
        auto reserved = m_node.walletLoader().createWallet(
            race_name.toStdString(), SecureString{},
            wallet::WALLET_FLAG_DESCRIPTORS | wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS |
                wallet::WALLET_FLAG_BLANK_WALLET,
            warnings);
        QVERIFY2(reserved, qPrintable(QString::fromStdString(util::ErrorString(reserved).original)));
        WalletModel* const reserved_model = controller.getOrCreateWallet(std::move(*reserved));
        QVERIFY(reserved_model);
        QVERIFY(reserved_model->wallet().privateKeysDisabled());
        QVERIFY(!reserved_model->wallet().getVaultStatus().is_vault);
        const auto wallets_before = controller.listWalletDir();
        QVERIFY(wallets_before.count(race_name.toStdString()) == 1);
        QVERIFY(wallets_before.at(race_name.toStdString()).first);

        CompleteBackupPage(collision);
        QString warning_text;
        QTimer::singleShot(0, [&warning_text] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* message = qobject_cast<QMessageBox*>(widget)) {
                    warning_text = message->text();
                    message->accept();
                }
            }
        });
        collision.next();
        QTRY_VERIFY_WITH_TIMEOUT(
            collision.currentId() == static_cast<int>(MultisigWizard::Page_Keys), 5000);
        QVERIFY(warning_text.contains(QStringLiteral("already exists"), Qt::CaseInsensitive));
        QCOMPARE(created_spy.count(), 0);
        QVERIFY(!collision.createdWallet());
        QCOMPARE(name->text(), race_name);
        QTRY_VERIFY_WITH_TIMEOUT(
            name_error->text().contains(QStringLiteral("already exists"), Qt::CaseInsensitive), 5000);
        QVERIFY(!collision.button(QWizard::NextButton)->isEnabled());

        const auto wallets_after = controller.listWalletDir();
        QCOMPARE(wallets_after.size(), wallets_before.size());
        QVERIFY(wallets_after.count(race_name.toStdString()) == 1);
        QVERIFY(wallets_after.at(race_name.toStdString()).first);
        QCOMPARE(QString::fromStdString(wallets_after.at(race_name.toStdString()).second),
                 QString::fromStdString(wallets_before.at(race_name.toStdString()).second));
        QVERIFY(reserved_model->wallet().privateKeysDisabled());
        QVERIFY(!reserved_model->wallet().getVaultStatus().is_vault);
        collision.close();
    }

    hwi::MockRegistration mock{hwi::MakeMockMasterFromHex(), ChainType::REGTEST};

    // A detected device consumes one of the fixed three slots; Core fills only
    // the remaining two with software keys.
    {
        MultisigWizard staged(m_node, &controller);
        staged.show();
        QApplication::processEvents();
        auto* name = staged.findChild<QLineEdit*>("stagedWalletNameEdit");
        QVERIFY(name);
        name->setText(QStringLiteral("DefaultMixedPreview"));
        QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        QCOMPARE(staged.localKeyCount(), 2);
        QCOMPARE(static_cast<int>(staged.keys().size()), 3);
        QCOMPARE(staged.nActiveKeys(), 3);
        auto* authority = staged.findChild<QLabel*>("fixedAuthorityLabel");
        QVERIFY(authority);
        QCOMPARE(authority->text(), QStringLiteral("This computer holds two keys. Together they can recover after about 30 days; the hardware wallet is also required to spend immediately."));
        const QString one_hardware_text{VisibleText(staged)};
        QVERIFY(one_hardware_text.contains(QString::fromStdString(mock.Fingerprint()), Qt::CaseInsensitive));
        QCOMPARE(one_hardware_text.count(QStringLiteral("Stored in this wallet on this computer")), 2);
        QVERIFY(staged.button(QWizard::NextButton)->isEnabled());
        staged.close();
    }

    hwi::MockRegistration mock_b{
        hwi::MakeMockMasterFromHex("101112131415161718191a1b1c1d1e1f"), ChainType::REGTEST};
    {
        MultisigWizard staged(m_node, &controller);
        staged.show();
        QApplication::processEvents();
        auto* name = staged.findChild<QLineEdit*>("stagedWalletNameEdit");
        QVERIFY(name);
        name->setText(QStringLiteral("DefaultTwoHardwarePreview"));
        QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        QCOMPARE(staged.localKeyCount(), 1);
        QCOMPARE(static_cast<int>(staged.keys().size()), 3);
        auto* authority = staged.findChild<QLabel*>("fixedAuthorityLabel");
        auto* risk = staged.findChild<QCheckBox*>("localSoftwareKeysRiskCheck");
        QVERIFY(authority);
        QVERIFY(risk);
        QCOMPARE(authority->text(), QStringLiteral("This computer holds one key. It can recover alone after about 60 days."));
        QCOMPARE(VisibleText(staged).count(QStringLiteral("Stored in this wallet on this computer")), 1);
        QVERIFY(!risk->isVisible());
        QVERIFY(!risk->isChecked());
        QVERIFY(staged.button(QWizard::NextButton)->isEnabled());
        staged.close();
    }

    hwi::MockRegistration mock_c{
        hwi::MakeMockMasterFromHex("202122232425262728292a2b2c2d2e2f"), ChainType::REGTEST};
    {
        MultisigWizard staged(m_node, &controller);
        staged.show();
        QApplication::processEvents();
        auto* name = staged.findChild<QLineEdit*>("stagedWalletNameEdit");
        QVERIFY(name);
        name->setText(QStringLiteral("DefaultHardwareOnlyPreview"));
        QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        QCOMPARE(staged.localKeyCount(), 0);
        QCOMPARE(static_cast<int>(staged.keys().size()), 3);
        auto* authority = staged.findChild<QLabel*>("fixedAuthorityLabel");
        auto* risk = staged.findChild<QCheckBox*>("localSoftwareKeysRiskCheck");
        QVERIFY(authority);
        QVERIFY(risk);
        QCOMPARE(authority->text(), QStringLiteral("No private keys are stored on this computer. Any two devices can recover after about 30 days; any one can recover after about 60 days."));
        QVERIFY(!risk->isVisible());
        QVERIFY(!risk->isChecked());
        QVERIFY(staged.button(QWizard::NextButton)->isEnabled());
        staged.close();
    }

    // More than three devices is never resolved by choosing an arbitrary
    // subset. Disconnecting the fourth device restores a fresh, unacknowledged
    // three-device roster.
    {
        MultisigWizard staged(m_node, &controller);
        staged.show();
        QApplication::processEvents();
        auto* name = staged.findChild<QLineEdit*>("stagedWalletNameEdit");
        QVERIFY(name);
        name->setText(QStringLiteral("DefaultTooManyHardwarePreview"));
        {
            hwi::MockRegistration mock_d{
                hwi::MakeMockMasterFromHex("303132333435363738393a3b3c3d3e3f"), ChainType::REGTEST};
            staged.findChild<QPushButton*>("refreshDevicesButton")->click();
            QApplication::processEvents();
            QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
            QCOMPARE(staged.localKeyCount(), 0);
            auto* discovery = staged.findChild<QLabel*>("hardwareDiscoveryStatus");
            QVERIFY(discovery);
            QVERIFY(discovery->text().contains(QStringLiteral("4 hardware wallets"), Qt::CaseInsensitive));
            QVERIFY(discovery->text().contains(QStringLiteral("Disconnect extras"), Qt::CaseInsensitive));
            QVERIFY(!staged.button(QWizard::NextButton)->isEnabled());
            QVERIFY(!staged.createdWallet());
            staged.next();
            QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
            QVERIFY(!staged.createdWallet());
        }

        auto* refresh = staged.findChild<QPushButton*>("refreshDevicesButton");
        auto* authority = staged.findChild<QLabel*>("fixedAuthorityLabel");
        QVERIFY(refresh);
        QVERIFY(authority);
        refresh->click();
        QApplication::processEvents();
        QCOMPARE(staged.localKeyCount(), 0);
        QCOMPARE(static_cast<int>(staged.keys().size()), 3);
        QCOMPARE(authority->text(), QStringLiteral("No private keys are stored on this computer. Any two devices can recover after about 30 days; any one can recover after about 60 days."));
        QVERIFY(staged.button(QWizard::NextButton)->isEnabled());
        QVERIFY(!staged.createdWallet());
        staged.close();
    }

    MultisigWizard wizard(m_node, &controller);
    wizard.setWalletName(QStringLiteral("FamilyVault"));
    wizard.setLocalKeyCount(1);
    wizard.addHardwareKey(mock.Fingerprint(), "Mock Trezor");
    wizard.rebuildKeyList();
    QCOMPARE(static_cast<int>(wizard.keys().size()), 2);
    wizard.setNRequired(1);
    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(1);
    wizard.setFallbackOlderOneKey(std::nullopt);

    QVERIFY2(wizard.createWallet(), qPrintable(wizard.createError()));
    QVERIFY(wizard.createdWallet());
    QVERIFY(wizard.transcript().contains(QStringLiteral("tr(musig")));
    QVERIFY(wizard.transcript().contains(QStringLiteral("older")));

    const auto dest = wizard.firstReceiveAddress();
    QVERIFY2(!!dest, "wizard did not produce a receive address");
    const std::string addr = EncodeDestination(*dest);
    QVERIFY(QString::fromStdString(addr).startsWith(QStringLiteral("bcrt1p")));

    const auto shown = wizard.verifyOnDevice(mock.Fingerprint());
    QVERIFY2(!!shown, qPrintable(QString::fromStdString(util::ErrorString(shown).original)));

    QCOMPARE(*wizard.createdWallet()->wallet().taprootRecoveryDelay(), 1u);
    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(wizard.createdWallet());
    auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
    QVERIFY(recovery);
    QVERIFY(!recovery->isHidden());
    QCOMPARE(recovery->text(), QStringLiteral("Recover Funds"));
    QVERIFY(!recovery->isChecked());
    recovery->setChecked(true);
    QApplication::processEvents();
    QVERIFY(send.getCoinControl()->m_nSequence == 1u);
}

void MultisigWizardTests::automaticPolicyBackup()
{
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    hwi::UsbEnumerateSuppress suppress_usb;

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    const std::array<AirKey, 3> keys{MakeAirKey(), MakeAirKey(), MakeAirKey()};
    QString policy_path;

    // First creation writes the exact importable package to the active
    // network datadir under its policy id, without prompting for a path.
    {
        MultisigWizard first(m_node, &controller);
        ConfigureStagedAirgapPolicy(first, QStringLiteral("AutomaticPolicyA"), keys);
        QVERIFY2(first.createWallet(), qPrintable(first.createError()));
        first.setStartId(MultisigWizard::Page_Backup);
        ShowSized(first);
        AssertBackupPage(first, MultisigWizard::kThirtyDayVaultDelay, {}, MultisigWizard::kSixtyDayVaultDelay, false);

        const QString package_text = first.findChild<QPlainTextEdit*>("policyPackageEdit")->toPlainText();
        const auto package = wallet::ParseVaultPolicyPackage(package_text.toStdString());
        QVERIFY(package);
        policy_path = QDir{GUIUtil::PathToQString(gArgs.GetDataDirNet())}.filePath(
            QStringLiteral("vault-policy-%1.json").arg(QString::fromStdString(package->policy_id)));
        QFile file{policy_path};
        QVERIFY2(file.open(QIODevice::ReadOnly), qPrintable(file.errorString()));
        QCOMPARE(file.readAll(), package_text.toUtf8());
        file.close();

        // Give the file a distinctive timestamp. Re-entering the same policy
        // through another wallet must recognize identical bytes and leave the
        // existing backup untouched.
        QVERIFY2(file.open(QIODevice::ReadWrite), qPrintable(file.errorString()));
        const QDateTime sentinel_time = QDateTime::fromMSecsSinceEpoch(946684800000LL);
        QVERIFY(file.setFileTime(sentinel_time, QFileDevice::FileModificationTime));
        file.close();
        first.close();
    }

    const QDateTime preserved_time = QFileInfo{policy_path}.lastModified();
    {
        MultisigWizard identical(m_node, &controller);
        ConfigureStagedAirgapPolicy(identical, QStringLiteral("AutomaticPolicyB"), keys);
        QVERIFY2(identical.createWallet(), qPrintable(identical.createError()));
        identical.setStartId(MultisigWizard::Page_Backup);
        ShowSized(identical);
        AssertBackupPage(identical, MultisigWizard::kThirtyDayVaultDelay, {}, MultisigWizard::kSixtyDayVaultDelay, false);
        QCOMPARE(QFileInfo{policy_path}.lastModified(), preserved_time);
        identical.close();
    }

    // A file at the deterministic path with different contents is never
    // overwritten. Persistence failure keeps the backup page incomplete even
    // though the in-memory policy itself remains available for inspection.
    const QByteArray foreign_bytes{"{\"foreign\":true}\n"};
    {
        QFile file{policy_path};
        QVERIFY2(file.open(QIODevice::WriteOnly | QIODevice::Truncate), qPrintable(file.errorString()));
        QCOMPARE(file.write(foreign_bytes), static_cast<qint64>(foreign_bytes.size()));
    }
    {
        MultisigWizard conflict(m_node, &controller);
        ConfigureStagedAirgapPolicy(conflict, QStringLiteral("AutomaticPolicyConflict"), keys);
        QVERIFY2(conflict.createWallet(), qPrintable(conflict.createError()));
        conflict.setStartId(MultisigWizard::Page_Backup);
        ShowSized(conflict);
        QCOMPARE(conflict.currentId(), static_cast<int>(MultisigWizard::Page_Backup));

        auto* path = conflict.findChild<QLabel*>("policyPackagePathLabel");
        auto* status = conflict.findChild<QLabel*>("policyPackageStatus");
        auto* print = conflict.findChild<QPushButton*>("printPolicyButton");
        auto* retry = conflict.findChild<QPushButton*>("retryPolicySaveButton");
        auto* ack = conflict.findChild<QCheckBox*>("backupAckCheck");
        QVERIFY(path);
        QVERIFY(status);
        QVERIFY(print);
        QVERIFY(retry);
        QVERIFY(ack);
        QVERIFY(status->text().contains(QStringLiteral("different"), Qt::CaseInsensitive) ||
                status->text().contains(QStringLiteral("exists"), Qt::CaseInsensitive) ||
                status->text().contains(QStringLiteral("replace"), Qt::CaseInsensitive));
        QVERIFY(retry->isVisible());
        QVERIFY(retry->isEnabled());
        QVERIFY(!ack->isEnabled());
        ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(!conflict.button(QWizard::NextButton)->isEnabled());

        QFile preserved{policy_path};
        QVERIFY2(preserved.open(QIODevice::ReadOnly), qPrintable(preserved.errorString()));
        QCOMPARE(preserved.readAll(), foreign_bytes);
        preserved.close();

        // Removing the conflicting file and using the visible Retry action
        // recovers without recreating the already-persistent wallet.
        QVERIFY(QFile::remove(policy_path));
        retry->click();
        QApplication::processEvents();
        QVERIFY(!retry->isVisible());
        QVERIFY(ack->isEnabled());
        QFile recovered{policy_path};
        QVERIFY2(recovered.open(QIODevice::ReadOnly), qPrintable(recovered.errorString()));
        QCOMPARE(recovered.readAll(), conflict.findChild<QPlainTextEdit*>("policyPackageEdit")->toPlainText().toUtf8());
        conflict.close();
    }

    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    m_node.setContext(nullptr);
}

void MultisigWizardTests::mnemonicPrintBackup()
{
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    hwi::UsbEnumerateSuppress suppress_usb;

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    QString private_pdf;
    QString policy_json;
    QString source_address;
    std::vector<SecureString> printed_phrases;
    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("MnemonicPrintBackup"));
        QVERIFY2(wizard.createWallet(), qPrintable(wizard.createError()));
        QCOMPARE(wizard.localKeyCount(), 3);
        wizard.setStartId(MultisigWizard::Page_Backup);
        ShowSized(wizard);
        AssertBackupPage(wizard, MultisigWizard::kThirtyDayVaultDelay, {},
                         MultisigWizard::kSixtyDayVaultDelay, false);

        auto* print = wizard.findChild<QPushButton*>("printPolicyButton");
        auto* print_status = wizard.findChild<QLabel*>("printPolicyStatus");
        auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
        QVERIFY(print);
        QVERIFY(print_status);
        QVERIFY(ack);
        QVERIFY(print->isEnabled());
        QVERIFY(!ack->isEnabled());
        QVERIFY(!ack->isChecked());

        policy_json = wizard.findChild<QPlainTextEdit*>("policyPackageEdit")->toPlainText();
        const QString kit_html = wizard.privateRecoveryKitHtml();
        QVERIFY(!kit_html.isEmpty());
        QVERIFY(kit_html.contains(policy_json.toHtmlEscaped()));
        const auto qr_parts = wallet::EncodeVaultPolicyQrParts(policy_json.toStdString());
        QVERIFY(qr_parts);
        const int qr_pages = (static_cast<int>(qr_parts->size()) + 1) / 2;
        QCOMPARE(static_cast<int>(kit_html.count(QStringLiteral("<div class=\"page"))), 6 + qr_pages);
        for (const std::string& part : *qr_parts) {
            QVERIFY(kit_html.contains(QString::fromStdString(part).toHtmlEscaped()));
        }
        QTextDocument kit_document;
        kit_document.setHtml(kit_html);
        const QString kit_text = kit_document.toPlainText().simplified();
        QVERIFY(kit_text.contains(QStringLiteral("UNENCRYPTED BEARER BACKUP"), Qt::CaseInsensitive));
        QVERIFY(kit_text.contains(QStringLiteral("document alone can spend the vault immediately"), Qt::CaseInsensitive));
        QVERIFY(kit_text.contains(QStringLiteral("4,320")));
        QVERIFY(kit_text.contains(QStringLiteral("8,640")));
        QVERIFY(kit_text.contains(QStringLiteral("restore"), Qt::CaseInsensitive));
        QCOMPARE(static_cast<int>(kit_text.count(QStringLiteral("24-word mnemonic"), Qt::CaseInsensitive)), 3);
        for (const auto& recovery : wizard.m_software_recovery) {
            const QString phrase = QString::fromUtf8(recovery.mnemonic.data(), static_cast<qsizetype>(recovery.mnemonic.size()));
            const QStringList words = phrase.split(QLatin1Char(' '), Qt::SkipEmptyParts);
            QCOMPARE(words.size(), 24);
            for (int word = 0; word < words.size(); ++word) {
                QVERIFY2(kit_text.contains(QStringLiteral("%1. %2").arg(word + 1).arg(words[word])),
                         qPrintable(QStringLiteral("print kit omitted word %1 for software-key slot %2")
                                        .arg(word + 1)
                                        .arg(recovery.key_index + 1)));
            }
            QVERIFY(kit_text.contains(QString::fromStdString(recovery.fingerprint)));
            QVERIFY(kit_text.contains(QString::fromStdString(recovery.path)));
            QVERIFY(kit_text.contains(QString::fromStdString(recovery.xpub)));
            printed_phrases.emplace_back(recovery.mnemonic.begin(), recovery.mnemonic.end());
        }

        // The same formatter must retain the authority boundary for mixed
        // hardware/software rosters. Use valid subsets from this canonical
        // policy so the test exercises the real mnemonic-to-policy preflight.
        for (const int local_count : {1, 2}) {
            MultisigWizard mixed(m_node, &controller);
            mixed.m_wallet_name = wizard.m_wallet_name;
            mixed.m_policy_package = wizard.m_policy_package;
            mixed.m_local_key_count = local_count;
            const auto first_local = wizard.m_software_recovery.end() - local_count;
            mixed.m_software_recovery.assign(first_local, wizard.m_software_recovery.end());
            const QString mixed_html = mixed.privateRecoveryKitHtml();
            QVERIFY(!mixed_html.isEmpty());
            QVERIFY(mixed_html.contains(policy_json.toHtmlEscaped()));
            QTextDocument mixed_document;
            mixed_document.setHtml(mixed_html);
            const QString mixed_text = mixed_document.toPlainText().simplified();
            QCOMPARE(static_cast<int>(mixed_text.count(QStringLiteral("24-word mnemonic"), Qt::CaseInsensitive)), local_count);
            if (local_count == 2) {
                QVERIFY(mixed_text.contains(QStringLiteral("after 4,320 blocks"), Qt::CaseInsensitive));
                QVERIFY(mixed_text.contains(QStringLiteral("hardware key is still required for an immediate spend"), Qt::CaseInsensitive));
            } else {
                QVERIFY(mixed_text.contains(QStringLiteral("after 8,640 blocks"), Qt::CaseInsensitive));
                QVERIFY(mixed_text.contains(QStringLiteral("second key is required at 4,320 blocks"), Qt::CaseInsensitive));
            }
        }
        MultisigWizard hardware_only(m_node, &controller);
        hardware_only.m_wallet_name = wizard.m_wallet_name;
        hardware_only.m_policy_package = wizard.m_policy_package;
        hardware_only.m_local_key_count = 0;
        const QString hardware_only_html = hardware_only.privateRecoveryKitHtml();
        QVERIFY(!hardware_only_html.isEmpty());
        QCOMPARE(static_cast<int>(hardware_only_html.count(QStringLiteral("<div class=\"page"))), 3 + qr_pages);
        QTextDocument hardware_only_document;
        hardware_only_document.setHtml(hardware_only_html);
        const QString hardware_only_text = hardware_only_document.toPlainText().simplified();
        QVERIFY(hardware_only_text.contains(QStringLiteral("complete public policy but no private keys"), Qt::CaseInsensitive));
        QVERIFY(hardware_only_text.contains(QStringLiteral("Reconnect the exact hardware wallets"), Qt::CaseInsensitive));
        QVERIFY(!hardware_only_text.contains(QStringLiteral("24-word mnemonic"), Qt::CaseInsensitive));

        // A failure before a secure temporary file can be created must leave
        // the candidate uncommitted and the acknowledgment unusable. Point
        // Qt's temp root at an isolated directory whose managed subpath is a
        // regular file, so no global/user temp state is disturbed.
        {
            QTemporaryDir isolated_temp;
            QVERIFY(isolated_temp.isValid());
            struct TempEnvironmentGuard {
                bool existed{qEnvironmentVariableIsSet("TMPDIR")};
                QByteArray value{qgetenv("TMPDIR")};
                ~TempEnvironmentGuard()
                {
                    if (existed) {
                        qputenv("TMPDIR", value);
                    } else {
                        qunsetenv("TMPDIR");
                    }
                }
            } temp_environment_guard;
            QVERIFY(qputenv("TMPDIR", isolated_temp.path().toUtf8()));
            QCOMPARE(QDir::cleanPath(QDir::tempPath()), QDir::cleanPath(isolated_temp.path()));
            QFile blocker{isolated_temp.filePath(QStringLiteral("bitcoin-core-vault-recovery"))};
            QVERIFY2(blocker.open(QIODevice::WriteOnly), qPrintable(blocker.errorString()));
            blocker.close();
            QString disk_warning;
            QTimer::singleShot(0, [&disk_warning] {
                for (QWidget* widget : QApplication::topLevelWidgets()) {
                    if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                        disk_warning = box->text();
                        box->accept();
                    }
                }
            });
            print->click();
            QVERIFY(disk_warning.contains(QStringLiteral("owner-only recovery-print directory"), Qt::CaseInsensitive));
            QVERIFY(!ack->isEnabled());
            QVERIFY(!ack->isChecked());
            QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
            QVERIFY(!wizard.createdWallet());
        }

        // Corrupting the in-memory public identity after candidate creation
        // exercises the private-kit rendering/re-derivation refusal. The
        // failed output is synchronously removed and cannot unlock Continue.
        const std::string valid_xpub{wizard.m_software_recovery.front().xpub};
        wizard.m_software_recovery.front().xpub += "-corrupt";
        QString render_warning;
        QTimer::singleShot(0, [&render_warning] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                    render_warning = box->text();
                    box->accept();
                }
            }
        });
        print->click();
        wizard.m_software_recovery.front().xpub = valid_xpub;
        QVERIFY(render_warning.contains(QStringLiteral("could not be validated"), Qt::CaseInsensitive));
        QVERIFY(!ack->isEnabled());
        QVERIFY(!ack->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        QVERIFY(!wizard.createdWallet());

        struct UrlHandlerGuard {
            ~UrlHandlerGuard() { QDesktopServices::unsetUrlHandler(QStringLiteral("file")); }
        } handler_guard;
        QDesktopServices::setUrlHandler(QStringLiteral("file"), this, "captureRecoveryUrl");
        m_opened_recovery_url.clear();
        m_opened_recovery_count = 0;
        print->click();
        QTRY_COMPARE_WITH_TIMEOUT(m_opened_recovery_count, 1, 5000);
        QVERIFY(m_opened_recovery_url.isLocalFile());
        private_pdf = m_opened_recovery_url.toLocalFile();
        QVERIFY(!private_pdf.isEmpty());
        QFile pdf{private_pdf};
        QVERIFY2(pdf.open(QIODevice::ReadOnly), qPrintable(pdf.errorString()));
        QCOMPARE(pdf.read(5), QByteArray{"%PDF-"});
        QVERIFY(pdf.size() > 100);
        pdf.close();
        const auto permissions = QFileInfo{private_pdf}.permissions();
        QVERIFY(permissions & QFileDevice::ReadOwner);
        QVERIFY(permissions & QFileDevice::WriteOwner);
        const auto forbidden = QFileDevice::ExeOwner | QFileDevice::ReadGroup | QFileDevice::WriteGroup |
                               QFileDevice::ExeGroup | QFileDevice::ReadOther | QFileDevice::WriteOther |
                               QFileDevice::ExeOther;
        QVERIFY(!(permissions & forbidden));
        QCOMPARE(print->text(), QStringLiteral("Print PDF…"));
        QCOMPARE(m_opened_recovery_count, 1);
        QVERIFY(ack->isEnabled());
        QVERIFY(!ack->isChecked());
        QVERIFY(print_status->text().contains(QStringLiteral("validated"), Qt::CaseInsensitive));
        QVERIFY(print_status->text().contains(QStringLiteral("opened"), Qt::CaseInsensitive));
        QVERIFY(print_status->text().contains(QStringLiteral("PDF"), Qt::CaseInsensitive));
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());

        // Reusing the sole action must reopen the tracked PDF rather than
        // minting a second private copy at another pathname.
        print->click();
        QTRY_COMPARE_WITH_TIMEOUT(m_opened_recovery_count, 2, 5000);
        QCOMPARE(m_opened_recovery_url.toLocalFile(), private_pdf);
        QVERIFY(QFileInfo::exists(private_pdf));
        QCOMPARE(print->text(), QStringLiteral("Print PDF…"));

        // Successful generation is necessary but not sufficient: the one
        // explicit acknowledgment is the only action that unlocks Continue.
        ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());

        // Reopening after the user has acknowledged the prior view must make
        // that acknowledgment stale. A successful reopen leaves the checkbox
        // available but unchecked, and Continue locked until it is checked
        // again for the newly viewed document.
        print->click();
        QTRY_COMPARE_WITH_TIMEOUT(m_opened_recovery_count, 3, 5000);
        QCOMPARE(m_opened_recovery_url.toLocalFile(), private_pdf);
        QVERIFY(ack->isEnabled());
        QVERIFY(!ack->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());

        // Simulate a desktop-service delivery failure with a deliberately
        // missing handler method. Even though the validated PDF still exists,
        // failure to open it must clear and disable the acknowledgment and
        // keep Continue gated. The warning is accepted by the timer.
        QDesktopServices::unsetUrlHandler(QStringLiteral("file"));
        QDesktopServices::setUrlHandler(QStringLiteral("file"), this, "missingRecoveryUrlHandler");
        QString open_warning;
        QTimer::singleShot(0, [&open_warning] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                    open_warning = box->text();
                    box->accept();
                }
            }
        });
        print->click();
        QApplication::processEvents();
        QCOMPARE(m_opened_recovery_count, 3);
        QVERIFY(open_warning.contains(QStringLiteral("No PDF viewer"), Qt::CaseInsensitive));
        QVERIFY(QFileInfo::exists(private_pdf));
        QVERIFY(!ack->isEnabled());
        QVERIFY(!ack->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        QVERIFY(print_status->text().contains(QStringLiteral("could not be opened"), Qt::CaseInsensitive));

        // A later successful reopen restores only the ability to acknowledge;
        // it never restores the stale check itself.
        QDesktopServices::unsetUrlHandler(QStringLiteral("file"));
        QDesktopServices::setUrlHandler(QStringLiteral("file"), this, "captureRecoveryUrl");
        print->click();
        QTRY_COMPARE_WITH_TIMEOUT(m_opened_recovery_count, 4, 5000);
        QCOMPARE(m_opened_recovery_url.toLocalFile(), private_pdf);
        QVERIFY(ack->isEnabled());
        QVERIFY(!ack->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());

        // Public widgets, transcript, automatic JSON, and screenshots remain
        // public-only. Secret phrases exist only in the private print kit.
        const QString public_text = wizard.findChild<QPlainTextEdit*>("policyPackageEdit")->toPlainText() +
                                    wizard.findChild<QPlainTextEdit*>("humanTranscriptEdit")->toPlainText() +
                                    VisibleText(*wizard.currentPage());
        QVERIFY(!public_text.contains(QStringLiteral("BIP39 passphrase"), Qt::CaseInsensitive));
        for (const auto& recovery : wizard.m_software_recovery) {
            QVERIFY(!public_text.contains(QString::fromUtf8(recovery.mnemonic.data(), static_cast<qsizetype>(recovery.mnemonic.size()))));
        }
        QVERIFY(!wizard.createdWallet());
        QVERIFY(!wizard.firstReceiveAddress());

        // Continue owns checked cleanup. Replacing the active PDF with a
        // directory makes deletion fail deterministically; the wizard must
        // remain on Backup. Once the pathname is removable, retrying Continue
        // deletes it and advances without creating or opening another copy.
        QVERIFY(QFile::remove(private_pdf));
        QDir directory;
        QVERIFY(directory.mkdir(private_pdf));
        wizard.next();
        QApplication::processEvents();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
        QCOMPARE(m_opened_recovery_count, 4);
        QVERIFY(QFileInfo{private_pdf}.isDir());
        QCOMPARE(print->text(), QStringLiteral("Print PDF…"));
        QVERIFY(print_status->text().contains(QStringLiteral("could not delete"), Qt::CaseInsensitive));
        QVERIFY(ack->isEnabled());
        QVERIFY(!ack->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        QVERIFY(directory.rmdir(private_pdf));
        QVERIFY(!QFileInfo::exists(private_pdf));
        ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
        wizard.next();
        QApplication::processEvents();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        QCOMPARE(m_opened_recovery_count, 4);
        QVERIFY(!QFileInfo::exists(private_pdf));
        const auto first_address = wizard.firstReceiveAddress();
        QVERIFY(first_address);
        source_address = QString::fromStdString(EncodeDestination(*first_address));
        wizard.hide();
    }
    QVERIFY2(!QFileInfo::exists(private_pdf), qPrintable(QStringLiteral("temporary private PDF survived wizard destruction: ") + private_pdf));

    // Closing/destroying a pre-commit wizard is a cancellation boundary: its
    // sole private PDF disappears, its candidate secrets are cleansed by the
    // owner, and the selected wallet name remains immediately reusable.
    QString cancelled_pdf;
    const QString cancelled_name{QStringLiteral("CancelledRecoveryCandidate")};
    {
        MultisigWizard cancelled(m_node, &controller);
        cancelled.setWalletName(cancelled_name);
        QVERIFY2(cancelled.createWallet(), qPrintable(cancelled.createError()));
        cancelled.setStartId(MultisigWizard::Page_Backup);
        ShowSized(cancelled);
        AssertBackupPage(cancelled, MultisigWizard::kThirtyDayVaultDelay, {},
                         MultisigWizard::kSixtyDayVaultDelay, false);
        struct UrlHandlerGuard {
            ~UrlHandlerGuard() { QDesktopServices::unsetUrlHandler(QStringLiteral("file")); }
        } handler_guard;
        QDesktopServices::setUrlHandler(QStringLiteral("file"), this, "captureRecoveryUrl");
        m_opened_recovery_url.clear();
        m_opened_recovery_count = 0;
        auto* cancelled_print = cancelled.findChild<QPushButton*>("printPolicyButton");
        QVERIFY(cancelled_print);
        cancelled_print->click();
        QTRY_COMPARE_WITH_TIMEOUT(m_opened_recovery_count, 1, 5000);
        cancelled_pdf = m_opened_recovery_url.toLocalFile();
        QVERIFY(QFileInfo::exists(cancelled_pdf));
        QVERIFY(!cancelled.createdWallet());
        QVERIFY(controller.listWalletDir().count(cancelled_name.toStdString()) == 0);
        cancelled.close();
    }
    QTRY_VERIFY_WITH_TIMEOUT(!QFileInfo::exists(cancelled_pdf), 5000);
    QVERIFY(controller.listWalletDir().count(cancelled_name.toStdString()) == 0);
    {
        MultisigWizard reused(m_node, &controller);
        reused.setWalletName(cancelled_name);
        QVERIFY2(reused.createWallet(), qPrintable(reused.createError()));
        QVERIFY(!reused.createdWallet());
        QVERIFY(controller.listWalletDir().count(cancelled_name.toStdString()) == 0);
    }

    // A PDF whose owner crashed is eligible for stale cleanup, but cleanup is
    // a fail-closed boundary: neither a failed removal nor a remover that lies
    // about success may permit a second managed private copy. Once the same
    // crashed-owner artifact is actually removed, one fresh kit may be made.
    {
        QTemporaryDir isolated_temp;
        QVERIFY(isolated_temp.isValid());
        struct TempEnvironmentGuard {
            bool existed{qEnvironmentVariableIsSet("TMPDIR")};
            QByteArray value{qgetenv("TMPDIR")};
            ~TempEnvironmentGuard()
            {
                if (existed) {
                    qputenv("TMPDIR", value);
                } else {
                    qunsetenv("TMPDIR");
                }
            }
        } temp_environment_guard;
        QVERIFY(qputenv("TMPDIR", isolated_temp.path().toUtf8()));
        QCOMPARE(QDir::cleanPath(QDir::tempPath()), QDir::cleanPath(isolated_temp.path()));

        const QString private_dir_path{isolated_temp.filePath(QStringLiteral("bitcoin-core-vault-recovery"))};
        QVERIFY(QDir{}.mkpath(private_dir_path));
        QVERIFY(QFile::setPermissions(private_dir_path, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
        const QString stale_pdf{QDir{private_dir_path}.filePath(QStringLiteral("complete-recovery-crashed.pdf"))};
        const QString stale_lock_path{stale_pdf + QStringLiteral(".lock")};
        QFile stale_file{stale_pdf};
        QVERIFY2(stale_file.open(QIODevice::WriteOnly), qPrintable(stale_file.errorString()));
        QCOMPARE(stale_file.write("%PDF-crashed-owner\n"), qint64{19});
        stale_file.close();

        const auto write_crashed_owner_lock = [&] {
            QLockFile live_owner{stale_lock_path};
            live_owner.setStaleLockTime(0);
            if (!live_owner.tryLock()) return false;
            QFile live_lock{stale_lock_path};
            if (!live_lock.open(QIODevice::ReadOnly)) {
                live_owner.unlock();
                return false;
            }
            QByteArray contents{live_lock.readAll()};
            live_lock.close();
            live_owner.unlock();
            const qsizetype first_newline{contents.indexOf('\n')};
            if (first_newline <= 0) return false;
            contents.replace(0, first_newline, QByteArrayLiteral("99999999"));
            QFile crashed_lock{stale_lock_path};
            if (!crashed_lock.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
            const bool written{crashed_lock.write(contents) == contents.size()};
            crashed_lock.close();
            return written;
        };
        QVERIFY(write_crashed_owner_lock());

        QString minted_pdf;
        {
            MultisigWizard stale_cleanup(m_node, &controller);
            stale_cleanup.setWalletName(QStringLiteral("CrashedOwnerRecoveryCandidate"));
            QVERIFY2(stale_cleanup.createWallet(), qPrintable(stale_cleanup.createError()));
            stale_cleanup.setStartId(MultisigWizard::Page_Backup);
            ShowSized(stale_cleanup);
            AssertBackupPage(stale_cleanup, MultisigWizard::kThirtyDayVaultDelay, {},
                             MultisigWizard::kSixtyDayVaultDelay, false);
            auto* print = stale_cleanup.findChild<QPushButton*>("printPolicyButton");
            auto* print_status = stale_cleanup.findChild<QLabel*>("printPolicyStatus");
            auto* ack = stale_cleanup.findChild<QCheckBox*>("backupAckCheck");
            QVERIFY(print);
            QVERIFY(print_status);
            QVERIFY(ack);

            struct UrlHandlerGuard {
                ~UrlHandlerGuard() { QDesktopServices::unsetUrlHandler(QStringLiteral("file")); }
            } handler_guard;
            QDesktopServices::setUrlHandler(QStringLiteral("file"), this, "captureRecoveryUrl");
            m_opened_recovery_url.clear();
            m_opened_recovery_count = 0;

            int removal_calls{0};
            QString attempted_path;
            stale_cleanup.m_private_print_remover = [&](const QString& path) {
                attempted_path = path;
                ++removal_calls;
                return removal_calls != 1; // Second attempt reports success without removing.
            };
            const auto click_and_capture_warning = [&] {
                QString warning;
                QTimer::singleShot(0, [&warning] {
                    for (QWidget* widget : QApplication::topLevelWidgets()) {
                        if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                            warning = box->text();
                            box->accept();
                        }
                    }
                });
                print->click();
                return warning;
            };

            const QString failed_warning{click_and_capture_warning()};
            QCOMPARE(removal_calls, 1);
            QCOMPARE(attempted_path, stale_pdf);
            QVERIFY(failed_warning.contains(QStringLiteral("No new recovery PDF"), Qt::CaseInsensitive));
            QVERIFY(QFileInfo::exists(stale_pdf));
            QCOMPARE(QDir{private_dir_path}.entryList({QStringLiteral("*.pdf")}, QDir::Files), QStringList{QFileInfo{stale_pdf}.fileName()});
            QCOMPARE(m_opened_recovery_count, 0);
            QVERIFY(!ack->isEnabled());
            QVERIFY(!stale_cleanup.button(QWizard::NextButton)->isEnabled());
            QVERIFY(print_status->text().contains(QStringLiteral("No new PDF"), Qt::CaseInsensitive));

            const QString still_exists_warning{click_and_capture_warning()};
            QCOMPARE(removal_calls, 2);
            QVERIFY(still_exists_warning.contains(QStringLiteral("No new recovery PDF"), Qt::CaseInsensitive));
            QVERIFY(QFileInfo::exists(stale_pdf));
            QCOMPARE(QDir{private_dir_path}.entryList({QStringLiteral("*.pdf")}, QDir::Files), QStringList{QFileInfo{stale_pdf}.fileName()});
            QCOMPARE(m_opened_recovery_count, 0);
            QVERIFY(!ack->isEnabled());

            // Recreate the dead owner's adjacent lock: successful retry must
            // reap both artifacts before minting exactly one replacement.
            QVERIFY(write_crashed_owner_lock());
            stale_cleanup.m_private_print_remover = {};
            print->click();
            QTRY_COMPARE_WITH_TIMEOUT(m_opened_recovery_count, 1, 5000);
            minted_pdf = m_opened_recovery_url.toLocalFile();
            QVERIFY(!minted_pdf.isEmpty());
            QVERIFY(minted_pdf != stale_pdf);
            QVERIFY(!QFileInfo::exists(stale_pdf));
            QVERIFY(!QFileInfo::exists(stale_lock_path));
            QCOMPARE(QDir{private_dir_path}.entryList({QStringLiteral("*.pdf")}, QDir::Files), QStringList{QFileInfo{minted_pdf}.fileName()});
            QVERIFY(ack->isEnabled());
            QVERIFY(!ack->isChecked());
            QVERIFY(!stale_cleanup.createdWallet());
        }
        QVERIFY(!QFileInfo::exists(minted_pdf));
    }

    // Exercise the actual user-facing restore journey with the kit phrases entered
    // in a different order. Matching is by full derived account xpub.
    {
        MultisigWizard restored(m_node, &controller);
        int rescan_attempts{0};
        restored.m_restore_rescan_override = [&](interfaces::Wallet& wallet) -> util::Result<void> {
            if (++rescan_attempts == 1) {
                return util::Error{Untranslated("Injected post-install genesis rescan failure")};
            }
            return wallet.rescanFromGenesis();
        };
        ShowSized(restored);
        QSignalSpy created_spy(&restored, &MultisigWizard::created);
        auto* restore_button = restored.findChild<QPushButton*>("restoreFromMnemonicButton");
        QVERIFY(restore_button);
        bool populated{false};
        bool retry_started{false};
        size_t next_phrase{0};
        QTimer modal_driver;
        connect(&modal_driver, &QTimer::timeout, this, [&] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                    box->accept();
                    continue;
                }
                auto* dialog = qobject_cast<QWizard*>(widget);
                if (!dialog || dialog == &restored || !dialog->isVisible()) continue;
                const std::array<size_t, 3> order{2, 0, 1};
                if (dialog->currentId() == 0) {
                    auto* name = dialog->findChild<QLineEdit*>("restoreWalletNameEdit");
                    auto* policy = dialog->findChild<QPlainTextEdit*>("restorePolicyEdit");
                    auto* phrase = dialog->findChild<QWidget*>("restoreMnemonicEdit");
                    QVERIFY(name);
                    QVERIFY(policy);
                    QVERIFY(phrase);
                    QVERIFY(phrase->property("secureMnemonicBacking").toBool());
                    QVERIFY(qobject_cast<QLineEdit*>(phrase) == nullptr);
                    QVERIFY(!phrase->isVisible());
                    name->setText(QStringLiteral("MnemonicSheetRestored"));
                    policy->setPlainText(policy_json);
                    dialog->next();
                    return;
                }
                if (dialog->currentId() == 1 && next_phrase < order.size()) {
                    auto* phrase = dialog->findChild<QWidget*>("restoreMnemonicEdit");
                    auto* add = dialog->findChild<QPushButton*>("restoreAddKeyButton");
                    QVERIFY(phrase);
                    QVERIFY(add);
                    const SecureString& value = printed_phrases.at(order[next_phrase++]);
                    QTest::keyClicks(phrase, QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size())));
                    add->click();
                    return;
                }
                if (dialog->currentId() == 1) {
                    QCOMPARE(dialog->findChild<QListWidget*>("restoreAcceptedKeys")->count(), 3);
                    dialog->next();
                    return;
                }
                if (dialog->currentId() == 2) {
                    QVERIFY(dialog->findChild<QLabel*>("restoreAuthoritySummary")->text().contains(QStringLiteral("All three")));
                    dialog->next();
                    return;
                }
                if (dialog->currentId() == 3 && !populated) {
                    populated = true;
                    dialog->button(QWizard::FinishButton)->click();
                    return;
                }
                if (dialog->currentId() == 3 && populated && !retry_started &&
                    dialog->button(QWizard::FinishButton)->isEnabled() &&
                    dialog->button(QWizard::FinishButton)->text().contains(QStringLiteral("Retry Rescan"))) {
                    retry_started = true;
                    dialog->button(QWizard::FinishButton)->click();
                }
            }
        });
        modal_driver.start(20);
        restore_button->click();
        QTRY_COMPARE_WITH_TIMEOUT(created_spy.count(), 1, 30000);
        modal_driver.stop();
        QVERIFY(populated);
        QVERIFY(retry_started);
        QCOMPARE(rescan_attempts, 2);
        QVERIFY(restored.createdWallet());
        QCOMPARE(QString::fromStdString(restored.createdWallet()->wallet().exportVaultPolicy()), policy_json);
        const auto restored_address = restored.firstReceiveAddress();
        QVERIFY(restored_address);
        QCOMPARE(QString::fromStdString(EncodeDestination(*restored_address)), source_address);
    }

    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    m_node.setContext(nullptr);
}

void MultisigWizardTests::wizardEdges()
{
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    gArgs.ForceSetArg("-fallbackfee", "0.0002");

    hwi::MockRegistration mock_a{hwi::MakeMockMasterFromHex(), ChainType::REGTEST};
    hwi::MockRegistration mock_b{hwi::MakeMockMasterFromHex("101112131415161718191a1b1c1d1e1f"), ChainType::REGTEST};

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    // Every preset must survive the complete, always-on GUI journey and
    // create the policy it advertises. The screenshot test covers the copy,
    // but is intentionally skipped unless an output directory is supplied.
    {
        const AirKey air = MakeAirKey();
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("PresetMaximumE2E"));
        wizard.setLocalKeyCount(1);
        wizard.addAirgappedKey(air.fpr, air.path, air.xpub, "cold-max");
        wizard.rebuildKeyList();
        wizard.setOutputType(OutputType::BECH32);
        wizard.show();
        QApplication::processEvents();
        WalkTemplateToDone(wizard, MultisigWizard::VaultTemplate::Maximum,
                           OutputType::BECH32M, /*keys=*/2, /*active=*/2,
                           /*nrequired=*/2);
        auto* package = wizard.findChild<QPlainTextEdit*>("policyPackageEdit");
        QVERIFY(package);
        const auto parsed = wallet::ParseVaultPolicyPackage(package->toPlainText().toStdString());
        QVERIFY(parsed);
        QCOMPARE(parsed->nrequired, 2);
        QVERIFY(!parsed->fallback_older);
        const auto policy = wallet::InferVaultPolicy(parsed->descs.front());
        QVERIFY(!policy.is_vault);
        QVERIFY(parsed->descs.front().find("tr(musig(") != std::string::npos);
        QVERIFY(parsed->descs.front().find("and_v(") == std::string::npos);
        QVERIFY(!wizard.createdWallet()->wallet().getVaultStatus().is_vault);
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("PresetHardwareCoordinatorE2E"));
        wizard.setLocalKeyCount(1);
        wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
        wizard.addHardwareKey(mock_b.Fingerprint(), "Mock B");
        wizard.rebuildKeyList();
        wizard.show();
        QApplication::processEvents();
        WalkTemplateToDone(wizard, MultisigWizard::VaultTemplate::HardwareCoordinator,
                           OutputType::BECH32M, /*keys=*/2, /*active=*/2,
                           /*nrequired=*/1, MultisigWizard::kDefaultVaultDelay);
        QVERIFY(!wizard.includeLocalKey());
        QVERIFY(wizard.createdWallet()->wallet().privateKeysDisabled());
        QVERIFY(wizard.createdWallet()->wallet().hasExternalSigner());
        auto* package = wizard.findChild<QPlainTextEdit*>("policyPackageEdit");
        QVERIFY(package);
        const auto parsed = wallet::ParseVaultPolicyPackage(package->toPlainText().toStdString());
        QVERIFY(parsed);
        const auto policy = wallet::InferVaultPolicy(parsed->descs.front());
        QVERIFY(policy.is_vault);
        QCOMPARE(policy.older, std::optional<uint32_t>{MultisigWizard::kDefaultVaultDelay});
        QCOMPARE(policy.recovery_m, 1);
        const size_t branch = parsed->descs.front().find(",and_v");
        QVERIFY(branch != std::string::npos);
        QVERIFY(parsed->descs.front().find(mock_a.Fingerprint()) < branch);
        QVERIFY(parsed->descs.front().find(mock_b.Fingerprint()) < branch);
        wizard.close();
    }

    {
        const AirKey active = MakeAirKey();
        const AirKey heir = MakeAirKey();
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("PresetInheritanceE2E"));
        wizard.setLocalKeyCount(1);
        wizard.addAirgappedKey(active.fpr, active.path, active.xpub, "active-cold");
        wizard.addAirgappedKey(heir.fpr, heir.path, heir.xpub, "heir");
        wizard.rebuildKeyList();
        wizard.show();
        QApplication::processEvents();
        WalkTemplateToDone(wizard, MultisigWizard::VaultTemplate::Inheritance,
                           OutputType::BECH32M, /*keys=*/3, /*active=*/2,
                           /*nrequired=*/2, MultisigWizard::kDefaultVaultDelay);
        QVERIFY(wizard.keys().back().recovery_only);
        auto* package = wizard.findChild<QPlainTextEdit*>("policyPackageEdit");
        QVERIFY(package);
        const QString package_text = package->toPlainText();
        const auto parsed = wallet::ParseVaultPolicyPackage(package_text.toStdString());
        QVERIFY(parsed);
        const auto policy = wallet::InferVaultPolicy(parsed->descs.front());
        QVERIFY(policy.is_vault);
        QCOMPARE(policy.recovery_m, 2);
        const size_t branch = parsed->descs.front().find(",and_v");
        QVERIFY(branch != std::string::npos);
        const size_t active_pos = parsed->descs.front().find(active.fpr);
        const size_t heir_pos = parsed->descs.front().find(heir.fpr);
        QVERIFY(active_pos != std::string::npos);
        QVERIFY(heir_pos != std::string::npos);
        QVERIFY(active_pos < branch);
        QVERIFY(heir_pos > branch);

        // A backup is useful only if a fresh watch wallet can import exactly
        // what the wizard emitted, reproduce address zero, and notice later
        // funding on regtest.
        const auto source_dest = wizard.firstReceiveAddress();
        QVERIFY2(source_dest, qPrintable(QString::fromStdString(util::ErrorString(source_dest).original)));
        std::vector<bilingual_str> restore_warnings;
        const uint64_t restore_flags = wallet::WALLET_FLAG_DESCRIPTORS |
                                       wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS |
                                       wallet::WALLET_FLAG_BLANK_WALLET;
        auto restored_result = m_node.walletLoader().createWallet(
            "PresetInheritanceRestored", SecureString{}, restore_flags, restore_warnings);
        QVERIFY2(restored_result, qPrintable(QString::fromStdString(util::ErrorString(restored_result).original)));
        auto restored = std::move(*restored_result);
        QVERIFY(restored->privateKeysDisabled());
        const auto imported = restored->importVaultPolicy(package_text.toStdString());
        QVERIFY2(imported, qPrintable(QString::fromStdString(util::ErrorString(imported).original)));
        const auto restored_status = restored->getVaultStatus();
        QVERIFY(restored_status.is_vault);
        QCOMPARE(restored_status.older,
                 std::optional<uint32_t>{MultisigWizard::kDefaultVaultDelay});
        QCOMPARE(restored_status.recovery_m, 2);
        const auto restored_dest = restored->getNewDestination(OutputType::BECH32M, "");
        QVERIFY2(restored_dest, qPrintable(QString::fromStdString(util::ErrorString(restored_dest).original)));
        QCOMPARE(EncodeDestination(*restored_dest), EncodeDestination(*source_dest));
        const auto restored_package = wallet::ParseVaultPolicyPackage(restored->exportVaultPolicy());
        QVERIFY(restored_package);
        QCOMPARE(restored_package->policy_id, parsed->policy_id);

        const CScript spk = GetScriptForDestination(*source_dest);
        CMutableTransaction fund = test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.at(0), /*input_vout=*/0, /*input_height=*/1,
            test.coinbaseKey, spk, 5 * COIN, /*submit=*/false);
        test.CreateAndProcessBlock({fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        const auto restored_balances = restored->getBalances();
        QVERIFY(restored_balances.is_vault);
        QVERIFY2(restored_balances.balance >= 5 * COIN,
                 "restored policy wallet did not recognize subsequent funding");
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("PresetRecoverOneLostE2E"));
        wizard.setLocalKeyCount(1);
        wizard.setIncludeLocalKey(false);
        wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
        wizard.addHardwareKey(mock_b.Fingerprint(), "Mock B");
        wizard.rebuildKeyList();
        wizard.show();
        QApplication::processEvents();
        WalkTemplateToDone(wizard, MultisigWizard::VaultTemplate::RecoverOneLost,
                           OutputType::BECH32M, /*keys=*/3, /*active=*/3,
                           /*nrequired=*/2, MultisigWizard::kDefaultVaultDelay);
        QVERIFY(wizard.includeLocalKey());
        auto* package = wizard.findChild<QPlainTextEdit*>("policyPackageEdit");
        QVERIFY(package);
        const auto parsed = wallet::ParseVaultPolicyPackage(package->toPlainText().toStdString());
        QVERIFY(parsed);
        const auto policy = wallet::InferVaultPolicy(parsed->descs.front());
        QVERIFY(policy.is_vault);
        QCOMPARE(policy.recovery_m, 2);
        const size_t branch = parsed->descs.front().find(",and_v");
        QVERIFY(branch != std::string::npos);
        QVERIFY(parsed->descs.front().find(mock_a.Fingerprint()) < branch);
        QVERIFY(parsed->descs.front().find(mock_b.Fingerprint()) < branch);
        wizard.close();
    }

    // Native SegWit is a separate product path, not just different copy. Run
    // it without the screenshot environment variable, fund it on regtest, and
    // prove the GUI produces a real P2WSH multisig witness with no vault UI.
    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("OrdinaryP2WSHE2E"));
        wizard.setLocalKeyCount(1);
        wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
        wizard.rebuildKeyList();
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32);
        wizard.setFallbackOlder(std::nullopt);
        wizard.setFallbackAfter(std::nullopt);
        wizard.show();
        QApplication::processEvents();
        WalkTemplateToDone(wizard, MultisigWizard::VaultTemplate::Custom,
                           OutputType::BECH32, /*keys=*/2, /*active=*/2,
                           /*nrequired=*/2);
        auto* package = wizard.findChild<QPlainTextEdit*>("policyPackageEdit");
        QVERIFY(package);
        const auto parsed = wallet::ParseVaultPolicyPackage(package->toPlainText().toStdString());
        QVERIFY(parsed);
        QCOMPARE(parsed->nrequired, 2);
        QVERIFY(!wallet::InferVaultPolicy(parsed->descs.front()).is_vault);
        QVERIFY(parsed->descs.front().find("wsh(sortedmulti(") != std::string::npos);

        const auto dest = wizard.firstReceiveAddress();
        QVERIFY2(dest, qPrintable(QString::fromStdString(util::ErrorString(dest).original)));
        QVERIFY(QString::fromStdString(EncodeDestination(*dest)).startsWith(QStringLiteral("bcrt1q")));
        const CScript spk = GetScriptForDestination(*dest);
        CMutableTransaction fund = test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.at(1), /*input_vout=*/0, /*input_height=*/2,
            test.coinbaseKey, spk, 10 * COIN, /*submit=*/false);
        test.CreateAndProcessBlock({fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        WalletModel* model = wizard.createdWallet();
        model->pollBalanceChanged();
        QVERIFY(model->wallet().getBalances().balance >= 10 * COIN);

        SendCoinsDialog send(style.get());
        send.setClientModel(&client);
        send.setModel(model);
        auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
        QVERIFY(recovery);
        QVERIFY(recovery->isHidden());
        const QString pay = QString::fromStdString(EncodeDestination(PKHash(test.coinbaseKey.GetPubKey())));
        const Txid txid = SendFromDialog(send, pay, 1 * COIN);
        const auto tx = model->wallet().getTx(txid);
        QVERIFY(tx);
        QCOMPARE(tx->vin.size(), size_t{1});
        QCOMPARE(tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
        QVERIFY(tx->vin[0].scriptWitness.stack.size() >= 4);
        const auto& encoded_witness_script = tx->vin[0].scriptWitness.stack.back();
        const CScript witness_script{encoded_witness_script.begin(), encoded_witness_script.end()};
        QVERIFY(GetScriptForDestination(WitnessV0ScriptHash{witness_script}) == spk);
        wizard.close();
    }

    // Bad pasted public data is rejected before a persistent wallet is
    // created, so correcting it can reuse the intended wallet name.
    {
        const AirKey good_key = MakeAirKey();
        MultisigWizard invalid(m_node, &controller);
        invalid.setWalletName(QStringLiteral("PreflightRetry"));
        invalid.setLocalKeyCount(1);
        invalid.addAirgappedKey(good_key.fpr, good_key.path, "not-an-xpub", "bad paste");
        invalid.rebuildKeyList();
        invalid.setNRequired(1);
        invalid.setOutputType(OutputType::BECH32M);
        invalid.setFallbackOlder(1);
        invalid.setFallbackOlderOneKey(std::nullopt);
        QVERIFY(!invalid.createWallet());
        QVERIFY(invalid.createError().contains(QStringLiteral("xpub"), Qt::CaseInsensitive));

        MultisigWizard corrected(m_node, &controller);
        corrected.setWalletName(QStringLiteral("PreflightRetry"));
        corrected.setLocalKeyCount(1);
        corrected.addAirgappedKey(good_key.fpr, good_key.path, good_key.xpub, "corrected paste");
        corrected.rebuildKeyList();
        corrected.setNRequired(1);
        corrected.setOutputType(OutputType::BECH32M);
        corrected.setFallbackOlder(1);
        corrected.setFallbackOlderOneKey(std::nullopt);
        QVERIFY2(corrected.createWallet(), qPrintable(corrected.createError()));
    }

    {
        const AirKey a = MakeAirKey();
        const AirKey b = MakeAirKey();
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("RoleToggleRegression"));
        wizard.setLocalKeyCount(1);
        wizard.addAirgappedKey(a.fpr, a.path, a.xpub, "active-a");
        wizard.addAirgappedKey(b.fpr, b.path, b.xpub, "heir-b");
        wizard.rebuildKeyList();
        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
        wizard.applyTemplate();
        wizard.show();
        QApplication::processEvents();
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Template));
        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
        wizard.applyTemplate();
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));

        auto* recovery_only = wizard.findChild<QCheckBox*>("recoveryOnlyCheck");
        auto* air_keys = wizard.findChild<QListWidget*>("airgappedList");
        auto* remove = wizard.findChild<QPushButton*>("removeXpubButton");
        QVERIFY(recovery_only);
        QVERIFY(air_keys);
        QVERIFY(remove);
        QCOMPARE(wizard.nActiveKeys(), 3);
        QVERIFY(!wizard.keys().back().recovery_only);

        recovery_only->setChecked(true);
        QApplication::processEvents();
        QCOMPARE(wizard.nActiveKeys(), 2);
        QVERIFY(wizard.keys().back().recovery_only);
        QVERIFY(air_keys->item(air_keys->count() - 1)->text().contains(QStringLiteral("recovery-only")));

        recovery_only->setChecked(false);
        QApplication::processEvents();
        QCOMPARE(wizard.nActiveKeys(), 3);
        QVERIFY(!wizard.keys().back().recovery_only);
        QVERIFY(air_keys->item(air_keys->count() - 1)->text().contains(QStringLiteral("active")));

        recovery_only->setChecked(true);
        air_keys->setCurrentRow(air_keys->count() - 1);
        remove->click();
        QApplication::processEvents();
        QCOMPARE(air_keys->count(), 1);
        QCOMPARE(static_cast<int>(wizard.keys().size()), 2);
        QCOMPARE(wizard.nActiveKeys(), 2);
        QVERIFY(!wizard.keys().back().recovery_only);
        QVERIFY(!recovery_only->isChecked());

        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Inheritance);
        wizard.applyTemplate();
        wizard.rebuildKeyList();
        QVERIFY(wizard.keys().back().recovery_only);
        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Maximum);
        wizard.applyTemplate();
        wizard.rebuildKeyList();
        QVERIFY(!wizard.keys().back().recovery_only);
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("FreshAbsoluteRegression"));
        wizard.setLocalKeyCount(1);
        wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
        wizard.rebuildKeyList();
        wizard.setNRequired(1);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
        wizard.applyTemplate();
        wizard.show();
        QApplication::processEvents();
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Template));
        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
        wizard.applyTemplate();
        wizard.next();
        wizard.next();
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Threshold));
        auto* delay_kind = wizard.findChild<QComboBox*>("delayKindCombo");
        auto* after = wizard.findChild<QSpinBox*>("fallbackAfterSpin");
        QVERIFY(delay_kind);
        QVERIFY(after);
        int absolute_idx{-1};
        for (int i = 0; i < delay_kind->count(); ++i) {
            if (delay_kind->itemData(i).toInt() == 1) absolute_idx = i;
        }
        QVERIFY(absolute_idx >= 0);
        delay_kind->blockSignals(true);
        delay_kind->setCurrentIndex(absolute_idx);
        delay_kind->blockSignals(false);
        QVERIFY(QMetaObject::invokeMethod(delay_kind, "currentIndexChanged", Qt::DirectConnection, Q_ARG(int, absolute_idx)));
        QApplication::processEvents();
        QCOMPARE(delay_kind->currentData().toInt(), 1);
        QVERIFY(after->isVisible());
        QVERIFY(after->value() > 1);
        QVERIFY(wizard.fallbackAfter());
        QCOMPARE(*wizard.fallbackAfter(), static_cast<uint32_t>(after->value()));
        QVERIFY(!wizard.fallbackOlder());
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("DelayOff"));
        wizard.setLocalKeyCount(1);
        wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
        wizard.rebuildKeyList();
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.setFallbackOlder(std::nullopt);
        wizard.show();
        QApplication::processEvents();
        WalkScroogeToDone(wizard, /*nrequired=*/2, /*delay_blocks=*/0);
        QVERIFY(wizard.createdWallet());
        QVERIFY(!wizard.createdWallet()->wallet().taprootRecoveryDelay());
        QVERIFY(!wizard.transcript().contains(QStringLiteral("Scrooge vault")));
        SendCoinsDialog send(style.get());
        send.setClientModel(&client);
        send.setModel(wizard.createdWallet());
        auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
        QVERIFY(recovery);
        QVERIFY(recovery->isHidden());
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("Delay144"));
        wizard.setLocalKeyCount(1);
        wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
        wizard.rebuildKeyList();
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.setFallbackOlder(144);
        wizard.show();
        QApplication::processEvents();
        WalkScroogeToDone(wizard, /*nrequired=*/2, /*delay_blocks=*/144);
        QVERIFY2(wizard.createdWallet(), qPrintable(wizard.createError()));
        QCOMPARE(*wizard.createdWallet()->wallet().taprootRecoveryDelay(), 144u);
        auto* pkg_text = wizard.findChild<QPlainTextEdit*>("policyPackageEdit");
        auto* human_text = wizard.findChild<QPlainTextEdit*>("humanTranscriptEdit");
        QVERIFY(pkg_text);
        QVERIFY(human_text);
        QVERIFY(pkg_text->toPlainText().contains(QStringLiteral("bitcoin-core-vault-policy")));
        auto parsed_pkg = wallet::ParseVaultPolicyPackage(pkg_text->toPlainText().toStdString());
        QVERIFY(parsed_pkg);
        QString public_error;
        QVERIFY2(PublicOnlyDescriptors(parsed_pkg->descs, public_error), qPrintable(public_error));
        QVERIFY(!pkg_text->toPlainText().contains(QStringLiteral("Scrooge vault")));
        QVERIFY(human_text->toPlainText().contains(QStringLiteral("Scrooge vault")));
        SendCoinsDialog send(style.get());
        send.setClientModel(&client);
        send.setModel(wizard.createdWallet());
        auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
        QVERIFY(recovery);
        QVERIFY(!recovery->isHidden());
        QCOMPARE(recovery->text(), QStringLiteral("Recover Funds"));
        recovery->setChecked(true);
        QApplication::processEvents();
        QCOMPARE(*send.getCoinControl()->m_nSequence, 144u);
        wizard.close();
    }

    {
        const AirKey a = MakeAirKey();
        const AirKey b = MakeAirKey();
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("AirOnly"));
        wizard.setIncludeLocalKey(false);
        wizard.addAirgappedKey(a.fpr, a.path, a.xpub, "cold-a");
        wizard.addAirgappedKey(b.fpr, b.path, b.xpub, "cold-b");
        wizard.rebuildKeyList();
        QCOMPARE(static_cast<int>(wizard.keys().size()), 2);
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.show();
        QApplication::processEvents();
        WalkScroogeToDone(wizard, /*nrequired=*/2, /*delay_blocks=*/0);
        QVERIFY2(wizard.createdWallet(), qPrintable(wizard.createError()));
        QVERIFY(wizard.createdWallet()->wallet().privateKeysDisabled());
        QVERIFY(!wizard.transcript().contains(QStringLiteral("This computer")));
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("HwOnly"));
        wizard.setIncludeLocalKey(false);
        wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
        wizard.addHardwareKey(mock_b.Fingerprint(), "Mock B");
        wizard.rebuildKeyList();
        QCOMPARE(static_cast<int>(wizard.keys().size()), 2);
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.setFallbackOlder(1);
        wizard.show();
        QApplication::processEvents();
        WalkScroogeToDone(wizard, /*nrequired=*/2, /*delay_blocks=*/1);
        QVERIFY2(wizard.createdWallet(), qPrintable(wizard.createError()));
        QCOMPARE(*wizard.createdWallet()->wallet().taprootRecoveryDelay(), 1u);
        QVERIFY(wizard.transcript().contains(QStringLiteral("Scrooge vault")));
        SendCoinsDialog send(style.get());
        send.setClientModel(&client);
        send.setModel(wizard.createdWallet());
        auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
        QVERIFY(recovery);
        QVERIFY(!recovery->isHidden());
        QCOMPARE(recovery->text(), QStringLiteral("Recover Funds"));
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("AfterHeight"));
        wizard.setLocalKeyCount(1);
        wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
        wizard.rebuildKeyList();
        wizard.setNRequired(1);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.setFallbackOlder(std::nullopt);
        wizard.setFallbackAfter(500);
        QVERIFY2(wizard.createWallet(), qPrintable(wizard.createError()));
        QVERIFY(wizard.transcript().contains(QStringLiteral("after")));
        QVERIFY(wizard.transcript().contains(QStringLiteral("500")));
        QVERIFY(wizard.transcript().contains(QStringLiteral("CLTV")));
        const auto st = wizard.createdWallet()->wallet().getVaultStatus();
        QVERIFY(st.is_vault);
        QVERIFY(st.after);
        QCOMPARE(*st.after, 500u);
        QVERIFY(!st.older);
        SendCoinsDialog send(style.get());
        send.setClientModel(&client);
        send.setModel(wizard.createdWallet());
        auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
        QVERIFY(recovery);
        QVERIFY(!recovery->isHidden());
        QCOMPARE(recovery->text(), QStringLiteral("Recover Funds"));
        const QString absolute_copy = recovery->text() + QLatin1Char(' ') + recovery->toolTip();
        QVERIFY(!absolute_copy.contains(QStringLiteral("relative delay"), Qt::CaseInsensitive));
        QVERIFY(!absolute_copy.contains(QStringLiteral("starts over"), Qt::CaseInsensitive));
        QVERIFY(!absolute_copy.contains(QStringLiteral("new clock"), Qt::CaseInsensitive));
        recovery->setChecked(true);
        QApplication::processEvents();
        QCOMPARE(*send.getCoinControl()->m_locktime, 500u);
        QVERIFY(send.getCoinControl()->m_script_path);
        QCOMPARE(send.getCoinControl()->m_min_depth, std::numeric_limits<int>::max());
        wizard.close();
    }
}

void MultisigWizardTests::vaultGuiSend()
{
    TestChain100Setup test;
    test.mineBlocks(5);
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    gArgs.ForceSetArg("-fallbackfee", "0.0002");

    hwi::MockRegistration mock{hwi::MakeMockMasterFromHex(), ChainType::REGTEST};

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    MultisigWizard wizard(m_node, &controller);
    wizard.setWalletName(QStringLiteral("GuiSendVault"));
    wizard.setLocalKeyCount(1);
    wizard.addHardwareKey(mock.Fingerprint(), "Mock Trezor");
    wizard.rebuildKeyList();
    wizard.setNRequired(2);
    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(1);
    wizard.show();
    QApplication::processEvents();
    WalkScroogeToDone(wizard, /*nrequired=*/2, /*delay_blocks=*/1);
    QVERIFY2(wizard.createdWallet(), qPrintable(wizard.createError()));
    WalletModel* model = wizard.createdWallet();
    const auto dest = wizard.firstReceiveAddress();
    QVERIFY2(!!dest, "no receive address");
    const CScript spk = GetScriptForDestination(*dest);

    auto fund = [&](size_t coin_i) {
        const int height = static_cast<int>(coin_i) + 1;
        CMutableTransaction tx = test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.at(coin_i), /*input_vout=*/0, height, test.coinbaseKey,
            spk, 10 * COIN, /*submit=*/false);
        test.CreateAndProcessBlock({tx}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    };
    fund(0);
    fund(1);
    fund(2);
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    QVERIFY2(model->wallet().getBalances().balance >= 30 * COIN, "vault was not funded");
    {
        OverviewPage overview(style.get());
        overview.setClientModel(&client);
        overview.setWalletModel(model);
        const auto bals = model->wallet().getBalances();
        QVERIFY(bals.is_vault);
        overview.setBalance(bals);
        QApplication::processEvents();
        auto* immediate = overview.findChild<QLabel*>("vaultImmediateStatusLabel");
        auto* recovery_status = overview.findChild<QLabel*>("vaultRecoveryStatusLabel");
        QVERIFY(immediate);
        QVERIFY(recovery_status);
        QVERIFY(!immediate->isHidden());
        QVERIFY(!recovery_status->isHidden());
        QVERIFY(!overview.findChild<QLabel*>("labelVaultPathNote"));
        QVERIFY(bals.vault_immediate > 0 || bals.vault_recoverable > 0);
        auto* balance_value = overview.findChild<QLabel*>("labelBalance");
        auto* total_text = overview.findChild<QLabel*>("labelTotalText");
        auto* total_value = overview.findChild<QLabel*>("labelTotal");
        QVERIFY(balance_value);
        QVERIFY(total_text);
        QVERIFY(total_value);
        QVERIFY(balance_value->isHidden());
        QCOMPARE(total_text->text(), QStringLiteral("Total balance:"));
        QVERIFY(!total_value->isHidden());
    }

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
    QVERIFY(recovery);
    QVERIFY(!recovery->isHidden());
    QCOMPARE(recovery->text(), QStringLiteral("Recover Funds"));
    QVERIFY(!recovery->isChecked());

    recovery->setChecked(true);
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 1u);
    QVERIFY(send.getCoinControl()->m_script_path);
    send.clear();
    QApplication::processEvents();
    QVERIFY(!recovery->isChecked());
    QVERIFY(!send.getCoinControl()->m_nSequence);
    QVERIFY(!send.getCoinControl()->m_locktime);
    QVERIFY(!send.getCoinControl()->m_script_path);

    const QString pay = QString::fromStdString(EncodeDestination(PKHash(test.coinbaseKey.GetPubKey())));
    QString keypath_copy;
    const Txid keypath_id = SendFromDialog(send, pay, 1 * COIN, &keypath_copy);
    QVERIFY(keypath_copy.contains(QStringLiteral("You can increase the fee later.")));
    const auto keypath_tx = model->wallet().getTx(keypath_id);
    QVERIFY(keypath_tx);
    QCOMPARE(keypath_tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
    QCOMPARE(static_cast<int>(keypath_tx->vin[0].scriptWitness.stack.size()), 1);
    const int64_t keypath_vsize = GetVirtualTransactionSize(*keypath_tx);
    QVERIFY(keypath_vsize < 180);
    QVERIFY(model->wallet().transactionCanBeBumped(keypath_id));
    QVERIFY(!recovery->isChecked());
    QVERIFY(!send.getCoinControl()->m_nSequence);
    QVERIFY(!send.getCoinControl()->m_script_path);

    TransactionView view(style.get());
    view.setModel(model);
    QApplication::processEvents();
    BumpFeeView(view, keypath_id);
    QVERIFY(!model->wallet().transactionCanBeBumped(keypath_id));

    send.addEntry();
    auto* entries = send.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries);
    QCOMPARE(entries->count(), 2);
    auto* entry0 = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    auto* entry1 = qobject_cast<SendCoinsEntry*>(entries->itemAt(1)->widget());
    QVERIFY(entry0);
    QVERIFY(entry1);
    const QString pay2 = QString::fromStdString(EncodeDestination(WitnessV1Taproot{XOnlyPubKey(GenerateRandomKey().GetPubKey())}));
    entry0->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    entry0->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    entry1->findChild<QValidatedLineEdit*>("payTo")->setText(pay2);
    entry1->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    auto two_id = std::make_shared<Txid>();
    QObject::connect(&send, &SendCoinsDialog::coinsSent, [two_id](const Txid& hash) { *two_id = hash; });
    ConfirmSend();
    QVERIFY(QMetaObject::invokeMethod(&send, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY(!two_id->IsNull());
    const auto two_tx = model->wallet().getTx(*two_id);
    QVERIFY(two_tx);
    QVERIFY(two_tx->vout.size() >= 2);
    QCOMPARE(two_tx->vin[0].scriptWitness.stack.size(), 1u);

    recovery->setChecked(true);
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 1u);
    QString recovery_copy;
    const Txid recovery_id = SendFromDialog(send, pay, 1 * COIN, &recovery_copy);
    QVERIFY(recovery_copy.contains(QStringLiteral("You can increase the fee later.")));
    QVERIFY(recovery_copy.contains(QStringLiteral("Recovery spend:")));
    QVERIFY(recovery_copy.contains(QStringLiteral("relative delay starts over")));
    QVERIFY(!recovery->isChecked());
    QVERIFY(!send.getCoinControl()->m_nSequence);
    QVERIFY(!send.getCoinControl()->m_locktime);
    QVERIFY(!send.getCoinControl()->m_script_path);
    const auto recovery_tx = model->wallet().getTx(recovery_id);
    QVERIFY(recovery_tx);
    QCOMPARE(recovery_tx->vin[0].nSequence, 1u);
    QVERIFY(recovery_tx->vin[0].scriptWitness.stack.size() > 1);
    const int64_t recovery_vsize = GetVirtualTransactionSize(*recovery_tx);
    QVERIFY(recovery_vsize > keypath_vsize);
    QVERIFY(model->wallet().transactionCanBeBumped(recovery_id));
    model->pollBalanceChanged();
    QApplication::processEvents();
    BumpFeeView(view, recovery_id);
    QVERIFY(!model->wallet().transactionCanBeBumped(recovery_id));

    // A loss notification arriving while the modal confirmation is open must
    // still block the already-prepared immediate transaction.
    auto* race_entries = send.findChild<QVBoxLayout*>("entries");
    QVERIFY(race_entries);
    auto* race_entry = qobject_cast<SendCoinsEntry*>(race_entries->itemAt(0)->widget());
    QVERIFY(race_entry);
    race_entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    race_entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    auto race_txid = std::make_shared<Txid>();
    QObject::connect(&send, &SendCoinsDialog::coinsSent, [race_txid](const Txid& hash) { *race_txid = hash; });
    LoseSignerAndConfirm(*model, mock.Fingerprint());
    QVERIFY(QMetaObject::invokeMethod(&send, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY(race_txid->IsNull());

    model->updateTransaction();
    model->pollBalanceChanged();
    QApplication::processEvents();
    auto* open_lost = send.findChild<QLabel*>("vaultLostSignerLabel");
    auto* open_balance = send.findChild<QLabel*>("labelBalance");
    auto* open_send_btn = send.findChild<QPushButton*>("sendButton");
    QVERIFY(open_lost);
    QVERIFY(open_balance);
    QVERIFY(open_send_btn);
    QVERIFY(!open_lost->isHidden());
    QVERIFY(open_balance->text().startsWith(QStringLiteral("0.00000000")));
    QVERIFY(!open_send_btn->isEnabled());
    QVERIFY(!recovery->isChecked());

    auto* guard_entries = send.findChild<QVBoxLayout*>("entries");
    QVERIFY(guard_entries);
    auto* guard_entry = qobject_cast<SendCoinsEntry*>(guard_entries->itemAt(0)->widget());
    QVERIFY(guard_entry);
    guard_entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    guard_entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    Txid guarded_txid;
    QObject::connect(&send, &SendCoinsDialog::coinsSent, [&guarded_txid](const Txid& hash) { guarded_txid = hash; });
    QString guard_message;
    ConfirmMessage(&guard_message, std::chrono::milliseconds{0});
    QVERIFY(QMetaObject::invokeMethod(&send, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY(guarded_txid.IsNull());

    SendCoinsDialog send_lost(style.get());
    send_lost.setClientModel(&client);
    send_lost.setModel(model);
    auto* lost = send_lost.findChild<QLabel*>("vaultLostSignerLabel");
    QVERIFY(lost);
    QVERIFY(!lost->isHidden());
    QVERIFY(lost->text().contains(QStringLiteral("lost")));
    QVERIFY(lost->text().contains(QStringLiteral("mock"), Qt::CaseInsensitive));
    QVERIFY(lost->text().contains(QString::fromStdString(mock.Fingerprint())));
    auto* lost_name = send_lost.findChild<QLabel*>("labelBalanceName");
    auto* lost_bal = send_lost.findChild<QLabel*>("labelBalance");
    QVERIFY(lost_name);
    QVERIFY(lost_bal);
    QVERIFY(lost_name->text().contains(QStringLiteral("Spendable now")));
    QVERIFY(lost_bal->text().startsWith(QStringLiteral("0.00000000")));
    auto* send_btn = send_lost.findChild<QPushButton*>("sendButton");
    QVERIFY(send_btn);
    QVERIFY(!send_btn->isEnabled());
    auto* rec_lost = send_lost.findChild<QRadioButton*>("vaultRecoveryModeButton");
    auto* normal_lost = send_lost.findChild<QRadioButton*>("vaultNormalModeButton");
    QVERIFY(rec_lost);
    QVERIFY(normal_lost);
    QVERIFY(!rec_lost->isChecked());
    rec_lost->setChecked(true);
    QApplication::processEvents();
    QVERIFY(send_btn->isEnabled());

    // Restoring the signer must return this already-open dialog to the
    // immediate path without silently retaining the recovery opt-in.
    normal_lost->setChecked(true);
    model->wallet().setLostSigner(mock.Fingerprint(), false);
    QVERIFY(model->wallet().getVaultStatus().lost_signers.empty());
    model->updateTransaction();
    model->pollBalanceChanged();
    send_lost.setBalance(model->wallet().getBalances());
    QApplication::processEvents();
    QVERIFY(lost->isHidden());
    QVERIFY(!rec_lost->isChecked());
    QVERIFY(send_btn->isEnabled());
    wizard.close();

    // Exercise the relative-delay lifecycle through the actual Qt send flow:
    // one-confirmation coins are unavailable to older(2), become recoverable
    // after the next block, and recovery change starts at depth one again.
    {
        MultisigWizard relative(m_node, &controller);
        relative.setWalletName(QStringLiteral("GuiRelativeLifecycle"));
        relative.setLocalKeyCount(1);
        relative.addHardwareKey(mock.Fingerprint(), "Mock Trezor");
        relative.rebuildKeyList();
        relative.setNRequired(2);
        relative.setOutputType(OutputType::BECH32M);
        relative.setFallbackOlder(2);
        relative.setFallbackOlderOneKey(std::nullopt);
        QVERIFY2(relative.createWallet(), qPrintable(relative.createError()));
        WalletModel* relative_model = relative.createdWallet();
        QVERIFY(relative_model);
        const auto relative_dest = relative.firstReceiveAddress();
        QVERIFY(relative_dest);
        const CScript relative_spk = GetScriptForDestination(*relative_dest);
        CMutableTransaction relative_fund = test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.at(3), /*input_vout=*/0, /*input_height=*/4, test.coinbaseKey,
            relative_spk, 10 * COIN, /*submit=*/false);
        test.CreateAndProcessBlock({relative_fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        relative_model->pollBalanceChanged();
        QApplication::processEvents();

        const auto young = relative_model->wallet().getBalances();
        QVERIFY(young.is_vault);
        QCOMPARE(young.vault_recoverable, 0);
        QCOMPARE(young.vault_awaiting, 10 * COIN);
        QVERIFY(young.vault_blocks_remaining);
        QCOMPARE(*young.vault_blocks_remaining, 1);

        OverviewPage relative_overview(style.get());
        relative_overview.setClientModel(&client);
        relative_overview.setWalletModel(relative_model);
        relative_overview.setBalance(young);
        QApplication::processEvents();
        auto* recovery_status = relative_overview.findChild<QLabel*>("vaultRecoveryStatusLabel");
        auto* recovery_option = relative_overview.findChild<QLabel*>("vaultRecoveryOptionLabel");
        QVERIFY(recovery_status);
        QVERIFY(recovery_option);
        QVERIFY(!recovery_status->isHidden());
        QVERIFY(recovery_status->text().contains(QStringLiteral("1 block")));
        QVERIFY(!recovery_option->text().isEmpty());

        SendCoinsDialog relative_send(style.get());
        relative_send.setClientModel(&client);
        relative_send.setModel(relative_model);
        auto* relative_recovery = relative_send.findChild<QRadioButton*>("vaultRecoveryModeButton");
        auto* relative_lost = relative_send.findChild<QLabel*>("vaultLostSignerLabel");
        auto* relative_balance = relative_send.findChild<QLabel*>("labelBalance");
        auto* relative_send_button = relative_send.findChild<QPushButton*>("sendButton");
        QVERIFY(relative_recovery);
        QVERIFY(relative_lost);
        QVERIFY(relative_balance);
        QVERIFY(relative_send_button);

        // Use an otherwise untouched confirmed coin to prove that clearing a
        // lost-signer flag restores both the immediate balance and the action
        // in an already-open dialog.
        relative_model->wallet().setLostSigner(mock.Fingerprint(), true);
        relative_send.setBalance(relative_model->wallet().getBalances());
        QApplication::processEvents();
        QVERIFY(!relative_lost->isHidden());
        // This advanced 2-of-2 policy has no reduced-quorum branch. Maturity
        // cannot compensate for the marked-lost hardware key, so do not show
        // a misleading one-block countdown.
        QVERIFY(relative_lost->text().contains(QStringLiteral("Reconnect this signer")));
        QVERIFY(relative_lost->text().contains(QStringLiteral("not available yet"), Qt::CaseInsensitive));
        QVERIFY(relative_balance->text().startsWith(QStringLiteral("0.00000000")));
        QVERIFY(!relative_send_button->isEnabled());
        QVERIFY(!relative_recovery->isChecked());
        relative_model->wallet().setLostSigner(mock.Fingerprint(), false);
        relative_send.setBalance(relative_model->wallet().getBalances());
        QApplication::processEvents();
        QVERIFY(relative_lost->isHidden());
        QVERIFY(!relative_balance->text().startsWith(QStringLiteral("0.00000000")));
        QVERIFY(relative_send_button->isEnabled());
        QVERIFY(!relative_recovery->isChecked());

        relative_recovery->setChecked(true);
        QApplication::processEvents();
        QCOMPARE(*relative_send.getCoinControl()->m_nSequence, 2u);
        QVERIFY(relative_send.getCoinControl()->m_script_path);
        auto* relative_entries = relative_send.findChild<QVBoxLayout*>("entries");
        QVERIFY(relative_entries);
        auto* relative_entry = qobject_cast<SendCoinsEntry*>(relative_entries->itemAt(0)->widget());
        QVERIFY(relative_entry);
        relative_entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
        relative_entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
        Txid premature_relative;
        QObject::connect(&relative_send, &SendCoinsDialog::coinsSent,
                         [&premature_relative](const Txid& hash) { premature_relative = hash; });
        QVERIFY(QMetaObject::invokeMethod(&relative_send, "sendButtonClicked", Q_ARG(bool, false)));
        QVERIFY(premature_relative.IsNull());
        QVERIFY(relative_recovery->isChecked());

        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        relative_model->pollBalanceChanged();
        QApplication::processEvents();
        const auto mature = relative_model->wallet().getBalances();
        QCOMPARE(mature.vault_awaiting, 0);
        QCOMPARE(mature.vault_recoverable, 10 * COIN);

        QString relative_confirmation;
        const Txid relative_id = SendFromDialog(relative_send, pay, 1 * COIN, &relative_confirmation);
        QVERIFY(relative_confirmation.contains(QStringLiteral("relative delay starts over")));
        const auto relative_tx = relative_model->wallet().getTx(relative_id);
        QVERIFY(relative_tx);
        QCOMPARE(relative_tx->vin[0].nSequence, 2u);
        QVERIFY(relative_tx->vin[0].scriptWitness.stack.size() > 1);
        QVERIFY(!relative_recovery->isChecked());

        test.CreateAndProcessBlock({CMutableTransaction{*relative_tx}}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        relative_model->pollBalanceChanged();
        QApplication::processEvents();
        const auto fresh_change = relative_model->wallet().getBalances();
        QCOMPARE(fresh_change.vault_recoverable, 0);
        QVERIFY(fresh_change.vault_awaiting > 8 * COIN);
        QVERIFY(fresh_change.vault_blocks_remaining);
        QCOMPARE(*fresh_change.vault_blocks_remaining, 1);
        relative_overview.setBalance(fresh_change);
        QApplication::processEvents();
        QVERIFY(!recovery_status->isHidden());
        QVERIFY(recovery_status->text().contains(QStringLiteral("1 block")));

        relative_recovery->setChecked(true);
        QApplication::processEvents();
        relative_entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
        relative_entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
        Txid premature_change;
        QObject::connect(&relative_send, &SendCoinsDialog::coinsSent,
                         [&premature_change](const Txid& hash) { premature_change = hash; });
        QVERIFY(QMetaObject::invokeMethod(&relative_send, "sendButtonClicked", Q_ARG(bool, false)));
        QVERIFY(premature_change.IsNull());

        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        relative_model->pollBalanceChanged();
        const auto rematured_change = relative_model->wallet().getBalances();
        QCOMPARE(rematured_change.vault_awaiting, 0);
        QVERIFY(rematured_change.vault_recoverable > 8 * COIN);
        relative.close();
    }

    // Exercise absolute-height recovery end to end. The GUI must reject the
    // script path below after(H), then create a CLTV transaction at H without
    // substituting relative sequence semantics.
    {
        const uint32_t after_height = static_cast<uint32_t>(m_node.getNumBlocks() + 3);
        MultisigWizard absolute(m_node, &controller);
        absolute.setWalletName(QStringLiteral("GuiAbsoluteLifecycle"));
        absolute.setLocalKeyCount(1);
        absolute.addHardwareKey(mock.Fingerprint(), "Mock Trezor");
        absolute.rebuildKeyList();
        absolute.setNRequired(2);
        absolute.setOutputType(OutputType::BECH32M);
        absolute.setFallbackOlder(std::nullopt);
        absolute.setFallbackAfter(after_height);
        QVERIFY2(absolute.createWallet(), qPrintable(absolute.createError()));
        WalletModel* absolute_model = absolute.createdWallet();
        QVERIFY(absolute_model);
        const auto absolute_dest = absolute.firstReceiveAddress();
        QVERIFY(absolute_dest);
        const CScript absolute_spk = GetScriptForDestination(*absolute_dest);
        CMutableTransaction absolute_fund = test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.at(4), /*input_vout=*/0, /*input_height=*/5, test.coinbaseKey,
            absolute_spk, 10 * COIN, /*submit=*/false);
        test.CreateAndProcessBlock({absolute_fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        absolute_model->pollBalanceChanged();
        QApplication::processEvents();
        const auto before_height = absolute_model->wallet().getBalances();
        QCOMPARE(before_height.vault_recoverable, 0);
        QCOMPARE(before_height.vault_awaiting, 10 * COIN);
        QVERIFY(before_height.vault_blocks_remaining);
        QVERIFY(*before_height.vault_blocks_remaining > 0);

        SendCoinsDialog absolute_send(style.get());
        absolute_send.setClientModel(&client);
        absolute_send.setModel(absolute_model);
        auto* absolute_recovery = absolute_send.findChild<QRadioButton*>("vaultRecoveryModeButton");
        QVERIFY(absolute_recovery);
        absolute_recovery->setChecked(true);
        QApplication::processEvents();
        QVERIFY(!absolute_send.getCoinControl()->m_nSequence);
        QCOMPARE(*absolute_send.getCoinControl()->m_locktime, after_height);
        QVERIFY(absolute_send.getCoinControl()->m_script_path);
        auto* absolute_entries = absolute_send.findChild<QVBoxLayout*>("entries");
        QVERIFY(absolute_entries);
        auto* absolute_entry = qobject_cast<SendCoinsEntry*>(absolute_entries->itemAt(0)->widget());
        QVERIFY(absolute_entry);
        absolute_entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
        absolute_entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
        Txid premature_absolute;
        QObject::connect(&absolute_send, &SendCoinsDialog::coinsSent,
                         [&premature_absolute](const Txid& hash) { premature_absolute = hash; });
        QVERIFY(QMetaObject::invokeMethod(&absolute_send, "sendButtonClicked", Q_ARG(bool, false)));
        QVERIFY(premature_absolute.IsNull());
        QVERIFY(absolute_recovery->isChecked());

        while (m_node.getNumBlocks() < static_cast<int>(after_height)) {
            test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        }
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        absolute_model->pollBalanceChanged();
        QApplication::processEvents();
        const auto at_height = absolute_model->wallet().getBalances();
        QCOMPARE(at_height.vault_awaiting, 0);
        QCOMPARE(at_height.vault_recoverable, 10 * COIN);

        QString absolute_confirmation;
        const Txid absolute_id = SendFromDialog(absolute_send, pay, 1 * COIN, &absolute_confirmation);
        QVERIFY(absolute_confirmation.contains(QStringLiteral("absolute block height")));
        QVERIFY(!absolute_confirmation.contains(QStringLiteral("relative delay starts over")));
        const auto absolute_tx = absolute_model->wallet().getTx(absolute_id);
        QVERIFY(absolute_tx);
        QCOMPARE(absolute_tx->nLockTime, after_height);
        QVERIFY(absolute_tx->vin[0].nSequence != CTxIn::SEQUENCE_FINAL);
        QVERIFY(absolute_tx->vin[0].scriptWitness.stack.size() > 1);
        QVERIFY(!absolute_recovery->isChecked());
        QVERIFY(!absolute_send.getCoinControl()->m_nSequence);
        QVERIFY(!absolute_send.getCoinControl()->m_locktime);
        QVERIFY(!absolute_send.getCoinControl()->m_script_path);
        absolute.close();
    }
}

void MultisigWizardTests::vaultGuiStagedRecovery()
{
    TestChain100Setup test;
    test.mineBlocks(5);
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    gArgs.ForceSetArg("-fallbackfee", "0.0002");

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    std::unique_ptr<ReceiveCoinsDialog> receive_dialog;
    WalletModel* blank_time_model{nullptr};
    int blank_time_address_type_count{-1};
    bool blank_time_can_get_addresses{true};
    bool blank_time_receive_button_enabled{true};
    connect(&controller, &WalletController::walletAdded, this, [&](WalletModel* added_model) {
        blank_time_model = added_model;
        receive_dialog = std::make_unique<ReceiveCoinsDialog>(style.get());
        receive_dialog->setModel(added_model);
        auto* address_type = receive_dialog->findChild<QComboBox*>("addressType");
        auto* receive_button = receive_dialog->findChild<QPushButton*>("receiveButton");
        blank_time_address_type_count = address_type ? address_type->count() : -1;
        blank_time_can_get_addresses = added_model->wallet().canGetAddresses();
        blank_time_receive_button_enabled = receive_button && receive_button->isEnabled();
    });

    MultisigWizard wizard(m_node, &controller);
    wizard.setWalletName(QStringLiteral("GuiStagedVault"));
    wizard.setLocalKeyCount(3);
    wizard.rebuildKeyList();
    wizard.show();
    WalkStagedRecoveryToDone(wizard, /*first_delay=*/2, /*final_delay=*/4);
    WalletModel* model = wizard.createdWallet();
    QVERIFY(model);
    QVERIFY(receive_dialog);
    QCOMPARE(blank_time_model, model);
    QCOMPARE(blank_time_address_type_count, 0);
    QVERIFY(!blank_time_can_get_addresses);
    QVERIFY(!blank_time_receive_button_enabled);
    QApplication::processEvents();
    auto* receive_type = receive_dialog->findChild<QComboBox*>("addressType");
    auto* receive_button = receive_dialog->findChild<QPushButton*>("receiveButton");
    QVERIFY(receive_type);
    QVERIFY(receive_button);
    QCOMPARE(receive_type->count(), 1);
    QCOMPARE(receive_type->currentData().toInt(), static_cast<int>(OutputType::BECH32M));
    QVERIFY(receive_button->isEnabled());
    QVERIFY(!model->wallet().canGetAddresses(OutputType::LEGACY));
    QVERIFY(!model->wallet().canGetAddresses(OutputType::P2SH_SEGWIT));
    QVERIFY(!model->wallet().canGetAddresses(OutputType::BECH32));
    QVERIFY(model->wallet().canGetAddresses(OutputType::BECH32M));

    ReceiveCoinsDialog reopened_receive_dialog(style.get());
    reopened_receive_dialog.setModel(model);
    auto* reopened_type = reopened_receive_dialog.findChild<QComboBox*>("addressType");
    auto* reopened_button = reopened_receive_dialog.findChild<QPushButton*>("receiveButton");
    QVERIFY(reopened_type);
    QVERIFY(reopened_button);
    QCOMPARE(reopened_type->count(), 1);
    QCOMPARE(reopened_type->currentData().toInt(), static_cast<int>(OutputType::BECH32M));
    QVERIFY(reopened_button->isEnabled());

    const int request_count = model->getRecentRequestsTableModel()->rowCount({});
    QTimer::singleShot(0, [] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* message = qobject_cast<QMessageBox*>(widget)) message->accept();
        }
    });
    receive_button->click();
    QApplication::processEvents();
    QCOMPARE(model->getRecentRequestsTableModel()->rowCount({}), request_count + 1);
    bool found_taproot_request{false};
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (!widget->inherits("ReceiveRequestDialog")) continue;
        auto* address = widget->findChild<QLabel*>("address_content");
        if (address && address->text().startsWith(QStringLiteral("bcrt1p"))) {
            found_taproot_request = true;
            widget->close();
        }
    }
    QVERIFY(found_taproot_request);
    QVERIFY(!model->wallet().privateKeysDisabled());
    QVERIFY(!model->wallet().hasExternalSigner());
    auto status = model->wallet().getVaultStatus();
    QCOMPARE(status.recovery_stages.size(), size_t{2});
    QCOMPARE(status.recovery_stages[0].nrequired, 2);
    QCOMPARE(status.recovery_stages[0].older, std::optional<uint32_t>{2});
    QCOMPARE(status.recovery_stages[1].nrequired, 1);
    QCOMPARE(status.recovery_stages[1].older, std::optional<uint32_t>{4});

    const auto dest = wizard.firstReceiveAddress();
    QVERIFY(dest);
    CMutableTransaction funding = test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.at(0), /*input_vout=*/0, /*input_height=*/1, test.coinbaseKey,
        GetScriptForDestination(*dest), 10 * COIN, /*submit=*/false);
    test.CreateAndProcessBlock({funding}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    QApplication::processEvents();

    // The wizard-generated wallet holds three distinct roots and can complete
    // the all-three MuSig2 key path without an external signer.
    SendCoinsDialog immediate(style.get());
    immediate.setClientModel(&client);
    immediate.setModel(model);
    const QString pay = QString::fromStdString(EncodeDestination(PKHash(test.coinbaseKey.GetPubKey())));
    const Txid immediate_id = SendFromDialog(immediate, pay, 1 * COIN);
    const auto immediate_tx = model->wallet().getTx(immediate_id);
    QVERIFY(immediate_tx);
    QCOMPARE(immediate_tx->vin.size(), size_t{1});
    QCOMPARE(immediate_tx->vin[0].scriptWitness.stack.size(), size_t{1});
    test.CreateAndProcessBlock({CMutableTransaction{*immediate_tx}}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    QApplication::processEvents();

    status = model->wallet().getVaultStatus();
    QCOMPARE(status.recovery_stages[0].recoverable_now, 0);
    QCOMPARE(status.recovery_stages[0].earliest_blocks_remaining, std::optional<int>{1});
    QCOMPARE(status.recovery_stages[1].recoverable_now, 0);
    QCOMPARE(status.recovery_stages[1].earliest_blocks_remaining, std::optional<int>{3});

    OverviewPage overview(style.get());
    overview.setClientModel(&client);
    overview.setWalletModel(model);
    overview.setBalance(model->wallet().getBalances());
    QApplication::processEvents();
    auto* final_option = overview.findChild<QLabel*>("vaultFinalOptionLabel");
    auto* final_status = overview.findChild<QLabel*>("vaultFinalStatusLabel");
    QVERIFY(final_option);
    QVERIFY(final_status);
    QVERIFY(!final_option->isHidden());
    QVERIFY(!final_status->isHidden());
    QVERIFY(final_option->text().contains(QStringLiteral("Any 1 key")));
    QVERIFY(final_status->text().contains(QStringLiteral("3 blocks")));

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
    auto* stages = send.findChild<QComboBox*>("vaultRecoveryStageCombo");
    QVERIFY(recovery);
    QVERIFY(stages);
    QVERIFY(!recovery->isChecked());
    QVERIFY(!stages->isHidden());
    QCOMPARE(stages->count(), 3);
    QCOMPARE(stages->currentIndex(), 0);
    QVERIFY(!stages->currentData().isValid());
    QVERIFY(!stages->isEnabled());
    recovery->setChecked(true);
    QApplication::processEvents();
    QVERIFY(stages->isEnabled());
    QVERIFY(!send.findChild<QPushButton*>("sendButton")->isEnabled());
    QVERIFY(!send.getCoinControl()->m_nSequence);
    stages->setCurrentIndex(1);
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 2u);
    stages->setCurrentIndex(2);
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 4u);
    QCOMPARE(send.getCoinControl()->m_min_depth, 4);
    QVERIFY(send.getCoinControl()->m_script_path);

    stages->setCurrentIndex(1);
    test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    status = model->wallet().getVaultStatus();
    QVERIFY(status.recovery_stages[0].recoverable_now > 0);
    QCOMPARE(status.recovery_stages[1].recoverable_now, 0);
    QCOMPARE(stages->currentData().toUInt(), 2u);

    test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    status = model->wallet().getVaultStatus();
    QVERIFY(status.recovery_stages[0].recoverable_now > 0);
    QVERIFY(status.recovery_stages[1].recoverable_now > 0);
    QCOMPARE(stages->currentData().toUInt(), 2u); // Never auto-escalate to one key.

    stages->setCurrentIndex(2);
    recovery->setChecked(true);
    QApplication::processEvents();
    QString confirmation;
    const Txid final_id = SendFromDialog(send, pay, 1 * COIN, &confirmation);
    QVERIFY(confirmation.contains(QStringLiteral("1 recovery key")));
    QVERIFY(confirmation.contains(QStringLiteral("4 blocks")));
    QVERIFY(confirmation.contains(QStringLiteral("all relative recovery clocks")));
    const auto final_tx = model->wallet().getTx(final_id);
    QVERIFY(final_tx);
    QCOMPARE(final_tx->vin.size(), size_t{1});
    QCOMPARE(final_tx->vin[0].nSequence, 4u);
    const auto& witness = final_tx->vin[0].scriptWitness.stack;
    QVERIFY(witness.size() >= 4);
    QCOMPARE(static_cast<int>(std::count_if(witness.begin(), witness.end() - 2,
                                           [](const auto& item) { return !item.empty(); })), 1);
    QVERIFY(!recovery->isChecked());
    QCOMPARE(stages->currentIndex(), 0);

    test.CreateAndProcessBlock({CMutableTransaction{*final_tx}}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    status = model->wallet().getVaultStatus();
    QCOMPARE(status.recovery_stages[0].recoverable_now, 0);
    QCOMPARE(status.recovery_stages[1].recoverable_now, 0);
    QVERIFY(status.recovery_stages[0].awaiting_maturity > 0);
    QVERIFY(status.recovery_stages[1].awaiting_maturity > 0);
}

void MultisigWizardTests::vaultGuiMissingKey()
{
    TestChain100Setup test;
    test.mineBlocks(5);
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    gArgs.ForceSetArg("-fallbackfee", "0.0002");

    hwi::MockRegistration mock_a{hwi::MakeMockMasterFromHex(), ChainType::REGTEST};
    auto mock_b = std::make_unique<hwi::MockRegistration>(
        hwi::MakeMockMasterFromHex("101112131415161718191a1b1c1d1e1f"), ChainType::REGTEST);

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    MultisigWizard wizard(m_node, &controller);
    wizard.setWalletName(QStringLiteral("GuiMissingKey"));
    wizard.setLocalKeyCount(1);
    wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
    wizard.addHardwareKey(mock_b->Fingerprint(), "Mock B");
    wizard.rebuildKeyList();
    QCOMPARE(static_cast<int>(wizard.keys().size()), 3);
    wizard.setNRequired(2);
    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(1);
    wizard.show();
    QApplication::processEvents();
    WalkScroogeToDone(wizard, /*nrequired=*/2, /*delay_blocks=*/1);
    QVERIFY2(wizard.createdWallet(), qPrintable(wizard.createError()));
    WalletModel* model = wizard.createdWallet();
    const auto dest = wizard.firstReceiveAddress();
    QVERIFY(!!dest);
    const CScript spk = GetScriptForDestination(*dest);
    CMutableTransaction fund = test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.front(), 0, /*input_height=*/1, test.coinbaseKey, spk, 10 * COIN, /*submit=*/false);
    test.CreateAndProcessBlock({fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    QVERIFY(model->wallet().getBalances().balance >= 10 * COIN);

    mock_b.reset();

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    const QString pay = QString::fromStdString(EncodeDestination(PKHash(test.coinbaseKey.GetPubKey())));
    QString err;
    ConfirmMessage(&err, std::chrono::milliseconds{0});
    auto* entries = send.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries);
    auto* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    QVERIFY(entry);
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    Txid too_soon;
    QObject::connect(&send, &SendCoinsDialog::coinsSent, [&](const Txid& hash) { too_soon = hash; });
    QVERIFY(QMetaObject::invokeMethod(&send, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY(too_soon.IsNull());

    auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
    QVERIFY(recovery);
    recovery->setChecked(true);
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 1u);
    const Txid rec_id = SendFromDialog(send, pay, 1 * COIN);
    const auto rec_tx = model->wallet().getTx(rec_id);
    QVERIFY(rec_tx);
    QCOMPARE(rec_tx->vin[0].nSequence, 1u);
    QVERIFY(rec_tx->vin[0].scriptWitness.stack.size() > 1);
    wizard.close();
}

void MultisigWizardTests::vaultGuiAirgapPsbt()
{
    TestChain100Setup test;
    test.mineBlocks(5);
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-fallbackfee", "0.0002");

    const AirKey a = MakeAirKey();
    const AirKey b = MakeAirKey();
    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    MultisigWizard wizard(m_node, &controller);
    wizard.setWalletName(QStringLiteral("GuiAirgap"));
    wizard.setIncludeLocalKey(false);
    wizard.addAirgappedKey(a.fpr, a.path, a.xpub, "cold-a");
    wizard.addAirgappedKey(b.fpr, b.path, b.xpub, "cold-b");
    wizard.rebuildKeyList();
    wizard.setNRequired(2);
    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(1);
    wizard.show();
    QApplication::processEvents();
    WalkScroogeToDone(wizard, /*nrequired=*/2, /*delay_blocks=*/1);
    QVERIFY2(wizard.createdWallet(), qPrintable(wizard.createError()));
    WalletModel* model = wizard.createdWallet();
    QVERIFY(model->wallet().privateKeysDisabled());
    const auto dest = wizard.firstReceiveAddress();
    QVERIFY(!!dest);
    const CScript spk = GetScriptForDestination(*dest);
    CMutableTransaction fund = test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.front(), 0, /*input_height=*/1, test.coinbaseKey, spk, 10 * COIN, /*submit=*/false);
    test.CreateAndProcessBlock({fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    QVERIFY(model->wallet().getBalances().balance >= 10 * COIN);

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
    QVERIFY(recovery);
    QVERIFY(!recovery->isHidden());
    recovery->setChecked(true);
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 1u);
    const QString pay = QString::fromStdString(EncodeDestination(PKHash(test.coinbaseKey.GetPubKey())));
    QTimer dismiss;
    dismiss.setInterval(200);
    QObject::connect(&dismiss, &QTimer::timeout, [&]() {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("QMessageBox") && widget->objectName() == QStringLiteral("psbt_copied_message")) {
                auto* box = qobject_cast<QMessageBox*>(widget);
                QAbstractButton* button = box->button(QMessageBox::Discard);
                if (button) {
                    button->setEnabled(true);
                    button->click();
                }
                dismiss.stop();
            }
        }
    });
    dismiss.start(200);
    auto* entries = send.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries);
    auto* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    QVERIFY(entry);
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    ConfirmSend(/*text=*/nullptr, QMessageBox::Save);
    QVERIFY(QMetaObject::invokeMethod(&send, "sendButtonClicked", Q_ARG(bool, false)));
    const std::string psbt_b64 = QApplication::clipboard()->text().toStdString();
    QVERIFY(!psbt_b64.empty());
    const auto decoded = DecodeBase64(psbt_b64);
    QVERIFY(decoded);
    const auto psbt = DecodeRawPSBT(MakeByteSpan(*decoded));
    QVERIFY(psbt);
    QVERIFY(!psbt->inputs.empty());
    QVERIFY(psbt->inputs[0].sequence);
    QCOMPARE(*psbt->inputs[0].sequence, 1u);
    wizard.close();
}

void MultisigWizardTests::vaultGuiHardwareOnly()
{
    TestChain100Setup test;
    test.mineBlocks(5);
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    gArgs.ForceSetArg("-fallbackfee", "0.0002");

    hwi::MockRegistration mock_a{hwi::MakeMockMasterFromHex(), ChainType::REGTEST};
    hwi::MockRegistration mock_b{hwi::MakeMockMasterFromHex("101112131415161718191a1b1c1d1e1f"), ChainType::REGTEST};

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    MultisigWizard wizard(m_node, &controller);
    wizard.setWalletName(QStringLiteral("GuiHwOnly"));
    wizard.setIncludeLocalKey(false);
    wizard.addHardwareKey(mock_a.Fingerprint(), "Mock A");
    wizard.addHardwareKey(mock_b.Fingerprint(), "Mock B");
    wizard.rebuildKeyList();
    wizard.setNRequired(2);
    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(1);
    wizard.show();
    QApplication::processEvents();
    WalkScroogeToDone(wizard, /*nrequired=*/2, /*delay_blocks=*/1);
    QVERIFY2(wizard.createdWallet(), qPrintable(wizard.createError()));
    WalletModel* model = wizard.createdWallet();
    QVERIFY(model->wallet().privateKeysDisabled());
    QVERIFY(model->wallet().hasExternalSigner());
    const auto dest = wizard.firstReceiveAddress();
    QVERIFY(!!dest);
    const CScript spk = GetScriptForDestination(*dest);
    auto fund = [&](size_t coin_i) {
        const int height = static_cast<int>(coin_i) + 1;
        CMutableTransaction tx = test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.at(coin_i), /*input_vout=*/0, height, test.coinbaseKey,
            spk, 10 * COIN, /*submit=*/false);
        test.CreateAndProcessBlock({tx}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    };
    fund(0);
    fund(1);
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    QVERIFY(model->wallet().getBalances().balance >= 20 * COIN);

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    auto* recovery = send.findChild<QRadioButton*>("vaultRecoveryModeButton");
    QVERIFY(recovery);
    QVERIFY(!recovery->isHidden());
    const QString pay = QString::fromStdString(EncodeDestination(PKHash(test.coinbaseKey.GetPubKey())));
    const Txid keypath_id = SendFromDialog(send, pay, 1 * COIN);
    const auto keypath_tx = model->wallet().getTx(keypath_id);
    QVERIFY(keypath_tx);
    QCOMPARE(keypath_tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
    QCOMPARE(static_cast<int>(keypath_tx->vin[0].scriptWitness.stack.size()), 1);

    recovery->setChecked(true);
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 1u);
    const Txid rec_id = SendFromDialog(send, pay, 1 * COIN);
    const auto rec_tx = model->wallet().getTx(rec_id);
    QVERIFY(rec_tx);
    QCOMPARE(rec_tx->vin[0].nSequence, 1u);
    QVERIFY(rec_tx->vin[0].scriptWitness.stack.size() > 1);
    wizard.close();
}
