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
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <qt/bitcoinamountfield.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/multisigwizard.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/qrimagewidget.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/receivecoinsdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/test/util.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <span.h>
#include <support/allocators/secure.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/bip32.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/rbf.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/bip39.h>
#include <wallet/coincontrol.h>
#include <wallet/multisig.h>
#include <wallet/vault_policy_qr.h>
#include <wallet/walletutil.h>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QEvent>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QLocale>
#include <QLockFile>
#include <QMessageBox>
#include <QPalette>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSignalSpy>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableView>
#include <QTemporaryDir>
#include <QTest>
#include <QTextDocument>
#include <QTimer>
#include <QToolButton>
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
        QStringLiteral("verification-remaining"),
        QStringLiteral("vault-ready"),
        QStringLiteral("overview"),
        QStringLiteral("overview-lost-signer"),
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
        for (const QString& state : states)
            names << theme + QLatin1Char('-') + state;
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
        // The default staged-vault backup keeps one Recovery Kit action and a
        // precise page-count acknowledgment. Back and Cancel remain available
        // until the explicit Create Vault commitment.
        QVERIFY(print_policy->isVisible());
        QVERIFY(print_policy->text().startsWith(QStringLiteral("Open Recovery Kit for Printing")));
        QVERIFY(print_policy->text().contains(QStringLiteral("pages")));
        QVERIFY(print_policy->isEnabled());
        QVERIFY(ack->isVisible());
        QVERIFY(ack->text().contains(QStringLiteral("printed all"), Qt::CaseInsensitive));
        QVERIFY(ack->text().contains(QStringLiteral("legible"), Qt::CaseInsensitive));
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
        if (committed_journey) {
            QVERIFY(!wizard.button(QWizard::BackButton)->isHidden());
        } else {
            // Tests may enter Backup as the synthetic start page. There is no
            // prior page in that harness, so QWizard correctly hides Back.
            QVERIFY(wizard.button(QWizard::BackButton)->isHidden());
        }
        QVERIFY(!wizard.button(QWizard::CancelButton)->isHidden());
        QVERIFY(!wizard.button(QWizard::CommitButton)->isVisible());
        QVERIFY(!wizard.button(QWizard::FinishButton)->isVisible());
        QVERIFY(wizard.button(QWizard::NextButton)->isVisible());
        QString create_text = wizard.button(QWizard::NextButton)->text();
        create_text.remove(QLatin1Char('&'));
        QCOMPARE(create_text, QStringLiteral("Create Vault"));
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
    Q_UNUSED(committed_journey);
    QVERIFY(!wizard.testOption(QWizard::NoCancelButton));
    QVERIFY(!wizard.button(QWizard::CancelButton)->isHidden());
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
        QVERIFY(!wizard.button(QWizard::BackButton)->isHidden());
        QVERIFY(!wizard.button(QWizard::CancelButton)->isHidden());
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
        QTRY_VERIFY_WITH_TIMEOUT(
            devices->item(row)->text().startsWith(QStringLiteral("✓")) ||
                !show->isEnabled(),
            10000);
        QTRY_VERIFY_WITH_TIMEOUT(
            devices->item(row)->text().startsWith(QStringLiteral("✓")),
            10000);
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
            // Simulate an RPC or another wallet surface mutating durable state
            // without first updating WalletModel's GUI cache.
            Assert(model.wallet().setLostSigner(fingerprint, true));
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

std::optional<wallet::VaultPolicyPackage> ReencodeFixedSchedule(
    wallet::VaultPolicyPackage package,
    uint32_t primary_delay,
    uint32_t final_delay)
{
    if (package.recovery_stages.size() != 2 ||
        !package.recovery_stages[0].older || !package.recovery_stages[1].older) {
        return std::nullopt;
    }
    const uint32_t old_primary{*package.recovery_stages[0].older};
    const uint32_t old_final{*package.recovery_stages[1].older};
    for (std::string& descriptor : package.descs) {
        const size_t checksum_marker{descriptor.find('#')};
        if (checksum_marker == std::string::npos) return std::nullopt;
        descriptor.resize(checksum_marker);
        const auto replace_delay = [&](uint32_t from, uint32_t to) {
            const std::string old_lock{strprintf("older(%u)", from)};
            const size_t position{descriptor.find(old_lock)};
            if (position == std::string::npos) return false;
            descriptor.replace(position, old_lock.size(), strprintf("older(%u)", to));
            return true;
        };
        if (!replace_delay(old_primary, primary_delay) || !replace_delay(old_final, final_delay)) {
            return std::nullopt;
        }
        const std::string checksum{GetDescriptorChecksum(descriptor)};
        if (checksum.empty()) return std::nullopt;
        descriptor += "#" + checksum;
    }
    package.policy_id = wallet::VaultPolicyId(package.descs.front());
    package.fallback_older = primary_delay;
    package.fallback_after.reset();
    package.fallback_older_one_key = final_delay;
    package.recovery_stages = {{2, primary_delay, {}}, {1, final_delay, {}}};
    return package;
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
    wizard.setFallbackOlder(MultisigWizard::kCurrentPrimaryVaultDelay);
    wizard.setFallbackOlderOneKey(MultisigWizard::kCurrentFinalVaultDelay);
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

void WalkStagedRecoveryToDone(MultisigWizard& wizard,
                              int first_delay = MultisigWizard::kCurrentPrimaryVaultDelay,
                              int final_delay = MultisigWizard::kCurrentFinalVaultDelay)
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
    QVERIFY(wizard.currentPage()->title().isEmpty());
    auto* phase = wizard.findChild<QLabel*>("vaultPhaseProgress");
    auto* consequences = wizard.findChild<QLabel*>("essentialRecoveryConsequences");
    QVERIFY(phase);
    QVERIFY(consequences);
    QCOMPARE(phase->text(), QStringLiteral("Step 1 of 4"));
    QVERIFY(consequences->text().contains(QStringLiteral("Recovery never happens automatically")));
    QCOMPARE(wizard.nextId(), static_cast<int>(MultisigWizard::Page_Backup));
    QVERIFY(!wizard.findChild<QCheckBox*>("localSoftwareKeysRiskCheck")->isVisible());
    const auto restore_buttons = wizard.findChildren<QPushButton*>("restoreFromMnemonicButton");
    QVERIFY(std::any_of(restore_buttons.begin(), restore_buttons.end(), [](const QPushButton* button) {
        return button->isVisible();
    }));
    QVERIFY(wizard.findChild<QPushButton*>("advancedVaultButton")->isVisible());

    auto* review_scroll = wizard.findChild<QScrollArea*>("recoveryVaultReviewScroll");
    QVERIFY(review_scroll);
    QCOMPARE(review_scroll->horizontalScrollBarPolicy(), Qt::ScrollBarAlwaysOff);
    const QFont normal_font = wizard.font();
    QFont enlarged_font = normal_font;
    enlarged_font.setPointSize(normal_font.pointSize() > 0 ? normal_font.pointSize() + 4 : 16);
    wizard.setFont(enlarged_font);
    for (const QSize target : {QSize{760, 600}, QSize{900, 620}, QSize{1200, 800}}) {
        wizard.resize(target);
        QApplication::processEvents();
        QCOMPARE(wizard.size(), target);
        QVERIFY(wizard.button(QWizard::NextButton)->isVisible());
        QVERIFY(wizard.button(QWizard::CancelButton)->isVisible());
        QCOMPARE(review_scroll->horizontalScrollBarPolicy(), Qt::ScrollBarAlwaysOff);
    }
    wizard.setFont(normal_font);
    wizard.resize(900, 620);
    QApplication::processEvents();

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
            auto* progress = wizard.findChild<QLabel*>("vaultPhaseProgress");
            QVERIFY(name);
            QVERIFY(authority);
            QVERIFY(discovery);
            QVERIFY(restore);
            QVERIFY(progress);
            name->setText(QStringLiteral("Shot%1Review%2").arg(dark ? QStringLiteral("Dark") : QStringLiteral("Light")).arg(hardware_count));
            QApplication::processEvents();
            QVERIFY(!name->accessibleName().isEmpty());
            QVERIFY(progress->isVisible());
            QCOMPARE(progress->text(), QStringLiteral("Step 1 of 4"));
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
            QVERIFY(wizard.currentPage()->title().isEmpty());
            auto* backup_headline = wizard.currentPage()->findChild<QLabel*>("vaultPhaseHeadline");
            QVERIFY(backup_headline);
            QCOMPARE(backup_headline->text(), QStringLiteral("Secure your Recovery Kit"));
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
            QVERIFY(wizard.button(QWizard::BackButton)->isVisible());
            QVERIFY(wizard.button(QWizard::CancelButton)->isVisible());
            capture(wizard, QStringLiteral("secure-recovery-after-print"));

            wizard.next();
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
            QVERIFY(wizard.createdWallet());
            QVERIFY(wizard.currentPage()->title().isEmpty());
            auto* qr = wizard.findChild<QRImageWidget*>("verifyQr");
            auto* address = wizard.findChild<QPlainTextEdit*>("verifyAddressEdit");
            auto* independent = wizard.findChild<QLabel*>("independentVerificationState");
            auto* import_policy = wizard.findChild<QPushButton*>("verifyImportedPolicyButton");
            QVERIFY(qr);
            QVERIFY(address);
            QVERIFY(independent);
            QVERIFY(import_policy);
            QVERIFY(qr->isVisible());
            QCOMPARE(qr->size(), QSize(168, 168));
            QVERIFY(!address->toPlainText().isEmpty());
            QVERIFY(independent->text().contains(QStringLiteral("Not independently verified"), Qt::CaseInsensitive));
            QCOMPARE(independent->backgroundRole(), QPalette::ToolTipBase);
            QCOMPARE(independent->foregroundRole(), QPalette::ToolTipText);
            QCOMPARE(independent->palette().color(independent->backgroundRole()), palette.color(QPalette::ToolTipBase));
            QCOMPARE(independent->palette().color(independent->foregroundRole()), palette.color(QPalette::ToolTipText));
            QVERIFY(import_policy->isVisible());
            QVERIFY(qr->mapTo(wizard.currentPage(), QPoint{qr->width(), qr->height()}).y() <= wizard.currentPage()->height());
            capture(wizard, QStringLiteral("confirm-review"));

            auto* unverified_ack = wizard.findChild<QCheckBox*>("finishUnverifiedAcknowledgment");
            auto* finish_unverified = wizard.findChild<QPushButton*>("finishUnverifiedButton");
            QVERIFY(unverified_ack);
            QVERIFY(finish_unverified);
            QVERIFY(unverified_ack->isVisible());
            unverified_ack->setChecked(true);
            finish_unverified->click();
            QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
            auto* summary = wizard.findChild<QLabel*>("doneSummaryLabel");
            auto* policy_id = wizard.findChild<QLineEdit*>("readyPolicyId");
            auto* technical_details = wizard.findChild<QToolButton*>("readyTechnicalDetailsButton");
            auto* receive = wizard.findChild<QPushButton*>("receiveTestPaymentButton");
            auto* done = qobject_cast<QPushButton*>(wizard.button(QWizard::FinishButton));
            QVERIFY(summary);
            QVERIFY(policy_id);
            QVERIFY(technical_details);
            QVERIFY(receive);
            QVERIFY(done);
            QVERIFY(summary->text().contains(QStringLiteral("Recovery Kit confirmed"), Qt::CaseInsensitive));
            QVERIFY(!policy_id->text().isEmpty());
            QVERIFY(!policy_id->accessibleName().isEmpty());
            QVERIFY(!policy_id->isVisible());
            QVERIFY(!technical_details->accessibleName().isEmpty());
            QVERIFY(!receive->accessibleName().isEmpty());
            QTRY_VERIFY(receive->isDefault());
            QVERIFY(!done->isDefault());
            QVERIFY(!wizard.button(QWizard::BackButton)->isVisible());
            QVERIFY(!wizard.button(QWizard::CancelButton)->isVisible());
            QVERIFY(receive->mapTo(wizard.currentPage(), QPoint{0, receive->height()}).y() <= wizard.currentPage()->height());
            capture(wizard, QStringLiteral("verification-remaining"));
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
            QVERIFY(wizard.currentPage()->title().isEmpty());
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
            auto* ready_summary = wizard.findChild<QLabel*>("doneSummaryLabel");
            QVERIFY(ready_summary);
            QVERIFY(ready_summary->text().contains(QStringLiteral("independently verified"), Qt::CaseInsensitive));
            capture(wizard, QStringLiteral("vault-ready"));
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
            QTRY_VERIFY_WITH_TIMEOUT(operational_model->vaultStatus().signer_discovery_complete, 10000);
            QTRY_VERIFY_WITH_TIMEOUT(
                overview.findChild<QLabel*>("vaultRecoveryStage1Summary") &&
                    overview.findChild<QLabel*>("vaultRecoveryStage1Summary")->isVisible(),
                10000);
            QTRY_VERIFY_WITH_TIMEOUT(
                overview.findChild<QLabel*>("vaultRecoveryStage2Summary") &&
                    overview.findChild<QLabel*>("vaultRecoveryStage2Summary")->isVisible(),
                10000);
            auto* total = overview.findChild<QLabel*>("vaultTotalAmount");
            auto* immediate = overview.findChild<QLabel*>("vaultImmediateAmount");
            auto* first = overview.findChild<QLabel*>("vaultRecoveryStage1Summary");
            auto* final = overview.findChild<QLabel*>("vaultRecoveryStage2Summary");
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
            auto* notice = send.findChild<QLabel*>("vaultSendNotice");
            auto* recovery_panel = send.findChild<QWidget*>("delayedRecoveryPanel");
            auto* fee = send.findChild<QWidget*>("frameFee");
            auto* review = send.findChild<QPushButton*>("sendButton");
            QVERIFY(notice);
            QVERIFY(recovery_panel);
            QVERIFY(fee);
            QVERIFY(review);
            QVERIFY(!send.findChild<QRadioButton*>("vaultNormalModeButton"));
            QVERIFY(!send.findChild<QRadioButton*>("vaultRecoveryModeButton"));
            QVERIFY(notice->isVisible());
            QVERIFY(recovery_panel->isHidden());
            QTRY_VERIFY_WITH_TIMEOUT(
                notice->text().contains(QStringLiteral("Immediate spend"), Qt::CaseInsensitive),
                10000);
            QCOMPARE(review->text(), QStringLiteral("Review Transaction"));
            QVERIFY(!notice->accessibleName().isEmpty());
            QVERIFY(!review->accessibleName().isEmpty());
            QVERIFY(notice->mapTo(&send, QPoint{}).y() < fee->mapTo(&send, QPoint{}).y());
            QVERIFY(review->mapTo(&send, QPoint{0, review->height()}).y() <= send.height());
            capture(send, QStringLiteral("send-normal"));

            send.startDelayedRecovery();
            auto* first_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
            auto* final_stage = send.findChild<QRadioButton*>("delayedRecoveryStage2Button");
            QVERIFY(first_stage);
            QVERIFY(final_stage);
            QVERIFY(!first_stage->isChecked());
            QVERIFY(!final_stage->isChecked());
            first_stage->click();
            QApplication::processEvents();
            QVERIFY(recovery_panel->isVisible());
            first_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
            QVERIFY(first_stage);
            QVERIFY(first_stage->isChecked());
            QCOMPARE(send.getCoinControl()->m_nSequence, std::optional<uint32_t>{MultisigWizard::kCurrentPrimaryVaultDelay});
            QVERIFY(!review->isEnabled());
            capture(send, QStringLiteral("send-first-recovery"));

            final_stage = send.findChild<QRadioButton*>("delayedRecoveryStage2Button");
            QVERIFY(final_stage);
            final_stage->click();
            QApplication::processEvents();
            QCOMPARE(send.getCoinControl()->m_nSequence, std::optional<uint32_t>{MultisigWizard::kCurrentFinalVaultDelay});
            QVERIFY(!review->isEnabled());
            capture(send, QStringLiteral("send-final-recovery"));

            send.clear();
            const std::string lost_fingerprint{mock_a->Fingerprint()};
            mock_a.reset();
            QVERIFY(operational_model->setVaultSignerLost(lost_fingerprint, true));
            QApplication::processEvents();
            QVERIFY(notice->isVisible());
            QVERIFY(!notice->accessibleDescription().isEmpty());
            QTRY_VERIFY_WITH_TIMEOUT(!review->isEnabled(), 10000);
            QTRY_VERIFY_WITH_TIMEOUT(
                notice->text().contains(QString::fromStdString(lost_fingerprint), Qt::CaseInsensitive),
                10000);
            QVERIFY(notice->mapTo(&send, QPoint{0, notice->height()}).y() <= send.height());
            capture(send, QStringLiteral("send-lost-signer"));

            OverviewPage lost_overview(style.get());
            lost_overview.setClientModel(&client);
            lost_overview.setWalletModel(operational_model);
            lost_overview.setBalance(operational_model->wallet().getBalances());
            lost_overview.resize(900, 620);
            lost_overview.show();
            QApplication::processEvents();
            QTRY_VERIFY_WITH_TIMEOUT(
                std::ranges::any_of(
                    lost_overview.findChildren<QLabel*>(QRegularExpression{QStringLiteral("vaultParticipant[0-9]+Status")}),
                    [](const QLabel* label) {
                        return label->text().contains(QStringLiteral("lost"), Qt::CaseInsensitive);
                    }),
                10000);
            QTRY_VERIFY_WITH_TIMEOUT(
                lost_overview.findChild<QLabel*>("vaultRecoveryStage1Summary") &&
                    lost_overview.findChild<QLabel*>("vaultRecoveryStage1Summary")->isVisible(),
                10000);
            QTRY_VERIFY_WITH_TIMEOUT(
                lost_overview.findChild<QLabel*>("vaultRecoveryStage2Summary") &&
                    lost_overview.findChild<QLabel*>("vaultRecoveryStage2Summary")->isVisible(),
                10000);
            capture(lost_overview, QStringLiteral("overview-lost-signer"));
            QVERIFY(operational_model->setVaultSignerLost(lost_fingerprint, false));
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
                auto* remove_word = dialog->findChild<QPushButton*>("restoreRemoveLastWordButton");
                auto* add = dialog->findChild<QPushButton*>("restoreAddKeyButton");
                auto* watch_only = dialog->findChild<QRadioButton*>("restoreWatchOnlyChoice");
                auto* printed_phrases = dialog->findChild<QRadioButton*>("restorePrintedPhrasesChoice");
                auto* keys = dialog->findChild<QListWidget*>("restoreAcceptedKeys");
                auto* key_status = dialog->findChild<QLabel*>("restoreKeyStatus");
                auto* key_authority = dialog->findChild<QLabel*>("restoreIncrementalAuthority");
                auto* authority = dialog->findChild<QLabel*>("restoreAuthoritySummary");
                check(name && policy && policy_summary && policy_status && phrase && remove_word && add && watch_only && printed_phrases && keys && key_status && key_authority && authority,
                      QStringLiteral("restore controls missing"));
                if (name && policy && policy_summary && policy_status && phrase && remove_word && add && watch_only && printed_phrases && keys && key_status && key_authority && authority) {
                    name->setText(QStringLiteral("Shot%1RestoredPreview").arg(dark ? QStringLiteral("Dark") : QStringLiteral("Light")));
                    policy->setPlainText(restore_policy);
                    dialog->next();
                    check(dialog->currentId() == 1, QStringLiteral("policy preflight did not advance"));
                    dialog->back();
                    check(dialog->currentId() == 0, QStringLiteral("restore policy page unavailable"));
                    check(!name->accessibleName().isEmpty(), QStringLiteral("restore name lacks accessibility name"));
                    check(policy_summary->text().contains(QStringLiteral("Policy identity")), QStringLiteral("policy summary missing ID"));
                    check(policy_summary->text().contains(QStringLiteral("all 3 always"), Qt::CaseInsensitive), QStringLiteral("policy summary implies the immediate path expires"));
                    check(policy_summary->text().contains(QStringLiteral("~90 days")) && policy_summary->text().contains(QStringLiteral("~180 days")), QStringLiteral("policy summary does not show the current schedule"));
                    check(policy_status->text().contains(QStringLiteral("recognized"), Qt::CaseInsensitive), QStringLiteral("policy status missing recognition result"));
                    check(!policy->isVisible(), QStringLiteral("manual policy entry must remain secondary"));
                    capture(*dialog, QStringLiteral("restore-policy"));

                    dialog->next();
                    check(dialog->currentId() == 1, QStringLiteral("recovery-key page unavailable"));
                    watch_only->setChecked(true);
                    dialog->next();
                    check(dialog->currentId() == 2, QStringLiteral("public-only authority page unavailable"));
                    check(authority->text().contains(QStringLiteral("Watch-only"), Qt::CaseInsensitive), QStringLiteral("watch-only authority missing"));
                    capture(*dialog, QStringLiteral("restore-public-only"));
                    dialog->back();

                    printed_phrases->setChecked(true);
                    QTest::keyClicks(phrase, QStringLiteral("alpha beta"));
                    check(phrase->accessibleDescription().contains(QStringLiteral("2 of 24")),
                          QStringLiteral("word-count accessibility state missing"));
                    remove_word->click();
                    check(phrase->accessibleDescription().contains(QStringLiteral("1 of 24")),
                          QStringLiteral("visible word correction did not remove one word"));
                    phrase->setFocus();
                    QTest::keyClick(phrase, Qt::Key_Backspace, Qt::ControlModifier);
                    check(phrase->accessibleDescription().contains(QStringLiteral("No recovery words"), Qt::CaseInsensitive),
                          QStringLiteral("Ctrl+Backspace did not remove the last word"));
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
    QCOMPARE(*wizard.fallbackOlder(), MultisigWizard::kCurrentPrimaryVaultDelay);
    QCOMPARE(*wizard.fallbackOlderOneKey(), MultisigWizard::kCurrentFinalVaultDelay);

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
    // hardware it creates three software keys and fixes the 90/180-day policy.
    {
        MultisigWizard staged(m_node, &controller);
        QSignalSpy created_spy(&staged, &MultisigWizard::created);
        QVERIFY(!staged.advancedFlow());
        QCOMPARE(staged.outputType(), OutputType::BECH32M);
        QCOMPARE(staged.localKeyCount(), MultisigWizard::kStagedVaultKeyCount);
        QCOMPARE(staged.nrequired(), 2);
        QCOMPARE(staged.fallbackOlder(), std::optional<uint32_t>{MultisigWizard::kCurrentPrimaryVaultDelay});
        QCOMPARE(staged.fallbackOlderOneKey(), std::optional<uint32_t>{MultisigWizard::kCurrentFinalVaultDelay});
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
        QCOMPARE(authority->text(), QStringLiteral("This computer holds all three keys. This wallet or its Recovery Kit can spend immediately at every coin age."));
        QVERIFY(technical->text().contains(QLocale().toString(static_cast<qulonglong>(MultisigWizard::kCurrentPrimaryVaultDelay))));
        QVERIFY(technical->text().contains(QLocale().toString(static_cast<qulonglong>(MultisigWizard::kCurrentFinalVaultDelay))));
        QVERIFY(technical->text().contains(QStringLiteral("remains available at every coin age"), Qt::CaseInsensitive));
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
        AssertBackupPage(staged, MultisigWizard::kCurrentPrimaryVaultDelay, {}, MultisigWizard::kCurrentFinalVaultDelay);
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
        QVERIFY(!staged.button(QWizard::NextButton)->isEnabled());
        auto* verified_address = staged.findChild<QPlainTextEdit*>("verifyAddressEdit");
        auto* import_policy = staged.findChild<QPushButton*>("verifyImportedPolicyButton");
        auto* verify_status = staged.findChild<QLabel*>("verifyStatusLabel");
        auto* independent_state = staged.findChild<QLabel*>("independentVerificationState");
        QVERIFY(verified_address);
        QVERIFY(import_policy);
        QVERIFY(verify_status);
        QVERIFY(independent_state);
        auto* copy_address = staged.findChild<QPushButton*>("copyAddressButton");
        QVERIFY(copy_address);
        const QString canonical_address = verified_address->toPlainText();
        copy_address->click();
        QCOMPARE(QApplication::clipboard()->text(), canonical_address);
        QCOMPARE(verified_address->horizontalScrollBarPolicy(), Qt::ScrollBarAlwaysOff);
        QCOMPARE(verified_address->verticalScrollBarPolicy(), Qt::ScrollBarAlwaysOff);
        for (const QSize target : {QSize{760, 600}, QSize{900, 620}, QSize{1200, 800}}) {
            staged.resize(target);
            QApplication::processEvents();
            QCOMPARE(staged.size(), target);
            QVERIFY2(verified_address->document()->size().height() <= verified_address->viewport()->height() + 2,
                     "complete canonical address is clipped");
            QCOMPARE(verified_address->toPlainText(), canonical_address);
        }
        const QFont normal_address_font = verified_address->font();
        QFont increased_address_font = normal_address_font;
        increased_address_font.setPointSize(increased_address_font.pointSize() + 6);
        verified_address->setFont(increased_address_font);
        staged.resize(760, 600);
        QApplication::processEvents();
        QVERIFY2(verified_address->document()->size().height() <= verified_address->viewport()->height() + 2,
                 "complete canonical address is clipped with increased font metrics");
        QCOMPARE(verified_address->toPlainText(), canonical_address);
        verified_address->setFont(normal_address_font);
        staged.resize(900, 620);
        QApplication::processEvents();

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
        const QString first_address = verified_address->toPlainText();
        verified_address->setPlainText(QStringLiteral("different-address"));
        choose_independent_policy();
        import_policy->click();
        QVERIFY(verify_status->text().contains(QStringLiteral("does not derive"), Qt::CaseInsensitive));
        QVERIFY(independent_state->text().contains(QStringLiteral("Not independently verified"), Qt::CaseInsensitive));
        verified_address->setPlainText(first_address);
        choose_independent_policy();
        import_policy->click();
        QVERIFY(independent_state->text().contains(QStringLiteral("Recovery Kit matches"), Qt::CaseInsensitive));
        QVERIFY(independent_state->text().contains(QStringLiteral("not independent"), Qt::CaseInsensitive));
        QVERIFY(!staged.button(QWizard::NextButton)->isEnabled());
        auto* unverified_ack = staged.findChild<QCheckBox*>("finishUnverifiedAcknowledgment");
        auto* finish_unverified = staged.findChild<QPushButton*>("finishUnverifiedButton");
        QVERIFY(unverified_ack);
        QVERIFY(finish_unverified);
        unverified_ack->setChecked(true);
        finish_unverified->click();
        QCOMPARE(staged.currentId(), static_cast<int>(MultisigWizard::Page_Done));
        QCOMPARE(created_spy.count(), 1);
        QVERIFY(staged.createdWallet());
        const auto status = staged.createdWallet()->wallet().getVaultStatus();
        QVERIFY(status.is_vault);
        QCOMPARE(status.recovery_stages.size(), size_t{2});
        QCOMPARE(status.recovery_stages[0].nrequired, 2);
        QCOMPARE(status.recovery_stages[0].older, std::optional<uint32_t>{MultisigWizard::kCurrentPrimaryVaultDelay});
        QCOMPARE(status.recovery_stages[1].nrequired, 1);
        QCOMPARE(status.recovery_stages[1].older, std::optional<uint32_t>{MultisigWizard::kCurrentFinalVaultDelay});
        QCOMPARE(status.setup_state, interfaces::Wallet::VaultSetupState::COMPLETE);
        QCOMPARE(status.verification_state, interfaces::Wallet::VaultVerificationState::FINISHED_UNVERIFIED);

        // RPC compatibility permits markers unrelated to the active fixed
        // policy. Preserve them in raw wallet status, but never present one as
        // a current participant or let it block the fixed Recovery Vault UI.
        {
            SendCoinsDialog send(style.get());
            send.setClientModel(&client);
            send.setModel(staged.createdWallet());
            auto* vault_notice = send.findChild<QLabel*>("vaultSendNotice");
            auto* send_button = send.findChild<QPushButton*>("sendButton");
            QVERIFY(vault_notice);
            QVERIFY(send_button);

            const std::string unrelated_fingerprint{"deadbeef"};
            QVERIFY(staged.createdWallet()->setVaultSignerLost(unrelated_fingerprint, true));
            QApplication::processEvents();
            const auto unrelated_status = staged.createdWallet()->vaultStatus();
            QVERIFY(unrelated_status.is_fixed_staged_vault);
            QVERIFY(std::ranges::find(unrelated_status.manually_lost_signers, unrelated_fingerprint) !=
                    unrelated_status.manually_lost_signers.end());
            QVERIFY(!vault_notice->text().contains(QString::fromStdString(unrelated_fingerprint), Qt::CaseInsensitive));
            QVERIFY(!vault_notice->text().contains(QStringLiteral("marked lost"), Qt::CaseInsensitive));
            QVERIFY(send_button->isEnabled());
            QVERIFY(staged.createdWallet()->setVaultSignerLost(unrelated_fingerprint, false));
            QApplication::processEvents();
        }

        auto* receive_test = staged.findChild<QPushButton*>("receiveTestPaymentButton");
        QVERIFY(receive_test);
        QSignalSpy receive_spy(&staged, &MultisigWizard::receiveRequested);
        receive_test->click();
        QCOMPARE(receive_spy.count(), 1);
        QCOMPARE(receive_spy.first().at(1).toString(), verified_address->toPlainText());
        staged.close();
    }

    // Closing after commitment is safe: the wallet remains durably marked as
    // incomplete, is published to the controller, and resumes directly at
    // address verification without recreating descriptors or recovery keys.
    {
        MultisigWizard incomplete(m_node, &controller);
        QSignalSpy created_spy(&incomplete, &MultisigWizard::created);
        ShowSized(incomplete);
        auto* name = incomplete.findChild<QLineEdit*>("stagedWalletNameEdit");
        QVERIFY(name);
        name->setText(QStringLiteral("CloseSafeResumeVault"));
        incomplete.next();
        QCOMPARE(incomplete.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
        CompleteBackupPage(incomplete);
        incomplete.next();
        QCOMPARE(incomplete.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        WalletModel* const model = incomplete.createdWallet();
        QVERIFY(model);
        QCOMPARE(model->vaultStatus().setup_state,
                 interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED);
        QCOMPARE(model->vaultStatus().verification_state,
                 interfaces::Wallet::VaultVerificationState::PENDING);
        incomplete.close();
        QApplication::processEvents();
        QCOMPARE(created_spy.count(), 1);

        MultisigWizard resumed(m_node, &controller);
        QVERIFY(resumed.resumeSetup(model));
        ShowSized(resumed);
        QCOMPARE(resumed.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        auto* address = resumed.findChild<QPlainTextEdit*>("verifyAddressEdit");
        auto* ack = resumed.findChild<QCheckBox*>("finishUnverifiedAcknowledgment");
        auto* finish = resumed.findChild<QPushButton*>("finishUnverifiedButton");
        QVERIFY(address);
        QVERIFY(ack);
        QVERIFY(finish);
        QVERIFY(!address->toPlainText().isEmpty());
        QVERIFY(ack->isVisible());
        ack->setChecked(true);
        finish->click();
        QCOMPARE(resumed.currentId(), static_cast<int>(MultisigWizard::Page_Done));
        QCOMPARE(model->vaultStatus().setup_state, interfaces::Wallet::VaultSetupState::COMPLETE);
        QCOMPARE(model->vaultStatus().verification_state,
                 interfaces::Wallet::VaultVerificationState::FINISHED_UNVERIFIED);
        resumed.close();

        // A completed-but-unverified setup is not a terminal Ready state.
        // Opening Finish Setup again returns to verification and retains the
        // explicit warning until genuine independent verification succeeds.
        MultisigWizard verify_again(m_node, &controller);
        QVERIFY(verify_again.resumeSetup(model));
        ShowSized(verify_again);
        QCOMPARE(verify_again.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        auto* warning = verify_again.findChild<QLabel*>("independentVerificationState");
        QVERIFY(warning);
        QVERIFY(warning->text().contains(QStringLiteral("previously finished"), Qt::CaseInsensitive));
        QVERIFY(!warning->text().contains(QStringLiteral("Vault Ready"), Qt::CaseInsensitive));
        QCOMPARE(model->vaultStatus().verification_state,
                 interfaces::Wallet::VaultVerificationState::FINISHED_UNVERIFIED);
        verify_again.close();

        // Legacy vaults have no durable evidence that the Recovery Kit was
        // checked. They cannot clear NOT_RECORDED or finish unverified until
        // the user explicitly confirms the original complete printed kit.
        QVERIFY(model->setVaultSetupState(
            interfaces::Wallet::VaultSetupState::NOT_RECORDED,
            interfaces::Wallet::VaultVerificationState::NOT_RECORDED));
        MultisigWizard legacy(m_node, &controller);
        QVERIFY(legacy.resumeSetup(model));
        ShowSized(legacy);
        QCOMPARE(legacy.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        auto* kit_ack = legacy.findChild<QCheckBox*>("resumeRecoveryKitAcknowledgment");
        auto* legacy_unverified_ack = legacy.findChild<QCheckBox*>("finishUnverifiedAcknowledgment");
        auto* legacy_finish = legacy.findChild<QPushButton*>("finishUnverifiedButton");
        QVERIFY(kit_ack);
        QVERIFY(legacy_unverified_ack);
        QVERIFY(legacy_finish);
        QVERIFY(kit_ack->isVisible());
        legacy_unverified_ack->setChecked(true);
        QVERIFY(!legacy_finish->isEnabled());
        QCOMPARE(model->vaultStatus().setup_state,
                 interfaces::Wallet::VaultSetupState::NOT_RECORDED);
        kit_ack->setChecked(true);
        QCOMPARE(model->vaultStatus().setup_state,
                 interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED);
        QCOMPARE(model->vaultStatus().verification_state,
                 interfaces::Wallet::VaultVerificationState::PENDING);
        QVERIFY(legacy_finish->isEnabled());
        legacy_finish->click();
        QCOMPARE(legacy.currentId(), static_cast<int>(MultisigWizard::Page_Done));
        QCOMPARE(model->vaultStatus().setup_state, interfaces::Wallet::VaultSetupState::COMPLETE);
        QCOMPARE(model->vaultStatus().verification_state,
                 interfaces::Wallet::VaultVerificationState::FINISHED_UNVERIFIED);
        legacy.close();
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
        QCOMPARE(name->text(), QStringLiteral("Recovery Vault"));
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
        QCOMPARE(authority->text(), QStringLiteral("This computer holds two keys. Together they gain an additional recovery path after ~90 days; the hardware wallet is required for the immediate all-three path."));
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
        QCOMPARE(authority->text(), QStringLiteral("This computer holds one key. It gains the additional one-key recovery path after ~180 days."));
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
        QCOMPARE(authority->text(), QStringLiteral("No private keys are stored on this computer. Any two devices gain an additional path after ~90 days; any one gains another after ~180 days. All three devices can always spend immediately."));
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
        QCOMPARE(authority->text(), QStringLiteral("No private keys are stored on this computer. Any two devices gain an additional path after ~90 days; any one gains another after ~180 days. All three devices can always spend immediately."));
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
    QVERIFY(!send.findChild<QRadioButton*>("vaultRecoveryModeButton"));
    send.startDelayedRecovery();
    auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
    auto* stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    QVERIFY(recovery);
    QVERIFY(stage);
    QVERIFY(!recovery->isHidden());
    QVERIFY(!stage->isChecked());
    stage->click();
    QApplication::processEvents();
    QVERIFY(send.getCoinControl()->m_nSequence == 1u);
}

void MultisigWizardTests::verificationIdentityBinding()
{
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    hwi::UsbEnumerateSuppress suppress_usb;

    const CExtKey master_a{hwi::MakeMockMasterFromHex()};
    const CExtKey master_b{hwi::MakeMockMasterFromHex("101112131415161718191a1b1c1d1e1f")};
    const CExtKey different_master{hwi::MakeMockMasterFromHex("303132333435363738393a3b3c3d3e3f")};
    auto mock_a = std::make_unique<hwi::MockRegistration>(master_a, ChainType::REGTEST);
    hwi::MockDeviceOptions initially_incapable;
    initially_incapable.can_display_multisig_address = false;
    auto mock_b = std::make_unique<hwi::MockRegistration>(
        master_b, ChainType::REGTEST, initially_incapable);
    const std::string fingerprint_a{mock_a->Fingerprint()};

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    MultisigWizard wizard(m_node, &controller);
    ShowSized(wizard);
    auto* name = wizard.findChild<QLineEdit*>("stagedWalletNameEdit");
    QVERIFY(name);
    name->setText(QStringLiteral("ExactVerificationBinding"));
    QCOMPARE(wizard.localKeyCount(), 1);
    QCOMPARE(wizard.m_fixed_hardware_accounts.size(), size_t{2});
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
    CompleteBackupPage(wizard);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
    WalletModel* const model{wizard.createdWallet()};
    QVERIFY(model);
    auto* devices = wizard.findChild<QListWidget*>("verifyDeviceList");
    auto* show = wizard.findChild<QPushButton*>("showOnDeviceButton");
    auto* verify_status = wizard.findChild<QLabel*>("verifyStatusLabel");
    QVERIFY(devices);
    QVERIFY(show);
    QVERIFY(verify_status);
    QCOMPARE(devices->count(), 1);

    const auto expect_rejection = [&](const QString& evidence) {
        show->click();
        QTRY_VERIFY_WITH_TIMEOUT(show->isEnabled(), 10000);
        QTRY_VERIFY_WITH_TIMEOUT(verify_status->text().contains(evidence, Qt::CaseInsensitive), 10000);
        for (int row = 0; row < devices->count(); ++row) {
            QVERIFY(!devices->item(row)->text().startsWith(QStringLiteral("✓")));
        }
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        QCOMPARE(model->vaultStatus().setup_state,
                 interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED);
        QCOMPARE(model->vaultStatus().verification_state,
                 interfaces::Wallet::VaultVerificationState::PENDING);
    };

    // Capability is fresh runtime evidence, not the pre-backup snapshot. A
    // device that gains display support joins the required set immediately;
    // the first successful display does not let the newly capable peer escape
    // its own check.
    mock_b.reset();
    mock_b = std::make_unique<hwi::MockRegistration>(master_b, ChainType::REGTEST);
    show->click();
    QTRY_COMPARE_WITH_TIMEOUT(devices->count(), 2, 10000);
    QTRY_VERIFY_WITH_TIMEOUT(show->isEnabled(), 10000);
    int verified_count{0};
    for (int row = 0; row < devices->count(); ++row) {
        verified_count += devices->item(row)->text().startsWith(QStringLiteral("✓"));
    }
    QCOMPARE(verified_count, 1);
    QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());

    // A partial roster fails before any fingerprint-only display dispatch and
    // invalidates the successful check made against the prior roster.
    mock_b.reset();
    expect_rejection(QStringLiteral("roster changed or is incomplete"));
    mock_b = std::make_unique<hwi::MockRegistration>(master_b, ChainType::REGTEST);

    // Two devices reporting the same 32-bit fingerprint are ambiguous even
    // when one has the configured complete account xpub.
    hwi::MockDeviceOptions collision_options;
    collision_options.fingerprint_override = fingerprint_a;
    auto collision = std::make_unique<hwi::MockRegistration>(
        different_master, ChainType::REGTEST, collision_options);
    expect_rejection(QStringLiteral("duplicate fingerprint"));
    collision.reset();

    // A replacement can collide on fingerprint while deriving a different
    // full account xpub. It must not reach the device display call or grant a
    // persisted independent-verification state.
    mock_a.reset();
    hwi::MockDeviceOptions replacement_options;
    replacement_options.fingerprint_override = fingerprint_a;
    auto replacement = std::make_unique<hwi::MockRegistration>(
        different_master, ChainType::REGTEST, replacement_options);
    expect_rejection(QStringLiteral("different complete account xpub"));
    replacement.reset();

    // Closing and reopening reconstructs the exact binding from durable
    // participant metadata. Legacy UNKNOWN source metadata remains merely a
    // candidate until a fresh exact match succeeds and records HARDWARE.
    mock_a = std::make_unique<hwi::MockRegistration>(master_a, ChainType::REGTEST);
    mock_b.reset();
    hwi::MockDeviceOptions resumed_incapable;
    resumed_incapable.can_display_multisig_address = false;
    mock_b = std::make_unique<hwi::MockRegistration>(
        master_b, ChainType::REGTEST, resumed_incapable);
    QVERIFY(model->setVaultParticipantType(
        fingerprint_a, interfaces::Wallet::VaultParticipantType::UNKNOWN));
    wizard.close();
    QApplication::processEvents();

    MultisigWizard resumed(m_node, &controller);
    QVERIFY(resumed.resumeSetup(model));
    ShowSized(resumed);
    QCOMPARE(resumed.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
    QCOMPARE(resumed.m_fixed_hardware_accounts.size(), size_t{2});
    auto* resumed_devices = resumed.findChild<QListWidget*>("verifyDeviceList");
    QVERIFY(resumed_devices);
    // Source metadata reconstructs both exact account bindings, but the
    // resumed page immediately reconciles the fresh device capabilities. The
    // incapable participant is never presented as requiring an address check.
    QCOMPARE(resumed_devices->count(), 1);
    CompleteVerification(resumed);
    QCOMPARE(resumed_devices->count(), 1);
    resumed.next();
    QCOMPARE(resumed.currentId(), static_cast<int>(MultisigWizard::Page_Done));
    const auto completed_status{model->vaultStatus()};
    QCOMPARE(completed_status.setup_state, interfaces::Wallet::VaultSetupState::COMPLETE);
    QCOMPARE(completed_status.verification_state,
             interfaces::Wallet::VaultVerificationState::INDEPENDENTLY_VERIFIED);
    const auto participant_a{std::find_if(
        completed_status.participants.begin(), completed_status.participants.end(),
        [&](const auto& participant) { return participant.fingerprint == fingerprint_a; })};
    QVERIFY(participant_a != completed_status.participants.end());
    QCOMPARE(participant_a->type, interfaces::Wallet::VaultParticipantType::HARDWARE);
    resumed.close();
}

void MultisigWizardTests::advancedPolicyCommitmentBinding()
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

    // Advanced policy A is deliberately not the fixed staged template. The
    // verification decision below must remain bound to this exact public
    // policy even if advanced/RPC tooling activates policy B in the meantime.
    const AirKey a1 = MakeAirKey();
    const AirKey a2 = MakeAirKey();
    MultisigWizard wizard(m_node, &controller);
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
    wizard.applyTemplate();
    wizard.setWalletName(QStringLiteral("AdvancedPolicyCommitment"));
    wizard.setLocalKeyCount(0);
    wizard.addAirgappedKey(a1.fpr, a1.path, a1.xpub, "policy-a-1");
    wizard.addAirgappedKey(a2.fpr, a2.path, a2.xpub, "policy-a-2");
    wizard.rebuildKeyList();
    wizard.setNRequired(1);
    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(17);
    wizard.setFallbackOlderOneKey(std::nullopt);
    wizard.setFallbackAfter(std::nullopt);
    QVERIFY(wizard.advancedFlow());
    QVERIFY2(wizard.createWallet(), qPrintable(wizard.createError()));
    WalletModel* const model{wizard.createdWallet()};
    QVERIFY(model);

    const auto policy_a = wallet::ParseVaultPolicyPackage(wizard.m_policy_package.toStdString());
    QVERIFY2(policy_a, qPrintable(QString::fromStdString(util::ErrorString(policy_a).original)));
    QVERIFY(wallet::InferVaultPolicy(policy_a->descs.front()).is_vault);
    QVERIFY(wizard.m_expected_policy_commitment);
    QCOMPARE(*wizard.m_expected_policy_commitment, wallet::VaultPolicyCommitment(*policy_a));
    QVERIFY(wizard.m_prepared_policy_is_vault);

    QSignalSpy created_spy(&wizard, &MultisigWizard::created);
    wizard.setStartId(MultisigWizard::Page_Verify);
    ShowSized(wizard);
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
    CompleteVerification(wizard);
    QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());

    std::vector<wallet::MultisigKeySpec> replacement_keys;
    for (const QString& label : {QStringLiteral("policy-b-1"), QStringLiteral("policy-b-2")}) {
        const AirKey key = MakeAirKey();
        wallet::MultisigKeySpec spec;
        spec.fingerprint = key.fpr;
        spec.path = key.path;
        spec.xpub = key.xpub;
        spec.label = label.toStdString();
        replacement_keys.push_back(std::move(spec));
    }
    wallet::MultisigOptions replacement_options;
    replacement_options.type = OutputType::BECH32M;
    replacement_options.fallback_older = policy_a->fallback_older;
    replacement_options.fallback_after = policy_a->fallback_after;
    replacement_options.fallback_older_one_key = policy_a->fallback_older_one_key;
    auto prepared_b = wallet::PrepareMultisigDescriptor(
        policy_a->nrequired, replacement_keys, replacement_options);
    QVERIFY2(prepared_b,
             qPrintable(QString::fromStdString(util::ErrorString(prepared_b).original)));
    wallet::VaultPolicyPackage policy_b{*policy_a};
    policy_b.descs = prepared_b->descs;
    policy_b.policy_id = prepared_b->policy_id;
    QVERIFY(wallet::VaultPolicyCommitment(policy_b) != wallet::VaultPolicyCommitment(*policy_a));
    const auto imported = model->wallet().importVaultPolicy(wallet::FormatVaultPolicyPackage(policy_b));
    QVERIFY2(imported, qPrintable(QString::fromStdString(util::ErrorString(imported).original)));

    const auto active_b = wallet::ParseVaultPolicyPackage(model->wallet().exportVaultPolicy());
    QVERIFY(active_b);
    QCOMPARE(wallet::VaultPolicyCommitment(*active_b), wallet::VaultPolicyCommitment(policy_b));
    const auto before_finish = model->wallet().getVaultStatus();
    QCOMPARE(before_finish.setup_state, interfaces::Wallet::VaultSetupState::NOT_RECORDED);
    QCOMPARE(before_finish.verification_state, interfaces::Wallet::VaultVerificationState::NOT_RECORDED);

    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
    QCOMPARE(created_spy.count(), 0);
    auto* verify_status = wizard.findChild<QLabel*>("verifyStatusLabel");
    QVERIFY(verify_status);
    QVERIFY(verify_status->text().contains(QStringLiteral("exact policy"), Qt::CaseInsensitive));
    const auto after_rejection = model->wallet().getVaultStatus();
    QCOMPARE(after_rejection.setup_state, interfaces::Wallet::VaultSetupState::NOT_RECORDED);
    QCOMPARE(after_rejection.verification_state, interfaces::Wallet::VaultVerificationState::NOT_RECORDED);
    wizard.close();
}

void MultisigWizardTests::restoreRejectsWrongTypedKit()
{
    MultisigWizard host(m_node, /*wallet_controller=*/nullptr);
    bool inspected{false};
    bool rejected_inline{false};
    QString failure;

    QTimer::singleShot(0, &host, [&] {
        QWizard* restore{nullptr};
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            auto* candidate = qobject_cast<QWizard*>(widget);
            if (candidate && candidate != &host && candidate->isVisible()) {
                restore = candidate;
                break;
            }
        }
        if (!restore) {
            failure = QStringLiteral("restore dialog did not open");
            return;
        }

        auto* manual = restore->findChild<QToolButton*>("manualRestorePolicyButton");
        auto* policy = restore->findChild<QPlainTextEdit*>("restorePolicyEdit");
        auto* status = restore->findChild<QLabel*>("restorePolicyStatus");
        if (!manual || !policy || !status) {
            failure = QStringLiteral("restore policy controls are missing");
            restore->reject();
            return;
        }

        manual->setChecked(true);
        policy->setPlainText(QStringLiteral(R"({"format":3,"descs":[7]})"));
        restore->next();
        QApplication::processEvents();
        inspected = true;
        rejected_inline = restore->currentId() == 0 && !status->text().trimmed().isEmpty();
        if (!rejected_inline) {
            failure = QStringLiteral("wrong-typed Recovery Kit advanced or produced no inline validation error; page=%1 status=%2")
                          .arg(restore->currentId())
                          .arg(status->text());
        }
        restore->reject();
    });

    host.startRestore();
    QVERIFY2(inspected, qPrintable(failure));
    QVERIFY2(rejected_inline, qPrintable(failure));
}

void MultisigWizardTests::legacyFixedVaultCompatibility()
{
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    m_node.setContext(&test.m_node);
    gArgs.ForceSetArg("-signer", "internal");
    hwi::UsbEnumerateSuppress suppress_usb;

    {
        bilingual_str error;
        OptionsModel options_model(m_node);
        QVERIFY(options_model.Init(error));
        ClientModel client(m_node, &options_model);
        std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
        QVERIFY(style);
        WalletController controller(client, style.get(), nullptr);
        QApplication::processEvents();

        std::vector<wallet::MultisigKeySpec> specs(3);
        for (auto& spec : specs)
            spec.generate_local = true;
        wallet::MultisigOptions options;
        options.type = OutputType::BECH32M;
        options.fallback_older = wallet::FIXED_VAULT_CURRENT_PRIMARY_DELAY;
        options.fallback_older_one_key = wallet::FIXED_VAULT_CURRENT_FINAL_DELAY;
        auto prepared{wallet::PrepareMultisigDescriptor(/*nrequired=*/2, specs, options)};
        QVERIFY2(prepared, qPrintable(QString::fromStdString(util::ErrorString(prepared).original)));

        wallet::VaultPolicyPackage current;
        current.network = Params().GetChainTypeString();
        current.nrequired = 2;
        current.fallback_older = wallet::FIXED_VAULT_CURRENT_PRIMARY_DELAY;
        current.fallback_older_one_key = wallet::FIXED_VAULT_CURRENT_FINAL_DELAY;
        current.recovery_stages = {
            {2, wallet::FIXED_VAULT_CURRENT_PRIMARY_DELAY, {}},
            {1, wallet::FIXED_VAULT_CURRENT_FINAL_DELAY, {}},
        };
        current.descs = prepared->descs;
        current.policy_id = prepared->policy_id;
        QVERIFY(wallet::ValidateFixedStagedVaultPolicy(current));

        const auto legacy{ReencodeFixedSchedule(
            current, wallet::FIXED_VAULT_LEGACY_PRIMARY_DELAY,
            wallet::FIXED_VAULT_LEGACY_FINAL_DELAY)};
        QVERIFY(legacy);
        QVERIFY(wallet::ValidateFixedStagedVaultPolicy(*legacy));
        QCOMPARE(static_cast<int>(wallet::ClassifyFixedVaultSchedule(*legacy)),
                 static_cast<int>(wallet::FixedVaultSchedule::LEGACY_30_60));
        QVERIFY(wallet::VaultPolicyCommitment(current) != wallet::VaultPolicyCommitment(*legacy));
        const QString legacy_kit{QString::fromStdString(wallet::FormatVaultPolicyPackage(*legacy))};

        std::vector<SecureString> phrases;
        phrases.reserve(prepared->recovery.size());
        for (const auto& recovery : prepared->recovery) {
            phrases.emplace_back(recovery.mnemonic.begin(), recovery.mnemonic.end());
        }

        MultisigWizard installer(m_node, &controller);
        installer.m_restore_rescan_override = [](interfaces::Wallet&) -> util::Result<void> { return {}; };
        QSignalSpy restored_spy(&installer, &MultisigWizard::restoreCompleted);
        QString restore_error;
        QVERIFY2(installer.restoreFromRecoverySheets(
                     QStringLiteral("LegacyFixedVaultRestore"), legacy_kit, phrases,
                     restore_error),
                 qPrintable(restore_error));
        QTRY_COMPARE_WITH_TIMEOUT(restored_spy.count(), 1, 30000);
        WalletModel* const legacy_model{installer.createdWallet()};
        QVERIFY(legacy_model);
        const auto installed_package{wallet::ParseVaultPolicyPackage(legacy_model->wallet().exportVaultPolicy())};
        QVERIFY(installed_package);
        QCOMPARE(static_cast<int>(wallet::ClassifyFixedVaultSchedule(*installed_package)),
                 static_cast<int>(wallet::FixedVaultSchedule::LEGACY_30_60));
        QVERIFY(legacy_model->wallet().getVaultStatus().is_fixed_staged_vault);

        MultisigWizard resumed(m_node, &controller);
        QVERIFY(resumed.resumeSetup(legacy_model));
        QCOMPARE(resumed.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        QCOMPARE(resumed.fallbackOlder(), std::optional<uint32_t>{wallet::FIXED_VAULT_LEGACY_PRIMARY_DELAY});
        QCOMPARE(resumed.fallbackOlderOneKey(), std::optional<uint32_t>{wallet::FIXED_VAULT_LEGACY_FINAL_DELAY});

        bool inspected_display{false};
        QString display_failure;
        MultisigWizard display_host(m_node, &controller);
        QTimer::singleShot(0, &display_host, [&] {
            QWizard* restore{nullptr};
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                auto* candidate = qobject_cast<QWizard*>(widget);
                if (candidate && candidate != &display_host && candidate->isVisible()) {
                    restore = candidate;
                    break;
                }
            }
            if (!restore) {
                display_failure = QStringLiteral("legacy restore dialog did not open");
                return;
            }
            auto* name = restore->findChild<QLineEdit*>("restoreWalletNameEdit");
            auto* policy = restore->findChild<QPlainTextEdit*>("restorePolicyEdit");
            auto* summary = restore->findChild<QLabel*>("restorePolicySummary");
            auto* rules = restore->findChild<QLabel*>("restoreAuthorityRules");
            auto* technical = restore->findChild<QLabel*>("restoreAuthorityTechnical");
            if (!name || !policy || !summary || !rules || !technical) {
                display_failure = QStringLiteral("legacy restore display controls are missing");
                restore->reject();
                return;
            }
            name->setText(QStringLiteral("LegacyFixedVaultDisplayOnly"));
            policy->setPlainText(legacy_kit);
            restore->next();
            QApplication::processEvents();
            const QString legacy_primary{QLocale().toString(static_cast<qulonglong>(wallet::FIXED_VAULT_LEGACY_PRIMARY_DELAY))};
            const QString legacy_final{QLocale().toString(static_cast<qulonglong>(wallet::FIXED_VAULT_LEGACY_FINAL_DELAY))};
            inspected_display = restore->currentId() == 1 &&
                                summary->text().contains(QStringLiteral("all 3 always"), Qt::CaseInsensitive) &&
                                summary->text().contains(QStringLiteral("~30 days")) &&
                                summary->text().contains(QStringLiteral("~60 days")) &&
                                rules->text().contains(QStringLiteral("can always spend"), Qt::CaseInsensitive) &&
                                technical->text().contains(legacy_primary) &&
                                technical->text().contains(legacy_final) &&
                                technical->text().contains(QStringLiteral("remains available"), Qt::CaseInsensitive);
            if (!inspected_display) {
                display_failure = QStringLiteral("legacy schedule was not rendered from the Recovery Kit; page=%1 summary=%2 rules=%3 technical=%4")
                                      .arg(restore->currentId())
                                      .arg(summary->text(), rules->text(), technical->text());
            }
            restore->reject();
        });
        display_host.startRestore();
        QVERIFY2(inspected_display, qPrintable(display_failure));

        {
            OverviewPage legacy_overview(style.get());
            legacy_overview.setClientModel(&client);
            legacy_overview.setWalletModel(legacy_model);
            legacy_overview.setBalance(legacy_model->wallet().getBalances());
            QTRY_COMPARE_WITH_TIMEOUT(
                static_cast<int>(legacy_model->vaultRenewalStatus().schedule),
                static_cast<int>(wallet::FixedVaultSchedule::LEGACY_30_60), 5000);
            auto* protection = legacy_overview.findChild<QWidget*>("vaultThreeKeyProtectionCard");
            auto* renew = legacy_overview.findChild<QPushButton*>("vaultRenewalButton");
            auto* timing = legacy_overview.findChild<QLabel*>("vaultNextAccessExpansion");
            QVERIFY(protection);
            QVERIFY(renew);
            QVERIFY(timing);
            QVERIFY(!protection->isHidden());
            QVERIFY(renew->isHidden());
            QVERIFY(timing->text().contains(QStringLiteral("legacy"), Qt::CaseInsensitive));
        }

        for (SecureString& phrase : phrases) {
            if (!phrase.empty()) memory_cleanse(phrase.data(), phrase.size());
        }
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    }
    m_node.setContext(nullptr);
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
        AssertBackupPage(first, MultisigWizard::kCurrentPrimaryVaultDelay, {}, MultisigWizard::kCurrentFinalVaultDelay, false);

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
        AssertBackupPage(identical, MultisigWizard::kCurrentPrimaryVaultDelay, {}, MultisigWizard::kCurrentFinalVaultDelay, false);
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
        AssertBackupPage(wizard, MultisigWizard::kCurrentPrimaryVaultDelay, {},
                         MultisigWizard::kCurrentFinalVaultDelay, false);

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
        QVERIFY(kit_text.contains(QStringLiteral("immediate all-three path at every coin age"), Qt::CaseInsensitive));
        QVERIFY(kit_text.contains(QLocale().toString(static_cast<qulonglong>(MultisigWizard::kCurrentPrimaryVaultDelay))));
        QVERIFY(kit_text.contains(QLocale().toString(static_cast<qulonglong>(MultisigWizard::kCurrentFinalVaultDelay))));
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
                QVERIFY(mixed_text.contains(
                    QStringLiteral("after %1 blocks").arg(QLocale().toString(static_cast<qulonglong>(MultisigWizard::kCurrentPrimaryVaultDelay))),
                    Qt::CaseInsensitive));
                QVERIFY(mixed_text.contains(QStringLiteral("hardware key is still required for an immediate spend"), Qt::CaseInsensitive));
            } else {
                QVERIFY(mixed_text.contains(
                    QStringLiteral("after %1 blocks").arg(QLocale().toString(static_cast<qulonglong>(MultisigWizard::kCurrentFinalVaultDelay))),
                    Qt::CaseInsensitive));
                QVERIFY(mixed_text.contains(
                    QStringLiteral("second key is required for the path after %1 blocks").arg(QLocale().toString(static_cast<qulonglong>(MultisigWizard::kCurrentPrimaryVaultDelay))),
                    Qt::CaseInsensitive));
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
        QTimer render_warning_closer;
        connect(&render_warning_closer, &QTimer::timeout, [&render_warning] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                    render_warning = box->text();
                    box->accept();
                }
            }
        });
        render_warning_closer.start(10);
        QVERIFY(print->isEnabled());
        print->click();
        render_warning_closer.stop();
        wizard.m_software_recovery.front().xpub = valid_xpub;
        QVERIFY2(render_warning.contains(QStringLiteral("could not be validated"), Qt::CaseInsensitive),
                 qPrintable(render_warning));
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
        QVERIFY(print->text().startsWith(QStringLiteral("Open Recovery Kit for Printing")));
        QCOMPARE(m_opened_recovery_count, 1);
        QVERIFY(ack->isEnabled());
        QVERIFY(!ack->isChecked());
        QVERIFY(print_status->text().contains(QStringLiteral("validated"), Qt::CaseInsensitive));
        QVERIFY(print_status->text().contains(QStringLiteral("opened"), Qt::CaseInsensitive));
        QVERIFY(print_status->text().contains(QStringLiteral("Recovery Kit"), Qt::CaseInsensitive));
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());

        // Reusing the sole action must reopen the tracked PDF rather than
        // minting a second private copy at another pathname.
        print->click();
        QTRY_COMPARE_WITH_TIMEOUT(m_opened_recovery_count, 2, 5000);
        QCOMPARE(m_opened_recovery_url.toLocalFile(), private_pdf);
        QVERIFY(QFileInfo::exists(private_pdf));
        QVERIFY(print->text().startsWith(QStringLiteral("Open Recovery Kit for Printing")));

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
        QVERIFY(print->text().startsWith(QStringLiteral("Open Recovery Kit for Printing")));
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

    // Closing/destroying a pre-commit wizard is a cancellation boundary. If
    // an external viewer temporarily prevents deletion, close must still
    // proceed while the controller retains the exact file and lock for a
    // checked retry; candidate secrets and the wallet name remain uncommitted.
    QString cancelled_pdf;
    QString close_cleanup_warning;
    const QString cancelled_name{QStringLiteral("CancelledRecoveryCandidate")};
    {
        MultisigWizard cancelled(m_node, &controller);
        cancelled.setWalletName(cancelled_name);
        QVERIFY2(cancelled.createWallet(), qPrintable(cancelled.createError()));
        cancelled.setStartId(MultisigWizard::Page_Backup);
        ShowSized(cancelled);
        AssertBackupPage(cancelled, MultisigWizard::kCurrentPrimaryVaultDelay, {},
                         MultisigWizard::kCurrentFinalVaultDelay, false);
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
        cancelled.m_private_print_remover = [&](const QString& path) {
            return path != cancelled_pdf && QFile::remove(path);
        };
        cancelled.close();
        QApplication::processEvents();
        QVERIFY(!cancelled.isVisible());
        QCOMPARE(controller.pendingRecoveryKitCleanupCount(), size_t{1});
        QVERIFY(QFileInfo::exists(cancelled_pdf));
        QMessageBox* cleanup_warning_box{nullptr};
        for (QWidget* widget : QApplication::allWidgets()) {
            if (auto* box = qobject_cast<QMessageBox*>(widget);
                box && box->objectName() == QStringLiteral("recoveryKitCleanupWarning")) {
                cleanup_warning_box = box;
                break;
            }
        }
        QVERIFY(cleanup_warning_box);
        close_cleanup_warning = cleanup_warning_box->text() + QLatin1Char(' ') + cleanup_warning_box->informativeText();
        cleanup_warning_box->accept();
        QVERIFY(close_cleanup_warning.contains(QStringLiteral("keep retrying"), Qt::CaseInsensitive));
        QVERIFY(close_cleanup_warning.contains(cancelled_pdf));
    }
    QCOMPARE(controller.pendingRecoveryKitCleanupCount(), size_t{1});
    QVERIFY(QFileInfo::exists(cancelled_pdf));
    controller.retryPendingRecoveryKitCleanup();
    QTRY_VERIFY_WITH_TIMEOUT(!QFileInfo::exists(cancelled_pdf), 5000);
    QCOMPARE(controller.pendingRecoveryKitCleanupCount(), size_t{0});
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
            AssertBackupPage(stale_cleanup, MultisigWizard::kCurrentPrimaryVaultDelay, {},
                             MultisigWizard::kCurrentFinalVaultDelay, false);
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
                    auto* printed_choice = dialog->findChild<QRadioButton*>("restorePrintedPhrasesChoice");
                    auto* phrase = dialog->findChild<QWidget*>("restoreMnemonicEdit");
                    auto* add = dialog->findChild<QPushButton*>("restoreAddKeyButton");
                    QVERIFY(printed_choice);
                    QVERIFY(phrase);
                    QVERIFY(add);
                    if (!printed_choice->isChecked()) printed_choice->setChecked(true);
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
                    dialog->button(QWizard::FinishButton)->text().contains(QStringLiteral("Resume Scan"))) {
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

    // The hardware-authority handoff persists only exact identities matched
    // during restore preflight. Selecting the hardware route must never label
    // every otherwise-unknown policy participant as hardware.
    {
        const auto package = wallet::ParseVaultPolicyPackage(policy_json.toStdString());
        QVERIFY(package);
        const auto participants = wallet::FixedVaultParticipants(*package);
        QVERIFY(participants);
        QCOMPARE(participants->size(), size_t{3});
        const std::string matched_fingerprint{participants->front().fingerprint};

        MultisigWizard hardware_subset(m_node, &controller);
        hardware_subset.m_restore_rescan_override = [](interfaces::Wallet& wallet) {
            return wallet.rescanFromGenesis();
        };
        QSignalSpy completed_spy(&hardware_subset, &MultisigWizard::restoreCompleted);
        QString restore_error;
        QVERIFY2(hardware_subset.restoreFromRecoverySheets(
                     QStringLiteral("MatchedHardwareSubsetRestored"), policy_json,
                     /*mnemonics=*/{}, restore_error, {matched_fingerprint},
                     /*enable_external_signing=*/true),
                 qPrintable(restore_error));
        QTRY_COMPARE_WITH_TIMEOUT(completed_spy.count(), 1, 30000);
        QVERIFY(hardware_subset.createdWallet());
        QVERIFY(hardware_subset.createdWallet()->wallet().hasExternalSigner());
        const auto status = hardware_subset.createdWallet()->vaultStatus();
        for (const auto& participant : status.participants) {
            QCOMPARE(participant.type,
                     participant.fingerprint == matched_fingerprint ? interfaces::Wallet::VaultParticipantType::HARDWARE : interfaces::Wallet::VaultParticipantType::UNKNOWN);
        }

        // The durable restore activity, not the launching wizard, owns source
        // provenance. Destroy the complete UI immediately after starting and
        // require the resulting wallet to retain only the exact reviewed
        // hardware participant.
        WalletModel* close_safe_model{nullptr};
        const QString close_safe_name{QStringLiteral("ClosedDuringHardwareRestore")};
        const QMetaObject::Connection added_connection = connect(
            &controller, &WalletController::walletAdded, this,
            [&](WalletModel* model) {
                if (QString::fromStdString(model->wallet().getWalletName()) == close_safe_name) {
                    close_safe_model = model;
                }
            });
        {
            auto closing_wizard = std::make_unique<MultisigWizard>(m_node, &controller);
            closing_wizard->m_restore_rescan_override = [](interfaces::Wallet&) -> util::Result<void> { return {}; };
            QString close_error;
            QVERIFY2(closing_wizard->restoreFromRecoverySheets(
                         close_safe_name, policy_json, /*mnemonics=*/{}, close_error,
                         {matched_fingerprint}, /*enable_external_signing=*/true),
                     qPrintable(close_error));
            closing_wizard->close();
            closing_wizard.reset();
        }
        QTRY_VERIFY_WITH_TIMEOUT(close_safe_model != nullptr, 30000);
        const auto provenance_is_durable = [&] {
            const auto close_status{close_safe_model->vaultStatus()};
            return std::ranges::all_of(close_status.participants, [&](const auto& participant) {
                return participant.type == (participant.fingerprint == matched_fingerprint ? interfaces::Wallet::VaultParticipantType::HARDWARE : interfaces::Wallet::VaultParticipantType::UNKNOWN);
            });
        };
        QTRY_VERIFY_WITH_TIMEOUT(provenance_is_durable(), 10000);
        QVERIFY(close_safe_model->wallet().hasExternalSigner());
        disconnect(added_connection);
    }

    // Restore authority is explicit and survives a matching connected device.
    // Watch-only and printed-phrases-only installs must not gain HWI dispatch
    // merely because fewer than three local phrases were supplied.
    {
        QVERIFY(!printed_phrases.empty());
        const std::string_view phrase_view{
            printed_phrases.front().data(), printed_phrases.front().size()};
        const auto seed{wallet::BIP39MnemonicToSeed(phrase_view)};
        QVERIFY(seed);
        CExtKey matching_master;
        matching_master.SetSeed(std::as_bytes(std::span{*seed}));
        hwi::MockRegistration matching_device{matching_master, ChainType::REGTEST};

        QTimer message_closer;
        connect(&message_closer, &QTimer::timeout, [] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* box = qobject_cast<QMessageBox*>(widget); box && box->isVisible()) {
                    box->accept();
                }
            }
        });
        message_closer.start(10);

        MultisigWizard watch_only(m_node, &controller);
        watch_only.m_restore_rescan_override = [](interfaces::Wallet&) -> util::Result<void> { return {}; };
        QSignalSpy watch_complete(&watch_only, &MultisigWizard::restoreCompleted);
        QString watch_error;
        QVERIFY2(watch_only.restoreFromRecoverySheets(
                     QStringLiteral("ExplicitWatchOnlyRestore"), policy_json,
                     /*mnemonics=*/{}, watch_error, /*matched_hardware=*/{},
                     /*enable_external_signing=*/false),
                 qPrintable(watch_error));
        QTRY_COMPARE_WITH_TIMEOUT(watch_complete.count(), 1, 30000);
        QVERIFY(watch_only.createdWallet());
        QVERIFY(watch_only.createdWallet()->wallet().privateKeysDisabled());
        QVERIFY(!watch_only.createdWallet()->wallet().hasExternalSigner());
        const auto watch_status{watch_only.createdWallet()->wallet().getVaultStatus()};
        QVERIFY(std::ranges::all_of(watch_status.participants, [](const auto& participant) {
            return participant.type == interfaces::Wallet::VaultParticipantType::UNKNOWN;
        }));

        MultisigWizard phrases_only(m_node, &controller);
        phrases_only.m_restore_rescan_override = [](interfaces::Wallet&) -> util::Result<void> { return {}; };
        QSignalSpy phrases_complete(&phrases_only, &MultisigWizard::restoreCompleted);
        QString phrases_error;
        const std::vector<SecureString> one_phrase{printed_phrases.front()};
        QVERIFY2(phrases_only.restoreFromRecoverySheets(
                     QStringLiteral("ExplicitPhrasesOnlyRestore"), policy_json,
                     one_phrase, phrases_error, /*matched_hardware=*/{},
                     /*enable_external_signing=*/false),
                 qPrintable(phrases_error));
        QTRY_COMPARE_WITH_TIMEOUT(phrases_complete.count(), 1, 30000);
        QVERIFY(phrases_only.createdWallet());
        QVERIFY(!phrases_only.createdWallet()->wallet().privateKeysDisabled());
        QVERIFY(!phrases_only.createdWallet()->wallet().hasExternalSigner());
        const auto phrases_status{phrases_only.createdWallet()->wallet().getVaultStatus()};
        QCOMPARE(static_cast<int>(std::count_if(
                     phrases_status.participants.begin(), phrases_status.participants.end(),
                     [](const auto& participant) {
                         return participant.type == interfaces::Wallet::VaultParticipantType::LOCAL_SOFTWARE;
                     })),
                 1);
        QVERIFY(std::ranges::none_of(phrases_status.participants, [](const auto& participant) {
            return participant.type == interfaces::Wallet::VaultParticipantType::HARDWARE;
        }));
        message_closer.stop();
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
        auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
        QVERIFY(recovery);
        QVERIFY(recovery->isHidden());
        QVERIFY(!send.findChild<QRadioButton*>("vaultRecoveryModeButton"));
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
        auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
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
        send.startDelayedRecovery();
        auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
        auto* stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
        QVERIFY(recovery);
        QVERIFY(!recovery->isHidden());
        QVERIFY(stage);
        QVERIFY(!stage->isChecked());
        stage->click();
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
        auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
        QVERIFY(recovery);
        QVERIFY(recovery->isHidden());
        QVERIFY(send.findChild<QLabel*>("vaultSendNotice")->isVisibleTo(&send));
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
        send.startDelayedRecovery();
        auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
        auto* stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
        QVERIFY(recovery);
        QVERIFY(!recovery->isHidden());
        QVERIFY(stage);
        const QString absolute_copy = stage->text() + QLatin1Char(' ') + stage->toolTip();
        QVERIFY(!absolute_copy.contains(QStringLiteral("relative delay"), Qt::CaseInsensitive));
        QVERIFY(!absolute_copy.contains(QStringLiteral("starts over"), Qt::CaseInsensitive));
        QVERIFY(!absolute_copy.contains(QStringLiteral("new clock"), Qt::CaseInsensitive));
        stage->click();
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
        QTRY_VERIFY_WITH_TIMEOUT(model->vaultRenewalStatus().primary_delay == 1, 5000);
        QTRY_VERIFY_WITH_TIMEOUT(!model->m_vault_renewal_refresh_running, 5000);
        const uint64_t renewal_generation{model->m_vault_renewal_refresh_generation};
        Q_EMIT client.numBlocksChanged(
            /*count=*/test.m_node.chainman->ActiveHeight(), QDateTime::currentDateTime(),
            /*nVerificationProgress=*/1.0, SyncType::BLOCK_SYNC,
            SynchronizationState::POST_INIT);
        QTRY_VERIFY_WITH_TIMEOUT(
            model->m_vault_renewal_refresh_generation > renewal_generation, 5000);
        auto* immediate = overview.findChild<QLabel*>("vaultImmediateAmount");
        auto* recovery_status = overview.findChild<QLabel*>("vaultRecoveryStage1Summary");
        auto* dashboard_total = overview.findChild<QLabel*>("vaultTotalAmount");
        auto* protection_card = overview.findChild<QWidget*>("vaultThreeKeyProtectionCard");
        auto* protected_amount = overview.findChild<QLabel*>("vaultThreeKeyOnlyAmount");
        auto* recovery_enabled_amount = overview.findChild<QLabel*>("vaultRecoveryEnabledAmount");
        auto* renewal_due_amount = overview.findChild<QLabel*>("vaultRenewalDueAmount");
        auto* unconfirmed_clock_amount = overview.findChild<QLabel*>("vaultUnconfirmedClockAmount");
        auto* next_expansion = overview.findChild<QLabel*>("vaultNextAccessExpansion");
        auto* renewal_button = overview.findChild<QPushButton*>("vaultRenewalButton");
        QVERIFY(immediate);
        QVERIFY(recovery_status);
        QVERIFY(dashboard_total);
        QVERIFY(protection_card);
        QVERIFY(protected_amount);
        QVERIFY(recovery_enabled_amount);
        QVERIFY(renewal_due_amount);
        QVERIFY(unconfirmed_clock_amount);
        QVERIFY(next_expansion);
        QVERIFY(renewal_button);
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
        QVERIFY(total_text->isHidden());
        QVERIFY(total_value->isHidden());
        QVERIFY(!dashboard_total->isHidden());
        QVERIFY(!protection_card->isHidden());
        // This one-block advanced policy is custom. Its protection state is
        // shown truthfully, but guided 90/180 renewal must not be offered.
        QVERIFY(renewal_button->isHidden());
        QVERIFY(next_expansion->text().contains(QStringLiteral("custom schedule"), Qt::CaseInsensitive));
        QVERIFY(next_expansion->toolTip().isEmpty());

        QSignalSpy delayed_spy(&overview, &OverviewPage::delayedRecoveryRequested);
        QSignalSpy kit_spy(&overview, &OverviewPage::recoveryKitRequested);
        QSignalSpy setup_spy(&overview, &OverviewPage::finishVaultSetupRequested);
        auto* delayed_button = overview.findChild<QPushButton*>("startDelayedRecoveryButton");
        auto* kit_button = overview.findChild<QPushButton*>("recoveryKitButton");
        QVERIFY(delayed_button);
        QVERIFY(kit_button);
        QVERIFY(delayed_button->isEnabled());
        delayed_button->click();
        kit_button->click();
        QCOMPARE(delayed_spy.count(), 1);
        QCOMPARE(kit_spy.count(), 1);

        QVERIFY(model->setVaultSetupState(interfaces::Wallet::VaultSetupState::RECOVERY_KIT_REQUIRED,
                                          interfaces::Wallet::VaultVerificationState::PENDING));
        QApplication::processEvents();
        auto* finish_setup = overview.findChild<QPushButton*>("finishVaultSetupButton");
        QVERIFY(finish_setup);
        QVERIFY(!finish_setup->isHidden());
        finish_setup->click();
        QCOMPARE(setup_spy.count(), 1);

        const QString unmasked_total = dashboard_total->text();
        const QString unmasked_protected = protected_amount->text();
        const QString unmasked_recovery_enabled = recovery_enabled_amount->text();
        const QString unmasked_due = renewal_due_amount->text();
        const QString unmasked_unconfirmed = unconfirmed_clock_amount->text();
        overview.setPrivacy(true);
        QApplication::processEvents();
        recovery_status = overview.findChild<QLabel*>("vaultRecoveryStage1Summary");
        auto* participant_identity = overview.findChild<QLabel*>("vaultParticipant1Identity");
        auto* participant_status = overview.findChild<QLabel*>("vaultParticipant1Status");
        QVERIFY(recovery_status);
        QCOMPARE(recovery_status->text(), QStringLiteral("Hidden"));
        if (participant_identity && participant_status) {
            QVERIFY(participant_identity->text().contains(QStringLiteral("Hidden")));
            QCOMPARE(participant_status->text(), QStringLiteral("Hidden"));
        }
        QVERIFY(overview.findChild<QWidget*>("vaultDashboardActions")->isHidden());
        QVERIFY(dashboard_total->text() != unmasked_total);
        QVERIFY(protected_amount->text() != unmasked_protected);
        QVERIFY(recovery_enabled_amount->text() != unmasked_recovery_enabled);
        QVERIFY(renewal_due_amount->text() != unmasked_due);
        QVERIFY(unconfirmed_clock_amount->text() != unmasked_unconfirmed);
        QCOMPARE(next_expansion->text(), QStringLiteral("Protection timing hidden"));
        QVERIFY(renewal_button->isHidden());
        overview.setPrivacy(false);
        QVERIFY(model->setVaultSetupState(interfaces::Wallet::VaultSetupState::COMPLETE,
                                          interfaces::Wallet::VaultVerificationState::INDEPENDENTLY_VERIFIED));

        const QByteArray shot_destination{qgetenv("VAULT_RENEWAL_SHOTS")};
        if (!shot_destination.isEmpty()) {
            const QString shot_dir{QString::fromLocal8Bit(shot_destination)};
            QVERIFY(QDir().mkpath(shot_dir));
            const QPalette original_palette{QApplication::palette()};
            const QSignalBlocker model_signal_blocker{model};
            interfaces::Wallet::VaultStatus dashboard_status{model->vaultStatus()};
            dashboard_status.is_fixed_staged_vault = true;
            dashboard_status.setup_state = interfaces::Wallet::VaultSetupState::COMPLETE;
            dashboard_status.verification_state =
                interfaces::Wallet::VaultVerificationState::INDEPENDENTLY_VERIFIED;
            dashboard_status.signer_discovery_complete = true;
            dashboard_status.older = wallet::FIXED_VAULT_CURRENT_PRIMARY_DELAY;
            dashboard_status.recovery_m = 2;
            dashboard_status.immediate = 30 * COIN;
            dashboard_status.recoverable_now = 7 * COIN;
            dashboard_status.awaiting_maturity = 23 * COIN;
            dashboard_status.earliest_blocks_remaining = 1'440;
            dashboard_status.lost_signers.clear();
            dashboard_status.manually_lost_signers.clear();
            dashboard_status.participants.clear();
            for (const std::string& fingerprint : {"11111111", "22222222", "33333333"}) {
                interfaces::Wallet::VaultStatus::VaultParticipant participant;
                participant.fingerprint = fingerprint;
                participant.type = interfaces::Wallet::VaultParticipantType::LOCAL_SOFTWARE;
                participant.availability = interfaces::Wallet::VaultSignerAvailability::AVAILABLE;
                dashboard_status.participants.push_back(std::move(participant));
            }
            dashboard_status.recovery_stages = {
                {2, wallet::FIXED_VAULT_CURRENT_PRIMARY_DELAY, std::nullopt,
                 7 * COIN, 23 * COIN, 1'440},
                {1, wallet::FIXED_VAULT_CURRENT_FINAL_DELAY, std::nullopt,
                 0, 30 * COIN, 14'400},
            };
            const auto publish = [&](wallet::VaultRenewalStatus status) {
                auto visible_status{dashboard_status};
                visible_status.older = status.primary_delay;
                visible_status.earliest_blocks_remaining = status.next_expansion_blocks;
                visible_status.recovery_stages[0].older = status.primary_delay;
                visible_status.recovery_stages[0].earliest_blocks_remaining =
                    status.next_expansion_blocks;
                visible_status.recovery_stages[1].older = status.final_delay;
                visible_status.recovery_stages[1].earliest_blocks_remaining =
                    status.next_expansion_blocks ? std::optional<int>{*status.next_expansion_blocks +
                                                                      static_cast<int>(status.final_delay - status.primary_delay)} :
                                                   std::nullopt;
                overview.m_vault_status = std::move(visible_status);
                overview.m_vault_renewal_status = std::move(status);
                overview.updateVaultDashboard();
            };
            const auto status_for = [](bool due, bool supported = true) {
                wallet::VaultRenewalStatus status;
                status.supported = supported;
                status.schedule = supported ? wallet::FixedVaultSchedule::CURRENT_90_180 : wallet::FixedVaultSchedule::LEGACY_30_60;
                status.primary_delay = supported ? wallet::FIXED_VAULT_CURRENT_PRIMARY_DELAY : wallet::FIXED_VAULT_LEGACY_PRIMARY_DELAY;
                status.final_delay = supported ? wallet::FIXED_VAULT_CURRENT_FINAL_DELAY : wallet::FIXED_VAULT_LEGACY_FINAL_DELAY;
                status.policy_commitment = supported ? "current-policy" : "legacy-policy";
                status.three_key_only = 18 * COIN;
                status.recovery_enabled = 7 * COIN;
                status.warning = due ? 6 * COIN : 0;
                status.unconfirmed = 2 * COIN;
                status.next_expansion_blocks = due ? 1'440 : 4'320;
                wallet::VaultRenewalCluster group;
                group.id = "privacy-group-a";
                group.value = 18 * COIN;
                group.coin_count = 2;
                group.due = due;
                group.blocks_until_primary = due ? 1'440 : 4'320;
                status.clusters.push_back(group);
                if (due) status.due_set_digest = "due-set-a";
                return status;
            };
            const auto palette_for = [&](bool dark) {
                QPalette palette{original_palette};
                if (dark) {
                    palette.setColor(QPalette::Window, QColor(30, 32, 35));
                    palette.setColor(QPalette::WindowText, QColor(236, 238, 241));
                    palette.setColor(QPalette::Base, QColor(24, 26, 29));
                    palette.setColor(QPalette::AlternateBase, QColor(42, 45, 49));
                    palette.setColor(QPalette::Text, QColor(236, 238, 241));
                    palette.setColor(QPalette::Button, QColor(48, 51, 56));
                    palette.setColor(QPalette::ButtonText, QColor(236, 238, 241));
                    palette.setColor(QPalette::Mid, QColor(72, 76, 82));
                    palette.setColor(QPalette::Midlight, QColor(58, 62, 68));
                    palette.setColor(QPalette::Light, QColor(90, 94, 100));
                    palette.setColor(QPalette::Dark, QColor(18, 20, 22));
                    palette.setColor(QPalette::Highlight, QColor(88, 138, 216));
                    palette.setColor(QPalette::HighlightedText, QColor(255, 255, 255));
                }
                return palette;
            };
            const auto capture = [&](const QString& theme, const QString& state) {
                overview.resize(900, 620);
                overview.show();
                QCoreApplication::sendPostedEvents(nullptr, QEvent::LayoutRequest);
                QApplication::processEvents();
                const QString path{QDir(shot_dir).filePath(
                    theme + QStringLiteral("-renewal-dashboard-") + state + QStringLiteral(".png"))};
                QVERIFY2(overview.grab().save(path, "PNG"), qPrintable(path));
                QVERIFY(QFileInfo(path).size() > 0);
            };

            for (const bool dark : {false, true}) {
                const QString theme{dark ? QStringLiteral("dark") : QStringLiteral("light")};
                const QPalette themed{palette_for(dark)};
                QApplication::setPalette(themed);
                overview.setPalette(themed);
                overview.setPrivacy(false);
                publish(status_for(/*due=*/false));
                QVERIFY(!renewal_button->isHidden());
                QCOMPARE(renewal_button->text(), QStringLiteral("Renew Early…"));
                QVERIFY(renewal_button->isFlat());
                QVERIFY(!renewal_button->isDefault());
                auto* stage1_phase = overview.findChild<QLabel*>("vaultRecoveryStage1CardPhase");
                auto* stage2_phase = overview.findChild<QLabel*>("vaultRecoveryStage2CardPhase");
                QVERIFY(stage1_phase);
                QVERIFY(stage2_phase);
                QVERIFY(stage1_phase->text().contains(QStringLiteral("90 days")));
                QVERIFY(stage2_phase->text().contains(QStringLiteral("180 days")));
                QVERIFY(!stage1_phase->text().contains(QStringLiteral("week"), Qt::CaseInsensitive));
                QVERIFY(!stage2_phase->text().contains(QStringLiteral("week"), Qt::CaseInsensitive));
                capture(theme, QStringLiteral("early"));

                publish(status_for(/*due=*/true));
                QVERIFY(!renewal_button->isHidden());
                QCOMPARE(renewal_button->text(), QStringLiteral("Renew Three-Key Protection…"));
                QVERIFY(!renewal_button->isFlat());
                QVERIFY(renewal_button->isDefault());
                capture(theme, QStringLiteral("due"));

                overview.setPrivacy(true);
                publish(status_for(/*due=*/true));
                capture(theme, QStringLiteral("privacy"));
                overview.setPrivacy(false);
                publish(status_for(/*due=*/false, /*supported=*/false));
                QVERIFY(renewal_button->isHidden());
                QVERIFY(next_expansion->text().contains(QStringLiteral("legacy 30/60-day"), Qt::CaseInsensitive));
                QVERIFY(next_expansion->text().contains(QStringLiteral("create a new Recovery Vault"), Qt::CaseInsensitive));
                QVERIFY(next_expansion->text().contains(QStringLiteral("send the funds"), Qt::CaseInsensitive));
                capture(theme, QStringLiteral("legacy"));
            }
            overview.setPrivacy(false);
            QApplication::setPalette(original_palette);
            overview.setPalette(original_palette);
            overview.m_vault_status = model->vaultStatus();
            overview.m_vault_renewal_status = model->vaultRenewalStatus();
            overview.updateVaultDashboard();
        }
    }

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    QVERIFY(!send.findChild<QRadioButton*>("vaultRecoveryModeButton"));
    auto* vault_notice = send.findChild<QLabel*>("vaultSendNotice");
    QVERIFY(vault_notice);
    QVERIFY(!vault_notice->isHidden());
    QVERIFY(vault_notice->text().contains(QStringLiteral("Immediate spend"), Qt::CaseInsensitive));

    // This advanced/custom policy has no authoritative participant roster.
    // Preserve conservative legacy semantics: any policy-bound manual marker
    // remains visible and blocks direct Send until explicitly cleared.
    {
        const std::string unrelated_fingerprint{"deadbeef"};
        QVERIFY(model->setVaultSignerLost(unrelated_fingerprint, true));
        QApplication::processEvents();
        const auto unrelated_status = model->vaultStatus();
        QVERIFY(!unrelated_status.is_fixed_staged_vault);
        QVERIFY(std::ranges::find(unrelated_status.manually_lost_signers, unrelated_fingerprint) !=
                unrelated_status.manually_lost_signers.end());
        QVERIFY(vault_notice->text().contains(QString::fromStdString(unrelated_fingerprint), Qt::CaseInsensitive));
        QVERIFY(vault_notice->text().contains(QStringLiteral("marked lost"), Qt::CaseInsensitive));
        QVERIFY(!send.findChild<QPushButton*>("sendButton")->isEnabled());
        QVERIFY(model->setVaultSignerLost(unrelated_fingerprint, false));
        QApplication::processEvents();
        QVERIFY(send.findChild<QPushButton*>("sendButton")->isEnabled());
    }

    send.startDelayedRecovery();
    auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
    auto* recovery_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    QVERIFY(recovery);
    QVERIFY(recovery_stage);
    QVERIFY(!recovery->isHidden());
    QVERIFY(!recovery_stage->isChecked());
    recovery_stage->click();
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 1u);
    QVERIFY(send.getCoinControl()->m_script_path);
    send.clear();
    QApplication::processEvents();
    QVERIFY(recovery->isHidden());
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
    QVERIFY(recovery->isHidden());
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

    send.startDelayedRecovery();
    recovery_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    QVERIFY(recovery_stage);
    recovery_stage->click();
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 1u);
    QString recovery_copy;
    const Txid recovery_id = SendFromDialog(send, pay, 1 * COIN, &recovery_copy);
    QVERIFY(recovery_copy.contains(QStringLiteral("You can increase the fee later.")));
    QVERIFY(recovery_copy.contains(QStringLiteral("Delayed recovery:")));
    QVERIFY(recovery_copy.contains(QStringLiteral("relative recovery clock starts over")));
    QVERIFY(recovery->isHidden());
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
    QVERIFY(model->vaultStatus().manually_lost_signers.empty());
    LoseSignerAndConfirm(*model, mock.Fingerprint());
    QVERIFY(QMetaObject::invokeMethod(&send, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY(race_txid->IsNull());

    model->updateTransaction();
    model->pollBalanceChanged();
    QApplication::processEvents();
    auto* open_lost = send.findChild<QLabel*>("vaultSendNotice");
    auto* open_balance = send.findChild<QLabel*>("labelBalance");
    auto* open_send_btn = send.findChild<QPushButton*>("sendButton");
    QVERIFY(open_lost);
    QVERIFY(open_balance);
    QVERIFY(open_send_btn);
    QVERIFY(!open_lost->isHidden());
    QVERIFY(open_balance->text().startsWith(QStringLiteral("0.00000000")));
    QVERIFY(!open_send_btn->isEnabled());
    QVERIFY(recovery->isHidden());

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

    // Leave a known-mature recovery output for the lost-participant offer.
    // Earlier send/change transactions intentionally restart their own clocks.
    fund(3);
    test.mineBlocks(1);
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    QApplication::processEvents();

    SendCoinsDialog send_lost(style.get());
    send_lost.setClientModel(&client);
    send_lost.setModel(model);
    auto* lost = send_lost.findChild<QLabel*>("vaultSendNotice");
    QVERIFY(lost);
    QVERIFY(!lost->isHidden());
    QVERIFY(lost->text().contains(QStringLiteral("lost")));
    QVERIFY(lost->text().contains(QStringLiteral("participant"), Qt::CaseInsensitive));
    QVERIFY(lost->text().contains(QString::fromStdString(mock.Fingerprint())));
    auto* lost_name = send_lost.findChild<QLabel*>("labelBalanceName");
    auto* lost_bal = send_lost.findChild<QLabel*>("labelBalance");
    QVERIFY(lost_name);
    QVERIFY(lost_bal);
    QVERIFY(lost_name->text().contains(QStringLiteral("immediate send"), Qt::CaseInsensitive));
    QVERIFY(lost_bal->text().startsWith(QStringLiteral("0.00000000")));
    auto* send_btn = send_lost.findChild<QPushButton*>("sendButton");
    QVERIFY(send_btn);
    QVERIFY(!send_btn->isEnabled());
    auto* recovery_offer = send_lost.findChild<QPushButton*>("vaultDelayedRecoveryOfferButton");
    QVERIFY(recovery_offer);
    QVERIFY(!recovery_offer->isHidden());
    QVERIFY(recovery_offer->isEnabled());
    recovery_offer->click();
    auto* rec_lost = send_lost.findChild<QWidget*>("delayedRecoveryPanel");
    auto* lost_stage = send_lost.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    QVERIFY(rec_lost);
    QVERIFY(lost_stage);
    QVERIFY(!lost_stage->isChecked());
    lost_stage->click();
    QApplication::processEvents();
    QVERIFY(send_btn->isEnabled());

    // Returning to standard Send is an explicit boundary; it must not retain
    // recovery coin-control state.
    send_lost.clear();
    QVERIFY(model->setVaultSignerLost(mock.Fingerprint(), false));
    QVERIFY(model->wallet().getVaultStatus().lost_signers.empty());
    model->updateTransaction();
    model->pollBalanceChanged();
    send_lost.setBalance(model->wallet().getBalances());
    QApplication::processEvents();
    QVERIFY(!lost->text().contains(QStringLiteral("marked lost"), Qt::CaseInsensitive));
    QVERIFY(rec_lost->isHidden());
    QVERIFY(send_btn->isEnabled());

    // A durable mutation made outside WalletModel (for example by RPC) must
    // also be caught before the review dialog opens, even while the GUI cache
    // still reports no loss.
    QTRY_VERIFY_WITH_TIMEOUT(model->vaultStatus().manually_lost_signers.empty(), 5000);
    QVERIFY(model->wallet().setLostSigner(mock.Fingerprint(), true));
    QVERIFY(model->vaultStatus().manually_lost_signers.empty());
    auto* stale_entries = send_lost.findChild<QVBoxLayout*>("entries");
    QVERIFY(stale_entries);
    auto* stale_entry = qobject_cast<SendCoinsEntry*>(stale_entries->itemAt(0)->widget());
    QVERIFY(stale_entry);
    stale_entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    stale_entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    Txid stale_txid;
    QObject::connect(&send_lost, &SendCoinsDialog::coinsSent, [&](const Txid& hash) { stale_txid = hash; });
    ConfirmSend();
    QVERIFY(QMetaObject::invokeMethod(&send_lost, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY(stale_txid.IsNull());
    QVERIFY(model->wallet().setLostSigner(mock.Fingerprint(), false));
    model->refreshVaultSignerStatus();

    // A transaction reviewed for policy A must not survive advanced/RPC
    // tooling activating policy B while the confirmation modal is open. Build
    // a structurally equivalent vault around fresh public participants so the
    // complete policy commitment, rather than only the visible stage, changes.
    const auto original_policy = wallet::ParseVaultPolicyPackage(model->wallet().exportVaultPolicy());
    QVERIFY2(original_policy, qPrintable(QString::fromStdString(util::ErrorString(original_policy).original)));
    const auto original_status = model->wallet().getVaultStatus();
    QVERIFY(!original_status.is_fixed_staged_vault);
    QVERIFY(original_status.participants.empty());
    std::set<std::string> original_fingerprints;
    for (size_t pos = original_policy->descs.front().find('['); pos != std::string::npos;
         pos = original_policy->descs.front().find('[', pos + 1)) {
        if (pos + 9 > original_policy->descs.front().size()) continue;
        const std::string fingerprint{original_policy->descs.front().substr(pos + 1, 8)};
        if (IsHex(fingerprint)) original_fingerprints.insert(fingerprint);
    }
    QVERIFY(!original_fingerprints.empty());
    std::vector<wallet::MultisigKeySpec> replacement_keys;
    replacement_keys.reserve(original_fingerprints.size());
    for (size_t index = 0; index < original_fingerprints.size(); ++index) {
        const AirKey key = MakeAirKey();
        wallet::MultisigKeySpec spec;
        spec.fingerprint = key.fpr;
        spec.path = key.path;
        spec.xpub = key.xpub;
        spec.label = "policy-swap-participant-" + std::to_string(index + 1);
        replacement_keys.push_back(std::move(spec));
    }
    wallet::MultisigOptions replacement_options;
    replacement_options.type = OutputType::BECH32M;
    replacement_options.fallback_older = original_policy->fallback_older;
    replacement_options.fallback_after = original_policy->fallback_after;
    replacement_options.fallback_older_one_key = original_policy->fallback_older_one_key;
    auto replacement_descriptors = wallet::PrepareMultisigDescriptor(
        original_policy->nrequired, replacement_keys, replacement_options);
    QVERIFY2(replacement_descriptors,
             qPrintable(QString::fromStdString(util::ErrorString(replacement_descriptors).original)));
    wallet::VaultPolicyPackage replacement_policy{*original_policy};
    replacement_policy.descs = replacement_descriptors->descs;
    replacement_policy.policy_id = replacement_descriptors->policy_id;
    QVERIFY(wallet::VaultPolicyCommitment(replacement_policy) !=
            wallet::VaultPolicyCommitment(*original_policy));
    const std::string replacement_policy_json = wallet::FormatVaultPolicyPackage(replacement_policy);

    SendCoinsDialog policy_swap_send(style.get());
    policy_swap_send.setClientModel(&client);
    policy_swap_send.setModel(model);
    auto* policy_swap_entries = policy_swap_send.findChild<QVBoxLayout*>("entries");
    QVERIFY(policy_swap_entries);
    auto* policy_swap_entry = qobject_cast<SendCoinsEntry*>(policy_swap_entries->itemAt(0)->widget());
    QVERIFY(policy_swap_entry);
    policy_swap_entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    policy_swap_entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    Txid policy_swap_txid;
    QString policy_swap_rejection;
    QString policy_swap_error;
    bool policy_swapped{false};
    QObject::connect(&policy_swap_send, &SendCoinsDialog::coinsSent,
                     [&](const Txid& hash) { policy_swap_txid = hash; });
    QObject::connect(&policy_swap_send, &SendCoinsDialog::message,
                     [&](const QString&, const QString& message, unsigned int) {
                         if (message.contains(QStringLiteral("policy"), Qt::CaseInsensitive)) {
                             policy_swap_rejection = message;
                         }
                     });
    QTimer::singleShot(0, [&] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (!widget->inherits("SendConfirmationDialog")) continue;
            const auto imported = model->wallet().importVaultPolicy(replacement_policy_json);
            policy_swapped = imported.has_value();
            if (!imported) {
                policy_swap_error = QString::fromStdString(util::ErrorString(imported).original);
            }
            auto* dialog = qobject_cast<SendConfirmationDialog*>(widget);
            QAbstractButton* button = dialog->button(QMessageBox::Yes);
            Assert(button);
            button->setEnabled(true);
            button->click();
        }
    });
    QVERIFY(QMetaObject::invokeMethod(&policy_swap_send, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY2(policy_swapped, qPrintable(policy_swap_error));
    const auto active_replacement = wallet::ParseVaultPolicyPackage(model->wallet().exportVaultPolicy());
    QVERIFY(active_replacement);
    QCOMPARE(wallet::VaultPolicyCommitment(*active_replacement),
             wallet::VaultPolicyCommitment(replacement_policy));
    QVERIFY(policy_swap_txid.IsNull());
    QVERIFY(policy_swap_rejection.contains(QStringLiteral("policy"), Qt::CaseInsensitive));
    QVERIFY(policy_swap_rejection.contains(QStringLiteral("draft"), Qt::CaseInsensitive));
    QVERIFY(policy_swap_rejection.contains(QStringLiteral("discard"), Qt::CaseInsensitive));

    // An imported advanced policy can contain both relative and absolute
    // recovery leaves. Preserve the exact GUI-selected stage through
    // WalletModel and the wallet interface: selecting after(500) must never
    // be reinterpreted as the first (already mature) older(10) leaf.
    wallet::VaultPolicyPackage mixed_lock_policy{replacement_policy};
    mixed_lock_policy.descs.clear();
    for (const std::string& encoded : replacement_policy.descs) {
        const size_t checksum_pos{encoded.rfind('#')};
        QVERIFY(checksum_pos != std::string::npos);
        const std::string body{encoded.substr(0, checksum_pos)};
        const std::string relative_marker{"and_v(v:older(1),"};
        const size_t leaf_pos{body.find(relative_marker)};
        QVERIFY(leaf_pos != std::string::npos);
        QVERIFY(body.ends_with(')'));

        // The source descriptor has one Taproot leaf at the end. Retain its
        // exact keys/quorum, duplicate it into a two-leaf tree, and change
        // only the lock identities before recomputing the descriptor checksum.
        std::string relative_leaf{body.substr(leaf_pos, body.size() - leaf_pos - 1)};
        const size_t relative_lock{relative_leaf.find("older(1)")};
        QVERIFY(relative_lock != std::string::npos);
        relative_leaf.replace(relative_lock, std::string{"older(1)"}.size(), "older(10)");
        std::string absolute_leaf{relative_leaf};
        const size_t absolute_lock{absolute_leaf.find("older(10)")};
        QVERIFY(absolute_lock != std::string::npos);
        absolute_leaf.replace(absolute_lock, std::string{"older(10)"}.size(), "after(500)");
        const std::string mixed_body{body.substr(0, leaf_pos) + "{" + relative_leaf + "," + absolute_leaf + "})"};
        const std::string checksum{GetDescriptorChecksum(mixed_body)};
        QVERIFY(!checksum.empty());
        mixed_lock_policy.descs.push_back(mixed_body + "#" + checksum);
    }
    mixed_lock_policy.policy_id = wallet::VaultPolicyId(mixed_lock_policy.descs.front());
    mixed_lock_policy.nrequired = 2;
    mixed_lock_policy.fallback_older = 10;
    mixed_lock_policy.fallback_after.reset();
    mixed_lock_policy.fallback_older_one_key.reset();
    mixed_lock_policy.recovery_stages = {
        {2, uint32_t{10}, {}},
        {2, {}, uint32_t{500}},
    };
    const std::string mixed_lock_json{wallet::FormatVaultPolicyPackage(mixed_lock_policy)};
    const auto checked_mixed_lock{wallet::ParseVaultPolicyPackage(mixed_lock_json)};
    QVERIFY2(checked_mixed_lock,
             qPrintable(QString::fromStdString(util::ErrorString(checked_mixed_lock).original)));
    QCOMPARE(checked_mixed_lock->recovery_stages.size(), size_t{2});
    QCOMPARE(checked_mixed_lock->recovery_stages[0].older, std::optional<uint32_t>{10});
    QCOMPARE(checked_mixed_lock->recovery_stages[1].after, std::optional<uint32_t>{500});
    const auto imported_mixed_lock{model->wallet().importVaultPolicy(mixed_lock_json)};
    QVERIFY2(imported_mixed_lock,
             qPrintable(QString::fromStdString(util::ErrorString(imported_mixed_lock).original)));

    const auto mixed_lock_dest{model->wallet().getNewDestination(OutputType::BECH32M, "")};
    QVERIFY2(mixed_lock_dest,
             qPrintable(QString::fromStdString(util::ErrorString(mixed_lock_dest).original)));
    CMutableTransaction mixed_lock_fund = test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.at(6), /*input_vout=*/0, /*input_height=*/7,
        test.coinbaseKey, GetScriptForDestination(*mixed_lock_dest),
        10 * COIN, /*submit=*/false);
    test.CreateAndProcessBlock({mixed_lock_fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.mineBlocks(9);
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    model->refreshVaultSignerStatus();
    QApplication::processEvents();
    QVERIFY(m_node.getNumBlocks() < 500);
    const auto mixed_lock_status{model->wallet().getVaultStatus()};
    QCOMPARE(mixed_lock_status.recovery_stages.size(), size_t{2});
    QVERIFY(mixed_lock_status.recovery_stages[0].recoverable_now > 0);
    QCOMPARE(mixed_lock_status.recovery_stages[1].recoverable_now, 0);
    QVERIFY(mixed_lock_status.recovery_stages[1].awaiting_maturity > 0);

    SendCoinsDialog mixed_lock_send(style.get());
    mixed_lock_send.setClientModel(&client);
    mixed_lock_send.setModel(model);
    mixed_lock_send.startDelayedRecovery();
    auto* mixed_after_stage = mixed_lock_send.findChild<QRadioButton*>("delayedRecoveryStage2Button");
    QVERIFY(mixed_after_stage);
    mixed_after_stage->click();
    QApplication::processEvents();
    const wallet::CCoinControl* const mixed_after_control{mixed_lock_send.getCoinControl()};
    QVERIFY(mixed_after_control->m_script_path);
    QVERIFY(!mixed_after_control->m_nSequence);
    QCOMPARE(mixed_after_control->m_locktime, std::optional<uint32_t>{500});
    QCOMPARE(model->wallet().getAvailableBalance(*mixed_after_control), 0);
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
            test.m_coinbase_txns.at(5), /*input_vout=*/0, /*input_height=*/6, test.coinbaseKey,
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
        auto* recovery_status = relative_overview.findChild<QLabel*>("vaultRecoveryStage1Summary");
        auto* recovery_technical = relative_overview.findChild<QLabel*>("vaultRecoveryStage1Technical");
        QVERIFY(recovery_status);
        QVERIFY(recovery_technical);
        QVERIFY(!recovery_status->isHidden());
        QVERIFY(recovery_status->text().contains(QStringLiteral("about"), Qt::CaseInsensitive));
        QVERIFY(recovery_technical->isHidden());
        QVERIFY(recovery_technical->text().contains(QStringLiteral("1 block")));
        QVERIFY(!recovery_technical->text().contains(QStringLiteral("1 blocks")));

        SendCoinsDialog relative_send(style.get());
        relative_send.setClientModel(&client);
        relative_send.setModel(relative_model);
        auto* relative_lost = relative_send.findChild<QLabel*>("vaultSendNotice");
        auto* relative_balance = relative_send.findChild<QLabel*>("labelBalance");
        auto* relative_send_button = relative_send.findChild<QPushButton*>("sendButton");
        QVERIFY(relative_lost);
        QVERIFY(relative_balance);
        QVERIFY(relative_send_button);

        // Use an otherwise untouched confirmed coin to prove that clearing a
        // lost-signer flag restores both the immediate balance and the action
        // in an already-open dialog.
        QVERIFY(relative_model->setVaultSignerLost(mock.Fingerprint(), true));
        relative_send.setBalance(relative_model->wallet().getBalances());
        QApplication::processEvents();
        QVERIFY(!relative_lost->isHidden());
        // This advanced 2-of-2 policy has no reduced-quorum branch. Maturity
        // cannot compensate for the marked-lost hardware key, so do not show
        // a misleading one-block countdown.
        QVERIFY(relative_lost->text().contains(QStringLiteral("marked lost"), Qt::CaseInsensitive));
        QVERIFY(relative_lost->text().contains(QStringLiteral("dashboard"), Qt::CaseInsensitive));
        QVERIFY(relative_balance->text().startsWith(QStringLiteral("0.00000000")));
        QVERIFY(!relative_send_button->isEnabled());
        QVERIFY(relative_send.findChild<QWidget*>("delayedRecoveryPanel")->isHidden());
        QVERIFY(relative_model->setVaultSignerLost(mock.Fingerprint(), false));
        relative_send.setBalance(relative_model->wallet().getBalances());
        QApplication::processEvents();
        QVERIFY(!relative_lost->text().contains(QStringLiteral("marked lost"), Qt::CaseInsensitive));
        QVERIFY(!relative_balance->text().startsWith(QStringLiteral("0.00000000")));
        QVERIFY(relative_send_button->isEnabled());
        QVERIFY(relative_send.findChild<QWidget*>("delayedRecoveryPanel")->isHidden());

        relative_send.startDelayedRecovery();
        auto* relative_recovery = relative_send.findChild<QWidget*>("delayedRecoveryPanel");
        auto* relative_stage = relative_send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
        QVERIFY(relative_recovery);
        QVERIFY(relative_stage);
        relative_stage->click();
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
        QVERIFY(!relative_recovery->isHidden());

        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        relative_model->pollBalanceChanged();
        QApplication::processEvents();
        const auto mature = relative_model->wallet().getBalances();
        QCOMPARE(mature.vault_awaiting, 0);
        QCOMPARE(mature.vault_recoverable, 10 * COIN);

        QString relative_confirmation;
        const Txid relative_id = SendFromDialog(relative_send, pay, 1 * COIN, &relative_confirmation);
        QVERIFY(relative_confirmation.contains(QStringLiteral("relative recovery clock starts over")));
        const auto relative_tx = relative_model->wallet().getTx(relative_id);
        QVERIFY(relative_tx);
        QCOMPARE(relative_tx->vin[0].nSequence, 2u);
        QVERIFY(relative_tx->vin[0].scriptWitness.stack.size() > 1);
        QVERIFY(relative_recovery->isHidden());

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
        recovery_status = relative_overview.findChild<QLabel*>("vaultRecoveryStage1Summary");
        recovery_technical = relative_overview.findChild<QLabel*>("vaultRecoveryStage1Technical");
        QVERIFY(recovery_status);
        QVERIFY(recovery_technical);
        QVERIFY(!recovery_status->isHidden());
        QVERIFY(recovery_technical->text().contains(QStringLiteral("1 block")));
        QVERIFY(!recovery_technical->text().contains(QStringLiteral("1 blocks")));

        relative_send.startDelayedRecovery();
        relative_stage = relative_send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
        QVERIFY(relative_stage);
        relative_stage->click();
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
        absolute_send.startDelayedRecovery();
        auto* absolute_recovery = absolute_send.findChild<QWidget*>("delayedRecoveryPanel");
        auto* absolute_stage = absolute_send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
        QVERIFY(absolute_recovery);
        QVERIFY(absolute_stage);
        absolute_stage->click();
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
        QVERIFY(!absolute_recovery->isHidden());

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
        QVERIFY(absolute_confirmation.contains(QStringLiteral("eligible now")));
        QVERIFY(!absolute_confirmation.contains(QStringLiteral("absolute block")));
        QVERIFY(!absolute_confirmation.contains(QStringLiteral("relative recovery clock starts over")));
        const auto absolute_tx = absolute_model->wallet().getTx(absolute_id);
        QVERIFY(absolute_tx);
        QCOMPARE(absolute_tx->nLockTime, after_height);
        QVERIFY(absolute_tx->vin[0].nSequence != CTxIn::SEQUENCE_FINAL);
        QVERIFY(absolute_tx->vin[0].scriptWitness.stack.size() > 1);
        QVERIFY(absolute_recovery->isHidden());
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
    // The 2/4-block fixture is an advanced/custom policy used to exercise
    // maturity transitions quickly. Do not invent a trusted participant
    // roster for it: only an exact canonical fixed schedule is eligible for
    // FixedVaultParticipants and participant-aware reduced-quorum signing.
    QVERIFY(!status.is_fixed_staged_vault);
    QVERIFY(status.participants.empty());
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

    // Even when every key is local, a Recovery Vault must remain unsigned
    // until after review. Simulate an RPC loss marker arriving in the modal
    // event loop and prove the post-confirmation durable-state check blocks the
    // transaction that was already prepared for review.
    // This test created all three keys locally, so it can select a known
    // fixture identity directly from the authoritative public descriptor
    // without asking the product to expose a custom-policy roster.
    const auto active_policy = wallet::ParseVaultPolicyPackage(model->wallet().exportVaultPolicy());
    QVERIFY2(active_policy, qPrintable(QString::fromStdString(util::ErrorString(active_policy).original)));
    std::set<std::string> local_fingerprints;
    for (size_t pos = active_policy->descs.front().find('['); pos != std::string::npos;
         pos = active_policy->descs.front().find('[', pos + 1)) {
        if (pos + 9 > active_policy->descs.front().size()) continue;
        const std::string fingerprint{active_policy->descs.front().substr(pos + 1, 8)};
        if (IsHex(fingerprint)) local_fingerprints.insert(fingerprint);
    }
    QCOMPARE(local_fingerprints.size(), size_t{3});
    const std::string local_fingerprint{*local_fingerprints.begin()};
    auto* immediate_entries = immediate.findChild<QVBoxLayout*>("entries");
    QVERIFY(immediate_entries);
    auto* immediate_entry = qobject_cast<SendCoinsEntry*>(immediate_entries->itemAt(0)->widget());
    QVERIFY(immediate_entry);
    immediate_entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    immediate_entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    bool unsigned_at_review{false};
    Txid blocked_local_txid;
    const auto blocked_connection = QObject::connect(
        &immediate, &SendCoinsDialog::coinsSent,
        [&](const Txid& hash) { blocked_local_txid = hash; });
    QTimer::singleShot(0, [&] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (!widget->inherits("SendConfirmationDialog")) continue;
            auto* dialog = qobject_cast<SendConfirmationDialog*>(widget);
            unsigned_at_review = immediate.currentTransactionIsUnsignedForTest();
            Assert(model->wallet().setLostSigner(local_fingerprint, true));
            QAbstractButton* button = dialog->button(QMessageBox::Yes);
            Assert(button);
            button->setEnabled(true);
            button->click();
        }
    });
    QVERIFY(QMetaObject::invokeMethod(&immediate, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY(unsigned_at_review);
    QVERIFY(blocked_local_txid.IsNull());
    QObject::disconnect(blocked_connection);
    QVERIFY(model->setVaultSignerLost(local_fingerprint, false));
    QApplication::processEvents();

    // With the participant restored, signing occurs only after confirmation
    // and still produces the expected complete key-path spend.
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
    auto* final_status = overview.findChild<QLabel*>("vaultRecoveryStage2Summary");
    auto* final_quorum = overview.findChild<QLabel*>("vaultRecoveryStage2Quorum");
    auto* final_technical = overview.findChild<QLabel*>("vaultRecoveryStage2Technical");
    auto* final_disclosure = overview.findChild<QPushButton*>("vaultAccessTechnicalButton");
    QVERIFY(final_status);
    QVERIFY(final_quorum);
    QVERIFY(final_technical);
    QVERIFY(final_disclosure);
    QVERIFY(!final_status->isHidden());
    QVERIFY(final_quorum->text().contains(QStringLiteral("Any 1 key")));
    QVERIFY(final_technical->isHidden());
    final_disclosure->click();
    QVERIFY(!final_technical->isHidden());
    QVERIFY(final_technical->text().contains(QStringLiteral("3 blocks")));

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    send.startDelayedRecovery();
    auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
    auto* first_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    auto* final_stage = send.findChild<QRadioButton*>("delayedRecoveryStage2Button");
    QVERIFY(recovery);
    QVERIFY(first_stage);
    QVERIFY(final_stage);
    QVERIFY(!recovery->isHidden());
    QVERIFY(!first_stage->isChecked());
    QVERIFY(!final_stage->isChecked());
    auto* send_technical = send.findChild<QLabel*>("delayedRecoveryStage2Technical");
    auto* send_disclosure = send.findChild<QPushButton*>("delayedRecoveryStage2TechnicalButton");
    QVERIFY(send_technical);
    QVERIFY(send_disclosure);
    QVERIFY(send_technical->isHidden());
    send_disclosure->click();
    QVERIFY(!send_technical->isHidden());
    QVERIFY(send_technical->text().contains(QStringLiteral("4-block")));
    QVERIFY(!send.findChild<QPushButton*>("sendButton")->isEnabled());
    QVERIFY(!send.getCoinControl()->m_nSequence);
    first_stage->click();
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 2u);
    final_stage = send.findChild<QRadioButton*>("delayedRecoveryStage2Button");
    QVERIFY(final_stage);
    final_stage->click();
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 4u);
    QCOMPARE(send.getCoinControl()->m_min_depth, 4);
    QVERIFY(send.getCoinControl()->m_script_path);

    first_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    QVERIFY(first_stage);
    first_stage->click();
    test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    status = model->wallet().getVaultStatus();
    QVERIFY(status.recovery_stages[0].recoverable_now > 0);
    QCOMPARE(status.recovery_stages[1].recoverable_now, 0);
    QApplication::processEvents();
    first_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    QVERIFY(first_stage);
    QVERIFY(first_stage->isChecked());

    test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    status = model->wallet().getVaultStatus();
    QVERIFY(status.recovery_stages[0].recoverable_now > 0);
    QVERIFY(status.recovery_stages[1].recoverable_now > 0);
    QApplication::processEvents();
    first_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    final_stage = send.findChild<QRadioButton*>("delayedRecoveryStage2Button");
    QVERIFY(first_stage);
    QVERIFY(final_stage);
    QVERIFY(first_stage->isChecked()); // Never auto-select the lower-signature stage.
    QVERIFY(!final_stage->isChecked());

    final_stage->click();
    QApplication::processEvents();
    QString confirmation;
    const Txid final_id = SendFromDialog(send, pay, 1 * COIN, &confirmation);
    QVERIFY(confirmation.contains(QStringLiteral("any 1 participant")));
    QVERIFY(confirmation.contains(QStringLiteral("after about")));
    QVERIFY(!confirmation.contains(QStringLiteral("4 blocks")));
    QVERIFY(confirmation.contains(QStringLiteral("relative recovery clock starts over")));
    const auto final_tx = model->wallet().getTx(final_id);
    QVERIFY(final_tx);
    QCOMPARE(final_tx->vin.size(), size_t{1});
    QCOMPARE(final_tx->vin[0].nSequence, 4u);
    const auto& witness = final_tx->vin[0].scriptWitness.stack;
    QVERIFY(witness.size() >= 4);
    QCOMPARE(static_cast<int>(std::count_if(witness.begin(), witness.end() - 2,
                                           [](const auto& item) { return !item.empty(); })), 1);
    QVERIFY(recovery->isHidden());

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

    auto mock = std::make_unique<hwi::MockRegistration>(
        hwi::MakeMockMasterFromHex(), ChainType::REGTEST);

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    MultisigWizard wizard(m_node, &controller);
    wizard.show();
    QApplication::processEvents();
    auto* name = wizard.findChild<QLineEdit*>("stagedWalletNameEdit");
    QVERIFY(name);
    name->setText(QStringLiteral("GuiMissingKey"));
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
    QCOMPARE(wizard.localKeyCount(), 2);
    QCOMPARE(static_cast<int>(wizard.keys().size()), MultisigWizard::kStagedVaultKeyCount);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
    CompleteBackupPage(wizard);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
    CompleteVerification(wizard);
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
    QVERIFY2(wizard.createdWallet(), qPrintable(wizard.createError()));
    WalletModel* model = wizard.createdWallet();
    QVERIFY(model->vaultStatus().is_fixed_staged_vault);
    const auto dest = wizard.firstReceiveAddress();
    QVERIFY(!!dest);
    const CScript spk = GetScriptForDestination(*dest);
    CMutableTransaction fund = test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.front(), 0, /*input_height=*/1, test.coinbaseKey, spk, 10 * COIN, /*submit=*/false);
    test.CreateAndProcessBlock({fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    CMutableTransaction young_fund = test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.at(1), 0, /*input_height=*/2, test.coinbaseKey, spk, 7 * COIN, /*submit=*/false);
    test.CreateAndProcessBlock({young_fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
    model->pollBalanceChanged();
    QVERIFY(model->wallet().getBalances().balance >= 17 * COIN);

    mock.reset();
    QSignalSpy signer_refresh{model, &WalletModel::vaultSignerStatusChanged};
    model->refreshVaultSignerStatus();
    QTRY_VERIFY_WITH_TIMEOUT(signer_refresh.count() >= 2, 5000);
    QTRY_VERIFY_WITH_TIMEOUT(model->vaultStatus().signer_discovery_complete, 5000);
    const auto missing_status{model->vaultStatus()};
    QVERIFY(missing_status.is_fixed_staged_vault);
    QCOMPARE(missing_status.recovery_stages.size(), size_t{2});
    QCOMPARE(missing_status.recovery_stages.front().nrequired, 2);
    QCOMPARE(missing_status.recovery_stages.front().older,
             std::optional<uint32_t>{MultisigWizard::kCurrentPrimaryVaultDelay});
    QCOMPARE(missing_status.recovery_stages.front().recoverable_now, 0);
    QCOMPARE(missing_status.recovery_stages.front().awaiting_maturity, 17 * COIN);
    QCOMPARE(missing_status.recovery_stages.back().nrequired, 1);
    QCOMPARE(missing_status.recovery_stages.back().older,
             std::optional<uint32_t>{MultisigWizard::kCurrentFinalVaultDelay});
    QCOMPARE(missing_status.recovery_stages.back().recoverable_now, 0);
    QCOMPARE(missing_status.recovery_stages.back().awaiting_maturity, 17 * COIN);
    const auto missing_hardware{std::ranges::find_if(missing_status.participants, [](const auto& participant) {
        return participant.type == interfaces::Wallet::VaultParticipantType::HARDWARE;
    })};
    QVERIFY(missing_hardware != missing_status.participants.end());
    QCOMPARE(missing_hardware->availability, interfaces::Wallet::VaultSignerAvailability::UNAVAILABLE);

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    auto* recovery_offer = send.findChild<QPushButton*>("vaultDelayedRecoveryOfferButton");
    auto* recovery_availability = send.findChild<QLabel*>("vaultDelayedRecoveryOfferAvailability");
    QVERIFY(recovery_offer);
    QVERIFY(recovery_availability);
    QVERIFY(!recovery_offer->isHidden());
    QVERIFY(!recovery_offer->isEnabled());
    QVERIFY(recovery_availability->text().contains(QStringLiteral("about"), Qt::CaseInsensitive));
    const QString pay = QString::fromStdString(EncodeDestination(PKHash(test.coinbaseKey.GetPubKey())));
    auto* entries = send.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries);
    auto* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    QVERIFY(entry);
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(pay);
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(1 * COIN);
    Txid too_soon;
    QObject::connect(&send, &SendCoinsDialog::coinsSent, [&](const Txid& hash) { too_soon = hash; });
    bool review_seen{false};
    bool direct_send_disabled{false};
    bool unsigned_available{false};
    QString prepare_error;
    QTimer::singleShot(0, [&] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog")) {
                auto* dialog = qobject_cast<SendConfirmationDialog*>(widget);
                review_seen = true;
                for (int i = 0; i < SEND_CONFIRM_DELAY + 1; ++i) {
                    QMetaObject::invokeMethod(dialog, "countDown", Qt::DirectConnection);
                }
                direct_send_disabled = !dialog->button(QMessageBox::Yes)->isEnabled();
                unsigned_available = dialog->button(QMessageBox::Save) && dialog->button(QMessageBox::Save)->isEnabled();
                dialog->button(QMessageBox::Cancel)->click();
            } else if (auto* message = qobject_cast<QMessageBox*>(widget)) {
                prepare_error = message->text();
                message->accept();
            }
        }
    });
    QVERIFY(QMetaObject::invokeMethod(&send, "sendButtonClicked", Q_ARG(bool, false)));
    QVERIFY(too_soon.IsNull());
    QVERIFY2(review_seen, qPrintable(prepare_error));
    QVERIFY(direct_send_disabled);
    QVERIFY(unsigned_available);

    // A missing immediate signer exposes the exceptional recovery route, but
    // an immature fixed vault must not offer a misleading enabled action.
    recovery_offer->click();
    auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
    QVERIFY(recovery);
    QVERIFY(recovery->isHidden());
    QVERIFY(!send.getCoinControl()->m_nSequence);
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
    send.startDelayedRecovery();
    auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
    auto* recovery_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    QVERIFY(recovery);
    QVERIFY(recovery_stage);
    QVERIFY(!recovery->isHidden());
    recovery_stage->click();
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
    QVERIFY(!send.findChild<QRadioButton*>("vaultRecoveryModeButton"));
    const QString pay = QString::fromStdString(EncodeDestination(PKHash(test.coinbaseKey.GetPubKey())));
    const Txid keypath_id = SendFromDialog(send, pay, 1 * COIN);
    const auto keypath_tx = model->wallet().getTx(keypath_id);
    QVERIFY(keypath_tx);
    QCOMPARE(keypath_tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
    QCOMPARE(static_cast<int>(keypath_tx->vin[0].scriptWitness.stack.size()), 1);

    send.startDelayedRecovery();
    auto* recovery = send.findChild<QWidget*>("delayedRecoveryPanel");
    auto* recovery_stage = send.findChild<QRadioButton*>("delayedRecoveryStage1Button");
    QVERIFY(recovery);
    QVERIFY(recovery_stage);
    recovery_stage->click();
    QApplication::processEvents();
    QCOMPARE(*send.getCoinControl()->m_nSequence, 1u);
    const Txid rec_id = SendFromDialog(send, pay, 1 * COIN);
    const auto rec_tx = model->wallet().getTx(rec_id);
    QVERIFY(rec_tx);
    QCOMPARE(rec_tx->vin[0].nSequence, 1u);
    QVERIFY(rec_tx->vin[0].scriptWitness.stack.size() > 1);
    wizard.close();
}
