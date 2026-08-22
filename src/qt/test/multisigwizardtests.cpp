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
#include <wallet/walletutil.h>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QItemSelectionModel>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPalette>
#include <QPixmap>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QSignalSpy>
#include <QSpinBox>
#include <QTableView>
#include <QTabWidget>
#include <QTest>
#include <QTimer>
#include <QVBoxLayout>
#include <QWizard>

#include <chrono>
#include <limits>
#include <memory>
#include <optional>

namespace {
const QStringList kShotNames{
    QStringLiteral("00-intro"),
    QStringLiteral("00b-template"),
    QStringLiteral("01-setup-p2wsh"),
    QStringLiteral("01b-setup-taproot"),
    QStringLiteral("02-keys"),
    QStringLiteral("02b-keys-recovery-only"),
    QStringLiteral("03-policy-p2wsh"),
    QStringLiteral("03b-policy-taproot"),
    QStringLiteral("03c-policy-after"),
    QStringLiteral("04-backup"),
    QStringLiteral("04b-backup-taproot"),
    QStringLiteral("05-verify"),
    QStringLiteral("05b-verify-hardware"),
    QStringLiteral("06-done"),
    QStringLiteral("06b-done-taproot"),
    QStringLiteral("07-overview-vault"),
    QStringLiteral("08-send-vault"),
    QStringLiteral("08b-send-recovery"),
    QStringLiteral("08c-send-lost-signer"),
};

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

void AssertBackupPage(MultisigWizard& wizard, std::optional<uint32_t> older = {}, std::optional<uint32_t> after = {})
{
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Backup));
    auto* policy = wizard.findChild<QPlainTextEdit*>("policyPackageEdit");
    auto* transcript = wizard.findChild<QPlainTextEdit*>("humanTranscriptEdit");
    auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
    QVERIFY(policy);
    QVERIFY(transcript);
    QVERIFY(ack);
    QVERIFY(wizard.createdWallet());

    const QString package_text = policy->toPlainText();
    const auto parsed = wallet::ParseVaultPolicyPackage(package_text.toStdString());
    QVERIFY2(parsed, qPrintable(QString::fromStdString(util::ErrorString(parsed).original)));
    QCOMPARE(QString::fromStdString(parsed->format), QStringLiteral("bitcoin-core-vault-policy"));
    QCOMPARE(parsed->version, 1);
    QCOMPARE(parsed->fallback_older, older);
    QCOMPARE(parsed->fallback_after, after);
    QCOMPARE(parsed->descs.size(), size_t{2});
    QCOMPARE(QString::fromStdString(parsed->policy_id), QString::fromStdString(wallet::VaultPolicyId(parsed->descs.front())));
    QCOMPARE(QString::fromStdString(parsed->network), QString::fromStdString(Params().GetChainTypeString()));
    QCOMPARE(parsed->nrequired, wizard.nrequired());
    QCOMPARE(package_text.trimmed(), QString::fromStdString(wallet::FormatVaultPolicyPackage(*parsed)).trimmed());
    QString public_error;
    QVERIFY2(PublicOnlyDescriptors(parsed->descs, public_error), qPrintable(public_error));
    QVERIFY(!package_text.contains(QStringLiteral("human transcript"), Qt::CaseInsensitive));
    QVERIFY(parsed->descs.front() != parsed->descs.back());

    const QString human = transcript->toPlainText();
    QVERIFY(human.contains(wizard.walletName()));
    QVERIFY(human.contains(QStringLiteral("## Descriptors")));
    QVERIFY(!human.contains(QStringLiteral("bitcoin-core-vault-policy")));
    QVERIFY(!ack->isChecked());
    QVERIFY(wizard.testOption(QWizard::NoCancelButton));
    QVERIFY(!wizard.button(QWizard::CancelButton)->isVisible());
    QApplication::processEvents();
    QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
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
        QVERIFY2(devices->item(row)->text().contains(QStringLiteral("verified"), Qt::CaseInsensitive),
                 qPrintable(status->text() + QStringLiteral(" | ") + devices->item(row)->text()));
        QVERIFY(status->text().contains(QStringLiteral("same address"), Qt::CaseInsensitive));
    }
    auto* air = wizard.findChild<QCheckBox*>("airgapVerifyCheck");
    QVERIFY(air);
    if (air->isVisible()) air->setChecked(true);
    QApplication::processEvents();
    QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
}

void WalkTo(MultisigWizard& wizard, int page)
{
    int guard = 0;
    while (wizard.currentId() != page && guard++ < 12) {
        if (wizard.currentId() == MultisigWizard::Page_Backup) {
            auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
            QVERIFY(ack);
            ack->setChecked(true);
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

void WalkScroogeToDone(MultisigWizard& wizard, int nrequired, int delay_blocks)
{
    QSignalSpy created_spy(&wizard, &MultisigWizard::created);
    const bool expect_preserved_off = delay_blocks == 0 && !wizard.fallbackOlder();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Template));
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
    wizard.applyTemplate();
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
    auto* local = wizard.findChild<QCheckBox*>("includeLocalCheck");
    QVERIFY(local);
    local->setChecked(wizard.includeLocalKey());
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
    auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
    QVERIFY(ack);
    ack->setChecked(true);
    QApplication::processEvents();
    QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
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

void WalkTemplateToDone(MultisigWizard& wizard,
                        MultisigWizard::VaultTemplate preset,
                        OutputType output_type,
                        int expected_keys,
                        int expected_active_keys,
                        int expected_nrequired,
                        std::optional<uint32_t> expected_older = {})
{
    QSignalSpy created_spy(&wizard, &MultisigWizard::created);
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));
    wizard.next();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Template));
    wizard.setVaultTemplate(preset);
    wizard.applyTemplate();
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
    auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
    QVERIFY(ack);
    ack->setChecked(true);
    QApplication::processEvents();
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
    MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
    QCOMPARE(wizard.startId(), static_cast<int>(MultisigWizard::Page_Intro));
    wizard.show();
    QApplication::processEvents();
    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));

    wizard.setWalletName(QStringLiteral("Family"));
    wizard.setIncludeLocalKey(true);
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
}

void MultisigWizardTests::grabPages()
{
    const QByteArray dest = qgetenv("MULTISIG_WIZARD_SHOTS");
    if (dest.isEmpty()) {
        QSKIP("Set MULTISIG_WIZARD_SHOTS to a directory to dump wizard PNGs");
    }
    const QString dir = QString::fromLocal8Bit(dest);
    QVERIFY(QDir().mkpath(dir));

    QStringList expected_files;
    for (const QString& name : kShotNames) {
        const QString filename = name + QStringLiteral(".png");
        expected_files << filename;
        const QString path = QDir(dir).filePath(filename);
        if (QFileInfo::exists(path)) {
            QVERIFY2(QFile::remove(path), qPrintable(QStringLiteral("failed to remove stale shot ") + path));
        }
        QVERIFY(!QFileInfo::exists(path));
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

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate(QStringLiteral("other")));
    QVERIFY(style);
    WalletController controller(client, style.get(), nullptr);
    QApplication::processEvents();

    const AirKey family_key = MakeAirKey();
    const AirKey heir_key = MakeAirKey();

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("ShotOrdinaryWallet"));
        wizard.setIncludeLocalKey(true);
        wizard.addAirgappedKey(family_key.fpr, family_key.path, family_key.xpub, "Coldcard (vault)");
        wizard.rebuildKeyList();
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32);
        ShowSized(wizard);
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));
        Grab(wizard, dir, QStringLiteral("00-intro"));

        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Template));
        Grab(wizard, dir, QStringLiteral("00b-template"));
        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
        wizard.applyTemplate();
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
        auto* type = wizard.findChild<QComboBox*>("scriptTypeCombo");
        QVERIFY(type);
        const int vault_idx = OutputTypeIndex(*type, OutputType::BECH32M);
        const int p2wsh_idx = OutputTypeIndex(*type, OutputType::BECH32);
        QVERIFY(vault_idx >= 0);
        QVERIFY(p2wsh_idx >= 0);
        QCOMPARE(type->currentData().toInt(), static_cast<int>(OutputType::BECH32));
        const QString p2wsh_setup = VisibleText(wizard);
        QVERIFY(p2wsh_setup.contains(QStringLiteral("Ordinary multisig")));
        QVERIFY(p2wsh_setup.contains(QStringLiteral("no delayed recovery"), Qt::CaseInsensitive));
        Grab(wizard, dir, QStringLiteral("01-setup-p2wsh"));

        type->setCurrentIndex(vault_idx);
        QApplication::processEvents();
        QCOMPARE(type->currentData().toInt(), static_cast<int>(OutputType::BECH32M));
        Grab(wizard, dir, QStringLiteral("01b-setup-taproot"));
        type->setCurrentIndex(p2wsh_idx);

        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        QCOMPARE(static_cast<int>(wizard.keys().size()), 2);
        QCOMPARE(wizard.nActiveKeys(), 2);
        auto* key_count = wizard.findChild<QLabel*>("vaultKeyCount");
        auto* air_keys = wizard.findChild<QListWidget*>("airgappedList");
        QVERIFY(key_count);
        QVERIFY(air_keys);
        QCOMPARE(air_keys->count(), 1);
        QVERIFY(!air_keys->item(0)->text().contains(QStringLiteral("Heir")));
        Grab(wizard, dir, QStringLiteral("02-keys"));
        wizard.back();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
        type->setCurrentIndex(vault_idx);
        QApplication::processEvents();
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        wizard.addAirgappedKey(heir_key.fpr, heir_key.path, heir_key.xpub, "Heir", /*recovery_only=*/true);
        wizard.back();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        QApplication::processEvents();
        QCOMPARE(static_cast<int>(wizard.keys().size()), 3);
        QCOMPARE(wizard.nActiveKeys(), 2);
        QVERIFY(wizard.keys().back().recovery_only);
        QVERIFY(key_count->text().contains(QStringLiteral("2 active")));
        QVERIFY(key_count->text().contains(QStringLiteral("1 recovery-only")));
        QCOMPARE(air_keys->count(), 2);
        QVERIFY(air_keys->item(air_keys->count() - 1)->text().contains(QStringLiteral("Heir")));
        QVERIFY(air_keys->item(air_keys->count() - 1)->text().contains(QStringLiteral("recovery-only")));
        Grab(wizard, dir, QStringLiteral("02b-keys-recovery-only"));

        wizard.back();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
        type->setCurrentIndex(p2wsh_idx);
        QApplication::processEvents();
        wizard.next();
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Threshold));
        QCOMPARE(wizard.nActiveKeys(), 3);
        auto* delay_kind = wizard.findChild<QComboBox*>("delayKindCombo");
        auto* older = wizard.findChild<QSpinBox*>("fallbackOlderSpin");
        auto* after = wizard.findChild<QSpinBox*>("fallbackAfterSpin");
        QVERIFY(delay_kind);
        QVERIFY(older);
        QVERIFY(after);
        QVERIFY(!delay_kind->isVisible());
        QVERIFY(!older->isVisible());
        QVERIFY(!after->isVisible());
        const QString p2wsh_policy = VisibleText(wizard);
        QVERIFY(p2wsh_policy.contains(QStringLiteral("ordinary m-of-n"), Qt::CaseInsensitive));
        QVERIFY(p2wsh_policy.contains(QStringLiteral("no delayed recovery"), Qt::CaseInsensitive));
        Grab(wizard, dir, QStringLiteral("03-policy-p2wsh"));

        WalkTo(wizard, MultisigWizard::Page_Backup);
        AssertBackupPage(wizard);
        auto* backup_tabs = wizard.findChild<QTabWidget*>("backupTabs");
        QVERIFY(backup_tabs);
        QCOMPARE(backup_tabs->currentIndex(), 0);
        QVERIFY(backup_tabs->tabText(0).contains(QStringLiteral("JSON")));
        Grab(wizard, dir, QStringLiteral("04-backup"));
        auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
        QVERIFY(ack);
        ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        auto* address = wizard.findChild<QLineEdit*>("verifyAddressEdit");
        auto* qr = wizard.findChild<QRImageWidget*>("verifyQr");
        auto* devices = wizard.findChild<QListWidget*>("verifyDeviceList");
        auto* air = wizard.findChild<QCheckBox*>("airgapVerifyCheck");
        QVERIFY(address);
        QVERIFY(qr);
        QVERIFY(devices);
        QVERIFY(air);
        QVERIFY(!address->text().isEmpty());
        QVERIFY(qr->isVisible());
        QVERIFY(GUIUtil::HasPixmap(qr));
        QCOMPARE(devices->count(), 0);
        QVERIFY(air->isVisible());
        QVERIFY(!air->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        Grab(wizard, dir, QStringLiteral("05-verify"));
        air->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
        const QString ordinary_done = VisibleText(*wizard.currentPage());
        QVERIFY(ordinary_done.contains(QStringLiteral("ordinary"), Qt::CaseInsensitive));
        QVERIFY(ordinary_done.contains(QStringLiteral("2 of 3")));
        QVERIFY(ordinary_done.contains(QStringLiteral("no delayed recovery"), Qt::CaseInsensitive));
        Grab(wizard, dir, QStringLiteral("06-done"));
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("ShotAbsolutePreview"));
        wizard.setIncludeLocalKey(true);
        wizard.addAirgappedKey(family_key.fpr, family_key.path, family_key.xpub, "Coldcard");
        wizard.addAirgappedKey(heir_key.fpr, heir_key.path, heir_key.xpub, "Heir");
        wizard.rebuildKeyList();
        wizard.setNRequired(1);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.setFallbackOlder(std::nullopt);
        wizard.setFallbackAfter(840000);
        ShowSized(wizard);
        WalkTo(wizard, MultisigWizard::Page_Template);
        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
        wizard.applyTemplate();
        WalkTo(wizard, MultisigWizard::Page_Threshold);
        auto* delay_kind = wizard.findChild<QComboBox*>("delayKindCombo");
        auto* older = wizard.findChild<QSpinBox*>("fallbackOlderSpin");
        auto* after = wizard.findChild<QSpinBox*>("fallbackAfterSpin");
        auto* req = wizard.findChild<QSpinBox*>("nrequiredSpin");
        QVERIFY(delay_kind);
        QVERIFY(older);
        QVERIFY(after);
        QVERIFY(req);
        QCOMPARE(delay_kind->currentData().toInt(), 1);
        QVERIFY(!older->isVisible());
        QVERIFY(after->isVisible());
        QCOMPARE(after->value(), 840000);
        QCOMPARE(req->value(), 1);
        QVERIFY(!wizard.fallbackOlder());
        QVERIFY(wizard.fallbackAfter());
        QCOMPARE(*wizard.fallbackAfter(), 840000u);
        Grab(wizard, dir, QStringLiteral("03c-policy-after"));
        wizard.close();
    }

    hwi::MockRegistration mock{hwi::MakeMockMasterFromHex(), ChainType::REGTEST};
    const AirKey mixed_air = MakeAirKey();

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("ShotMixedVault"));
        wizard.setIncludeLocalKey(true);
        wizard.addAirgappedKey(mixed_air.fpr, mixed_air.path, mixed_air.xpub, "Coldcard");
        wizard.addHardwareKey(mock.Fingerprint(), "Mock Trezor");
        wizard.rebuildKeyList();
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.setFallbackOlder(144);
        ShowSized(wizard);
        WalkTo(wizard, MultisigWizard::Page_Template);
        wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
        wizard.applyTemplate();
        WalkTo(wizard, MultisigWizard::Page_Setup);
        auto* type = wizard.findChild<QComboBox*>("scriptTypeCombo");
        QVERIFY(type);
        const int vault_idx = OutputTypeIndex(*type, OutputType::BECH32M);
        QVERIFY(vault_idx >= 0);
        type->setCurrentIndex(vault_idx);
        wizard.next();
        WalkTo(wizard, MultisigWizard::Page_Threshold);
        auto* delay = wizard.findChild<QSpinBox*>("fallbackOlderSpin");
        auto* delay_kind = wizard.findChild<QComboBox*>("delayKindCombo");
        auto* after = wizard.findChild<QSpinBox*>("fallbackAfterSpin");
        QVERIFY(delay);
        QVERIFY(delay_kind);
        QVERIFY(after);
        delay->setValue(144);
        QApplication::processEvents();
        QCOMPARE(delay_kind->currentData().toInt(), 0);
        QVERIFY(delay->isVisible());
        QVERIFY(!after->isVisible());
        QVERIFY(wizard.fallbackOlder());
        QCOMPARE(*wizard.fallbackOlder(), 144u);
        Grab(wizard, dir, QStringLiteral("03b-policy-taproot"));
        WalkTo(wizard, MultisigWizard::Page_Backup);
        AssertBackupPage(wizard, 144u);
        auto* backup_tabs = wizard.findChild<QTabWidget*>("backupTabs");
        auto* human_transcript = wizard.findChild<QPlainTextEdit*>("humanTranscriptEdit");
        QVERIFY(backup_tabs);
        QVERIFY(human_transcript);
        backup_tabs->setCurrentIndex(1);
        QApplication::processEvents();
        QCOMPARE(backup_tabs->currentIndex(), 1);
        QVERIFY(backup_tabs->tabText(1).contains(QStringLiteral("transcript"), Qt::CaseInsensitive));
        QVERIFY(human_transcript->toPlainText().contains(QStringLiteral("Scrooge vault")));
        Grab(wizard, dir, QStringLiteral("04b-backup-taproot"));
        auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
        QVERIFY(ack);
        ack->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        auto* devices = wizard.findChild<QListWidget*>("verifyDeviceList");
        auto* qr = wizard.findChild<QRImageWidget*>("verifyQr");
        auto* show = wizard.findChild<QPushButton*>("showOnDeviceButton");
        auto* status = wizard.findChild<QLabel*>("verifyStatusLabel");
        auto* air = wizard.findChild<QCheckBox*>("airgapVerifyCheck");
        QVERIFY(devices);
        QVERIFY(qr);
        QVERIFY(show);
        QVERIFY(status);
        QVERIFY(air);
        QCOMPARE(devices->count(), 1);
        QVERIFY(qr->isVisible());
        QVERIFY(GUIUtil::HasPixmap(qr));
        QVERIFY(!(devices->item(0)->flags() & Qt::ItemIsUserCheckable));
        QVERIFY(!devices->item(0)->text().contains(QStringLiteral("verified"), Qt::CaseInsensitive));
        QVERIFY(air->isVisible());
        QVERIFY(!air->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        air->setChecked(true);
        QApplication::processEvents();
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        air->setChecked(false);
        devices->setCurrentRow(0);
        show->click();
        QApplication::processEvents();
        QVERIFY(devices->item(0)->text().contains(QStringLiteral("verified"), Qt::CaseInsensitive));
        QVERIFY(status->text().contains(QStringLiteral("same address"), Qt::CaseInsensitive));
        QVERIFY(!air->isChecked());
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        Grab(wizard, dir, QStringLiteral("05b-verify-hardware"));
        air->setChecked(true);
        QApplication::processEvents();
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
        const QString vault_done = VisibleText(*wizard.currentPage());
        QVERIFY(vault_done.contains(QStringLiteral("all 3 active keys"), Qt::CaseInsensitive));
        QVERIFY(vault_done.contains(QStringLiteral("2 of 3")));
        Grab(wizard, dir, QStringLiteral("06b-done-taproot"));
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("ShotOperationalVault"));
        wizard.setIncludeLocalKey(true);
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
        QVERIFY(!!dest);
        const CScript spk = GetScriptForDestination(*dest);
        CMutableTransaction fund = test.CreateValidMempoolTransaction(
            test.m_coinbase_txns.front(), 0, /*input_height=*/1, test.coinbaseKey, spk, 10 * COIN, /*submit=*/false);
        test.CreateAndProcessBlock({fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
        test.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        model->pollBalanceChanged();

        OverviewPage overview(style.get());
        overview.setClientModel(&client);
        overview.setWalletModel(model);
        const auto balances = model->wallet().getBalances();
        QVERIFY(balances.is_vault);
        QCOMPARE(balances.vault_awaiting, 0);
        overview.setBalance(balances);
        overview.resize(780, 560);
        overview.show();
        QApplication::processEvents();
        auto* recoverable = overview.findChild<QLabel*>("labelVaultRecoverable");
        auto* awaiting = overview.findChild<QLabel*>("labelVaultAwaiting");
        auto* awaiting_text = overview.findChild<QLabel*>("labelVaultAwaitingText");
        auto* note = overview.findChild<QLabel*>("labelVaultPathNote");
        QVERIFY(recoverable);
        QVERIFY(awaiting);
        QVERIFY(awaiting_text);
        QVERIFY(note);
        QVERIFY(recoverable->isVisible());
        QVERIFY(awaiting->isHidden());
        QVERIFY(note->text().contains(QStringLiteral("same bitcoin"), Qt::CaseInsensitive));
        QVERIFY(note->text().contains(QStringLiteral("not extra"), Qt::CaseInsensitive));

        auto earliest = balances;
        earliest.vault_awaiting = COIN;
        earliest.vault_blocks_remaining = 1;
        overview.setBalance(earliest);
        QApplication::processEvents();
        QVERIFY(awaiting->isVisible());
        QVERIFY(awaiting->text().contains(QStringLiteral("1 block")));
        QVERIFY(!awaiting->text().contains(QStringLiteral("1 blocks")));
        const QString maturity_copy = awaiting_text->text() + QLatin1Char(' ') + awaiting_text->toolTip() +
                                      QLatin1Char(' ') + awaiting->text() + QLatin1Char(' ') + note->text();
        QVERIFY(maturity_copy.contains(QStringLiteral("earliest"), Qt::CaseInsensitive));
        QVERIFY(maturity_copy.contains(QStringLiteral("each coin"), Qt::CaseInsensitive) ||
                maturity_copy.contains(QStringLiteral("per coin"), Qt::CaseInsensitive));
        overview.setBalance(balances);
        QApplication::processEvents();
        Grab(overview, dir, QStringLiteral("07-overview-vault"));

        SendCoinsDialog send(style.get());
        send.setClientModel(&client);
        send.setModel(model);
        send.resize(780, 620);
        send.show();
        QApplication::processEvents();
        auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
        auto* fee = send.findChild<QWidget*>("frameFee");
        auto* balance_name = send.findChild<QLabel*>("labelBalanceName");
        QVERIFY(recovery);
        QVERIFY(fee);
        QVERIFY(balance_name);
        QVERIFY(recovery->isVisible());
        QVERIFY(!recovery->isChecked());
        QVERIFY(recovery->text().contains(QStringLiteral("1 block")));
        QVERIFY(!recovery->text().contains(QStringLiteral("1 blocks")));
        QVERIFY(recovery->mapTo(&send, QPoint{}).y() < fee->mapTo(&send, QPoint{}).y());
        QVERIFY(balance_name->text().contains(QStringLiteral("Spendable now")));
        Grab(send, dir, QStringLiteral("08-send-vault"));

        recovery->setChecked(true);
        QApplication::processEvents();
        QVERIFY(recovery->isChecked());
        QVERIFY(balance_name->text().contains(QStringLiteral("Recoverable now")));
        const QString recovery_copy = VisibleText(send);
        QVERIFY(recovery_copy.contains(QStringLiteral("same"), Qt::CaseInsensitive));
        QVERIFY(recovery_copy.contains(QStringLiteral("coin"), Qt::CaseInsensitive) ||
                recovery_copy.contains(QStringLiteral("bitcoin"), Qt::CaseInsensitive));
        Grab(send, dir, QStringLiteral("08b-send-recovery"));

        recovery->setChecked(false);
        model->wallet().setLostSigner(mock.Fingerprint(), true);
        model->updateTransaction();
        model->pollBalanceChanged();
        QApplication::processEvents();
        auto* open_send_button = send.findChild<QPushButton*>("sendButton");
        auto* open_lost = send.findChild<QLabel*>("vaultLostSignerLabel");
        QVERIFY(open_send_button);
        QVERIFY(open_lost);
        QVERIFY(!open_send_button->isEnabled());
        QVERIFY(open_lost->isVisible());

        SendCoinsDialog send_lost(style.get());
        send_lost.setClientModel(&client);
        send_lost.setModel(model);
        send_lost.resize(780, 620);
        send_lost.show();
        QApplication::processEvents();
        auto* lost_recovery = send_lost.findChild<QCheckBox*>("vaultRecoveryCheck");
        auto* lost_name = send_lost.findChild<QLabel*>("labelBalanceName");
        auto* lost_balance = send_lost.findChild<QLabel*>("labelBalance");
        auto* lost_button = send_lost.findChild<QPushButton*>("sendButton");
        auto* lost_banner = send_lost.findChild<QLabel*>("vaultLostSignerLabel");
        QVERIFY(lost_recovery);
        QVERIFY(lost_name);
        QVERIFY(lost_balance);
        QVERIFY(lost_button);
        QVERIFY(lost_banner);
        QVERIFY(!lost_recovery->isChecked());
        QVERIFY(lost_name->text().contains(QStringLiteral("Spendable now")));
        QVERIFY(lost_balance->text().startsWith(QStringLiteral("0.00000000")));
        QVERIFY(lost_button->text().contains(QStringLiteral("Sign on device")));
        QVERIFY(!lost_button->isEnabled());
        QVERIFY(lost_banner->isVisible());
        QVERIFY(lost_banner->text().contains(QStringLiteral("mock"), Qt::CaseInsensitive));
        QVERIFY(lost_banner->text().contains(QString::fromStdString(mock.Fingerprint()), Qt::CaseInsensitive));
        Grab(send_lost, dir, QStringLiteral("08c-send-lost-signer"));
        wizard.close();
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
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Maximum);
    wizard.applyTemplate();
    QVERIFY(!wizard.fallbackOlder());
    QVERIFY(!wizard.preferNMinus1());
    QCOMPARE(wizard.outputType(), OutputType::BECH32M);

    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::HardwareCoordinator);
    wizard.applyTemplate();
    QVERIFY(!wizard.includeLocalKey());
    QCOMPARE(*wizard.fallbackOlder(), MultisigWizard::kDefaultVaultDelay);

    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Inheritance);
    wizard.applyTemplate();
    QCOMPARE(*wizard.fallbackOlder(), MultisigWizard::kDefaultVaultDelay);

    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::RecoverOneLost);
    wizard.applyTemplate();
    QVERIFY(wizard.includeLocalKey());
    QVERIFY(wizard.preferNMinus1());
    QCOMPARE(*wizard.fallbackOlder(), MultisigWizard::kDefaultVaultDelay);

    wizard.setNRequired(1);
    wizard.setVaultTemplate(MultisigWizard::VaultTemplate::Custom);
    wizard.applyTemplate();
    QVERIFY(!wizard.preferNMinus1());
    QCOMPARE(wizard.nrequired(), 1);

    wizard.setIncludeLocalKey(true);
    wizard.addAirgappedKey("aabbccdd", "m/48h/1h/0h/3h", "tpubDummyA", "cold-a");
    wizard.addAirgappedKey("11223344", "m/48h/1h/0h/3h", "tpubDummyB", "cold-b", /*recovery_only=*/true);
    wizard.rebuildKeyList();
    QCOMPARE(static_cast<int>(wizard.keys().size()), 3);
    QVERIFY(wizard.keys().back().recovery_only);
    wizard.close();

    MultisigWizard role_templates(m_node, /*wallet_controller=*/nullptr);
    role_templates.setIncludeLocalKey(true);
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
    wizard.setWalletName(QStringLiteral("FamilyVault"));
    wizard.setIncludeLocalKey(true);
    wizard.addHardwareKey(mock.Fingerprint(), "Mock Trezor");
    wizard.rebuildKeyList();
    QCOMPARE(static_cast<int>(wizard.keys().size()), 2);
    wizard.setNRequired(1);
    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(1);

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
    auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
    QVERIFY(recovery);
    QVERIFY(!recovery->isHidden());
    QVERIFY(recovery->text().contains(QStringLiteral("1 block")));
    QVERIFY(!recovery->text().contains(QStringLiteral("1 blocks")));
    QVERIFY(!recovery->isChecked());
    recovery->setChecked(true);
    QApplication::processEvents();
    QVERIFY(send.getCoinControl()->m_nSequence == 1u);
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
        wizard.setIncludeLocalKey(true);
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
        wizard.setIncludeLocalKey(true);
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
        wizard.setIncludeLocalKey(true);
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
        wizard.setIncludeLocalKey(true);
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
        auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
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
        invalid.setIncludeLocalKey(true);
        invalid.addAirgappedKey(good_key.fpr, good_key.path, "not-an-xpub", "bad paste");
        invalid.rebuildKeyList();
        invalid.setNRequired(1);
        invalid.setOutputType(OutputType::BECH32M);
        invalid.setFallbackOlder(1);
        QVERIFY(!invalid.createWallet());
        QVERIFY(invalid.createError().contains(QStringLiteral("xpub"), Qt::CaseInsensitive));

        MultisigWizard corrected(m_node, &controller);
        corrected.setWalletName(QStringLiteral("PreflightRetry"));
        corrected.setIncludeLocalKey(true);
        corrected.addAirgappedKey(good_key.fpr, good_key.path, good_key.xpub, "corrected paste");
        corrected.rebuildKeyList();
        corrected.setNRequired(1);
        corrected.setOutputType(OutputType::BECH32M);
        corrected.setFallbackOlder(1);
        QVERIFY2(corrected.createWallet(), qPrintable(corrected.createError()));
    }

    {
        const AirKey a = MakeAirKey();
        const AirKey b = MakeAirKey();
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("RoleToggleRegression"));
        wizard.setIncludeLocalKey(true);
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
        wizard.setIncludeLocalKey(true);
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
        wizard.setIncludeLocalKey(true);
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
        auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
        QVERIFY(recovery);
        QVERIFY(recovery->isHidden());
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("Delay144"));
        wizard.setIncludeLocalKey(true);
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
        auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
        QVERIFY(recovery);
        QVERIFY(!recovery->isHidden());
        QVERIFY(recovery->text().contains(QStringLiteral("144")));
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
        auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
        QVERIFY(recovery);
        QVERIFY(!recovery->isHidden());
        QVERIFY(recovery->text().contains(QStringLiteral("1 block")));
        QVERIFY(!recovery->text().contains(QStringLiteral("1 blocks")));
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, &controller);
        wizard.setWalletName(QStringLiteral("AfterHeight"));
        wizard.setIncludeLocalKey(true);
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
        auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
        QVERIFY(recovery);
        QVERIFY(!recovery->isHidden());
        QVERIFY(recovery->text().contains(QStringLiteral("500")));
        QVERIFY(recovery->text().contains(QStringLiteral("height")));
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
    wizard.setIncludeLocalKey(true);
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
        auto* rec = overview.findChild<QLabel*>("labelVaultRecoverable");
        auto* wait = overview.findChild<QLabel*>("labelVaultAwaiting");
        auto* note = overview.findChild<QLabel*>("labelVaultPathNote");
        QVERIFY(rec);
        QVERIFY(wait);
        QVERIFY(note);
        QVERIFY(!rec->isHidden());
        QVERIFY(!note->isHidden());
        QVERIFY(note->text().contains(QStringLiteral("same bitcoin"), Qt::CaseInsensitive));
        QVERIFY(note->text().contains(QStringLiteral("not extra"), Qt::CaseInsensitive));
        if (bals.vault_awaiting == 0) QVERIFY(wait->isHidden());
        else QVERIFY(!wait->isHidden());
        QVERIFY(bals.vault_immediate > 0 || bals.vault_recoverable > 0);
        auto* bal_text = overview.findChild<QLabel*>("labelBalanceText");
        QVERIFY(bal_text);
        QVERIFY(bal_text->text().contains(QStringLiteral("Spendable")));
    }

    SendCoinsDialog send(style.get());
    send.setClientModel(&client);
    send.setModel(model);
    auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
    QVERIFY(recovery);
    QVERIFY(!recovery->isHidden());
    QVERIFY(recovery->text().contains(QStringLiteral("1 block")));
    QVERIFY(!recovery->text().contains(QStringLiteral("1 blocks")));
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
    auto* rec_lost = send_lost.findChild<QCheckBox*>("vaultRecoveryCheck");
    QVERIFY(rec_lost);
    QVERIFY(!rec_lost->isChecked());
    rec_lost->setChecked(true);
    QApplication::processEvents();
    QVERIFY(send_btn->isEnabled());

    // Restoring the signer must return this already-open dialog to the
    // immediate path without silently retaining the recovery opt-in.
    rec_lost->setChecked(false);
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
        relative.setIncludeLocalKey(true);
        relative.addHardwareKey(mock.Fingerprint(), "Mock Trezor");
        relative.rebuildKeyList();
        relative.setNRequired(2);
        relative.setOutputType(OutputType::BECH32M);
        relative.setFallbackOlder(2);
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
        auto* awaiting = relative_overview.findChild<QLabel*>("labelVaultAwaiting");
        auto* recoverable = relative_overview.findChild<QLabel*>("labelVaultRecoverable");
        QVERIFY(awaiting);
        QVERIFY(recoverable);
        QVERIFY(!awaiting->isHidden());
        QVERIFY(awaiting->text().contains(QStringLiteral("1 block")));
        QVERIFY(!recoverable->text().isEmpty());

        SendCoinsDialog relative_send(style.get());
        relative_send.setClientModel(&client);
        relative_send.setModel(relative_model);
        auto* relative_recovery = relative_send.findChild<QCheckBox*>("vaultRecoveryCheck");
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
        QVERIFY(!awaiting->isHidden());
        QVERIFY(awaiting->text().contains(QStringLiteral("1 block")));

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
        absolute.setIncludeLocalKey(true);
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
        auto* absolute_recovery = absolute_send.findChild<QCheckBox*>("vaultRecoveryCheck");
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
    wizard.setIncludeLocalKey(true);
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

    auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
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
    auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
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
    auto* recovery = send.findChild<QCheckBox*>("vaultRecoveryCheck");
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
