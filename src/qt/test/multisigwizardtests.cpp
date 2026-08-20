// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/multisigwizardtests.h>

#include <addresstype.h>
#include <common/args.h>
#include <hwi/mock.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>
#include <qt/clientmodel.h>
#include <qt/multisigwizard.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/test/util.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/result.h>
#include <util/translation.h>
#include <wallet/multisig.h>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QLineEdit>
#include <QPalette>
#include <QPixmap>
#include <QPushButton>
#include <QSpinBox>
#include <QTest>
#include <QWizard>

namespace {
// Known-valid regtest P2WPKH from wallet_signer.py (no ECC context required).
const QString kReceiveAddress = QStringLiteral("bcrt1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th68x4f8g");

void SeedKeys(MultisigWizard& wizard, bool extra_airgap)
{
    wizard.setIncludeLocalKey(true);
    wizard.addAirgappedKey("aabbccdd", "m/48h/1h/0h/2h", "tpubDummyFamily", "Coldcard (vault)");
    if (extra_airgap) {
        wizard.addAirgappedKey("11223344", "m/48h/1h/0h/3h", "tpubDummySpare", "Spare");
    }
    wizard.rebuildKeyList();
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

void WalkTo(MultisigWizard& wizard, int page)
{
    int guard = 0;
    while (wizard.currentId() != page && guard++ < 12) {
        if (wizard.currentId() == MultisigWizard::Page_Backup) {
            auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
            QVERIFY(ack);
            ack->setChecked(true);
        }
        QVERIFY2(wizard.nextId() != -1 || wizard.currentId() == page,
                 "wizard has no next page");
        wizard.next();
    }
    QCOMPARE(wizard.currentId(), page);
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

    wizard.setOutputType(OutputType::BECH32M);
    wizard.setFallbackOlder(144);
    const QString tap = wizard.transcript();
    QVERIFY(tap.contains(QStringLiteral("bech32m")));
    QVERIFY(tap.contains(QStringLiteral("MuSig2")));
    QVERIFY(tap.contains(QStringLiteral("144")));
    QVERIFY(tap.contains(QStringLiteral("older")));

    wizard.next();
    wizard.next();
    auto* name = wizard.findChild<QLineEdit*>("walletNameEdit");
    QVERIFY(name);
    name->setText(QStringLiteral("Family"));
    QVERIFY(wizard.validateCurrentPage());
}

void MultisigWizardTests::grabPages()
{
    const QByteArray dest = qgetenv("MULTISIG_WIZARD_SHOTS");
    if (dest.isEmpty()) {
        QSKIP("Set MULTISIG_WIZARD_SHOTS to a directory to dump wizard PNGs");
    }
    const QString dir = QString::fromLocal8Bit(dest);
    QVERIFY(QDir().mkpath(dir));

    // AppTests shuts the GUI node down; later tests leave a dangling context.
    // Give this wizard a live NodeContext so device listing does not crash.
    BasicTestingSetup test{ChainType::REGTEST};
    m_node.setContext(&test.m_node);

    {
        MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
        wizard.setWalletName(QStringLiteral("Family vault"));
        SeedKeys(wizard, /*extra_airgap=*/false);
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32);
        wizard.setReceiveAddress(kReceiveAddress);
        ShowSized(wizard);
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Intro));
        Grab(wizard, dir, QStringLiteral("00-intro"));

        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Setup));
        Grab(wizard, dir, QStringLiteral("01-setup-p2wsh"));
        auto* type = wizard.findChild<QComboBox*>("scriptTypeCombo");
        QVERIFY(type);
        type->setCurrentIndex(1);
        QApplication::processEvents();
        Grab(wizard, dir, QStringLiteral("01b-setup-taproot"));
        type->setCurrentIndex(0);

        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
        Grab(wizard, dir, QStringLiteral("02-keys"));

        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Threshold));
        Grab(wizard, dir, QStringLiteral("03-policy-p2wsh"));

        WalkTo(wizard, MultisigWizard::Page_Backup);
        Grab(wizard, dir, QStringLiteral("04-backup"));
        auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
        QVERIFY(ack);
        ack->setChecked(true);
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        Grab(wizard, dir, QStringLiteral("05-verify"));
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Done));
        Grab(wizard, dir, QStringLiteral("06-done"));
        wizard.close();
    }

    {
        MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
        wizard.setWalletName(QStringLiteral("Family vault"));
        SeedKeys(wizard, /*extra_airgap=*/true);
        wizard.addHardwareKey("deadbeef", "Trezor");
        wizard.rebuildKeyList();
        wizard.setNRequired(2);
        wizard.setOutputType(OutputType::BECH32M);
        wizard.setFallbackOlder(144);
        wizard.setReceiveAddress(kReceiveAddress);
        ShowSized(wizard);
        WalkTo(wizard, MultisigWizard::Page_Setup);
        auto* type = wizard.findChild<QComboBox*>("scriptTypeCombo");
        QVERIFY(type);
        type->setCurrentIndex(1);
        wizard.next();
        WalkTo(wizard, MultisigWizard::Page_Threshold);
        auto* delay = wizard.findChild<QSpinBox*>("fallbackOlderSpin");
        QVERIFY(delay);
        delay->setValue(144);
        QApplication::processEvents();
        Grab(wizard, dir, QStringLiteral("03b-policy-taproot"));
        WalkTo(wizard, MultisigWizard::Page_Backup);
        Grab(wizard, dir, QStringLiteral("04b-backup-taproot"));
        auto* ack = wizard.findChild<QCheckBox*>("backupAckCheck");
        QVERIFY(ack);
        ack->setChecked(true);
        wizard.next();
        QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Verify));
        Grab(wizard, dir, QStringLiteral("05b-verify-hardware"));
        wizard.next();
        Grab(wizard, dir, QStringLiteral("06b-done-taproot"));
        wizard.close();
    }
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
}
