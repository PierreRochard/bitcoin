// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/multisigwizardtests.h>

#include <outputtype.h>
#include <qt/multisigwizard.h>
#include <qt/test/util.h>
#include <wallet/multisig.h>

#include <QCheckBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QTest>

void MultisigWizardTests::wizardTests()
{
    MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
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
