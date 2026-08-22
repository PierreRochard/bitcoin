// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_MULTISIGWIZARDTESTS_H
#define BITCOIN_QT_TEST_MULTISIGWIZARDTESTS_H

#include <QObject>
#include <QTest>

namespace interfaces {
class Node;
} // namespace interfaces

class MultisigWizardTests : public QObject
{
public:
    explicit MultisigWizardTests(interfaces::Node& node) : m_node(node) {}
    interfaces::Node& m_node;

    Q_OBJECT

private Q_SLOTS:
    void wizardTests();
    void grabPages();
    void wizardTemplates();
    void createWalletWithController();
    void wizardEdges();
    void vaultGuiSend();
    void vaultGuiMissingKey();
    void vaultGuiAirgapPsbt();
    void vaultGuiHardwareOnly();
};

#endif // BITCOIN_QT_TEST_MULTISIGWIZARDTESTS_H
