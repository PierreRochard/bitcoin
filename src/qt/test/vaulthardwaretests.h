// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_TEST_VAULTHARDWARETESTS_H
#define BITCOIN_QT_TEST_VAULTHARDWARETESTS_H

#include <QObject>
#include <QTest>

namespace interfaces {
class Node;
} // namespace interfaces

class VaultHardwareTests : public QObject
{
public:
    explicit VaultHardwareTests(interfaces::Node& node) : m_node(node) {}

    Q_OBJECT

private Q_SLOTS:
    void fixedNativeDiscoveryWorksWithoutSignerOption();
    void fixedDiscoveryFailuresFailClosed();
    void fixedDiscoveryBoundaryChangesFailClosed();
    void hardwareOnlyRestoreReconcilesExactDevicesAcrossReload();

private:
    interfaces::Node& m_node;
};

#endif // BITCOIN_QT_TEST_VAULTHARDWARETESTS_H
