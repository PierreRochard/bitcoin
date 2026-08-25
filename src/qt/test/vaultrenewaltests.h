// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_TEST_VAULTRENEWALTESTS_H
#define BITCOIN_QT_TEST_VAULTRENEWALTESTS_H

#include <QObject>

class VaultRenewalTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void guidedPresentation();
    void privacyPresentation();
    void adaptiveRendering();
    void reminderDecisions();
    void signerReadiness();
};

#endif // BITCOIN_QT_TEST_VAULTRENEWALTESTS_H
