// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TEST_INIT_TEST_FIXTURE_H
#define BITCOIN_WALLET_TEST_INIT_TEST_FIXTURE_H

#include <test/test_bitcoin.h>


struct InitTestingSetup: public BasicTestingSetup {
    explicit InitTestingSetup(const std::string& chainName = CBaseChainParams::MAIN);
    void SetWalletDir(const fs::path& walletdir_path);

    fs::path m_datadir;
    std::map<std::string, fs::path> m_walletdir_path_cases;
};

#endif // BITCOIN_WALLET_TEST_INIT_TEST_FIXTURE_H
