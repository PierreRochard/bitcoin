// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <test/test_bitcoin.h>
#include <wallet/walletutil.h>


BOOST_FIXTURE_TEST_SUITE(walletutil_tests, TestingSetup)

/** If a user passes in a path with a trailing separator as the walletdir, multiple BerkeleyEnvironments
 * may be created in the same directory which can lead to data corruption.
 */
BOOST_AUTO_TEST_CASE(get_wallet_dir_trailing_separators)
{
    fs::path expected_wallet_dir = SetDataDir("get_wallet_dir");
    std::string trailing_separators;
    for (int i = 0; i < 4; ++i) {
        trailing_separators += fs::path::preferred_separator;
        gArgs.ForceSetArg("-walletdir", (expected_wallet_dir / trailing_separators).string());
        fs::path wallet_dir = GetWalletDir();
        BOOST_CHECK(wallet_dir == expected_wallet_dir);
    }
}

BOOST_AUTO_TEST_SUITE_END()
