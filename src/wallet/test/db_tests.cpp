// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <sync.h>
#include <test/test_bitcoin.h>
#include <wallet/db.h>


BOOST_FIXTURE_TEST_SUITE(db_tests, TestingSetup)

/** If a user passes in a path with a trailing separator as the walletdir, multiple BerkeleyEnvironments
 * may be created in the same directory which can lead to data corruption.
 */
BOOST_AUTO_TEST_CASE(get_wallet_env_trailing_slash)
{
    const char kPathSeparator =
    #ifdef WIN32
            '\\';
    #else
            '/';
    #endif

    fs::path data_dir = SetDataDir("get_wallet_env");
    fs::path wallet_dir = data_dir / "wallets";

    std::vector<fs::path> wallet_test_paths;
    std::string trailing_slashes;
    for (int i = 0; i < 4; ++i ) {
        trailing_slashes += kPathSeparator;
        wallet_test_paths.push_back(wallet_dir / trailing_slashes);
    }

    for (auto& wallet_test_path: wallet_test_paths) {
        std::string database_filename;
        BerkeleyEnvironment* env = GetWalletEnv(wallet_test_path, database_filename);
        BOOST_CHECK(env->Directory() == wallet_dir);
    }
}

BOOST_AUTO_TEST_SUITE_END()
