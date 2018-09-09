// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <test/test_bitcoin.h>
#include <wallet/wallet.h>
#include <wallet/init.cpp>


BOOST_FIXTURE_TEST_SUITE(init_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(walletinit_verify_disablewallet_true)
{
    gArgs.ForceSetArg("-disablewallet", "1");
    gArgs.ForceSetArg("-walletdir", "pathdoesnotexist");
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == true);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_disablewallet_false)
{
    gArgs.ForceSetArg("-disablewallet", "0");
    gArgs.ForceSetArg("-walletdir", "pathdoesnotexist");
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_disablewallet_default)
{
    gArgs.ForceSetArg("-walletdir", "pathdoesnotexist");
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == DEFAULT_DISABLE_WALLET);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_walletdir_does_not_exist)
{
    gArgs.ForceSetArg("-walletdir", "pathdoesnotexist");
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_walletdir_is_not_directory)
{
    fs::path data_dir = SetDataDir("verify_walletdir");
    gArgs.ForceSetArg("-walletdir", "pathdoesnotexist");
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == false);
}

/** If a user passes in a path with a trailing separator as the walletdir, multiple BerkeleyEnvironments
 * may be created in the same directory which can lead to data corruption.
 */
//BOOST_AUTO_TEST_CASE(walletdir_trailing_separator)
//{
//    fs::path expected_wallet_dir = SetDataDir("get_wallet_dir");
//    std::string trailing_separators;
//    for (int i = 0; i < 4; ++i) {
//        trailing_separators += fs::path::preferred_separator;
//        gArgs.ForceSetArg("-walletdir", (expected_wallet_dir / fs::path::preferred_separator).string());
//        fs::path wallet_dir = GetWalletDir();
//        BOOST_CHECK(wallet_dir == expected_wallet_dir);
//    }
//}
//
//BOOST_AUTO_TEST_CASE(walletdir_multiple_trailing_separators)
//{
//    fs::path expected_wallet_dir = SetDataDir("get_wallet_dir");
//    std::string trailing_separators;
//    for (int i = 0; i < 4; ++i) {
//        trailing_separators += fs::path::preferred_separator;
//        gArgs.ForceSetArg("-walletdir", (expected_wallet_dir / trailing_separators).string());
//        fs::path wallet_dir = GetWalletDir();
//        BOOST_CHECK(wallet_dir == expected_wallet_dir);
//    }
//}


BOOST_AUTO_TEST_SUITE_END()
