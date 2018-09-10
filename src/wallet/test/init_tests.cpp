// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <test/test_bitcoin.h>
#include <wallet/test/init_test_fixture.h>

#include <wallet/wallet.h>
#include <wallet/init.cpp>


BOOST_FIXTURE_TEST_SUITE(init_tests, InitTestingSetup)

BOOST_AUTO_TEST_CASE(walletinit_verify_disablewallet_true)
{
    gArgs.ForceSetArg("-disablewallet", "1");
    SetWalletDir(m_walletdir_path_cases["nonexistent"]);
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == true);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_disablewallet_false)
{
    gArgs.ForceSetArg("-disablewallet", "0");
    SetWalletDir(m_walletdir_path_cases["nonexistent"]);
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_disablewallet_default)
{
    SetWalletDir(m_walletdir_path_cases["nonexistent"]);
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == DEFAULT_DISABLE_WALLET);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_walletdir_does_not_exist)
{
    SetWalletDir(m_walletdir_path_cases["nonexistent"]);
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_walletdir_is_not_directory)
{
    SetWalletDir(m_walletdir_path_cases["file"]);
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_CASE(walletinit_verify_walletdir_is_not_relative)
{
    SetWalletDir(m_walletdir_path_cases["relative"]);
    bool result = g_wallet_init_interface.Verify();
    BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_SUITE_END()
