// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/coldcard.h>
#include <hwi/hwi.h>
#include <hwi/ledger.h>
#include <hwi/transport.h>
#include <hwi/trezor.h>

#include <key.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <string>

BOOST_FIXTURE_TEST_SUITE(hwi_emu_tests, BasicTestingSetup)

namespace {

bool RequireEnv(const char* name)
{
    const char* v = std::getenv(name);
    return v && v[0] != '\0' && v[0] != '0';
}

#define HWI_EMU_REQUIRE(available, env, msg)                                              \
    do {                                                                                  \
        if (!(available)) {                                                               \
            BOOST_REQUIRE_MESSAGE(!RequireEnv(env) && !RequireEnv("HWI_REQUIRE_EMULATORS"), \
                                  msg);                                                   \
            BOOST_TEST_MESSAGE(msg);                                                      \
            return;                                                                       \
        }                                                                                 \
    } while (0)

const std::string TREZOR_TEST_MNEMONIC =
    "alcohol woman abuse must during monitor noble actual mixed trade anger aisle";
const std::string TREZOR_TEST_FPR = "95d8f670";
const std::string LEDGER_SPECULOS_FPR = "f5acc2fd";
const std::string COLDCARD_SIM_FPR = "0f056943";

} // namespace

BOOST_AUTO_TEST_CASE(path_parsing)
{
    BOOST_CHECK(hwi::IsUdpPath("udp:127.0.0.1:21324"));
    BOOST_CHECK(hwi::IsTcpPath("tcp:127.0.0.1:9999"));
    BOOST_CHECK(hwi::IsUnixSocketPath("/tmp/ckcc-simulator.sock"));
    BOOST_CHECK(hwi::IsUnixSocketPath("unix:/tmp/ckcc-simulator.sock"));
    BOOST_CHECK(!hwi::IsUdpPath("tcp:127.0.0.1:9999"));
    BOOST_CHECK(!hwi::IsTcpPath("/dev/hidraw0"));
    BOOST_CHECK(!hwi::IsUnixSocketPath("udp:127.0.0.1:21324"));

    auto udp = hwi::ParseUdpPath("udp:127.0.0.1:21324");
    BOOST_REQUIRE(udp);
    BOOST_CHECK_EQUAL(udp->host, "127.0.0.1");
    BOOST_CHECK_EQUAL(udp->port, 21324);

    auto tcp = hwi::ParseTcpPath("tcp:10.0.0.2:1234");
    BOOST_REQUIRE(tcp);
    BOOST_CHECK_EQUAL(tcp->host, "10.0.0.2");
    BOOST_CHECK_EQUAL(tcp->port, 1234);

    BOOST_CHECK_EQUAL(hwi::UnixSocketPath("unix:/tmp/ckcc-simulator.sock"), "/tmp/ckcc-simulator.sock");
    BOOST_CHECK(!hwi::ParseUdpPath("not-udp"));
    BOOST_CHECK(!hwi::ParseTcpPath("udp:127.0.0.1:21324"));
}

BOOST_AUTO_TEST_CASE(missing_emulators_fail_fast)
{
    BOOST_CHECK(!hwi::TrezorUdpPing("127.0.0.1", 1, /*timeout_ms=*/50));
    BOOST_CHECK(!hwi::TrezorUdpAvailable("udp:127.0.0.1:1"));
    BOOST_CHECK(!hwi::LedgerTcpAvailable("tcp:127.0.0.1:1"));
    BOOST_CHECK(!hwi::ColdcardSimulatorAvailable("/tmp/ckcc-no-such-simulator.sock"));
    BOOST_CHECK_NO_THROW(hwi::Enumerate());
}

BOOST_AUTO_TEST_CASE(trezor_udp_enumerate_and_xpub)
{
    const std::string path = hwi::DefaultTrezorUdpPath();
    HWI_EMU_REQUIRE(!path.empty() && hwi::TrezorUdpAvailable(path), "HWI_REQUIRE_TREZOR",
                    "skipping: no Trezor UDP emulator at " + path);

    BOOST_CHECK_NO_THROW(hwi::TrezorEmulatorLoadMnemonic(path, TREZOR_TEST_MNEMONIC));

    hwi::DeviceInfo info;
    info.type = "trezor";
    info.path = path;
    auto client = hwi::ConnectTrezor(info);
    BOOST_REQUIRE(client);
    BOOST_CHECK_EQUAL(client->Type(), "trezor");
    BOOST_CHECK_EQUAL(hwi::FingerprintHex(client->GetMasterFingerprint()), TREZOR_TEST_FPR);

    const CExtPubKey xpub{client->GetPubkeyAtPath("m/84h/1h/0h")};
    BOOST_CHECK(xpub.pubkey.IsValid());
    client->Close();

    bool found = false;
    for (const hwi::DeviceInfo& d : hwi::EnumerateTrezor()) {
        if (d.path == path && d.fingerprint == TREZOR_TEST_FPR) found = true;
    }
    BOOST_CHECK(found);
}

BOOST_AUTO_TEST_CASE(ledger_speculos_enumerate_and_xpub)
{
    const std::string path = hwi::DefaultLedgerTcpPath();
    HWI_EMU_REQUIRE(!path.empty() && hwi::LedgerTcpAvailable(path), "HWI_REQUIRE_LEDGER",
                    "skipping: no Speculos TCP emulator at " + path);

    hwi::DeviceInfo info;
    info.type = "ledger";
    info.path = path;
    auto client = hwi::ConnectLedger(info);
    BOOST_REQUIRE(client);
    client->SetChain(ChainType::TESTNET);
    BOOST_CHECK_EQUAL(client->Type(), "ledger");
    BOOST_CHECK_EQUAL(hwi::FingerprintHex(client->GetMasterFingerprint()), LEDGER_SPECULOS_FPR);

    const CExtPubKey xpub{client->GetPubkeyAtPath("m/84h/1h/0h")};
    BOOST_CHECK(xpub.pubkey.IsValid());
    client->Close();

    bool found = false;
    for (const hwi::DeviceInfo& d : hwi::EnumerateLedger()) {
        if (d.path == path && d.fingerprint == LEDGER_SPECULOS_FPR) found = true;
    }
    BOOST_CHECK(found);
}

BOOST_AUTO_TEST_CASE(coldcard_unix_enumerate_and_xpub)
{
    const std::string path = hwi::DefaultColdcardUnixPath();
    HWI_EMU_REQUIRE(!path.empty() && hwi::ColdcardSimulatorAvailable(path), "HWI_REQUIRE_COLDCARD",
                    "skipping: no Coldcard unix simulator at " + path);

    hwi::DeviceInfo info;
    info.type = "coldcard";
    info.path = path;
    auto client = hwi::ConnectColdcard(info);
    BOOST_REQUIRE(client);
    BOOST_CHECK_EQUAL(client->Type(), "coldcard");
    BOOST_CHECK_EQUAL(hwi::FingerprintHex(client->GetMasterFingerprint()), COLDCARD_SIM_FPR);

    const CExtPubKey xpub{client->GetPubkeyAtPath("m/84h/0h/0h")};
    BOOST_CHECK(xpub.pubkey.IsValid());
    client->Close();

    bool found = false;
    for (const hwi::DeviceInfo& d : hwi::EnumerateColdcard()) {
        if (d.path == path && d.fingerprint == COLDCARD_SIM_FPR) found = true;
    }
    BOOST_CHECK(found);
}

BOOST_AUTO_TEST_SUITE_END()
