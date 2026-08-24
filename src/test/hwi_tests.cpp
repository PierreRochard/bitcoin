// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <external_signer.h>
#include <hwi/hwi.h>
#include <hwi/mock.h>
#include <key.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(hwi_tests, BasicTestingSetup)

static CExtKey MockMaster()
{
    return hwi::MakeMockMasterFromHex();
}

BOOST_AUTO_TEST_CASE(mock_enumerate_and_xpub)
{
    BOOST_CHECK(hwi::EnumerateMockDevices().empty());

    hwi::MockRegistration mock{MockMaster()};
    const std::vector<hwi::DeviceInfo> mocks{hwi::EnumerateMockDevices()};
    BOOST_REQUIRE_EQUAL(mocks.size(), 1U);
    BOOST_CHECK_EQUAL(mocks[0].type, "mock");
    BOOST_CHECK_EQUAL(mocks[0].fingerprint, mock.Fingerprint());
    BOOST_CHECK_EQUAL(mock.Fingerprint().size(), 8U);

    bool found = false;
    for (const hwi::DeviceInfo& d : hwi::Enumerate()) {
        if (d.type == "mock" && d.fingerprint == mock.Fingerprint()) found = true;
    }
    BOOST_CHECK(found);

    std::unique_ptr<hwi::HardwareWalletClient> client = mock.Connect();
    BOOST_REQUIRE(client);
    BOOST_CHECK_EQUAL(hwi::FingerprintHex(client->GetMasterFingerprint()), mock.Fingerprint());

    const CExtPubKey xpub{client->GetPubkeyAtPath("m/84h/0h/0h")};
    BOOST_CHECK(xpub.pubkey.IsValid());
    BOOST_CHECK_EQUAL(EncodeExtPubKey(xpub), EncodeExtPubKey(DeriveExtKey(MockMaster(), std::vector<uint32_t>{
                                                                                           84 | BIP32_HARDENED_FLAG,
                                                                                           BIP32_HARDENED_FLAG,
                                                                                           BIP32_HARDENED_FLAG,
                                                                                       })
                                                                ->first.Neuter()));
}

BOOST_AUTO_TEST_CASE(usb_enumerate_suppress_hides_hardware)
{
    BOOST_CHECK(!hwi::UsbEnumerateSuppressed());
    {
        hwi::UsbEnumerateSuppress outer;
        BOOST_CHECK(hwi::UsbEnumerateSuppressed());
        {
            hwi::UsbEnumerateSuppress inner;
            BOOST_CHECK(hwi::UsbEnumerateSuppressed());
        }
        BOOST_CHECK(hwi::UsbEnumerateSuppressed());
        for (const hwi::DeviceInfo& d : hwi::Enumerate()) {
            BOOST_CHECK_EQUAL(d.type, "mock");
        }
        hwi::MockRegistration mock{MockMaster()};
        const auto devices = hwi::Enumerate();
        BOOST_REQUIRE_EQUAL(devices.size(), 1U);
        BOOST_CHECK_EQUAL(devices[0].type, "mock");
        BOOST_CHECK_EQUAL(devices[0].fingerprint, mock.Fingerprint());
    }
    BOOST_CHECK(!hwi::UsbEnumerateSuppressed());
}

BOOST_AUTO_TEST_CASE(mock_getdescriptors)
{
    hwi::MockRegistration mock{MockMaster()};
    std::unique_ptr<hwi::HardwareWalletClient> client = mock.Connect();
    const hwi::DescriptorSets descs{hwi::GetDescriptors(*client, /*account=*/0)};
    BOOST_REQUIRE_EQUAL(descs.receive.size(), 4U);
    BOOST_REQUIRE_EQUAL(descs.internal.size(), 4U);

    for (const std::string& desc : descs.receive) {
        BOOST_CHECK(desc.find(mock.Fingerprint()) != std::string::npos);
        FlatSigningProvider provider;
        std::string error;
        auto parsed = Parse(desc, provider, error, /*require_checksum=*/true);
        BOOST_CHECK_MESSAGE(!parsed.empty(), error);
        BOOST_REQUIRE(!parsed.empty());
        std::vector<CScript> scripts;
        FlatSigningProvider out;
        BOOST_CHECK(parsed.at(0)->Expand(/*pos=*/0, provider, scripts, out));
        BOOST_CHECK(!scripts.empty());
    }
}

BOOST_AUTO_TEST_CASE(mock_displayaddress)
{
    hwi::MockRegistration mock{MockMaster()};
    std::unique_ptr<hwi::HardwareWalletClient> client = mock.Connect();

    const std::string path{"m/84h/0h/0h/0/0"};
    const std::string address{client->DisplaySinglesigAddress(path, OutputType::BECH32)};
    const CExtPubKey xpub{client->GetPubkeyAtPath(path)};
    BOOST_CHECK_EQUAL(address, EncodeDestination(WitnessV0KeyHash(xpub.pubkey)));

    const hwi::DescriptorSets descs{hwi::GetDescriptors(*client, /*account=*/0)};
    std::string bech32_receive;
    for (const std::string& desc : descs.receive) {
        if (desc.starts_with("wpkh(")) bech32_receive = desc;
    }
    BOOST_REQUIRE(!bech32_receive.empty());
    BOOST_CHECK_EQUAL(hwi::DisplayAddress(*client, bech32_receive), address);
}

BOOST_AUTO_TEST_CASE(mock_signmessage)
{
    hwi::MockRegistration mock{MockMaster()};
    std::unique_ptr<hwi::HardwareWalletClient> client = mock.Connect();
    const std::string signature{client->SignMessage("hello hwi", "m/84h/0h/0h/0/0")};
    BOOST_CHECK(!signature.empty());
}

BOOST_AUTO_TEST_CASE(mock_signtx)
{
    const CExtKey master{MockMaster()};
    hwi::MockRegistration mock{master};
    std::unique_ptr<hwi::HardwareWalletClient> client = mock.Connect();

    std::vector<uint32_t> path;
    BOOST_REQUIRE(ParseHDKeypath("m/84h/0h/0h/0/0", path));
    auto derived = DeriveExtKey(master, path);
    BOOST_REQUIRE(derived);
    const CPubKey pub{derived->first.key.GetPubKey()};
    const CScript spk{GetScriptForDestination(WitnessV0KeyHash(pub))};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(COIN - 10000, spk);

    PartiallySignedTransaction psbt(tx, /*version=*/0);
    BOOST_REQUIRE_EQUAL(psbt.inputs.size(), 1U);
    psbt.inputs[0].witness_utxo = CTxOut{COIN, spk};
    psbt.inputs[0].hd_keypaths[pub] = derived->second;

    PartiallySignedTransaction signed_psbt = client->SignTx(psbt);
    BOOST_CHECK(!signed_psbt.inputs[0].partial_sigs.empty());
    BOOST_CHECK(FinalizePSBT(signed_psbt));
}

BOOST_AUTO_TEST_CASE(native_external_signer)
{
    std::vector<ExternalSigner> none;
    BOOST_CHECK(ExternalSigner::Enumerate("internal", none, "main"));
    for (const ExternalSigner& s : none) {
        BOOST_CHECK(s.m_name != "mock");
    }

    hwi::MockRegistration mock{MockMaster()};
    std::vector<ExternalSigner> signers;
    BOOST_CHECK(ExternalSigner::Enumerate("internal", signers, "main"));
    ExternalSigner* mock_signer = nullptr;
    for (ExternalSigner& s : signers) {
        if (s.m_fingerprint == mock.Fingerprint()) mock_signer = &s;
    }
    BOOST_REQUIRE(mock_signer);
    BOOST_CHECK(mock_signer->m_native);
    BOOST_CHECK_EQUAL(mock_signer->m_name, "Mock Trezor");

    const UniValue xpub_res{mock_signer->GetXpub("m/48h/0h/0h/2h")};
    BOOST_CHECK(xpub_res.find_value("xpub").isStr());
    BOOST_CHECK(!xpub_res.find_value("xpub").get_str().empty());
    BOOST_CHECK_EQUAL(xpub_res.find_value("xpub").get_str(),
                      EncodeExtPubKey(mock.Connect()->GetPubkeyAtPath("m/48h/0h/0h/2h")));

    const UniValue descs{mock_signer->GetDescriptors(/*account=*/0)};
    BOOST_CHECK(descs.find_value("receive").isArray());
    BOOST_CHECK_EQUAL(descs.find_value("receive").getValues().size(), 4U);

    const std::string desc{descs.find_value("receive").getValues().at(2).get_str()};
    BOOST_CHECK(desc.starts_with("wpkh("));
    const UniValue displayed{mock_signer->DisplayAddress(desc)};
    BOOST_CHECK(displayed.find_value("address").isStr());
    BOOST_CHECK(!displayed.find_value("address").get_str().empty());
}

BOOST_AUTO_TEST_SUITE_END()
