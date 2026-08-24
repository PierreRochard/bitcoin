// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <external_signer.h>
#include <external_signer_discovery.h>
#include <hwi/hwi.h>
#include <hwi/mock.h>
#include <interfaces/node.h>
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

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(hwi_tests, BasicTestingSetup)

static CExtKey MockMaster()
{
    return hwi::MakeMockMasterFromHex();
}

static CExtKey OtherMockMaster(std::string_view suffix)
{
    return hwi::MakeMockMasterFromHex("101112131415161718191a1b1c1d1e" + std::string{suffix});
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

BOOST_AUTO_TEST_CASE(multisig_display_requires_physical_capability_and_exact_echo)
{
    const auto receive_descriptor = [](const hwi::MockRegistration& registration) {
        auto client{registration.Connect()};
        const hwi::DescriptorSets descs{hwi::GetDescriptors(*client, /*account=*/0)};
        const auto it{std::ranges::find_if(descs.receive, [](const std::string& desc) {
            return desc.starts_with("wpkh(");
        })};
        BOOST_REQUIRE(it != descs.receive.end());
        return *it;
    };

    hwi::MockDeviceOptions unsupported_options;
    unsupported_options.can_display_multisig_address = false;
    hwi::MockRegistration unsupported{OtherMockMaster("10"), ChainType::MAIN, unsupported_options};
    auto unsupported_client{unsupported.Connect()};
    const std::string unsupported_desc{receive_descriptor(unsupported)};
    BOOST_CHECK_THROW(hwi::DisplayAddress(*unsupported_client, unsupported_desc), hwi::HWIError);

    hwi::MockDeviceOptions refusal_options;
    refusal_options.display_address_error = "User refused physical display";
    hwi::MockRegistration refusal{OtherMockMaster("11"), ChainType::MAIN, refusal_options};
    auto refusal_client{refusal.Connect()};
    const std::string refusal_desc{receive_descriptor(refusal)};
    BOOST_CHECK_THROW(hwi::DisplayAddress(*refusal_client, refusal_desc), hwi::HWIError);

    hwi::MockDeviceOptions mismatch_options;
    mismatch_options.displayed_address_override = "bc1qwrongdisplayedaddress";
    hwi::MockRegistration mismatch{OtherMockMaster("12"), ChainType::MAIN, mismatch_options};
    auto mismatch_client{mismatch.Connect()};
    const std::string mismatch_desc{receive_descriptor(mismatch)};
    BOOST_CHECK_THROW(hwi::DisplayAddress(*mismatch_client, mismatch_desc), hwi::HWIError);
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

BOOST_AUTO_TEST_CASE(diagnostic_discovery_distinguishes_configuration_and_empty_success)
{
    static const std::string ACCOUNT_PATH{"m/48h/0h/0h/2h"};
    hwi::UsbEnumerateSuppress no_usb;

    const auto not_configured{DiscoverExternalSigners("", "main", ACCOUNT_PATH)};
    BOOST_CHECK(not_configured.status == interfaces::ExternalSignerDiscoveryStatus::NOT_CONFIGURED);
    BOOST_CHECK_EQUAL(not_configured.account_path, ACCOUNT_PATH);
    BOOST_CHECK(not_configured.devices.empty());
    BOOST_CHECK(!not_configured.error);

    const auto empty{DiscoverExternalSigners("internal", "main", ACCOUNT_PATH)};
    BOOST_CHECK(empty.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS);
    BOOST_CHECK(empty.devices.empty());
    BOOST_CHECK(!empty.error);

    std::unique_ptr<interfaces::Node> node{interfaces::MakeNode(m_node)};
    m_node.args->ForceSetArg("-signer", "");
    BOOST_CHECK(node->discoverExternalSigners(ACCOUNT_PATH).status == interfaces::ExternalSignerDiscoveryStatus::NOT_CONFIGURED);
    m_node.args->ForceSetArg("-signer", "internal");
    const auto node_empty{node->discoverExternalSigners(ACCOUNT_PATH)};
    BOOST_CHECK(node_empty.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS);
    BOOST_CHECK(node_empty.devices.empty());
}

BOOST_AUTO_TEST_CASE(diagnostic_discovery_retains_device_evidence_and_duplicates)
{
    static const std::string ACCOUNT_PATH{"m/48h/0h/0h/2h"};
    hwi::UsbEnumerateSuppress no_usb;
    const CExtKey master{MockMaster()};
    hwi::MockRegistration first{master};
    hwi::MockRegistration second{master};

    const auto result{DiscoverExternalSigners("internal", "main", ACCOUNT_PATH)};
    BOOST_REQUIRE(result.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS);
    BOOST_REQUIRE_EQUAL(result.devices.size(), 2U);
    BOOST_CHECK(!result.error);
    for (const auto& device : result.devices) {
        BOOST_CHECK_EQUAL(device.type, "mock");
        BOOST_CHECK_EQUAL(device.model, "Mock Trezor");
        BOOST_CHECK(!device.path.empty());
        BOOST_CHECK_EQUAL(device.fingerprint, first.Fingerprint());
        BOOST_CHECK(!device.locked);
        BOOST_CHECK(device.duplicate);
        BOOST_CHECK(!device.error);
        BOOST_REQUIRE(device.supports_staged_vault);
        BOOST_CHECK(*device.supports_staged_vault);
        BOOST_REQUIRE(device.supports_multisig_address_display);
        BOOST_CHECK(*device.supports_multisig_address_display);
        BOOST_REQUIRE(device.account_xpub);
        BOOST_CHECK(!device.account_xpub->empty());
        BOOST_CHECK(!device.account_xpub_error);
        BOOST_CHECK(!device.IsUsableForStagedVault());
    }
    BOOST_CHECK_NE(result.devices[0].path, result.devices[1].path);
    BOOST_CHECK_EQUAL(*result.devices[0].account_xpub, *result.devices[1].account_xpub);

    std::vector<ExternalSigner> legacy;
    BOOST_CHECK(ExternalSigner::Enumerate("internal", legacy, "main"));
    BOOST_CHECK_EQUAL(legacy.size(), 1U);
}

BOOST_AUTO_TEST_CASE(diagnostic_discovery_retains_faults_and_capability_evidence)
{
    static const std::string ACCOUNT_PATH{"m/48h/0h/0h/2h"};
    hwi::UsbEnumerateSuppress no_usb;

    hwi::MockDeviceOptions locked_options;
    locked_options.locked = true;
    locked_options.needs_pin = true;
    hwi::MockRegistration locked{OtherMockMaster("00"), ChainType::MAIN, locked_options};

    hwi::MockDeviceOptions enumeration_options;
    enumeration_options.enumerate_error = "Injected device enumeration error";
    hwi::MockRegistration enumeration_error{OtherMockMaster("01"), ChainType::MAIN, enumeration_options};

    hwi::MockDeviceOptions unsupported_options;
    unsupported_options.can_sign_musig2 = false;
    hwi::MockRegistration unsupported{OtherMockMaster("02"), ChainType::MAIN, unsupported_options};

    hwi::MockDeviceOptions xpub_options;
    xpub_options.account_xpub_error = "Injected account xpub failure";
    hwi::MockRegistration xpub_error{OtherMockMaster("03"), ChainType::MAIN, xpub_options};

    hwi::MockDeviceOptions connection_options;
    connection_options.connect_error = "Injected connection failure";
    hwi::MockRegistration connection_error{OtherMockMaster("04"), ChainType::MAIN, connection_options};

    hwi::MockRegistration supported{OtherMockMaster("05")};

    const auto result{DiscoverExternalSigners("internal", "main", ACCOUNT_PATH)};
    BOOST_REQUIRE(result.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS);
    BOOST_REQUIRE_EQUAL(result.devices.size(), 6U);

    auto find_device = [&](const hwi::MockRegistration& registration) -> const interfaces::ExternalSignerDeviceDiagnostics& {
        const auto it{std::find_if(result.devices.begin(), result.devices.end(), [&](const auto& device) {
            return device.path == registration.Path();
        })};
        BOOST_REQUIRE(it != result.devices.end());
        return *it;
    };

    const auto& locked_device{find_device(locked)};
    BOOST_CHECK(locked_device.locked);
    BOOST_CHECK(locked_device.fingerprint.empty());
    BOOST_CHECK(!locked_device.supports_staged_vault);
    BOOST_CHECK(!locked_device.account_xpub);
    BOOST_CHECK(!locked_device.IsUsableForStagedVault());

    const auto& enumeration_device{find_device(enumeration_error)};
    BOOST_REQUIRE(enumeration_device.error);
    BOOST_CHECK_EQUAL(*enumeration_device.error, "Injected device enumeration error");
    BOOST_CHECK(!enumeration_device.supports_staged_vault);
    BOOST_CHECK(!enumeration_device.account_xpub);
    BOOST_CHECK(!enumeration_device.IsUsableForStagedVault());

    const auto& unsupported_device{find_device(unsupported)};
    BOOST_REQUIRE(unsupported_device.supports_staged_vault);
    BOOST_CHECK(!*unsupported_device.supports_staged_vault);
    BOOST_REQUIRE(unsupported_device.account_xpub);
    BOOST_CHECK(!unsupported_device.account_xpub->empty());
    BOOST_CHECK(!unsupported_device.IsUsableForStagedVault());

    const auto& xpub_device{find_device(xpub_error)};
    BOOST_REQUIRE(xpub_device.supports_staged_vault);
    BOOST_CHECK(*xpub_device.supports_staged_vault);
    BOOST_CHECK(!xpub_device.account_xpub);
    BOOST_REQUIRE(xpub_device.account_xpub_error);
    BOOST_CHECK_EQUAL(*xpub_device.account_xpub_error, "Injected account xpub failure");
    BOOST_CHECK(!xpub_device.IsUsableForStagedVault());

    const auto& connection_device{find_device(connection_error)};
    BOOST_REQUIRE(connection_device.error);
    BOOST_CHECK_EQUAL(*connection_device.error, "Injected connection failure");
    BOOST_CHECK(!connection_device.supports_staged_vault);
    BOOST_CHECK(!connection_device.account_xpub);
    BOOST_CHECK(!connection_device.IsUsableForStagedVault());

    const auto& supported_device{find_device(supported)};
    BOOST_CHECK(supported_device.IsUsableForStagedVault());
    BOOST_REQUIRE(supported_device.supports_multisig_address_display);
    BOOST_CHECK(*supported_device.supports_multisig_address_display);
}

BOOST_AUTO_TEST_CASE(diagnostic_discovery_reports_backend_failure)
{
    hwi::UsbEnumerateSuppress no_usb;
    hwi::MockDeviceOptions options;
    options.enumerate_throws = true;
    hwi::MockRegistration failure{MockMaster(), ChainType::MAIN, options};

    const auto result{DiscoverExternalSigners("internal", "main", "m/48h/0h/0h/2h")};
    BOOST_CHECK(result.status == interfaces::ExternalSignerDiscoveryStatus::FAILED);
    BOOST_CHECK(result.devices.empty());
    BOOST_REQUIRE(result.error);
    BOOST_CHECK_EQUAL(*result.error, "Injected mock enumeration failure");
}

BOOST_AUTO_TEST_SUITE_END()
