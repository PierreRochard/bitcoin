// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/test/vaulthardwaretests.h>

#include <chainparams.h>
#include <common/args.h>
#include <hwi/mock.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <qt/clientmodel.h>
#include <qt/multisigwizard.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/sendcoinsdialog.h>
#include <qt/walletmodel.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/multisig.h>

#include <QApplication>
#include <QLabel>
#include <QPushButton>
#include <QWizard>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::array<std::string_view, 4> MASTER_SEEDS{
    "000102030405060708090a0b0c0d0e0f",
    "101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f",
    "303132333435363738393a3b3c3d3e3f",
};

struct FixedHardwareCandidate {
    std::string package;
    std::array<CExtKey, 3> masters;
    std::array<std::string, 3> fingerprints;
    std::array<std::string, 3> xpubs;
    std::string account_path;
};

FixedHardwareCandidate PrepareFixedHardwareCandidate()
{
    FixedHardwareCandidate candidate;
    candidate.account_path = wallet::DefaultMultisigPath(OutputType::BECH32M, /*account=*/0);
    std::vector<uint32_t> path;
    Assert(ParseHDKeypath(candidate.account_path, path));

    std::vector<wallet::MultisigKeySpec> specs(3);
    for (size_t index = 0; index < specs.size(); ++index) {
        candidate.masters[index] = hwi::MakeMockMasterFromHex(MASTER_SEEDS[index]);
        const auto derived{DeriveExtKey(candidate.masters[index], path)};
        Assert(derived);
        candidate.fingerprints[index] = HexStr(candidate.masters[index].id_key_fingerprint());
        candidate.xpubs[index] = EncodeExtPubKey(derived->first.Neuter());
        specs[index].fingerprint = candidate.fingerprints[index];
        specs[index].path = candidate.account_path;
        specs[index].xpub = candidate.xpubs[index];
        specs[index].label = "Hardware wallet " + std::to_string(index + 1);
    }

    wallet::MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.fallback_older = MultisigWizard::kThirtyDayVaultDelay;
    options.fallback_older_one_key = MultisigWizard::kSixtyDayVaultDelay;
    auto prepared{wallet::PrepareMultisigDescriptor(/*nrequired=*/2, specs, options)};
    Assert(prepared);

    wallet::VaultPolicyPackage policy;
    policy.network = Params().GetChainTypeString();
    policy.nrequired = 2;
    policy.fallback_older = MultisigWizard::kThirtyDayVaultDelay;
    policy.fallback_older_one_key = MultisigWizard::kSixtyDayVaultDelay;
    policy.recovery_stages = {
        {2, MultisigWizard::kThirtyDayVaultDelay, {}},
        {1, MultisigWizard::kSixtyDayVaultDelay, {}},
    };
    policy.descs = prepared->descs;
    policy.policy_id = prepared->policy_id;
    candidate.package = wallet::FormatVaultPolicyPackage(policy);
    return candidate;
}

void CheckFixedDiscoveryFailure(interfaces::Node& node, const QString& expected_text)
{
    MultisigWizard wizard(node, /*wallet_controller=*/nullptr);
    wizard.show();
    QApplication::processEvents();

    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
    auto* status{wizard.findChild<QLabel*>("hardwareDiscoveryStatus")};
    auto* retry{wizard.findChild<QPushButton*>("refreshDevicesButton")};
    QVERIFY(status);
    QVERIFY(retry);
    QVERIFY2(status->text().contains(expected_text, Qt::CaseInsensitive), qPrintable(status->text()));
    QVERIFY(retry->isVisible());
    QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
    QCOMPARE(wizard.localKeyCount(), 0);
    QVERIFY(wizard.keys().empty());
    QVERIFY(!wizard.createdWallet());
    wizard.close();
}

} // namespace

void VaultHardwareTests::fixedNativeDiscoveryWorksWithoutSignerOption()
{
    BasicTestingSetup test{ChainType::REGTEST};
    m_node.setContext(&test.m_node);
    QVERIFY(!test.m_node.args->IsArgSet("-signer"));
    hwi::UsbEnumerateSuppress no_usb;

    const std::string account_path{wallet::DefaultMultisigPath(OutputType::BECH32M, /*account=*/0)};
    const auto discovery{m_node.discoverExternalSigners(account_path)};
    QVERIFY(discovery.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS);
    QVERIFY(discovery.account_path == account_path);
    QVERIFY(discovery.devices.empty());
    QVERIFY(!discovery.error);

    MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
    wizard.show();
    QApplication::processEvents();

    QCOMPARE(wizard.currentId(), static_cast<int>(MultisigWizard::Page_Keys));
    QCOMPARE(wizard.localKeyCount(), MultisigWizard::kStagedVaultKeyCount);
    QCOMPARE(wizard.keys().size(), size_t{MultisigWizard::kStagedVaultKeyCount});
    QCOMPARE(wizard.nActiveKeys(), MultisigWizard::kStagedVaultKeyCount);
    QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());
    QVERIFY(!wizard.createdWallet());
    wizard.close();

    // Native diagnostics see a newly connected device without -signer, while
    // the legacy API still requires the option and remains empty.
    {
        hwi::MockRegistration device{hwi::MakeMockMasterFromHex(MASTER_SEEDS[0]), ChainType::REGTEST};
        const auto connected{m_node.discoverExternalSigners(account_path)};
        QVERIFY(connected.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS);
        QCOMPARE(connected.devices.size(), size_t{1});
        QVERIFY(connected.devices.front().fingerprint == device.Fingerprint());
        QVERIFY(m_node.listExternalSigners().empty());
    }

    // Explicitly disabling the configured signer remains distinguishable
    // from the absent-option native default.
    test.m_node.args->ForceSetArg("-signer", "");
    const auto explicitly_disabled{m_node.discoverExternalSigners(account_path)};
    QVERIFY(explicitly_disabled.status == interfaces::ExternalSignerDiscoveryStatus::NOT_CONFIGURED);
    QVERIFY(explicitly_disabled.devices.empty());
}

void VaultHardwareTests::fixedDiscoveryFailuresFailClosed()
{
    BasicTestingSetup test{ChainType::REGTEST};
    m_node.setContext(&test.m_node);
    test.m_node.args->ForceSetArg("-signer", "internal");
    hwi::UsbEnumerateSuppress no_usb;

    {
        hwi::MockDeviceOptions options;
        options.locked = true;
        options.needs_pin = true;
        hwi::MockRegistration device{hwi::MakeMockMasterFromHex(MASTER_SEEDS[0]), ChainType::REGTEST, options};
        CheckFixedDiscoveryFailure(m_node, QStringLiteral("locked"));
    }
    {
        hwi::MockDeviceOptions options;
        options.can_sign_musig2 = false;
        hwi::MockRegistration device{hwi::MakeMockMasterFromHex(MASTER_SEEDS[0]), ChainType::REGTEST, options};
        CheckFixedDiscoveryFailure(m_node, QStringLiteral("cannot complete"));
    }
    {
        const CExtKey master{hwi::MakeMockMasterFromHex(MASTER_SEEDS[0])};
        hwi::MockRegistration first{master, ChainType::REGTEST};
        hwi::MockRegistration second{master, ChainType::REGTEST};
        CheckFixedDiscoveryFailure(m_node, QStringLiteral("more than once"));
    }
    {
        hwi::MockDeviceOptions options;
        options.connect_error = "Injected Qt connection failure";
        hwi::MockRegistration device{hwi::MakeMockMasterFromHex(MASTER_SEEDS[0]), ChainType::REGTEST, options};
        CheckFixedDiscoveryFailure(m_node, QStringLiteral("could not be inspected"));
    }
    {
        hwi::MockDeviceOptions options;
        options.account_xpub_error = "Injected Qt account xpub failure";
        hwi::MockRegistration device{hwi::MakeMockMasterFromHex(MASTER_SEEDS[0]), ChainType::REGTEST, options};
        CheckFixedDiscoveryFailure(m_node, QStringLiteral("required account key"));
    }
    {
        hwi::MockDeviceOptions options;
        options.enumerate_throws = true;
        hwi::MockRegistration device{hwi::MakeMockMasterFromHex(MASTER_SEEDS[0]), ChainType::REGTEST, options};
        CheckFixedDiscoveryFailure(m_node, QStringLiteral("discovery failed"));
    }
}

void VaultHardwareTests::fixedDiscoveryBoundaryChangesFailClosed()
{
    BasicTestingSetup test{ChainType::REGTEST};
    m_node.setContext(&test.m_node);
    test.m_node.args->ForceSetArg("-signer", "internal");
    hwi::UsbEnumerateSuppress no_usb;

    auto first{std::make_unique<hwi::MockRegistration>(
        hwi::MakeMockMasterFromHex(MASTER_SEEDS[0]), ChainType::REGTEST)};
    auto second{std::make_unique<hwi::MockRegistration>(
        hwi::MakeMockMasterFromHex(MASTER_SEEDS[1]), ChainType::REGTEST)};
    {
        MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
        wizard.show();
        QApplication::processEvents();
        QCOMPARE(wizard.localKeyCount(), 1);
        QCOMPARE(wizard.keys().size(), size_t{3});
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());

        second.reset();
        QVERIFY(!wizard.validateCurrentPage());
        QApplication::processEvents();
        const auto* status{wizard.findChild<QLabel*>("hardwareDiscoveryStatus")};
        QVERIFY(status);
        QVERIFY2(status->text().contains(QStringLiteral("roster changed"), Qt::CaseInsensitive), qPrintable(status->text()));
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        QCOMPARE(wizard.localKeyCount(), 0);
        QVERIFY(wizard.keys().empty());
        QVERIFY(!wizard.createdWallet());
        wizard.close();
    }
    second = std::make_unique<hwi::MockRegistration>(
        hwi::MakeMockMasterFromHex(MASTER_SEEDS[1]), ChainType::REGTEST);

    struct RestoreMockOrder {
        ~RestoreMockOrder() { hwi::ReverseMockEnumerationOrder(); }
    } restore_order;
    {
        MultisigWizard wizard(m_node, /*wallet_controller=*/nullptr);
        wizard.show();
        QApplication::processEvents();
        QCOMPARE(wizard.localKeyCount(), 1);
        QCOMPARE(wizard.keys().size(), size_t{3});
        QVERIFY(wizard.button(QWizard::NextButton)->isEnabled());

        hwi::ReverseMockEnumerationOrder();
        QVERIFY(!wizard.validateCurrentPage());
        QApplication::processEvents();
        const auto* status{wizard.findChild<QLabel*>("hardwareDiscoveryStatus")};
        QVERIFY(status);
        QVERIFY2(status->text().contains(QStringLiteral("roster changed"), Qt::CaseInsensitive), qPrintable(status->text()));
        QVERIFY(!wizard.button(QWizard::NextButton)->isEnabled());
        QCOMPARE(wizard.localKeyCount(), 0);
        QVERIFY(wizard.keys().empty());
        QVERIFY(!wizard.createdWallet());
        wizard.close();
    }
}

void VaultHardwareTests::hardwareOnlyRestoreReconcilesExactDevicesAcrossReload()
{
    TestChain100Setup test;
    auto loader{interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args))};
    test.m_node.wallet_loader = loader.get();
    m_node.setContext(&test.m_node);
    QVERIFY(!test.m_node.args->IsArgSet("-signer"));
    hwi::UsbEnumerateSuppress no_usb;

    bilingual_str error;
    OptionsModel options(m_node);
    QVERIFY(options.Init(error));
    ClientModel client(m_node, &options);
    std::unique_ptr<const PlatformStyle> style{PlatformStyle::instantiate(QStringLiteral("other"))};
    QVERIFY(style);

    const FixedHardwareCandidate candidate{PrepareFixedHardwareCandidate()};
    const std::string wallet_name{"qt_hardware_only_restore"};
    std::vector<bilingual_str> warnings;
    auto installed{loader->installFixedVault(
        wallet_name, candidate.package, /*mnemonics=*/{},
        interfaces::FixedVaultInstallMode::RESTORE, warnings)};
    QVERIFY2(installed, qPrintable(QString::fromStdString(util::ErrorString(installed).original)));
    QVERIFY(installed->wallet);
    QVERIFY(installed->wallet->privateKeysDisabled());
    QVERIFY(installed->wallet->hasExternalSigner());

    auto model{std::make_unique<WalletModel>(std::move(installed->wallet), client, style.get())};
    auto status{model->wallet().getVaultStatus()};
    QCOMPARE(status.participants.size(), size_t{3});
    QCOMPARE(status.lost_signers.size(), size_t{3});
    QCOMPARE(model->reconcileVaultHardwareSigners().lost_signers.size(), size_t{3});

    {
        hwi::MockRegistration unrelated{hwi::MakeMockMasterFromHex(MASTER_SEEDS[3]), ChainType::REGTEST};
        QCOMPARE(model->reconcileVaultHardwareSigners().lost_signers.size(), size_t{3});
    }
    {
        hwi::MockDeviceOptions fault;
        fault.account_xpub_error = "Injected reconnect xpub failure";
        hwi::MockRegistration broken{candidate.masters[0], ChainType::REGTEST, fault};
        QCOMPARE(model->reconcileVaultHardwareSigners().lost_signers.size(), size_t{3});
    }
    {
        hwi::MockRegistration exact{candidate.masters[0], ChainType::REGTEST};
        const auto discovery{m_node.discoverExternalSigners(candidate.account_path)};
        QVERIFY(discovery.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS);
        QVERIFY(discovery.account_path == candidate.account_path);
        QCOMPARE(discovery.devices.size(), size_t{1});
        QVERIFY(discovery.devices.front().fingerprint == candidate.fingerprints[0]);
        QVERIFY(discovery.devices.front().account_xpub == std::optional<std::string>{candidate.xpubs[0]});
        status = model->reconcileVaultHardwareSigners();
        QCOMPARE(status.lost_signers.size(), size_t{2});
        QVERIFY(std::ranges::find(status.lost_signers, candidate.fingerprints[0]) == status.lost_signers.end());
    }

    model->wallet().remove();
    model.reset();
    auto reloaded{loader->loadWallet(wallet_name, warnings)};
    QVERIFY2(reloaded, qPrintable(QString::fromStdString(util::ErrorString(reloaded).original)));
    model = std::make_unique<WalletModel>(std::move(*reloaded), client, style.get());
    QCOMPARE(model->wallet().getVaultStatus().lost_signers.size(), size_t{2});

    {
        hwi::MockRegistration exact{candidate.masters[1], ChainType::REGTEST};
        status = model->reconcileVaultHardwareSigners();
        QCOMPARE(status.lost_signers.size(), size_t{1});
        QVERIFY(status.lost_signers.front() == candidate.fingerprints[2]);
    }

    model->wallet().remove();
    model.reset();
    auto reloaded_again{loader->loadWallet(wallet_name, warnings)};
    QVERIFY2(reloaded_again, qPrintable(QString::fromStdString(util::ErrorString(reloaded_again).original)));
    model = std::make_unique<WalletModel>(std::move(*reloaded_again), client, style.get());
    QCOMPARE(model->wallet().getVaultStatus().lost_signers.size(), size_t{1});

    {
        hwi::MockRegistration exact{candidate.masters[2], ChainType::REGTEST};
        status = model->reconcileVaultHardwareSigners();
        QVERIFY(status.lost_signers.empty());

        const auto destination{model->wallet().getNewDestination(OutputType::BECH32M, "")};
        QVERIFY2(destination, qPrintable(QString::fromStdString(util::ErrorString(destination).original)));
        const auto displayed{model->wallet().displayAddress(*destination, candidate.fingerprints[2])};
        QVERIFY2(displayed, qPrintable(QString::fromStdString(util::ErrorString(displayed).original)));

        QVERIFY(!test.m_node.args->IsArgSet("-signer"));
        QVERIFY(!options.hasSigner());
        QVERIFY(options.hasSigner(/*allow_native_default=*/true));
        SendCoinsDialog send{style.get()};
        send.setClientModel(&client);
        send.setModel(model.get());
        send.show();
        QApplication::processEvents();
        auto* send_button{send.findChild<QPushButton*>("sendButton")};
        QVERIFY(send_button);
        QVERIFY(!send_button->toolTip().contains(QStringLiteral("Set external signer"), Qt::CaseInsensitive));
        send.close();
    }

    model->wallet().remove();
    model.reset();
    auto reloaded_final{loader->loadWallet(wallet_name, warnings)};
    QVERIFY2(reloaded_final, qPrintable(QString::fromStdString(util::ErrorString(reloaded_final).original)));
    QCOMPARE((*reloaded_final)->getVaultStatus().lost_signers.size(), size_t{0});
    (*reloaded_final)->remove();
}
