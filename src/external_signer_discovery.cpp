// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <external_signer_discovery.h>

#include <common/run_command.h>
#include <external_signer.h>
#include <hwi/hwi.h>
#include <key_io.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/subprocess.h>

#include <algorithm>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

using interfaces::ExternalSignerDeviceDiagnostics;
using interfaces::ExternalSignerDiscovery;
using interfaces::ExternalSignerDiscoveryStatus;

void AddDeviceError(ExternalSignerDeviceDiagnostics& device, std::string error)
{
    if (device.error) {
        *device.error += "; " + error;
    } else {
        device.error = std::move(error);
    }
}

bool IsValidFingerprint(const std::string& fingerprint)
{
    return fingerprint.size() == 8 && IsHex(fingerprint) &&
           std::none_of(fingerprint.begin(), fingerprint.end(), [](char ch) { return ch >= 'A' && ch <= 'F'; });
}

void MarkDuplicates(std::vector<ExternalSignerDeviceDiagnostics>& devices)
{
    std::map<std::string, size_t> fingerprint_counts;
    std::map<std::string, size_t> path_counts;
    for (const auto& device : devices) {
        if (!device.fingerprint.empty()) ++fingerprint_counts[device.fingerprint];
        if (!device.path.empty()) ++path_counts[device.path];
    }
    for (auto& device : devices) {
        device.duplicate = (!device.fingerprint.empty() && fingerprint_counts[device.fingerprint] > 1) ||
                           (!device.path.empty() && path_counts[device.path] > 1);
    }
}

ExternalSignerDiscovery DiscoverNative(const std::string& chain, const std::string& account_path)
{
    ExternalSignerDiscovery result;
    const std::optional<ChainType> chain_type{ChainTypeFromString(chain)};
    if (!chain_type) {
        result.error = "Unknown chain for native HWI: " + chain;
        return result;
    }

    std::vector<hwi::DeviceInfo> enumerated;
    try {
        enumerated = hwi::Enumerate();
    } catch (const std::exception& e) {
        result.error = e.what();
        return result;
    }

    result.status = ExternalSignerDiscoveryStatus::SUCCESS;
    result.devices.reserve(enumerated.size());
    for (const hwi::DeviceInfo& info : enumerated) {
        ExternalSignerDeviceDiagnostics device;
        device.path = info.path;
        device.type = info.type;
        device.model = info.model;
        device.fingerprint = info.fingerprint;
        device.locked = info.fingerprint.empty() || info.needs_pin || info.needs_passphrase;
        device.error = info.error;
        if (!device.fingerprint.empty() && !IsValidFingerprint(device.fingerprint)) {
            AddDeviceError(device, "Invalid signer fingerprint; expected 8 lowercase hex characters");
        }
        result.devices.push_back(std::move(device));
    }
    MarkDuplicates(result.devices);

    for (size_t index = 0; index < result.devices.size(); ++index) {
        auto& device{result.devices[index]};
        if (device.locked || device.error || !IsValidFingerprint(device.fingerprint)) continue;
        try {
            std::unique_ptr<hwi::HardwareWalletClient> client{hwi::ConnectDevice(enumerated[index])};
            client->SetChain(*chain_type);
            device.supports_staged_vault = client->CanSignTaproot() && client->CanSignMuSig2();
            device.supports_multisig_address_display = client->CanDisplayMultisigAddress();
            try {
                device.account_xpub = EncodeExtPubKey(client->GetPubkeyAtPath(account_path));
            } catch (const std::exception& e) {
                device.account_xpub_error = e.what();
            }
            client->Close();
        } catch (const std::exception& e) {
            AddDeviceError(device, e.what());
        }
    }
    return result;
}

std::optional<std::string> StringField(const UniValue& object, const char* name, ExternalSignerDeviceDiagnostics& device)
{
    const UniValue& value{object.find_value(name)};
    if (value.isNull()) return std::nullopt;
    if (!value.isStr()) {
        AddDeviceError(device, strprintf("Signer field '%s' must be a string", name));
        return std::nullopt;
    }
    return value.get_str();
}

bool BoolField(const UniValue& object, const char* name, ExternalSignerDeviceDiagnostics& device)
{
    const UniValue& value{object.find_value(name)};
    if (value.isNull()) return false;
    if (!value.isBool()) {
        AddDeviceError(device, strprintf("Signer field '%s' must be a boolean", name));
        return false;
    }
    return value.get_bool();
}

ExternalSignerDiscovery DiscoverSubprocess(const std::string& command, const std::string& chain, const std::string& account_path)
{
    ExternalSignerDiscovery result;
    UniValue response;
    try {
        response = RunCommandParseJSON(Cat(subprocess::util::split(command), {"enumerate"}), "");
    } catch (const std::exception& e) {
        result.error = e.what();
        return result;
    }
    if (!response.isArray()) {
        result.error = strprintf("'%s' received invalid response, expected array of signers", command);
        return result;
    }

    result.status = ExternalSignerDiscoveryStatus::SUCCESS;
    for (const UniValue& value : response.getValues()) {
        ExternalSignerDeviceDiagnostics device;
        if (!value.isObject()) {
            device.error = "Signer entry must be an object";
            result.devices.push_back(std::move(device));
            continue;
        }
        if (auto field{StringField(value, "path", device)}) device.path = std::move(*field);
        if (auto field{StringField(value, "type", device)}) device.type = std::move(*field);
        if (auto field{StringField(value, "model", device)}) device.model = std::move(*field);
        if (auto field{StringField(value, "fingerprint", device)}) device.fingerprint = std::move(*field);
        if (auto field{StringField(value, "error", device)}; field && !field->empty()) AddDeviceError(device, std::move(*field));

        const bool needs_pin{BoolField(value, "needs_pin", device)};
        const bool needs_pin_sent{BoolField(value, "needs_pin_sent", device)};
        const bool needs_passphrase{BoolField(value, "needs_passphrase", device)};
        const bool needs_passphrase_sent{BoolField(value, "needs_passphrase_sent", device)};
        device.locked = device.fingerprint.empty() || needs_pin || needs_pin_sent || needs_passphrase || needs_passphrase_sent;
        const UniValue& capability{value.find_value("supports_staged_vault")};
        if (capability.isBool()) {
            device.supports_staged_vault = capability.get_bool();
        } else if (!capability.isNull()) {
            AddDeviceError(device, "Signer field 'supports_staged_vault' must be a boolean");
        }
        const UniValue& display_capability{value.find_value("supports_multisig_address_display")};
        if (display_capability.isBool()) {
            device.supports_multisig_address_display = display_capability.get_bool();
        } else if (!display_capability.isNull()) {
            AddDeviceError(device, "Signer field 'supports_multisig_address_display' must be a boolean");
        }
        if (!device.fingerprint.empty() && !IsValidFingerprint(device.fingerprint)) {
            AddDeviceError(device, "Invalid signer fingerprint; expected 8 lowercase hex characters");
        }
        result.devices.push_back(std::move(device));
    }
    MarkDuplicates(result.devices);

    for (auto& device : result.devices) {
        if (device.duplicate) {
            device.account_xpub_error = "Account xpub was not queried because the signer identity is duplicated";
            continue;
        }
        if (device.locked || device.error || !IsValidFingerprint(device.fingerprint)) continue;
        try {
            ExternalSigner signer{subprocess::util::split(command), chain, device.fingerprint, device.model};
            const UniValue xpub_result{signer.GetXpub(account_path)};
            const UniValue& signer_error{xpub_result.find_value("error")};
            const UniValue& xpub{xpub_result.find_value("xpub")};
            if (signer_error.isStr()) {
                device.account_xpub_error = signer_error.get_str();
            } else if (!xpub.isStr() || xpub.get_str().empty()) {
                device.account_xpub_error = "Signer returned no account xpub";
            } else if (!DecodeExtPubKey(xpub.get_str()).pubkey.IsValid()) {
                device.account_xpub_error = "Signer returned an invalid account xpub";
            } else {
                device.account_xpub = xpub.get_str();
            }
        } catch (const std::exception& e) {
            device.account_xpub_error = e.what();
        }
    }
    return result;
}

} // namespace

interfaces::ExternalSignerDiscovery DiscoverExternalSigners(
    const std::string& command,
    const std::string& chain,
    const std::string& account_path)
{
    interfaces::ExternalSignerDiscovery result;
    if (command.empty()) {
        result.status = interfaces::ExternalSignerDiscoveryStatus::NOT_CONFIGURED;
    } else if (hwi::IsNativeSignerCommand(command)) {
        result = DiscoverNative(chain, account_path);
    } else {
        result = DiscoverSubprocess(command, chain, account_path);
    }
    result.account_path = account_path;
    return result;
}
