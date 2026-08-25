// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <external_signer_discovery.h>

#include <common/run_command.h>
#include <external_signer.h>
#include <hwi/hwi.h>
#include <key_io.h>
#include <psbt.h>
#include <streams.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/subprocess.h>
#include <util/translation.h>

#include <algorithm>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <set>
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

struct ExactVerificationSelection {
    std::vector<std::string> display_capable_fingerprints;
    std::string fingerprint;
    std::string device_path;
};

struct ExactSigningSelection {
    const interfaces::ExternalSignerExpectedIdentity* identity;
    std::string device_path;
};

bool PSBTReferencesFingerprint(const PartiallySignedTransaction& psbt, const std::string& fingerprint)
{
    const std::vector<unsigned char> parsed{ParseHex(fingerprint)};
    auto matches = [&](const KeyOriginInfo& origin) {
        return std::ranges::equal(parsed, origin.fingerprint);
    };
    for (const auto& input : psbt.inputs) {
        if (std::ranges::any_of(input.hd_keypaths, [&](const auto& entry) {
                return matches(entry.second);
            }) ||
            std::ranges::any_of(input.m_tap_bip32_paths, [&](const auto& entry) {
                return matches(entry.second.second);
            })) {
            return true;
        }
    }
    return false;
}

util::Result<std::vector<ExactSigningSelection>> SelectExactSigningDevices(
    const ExternalSignerDiscovery& discovery,
    const std::vector<interfaces::ExternalSignerExpectedIdentity>& relevant_signers)
{
    if (discovery.status != ExternalSignerDiscoveryStatus::SUCCESS) {
        const std::string reason{discovery.status == ExternalSignerDiscoveryStatus::NOT_CONFIGURED ? "hardware discovery is not configured" : discovery.error.value_or("hardware discovery failed")};
        return util::Error{Untranslated("Fresh hardware discovery did not complete: " + reason)};
    }

    // An ambiguous or partially inspected enumeration cannot establish that a
    // colliding device is absent, so do not disclose the PSBT to any device.
    for (const auto& device : discovery.devices) {
        if (device.duplicate) {
            return util::Error{Untranslated("Fresh hardware discovery found a duplicate fingerprint or device path")};
        }
        if (device.locked) {
            return util::Error{Untranslated("A connected hardware wallet is locked or did not report its fingerprint")};
        }
        if (device.error) {
            return util::Error{Untranslated("A connected hardware wallet could not be inspected: " + *device.error)};
        }
        if (device.account_xpub_error) {
            return util::Error{Untranslated("A connected hardware wallet could not provide its account key: " + *device.account_xpub_error)};
        }
    }

    std::vector<ExactSigningSelection> selected;
    selected.reserve(relevant_signers.size());
    for (const auto& identity : relevant_signers) {
        const auto match{std::find_if(discovery.devices.begin(), discovery.devices.end(), [&](const auto& device) {
            return device.fingerprint == identity.fingerprint;
        })};
        if (match == discovery.devices.end()) {
            // A delayed-recovery branch may need only a subset of its policy
            // keys. Missing authorized participants are therefore left for
            // another signing pass or an offline PSBT; they must not force us
            // to disclose the transaction to a different device.
            continue;
        }
        if (!match->IsUsableForStagedVault()) {
            return util::Error{Untranslated("A required hardware wallet no longer reports the capabilities needed to sign this Recovery Vault transaction")};
        }
        if (match->path.empty()) {
            return util::Error{Untranslated("A required hardware wallet did not provide an exact device path")};
        }
        if (!match->account_xpub || *match->account_xpub != identity.account_xpub) {
            return util::Error{Untranslated(
                "A connected device has the expected fingerprint but a different complete account xpub")};
        }
        selected.push_back({&identity, match->path});
    }
    return selected;
}

util::Result<ExactVerificationSelection> SelectExactVerificationDevice(
    const ExternalSignerDiscovery& discovery,
    const std::vector<interfaces::ExternalSignerExpectedIdentity>& expected_roster,
    const std::string& preferred_fingerprint)
{
    if (expected_roster.empty()) {
        return util::Error{Untranslated("No configured hardware participants are available for verification")};
    }
    if (discovery.status != ExternalSignerDiscoveryStatus::SUCCESS) {
        const std::string reason{discovery.status == ExternalSignerDiscoveryStatus::NOT_CONFIGURED ? "hardware discovery is not configured" : discovery.error.value_or("hardware discovery failed")};
        return util::Error{Untranslated("Fresh hardware discovery did not complete: " + reason)};
    }

    std::map<std::string, const interfaces::ExternalSignerExpectedIdentity*> expected;
    std::optional<std::string> account_path;
    for (const auto& identity : expected_roster) {
        if (identity.fingerprint.empty() || identity.account_path.empty() ||
            !DecodeExtPubKey(identity.account_xpub).pubkey.IsValid()) {
            return util::Error{Untranslated("The configured hardware identity is incomplete")};
        }
        if (!expected.emplace(identity.fingerprint, &identity).second) {
            return util::Error{Untranslated("The configured hardware roster contains a duplicate fingerprint")};
        }
        if (account_path && *account_path != identity.account_path) {
            return util::Error{Untranslated("The configured hardware participants do not share the expected account path")};
        }
        account_path = identity.account_path;
    }
    if (!preferred_fingerprint.empty() && !expected.contains(preferred_fingerprint)) {
        return util::Error{Untranslated("The selected fingerprint is not a configured hardware participant")};
    }
    if (!account_path || discovery.account_path != *account_path) {
        return util::Error{Untranslated("Fresh hardware discovery used a different account path")};
    }

    // Diagnose ambiguity before comparing sizes so a colliding fingerprint is
    // never reduced to a generic roster-change error.
    for (const auto& device : discovery.devices) {
        if (device.duplicate) {
            return util::Error{Untranslated("Fresh hardware discovery found a duplicate fingerprint or device path")};
        }
        if (device.locked) {
            return util::Error{Untranslated("A connected hardware wallet is locked or did not report its fingerprint")};
        }
        if (device.error) {
            return util::Error{Untranslated("A connected hardware wallet could not be inspected: " + *device.error)};
        }
        if (device.account_xpub_error) {
            return util::Error{Untranslated("A connected hardware wallet could not provide its account key: " + *device.account_xpub_error)};
        }
        if (!device.IsUsableForStagedVault()) {
            return util::Error{Untranslated("A connected hardware wallet is not currently usable for this Recovery Vault")};
        }
    }

    if (discovery.devices.size() != expected.size()) {
        return util::Error{Untranslated("The connected hardware-wallet roster changed or is incomplete")};
    }

    std::set<std::string> seen;
    std::map<std::string, std::string> capable_paths;
    for (const auto& device : discovery.devices) {
        const auto configured{expected.find(device.fingerprint)};
        if (configured == expected.end()) {
            return util::Error{Untranslated("The connected hardware-wallet roster contains an unexpected participant")};
        }
        if (!seen.insert(device.fingerprint).second) {
            return util::Error{Untranslated("Fresh hardware discovery found a duplicate fingerprint")};
        }
        if (!device.account_xpub || *device.account_xpub != configured->second->account_xpub) {
            return util::Error{Untranslated(
                "A connected device has the expected fingerprint but a different complete account xpub")};
        }
        if (device.path.empty()) {
            return util::Error{Untranslated("A connected hardware wallet did not provide an exact device path")};
        }
        if (device.supports_multisig_address_display.value_or(false)) {
            capable_paths.emplace(device.fingerprint, device.path);
        }
    }
    if (seen.size() != expected.size()) {
        return util::Error{Untranslated("The connected hardware-wallet roster changed or is incomplete")};
    }

    ExactVerificationSelection selection;
    for (const auto& [fingerprint, path] : capable_paths) {
        selection.display_capable_fingerprints.push_back(fingerprint);
    }
    auto selected{capable_paths.end()};
    if (!preferred_fingerprint.empty()) selected = capable_paths.find(preferred_fingerprint);
    if (selected == capable_paths.end() && !capable_paths.empty()) selected = capable_paths.begin();
    if (selected != capable_paths.end()) {
        selection.fingerprint = selected->first;
        selection.device_path = selected->second;
    }
    return selection;
}

util::Result<std::string> ReadStringResult(
    const UniValue& result,
    const char* field,
    const std::string& missing_error)
{
    const UniValue& error{result.find_value("error")};
    if (error.isStr()) return util::Error{Untranslated("Signer returned error: " + error.get_str())};
    const UniValue& value{result.find_value(field)};
    if (!value.isStr() || value.get_str().empty()) return util::Error{Untranslated(missing_error)};
    return value.get_str();
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

util::Result<interfaces::ExternalSignerAddressVerification> VerifyAddressOnExactExternalSigner(
    const std::string& command,
    const std::string& chain,
    const std::vector<interfaces::ExternalSignerExpectedIdentity>& expected_roster,
    const std::string& preferred_fingerprint,
    const std::string& descriptor)
{
    if (expected_roster.empty()) {
        return util::Error{Untranslated("No configured hardware participants are available for verification")};
    }

    ExternalSignerDiscovery discovery;
    try {
        discovery = DiscoverExternalSigners(command, chain, expected_roster.front().account_path);
    } catch (const std::exception& e) {
        return util::Error{Untranslated("Fresh hardware discovery failed: " + std::string{e.what()})};
    }
    auto selection{SelectExactVerificationDevice(discovery, expected_roster, preferred_fingerprint)};
    if (!selection) return util::Error{util::ErrorString(selection)};

    interfaces::ExternalSignerAddressVerification evidence;
    evidence.display_capable_fingerprints = selection->display_capable_fingerprints;
    if (selection->fingerprint.empty()) return evidence;
    const auto target_identity{std::find_if(expected_roster.begin(), expected_roster.end(), [&](const auto& identity) {
        return identity.fingerprint == selection->fingerprint;
    })};
    if (target_identity == expected_roster.end()) {
        return util::Error{Untranslated("The selected fingerprint is not a configured hardware participant")};
    }

    try {
        const std::string expected_address{hwi::AddressFromDescriptor(descriptor)};
        if (hwi::IsNativeSignerCommand(command)) {
            const std::optional<ChainType> chain_type{ChainTypeFromString(chain)};
            if (!chain_type) return util::Error{Untranslated("Unknown chain for native HWI: " + chain)};

            const std::vector<hwi::DeviceInfo> devices{hwi::Enumerate()};
            const size_t fingerprint_count{static_cast<size_t>(std::count_if(
                devices.begin(), devices.end(), [&](const auto& device) {
                    return device.fingerprint == selection->fingerprint;
                }))};
            if (fingerprint_count != 1) {
                return util::Error{Untranslated(
                    "The selected hardware fingerprint became missing or duplicated before display")};
            }
            const auto selected{std::find_if(devices.begin(), devices.end(), [&](const auto& device) {
                return device.path == selection->device_path &&
                       device.fingerprint == selection->fingerprint;
            })};
            if (selected == devices.end()) {
                return util::Error{Untranslated("The exact hardware device changed before display")};
            }

            std::unique_ptr<hwi::HardwareWalletClient> client{hwi::ConnectDevice(*selected)};
            client->SetChain(*chain_type);
            if (hwi::FingerprintHex(client->GetMasterFingerprint()) != selection->fingerprint) {
                return util::Error{Untranslated("The exact hardware device reported a different master fingerprint")};
            }
            if (!client->CanSignTaproot() || !client->CanSignMuSig2() ||
                !client->CanDisplayMultisigAddress()) {
                return util::Error{Untranslated(
                    "The exact hardware device no longer reports the capabilities required for address verification")};
            }
            const std::string connected_xpub{EncodeExtPubKey(client->GetPubkeyAtPath(target_identity->account_path))};
            if (connected_xpub != target_identity->account_xpub) {
                return util::Error{Untranslated(
                    "The exact hardware device has the expected fingerprint but a different complete account xpub")};
            }
            const std::string displayed{hwi::DisplayAddress(*client, descriptor)};
            client->Close();
            if (displayed != expected_address) {
                return util::Error{Untranslated("The hardware wallet displayed a different address")};
            }
            evidence.displayed_fingerprint = selection->fingerprint;
            evidence.displayed_address = displayed;
            return evidence;
        }

        if (command.empty()) {
            return util::Error{Untranslated("Hardware discovery is not configured")};
        }
        const std::vector<std::string> selector{Cat(
            subprocess::util::split(command),
            {"--device-path", selection->device_path, "--chain", chain})};
        const UniValue xpub_result{RunCommandParseJSON(
            Cat(selector, {"getxpub", target_identity->account_path}), "")};
        auto connected_xpub{ReadStringResult(xpub_result, "xpub", "Signer returned no account xpub")};
        if (!connected_xpub) return util::Error{util::ErrorString(connected_xpub)};
        if (*connected_xpub != target_identity->account_xpub ||
            !DecodeExtPubKey(*connected_xpub).pubkey.IsValid()) {
            return util::Error{Untranslated(
                "The exact hardware device has the expected fingerprint but a different complete account xpub")};
        }
        const UniValue display_result{RunCommandParseJSON(
            Cat(selector, {"displayaddress", "--desc", descriptor}), "")};
        auto displayed{ReadStringResult(display_result, "address", "Signer did not echo an address")};
        if (!displayed) return util::Error{util::ErrorString(displayed)};
        if (*displayed != expected_address) {
            return util::Error{Untranslated("The hardware wallet displayed a different address")};
        }
        evidence.displayed_fingerprint = selection->fingerprint;
        evidence.displayed_address = *displayed;
        return evidence;
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

util::Result<std::vector<std::string>> SignPSBTWithExactExternalSigners(
    const std::string& command,
    const std::string& chain,
    const std::vector<interfaces::ExternalSignerExpectedIdentity>& allowed_signers,
    PartiallySignedTransaction& psbt,
    const std::function<bool(const PartiallySignedTransaction&)>& validate_response)
{
    if (allowed_signers.empty()) {
        return util::Error{Untranslated("No exact hardware participants are authorized to receive this PSBT")};
    }

    std::set<std::string> fingerprints;
    std::optional<std::string> account_path;
    std::vector<interfaces::ExternalSignerExpectedIdentity> relevant_signers;
    for (const auto& identity : allowed_signers) {
        if (!IsValidFingerprint(identity.fingerprint) || identity.account_path.empty() ||
            !DecodeExtPubKey(identity.account_xpub).pubkey.IsValid()) {
            return util::Error{Untranslated("An authorized hardware identity is incomplete")};
        }
        if (!fingerprints.insert(identity.fingerprint).second) {
            return util::Error{Untranslated("The authorized hardware signer set contains a duplicate fingerprint")};
        }
        if (account_path && *account_path != identity.account_path) {
            return util::Error{Untranslated("The authorized hardware signers do not share the expected account path")};
        }
        account_path = identity.account_path;
        if (PSBTReferencesFingerprint(psbt, identity.fingerprint)) {
            relevant_signers.push_back(identity);
        }
    }

    // Do not enumerate or disclose anything when this transaction does not
    // reference an authorized hardware participant.
    if (relevant_signers.empty()) return std::vector<std::string>{};

    ExternalSignerDiscovery discovery;
    try {
        discovery = DiscoverExternalSigners(command, chain, *account_path);
    } catch (const std::exception& e) {
        return util::Error{Untranslated("Fresh hardware discovery failed: " + std::string{e.what()})};
    }
    auto selected{SelectExactSigningDevices(discovery, relevant_signers)};
    if (!selected) return util::Error{util::ErrorString(selected)};

    const std::optional<ChainType> chain_type{ChainTypeFromString(chain)};
    if (hwi::IsNativeSignerCommand(command) && !chain_type) {
        return util::Error{Untranslated("Unknown chain for native HWI: " + chain)};
    }

    // Work on a copy so an error after one device has signed does not leave the
    // caller with a partially mutated transaction that looks like full success.
    PartiallySignedTransaction working{psbt};
    std::vector<std::string> contacted;
    contacted.reserve(selected->size());

    for (const auto& selection : *selected) {
        try {
            if (hwi::IsNativeSignerCommand(command)) {
                const std::vector<hwi::DeviceInfo> devices{hwi::Enumerate()};
                const size_t fingerprint_count{static_cast<size_t>(std::count_if(
                    devices.begin(), devices.end(), [&](const auto& device) {
                        return device.fingerprint == selection.identity->fingerprint;
                    }))};
                const size_t path_count{static_cast<size_t>(std::count_if(
                    devices.begin(), devices.end(), [&](const auto& device) {
                        return device.path == selection.device_path;
                    }))};
                if (fingerprint_count != 1 || path_count != 1) {
                    return util::Error{Untranslated(
                        "An exact hardware signer became missing or duplicated before signing")};
                }
                const auto device{std::find_if(devices.begin(), devices.end(), [&](const auto& candidate) {
                    return candidate.path == selection.device_path &&
                           candidate.fingerprint == selection.identity->fingerprint;
                })};
                if (device == devices.end() || device->error || device->fingerprint.empty() ||
                    device->needs_pin || device->needs_passphrase) {
                    return util::Error{Untranslated("The exact hardware device changed or became unavailable before signing")};
                }

                std::unique_ptr<hwi::HardwareWalletClient> client{hwi::ConnectDevice(*device)};
                client->SetChain(*chain_type);
                if (hwi::FingerprintHex(client->GetMasterFingerprint()) != selection.identity->fingerprint) {
                    client->Close();
                    return util::Error{Untranslated("The exact hardware device reported a different master fingerprint")};
                }
                if (!client->CanSignTaproot() || !client->CanSignMuSig2()) {
                    client->Close();
                    return util::Error{Untranslated(
                        "The exact hardware device no longer reports the capabilities required to sign this Recovery Vault transaction")};
                }
                const std::string connected_xpub{EncodeExtPubKey(
                    client->GetPubkeyAtPath(selection.identity->account_path))};
                if (connected_xpub != selection.identity->account_xpub) {
                    client->Close();
                    return util::Error{Untranslated(
                        "The exact hardware device has the expected fingerprint but a different complete account xpub")};
                }
                const PartiallySignedTransaction signed_psbt{client->SignTx(working)};
                client->Close();
                auto merged{CombinePSBTs({working, signed_psbt})};
                if (!merged) {
                    return util::Error{Untranslated(
                        "Hardware signer changed the unsigned transaction or returned conflicting PSBT data")};
                }
                working = std::move(*merged);
            } else {
                if (command.empty()) {
                    return util::Error{Untranslated("Hardware discovery is not configured")};
                }

                // Re-enumerate immediately before disclosure so a subprocess
                // device-path cannot silently be rebound after preflight.
                const ExternalSignerDiscovery current{DiscoverExternalSigners(
                    command, chain, selection.identity->account_path)};
                auto current_selection{SelectExactSigningDevices(current, {*selection.identity})};
                if (!current_selection) return util::Error{util::ErrorString(current_selection)};
                if (current_selection->size() != 1 ||
                    current_selection->front().device_path != selection.device_path) {
                    return util::Error{Untranslated("The exact hardware device path changed before signing")};
                }

                const std::vector<std::string> selector{Cat(
                    subprocess::util::split(command),
                    {"--device-path", selection.device_path, "--chain", chain})};
                const UniValue xpub_result{RunCommandParseJSON(
                    Cat(selector, {"getxpub", selection.identity->account_path}), "")};
                auto connected_xpub{ReadStringResult(xpub_result, "xpub", "Signer returned no account xpub")};
                if (!connected_xpub) return util::Error{util::ErrorString(connected_xpub)};
                if (*connected_xpub != selection.identity->account_xpub ||
                    !DecodeExtPubKey(*connected_xpub).pubkey.IsValid()) {
                    return util::Error{Untranslated(
                        "The exact hardware device has the expected fingerprint but a different complete account xpub")};
                }

                DataStream serialized{};
                serialized << working;
                const UniValue sign_result{RunCommandParseJSON(
                    Cat(selector, {"--stdin"}), "signtx " + EncodeBase64(serialized.str()))};
                auto encoded{ReadStringResult(sign_result, "psbt", "Signer returned no PSBT")};
                if (!encoded) return util::Error{util::ErrorString(encoded)};
                auto signed_psbt{DecodeBase64PSBT(*encoded)};
                if (!signed_psbt) {
                    return util::Error{Untranslated(
                        "Signer returned an invalid PSBT: " + util::ErrorString(signed_psbt).original)};
                }
                auto merged{CombinePSBTs({working, *signed_psbt})};
                if (!merged) {
                    return util::Error{Untranslated(
                        "Hardware signer changed the unsigned transaction or returned conflicting PSBT data")};
                }
                working = std::move(*merged);
            }
            // The signer response is still isolated in `working`. Give the
            // wallet a chance to reject unauthorized signature material after
            // every device response, before it is sent to another signer or
            // published back to the caller.
            if (validate_response && !validate_response(working)) {
                return util::Error{Untranslated(
                    "A hardware signer returned unauthorized signature data")};
            }
            contacted.push_back(selection.identity->fingerprint);
        } catch (const std::exception& e) {
            return util::Error{Untranslated(e.what())};
        }
    }

    psbt = std::move(working);
    return contacted;
}
