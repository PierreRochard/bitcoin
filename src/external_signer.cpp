// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <external_signer.h>

#include <chainparams.h>
#include <common/run_command.h>
#include <core_io.h>
#include <hwi/hwi.h>
#include <key_io.h>
#include <psbt.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/subprocess.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

ExternalSigner::ExternalSigner(std::vector<std::string> command, std::string chain, std::string fingerprint, std::string name, bool native)
    : m_command{std::move(command)}, m_chain{std::move(chain)}, m_fingerprint{std::move(fingerprint)}, m_name{std::move(name)}, m_native{native} {}

std::vector<std::string> ExternalSigner::NetworkArg() const
{
    return {"--chain", m_chain};
}

bool ExternalSigner::Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string& chain)
{
    if (hwi::IsNativeSignerCommand(command)) {
        for (const hwi::DeviceInfo& device : hwi::Enumerate()) {
            if (device.fingerprint.empty()) continue;
            if (device.fingerprint.size() != 8 || !IsHex(device.fingerprint)) {
                throw std::runtime_error(strprintf("'%s' received invalid fingerprint, must be 8 hex characters", command));
            }
            bool duplicate = false;
            for (const ExternalSigner& signer : signers) {
                if (signer.m_fingerprint == device.fingerprint) duplicate = true;
            }
            if (duplicate) continue;
            const std::string name = device.model.empty() ? device.type : device.model;
            signers.emplace_back(std::vector<std::string>{std::string{hwi::NATIVE_SIGNER_COMMAND}}, chain, device.fingerprint, name, /*native=*/true);
        }
        return true;
    }

    // Call <command> enumerate
    std::vector<std::string> cmd_args = Cat(subprocess::util::split(command), {"enumerate"});

    const UniValue result = RunCommandParseJSON(cmd_args, "");
    if (!result.isArray()) {
        throw std::runtime_error(strprintf("'%s' received invalid response, expected array of signers", command));
    }
    for (const UniValue& signer : result.getValues()) {
        // Check for error
        const UniValue& error = signer.find_value("error");
        if (!error.isNull()) {
            if (!error.isStr()) {
                throw std::runtime_error(strprintf("'%s' error", command));
            }
            throw std::runtime_error(strprintf("'%s' error: %s", command, error.getValStr()));
        }
        // Check if fingerprint is present
        const UniValue& fingerprint = signer.find_value("fingerprint");
        if (fingerprint.isNull()) {
            throw std::runtime_error(strprintf("'%s' received invalid response, missing signer fingerprint", command));
        }
        const std::string& fingerprintStr{fingerprint.get_str()};
        if (fingerprintStr.size() != 8 || !IsHex(fingerprintStr)) {
            throw std::runtime_error(strprintf("'%s' received invalid fingerprint, must be 8 hex characters", command));
        }
        // Skip duplicate signer
        bool duplicate = false;
        for (const ExternalSigner& signer : signers) {
            if (signer.m_fingerprint.compare(fingerprintStr) == 0) duplicate = true;
        }
        if (duplicate) continue;
        std::string name;
        const UniValue& model_field = signer.find_value("model");
        if (model_field.isStr() && model_field.getValStr() != "") {
            name += model_field.getValStr();
        }
        signers.emplace_back(subprocess::util::split(command), chain, fingerprintStr, name);
    }
    return true;
}

namespace {
std::unique_ptr<hwi::HardwareWalletClient> ConnectNative(const std::string& fingerprint, const std::string& chain)
{
    const std::optional<ChainType> chain_type{ChainTypeFromString(chain)};
    if (!chain_type) {
        throw std::runtime_error("Unknown chain for native HWI: " + chain);
    }
    std::unique_ptr<hwi::HardwareWalletClient> client = hwi::FindDevice(fingerprint);
    if (!client) {
        throw std::runtime_error("Native HWI device not found");
    }
    client->SetChain(*chain_type);
    return client;
}
} // namespace

UniValue ExternalSigner::DisplayAddress(const std::string& descriptor) const
{
    if (m_native) {
        UniValue result{UniValue::VOBJ};
        result.pushKV("address", hwi::DisplayAddress(*ConnectNative(m_fingerprint, m_chain), descriptor));
        return result;
    }
    return RunCommandParseJSON(Cat(m_command, Cat(Cat({"--fingerprint", m_fingerprint}, NetworkArg()), {"displayaddress", "--desc", descriptor})), "");
}

UniValue ExternalSigner::GetDescriptors(const int account)
{
    if (m_native) {
        const hwi::DescriptorSets descs{hwi::GetDescriptors(*ConnectNative(m_fingerprint, m_chain), account)};
        UniValue receive{UniValue::VARR};
        for (const std::string& desc : descs.receive) receive.push_back(desc);
        UniValue internal{UniValue::VARR};
        for (const std::string& desc : descs.internal) internal.push_back(desc);
        UniValue result{UniValue::VOBJ};
        result.pushKV("receive", std::move(receive));
        result.pushKV("internal", std::move(internal));
        return result;
    }
    return RunCommandParseJSON(Cat(m_command, Cat(Cat({"--fingerprint", m_fingerprint}, NetworkArg()), {"getdescriptors", "--account", strprintf("%d", account)})), "");
}

UniValue ExternalSigner::GetXpub(const std::string& path) const
{
    if (m_native) {
        UniValue result{UniValue::VOBJ};
        result.pushKV("xpub", EncodeExtPubKey(ConnectNative(m_fingerprint, m_chain)->GetPubkeyAtPath(path)));
        return result;
    }
    return RunCommandParseJSON(Cat(m_command, Cat(Cat({"--fingerprint", m_fingerprint}, NetworkArg()), {"getxpub", path})), "");
}

bool ExternalSigner::SignTransaction(PartiallySignedTransaction& psbtx, std::string& error)
{
    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;
    // parse ExternalSigner master fingerprint
    std::vector<unsigned char> parsed_m_fingerprint = ParseHex(m_fingerprint);
    // Check if signer fingerprint matches any input master key fingerprint
    auto matches_signer_fingerprint = [&](const PSBTInput& input) {
        for (const auto& entry : input.hd_keypaths) {
            if (std::ranges::equal(parsed_m_fingerprint, entry.second.fingerprint)) return true;
        }
        for (const auto& entry : input.m_tap_bip32_paths) {
            if (std::ranges::equal(parsed_m_fingerprint, entry.second.second.fingerprint)) return true;
        }
        return false;
    };

    if (!std::any_of(psbtx.inputs.begin(), psbtx.inputs.end(), matches_signer_fingerprint)) {
        error = "Signer fingerprint " + m_fingerprint + " does not match any of the inputs:\n" + EncodeBase64(ssTx.str());
        return false;
    }

    if (m_native) {
        try {
            psbtx = ConnectNative(m_fingerprint, m_chain)->SignTx(psbtx);
            return true;
        } catch (const std::exception& e) {
            error = e.what();
            return false;
        }
    }

    const std::vector<std::string> command = Cat(m_command, Cat({"--stdin", "--fingerprint", m_fingerprint}, NetworkArg()));
    const std::string stdinStr = "signtx " + EncodeBase64(ssTx.str());

    const UniValue signer_result = RunCommandParseJSON(command, stdinStr);

    if (signer_result.find_value("error").isStr()) {
        error = signer_result.find_value("error").get_str();
        return false;
    }

    if (!signer_result.find_value("psbt").isStr()) {
        error = "Unexpected result from signer";
        return false;
    }

    util::Result<PartiallySignedTransaction> signer_psbtx = DecodeBase64PSBT(signer_result.find_value("psbt").get_str());
    if (!signer_psbtx) {
        error = strprintf("TX decode failed %s", util::ErrorString(signer_psbtx).original);
        return false;
    }

    psbtx = *signer_psbtx;

    return true;
}
