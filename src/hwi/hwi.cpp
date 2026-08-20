// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/hwi.h>

#include <hwi/coldcard.h>
#include <hwi/ledger.h>
#include <hwi/mock.h>
#include <hwi/trezor.h>

#include <addresstype.h>
#include <crypto/hex_base.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/keyorigin.h>
#include <script/signingprovider.h>
#include <tinyformat.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <stdexcept>

namespace hwi {
namespace {

std::string AddressFromDescriptor(const std::string& desc_str)
{
    FlatSigningProvider provider;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> parsed = Parse(desc_str, provider, error, /*require_checksum=*/false);
    if (parsed.empty()) {
        throw HWIError("Invalid descriptor: " + error, ErrorCode::BAD_ARGUMENT);
    }
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    if (!parsed.at(0)->Expand(/*pos=*/0, provider, scripts, out) || scripts.empty()) {
        throw HWIError("Unable to expand descriptor", ErrorCode::BAD_ARGUMENT);
    }
    CTxDestination dest;
    if (!ExtractDestination(scripts.at(0), dest)) {
        throw HWIError("Descriptor does not have an address", ErrorCode::BAD_ARGUMENT);
    }
    return EncodeDestination(dest);
}

std::string WrapKeyExpr(OutputType type, const std::string& key_expr)
{
    switch (type) {
    case OutputType::LEGACY:
        return "pkh(" + key_expr + ")";
    case OutputType::P2SH_SEGWIT:
        return "sh(wpkh(" + key_expr + "))";
    case OutputType::BECH32:
        return "wpkh(" + key_expr + ")";
    case OutputType::BECH32M:
        return "tr(" + key_expr + ")";
    case OutputType::UNKNOWN:
        break;
    }
    throw HWIError("Unknown address type", ErrorCode::BAD_ARGUMENT);
}

std::string CanonicalDescriptor(const std::string& desc_str)
{
    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> parsed = Parse(desc_str, keys, error, /*require_checksum=*/false);
    if (parsed.empty()) {
        throw HWIError("Failed to construct descriptor: " + error, ErrorCode::UNKNOWN_ERROR);
    }
    return parsed.at(0)->ToString();
}

CTxDestination DestinationForPubkey(const CPubKey& pubkey, OutputType type)
{
    switch (type) {
    case OutputType::LEGACY:
        return PKHash(pubkey);
    case OutputType::P2SH_SEGWIT:
        return ScriptHash(GetScriptForDestination(WitnessV0KeyHash(pubkey)));
    case OutputType::BECH32:
        return WitnessV0KeyHash(pubkey);
    case OutputType::BECH32M: {
        const XOnlyPubKey internal{pubkey};
        const auto tweaked{internal.CreateTapTweak(/*merkle_root=*/nullptr)};
        if (!tweaked) {
            throw HWIError("Failed to tweak taproot key", ErrorCode::UNKNOWN_ERROR);
        }
        return WitnessV1Taproot(tweaked->first);
    }
    case OutputType::UNKNOWN:
        break;
    }
    throw HWIError("Unknown address type", ErrorCode::BAD_ARGUMENT);
}

} // namespace

HWIError::HWIError(const std::string& msg, ErrorCode code)
    : std::runtime_error(msg), m_code{code} {}

HardwareWalletClient::HardwareWalletClient(std::string path, ChainType chain)
    : m_path{std::move(path)}, m_chain{chain} {}

KeyFingerprint HardwareWalletClient::GetMasterFingerprint() const
{
    return GetPubkeyAtPath("m/0h").fingerprint;
}

CExtPubKey HardwareWalletClient::GetMasterXpub(OutputType type, uint32_t account) const
{
    const std::vector<uint32_t> path{
        BIP44Purpose(type) | BIP32_HARDENED_FLAG,
        BIP44CoinType(m_chain) | BIP32_HARDENED_FLAG,
        account | BIP32_HARDENED_FLAG,
    };
    return GetPubkeyAtPath(WriteHDKeypath(path));
}

std::string HardwareWalletClient::DisplaySinglesigAddress(const std::string& bip32_path, OutputType type) const
{
    const CExtPubKey xpub{GetPubkeyAtPath(bip32_path)};
    return EncodeDestination(DestinationForPubkey(xpub.pubkey, type));
}

std::string HardwareWalletClient::DisplayMultisigAddress(const std::string& descriptor) const
{
    return AddressFromDescriptor(descriptor);
}

std::vector<DeviceInfo> Enumerate()
{
    std::vector<DeviceInfo> devices = EnumerateMockDevices();
    auto append = [&](std::vector<DeviceInfo> extra) {
        devices.insert(devices.end(), extra.begin(), extra.end());
    };
    append(EnumerateColdcard());
    append(EnumerateLedger());
    append(EnumerateTrezor());
    return devices;
}

std::unique_ptr<HardwareWalletClient> FindDevice(const std::string& fingerprint, std::optional<std::string> type)
{
    for (const DeviceInfo& info : Enumerate()) {
        if (!fingerprint.empty() && info.fingerprint != fingerprint) continue;
        if (type && info.type != *type) continue;
        if (info.type == "mock") return ConnectMock(info);
        if (info.type == "coldcard") return ConnectColdcard(info);
        if (info.type == "ledger") return ConnectLedger(info);
        if (info.type == "trezor") return ConnectTrezor(info);
    }
    return nullptr;
}

DescriptorSets GetDescriptors(const HardwareWalletClient& client, int account)
{
    if (account < 0) {
        throw HWIError("Account must be non-negative", ErrorCode::BAD_ARGUMENT);
    }

    DescriptorSets result;
    const std::string fpr{FingerprintHex(client.GetMasterFingerprint())};
    const uint32_t coin{BIP44CoinType(client.GetChain())};

    auto one = [&](OutputType type, bool internal) {
        if (type == OutputType::BECH32M && !client.CanSignTaproot()) return;
        const std::vector<uint32_t> origin{
            BIP44Purpose(type) | BIP32_HARDENED_FLAG,
            coin | BIP32_HARDENED_FLAG,
            static_cast<uint32_t>(account) | BIP32_HARDENED_FLAG,
        };
        const CExtPubKey xpub{client.GetPubkeyAtPath(WriteHDKeypath(origin))};
        const std::string key_expr{strprintf("[%s%s]%s/%u/*",
                                             fpr,
                                             FormatHDKeypath(origin),
                                             EncodeExtPubKey(xpub),
                                             internal ? 1u : 0u)};
        const std::string desc{CanonicalDescriptor(WrapKeyExpr(type, key_expr))};
        if (internal) {
            result.internal.push_back(desc);
        } else {
            result.receive.push_back(desc);
        }
    };

    for (bool internal : {false, true}) {
        for (OutputType type : OUTPUT_TYPES) {
            if (type == OutputType::UNKNOWN) continue;
            one(type, internal);
        }
    }
    return result;
}

std::string DisplayAddress(const HardwareWalletClient& client, const std::string& descriptor)
{
    FlatSigningProvider provider;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> parsed = Parse(descriptor, provider, error, /*require_checksum=*/false);
    if (parsed.empty()) {
        throw HWIError("Invalid descriptor: " + error, ErrorCode::BAD_ARGUMENT);
    }

    std::vector<CScript> scripts;
    FlatSigningProvider out;
    if (!parsed.at(0)->Expand(/*pos=*/0, provider, scripts, out) || scripts.empty()) {
        throw HWIError("Unable to expand descriptor", ErrorCode::BAD_ARGUMENT);
    }

    const KeyFingerprint master{client.GetMasterFingerprint()};
    bool ours = false;
    for (const auto& [id, origin_pair] : out.origins) {
        const KeyOriginInfo& origin = origin_pair.second;
        if (origin.fingerprint != master) continue;
        ours = true;
        const CExtPubKey derived{client.GetPubkeyAtPath(WriteHDKeypath(origin.path))};
        const bool match_compressed{derived.pubkey.GetID() == id};
        const bool match_xonly{origin_pair.first.IsValid() && XOnlyPubKey(derived.pubkey) == XOnlyPubKey(origin_pair.first)};
        if (!match_compressed && !match_xonly) {
            throw HWIError("Key in descriptor does not match device", ErrorCode::BAD_ARGUMENT);
        }
    }
    if (!ours && !out.origins.empty()) {
        throw HWIError("Descriptor fingerprint does not match device", ErrorCode::BAD_ARGUMENT);
    }

    CTxDestination dest;
    if (!ExtractDestination(scripts.at(0), dest)) {
        throw HWIError("Descriptor does not have an address", ErrorCode::BAD_ARGUMENT);
    }
    return EncodeDestination(dest);
}

uint32_t BIP44Purpose(OutputType type)
{
    switch (type) {
    case OutputType::LEGACY:
        return 44;
    case OutputType::P2SH_SEGWIT:
        return 49;
    case OutputType::BECH32:
        return 84;
    case OutputType::BECH32M:
        return 86;
    case OutputType::UNKNOWN:
        break;
    }
    throw HWIError("Unknown address type", ErrorCode::BAD_ARGUMENT);
}

uint32_t BIP44CoinType(ChainType chain)
{
    return chain == ChainType::MAIN ? 0 : 1;
}

std::string FingerprintHex(const KeyFingerprint& fingerprint)
{
    return HexStr(fingerprint);
}

} // namespace hwi
