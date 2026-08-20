// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/mock.h>

#include <common/signmessage.h>
#include <common/types.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/keyorigin.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <utility>
#include <vector>

namespace hwi {
namespace {

GlobalMutex g_mocks_mutex;
int g_next_mock_id GUARDED_BY(g_mocks_mutex){0};

struct MockRecord {
    std::string path;
    CExtKey master;
    ChainType chain;
    std::string fingerprint;
};

std::vector<MockRecord> g_mocks GUARDED_BY(g_mocks_mutex);

CExtPubKey DeriveXpub(const CExtKey& master, const std::string& bip32_path)
{
    std::vector<uint32_t> path;
    if (!ParseHDKeypath(bip32_path, path)) {
        throw HWIError("Invalid BIP32 path: " + bip32_path, ErrorCode::BAD_ARGUMENT);
    }
    auto derived = DeriveExtKey(master, path);
    if (!derived) {
        throw HWIError("Failed to derive " + bip32_path, ErrorCode::BAD_ARGUMENT);
    }
    return derived->first.Neuter();
}

class MockHardwareWallet final : public HardwareWalletClient
{
public:
    MockHardwareWallet(std::string path, CExtKey master, ChainType chain)
        : HardwareWalletClient(std::move(path), chain), m_master{std::move(master)}
    {
    }

    std::string Type() const override { return "mock"; }

    CExtPubKey GetPubkeyAtPath(const std::string& bip32_path) const override
    {
        return DeriveXpub(m_master, bip32_path);
    }

    PartiallySignedTransaction SignTx(PartiallySignedTransaction psbt) const override
    {
        const KeyFingerprint master_fpr{m_master.id_key_fingerprint()};
        FlatSigningProvider provider;

        auto add_origin = [&](const KeyOriginInfo& origin, const CPubKey* expected_pubkey, const XOnlyPubKey* expected_xonly) {
            if (origin.fingerprint != master_fpr) return false;
            auto derived = DeriveExtKey(m_master, origin.path);
            if (!derived) {
                throw HWIError("Failed to derive signing key", ErrorCode::BAD_ARGUMENT);
            }
            const CKey& key = derived->first.key;
            const CPubKey derived_pub{key.GetPubKey()};
            if (expected_pubkey && expected_pubkey->IsValid() && derived_pub != *expected_pubkey) {
                throw HWIError("Derived key does not match PSBT origin", ErrorCode::INVALID_TX);
            }
            if (expected_xonly && XOnlyPubKey(derived_pub) != *expected_xonly) {
                throw HWIError("Derived taproot key does not match PSBT origin", ErrorCode::INVALID_TX);
            }
            const CKeyID id{derived_pub.GetID()};
            provider.keys[id] = key;
            provider.pubkeys[id] = derived_pub;
            provider.origins[id] = {derived_pub, origin};
            return true;
        };

        bool have_key = false;
        for (const PSBTInput& input : psbt.inputs) {
            for (const auto& [pubkey, origin] : input.hd_keypaths) {
                have_key |= add_origin(origin, &pubkey, nullptr);
            }
            for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
                have_key |= add_origin(leaf_origin.second, nullptr, &xonly);
            }
        }
        if (!have_key) {
            throw HWIError("Signer fingerprint does not match any PSBT input", ErrorCode::INVALID_TX);
        }

        std::optional<PrecomputedTransactionData> txdata = PrecomputePSBTData(psbt);
        const common::PSBTFillOptions options{
            .sign = true,
            .finalize = false,
            .bip32_derivs = true,
        };
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            const PSBTError err = SignPSBTInput(provider, psbt, static_cast<int>(i),
                                                txdata ? &*txdata : nullptr, options);
            if (err != PSBTError::OK && err != PSBTError::INCOMPLETE) {
                throw HWIError("Failed to sign PSBT input", ErrorCode::INVALID_TX);
            }
        }
        return psbt;
    }

    std::string SignMessage(const std::string& message, const std::string& bip32_path) const override
    {
        std::vector<uint32_t> path;
        if (!ParseHDKeypath(bip32_path, path)) {
            throw HWIError("Invalid BIP32 path: " + bip32_path, ErrorCode::BAD_ARGUMENT);
        }
        auto derived = DeriveExtKey(m_master, path);
        if (!derived) {
            throw HWIError("Failed to derive " + bip32_path, ErrorCode::BAD_ARGUMENT);
        }
        std::string signature;
        if (!MessageSign(derived->first.key, message, signature)) {
            throw HWIError("Message signing failed", ErrorCode::UNKNOWN_ERROR);
        }
        return signature;
    }

    bool CanSignTaproot() const override { return true; }
    void Close() override {}

    KeyFingerprint GetMasterFingerprint() const override
    {
        return m_master.id_key_fingerprint();
    }

private:
    CExtKey m_master;
};

} // namespace

CExtKey MakeMockMaster(std::span<const std::byte> seed)
{
    CExtKey key;
    key.SetSeed(seed);
    return key;
}

CExtKey MakeMockMasterFromHex(std::string_view hex_seed)
{
    const std::vector<std::byte> seed{ParseHex<std::byte>(hex_seed)};
    if (seed.size() < 16) {
        throw HWIError("Mock seed must be at least 16 bytes", ErrorCode::BAD_ARGUMENT);
    }
    return MakeMockMaster(seed);
}

MockRegistration::MockRegistration(CExtKey master, ChainType chain)
{
    LOCK(g_mocks_mutex);
    m_path = strprintf("mock:%d", g_next_mock_id++);
    m_fingerprint = FingerprintHex(master.id_key_fingerprint());
    g_mocks.push_back(MockRecord{m_path, std::move(master), chain, m_fingerprint});
}

MockRegistration::~MockRegistration()
{
    LOCK(g_mocks_mutex);
    std::erase_if(g_mocks, [&](const MockRecord& record) { return record.path == m_path; });
}

std::unique_ptr<HardwareWalletClient> MockRegistration::Connect() const
{
    DeviceInfo info;
    info.type = "mock";
    info.path = m_path;
    info.fingerprint = m_fingerprint;
    return ConnectMock(info);
}

std::vector<DeviceInfo> EnumerateMockDevices()
{
    LOCK(g_mocks_mutex);
    std::vector<DeviceInfo> result;
    result.reserve(g_mocks.size());
    for (const MockRecord& record : g_mocks) {
        DeviceInfo info;
        info.type = "mock";
        info.model = "mock";
        info.path = record.path;
        info.fingerprint = record.fingerprint;
        result.push_back(std::move(info));
    }
    return result;
}

std::unique_ptr<HardwareWalletClient> ConnectMock(const DeviceInfo& info)
{
    LOCK(g_mocks_mutex);
    for (const MockRecord& record : g_mocks) {
        if (record.path == info.path || (!info.fingerprint.empty() && record.fingerprint == info.fingerprint)) {
            return std::make_unique<MockHardwareWallet>(record.path, record.master, record.chain);
        }
    }
    throw HWIError("Mock device not found", ErrorCode::DEVICE_CONN_ERROR);
}

} // namespace hwi
