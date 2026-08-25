// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/mock.h>

#include <common/signmessage.h>
#include <common/types.h>
#include <musig.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/keyorigin.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <atomic>
#include <map>
#include <memory>
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
    MockDeviceOptions options;
    // Secret nonces must survive the nonce round so the next SignTx can
    // produce a MuSig2 partial signature (BIP 327).
    std::map<uint256, MuSig2SecNonce> musig2_secnonces;
};

std::vector<std::unique_ptr<MockRecord>> g_mocks GUARDED_BY(g_mocks_mutex);
std::atomic<int> g_usb_enumerate_suppress{0};

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
    MockHardwareWallet(std::string path, CExtKey master, ChainType chain, MockDeviceOptions options)
        : HardwareWalletClient(std::move(path), chain), m_master{std::move(master)}, m_options{std::move(options)}
    {
    }

    std::string Type() const override { return "mock"; }

    CExtPubKey GetPubkeyAtPath(const std::string& bip32_path) const override
    {
        if (m_options.account_xpub_error) {
            throw HWIError(*m_options.account_xpub_error, ErrorCode::DEVICE_CONN_ERROR);
        }
        return DeriveXpub(m_master, bip32_path);
    }

    PartiallySignedTransaction SignTx(PartiallySignedTransaction psbt) const override
    {
        const KeyFingerprint master_fpr{m_master.id_key_fingerprint()};
        FlatSigningProvider provider;

        auto add_origin = [&](const CExtKey& signing_master, const KeyFingerprint& signing_fpr,
                              const KeyOriginInfo& origin, const CPubKey* expected_pubkey,
                              const XOnlyPubKey* expected_xonly) {
            if (origin.fingerprint != signing_fpr) return false;
            auto derived = DeriveExtKey(signing_master, origin.path);
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
                have_key |= add_origin(m_master, master_fpr, origin, &pubkey, nullptr);
                if (m_options.additional_signing_master) {
                    have_key |= add_origin(*m_options.additional_signing_master,
                                           m_options.additional_signing_master->id_key_fingerprint(),
                                           origin, &pubkey, nullptr);
                }
            }
            for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
                have_key |= add_origin(m_master, master_fpr, leaf_origin.second, nullptr, &xonly);
                if (m_options.additional_signing_master) {
                    have_key |= add_origin(*m_options.additional_signing_master,
                                           m_options.additional_signing_master->id_key_fingerprint(),
                                           leaf_origin.second, nullptr, &xonly);
                }
            }
        }
        if (!have_key) {
            throw HWIError("Signer fingerprint does not match any PSBT input", ErrorCode::INVALID_TX);
        }

        if (m_options.mutate_unsigned_transaction) {
            auto mutated{psbt.GetUnsignedTx()};
            if (!mutated || mutated->vout.empty()) {
                throw HWIError("Cannot mutate this PSBT", ErrorCode::INVALID_TX);
            }
            ++mutated->vout.front().nValue;
            return PartiallySignedTransaction{*mutated};
        }

        for (const PSBTInput& input : psbt.inputs) {
            provider.aggregate_pubkeys.insert(input.m_musig2_participants.begin(), input.m_musig2_participants.end());
        }

        {
            LOCK(g_mocks_mutex);
            for (auto& record : g_mocks) {
                if (record->path == m_path) {
                    provider.musig2_secnonces = &record->musig2_secnonces;
                    break;
                }
            }
        }
        if (!provider.musig2_secnonces) {
            throw HWIError("Mock device not found", ErrorCode::DEVICE_CONN_ERROR);
        }

        std::optional<PrecomputedTransactionData> txdata = PrecomputePSBTData(psbt);
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            const common::PSBTFillOptions options{
                .sign = true,
                .sighash_type = psbt.inputs[i].sighash_type,
                .finalize = false,
                .bip32_derivs = true,
            };
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

    bool CanSignTaproot() const override { return m_options.can_sign_taproot; }
    bool CanSignMuSig2() const override { return m_options.can_sign_musig2; }
    bool CanDisplayMultisigAddress() const override { return m_options.can_display_multisig_address; }
    std::string DisplayMultisigAddress(const std::string& descriptor) const override
    {
        if (m_options.display_address_error) {
            throw HWIError(*m_options.display_address_error, ErrorCode::UNKNOWN_ERROR);
        }
        if (m_options.displayed_address_override) return *m_options.displayed_address_override;
        return AddressFromDescriptor(descriptor);
    }
    void Close() override {}

    KeyFingerprint GetMasterFingerprint() const override
    {
        return m_master.id_key_fingerprint();
    }

private:
    CExtKey m_master;
    MockDeviceOptions m_options;
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

MockRegistration::MockRegistration(CExtKey master, ChainType chain, MockDeviceOptions options)
{
    LOCK(g_mocks_mutex);
    m_path = strprintf("mock:%d", g_next_mock_id++);
    m_fingerprint = options.fingerprint_override.value_or(
        FingerprintHex(master.id_key_fingerprint()));
    auto rec = std::make_unique<MockRecord>();
    rec->path = m_path;
    rec->master = std::move(master);
    rec->chain = chain;
    rec->fingerprint = m_fingerprint;
    rec->options = std::move(options);
    g_mocks.push_back(std::move(rec));
}

MockRegistration::~MockRegistration()
{
    LOCK(g_mocks_mutex);
    std::erase_if(g_mocks, [&](const std::unique_ptr<MockRecord>& record) { return record->path == m_path; });
}

std::unique_ptr<HardwareWalletClient> MockRegistration::Connect() const
{
    DeviceInfo info;
    info.type = "mock";
    info.path = m_path;
    info.fingerprint = m_fingerprint;
    return ConnectMock(info);
}

bool UsbEnumerateSuppressed()
{
    return g_usb_enumerate_suppress.load(std::memory_order_acquire) > 0;
}

UsbEnumerateSuppress::UsbEnumerateSuppress()
{
    g_usb_enumerate_suppress.fetch_add(1, std::memory_order_acq_rel);
}

UsbEnumerateSuppress::~UsbEnumerateSuppress()
{
    g_usb_enumerate_suppress.fetch_sub(1, std::memory_order_acq_rel);
}

std::vector<DeviceInfo> EnumerateMockDevices()
{
    LOCK(g_mocks_mutex);
    std::vector<DeviceInfo> result;
    result.reserve(g_mocks.size());
    for (const auto& record : g_mocks) {
        if (record->options.enumerate_throws) {
            throw HWIError("Injected mock enumeration failure", ErrorCode::DEVICE_CONN_ERROR);
        }
        DeviceInfo info;
        info.type = "mock";
        info.model = record->options.model;
        info.path = record->path;
        if (!record->options.locked) info.fingerprint = record->fingerprint;
        info.needs_pin = record->options.needs_pin;
        info.needs_passphrase = record->options.needs_passphrase;
        info.error = record->options.enumerate_error;
        result.push_back(std::move(info));
    }
    return result;
}

void ReverseMockEnumerationOrder()
{
    LOCK(g_mocks_mutex);
    std::reverse(g_mocks.begin(), g_mocks.end());
}

std::unique_ptr<HardwareWalletClient> ConnectMock(const DeviceInfo& info)
{
    LOCK(g_mocks_mutex);
    auto connect = [](const MockRecord& record) -> std::unique_ptr<HardwareWalletClient> {
        if (record.options.connect_error) {
            throw HWIError(*record.options.connect_error, ErrorCode::DEVICE_CONN_ERROR);
        }
        return std::make_unique<MockHardwareWallet>(record.path, record.master, record.chain, record.options);
    };
    if (!info.path.empty()) {
        for (const auto& record : g_mocks) {
            if (record->path == info.path) return connect(*record);
        }
    }
    if (!info.fingerprint.empty()) {
        for (const auto& record : g_mocks) {
            if (record->fingerprint == info.fingerprint) return connect(*record);
        }
    }
    throw HWIError("Mock device not found", ErrorCode::DEVICE_CONN_ERROR);
}

} // namespace hwi
