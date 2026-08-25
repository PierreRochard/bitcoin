// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_MOCK_H
#define BITCOIN_HWI_MOCK_H

#include <hwi/hwi.h>
#include <key.h>
#include <span.h>
#include <util/chaintype.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace hwi {

//! BIP32 test vector 1 seed. Deterministic, well-known, never use with value.
inline constexpr std::string_view MOCK_SEED_HEX{"000102030405060708090a0b0c0d0e0f"};

CExtKey MakeMockMaster(std::span<const std::byte> seed);
CExtKey MakeMockMasterFromHex(std::string_view hex_seed = MOCK_SEED_HEX);

//! Per-registration fault and capability controls for discovery tests.
struct MockDeviceOptions {
    std::string model{"Mock Trezor"};
    bool locked{false};
    bool needs_pin{false};
    bool needs_passphrase{false};
    bool can_sign_taproot{true};
    bool can_sign_musig2{true};
    bool can_display_multisig_address{true};
    bool enumerate_throws{false};
    std::optional<std::string> enumerate_error;
    std::optional<std::string> connect_error;
    std::optional<std::string> account_xpub_error;
    std::optional<std::string> display_address_error;
    std::optional<std::string> displayed_address_override;
    //! Test-only malicious signer seam: return a PSBT for a different
    //! unsigned transaction after accepting the original PSBT.
    bool mutate_unsigned_transaction{false};
    //! Test-only malicious signer seam: contribute signatures for another
    //! participant while connected under this device's authorized identity.
    std::optional<CExtKey> additional_signing_master;
    //! Test-only collision seam: enumeration reports this fingerprint while
    //! the connected client still exposes the master's real key identity.
    std::optional<std::string> fingerprint_override;
};

//! RAII registration of a software "hardware wallet" that Enumerate() and
//! FindDevice() can see. Used by unit tests and (later) functional tests so
//! wallet/GUI work does not require USB hardware.
class MockRegistration
{
public:
    explicit MockRegistration(CExtKey master, ChainType chain = ChainType::MAIN, MockDeviceOptions options = {});
    ~MockRegistration();

    MockRegistration(const MockRegistration&) = delete;
    MockRegistration& operator=(const MockRegistration&) = delete;

    const std::string& Path() const { return m_path; }
    const std::string& Fingerprint() const { return m_fingerprint; }
    std::unique_ptr<HardwareWalletClient> Connect() const;

private:
    std::string m_path;
    std::string m_fingerprint;
};

std::vector<DeviceInfo> EnumerateMockDevices();
std::unique_ptr<HardwareWalletClient> ConnectMock(const DeviceInfo& info);
//! Test-only: reverse mock enumeration without changing paths or identities.
//! Callers must reverse again during teardown.
void ReverseMockEnumerationOrder();
//! True while a UsbEnumerateSuppress is alive (mock-only unit tests).
bool UsbEnumerateSuppressed();

//! RAII: Enumerate() returns only mock devices. Lets wallet unit tests assert
//! "signer unplugged" without a live Coldcard/Ledger/Trezor changing the set.
class UsbEnumerateSuppress
{
public:
    UsbEnumerateSuppress();
    ~UsbEnumerateSuppress();
    UsbEnumerateSuppress(const UsbEnumerateSuppress&) = delete;
    UsbEnumerateSuppress& operator=(const UsbEnumerateSuppress&) = delete;
};

} // namespace hwi

#endif // BITCOIN_HWI_MOCK_H
