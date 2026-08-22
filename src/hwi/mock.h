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
#include <string>
#include <string_view>
#include <vector>

namespace hwi {

//! BIP32 test vector 1 seed. Deterministic, well-known, never use with value.
inline constexpr std::string_view MOCK_SEED_HEX{"000102030405060708090a0b0c0d0e0f"};

CExtKey MakeMockMaster(std::span<const std::byte> seed);
CExtKey MakeMockMasterFromHex(std::string_view hex_seed = MOCK_SEED_HEX);

//! RAII registration of a software "hardware wallet" that Enumerate() and
//! FindDevice() can see. Used by unit tests and (later) functional tests so
//! wallet/GUI work does not require USB hardware.
class MockRegistration
{
public:
    explicit MockRegistration(CExtKey master, ChainType chain = ChainType::MAIN);
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
