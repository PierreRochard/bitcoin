// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_TREZOR_H
#define BITCOIN_HWI_TREZOR_H

#include <hwi/hwi.h>
#include <hwi/transport.h>

#include <memory>
#include <utility>
#include <vector>

namespace hwi {

inline constexpr std::pair<uint16_t, uint16_t> TREZOR1_ID{0x534c, 0x0001};
inline constexpr std::pair<uint16_t, uint16_t> TREZOR2_ID{0x1209, 0x53c1};
inline constexpr std::pair<uint16_t, uint16_t> TREZOR2_BL_ID{0x1209, 0x53c0};

std::vector<DeviceInfo> EnumerateTrezor();
std::unique_ptr<HardwareWalletClient> ConnectTrezor(const DeviceInfo& info);

//! Load a BIP39 mnemonic onto a debug-build Trezor UDP emulator. HID paths are rejected.
void TrezorEmulatorLoadMnemonic(const std::string& path, const std::string& mnemonic);

} // namespace hwi

#endif // BITCOIN_HWI_TREZOR_H
