// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_COLDCARD_H
#define BITCOIN_HWI_COLDCARD_H

#include <hwi/hwi.h>
#include <hwi/transport.h>

#include <memory>
#include <vector>

namespace hwi {

inline constexpr uint16_t COINKITE_VID = 0xd13e;
inline constexpr uint16_t CKCC_PID = 0xcc10;

std::vector<DeviceInfo> EnumerateColdcard();
std::unique_ptr<HardwareWalletClient> ConnectColdcard(const DeviceInfo& info);

} // namespace hwi

#endif // BITCOIN_HWI_COLDCARD_H
