// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_LEDGER_H
#define BITCOIN_HWI_LEDGER_H

#include <hwi/hwi.h>
#include <hwi/transport.h>

#include <memory>
#include <vector>

namespace hwi {

inline constexpr uint16_t LEDGER_VID = 0x2c97;

std::vector<DeviceInfo> EnumerateLedger();
std::unique_ptr<HardwareWalletClient> ConnectLedger(const DeviceInfo& info);

} // namespace hwi

#endif // BITCOIN_HWI_LEDGER_H
