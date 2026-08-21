// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_COLDCARD_H
#define BITCOIN_HWI_COLDCARD_H

#include <hwi/hwi.h>
#include <hwi/transport.h>

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace hwi {

inline constexpr uint16_t COINKITE_VID = 0xd13e;
inline constexpr uint16_t CKCC_PID = 0xcc10;

//! Parsed `vers` body (newline fields). Mk3 4.2.0 is date/version/bootloader/
//! timestamp/`mk3`. EDGE firmware sets `is_edge` when the human version ends
//! in `X` (Python HWI `firmware_version()[1][-1] == "X"`).
struct ColdcardVersion {
    std::string date;
    std::string version;
    std::string bootloader;
    std::string timestamp;
    std::string hw_label;
    bool is_edge{false};
};

ColdcardVersion ParseColdcardVersion(std::string_view text);
std::string ColdcardModelName(const ColdcardVersion& version);

std::vector<DeviceInfo> EnumerateColdcard();
std::unique_ptr<HardwareWalletClient> ConnectColdcard(const DeviceInfo& info);

} // namespace hwi

#endif // BITCOIN_HWI_COLDCARD_H
