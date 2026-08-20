// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_HID_H
#define BITCOIN_HWI_HID_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hwi {

struct HidInfo {
    std::string path;
    std::string serial;
    std::string manufacturer;
    std::string product;
    uint16_t vendor_id{0};
    uint16_t product_id{0};
    int interface_number{-1};
    uint16_t usage_page{0};
};

//! True when hidapi was found at configure time.
bool HidAvailable();

std::vector<HidInfo> EnumerateHid(uint16_t vendor_id = 0, uint16_t product_id = 0);

//! Open HID connection. Report-ID 0 is prepended on write (USB HID convention).
class HidConnection
{
public:
    explicit HidConnection(const std::string& path);
    ~HidConnection();

    HidConnection(const HidConnection&) = delete;
    HidConnection& operator=(const HidConnection&) = delete;

    void Write(const std::vector<unsigned char>& report64);
    std::vector<unsigned char> Read(int timeout_ms);
    std::string Serial() const;
    const std::string& Path() const { return m_path; }
    bool IsOpen() const { return m_dev != nullptr; }
    void Close();

private:
    std::string m_path;
    void* m_dev{nullptr};
};

} // namespace hwi

#endif // BITCOIN_HWI_HID_H
