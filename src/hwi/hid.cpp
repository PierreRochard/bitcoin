// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <hwi/hid.h>

#include <hwi/hwi.h>

#include <mutex>
#include <string>
#include <vector>

#ifdef ENABLE_HWI_USB
#if defined(__has_include)
#if __has_include(<hidapi/hidapi.h>)
#include <hidapi/hidapi.h>
#else
#include <hidapi.h>
#endif
#else
#include <hidapi.h>
#endif
#endif

namespace hwi {
namespace {

#ifdef ENABLE_HWI_USB
std::once_flag g_hid_once;

void EnsureHid()
{
    std::call_once(g_hid_once, [] {
        if (hid_init() != 0) {
            throw HWIError("hid_init failed", ErrorCode::DEVICE_CONN_ERROR);
        }
    });
}

std::string FromWChar(const wchar_t* w)
{
    if (!w) return {};
    std::string out;
    for (const wchar_t* p = w; *p; ++p) {
        if (*p < 0x80) out.push_back(static_cast<char>(*p));
    }
    return out;
}
#endif

} // namespace

bool HidAvailable()
{
#ifdef ENABLE_HWI_USB
    return true;
#else
    return false;
#endif
}

std::vector<HidInfo> EnumerateHid(uint16_t vendor_id, uint16_t product_id)
{
#ifdef ENABLE_HWI_USB
    EnsureHid();
    hid_device_info* list = hid_enumerate(vendor_id, product_id);
    std::vector<HidInfo> out;
    for (hid_device_info* info = list; info; info = info->next) {
        HidInfo item;
        item.path = info->path ? info->path : "";
        item.serial = FromWChar(info->serial_number);
        item.manufacturer = FromWChar(info->manufacturer_string);
        item.product = FromWChar(info->product_string);
        item.vendor_id = info->vendor_id;
        item.product_id = info->product_id;
        item.interface_number = info->interface_number;
        item.usage_page = info->usage_page;
        out.push_back(std::move(item));
    }
    hid_free_enumeration(list);
    return out;
#else
    (void)vendor_id;
    (void)product_id;
    return {};
#endif
}

HidConnection::HidConnection(const std::string& path) : m_path{path}
{
#ifdef ENABLE_HWI_USB
    EnsureHid();
    m_dev = hid_open_path(path.c_str());
    if (!m_dev) {
        throw HWIError("Failed to open HID device " + path, ErrorCode::DEVICE_CONN_ERROR);
    }
#else
    throw HWIError("USB hardware wallet support was not compiled (hidapi missing)", ErrorCode::DEVICE_CONN_ERROR);
#endif
}

HidConnection::~HidConnection()
{
    Close();
}

void HidConnection::Close()
{
#ifdef ENABLE_HWI_USB
    if (m_dev) {
        hid_close(static_cast<hid_device*>(m_dev));
        m_dev = nullptr;
    }
#endif
}

void HidConnection::Write(const std::vector<unsigned char>& report64)
{
#ifdef ENABLE_HWI_USB
    if (!m_dev) throw HWIError("HID device closed", ErrorCode::DEVICE_CONN_ERROR);
    std::vector<unsigned char> buf;
    buf.reserve(report64.size() + 1);
    buf.push_back(0x00); // report id
    buf.insert(buf.end(), report64.begin(), report64.end());
    const int n = hid_write(static_cast<hid_device*>(m_dev), buf.data(), buf.size());
    if (n < 0) {
        throw HWIError("HID write failed", ErrorCode::DEVICE_CONN_ERROR);
    }
#else
    (void)report64;
#endif
}

std::vector<unsigned char> HidConnection::Read(int timeout_ms)
{
#ifdef ENABLE_HWI_USB
    if (!m_dev) throw HWIError("HID device closed", ErrorCode::DEVICE_CONN_ERROR);
    unsigned char buf[65] = {};
    const int n = hid_read_timeout(static_cast<hid_device*>(m_dev), buf, sizeof(buf), timeout_ms);
    if (n < 0) {
        throw HWIError("HID read failed", ErrorCode::DEVICE_CONN_ERROR);
    }
    if (n == 0) return {};
    return {buf, buf + n};
#else
    (void)timeout_ms;
    return {};
#endif
}

std::string HidConnection::Serial() const
{
#ifdef ENABLE_HWI_USB
    if (!m_dev) return {};
    wchar_t serial[256] = {};
    if (hid_get_serial_number_string(static_cast<hid_device*>(m_dev), serial, 256) != 0) {
        return {};
    }
    return FromWChar(serial);
#else
    return {};
#endif
}

} // namespace hwi
