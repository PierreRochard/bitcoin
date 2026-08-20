// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_TRANSPORT_H
#define BITCOIN_HWI_TRANSPORT_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hwi {

//! Paths used by vendor emulators (Python HWI uses the same strings).
inline constexpr std::string_view TREZOR_UDP_DEFAULT_PATH{"udp:127.0.0.1:21324"};
inline constexpr std::string_view LEDGER_TCP_DEFAULT_PATH{"tcp:127.0.0.1:9999"};
inline constexpr std::string_view COLDCARD_UNIX_DEFAULT_PATH{"/tmp/ckcc-simulator.sock"};
inline constexpr uint16_t TREZOR_UDP_DEFAULT_PORT = 21324;
inline constexpr uint16_t LEDGER_TCP_DEFAULT_PORT = 9999;

struct HostPort {
    std::string host;
    uint16_t port{0};
};

bool IsUdpPath(std::string_view path);
bool IsTcpPath(std::string_view path);
bool IsUnixSocketPath(std::string_view path);

//! `udp:host:port` (prefix required).
std::optional<HostPort> ParseUdpPath(std::string_view path);
//! `tcp:host:port` (prefix required).
std::optional<HostPort> ParseTcpPath(std::string_view path);
//! Strip an optional `unix:` prefix.
std::string UnixSocketPath(std::string_view path);

//! Override via HWI_TREZOR_UDP / HWI_LEDGER_TCP / HWI_COLDCARD_SOCK. Empty env disables probing.
std::string DefaultTrezorUdpPath();
std::string DefaultLedgerTcpPath();
std::string DefaultColdcardUnixPath();

//! 64-byte HID-style packets. Trezor HID/UDP and Coldcard HID/unix all speak this.
class PacketLink
{
public:
    virtual ~PacketLink() = default;
    virtual void Write(const std::vector<unsigned char>& pkt) = 0;
    //! Empty vector means timeout.
    virtual std::vector<unsigned char> Read(int timeout_ms) = 0;
    virtual void Close() = 0;
};

std::unique_ptr<PacketLink> OpenPacketLinkHid(const std::string& path);
std::unique_ptr<PacketLink> OpenPacketLinkUdp(const std::string& host, uint16_t port);
std::unique_ptr<PacketLink> OpenPacketLinkUnixDgram(const std::string& path);

//! Trezor emulator: send `PINGPING`, expect `PONGPONG`.
bool TrezorUdpPing(const std::string& host, uint16_t port, int timeout_ms = 200);
bool TrezorUdpAvailable(std::string_view path = TREZOR_UDP_DEFAULT_PATH);

//! Speculos APDU over TCP: 4-byte BE length + APDU; reply is length + data + 2-byte SW.
class TcpApduLink
{
public:
    TcpApduLink(const std::string& host, uint16_t port);
    ~TcpApduLink();
    TcpApduLink(const TcpApduLink&) = delete;
    TcpApduLink& operator=(const TcpApduLink&) = delete;

    std::pair<uint16_t, std::vector<unsigned char>> Exchange(const std::vector<unsigned char>& apdu,
                                                             int timeout_ms = 30000);
    void Close();
    bool IsOpen() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

bool LedgerTcpAvailable(std::string_view path = LEDGER_TCP_DEFAULT_PATH);
bool ColdcardSimulatorAvailable(std::string_view path = COLDCARD_UNIX_DEFAULT_PATH);

} // namespace hwi

#endif // BITCOIN_HWI_TRANSPORT_H
