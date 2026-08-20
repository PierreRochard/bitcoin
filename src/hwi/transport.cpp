// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/transport.h>

#include <compat/compat.h>
#include <hwi/hid.h>
#include <hwi/hwi.h>
#include <tinyformat.h>
#include <util/sock.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef WIN32
#include <sys/un.h>
#include <unistd.h>
#endif

namespace hwi {
namespace {

constexpr const char* TREZOR_PING = "PINGPING";
constexpr const char* TREZOR_PONG = "PONGPONG";

bool StartsWithIgnoreCase(std::string_view s, std::string_view prefix)
{
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        char a = s[i];
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
        if (a != b) return false;
    }
    return true;
}

std::string EnvOr(const char* key, std::string_view fallback)
{
    if (const char* v = std::getenv(key)) return v;
    return std::string{fallback};
}

std::optional<HostPort> ParsePrefixedHostPort(std::string_view path, std::string_view prefix, uint16_t default_port)
{
    if (!StartsWithIgnoreCase(path, prefix)) return std::nullopt;
    std::string rest{path.substr(prefix.size())};
    HostPort out;
    out.port = default_port;
    const auto colon = rest.rfind(':');
    if (colon == std::string::npos) {
        out.host = rest.empty() ? "127.0.0.1" : rest;
    } else {
        out.host = rest.substr(0, colon);
        if (out.host.empty()) out.host = "127.0.0.1";
        try {
            const int p = std::stoi(rest.substr(colon + 1));
            if (p <= 0 || p > 65535) return std::nullopt;
            out.port = static_cast<uint16_t>(p);
        } catch (...) {
            return std::nullopt;
        }
    }
    if (out.host.empty()) out.host = "127.0.0.1";
    return out;
}

std::unique_ptr<Sock> ConnectInet(int socktype, int protocol, const std::string& host, uint16_t port)
{
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    addrinfo* res = nullptr;
    const std::string port_s = strprintf("%u", port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0 || !res) {
        throw HWIError("Failed to resolve " + host, ErrorCode::DEVICE_CONN_ERROR);
    }
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(res, freeaddrinfo);
    SOCKET fd = static_cast<SOCKET>(socket(res->ai_family, res->ai_socktype, res->ai_protocol));
    if (fd == INVALID_SOCKET) {
        throw HWIError("socket() failed", ErrorCode::DEVICE_CONN_ERROR);
    }
    auto sock = std::make_unique<Sock>(fd);
    if (sock->Connect(res->ai_addr, res->ai_addrlen) != 0) {
        throw HWIError(strprintf("Failed to connect to %s:%u", host, port), ErrorCode::DEVICE_CONN_ERROR);
    }
    return sock;
}

bool WaitRecv(Sock& sock, int timeout_ms)
{
    Sock::Event occurred = 0;
    if (!sock.Wait(std::chrono::milliseconds{timeout_ms}, Sock::RecvEvent, &occurred)) {
        return false;
    }
    return (occurred & Sock::RecvEvent) != 0;
}

void SendAll(Sock& sock, const unsigned char* data, size_t len, int timeout_ms)
{
    size_t sent = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
    while (sent < len) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            throw HWIError("Timeout sending to device", ErrorCode::DEVICE_CONN_ERROR);
        }
        Sock::Event occurred = 0;
        if (!sock.Wait(left, Sock::SendEvent, &occurred)) {
            throw HWIError("Wait for send failed", ErrorCode::DEVICE_CONN_ERROR);
        }
        if (!(occurred & Sock::SendEvent)) {
            throw HWIError("Timeout sending to device", ErrorCode::DEVICE_CONN_ERROR);
        }
        const ssize_t n = sock.Send(data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            const int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            throw HWIError("Send failed: " + NetworkErrorString(err), ErrorCode::DEVICE_CONN_ERROR);
        }
        if (n == 0) {
            throw HWIError("Connection closed while sending", ErrorCode::DEVICE_CONN_ERROR);
        }
        sent += static_cast<size_t>(n);
    }
}

std::vector<unsigned char> RecvExact(Sock& sock, size_t len, int timeout_ms)
{
    std::vector<unsigned char> out(len);
    size_t got = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
    while (got < len) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            throw HWIError("Timeout reading from device", ErrorCode::DEVICE_CONN_ERROR);
        }
        if (!WaitRecv(sock, static_cast<int>(left.count()))) {
            throw HWIError("Timeout reading from device", ErrorCode::DEVICE_CONN_ERROR);
        }
        const ssize_t n = sock.Recv(out.data() + got, len - got, 0);
        if (n < 0) {
            const int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            throw HWIError("Recv failed: " + NetworkErrorString(err), ErrorCode::DEVICE_CONN_ERROR);
        }
        if (n == 0) {
            throw HWIError("Connection closed while reading", ErrorCode::DEVICE_CONN_ERROR);
        }
        got += static_cast<size_t>(n);
    }
    return out;
}

class HidPacketLink final : public PacketLink
{
public:
    explicit HidPacketLink(const std::string& path) : m_hid(path) {}
    void Write(const std::vector<unsigned char>& pkt) override { m_hid.Write(pkt); }
    std::vector<unsigned char> Read(int timeout_ms) override { return m_hid.Read(timeout_ms); }
    void Close() override { m_hid.Close(); }

private:
    HidConnection m_hid;
};

class UdpPacketLink final : public PacketLink
{
public:
    UdpPacketLink(const std::string& host, uint16_t port)
        : m_sock(ConnectInet(SOCK_DGRAM, IPPROTO_UDP, host, port))
    {
    }

    void Write(const std::vector<unsigned char>& pkt) override
    {
        if (pkt.size() != 64) {
            throw HWIError("Trezor UDP chunk must be 64 bytes", ErrorCode::DEVICE_CONN_ERROR);
        }
        if (!m_sock) throw HWIError("UDP socket closed", ErrorCode::DEVICE_CONN_ERROR);
        const ssize_t n = m_sock->Send(pkt.data(), pkt.size(), 0);
        if (n != 64) {
            throw HWIError("UDP send failed", ErrorCode::DEVICE_CONN_ERROR);
        }
    }

    std::vector<unsigned char> Read(int timeout_ms) override
    {
        if (!m_sock) throw HWIError("UDP socket closed", ErrorCode::DEVICE_CONN_ERROR);
        if (!WaitRecv(*m_sock, timeout_ms)) return {};
        unsigned char buf[64] = {};
        const ssize_t n = m_sock->Recv(buf, sizeof(buf), 0);
        if (n < 0) {
            const int err = WSAGetLastError();
            if (err == WSAEAGAIN || err == WSAEWOULDBLOCK) return {};
            throw HWIError("UDP recv failed: " + NetworkErrorString(err), ErrorCode::DEVICE_CONN_ERROR);
        }
        if (n == 0) return {};
        std::vector<unsigned char> out(buf, buf + n);
        if (out.size() < 64) out.resize(64, 0);
        return out;
    }

    void Close() override { m_sock.reset(); }

private:
    std::unique_ptr<Sock> m_sock;
};

class UnixDgramLink final : public PacketLink
{
public:
    explicit UnixDgramLink(const std::string& path)
    {
#ifdef WIN32
        throw HWIError("Coldcard unix simulator is not supported on Windows", ErrorCode::DEVICE_CONN_ERROR);
#else
        SOCKET fd = static_cast<SOCKET>(socket(AF_UNIX, SOCK_DGRAM, 0));
        if (fd == INVALID_SOCKET) {
            throw HWIError("unix socket() failed", ErrorCode::DEVICE_CONN_ERROR);
        }
        m_sock = std::make_unique<Sock>(fd);

        sockaddr_un dest{};
        dest.sun_family = AF_UNIX;
        if (path.size() >= sizeof(dest.sun_path)) {
            throw HWIError("unix path too long", ErrorCode::BAD_ARGUMENT);
        }
        std::strncpy(dest.sun_path, path.c_str(), sizeof(dest.sun_path) - 1);
        if (m_sock->Connect(reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) != 0) {
            throw HWIError("Cannot connect to Coldcard simulator at " + path, ErrorCode::DEVICE_CONN_ERROR);
        }

        std::string last_err;
        for (int instance = 0; instance < 5; ++instance) {
            const std::string pn = strprintf("/tmp/ckcc-client-%d-%d.sock", static_cast<int>(getpid()), instance);
            unlink(pn.c_str());
            sockaddr_un local{};
            local.sun_family = AF_UNIX;
            if (pn.size() >= sizeof(local.sun_path)) continue;
            std::strncpy(local.sun_path, pn.c_str(), sizeof(local.sun_path) - 1);
            if (m_sock->Bind(reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0) {
                m_local = pn;
                break;
            }
            last_err = NetworkErrorString(WSAGetLastError());
        }
        if (m_local.empty()) {
            throw HWIError("Cannot bind Coldcard client socket: " + last_err, ErrorCode::DEVICE_CONN_ERROR);
        }
#endif
    }

    ~UnixDgramLink() override { Close(); }

    void Write(const std::vector<unsigned char>& pkt) override
    {
        if (!m_sock) throw HWIError("unix socket closed", ErrorCode::DEVICE_CONN_ERROR);
        // HID writes 64-byte payloads; the Python UnixSimulatorPipe strips a leading
        // report-id byte from a 65-byte hidapi buffer. We never send the report id.
        const unsigned char* data = pkt.data();
        size_t len = pkt.size();
        if (len == 65) {
            data += 1;
            len = 64;
        }
        if (len != 64) {
            throw HWIError("Coldcard unix frame must be 64 bytes", ErrorCode::DEVICE_CONN_ERROR);
        }
        const ssize_t n = m_sock->Send(data, len, 0);
        if (n != static_cast<ssize_t>(len)) {
            throw HWIError("unix send failed", ErrorCode::DEVICE_CONN_ERROR);
        }
    }

    std::vector<unsigned char> Read(int timeout_ms) override
    {
        if (!m_sock) throw HWIError("unix socket closed", ErrorCode::DEVICE_CONN_ERROR);
        if (!WaitRecv(*m_sock, timeout_ms)) return {};
        unsigned char buf[64] = {};
        const ssize_t n = m_sock->Recv(buf, sizeof(buf), 0);
        if (n < 0) {
            const int err = WSAGetLastError();
            if (err == WSAEAGAIN || err == WSAEWOULDBLOCK) return {};
            throw HWIError("unix recv failed: " + NetworkErrorString(err), ErrorCode::DEVICE_CONN_ERROR);
        }
        if (n == 0) return {};
        return {buf, buf + n};
    }

    void Close() override
    {
        m_sock.reset();
#ifndef WIN32
        if (!m_local.empty()) {
            unlink(m_local.c_str());
            m_local.clear();
        }
#endif
    }

private:
    std::unique_ptr<Sock> m_sock;
    std::string m_local;
};

} // namespace

bool IsUdpPath(std::string_view path)
{
    return StartsWithIgnoreCase(path, "udp:");
}

bool IsTcpPath(std::string_view path)
{
    return StartsWithIgnoreCase(path, "tcp:");
}

bool IsUnixSocketPath(std::string_view path)
{
    if (StartsWithIgnoreCase(path, "unix:")) return true;
    return path.starts_with('/') && path.find(".sock") != std::string_view::npos;
}

std::optional<HostPort> ParseUdpPath(std::string_view path)
{
    return ParsePrefixedHostPort(path, "udp:", TREZOR_UDP_DEFAULT_PORT);
}

std::optional<HostPort> ParseTcpPath(std::string_view path)
{
    return ParsePrefixedHostPort(path, "tcp:", LEDGER_TCP_DEFAULT_PORT);
}

std::string UnixSocketPath(std::string_view path)
{
    if (StartsWithIgnoreCase(path, "unix:")) return std::string{path.substr(5)};
    return std::string{path};
}

std::string DefaultTrezorUdpPath()
{
    std::string p = EnvOr("HWI_TREZOR_UDP", TREZOR_UDP_DEFAULT_PATH);
    if (p.empty()) return {};
    if (!IsUdpPath(p)) p = "udp:" + p;
    return p;
}

std::string DefaultLedgerTcpPath()
{
    std::string p = EnvOr("HWI_LEDGER_TCP", LEDGER_TCP_DEFAULT_PATH);
    if (p.empty()) return {};
    if (!IsTcpPath(p)) p = "tcp:" + p;
    return p;
}

std::string DefaultColdcardUnixPath()
{
    return EnvOr("HWI_COLDCARD_SOCK", COLDCARD_UNIX_DEFAULT_PATH);
}

std::unique_ptr<PacketLink> OpenPacketLinkHid(const std::string& path)
{
    return std::make_unique<HidPacketLink>(path);
}

std::unique_ptr<PacketLink> OpenPacketLinkUdp(const std::string& host, uint16_t port)
{
    return std::make_unique<UdpPacketLink>(host, port);
}

std::unique_ptr<PacketLink> OpenPacketLinkUnixDgram(const std::string& path)
{
    return std::make_unique<UnixDgramLink>(path);
}

bool TrezorUdpPing(const std::string& host, uint16_t port, int timeout_ms)
{
    try {
        auto sock = ConnectInet(SOCK_DGRAM, IPPROTO_UDP, host, port);
        const ssize_t n = sock->Send(TREZOR_PING, 8, 0);
        if (n != 8) return false;
        if (!WaitRecv(*sock, timeout_ms)) return false;
        char buf[8] = {};
        const ssize_t r = sock->Recv(buf, sizeof(buf), 0);
        return r == 8 && std::memcmp(buf, TREZOR_PONG, 8) == 0;
    } catch (...) {
        return false;
    }
}

bool TrezorUdpAvailable(std::string_view path)
{
    const auto hp = ParseUdpPath(path);
    if (!hp) return false;
    return TrezorUdpPing(hp->host, hp->port);
}

class TcpApduLink::Impl
{
public:
    Impl(const std::string& host, uint16_t port)
        : m_sock(ConnectInet(SOCK_STREAM, IPPROTO_TCP, host, port))
    {
    }

    std::pair<uint16_t, std::vector<unsigned char>> Exchange(const std::vector<unsigned char>& apdu, int timeout_ms)
    {
        if (!m_sock) throw HWIError("TCP socket closed", ErrorCode::DEVICE_CONN_ERROR);
        if (apdu.empty()) throw HWIError("Empty APDU", ErrorCode::BAD_ARGUMENT);

        unsigned char lenbuf[4] = {
            static_cast<unsigned char>(apdu.size() >> 24),
            static_cast<unsigned char>(apdu.size() >> 16),
            static_cast<unsigned char>(apdu.size() >> 8),
            static_cast<unsigned char>(apdu.size()),
        };
        SendAll(*m_sock, lenbuf, 4, timeout_ms);
        SendAll(*m_sock, apdu.data(), apdu.size(), timeout_ms);

        const auto lenb = RecvExact(*m_sock, 4, timeout_ms);
        const uint32_t rlen = (uint32_t(lenb[0]) << 24) | (uint32_t(lenb[1]) << 16) |
                              (uint32_t(lenb[2]) << 8) | uint32_t(lenb[3]);
        if (rlen > 4096) {
            throw HWIError("Speculos APDU response too large", ErrorCode::DEVICE_CONN_ERROR);
        }
        auto data = RecvExact(*m_sock, rlen, timeout_ms);
        const auto swb = RecvExact(*m_sock, 2, timeout_ms);
        const uint16_t sw = (uint16_t(swb[0]) << 8) | swb[1];
        return {sw, std::move(data)};
    }

    void Close() { m_sock.reset(); }
    bool IsOpen() const { return static_cast<bool>(m_sock); }

private:
    std::unique_ptr<Sock> m_sock;
};

TcpApduLink::TcpApduLink(const std::string& host, uint16_t port)
    : m_impl(std::make_unique<Impl>(host, port))
{
}

TcpApduLink::~TcpApduLink() = default;

std::pair<uint16_t, std::vector<unsigned char>> TcpApduLink::Exchange(const std::vector<unsigned char>& apdu, int timeout_ms)
{
    return m_impl->Exchange(apdu, timeout_ms);
}

void TcpApduLink::Close()
{
    m_impl->Close();
}

bool TcpApduLink::IsOpen() const
{
    return m_impl->IsOpen();
}

bool LedgerTcpAvailable(std::string_view path)
{
    const auto hp = ParseTcpPath(path);
    if (!hp) return false;
    try {
        TcpApduLink link(hp->host, hp->port);
        return link.IsOpen();
    } catch (...) {
        return false;
    }
}

bool ColdcardSimulatorAvailable(std::string_view path)
{
    if (path.empty()) return false;
    try {
        auto link = OpenPacketLinkUnixDgram(UnixSocketPath(path));
        link->Close();
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace hwi
