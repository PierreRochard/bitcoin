// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/coldcard.h>

#include <hwi/hid.h>
#include <hwi/hwi.h>
#include <hwi/transport.h>
#include <hwi/util.h>

#include <common/signmessage.h>
#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <psbt.h>
#include <pubkey.h>
#include <span.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>

namespace hwi {
namespace {

constexpr size_t MAX_BLK = 2048;
constexpr uint32_t USB_NCRY_V1 = 1;
constexpr uint32_t AF_CLASSIC = 0x01;
constexpr uint32_t AF_P2WPKH = 0x01 | 0x02 | 0x04;
constexpr uint32_t AF_P2WPKH_P2SH = 0x10 | 0x01 | 0x02;
constexpr uint32_t AF_P2TR = 0x01 | 0x02 | 0x20;

std::unique_ptr<PacketLink> OpenColdcardLink(const std::string& path)
{
    if (IsUnixSocketPath(path)) {
        return OpenPacketLinkUnixDgram(UnixSocketPath(path));
    }
    return OpenPacketLinkHid(path);
}

class ColdcardDevice
{
public:
    explicit ColdcardDevice(const std::string& path) : m_link(OpenColdcardLink(path))
    {
        Resync();
        StartEncryption();
    }

    void Close()
    {
        if (m_link) m_link->Close();
    }

    std::vector<unsigned char> SendRecv(const std::vector<unsigned char>& msg, int timeout_ms, bool encrypt = true)
    {
        if (msg.size() < 4 || msg.size() > 4 + 4 + 4 + MAX_BLK) {
            throw HWIError("Coldcard message length invalid", ErrorCode::BAD_ARGUMENT);
        }
        std::vector<unsigned char> payload = msg;
        if (encrypt) {
            if (m_session_key.empty()) {
                encrypt = false;
            } else {
                payload = Aes256Ctr(m_session_key, msg);
            }
        }

        size_t offset = 0;
        while (offset < payload.size()) {
            const size_t here = std::min<size_t>(63, payload.size() - offset);
            std::vector<unsigned char> pkt(64, 0);
            pkt[0] = static_cast<unsigned char>(here);
            if (offset + here == payload.size()) {
                pkt[0] |= 0x80;
                if (encrypt) pkt[0] |= 0x40;
            }
            memcpy(pkt.data() + 1, payload.data() + offset, here);
            m_link->Write(pkt);
            offset += here;
        }

        std::vector<unsigned char> resp;
        uint8_t flag = 0;
        while (true) {
            auto buf = m_link->Read(timeout_ms);
            if (buf.empty()) {
                throw HWIError("Timeout reading Coldcard", ErrorCode::DEVICE_CONN_ERROR);
            }
            // hidapi may include a leading report id
            if (buf.size() == 65 && buf[0] == 0) buf.erase(buf.begin());
            if (buf.size() < 2) throw HWIError("Short Coldcard frame", ErrorCode::DEVICE_CONN_ERROR);
            flag = buf[0];
            const size_t n = flag & 0x3f;
            if (buf.size() < 1 + n) throw HWIError("Truncated Coldcard frame", ErrorCode::DEVICE_CONN_ERROR);
            resp.insert(resp.end(), buf.begin() + 1, buf.begin() + 1 + n);
            if (flag & 0x80) break;
        }
        if (flag & 0x40) {
            if (m_session_key.empty()) throw HWIError("Encrypted Coldcard reply without session", ErrorCode::DEVICE_CONN_ERROR);
            resp = Aes256Ctr(m_session_key, resp);
        }
        return Decode(resp);
    }

    uint32_t MasterFingerprint() const { return m_fingerprint; }
    [[maybe_unused]] const std::string& MasterXpub() const { return m_xpub; }

    std::vector<unsigned char> Download(uint32_t length, const std::vector<unsigned char>& checksum, int file_number)
    {
        std::vector<unsigned char> data;
        data.reserve(length);
        uint32_t pos = 0;
        CSHA256 chk;
        while (pos < length) {
            const uint32_t here = std::min<uint32_t>(1024, length - pos);
            std::vector<unsigned char> cmd;
            cmd.insert(cmd.end(), {'d', 'w', 'l', 'd'});
            auto le = SerializeLe32(pos);
            cmd.insert(cmd.end(), le.begin(), le.end());
            le = SerializeLe32(here);
            cmd.insert(cmd.end(), le.begin(), le.end());
            le = SerializeLe32(file_number);
            cmd.insert(cmd.end(), le.begin(), le.end());
            auto chunk = SendRecv(cmd, 10000);
            if (chunk.size() < 4) throw HWIError("Coldcard download failed", ErrorCode::DEVICE_CONN_ERROR);
            // decode() for biny returns payload after 4-byte sig; SendRecv already decoded to payload-only for biny
            data.insert(data.end(), chunk.begin(), chunk.end());
            chk.Write(chunk.data(), chunk.size());
            pos += chunk.size();
            if (chunk.empty()) break;
        }
        unsigned char got[32];
        chk.Finalize(got);
        if (!checksum.empty() && (checksum.size() != 32 || memcmp(got, checksum.data(), 32) != 0)) {
            throw HWIError("Coldcard download checksum mismatch", ErrorCode::DEVICE_CONN_ERROR);
        }
        return data;
    }

private:
    void Resync()
    {
        for (int i = 0; i < 64; ++i) {
            auto junk = m_link->Read(1);
            if (junk.empty()) break;
        }
        std::vector<unsigned char> pkt(64, 0xff);
        pkt[0] = 0x80;
        m_link->Write(pkt);
        for (int i = 0; i < 64; ++i) {
            auto junk = m_link->Read(1);
            if (junk.empty()) break;
        }
    }

    void StartEncryption()
    {
        CKey our = GenerateRandomKey(/*compressed=*/false);
        CPubKey pub = our.GetPubKey();
        pub.Decompress();
        if (pub.size() != 65) throw HWIError("Failed to make uncompressed ECDH key", ErrorCode::DEVICE_CONN_ERROR);

        std::vector<unsigned char> cmd;
        cmd.insert(cmd.end(), {'n', 'c', 'r', 'y'});
        auto ver = SerializeLe32(USB_NCRY_V1);
        cmd.insert(cmd.end(), ver.begin(), ver.end());
        cmd.insert(cmd.end(), pub.data() + 1, pub.data() + 65);

        auto resp = SendRecv(cmd, 5000, /*encrypt=*/false);
        // mypb: 64 pubkey + uint32 fp + uint32 xpub_len + xpub, but Decode already stripped 4-byte 'mypb'
        if (resp.size() < 64 + 8) {
            throw HWIError("Invalid Coldcard ncry response", ErrorCode::DEVICE_CONN_ERROR);
        }
        m_session_key = EcdhUncompressedHash(our, {resp.data(), 64});
        m_fingerprint = ReadLe32({resp.data() + 64, 4});
        const uint32_t xpub_len = ReadLe32({resp.data() + 68, 4});
        if (resp.size() >= 72 + xpub_len) {
            m_xpub.assign(resp.begin() + 72, resp.begin() + 72 + xpub_len);
        }
    }

    static std::vector<unsigned char> Decode(const std::vector<unsigned char>& msg)
    {
        if (msg.size() < 4) throw HWIError("Short Coldcard response", ErrorCode::DEVICE_CONN_ERROR);
        const std::string sig(msg.begin(), msg.begin() + 4);
        if (sig == "okay") return {};
        if (sig == "biny" || sig == "asci") return {msg.begin() + 4, msg.end()};
        if (sig == "int1") {
            if (msg.size() < 8) throw HWIError("Short int1", ErrorCode::DEVICE_CONN_ERROR);
            return {msg.begin() + 4, msg.end()};
        }
        if (sig == "int2" || sig == "strx") return {msg.begin() + 4, msg.end()};
        if (sig == "mypb") return {msg.begin() + 4, msg.end()};
        if (sig == "smrx") return {msg.begin() + 4, msg.end()};
        if (sig == "refu") throw HWIError("User refused the Coldcard request", ErrorCode::ACTION_CANCELED);
        if (sig == "busy") throw HWIError("Coldcard is busy", ErrorCode::DEVICE_BUSY);
        if (sig == "err_" || sig == "fram") {
            const std::string err(msg.begin() + 4, msg.end());
            throw HWIError("Coldcard error: " + err, ErrorCode::BAD_ARGUMENT);
        }
        throw HWIError("Unknown Coldcard response: " + sig, ErrorCode::UNKNOWN_ERROR);
    }

    std::unique_ptr<PacketLink> m_link;
    std::vector<unsigned char> m_session_key;
    uint32_t m_fingerprint{0};
    std::string m_xpub;
};

class ColdcardClient final : public HardwareWalletClient
{
public:
    ColdcardClient(std::string path, ChainType chain)
        : HardwareWalletClient(std::move(path), chain), m_dev(Path())
    {
    }

    std::string Type() const override { return "coldcard"; }

    KeyFingerprint GetMasterFingerprint() const override
    {
        KeyFingerprint fpr{};
        uint32_t v = m_dev.MasterFingerprint();
        fpr[0] = v & 0xff;
        fpr[1] = (v >> 8) & 0xff;
        fpr[2] = (v >> 16) & 0xff;
        fpr[3] = (v >> 24) & 0xff;
        return fpr;
    }

    CExtPubKey GetPubkeyAtPath(const std::string& bip32_path) const override
    {
        std::string path = bip32_path;
        for (char& c : path) {
            if (c == 'h' || c == 'H') c = '\'';
        }
        std::vector<unsigned char> cmd{'x', 'p', 'u', 'b'};
        cmd.insert(cmd.end(), path.begin(), path.end());
        auto resp = m_dev.SendRecv(cmd, 10000);
        const std::string xpub(resp.begin(), resp.end());
        return DecodeXpubAnyVersion(xpub);
    }

    PartiallySignedTransaction SignTx(PartiallySignedTransaction psbt) const override
    {
        DataStream ss{};
        ss << psbt;
        const auto& raw = ss;
        std::vector<unsigned char> bytes(UCharCast(raw.data()), UCharCast(raw.data()) + raw.size());
        const auto digest = Sha256(bytes);

        uint32_t pos = 0;
        while (pos < bytes.size()) {
            const uint32_t here = std::min<uint32_t>(MAX_BLK, bytes.size() - pos);
            std::vector<unsigned char> cmd{'u', 'p', 'l', 'd'};
            auto le = SerializeLe32(pos);
            cmd.insert(cmd.end(), le.begin(), le.end());
            le = SerializeLe32(bytes.size());
            cmd.insert(cmd.end(), le.begin(), le.end());
            cmd.insert(cmd.end(), bytes.begin() + pos, bytes.begin() + pos + here);
            auto ack = m_dev.SendRecv(cmd, 10000);
            if (ack.size() >= 4) {
                const uint32_t got = ReadLe32(ack);
                if (got != pos) throw HWIError("Coldcard upload offset mismatch", ErrorCode::DEVICE_CONN_ERROR);
            }
            pos += here;
        }
        auto sha = m_dev.SendRecv({'s', 'h', 'a', '2'}, 5000);
        if (sha != digest) throw HWIError("Coldcard upload checksum mismatch", ErrorCode::DEVICE_CONN_ERROR);

        std::vector<unsigned char> stxn{'s', 't', 'x', 'n'};
        auto le = SerializeLe32(bytes.size());
        stxn.insert(stxn.end(), le.begin(), le.end());
        le = SerializeLe32(0);
        stxn.insert(stxn.end(), le.begin(), le.end());
        stxn.insert(stxn.end(), digest.begin(), digest.end());
        m_dev.SendRecv(stxn, 300000);

        std::vector<unsigned char> done;
        for (int i = 0; i < 1200; ++i) {
            done = m_dev.SendRecv({'s', 't', 'o', 'k'}, 1000);
            if (!done.empty()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        if (done.size() < 36) throw HWIError("Coldcard signing failed", ErrorCode::UNKNOWN_ERROR);
        const uint32_t result_len = ReadLe32(done);
        std::vector<unsigned char> result_sha(done.begin() + 4, done.begin() + 36);
        auto signed_bytes = m_dev.Download(result_len, result_sha, /*file_number=*/1);
        auto decoded = DecodeRawPSBT(std::as_bytes(std::span{signed_bytes}));
        if (!decoded) throw HWIError("Coldcard returned an invalid PSBT", ErrorCode::INVALID_TX);
        return *decoded;
    }

    std::string SignMessage(const std::string& message, const std::string& bip32_path) const override
    {
        std::string path = bip32_path;
        for (char& c : path) {
            if (c == 'h' || c == 'H') c = '\'';
        }
        std::vector<unsigned char> cmd{'s', 'm', 's', 'g'};
        auto le = SerializeLe32(AF_CLASSIC);
        cmd.insert(cmd.end(), le.begin(), le.end());
        le = SerializeLe32(path.size());
        cmd.insert(cmd.end(), le.begin(), le.end());
        le = SerializeLe32(message.size());
        cmd.insert(cmd.end(), le.begin(), le.end());
        cmd.insert(cmd.end(), path.begin(), path.end());
        cmd.insert(cmd.end(), message.begin(), message.end());
        m_dev.SendRecv(cmd, 300000);
        std::vector<unsigned char> done;
        for (int i = 0; i < 1200; ++i) {
            done = m_dev.SendRecv({'s', 'm', 'o', 'k'}, 1000);
            if (!done.empty()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        if (done.size() < 4) throw HWIError("Coldcard message signing failed", ErrorCode::UNKNOWN_ERROR);
        const uint32_t aln = ReadLe32(done);
        if (done.size() < 4 + aln) throw HWIError("Short Coldcard signature", ErrorCode::UNKNOWN_ERROR);
        std::vector<unsigned char> raw(done.begin() + 4 + aln, done.end());
        return EncodeBase64(raw);
    }

    std::string DisplaySinglesigAddress(const std::string& bip32_path, OutputType type) const override
    {
        std::string path = bip32_path;
        for (char& c : path) {
            if (c == 'h' || c == 'H') c = '\'';
        }
        uint32_t fmt = AF_P2WPKH;
        switch (type) {
        case OutputType::LEGACY: fmt = AF_CLASSIC; break;
        case OutputType::P2SH_SEGWIT: fmt = AF_P2WPKH_P2SH; break;
        case OutputType::BECH32: fmt = AF_P2WPKH; break;
        case OutputType::BECH32M: fmt = AF_P2TR; break;
        case OutputType::UNKNOWN: break;
        }
        std::vector<unsigned char> cmd{'s', 'h', 'o', 'w'};
        auto le = SerializeLe32(fmt);
        cmd.insert(cmd.end(), le.begin(), le.end());
        cmd.insert(cmd.end(), path.begin(), path.end());
        auto resp = m_dev.SendRecv(cmd, 300000);
        if (!resp.empty()) return std::string(resp.begin(), resp.end());
        return HardwareWalletClient::DisplaySinglesigAddress(bip32_path, type);
    }

    bool CanSignTaproot() const override { return true; }
    void Close() override { m_dev.Close(); }

private:
    mutable ColdcardDevice m_dev;
};

DeviceInfo ProbeColdcard(const std::string& path, const std::string& model)
{
    DeviceInfo info;
    info.type = "coldcard";
    info.model = model;
    info.path = path;
    try {
        ColdcardClient client(path, ChainType::MAIN);
        info.fingerprint = FingerprintHex(client.GetMasterFingerprint());
        client.Close();
    } catch (const std::exception& e) {
        info.error = e.what();
    }
    return info;
}

} // namespace

std::vector<DeviceInfo> EnumerateColdcard()
{
    std::vector<DeviceInfo> out;
    for (const HidInfo& hid : EnumerateHid(COINKITE_VID, CKCC_PID)) {
        out.push_back(ProbeColdcard(hid.path, "coldcard"));
    }
    const std::string sock = DefaultColdcardUnixPath();
    if (!sock.empty() && ColdcardSimulatorAvailable(sock)) {
        auto info = ProbeColdcard(sock, "coldcard_simulator");
        if (!info.fingerprint.empty()) out.push_back(std::move(info));
    }
    return out;
}

std::unique_ptr<HardwareWalletClient> ConnectColdcard(const DeviceInfo& info)
{
    return std::make_unique<ColdcardClient>(info.path, ChainType::MAIN);
}

} // namespace hwi
