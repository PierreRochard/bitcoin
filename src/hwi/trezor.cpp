// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/trezor.h>

#include <hwi/hid.h>
#include <hwi/hwi.h>
#include <hwi/protobuf.h>
#include <hwi/transport.h>
#include <hwi/util.h>

#include <addresstype.h>
#include <crypto/hex_base.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <span.h>
#include <script/sign.h>
#include <script/solver.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>

namespace hwi {
namespace {

constexpr int MSG_INITIALIZE = 0;
constexpr int MSG_SUCCESS = 2;
constexpr int MSG_FAILURE = 3;
constexpr int MSG_WIPEDEVICE = 5;
constexpr int MSG_LOADDEVICE = 13;
constexpr int MSG_GETPUBLICKEY = 11;
constexpr int MSG_PUBLICKEY = 12;
constexpr int MSG_SIGNTX = 15;
constexpr int MSG_FEATURES = 17;
constexpr int MSG_PINMATRIXREQUEST = 18;
constexpr int MSG_TXREQUEST = 21;
constexpr int MSG_TXACK = 22;
constexpr int MSG_BUTTONREQUEST = 26;
constexpr int MSG_BUTTONACK = 27;
constexpr int MSG_GETADDRESS = 29;
constexpr int MSG_ADDRESS = 30;
constexpr int MSG_SIGNMESSAGE = 38;
constexpr int MSG_MESSAGESIGNATURE = 40;
constexpr int MSG_PASSPHRASEREQUEST = 41;
constexpr int MSG_PASSPHRASEACK = 42;
constexpr int MSG_DEBUGLINKDECISION = 100;

constexpr int SPENDADDRESS = 0;
constexpr int SPENDWITNESS = 3;
constexpr int SPENDP2SHWITNESS = 4;
constexpr int SPENDTAPROOT = 5;
constexpr int PAYTOADDRESS = 0;
constexpr int PAYTOOPRETURN = 3;
constexpr int PAYTOWITNESS = 4;
constexpr int PAYTOP2SHWITNESS = 5;
constexpr int PAYTOTAPROOT = 6;
constexpr int TXINPUT = 0;
constexpr int TXOUTPUT = 1;
constexpr int TXMETA = 2;
constexpr int TXFINISHED = 3;

bool IsTrezorId(uint16_t vid, uint16_t pid)
{
    return (vid == TREZOR1_ID.first && pid == TREZOR1_ID.second) ||
           (vid == TREZOR2_ID.first && pid == TREZOR2_ID.second) ||
           (vid == TREZOR2_BL_ID.first && pid == TREZOR2_BL_ID.second);
}

void WriteProtocolV1(PacketLink& link, int msg_type, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> buf;
    buf.push_back('#');
    buf.push_back('#');
    buf.push_back(static_cast<unsigned char>(msg_type >> 8));
    buf.push_back(static_cast<unsigned char>(msg_type));
    buf.push_back(static_cast<unsigned char>(payload.size() >> 24));
    buf.push_back(static_cast<unsigned char>(payload.size() >> 16));
    buf.push_back(static_cast<unsigned char>(payload.size() >> 8));
    buf.push_back(static_cast<unsigned char>(payload.size()));
    buf.insert(buf.end(), payload.begin(), payload.end());
    while (!buf.empty()) {
        std::vector<unsigned char> chunk(64, 0);
        chunk[0] = '?';
        const size_t n = std::min<size_t>(63, buf.size());
        memcpy(chunk.data() + 1, buf.data(), n);
        link.Write(chunk);
        buf.erase(buf.begin(), buf.begin() + n);
    }
}

class TrezorWire
{
public:
    TrezorWire(std::unique_ptr<PacketLink> link, std::unique_ptr<PacketLink> debug)
        : m_link(std::move(link)), m_debug(std::move(debug))
    {
        if (!m_link) throw HWIError("No Trezor transport", ErrorCode::DEVICE_CONN_ERROR);
    }

    void Close()
    {
        if (m_link) m_link->Close();
        if (m_debug) m_debug->Close();
    }

    void Write(int msg_type, const std::vector<unsigned char>& payload)
    {
        WriteProtocolV1(*m_link, msg_type, payload);
    }

    std::pair<int, std::vector<unsigned char>> Read()
    {
        auto first = ReadChunk();
        if (first.size() < 9 || first[0] != '?' || first[1] != '#' || first[2] != '#') {
            throw HWIError("Invalid Trezor HID header", ErrorCode::DEVICE_CONN_ERROR);
        }
        const int msg_type = (int(first[3]) << 8) | first[4];
        const uint32_t len = (uint32_t(first[5]) << 24) | (uint32_t(first[6]) << 16) |
                             (uint32_t(first[7]) << 8) | uint32_t(first[8]);
        std::vector<unsigned char> data(first.begin() + 9, first.end());
        while (data.size() < len) {
            auto more = ReadChunk();
            if (more.empty() || more[0] != '?') throw HWIError("Invalid Trezor continuation", ErrorCode::DEVICE_CONN_ERROR);
            data.insert(data.end(), more.begin() + 1, more.end());
        }
        data.resize(len);
        return {msg_type, data};
    }

    std::pair<int, std::vector<unsigned char>> Call(int type, const std::vector<unsigned char>& payload)
    {
        Write(type, payload);
        while (true) {
            auto [resp_type, data] = Read();
            if (resp_type == MSG_BUTTONREQUEST) {
                Write(MSG_BUTTONACK, {});
                DebugConfirm();
                continue;
            }
            if (resp_type == MSG_PINMATRIXREQUEST) {
                throw HWIError("Trezor is locked; PIN required", ErrorCode::DEVICE_CONN_ERROR);
            }
            if (resp_type == MSG_PASSPHRASEREQUEST) {
                PbWriter ack;
                ack.AddString(1, "");
                Write(MSG_PASSPHRASEACK, ack.Finish());
                continue;
            }
            if (resp_type == MSG_FAILURE) {
                auto fields = PbDecode(data);
                auto msg = PbGetString(fields, 2).value_or("Trezor failure");
                throw HWIError(msg, ErrorCode::UNKNOWN_ERROR);
            }
            return {resp_type, data};
        }
    }

private:
    std::vector<unsigned char> ReadChunk()
    {
        auto buf = m_link->Read(30000);
        if (buf.empty()) throw HWIError("Timeout reading Trezor", ErrorCode::DEVICE_CONN_ERROR);
        if (buf.size() == 65 && buf[0] == 0) buf.erase(buf.begin());
        if (buf.size() < 64) buf.resize(64, 0);
        return buf;
    }

    void DebugConfirm()
    {
        if (!m_debug) return;
        PbWriter ack;
        ack.AddBool(1, true);
        WriteProtocolV1(*m_debug, MSG_DEBUGLINKDECISION, ack.Finish());
    }

    std::unique_ptr<PacketLink> m_link;
    std::unique_ptr<PacketLink> m_debug;
};

TrezorWire MakeTrezorWire(const std::string& path)
{
    if (IsUdpPath(path)) {
        const auto hp = ParseUdpPath(path);
        if (!hp) throw HWIError("Invalid Trezor UDP path: " + path, ErrorCode::BAD_ARGUMENT);
        auto link = OpenPacketLinkUdp(hp->host, hp->port);
        std::unique_ptr<PacketLink> debug;
        if (TrezorUdpPing(hp->host, hp->port + 1, /*timeout_ms=*/100)) {
            try {
                debug = OpenPacketLinkUdp(hp->host, hp->port + 1);
            } catch (...) {
            }
        }
        return TrezorWire(std::move(link), std::move(debug));
    }
    return TrezorWire(OpenPacketLinkHid(path), nullptr);
}

struct TxInMsg {
    std::vector<uint32_t> address_n;
    std::vector<unsigned char> prev_hash;
    uint32_t prev_index{0};
    uint32_t sequence{0xffffffff};
    int script_type{SPENDADDRESS};
    uint64_t amount{0};
    std::vector<unsigned char> script_sig;
};

struct TxOutMsg {
    std::string address;
    std::vector<uint32_t> address_n;
    uint64_t amount{0};
    int script_type{PAYTOADDRESS};
    std::vector<unsigned char> op_return;
};

std::vector<unsigned char> EncodeTxInput(const TxInMsg& in)
{
    PbWriter w;
    for (uint32_t n : in.address_n) w.AddVarint(1, n);
    w.AddBytes(2, in.prev_hash);
    w.AddVarint(3, in.prev_index);
    if (!in.script_sig.empty()) w.AddBytes(4, in.script_sig);
    w.AddVarint(5, in.sequence);
    w.AddVarint(6, in.script_type);
    w.AddVarint(8, in.amount);
    return w.Finish();
}

std::vector<unsigned char> EncodeTxOutput(const TxOutMsg& out)
{
    PbWriter w;
    if (!out.address.empty()) w.AddString(1, out.address);
    for (uint32_t n : out.address_n) w.AddVarint(2, n);
    w.AddVarint(3, out.amount);
    w.AddVarint(4, out.script_type);
    if (!out.op_return.empty()) w.AddBytes(6, out.op_return);
    return w.Finish();
}

class TrezorClientImpl final : public HardwareWalletClient
{
public:
    TrezorClientImpl(std::string path, ChainType chain)
        : HardwareWalletClient(std::move(path), chain), m_wire(MakeTrezorWire(Path()))
    {
        Init();
    }

    std::string Type() const override { return "trezor"; }

    CExtPubKey GetPubkeyAtPath(const std::string& bip32_path) const override
    {
        auto path = ParsePathOrThrow(bip32_path);
        PbWriter w;
        for (uint32_t n : path) w.AddVarint(1, n);
        w.AddString(4, CoinName(GetChain()));
        auto [type, data] = m_wire.Call(MSG_GETPUBLICKEY, w.Finish());
        if (type != MSG_PUBLICKEY) throw HWIError("Unexpected Trezor response for GetPublicKey", ErrorCode::UNKNOWN_ERROR);
        auto fields = PbDecode(data);
        auto xpub = PbGetString(fields, 2);
        if (!xpub) throw HWIError("Trezor PublicKey missing xpub", ErrorCode::UNKNOWN_ERROR);
        return DecodeXpubAnyVersion(*xpub);
    }

    PartiallySignedTransaction SignTx(PartiallySignedTransaction psbt) const override
    {
        const auto fpr = GetMasterFingerprint();
        std::optional<CMutableTransaction> tx = psbt.GetUnsignedTx();
        if (!tx) throw HWIError("PSBT missing unsigned tx", ErrorCode::INVALID_TX);

        std::vector<TxInMsg> inputs;
        std::vector<int> ignore;
        std::map<Txid, CTransactionRef> prevtxs;
        for (size_t i = 0; i < psbt.inputs.size(); ++i) {
            const auto& pin = psbt.inputs[i];
            TxInMsg in;
            const COutPoint prev = (i < tx->vin.size()) ? tx->vin[i].prevout : COutPoint{pin.prev_txid, pin.prev_out};
            {
                auto sp = MakeUCharSpan(prev.hash);
                in.prev_hash.assign(sp.begin(), sp.end());
            }
            in.prev_index = prev.n;
            in.sequence = pin.sequence.value_or(i < tx->vin.size() ? tx->vin[i].nSequence : 0xffffffff);
            const CTxOut* utxo = InputUtxo(pin);
            if (!utxo) continue;
            in.amount = utxo->nValue;
            CScript script = utxo->scriptPubKey;
            bool p2sh = false;
            if (IsP2SH(script) && !pin.redeem_script.empty()) {
                script = pin.redeem_script;
                p2sh = true;
            }
            const int wit = WitnessVersion(script);
            if (wit == 0) in.script_type = p2sh ? SPENDP2SHWITNESS : SPENDWITNESS;
            else if (wit == 1) in.script_type = SPENDTAPROOT;
            else in.script_type = SPENDADDRESS;

            bool found = false;
            if (in.script_type == SPENDTAPROOT) {
                for (const auto& [xonly, leaf] : pin.m_tap_bip32_paths) {
                    if (xonly == pin.m_tap_internal_key && leaf.second.fingerprint == fpr) {
                        in.address_n = leaf.second.path;
                        found = true;
                        break;
                    }
                }
            } else {
                for (const auto& [pub, origin] : pin.hd_keypaths) {
                    if (origin.fingerprint == fpr) {
                        in.address_n = origin.path;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                in.address_n = {84 | 0x80000000u, (GetChain() == ChainType::MAIN ? 0u : 1u) | 0x80000000u, 0x80000000u, 0, 0};
                in.script_type = SPENDWITNESS;
                ignore.push_back(static_cast<int>(i));
            }
            inputs.push_back(std::move(in));
            if (pin.non_witness_utxo) prevtxs.emplace(pin.non_witness_utxo->GetHash(), pin.non_witness_utxo);
        }

        std::vector<TxOutMsg> outputs;
        for (size_t i = 0; i < psbt.outputs.size(); ++i) {
            const auto& po = psbt.outputs[i];
            CTxOut out = (i < tx->vout.size()) ? tx->vout[i] : CTxOut{po.amount, po.script};
            TxOutMsg o;
            o.amount = out.nValue;
            std::vector<std::vector<unsigned char>> sol;
            const TxoutType t = Solver(out.scriptPubKey, sol);
            if (t == TxoutType::NULL_DATA) {
                o.script_type = PAYTOOPRETURN;
                o.op_return.assign(out.scriptPubKey.begin() + 2, out.scriptPubKey.end());
            } else {
                CTxDestination dest;
                if (!ExtractDestination(out.scriptPubKey, dest)) {
                    throw HWIError("Trezor cannot encode output", ErrorCode::BAD_ARGUMENT);
                }
                o.address = EncodeDestination(dest);
                o.script_type = PAYTOADDRESS;
                for (const auto& [pub, origin] : po.hd_keypaths) {
                    if (origin.fingerprint != fpr) continue;
                    o.address_n = origin.path;
                    o.address.clear();
                    if (t == TxoutType::PUBKEYHASH) o.script_type = PAYTOADDRESS;
                    else if (t == TxoutType::WITNESS_V0_KEYHASH) o.script_type = PAYTOWITNESS;
                    else if (t == TxoutType::SCRIPTHASH) o.script_type = PAYTOP2SHWITNESS;
                    break;
                }
                for (const auto& [xonly, leaf] : po.m_tap_bip32_paths) {
                    if (xonly == po.m_tap_internal_key && leaf.second.fingerprint == fpr) {
                        o.address_n = leaf.second.path;
                        o.address.clear();
                        o.script_type = PAYTOTAPROOT;
                        break;
                    }
                }
            }
            outputs.push_back(std::move(o));
        }

        PbWriter signtx;
        signtx.AddVarint(1, outputs.size());
        signtx.AddVarint(2, inputs.size());
        signtx.AddString(3, CoinName(GetChain()));
        signtx.AddVarint(4, tx->version);
        signtx.AddVarint(5, tx->nLockTime);
        signtx.AddBool(13, false); // serialize=false
        auto [rtype, rdata] = m_wire.Call(MSG_SIGNTX, signtx.Finish());

        std::vector<std::vector<unsigned char>> sigs(inputs.size());
        while (rtype == MSG_TXREQUEST) {
            auto fields = PbDecode(rdata);
            const int req = static_cast<int>(PbGetVarint(fields, 1).value_or(TXFINISHED));
            auto details = PbGetMessage(fields, 2).value_or(PbMap{});
            auto serialized = PbGetMessage(fields, 3);
            if (serialized) {
                auto sig = PbGetBytes(*serialized, 2);
                auto idx = PbGetVarint(*serialized, 1);
                if (sig && idx && *idx < sigs.size()) sigs[*idx] = *sig;
            }
            if (req == TXFINISHED) break;

            const int index = static_cast<int>(PbGetVarint(details, 1).value_or(0));
            auto txhash = PbGetBytes(details, 2);
            PbWriter ack;
            PbWriter inner;
            const Txid prev_id = txhash ? Txid::FromUint256(uint256(std::span<const unsigned char>{*txhash})) : Txid();
            if (txhash && prevtxs.count(prev_id)) {
                const CTransaction& prev = *prevtxs[prev_id];
                if (req == TXMETA) {
                    inner.AddVarint(1, prev.version);
                    inner.AddVarint(4, prev.nLockTime);
                    inner.AddVarint(6, prev.vin.size());
                    inner.AddVarint(7, prev.vout.size());
                } else if (req == TXINPUT && index >= 0 && static_cast<size_t>(index) < prev.vin.size()) {
                    const auto& vin = prev.vin[index];
                    PbWriter pin;
                    auto sp = MakeUCharSpan(vin.prevout.hash);
                    std::vector<unsigned char> ph(sp.begin(), sp.end());
                    pin.AddBytes(2, ph);
                    pin.AddVarint(3, vin.prevout.n);
                    pin.AddBytes(4, std::vector<unsigned char>(vin.scriptSig.begin(), vin.scriptSig.end()));
                    pin.AddVarint(5, vin.nSequence);
                    inner.AddMessage(2, pin.Finish());
                } else if (req == TXOUTPUT && index >= 0 && static_cast<size_t>(index) < prev.vout.size()) {
                    const auto& vout = prev.vout[index];
                    PbWriter pout;
                    pout.AddVarint(1, vout.nValue);
                    pout.AddBytes(2, std::vector<unsigned char>(vout.scriptPubKey.begin(), vout.scriptPubKey.end()));
                    inner.AddMessage(3, pout.Finish());
                }
            } else {
                if (req == TXMETA) {
                    inner.AddVarint(1, tx->version);
                    inner.AddVarint(4, tx->nLockTime);
                    inner.AddVarint(6, inputs.size());
                    inner.AddVarint(7, outputs.size());
                } else if (req == TXINPUT && index >= 0 && static_cast<size_t>(index) < inputs.size()) {
                    inner.AddMessage(2, EncodeTxInput(inputs[index]));
                } else if (req == TXOUTPUT && index >= 0 && static_cast<size_t>(index) < outputs.size()) {
                    inner.AddMessage(5, EncodeTxOutput(outputs[index]));
                }
            }
            ack.AddMessage(1, inner.Finish());
            auto next = m_wire.Call(MSG_TXACK, ack.Finish());
            rtype = next.first;
            rdata = std::move(next.second);
        }

        for (size_t i = 0; i < psbt.inputs.size() && i < sigs.size(); ++i) {
            if (std::find(ignore.begin(), ignore.end(), static_cast<int>(i)) != ignore.end()) continue;
            if (sigs[i].empty()) continue;
            auto& pin = psbt.inputs[i];
            if (pin.m_tap_internal_key.IsNull()) {
                for (const auto& [pub, origin] : pin.hd_keypaths) {
                    if (origin.fingerprint != fpr) continue;
                    auto sig = sigs[i];
                    if (sig.size() == 64) sig.push_back(0x01);
                    pin.partial_sigs[pub.GetID()] = SigPair(pub, sig);
                    break;
                }
            } else {
                pin.m_tap_key_sig = sigs[i];
            }
        }
        return psbt;
    }

    std::string SignMessage(const std::string& message, const std::string& bip32_path) const override
    {
        auto path = ParsePathOrThrow(bip32_path);
        PbWriter w;
        for (uint32_t n : path) w.AddVarint(1, n);
        w.AddBytes(2, std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(message.data()), message.size()});
        w.AddString(3, CoinName(GetChain()));
        auto [type, data] = m_wire.Call(MSG_SIGNMESSAGE, w.Finish());
        if (type != MSG_MESSAGESIGNATURE) throw HWIError("Unexpected Trezor SignMessage response", ErrorCode::UNKNOWN_ERROR);
        auto fields = PbDecode(data);
        auto sig = PbGetBytes(fields, 2);
        if (!sig) throw HWIError("Trezor MessageSignature missing signature", ErrorCode::UNKNOWN_ERROR);
        return EncodeBase64(*sig);
    }

    std::string DisplaySinglesigAddress(const std::string& bip32_path, OutputType type) const override
    {
        auto path = ParsePathOrThrow(bip32_path);
        int script = SPENDADDRESS;
        switch (type) {
        case OutputType::LEGACY: script = SPENDADDRESS; break;
        case OutputType::P2SH_SEGWIT: script = SPENDP2SHWITNESS; break;
        case OutputType::BECH32: script = SPENDWITNESS; break;
        case OutputType::BECH32M: script = SPENDTAPROOT; break;
        case OutputType::UNKNOWN: break;
        }
        PbWriter w;
        for (uint32_t n : path) w.AddVarint(1, n);
        w.AddString(2, CoinName(GetChain()));
        w.AddBool(3, true);
        w.AddVarint(5, script);
        auto [t, data] = m_wire.Call(MSG_GETADDRESS, w.Finish());
        if (t != MSG_ADDRESS) throw HWIError("Unexpected Trezor GetAddress response", ErrorCode::UNKNOWN_ERROR);
        auto fields = PbDecode(data);
        return PbGetString(fields, 1).value_or("");
    }

    bool CanSignTaproot() const override { return true; }
    void Close() override { m_wire.Close(); }

    bool PinProtection() const { return m_pin; }
    bool Unlocked() const { return m_unlocked; }
    bool Initialized() const { return m_initialized; }
    const std::string& Vendor() const { return m_vendor; }
    const std::string& Model() const { return m_model; }

    void Wipe()
    {
        auto [type, data] = m_wire.Call(MSG_WIPEDEVICE, {});
        if (type != MSG_SUCCESS) {
            throw HWIError("Trezor WipeDevice failed", ErrorCode::UNKNOWN_ERROR);
        }
        Init();
    }

    void LoadMnemonic(const std::string& mnemonic)
    {
        PbWriter w;
        w.AddString(1, mnemonic);
        w.AddBool(4, false);
        w.AddString(5, "en-US");
        w.AddString(6, "test");
        w.AddBool(7, true);
        auto [type, data] = m_wire.Call(MSG_LOADDEVICE, w.Finish());
        if (type != MSG_SUCCESS) {
            throw HWIError("Trezor LoadDevice failed", ErrorCode::UNKNOWN_ERROR);
        }
        Init();
    }

private:
    void Init()
    {
        auto [type, data] = m_wire.Call(MSG_INITIALIZE, {});
        if (type != MSG_FEATURES) throw HWIError("Trezor Initialize did not return Features", ErrorCode::DEVICE_CONN_ERROR);
        auto f = PbDecode(data);
        m_vendor = PbGetString(f, 1).value_or("");
        m_model = PbGetString(f, 21).value_or("1");
        m_pin = PbGetVarint(f, 7).value_or(0) != 0;
        m_passphrase = PbGetVarint(f, 8).value_or(0) != 0;
        m_initialized = PbGetVarint(f, 12).value_or(0) != 0;
        m_unlocked = PbGetVarint(f, 16).value_or(0) != 0;
    }

    mutable TrezorWire m_wire;
    std::string m_vendor;
    std::string m_model;
    bool m_pin{false};
    bool m_passphrase{false};
    bool m_initialized{true};
    bool m_unlocked{true};
};

DeviceInfo ProbeTrezor(const std::string& path)
{
    DeviceInfo info;
    info.type = "trezor";
    info.path = path;
    info.model = "trezor";
    try {
        TrezorClientImpl client(path, ChainType::MAIN);
        if (client.Vendor().find("trezor") == std::string::npos &&
            client.Vendor().find("bitcointrezor") == std::string::npos) {
            client.Close();
            info.error = "Not a Trezor";
            return info;
        }
        info.model = "trezor_" + client.Model();
        for (char& c : info.model) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        if (IsUdpPath(path)) info.model += "_simulator";
        info.needs_pin = client.PinProtection() && !client.Unlocked();
        if (!client.Initialized()) {
            info.error = "Not initialized";
        } else if (info.needs_pin) {
            info.error = "Trezor is locked";
        } else {
            info.fingerprint = FingerprintHex(client.GetMasterFingerprint());
        }
        client.Close();
    } catch (const std::exception& e) {
        info.error = e.what();
    }
    return info;
}

} // namespace

std::vector<DeviceInfo> EnumerateTrezor()
{
    std::vector<DeviceInfo> out;
    for (const HidInfo& hid : EnumerateHid(0, 0)) {
        if (!IsTrezorId(hid.vendor_id, hid.product_id)) continue;
        auto info = ProbeTrezor(hid.path);
        if (info.error == "Not a Trezor") continue;
        out.push_back(std::move(info));
    }
    const std::string udp = DefaultTrezorUdpPath();
    if (!udp.empty() && TrezorUdpAvailable(udp)) {
        out.push_back(ProbeTrezor(udp));
    }
    return out;
}

std::unique_ptr<HardwareWalletClient> ConnectTrezor(const DeviceInfo& info)
{
    return std::make_unique<TrezorClientImpl>(info.path, ChainType::MAIN);
}

void TrezorEmulatorLoadMnemonic(const std::string& path, const std::string& mnemonic)
{
    if (!IsUdpPath(path)) {
        throw HWIError("Trezor emulator LoadMnemonic requires a udp: path", ErrorCode::BAD_ARGUMENT);
    }
    TrezorClientImpl client(path, ChainType::MAIN);
    if (client.Initialized()) {
        client.Wipe();
    }
    client.LoadMnemonic(mnemonic);
}

} // namespace hwi
