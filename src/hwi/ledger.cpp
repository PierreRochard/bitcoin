// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/ledger.h>

#include <hwi/hid.h>
#include <hwi/hwi.h>
#include <hwi/transport.h>
#include <hwi/util.h>

#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <span>

namespace hwi {
namespace {

constexpr uint8_t CLA_BITCOIN = 0xe1;
constexpr uint8_t CLA_FRAMEWORK = 0xf8;
constexpr uint8_t INS_GET_XPUB = 0x00;
constexpr uint8_t INS_SIGN_PSBT = 0x04;
constexpr uint8_t INS_GET_FPR = 0x05;
constexpr uint8_t INS_SIGN_MSG = 0x10;
constexpr uint8_t INS_CONTINUE = 0x01;
constexpr uint16_t SW_OK = 0x9000;
constexpr uint16_t SW_INTERRUPTED = 0xe000;

std::vector<unsigned char> WriteVarint(uint64_t n)
{
    std::vector<unsigned char> out;
    if (n < 0xfd) {
        out.push_back(static_cast<unsigned char>(n));
    } else if (n <= 0xffff) {
        out.push_back(0xfd);
        out.push_back(n & 0xff);
        out.push_back((n >> 8) & 0xff);
    } else if (n <= 0xffffffffULL) {
        out.push_back(0xfe);
        auto le = SerializeLe32(static_cast<uint32_t>(n));
        out.insert(out.end(), le.begin(), le.end());
    } else {
        out.push_back(0xff);
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<unsigned char>(n >> (8 * i)));
    }
    return out;
}

std::vector<unsigned char> ElementHash(std::span<const unsigned char> preimage)
{
    std::vector<unsigned char> tagged;
    tagged.push_back(0x00);
    tagged.insert(tagged.end(), preimage.begin(), preimage.end());
    return Sha256(tagged);
}

std::vector<unsigned char> CombineHashes(std::span<const unsigned char> left, std::span<const unsigned char> right)
{
    std::vector<unsigned char> tagged{0x01};
    tagged.insert(tagged.end(), left.begin(), left.end());
    tagged.insert(tagged.end(), right.begin(), right.end());
    return Sha256(tagged);
}

class MerkleTree
{
public:
    explicit MerkleTree(std::vector<std::vector<unsigned char>> leaves) : m_leaves(std::move(leaves))
    {
        Build();
    }

    const std::vector<unsigned char>& Root() const { return m_root; }
    const std::vector<unsigned char>& Get(size_t i) const { return m_leaves.at(i); }

    size_t LeafIndex(const std::vector<unsigned char>& h) const
    {
        for (size_t i = 0; i < m_leaves.size(); ++i) {
            if (m_leaves[i] == h) return i;
        }
        throw HWIError("Merkle leaf not found", ErrorCode::UNKNOWN_ERROR);
    }

    std::vector<std::vector<unsigned char>> ProveLeaf(size_t index) const
    {
        std::vector<std::vector<unsigned char>> proof;
        size_t begin = 0;
        size_t size = m_leaves.size();
        size_t idx = index;
        Prove(begin, size, idx, proof);
        return proof;
    }

private:
    static size_t LargestPow2Lt(size_t n)
    {
        size_t p = 1;
        while (p * 2 < n) p *= 2;
        return p;
    }

    std::vector<unsigned char> HashRange(size_t begin, size_t size) const
    {
        if (size == 0) return std::vector<unsigned char>(32, 0);
        if (size == 1) return m_leaves[begin];
        const size_t l = LargestPow2Lt(size);
        auto left = HashRange(begin, l);
        auto right = HashRange(begin + l, size - l);
        return CombineHashes(left, right);
    }

    void Prove(size_t begin, size_t size, size_t idx, std::vector<std::vector<unsigned char>>& proof) const
    {
        if (size <= 1) return;
        const size_t l = LargestPow2Lt(size);
        if (idx < l) {
            Prove(begin, l, idx, proof);
            proof.push_back(HashRange(begin + l, size - l));
        } else {
            Prove(begin + l, size - l, idx - l, proof);
            proof.push_back(HashRange(begin, l));
        }
    }

    void Build()
    {
        if (m_leaves.empty()) {
            m_root.assign(32, 0);
        } else {
            m_root = HashRange(0, m_leaves.size());
        }
    }

    std::vector<std::vector<unsigned char>> m_leaves;
    std::vector<unsigned char> m_root;
};

std::vector<unsigned char> MapCommitment(const std::map<std::vector<unsigned char>, std::vector<unsigned char>>& m)
{
    std::vector<std::vector<unsigned char>> keys, vals;
    for (const auto& [k, v] : m) {
        keys.push_back(ElementHash(k));
        vals.push_back(ElementHash(v));
    }
    auto out = WriteVarint(m.size());
    auto kr = MerkleTree(keys).Root();
    auto vr = MerkleTree(vals).Root();
    out.insert(out.end(), kr.begin(), kr.end());
    out.insert(out.end(), vr.begin(), vr.end());
    return out;
}

using ByteMap = std::map<std::vector<unsigned char>, std::vector<unsigned char>>;

void ParseMaps(std::span<const unsigned char> psbt, ByteMap& global, std::vector<ByteMap>& inputs, std::vector<ByteMap>& outputs)
{
    auto read_compact = [&](size_t& off) -> uint64_t {
        if (off >= psbt.size()) throw HWIError("Truncated PSBT", ErrorCode::INVALID_TX);
        const unsigned char ch = psbt[off++];
        if (ch < 0xfd) return ch;
        if (ch == 0xfd) {
            if (off + 2 > psbt.size()) throw HWIError("Truncated PSBT", ErrorCode::INVALID_TX);
            uint64_t n = uint64_t(psbt[off]) | (uint64_t(psbt[off + 1]) << 8);
            off += 2;
            return n;
        }
        throw HWIError("Oversized PSBT compact size", ErrorCode::INVALID_TX);
    };
    auto read_bytes = [&](size_t& off) {
        const uint64_t n = read_compact(off);
        if (off + n > psbt.size()) throw HWIError("Truncated PSBT field", ErrorCode::INVALID_TX);
        std::vector<unsigned char> v(psbt.begin() + off, psbt.begin() + off + n);
        off += n;
        return v;
    };
    auto read_map = [&](size_t& off) {
        ByteMap m;
        while (true) {
            auto key = read_bytes(off);
            if (key.empty()) break;
            m.emplace(std::move(key), read_bytes(off));
        }
        return m;
    };

    size_t off = 0;
    if (psbt.size() < 5 || psbt[0] != 'p' || psbt[1] != 's' || psbt[2] != 'b' || psbt[3] != 't' || psbt[4] != 0xff) {
        throw HWIError("PSBT magic missing", ErrorCode::INVALID_TX);
    }
    off = 5;
    global = read_map(off);
    // Remaining maps alternate as inputs then we don't know counts for v0 easily.
    // Count unsigned-tx inputs from global 0x00 if present; otherwise consume until end pairing input/output by PSBT structure:
    // v0: global, then n_inputs maps, then n_outputs maps. n from unsigned tx.
    uint32_t n_in = 0, n_out = 0;
    auto it = global.find({0x00});
    if (it != global.end() && it->second.size() > 4) {
        DataStream ss{std::as_bytes(std::span{it->second})};
        CMutableTransaction tx;
        ss >> TX_NO_WITNESS(tx);
        n_in = tx.vin.size();
        n_out = tx.vout.size();
    }
    inputs.clear();
    outputs.clear();
    for (uint32_t i = 0; i < n_in; ++i) inputs.push_back(read_map(off));
    for (uint32_t i = 0; i < n_out; ++i) outputs.push_back(read_map(off));
}

class ClientInterpreter
{
public:
    std::vector<std::vector<unsigned char>> yielded;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> preimages;
    std::map<std::vector<unsigned char>, MerkleTree> trees;
    std::deque<std::vector<unsigned char>> queue;

    void AddPreimage(const std::vector<unsigned char>& pre)
    {
        preimages[Sha256(pre)] = pre;
    }
    void AddList(const std::vector<std::vector<unsigned char>>& items)
    {
        std::vector<std::vector<unsigned char>> hashes;
        for (const auto& it : items) hashes.push_back(ElementHash(it));
        MerkleTree mt(hashes);
        trees.emplace(mt.Root(), mt);
    }
    void AddMapping(const ByteMap& m)
    {
        std::vector<std::vector<unsigned char>> keys, vals;
        for (const auto& [k, v] : m) {
            AddPreimage(k);
            AddPreimage(v);
            keys.push_back(ElementHash(k));
            vals.push_back(ElementHash(v));
        }
        MerkleTree kt(keys), vt(vals);
        trees.emplace(kt.Root(), kt);
        trees.emplace(vt.Root(), vt);
    }

    std::vector<unsigned char> Execute(std::span<const unsigned char> req)
    {
        if (req.empty()) throw HWIError("Empty Ledger client command", ErrorCode::UNKNOWN_ERROR);
        const uint8_t code = req[0];
        auto rest = req.subspan(1);
        if (code == 0x10) { // YIELD
            yielded.emplace_back(rest.begin(), rest.end());
            return {};
        }
        if (code == 0x40) { // GET_PREIMAGE
            if (rest.size() < 33 || rest[0] != 0) throw HWIError("Bad GET_PREIMAGE", ErrorCode::UNKNOWN_ERROR);
            std::vector<unsigned char> h(rest.begin() + 1, rest.begin() + 33);
            auto it = preimages.find(h);
            if (it == preimages.end()) throw HWIError("Unknown preimage", ErrorCode::UNKNOWN_ERROR);
            const auto& pre = it->second;
            auto lenb = WriteVarint(pre.size());
            const size_t max_payload = 255 - lenb.size() - 1;
            const size_t payload = std::min(max_payload, pre.size());
            if (payload < pre.size()) {
                for (size_t i = payload; i < pre.size(); ++i) queue.push_back({pre[i]});
            }
            std::vector<unsigned char> out = lenb;
            out.push_back(static_cast<unsigned char>(payload));
            out.insert(out.end(), pre.begin(), pre.begin() + payload);
            return out;
        }
        if (code == 0x41) { // GET_MERKLE_LEAF_PROOF
            if (rest.size() < 32) throw HWIError("Bad GET_MERKLE_LEAF_PROOF", ErrorCode::UNKNOWN_ERROR);
            std::vector<unsigned char> root(rest.begin(), rest.begin() + 32);
            size_t off = 32;
            auto read_var = [&]() {
                if (off >= rest.size()) throw HWIError("Short varint", ErrorCode::UNKNOWN_ERROR);
                unsigned char ch = rest[off++];
                if (ch < 0xfd) return uint64_t(ch);
                throw HWIError("Unsupported varint", ErrorCode::UNKNOWN_ERROR);
            };
            const uint64_t tree_size = read_var();
            const uint64_t leaf_index = read_var();
            auto it = trees.find(root);
            if (it == trees.end()) throw HWIError("Unknown Merkle root", ErrorCode::UNKNOWN_ERROR);
            auto proof = it->second.ProveLeaf(leaf_index);
            const size_t n_resp = std::min<size_t>((255 - 32 - 1 - 1) / 32, proof.size());
            if (proof.size() > n_resp) {
                for (size_t i = n_resp; i < proof.size(); ++i) queue.push_back(proof[i]);
            }
            std::vector<unsigned char> out = it->second.Get(leaf_index);
            out.push_back(static_cast<unsigned char>(proof.size()));
            out.push_back(static_cast<unsigned char>(n_resp));
            for (size_t i = 0; i < n_resp; ++i) out.insert(out.end(), proof[i].begin(), proof[i].end());
            (void)tree_size;
            return out;
        }
        if (code == 0x42) { // GET_MERKLE_LEAF_INDEX
            if (rest.size() < 64) throw HWIError("Bad GET_MERKLE_LEAF_INDEX", ErrorCode::UNKNOWN_ERROR);
            std::vector<unsigned char> root(rest.begin(), rest.begin() + 32);
            std::vector<unsigned char> leaf(rest.begin() + 32, rest.begin() + 64);
            auto it = trees.find(root);
            uint8_t found = 0;
            uint64_t idx = 0;
            if (it != trees.end()) {
                try {
                    idx = it->second.LeafIndex(leaf);
                    found = 1;
                } catch (...) {
                    found = 0;
                }
            }
            auto out = std::vector<unsigned char>{found};
            auto v = WriteVarint(idx);
            out.insert(out.end(), v.begin(), v.end());
            return out;
        }
        if (code == 0xa0) { // GET_MORE_ELEMENTS
            if (queue.empty()) throw HWIError("No queued elements", ErrorCode::UNKNOWN_ERROR);
            const size_t elen = queue.front().size();
            std::vector<unsigned char> payload;
            uint8_t n = 0;
            while (!queue.empty() && payload.size() + elen <= 253) {
                payload.insert(payload.end(), queue.front().begin(), queue.front().end());
                queue.pop_front();
                ++n;
            }
            std::vector<unsigned char> out{n, static_cast<unsigned char>(elen)};
            out.insert(out.end(), payload.begin(), payload.end());
            return out;
        }
        throw HWIError(strprintf("Unknown Ledger client command 0x%02x", code), ErrorCode::UNKNOWN_ERROR);
    }
};

class LedgerTransport
{
public:
    explicit LedgerTransport(const std::string& path)
    {
        if (IsTcpPath(path)) {
            const auto hp = ParseTcpPath(path);
            if (!hp) throw HWIError("Invalid Ledger TCP path: " + path, ErrorCode::BAD_ARGUMENT);
            m_tcp = std::make_unique<TcpApduLink>(hp->host, hp->port);
        } else {
            m_hid = std::make_unique<HidConnection>(path);
        }
    }

    void Close()
    {
        if (m_tcp) m_tcp->Close();
        if (m_hid) m_hid->Close();
    }

    std::pair<uint16_t, std::vector<unsigned char>> Exchange(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                                                             const std::vector<unsigned char>& data)
    {
        std::vector<unsigned char> apdu{cla, ins, p1, p2, static_cast<unsigned char>(data.size())};
        apdu.insert(apdu.end(), data.begin(), data.end());
        if (m_tcp) return m_tcp->Exchange(apdu);
        SendApdu(apdu);
        return RecvApdu();
    }

private:
    void SendApdu(const std::vector<unsigned char>& apdu)
    {
        std::vector<unsigned char> wrapped;
        wrapped.push_back(static_cast<unsigned char>(apdu.size() >> 8));
        wrapped.push_back(static_cast<unsigned char>(apdu.size()));
        wrapped.insert(wrapped.end(), apdu.begin(), apdu.end());
        size_t offset = 0;
        uint16_t seq = 0;
        while (offset < wrapped.size()) {
            std::vector<unsigned char> chunk{0x01, 0x01, 0x05,
                                             static_cast<unsigned char>(seq >> 8),
                                             static_cast<unsigned char>(seq)};
            const size_t space = 64 - chunk.size();
            const size_t n = std::min(space, wrapped.size() - offset);
            chunk.insert(chunk.end(), wrapped.begin() + offset, wrapped.begin() + offset + n);
            chunk.resize(64, 0);
            m_hid->Write(chunk);
            offset += n;
            ++seq;
        }
    }

    std::pair<uint16_t, std::vector<unsigned char>> RecvApdu()
    {
        auto first = m_hid->Read(30000);
        if (first.empty()) throw HWIError("Timeout reading Ledger", ErrorCode::DEVICE_CONN_ERROR);
        if (first.size() == 65 && first[0] == 0) first.erase(first.begin());
        if (first.size() < 7 || first[0] != 0x01 || first[1] != 0x01 || first[2] != 0x05) {
            throw HWIError("Invalid Ledger HID header", ErrorCode::DEVICE_CONN_ERROR);
        }
        const uint16_t data_len = (uint16_t(first[5]) << 8) | first[6];
        std::vector<unsigned char> data(first.begin() + 7, first.end());
        uint16_t seq = 1;
        while (data.size() < data_len) {
            auto more = m_hid->Read(5000);
            if (more.empty()) throw HWIError("Timeout reading Ledger continuation", ErrorCode::DEVICE_CONN_ERROR);
            if (more.size() == 65 && more[0] == 0) more.erase(more.begin());
            if (more.size() < 5) throw HWIError("Short Ledger packet", ErrorCode::DEVICE_CONN_ERROR);
            data.insert(data.end(), more.begin() + 5, more.end());
            ++seq;
        }
        data.resize(data_len);
        if (data.size() < 2) throw HWIError("Ledger APDU too short", ErrorCode::DEVICE_CONN_ERROR);
        const uint16_t sw = (uint16_t(data[data.size() - 2]) << 8) | data.back();
        data.resize(data.size() - 2);
        (void)seq;
        return {sw, data};
    }

    std::unique_ptr<HidConnection> m_hid;
    std::unique_ptr<TcpApduLink> m_tcp;
};

std::vector<unsigned char> PathBytes(const std::vector<uint32_t>& path)
{
    std::vector<unsigned char> out;
    out.push_back(static_cast<unsigned char>(path.size()));
    for (uint32_t p : path) {
        auto be = SerializeBe32(p);
        out.insert(out.end(), be.begin(), be.end());
    }
    return out;
}

class LedgerClientImpl final : public HardwareWalletClient
{
public:
    LedgerClientImpl(std::string path, ChainType chain)
        : HardwareWalletClient(std::move(path), chain), m_dev(Path())
    {
    }

    std::string Type() const override { return "ledger"; }

    KeyFingerprint GetMasterFingerprint() const override
    {
        auto [sw, data] = m_dev.Exchange(CLA_BITCOIN, INS_GET_FPR, 0, 1, {});
        if (sw != SW_OK || data.size() < 4) {
            throw HWIError(strprintf("Ledger get_master_fingerprint failed sw=%04x", sw), ErrorCode::DEVICE_CONN_ERROR);
        }
        KeyFingerprint fpr{};
        std::copy_n(data.begin(), 4, fpr.begin());
        return fpr;
    }

    CExtPubKey GetPubkeyAtPath(const std::string& bip32_path) const override
    {
        auto path = ParsePathOrThrow(bip32_path);
        std::vector<unsigned char> cdata{0}; // display=false
        auto pb = PathBytes(path);
        cdata.insert(cdata.end(), pb.begin(), pb.end());
        auto [sw, data] = MakeRequest(CLA_BITCOIN, INS_GET_XPUB, 0, 1, cdata);
        if (sw != SW_OK) {
            throw HWIError(strprintf("Ledger get_extended_pubkey failed sw=%04x", sw), ErrorCode::BAD_ARGUMENT);
        }
        return DecodeXpubAnyVersion(std::string(data.begin(), data.end()));
    }

    PartiallySignedTransaction SignTx(PartiallySignedTransaction psbt) const override
    {
        DataStream ss{};
        ss << psbt;
        std::vector<unsigned char> raw(UCharCast(ss.data()), UCharCast(ss.data()) + ss.size());
        ByteMap global;
        std::vector<ByteMap> ins, outs;
        ParseMaps(raw, global, ins, outs);

        const auto fpr = GetMasterFingerprint();
        std::string key_info;
        OutputType addr_type = OutputType::BECH32;
        for (const auto& input : psbt.inputs) {
            for (const auto& [pub, origin] : input.hd_keypaths) {
                if (origin.fingerprint != fpr || origin.path.size() < 3) continue;
                addr_type = OutputType::BECH32;
                const auto xpub = GetPubkeyAtPath(WriteHDKeypath({origin.path[0], origin.path[1], origin.path[2]}));
                key_info = strprintf("[%s%s]%s", FingerprintHex(fpr), FormatHDKeypath({origin.path[0], origin.path[1], origin.path[2]}, true), EncodeExtPubKey(xpub));
                break;
            }
            if (!key_info.empty()) break;
        }
        if (key_info.empty()) throw HWIError("No Ledger key found in PSBT", ErrorCode::INVALID_TX);

        std::string templ = "wpkh(@0/**)";
        const std::vector<unsigned char> name{};
        auto keys_hash = ElementHash(std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(key_info.data()), key_info.size()});
        MerkleTree keys_tree({keys_hash});
        std::vector<unsigned char> policy;
        policy.push_back(2); // WALLET_POLICY_V2
        policy.push_back(0); // empty name
        auto desc = std::string(templ);
        auto desc_len = WriteVarint(desc.size());
        policy.insert(policy.end(), desc_len.begin(), desc_len.end());
        auto desc_hash = Sha256(std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(desc.data()), desc.size()});
        policy.insert(policy.end(), desc_hash.begin(), desc_hash.end());
        auto nkeys = WriteVarint(1);
        policy.insert(policy.end(), nkeys.begin(), nkeys.end());
        policy.insert(policy.end(), keys_tree.Root().begin(), keys_tree.Root().end());
        const auto wallet_id = Sha256(policy);

        ClientInterpreter interp;
        interp.AddPreimage(policy);
        interp.AddPreimage(std::vector<unsigned char>(desc.begin(), desc.end()));
        interp.AddList({std::vector<unsigned char>(key_info.begin(), key_info.end())});
        interp.AddMapping(global);
        std::vector<std::vector<unsigned char>> in_commit, out_commit;
        for (const auto& m : ins) {
            interp.AddMapping(m);
            in_commit.push_back(MapCommitment(m));
        }
        for (const auto& m : outs) {
            interp.AddMapping(m);
            out_commit.push_back(MapCommitment(m));
        }
        interp.AddList(in_commit);
        interp.AddList(out_commit);

        std::vector<unsigned char> cdata = MapCommitment(global);
        auto n_in = WriteVarint(ins.size());
        cdata.insert(cdata.end(), n_in.begin(), n_in.end());
        std::vector<std::vector<unsigned char>> in_hashes;
        for (const auto& c : in_commit) in_hashes.push_back(ElementHash(c));
        auto in_root = MerkleTree(in_hashes).Root();
        cdata.insert(cdata.end(), in_root.begin(), in_root.end());
        auto n_out = WriteVarint(outs.size());
        cdata.insert(cdata.end(), n_out.begin(), n_out.end());
        std::vector<std::vector<unsigned char>> out_hashes;
        for (const auto& c : out_commit) out_hashes.push_back(ElementHash(c));
        auto out_root = MerkleTree(out_hashes).Root();
        cdata.insert(cdata.end(), out_root.begin(), out_root.end());
        cdata.insert(cdata.end(), wallet_id.begin(), wallet_id.end());
        cdata.insert(cdata.end(), 32, 0); // hmac empty

        auto [sw, _] = MakeRequest(CLA_BITCOIN, INS_SIGN_PSBT, 0, 1, cdata, &interp);
        if (sw != SW_OK) {
            throw HWIError(strprintf("Ledger sign_psbt failed sw=%04x", sw), ErrorCode::UNKNOWN_ERROR);
        }
        for (const auto& y : interp.yielded) {
            if (y.size() < 3) continue;
            // varint index, uint8 pubkey_len, pubkey, signature
            size_t off = 0;
            uint64_t idx = y[off++];
            if (idx == 0xfd && y.size() > off + 2) {
                idx = uint64_t(y[off]) | (uint64_t(y[off + 1]) << 8);
                off += 2;
            }
            if (off >= y.size()) continue;
            const uint8_t pklen = y[off++];
            if (off + pklen > y.size()) continue;
            CPubKey pub(y.data() + off, y.data() + off + pklen);
            off += pklen;
            std::vector<unsigned char> sig(y.begin() + off, y.end());
            if (idx < psbt.inputs.size() && pub.IsValid()) {
                psbt.inputs[idx].partial_sigs[pub.GetID()] = SigPair(pub, sig);
            } else if (idx < psbt.inputs.size() && pklen == 32) {
                psbt.inputs[idx].m_tap_key_sig = sig;
            }
        }
        (void)addr_type;
        return psbt;
    }

    std::string SignMessage(const std::string& message, const std::string& bip32_path) const override
    {
        auto path = ParsePathOrThrow(bip32_path);
        std::vector<unsigned char> msg(message.begin(), message.end());
        std::vector<std::vector<unsigned char>> chunks;
        for (size_t i = 0; i < msg.size(); i += 64) {
            chunks.emplace_back(msg.begin() + i, msg.begin() + std::min(i + 64, msg.size()));
        }
        std::vector<std::vector<unsigned char>> hashes;
        for (const auto& c : chunks) hashes.push_back(ElementHash(c));
        ClientInterpreter interp;
        for (const auto& c : chunks) interp.AddPreimage(c);
        interp.AddList(std::vector<std::vector<unsigned char>>(msg.size() ? chunks : std::vector<std::vector<unsigned char>>{}));

        std::vector<unsigned char> cdata = PathBytes(path);
        auto ml = WriteVarint(msg.size());
        cdata.insert(cdata.end(), ml.begin(), ml.end());
        auto root = MerkleTree(hashes).Root();
        cdata.insert(cdata.end(), root.begin(), root.end());
        auto [sw, data] = MakeRequest(CLA_BITCOIN, INS_SIGN_MSG, 0, 1, cdata, &interp);
        if (sw != SW_OK) throw HWIError("Ledger sign_message failed", ErrorCode::UNKNOWN_ERROR);
        return EncodeBase64(data);
    }

    bool CanSignTaproot() const override { return true; }
    void Close() override { m_dev.Close(); }

private:
    std::pair<uint16_t, std::vector<unsigned char>> MakeRequest(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                                                                const std::vector<unsigned char>& data,
                                                                ClientInterpreter* interp = nullptr) const
    {
        auto [sw, resp] = m_dev.Exchange(cla, ins, p1, p2, data);
        while (sw == SW_INTERRUPTED) {
            if (!interp) throw HWIError("Unexpected Ledger interrupted execution", ErrorCode::UNKNOWN_ERROR);
            auto cont = interp->Execute(resp);
            auto out = m_dev.Exchange(CLA_FRAMEWORK, INS_CONTINUE, 0, 1, cont);
            sw = out.first;
            resp = std::move(out.second);
        }
        return {sw, resp};
    }

    mutable LedgerTransport m_dev;
};

std::string LedgerModelName(uint16_t product_id)
{
    switch (static_cast<uint8_t>(product_id >> 8)) {
    case 0x10: return "ledger_nano_s";
    case 0x40: return "ledger_nano_x";
    case 0x50: return "ledger_nano_s_plus";
    case 0x60: return "ledger_stax";
    case 0x70: return "ledger_flex";
    case 0x80: return "ledger_nano_gen5";
    default: return "ledger";
    }
}

DeviceInfo ProbeLedger(const std::string& path, const std::string& model)
{
    DeviceInfo info;
    info.type = "ledger";
    info.model = model;
    info.path = path;
    try {
        LedgerClientImpl client(path, ChainType::MAIN);
        info.fingerprint = FingerprintHex(client.GetMasterFingerprint());
        client.Close();
    } catch (const std::exception& e) {
        info.error = e.what();
    }
    return info;
}

} // namespace

std::vector<DeviceInfo> EnumerateLedger()
{
    std::vector<DeviceInfo> out;
    for (const HidInfo& hid : EnumerateHid(LEDGER_VID, 0)) {
        if (!(hid.interface_number == 0 || hid.usage_page == 0xffa0)) continue;
        auto info = ProbeLedger(hid.path, LedgerModelName(hid.product_id));
        out.push_back(std::move(info));
    }
    const std::string tcp = DefaultLedgerTcpPath();
    if (!tcp.empty() && LedgerTcpAvailable(tcp)) {
        auto info = ProbeLedger(tcp, "ledger_simulator");
        // Speculos with no Bitcoin app (or a different app) has no fingerprint.
        if (!info.fingerprint.empty()) out.push_back(std::move(info));
    }
    return out;
}

std::unique_ptr<HardwareWalletClient> ConnectLedger(const DeviceInfo& info)
{
    return std::make_unique<LedgerClientImpl>(info.path, ChainType::MAIN);
}

} // namespace hwi
