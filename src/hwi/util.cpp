// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/util.h>

#include <hwi/hwi.h>

#include <base58.h>
#include <crypto/aes.h>
#include <crypto/sha256.h>
#include <key.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/solver.h>
#include <secp256k1.h>
#include <span.h>
#include <util/bip32.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>
#include <memory>

namespace hwi {

CExtPubKey DecodeXpubAnyVersion(const std::string& xpub)
{
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(xpub, data, 78) || data.size() != 78) {
        throw HWIError("Invalid xpub", ErrorCode::BAD_ARGUMENT);
    }
    CExtPubKey out;
    out.Decode(data.data() + 4);
    return out;
}

std::vector<uint32_t> ParsePathOrThrow(const std::string& path)
{
    std::vector<uint32_t> out;
    if (!ParseHDKeypath(path, out)) {
        throw HWIError("Invalid BIP32 path: " + path, ErrorCode::BAD_ARGUMENT);
    }
    return out;
}

std::string PathToApostrophe(const std::vector<uint32_t>& path)
{
    return FormatHDKeypath(path, /*apostrophe=*/true);
}

std::vector<unsigned char> SerializeBe32(uint32_t v)
{
    return {static_cast<unsigned char>(v >> 24),
            static_cast<unsigned char>(v >> 16),
            static_cast<unsigned char>(v >> 8),
            static_cast<unsigned char>(v)};
}

std::vector<unsigned char> SerializeLe32(uint32_t v)
{
    return {static_cast<unsigned char>(v),
            static_cast<unsigned char>(v >> 8),
            static_cast<unsigned char>(v >> 16),
            static_cast<unsigned char>(v >> 24)};
}

uint32_t ReadBe32(std::span<const unsigned char> s)
{
    if (s.size() < 4) throw HWIError("Short be32", ErrorCode::INVALID_TX);
    return (uint32_t(s[0]) << 24) | (uint32_t(s[1]) << 16) | (uint32_t(s[2]) << 8) | uint32_t(s[3]);
}

uint32_t ReadLe32(std::span<const unsigned char> s)
{
    if (s.size() < 4) throw HWIError("Short le32", ErrorCode::INVALID_TX);
    return uint32_t(s[0]) | (uint32_t(s[1]) << 8) | (uint32_t(s[2]) << 16) | (uint32_t(s[3]) << 24);
}

std::vector<unsigned char> Sha256(std::span<const unsigned char> data)
{
    std::vector<unsigned char> out(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(data.data(), data.size()).Finalize(out.data());
    return out;
}

std::vector<unsigned char> Aes256Ctr(std::span<const unsigned char> key32, std::span<const unsigned char> data)
{
    Aes256CtrStream stream{key32};
    return stream.Crypt(data);
}

struct Aes256CtrStream::Impl
{
    explicit Impl(std::span<const unsigned char> key32) : enc{key32.data()} {}

    AES256Encrypt enc;
    unsigned char counter[16] = {};
    unsigned char keystream[16] = {};
    size_t ks_off{16};
};

Aes256CtrStream::Aes256CtrStream(std::span<const unsigned char> key32)
{
    if (key32.size() != 32) {
        throw HWIError("AES-256-CTR key must be 32 bytes", ErrorCode::BAD_ARGUMENT);
    }
    m_impl = std::make_unique<Impl>(key32);
}

Aes256CtrStream::~Aes256CtrStream() = default;
Aes256CtrStream::Aes256CtrStream(Aes256CtrStream&&) noexcept = default;
Aes256CtrStream& Aes256CtrStream::operator=(Aes256CtrStream&&) noexcept = default;

std::vector<unsigned char> Aes256CtrStream::Crypt(std::span<const unsigned char> data)
{
    std::vector<unsigned char> out(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        if (m_impl->ks_off == 16) {
            m_impl->enc.Encrypt(m_impl->keystream, m_impl->counter);
            m_impl->ks_off = 0;
            for (int c = 15; c >= 0; --c) {
                if (++m_impl->counter[c] != 0) break;
            }
        }
        out[i] = data[i] ^ m_impl->keystream[m_impl->ks_off++];
    }
    return out;
}

std::vector<unsigned char> EcdhUncompressedHash(const CKey& our_key, std::span<const unsigned char> their_xy64)
{
    if (!our_key.IsValid() || their_xy64.size() != 64) {
        throw HWIError("Invalid ECDH inputs", ErrorCode::DEVICE_CONN_ERROR);
    }
    secp256k1_context* ctx = GetSecp256k1SignContext();
    unsigned char raw[65];
    raw[0] = 0x04;
    memcpy(raw + 1, their_xy64.data(), 64);
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, raw, 65)) {
        throw HWIError("Peer ECDH pubkey is invalid", ErrorCode::DEVICE_CONN_ERROR);
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pk, UCharCast(our_key.data()))) {
        throw HWIError("ECDH multiply failed", ErrorCode::DEVICE_CONN_ERROR);
    }
    size_t len = 65;
    unsigned char out[65];
    secp256k1_ec_pubkey_serialize(ctx, out, &len, &pk, SECP256K1_EC_UNCOMPRESSED);
    return Sha256({out + 1, 64});
}

bool VerifyEcdsaCompactRaw(const CPubKey& pub,
                           std::span<const unsigned char> hash32,
                           std::span<const unsigned char> sig65)
{
    if (!pub.IsValid() || hash32.size() != 32 || sig65.size() != 65) return false;
    secp256k1_context* ctx = GetSecp256k1SignContext();
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pub.data(), pub.size())) return false;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig65.data() + 1)) return false;
    return secp256k1_ecdsa_verify(ctx, &sig, hash32.data(), &pk) == 1;
}

bool IsP2SH(const CScript& script)
{
    std::vector<std::vector<unsigned char>> sol;
    return Solver(script, sol) == TxoutType::SCRIPTHASH;
}

bool IsP2WSH(const CScript& script)
{
    std::vector<std::vector<unsigned char>> sol;
    return Solver(script, sol) == TxoutType::WITNESS_V0_SCRIPTHASH;
}

bool IsP2PKH(const CScript& script)
{
    std::vector<std::vector<unsigned char>> sol;
    return Solver(script, sol) == TxoutType::PUBKEYHASH;
}

int WitnessVersion(const CScript& script)
{
    std::vector<std::vector<unsigned char>> sol;
    switch (Solver(script, sol)) {
    case TxoutType::WITNESS_V0_KEYHASH:
    case TxoutType::WITNESS_V0_SCRIPTHASH:
        return 0;
    case TxoutType::WITNESS_V1_TAPROOT:
        return 1;
    default:
        return -1;
    }
}

const CTxOut* InputUtxo(const PSBTInput& input)
{
    if (!input.witness_utxo.IsNull()) return &input.witness_utxo;
    if (input.non_witness_utxo) {
        const auto& tx = *input.non_witness_utxo;
        if (input.prev_out < tx.vout.size()) return &tx.vout[input.prev_out];
    }
    return nullptr;
}

std::string CoinName(ChainType chain)
{
    return chain == ChainType::MAIN ? "Bitcoin" : "Testnet";
}

} // namespace hwi
