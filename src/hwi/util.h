// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_UTIL_H
#define BITCOIN_HWI_UTIL_H

#include <key.h>
#include <outputtype.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

class CTxOut;

namespace hwi {

CExtPubKey DecodeXpubAnyVersion(const std::string& xpub);
std::vector<uint32_t> ParsePathOrThrow(const std::string& path);
std::string PathToApostrophe(const std::vector<uint32_t>& path);
std::vector<unsigned char> SerializeBe32(uint32_t v);
std::vector<unsigned char> SerializeLe32(uint32_t v);
uint32_t ReadBe32(std::span<const unsigned char> s);
uint32_t ReadLe32(std::span<const unsigned char> s);
std::vector<unsigned char> Sha256(std::span<const unsigned char> data);
std::vector<unsigned char> Aes256Ctr(std::span<const unsigned char> key32,
                                     std::span<const unsigned char> data);

//! Session AES-256-CTR. ckcc keeps one encrypt counter and one decrypt
//! counter for the whole HID session; they must not restart at zero per
//! message (Mk3 4.2.0 / pyaes Counter).
class Aes256CtrStream
{
public:
    explicit Aes256CtrStream(std::span<const unsigned char> key32);
    ~Aes256CtrStream();
    Aes256CtrStream(Aes256CtrStream&&) noexcept;
    Aes256CtrStream& operator=(Aes256CtrStream&&) noexcept;
    Aes256CtrStream(const Aes256CtrStream&) = delete;
    Aes256CtrStream& operator=(const Aes256CtrStream&) = delete;
    std::vector<unsigned char> Crypt(std::span<const unsigned char> data);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

std::vector<unsigned char> EcdhUncompressedHash(const CKey& our_key,
                                                std::span<const unsigned char> their_xy64);
//! Coldcard `mitm` is ECDSA over the raw 32-byte session key (no Bitcoin
//! message prefix). `sig65` is the 1-byte header plus compact r||s.
bool VerifyEcdsaCompactRaw(const CPubKey& pub,
                           std::span<const unsigned char> hash32,
                           std::span<const unsigned char> sig65);

bool IsP2SH(const CScript& script);
bool IsP2WSH(const CScript& script);
bool IsP2PKH(const CScript& script);
int WitnessVersion(const CScript& script); //!< -1 if not witness

const CTxOut* InputUtxo(const ::PSBTInput& input);

std::string CoinName(ChainType chain);

} // namespace hwi

#endif // BITCOIN_HWI_UTIL_H
