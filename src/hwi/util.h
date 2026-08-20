// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_UTIL_H
#define BITCOIN_HWI_UTIL_H

#include <key.h>
#include <outputtype.h>
#include <psbt.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <cstdint>
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
std::vector<unsigned char> EcdhUncompressedHash(const CKey& our_key,
                                                std::span<const unsigned char> their_xy64);

bool IsP2SH(const CScript& script);
bool IsP2WSH(const CScript& script);
bool IsP2PKH(const CScript& script);
int WitnessVersion(const CScript& script); //!< -1 if not witness

const CTxOut* InputUtxo(const ::PSBTInput& input);

std::string CoinName(ChainType chain);

} // namespace hwi

#endif // BITCOIN_HWI_UTIL_H
