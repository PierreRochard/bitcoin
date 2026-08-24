// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_BIP39_H
#define BITCOIN_WALLET_BIP39_H

#include <support/allocators/secure.h>

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace wallet {

inline constexpr size_t BIP39_ENTROPY_SIZE{32};
inline constexpr size_t BIP39_SEED_SIZE{64};

using BIP39SecureBytes = std::vector<unsigned char, secure_allocator<unsigned char>>;

//! Encode 256 bits of entropy as a 24-word English BIP39 mnemonic.
SecureString EncodeBIP39Mnemonic(std::span<const unsigned char, BIP39_ENTROPY_SIZE> entropy);

//! Decode and checksum-validate a 24-word English BIP39 mnemonic.
std::optional<BIP39SecureBytes> DecodeBIP39Mnemonic(std::string_view mnemonic);

//! Return whether a mnemonic is a valid 24-word English BIP39 mnemonic.
bool IsValidBIP39Mnemonic(std::string_view mnemonic);

//! Derive the 64-byte BIP39 seed. The passphrase must already be UTF-8 NFKD.
//! Product recovery sheets use the empty passphrase.
std::optional<BIP39SecureBytes> BIP39MnemonicToSeed(std::string_view mnemonic,
                                                    std::string_view passphrase = {});

//! Official sorted 2,048-word English BIP39 list.
std::span<const std::string_view> BIP39EnglishWords();

} // namespace wallet

#endif // BITCOIN_WALLET_BIP39_H
