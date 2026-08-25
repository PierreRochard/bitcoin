// Copyright (c) 2010-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! @file common/types.h is a home for simple enum and struct type definitions
//! that can be used internally by functions in the libbitcoin_common library,
//! but also used externally by node, wallet, and GUI code.
//!
//! This file is intended to define only simple types that do not have external
//! dependencies. More complicated types should be defined in dedicated header
//! files.

#ifndef BITCOIN_COMMON_TYPES_H
#define BITCOIN_COMMON_TYPES_H

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace common {
enum class PSBTError {
    MISSING_INPUTS,
    SIGHASH_MISMATCH,
    EXTERNAL_SIGNER_NOT_FOUND,
    EXTERNAL_SIGNER_FAILED,
    WALLET_RESCAN_REQUIRED,
    VAULT_POLICY_MISMATCH,
    UNSUPPORTED,
    INCOMPLETE,
    INVALID_TX,
    OK,
};
/**
 * Instructions for how a PSBT should be signed or filled with information.
 */
struct PSBTFillOptions {
    /**
     * Whether to sign or not.
     */
    bool sign{true};

    /**
     * The sighash type to use when signing (if PSBT does not specify).
     */
    std::optional<int> sighash_type{std::nullopt};

    /**
     * Whether to create the final scriptSig or scriptWitness if possible.
     */
    bool finalize{true};

    /**
     * Whether to fill in bip32 derivation information if available.
     */
    bool bip32_derivs{true};

    /**
     * Master fingerprints whose private keys must not be used. Recovery Vault
     * spending uses this to keep an explicitly lost participant out of local
     * signing while allowing a mature threshold branch to use the remaining
     * trusted participants.
     */
    std::vector<std::array<unsigned char, 4>> excluded_signer_fingerprints;

    /**
     * Input indexes on which excluded signer fingerprints apply. Keeping the
     * scope explicit prevents Recovery Vault loss metadata from suppressing a
     * reused key fingerprint on unrelated descriptors in the same wallet.
     */
    std::vector<size_t> excluded_signer_input_indices;

    /**
     * Full Recovery Vault policy commitment expected by the caller. When
     * present, the wallet must reject the operation under its wallet lock if
     * the active policy changed before any PSBT data is added or signed.
     */
    std::optional<std::string> expected_vault_policy_commitment;
};

} // namespace common

#endif // BITCOIN_COMMON_TYPES_H
