// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_MULTISIG_H
#define BITCOIN_WALLET_MULTISIG_H

#include <outputtype.h>
#include <util/result.h>
#include <util/translation.h>

#include <optional>
#include <string>
#include <vector>

namespace wallet {
class CWallet;

//! One participant in a multisig descriptor (sortedmulti, musig, or sortedmulti_a).
struct MultisigKeySpec {
    //! BIP32 path from the master key. Empty means the default BIP48 path.
    std::optional<std::string> path;
    //! 8-character hex master fingerprint. With xpub, this is an air-gapped
    //! key (no device required). Without xpub, the xpub is fetched from that
    //! connected signer.
    std::optional<std::string> fingerprint;
    //! Local HD xpub (see gethdkeys) when the key is derived in this wallet.
    std::optional<std::string> hdkey;
    //! Public xpub already known (air-gapped export, coordinator transcript).
    std::optional<std::string> xpub;
    //! Human label for the backup transcript only.
    std::string label;
};

struct MultisigOptions {
    OutputType type{OutputType::BECH32};
    uint32_t account{0};
    std::optional<bool> internal_only;
};

struct MultisigDescriptorResult {
    int nrequired{0};
    std::vector<std::string> descs;
    std::vector<std::string> key_exprs;
};

//! BIP48 account path. Script type 0/1/2/3 = legacy / p2sh-segwit / bech32 / bech32m.
std::string DefaultMultisigPath(OutputType type, uint32_t account);
//! Wrap key expressions: sh/wsh(sortedmulti) for pre-taproot; for bech32m,
//! n-of-n is tr(musig(...)/<0;1>/*), m-of-n is tr(NUMS,sortedmulti_a(...)).
std::string WrapSortedMulti(OutputType type, int nrequired, const std::vector<std::string>& keys);

bilingual_str ValidateMultisigPolicy(int nrequired, size_t nkeys);

//! Printable backup in the spirit of Specter/Sparrow transcripts.
std::string FormatMultisigTranscript(const std::string& wallet_name,
                                     const std::string& chain,
                                     int nrequired,
                                     const std::vector<MultisigKeySpec>& keys,
                                     OutputType type,
                                     const std::vector<std::string>& public_descs);

//! Import an active sorted-multisig descriptor. Caller must hold cs_wallet
//! and, for wallets with private keys, have unlocked the wallet.
util::Result<MultisigDescriptorResult> CreateMultisigDescriptor(CWallet& wallet,
                                                                int nrequired,
                                                                const std::vector<MultisigKeySpec>& keys,
                                                                const MultisigOptions& options);
} // namespace wallet

#endif // BITCOIN_WALLET_MULTISIG_H
