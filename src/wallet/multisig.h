// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_MULTISIG_H
#define BITCOIN_WALLET_MULTISIG_H

#include <consensus/amount.h>
#include <outputtype.h>
#include <util/result.h>
#include <util/translation.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {
class CWallet;
class CCoinControl;

//! One participant in a multisig descriptor (sortedmulti, musig, or sortedmulti_a).
struct MultisigKeySpec {
    //! BIP32 path from the master key. Empty means the default BIP48 path.
    std::optional<std::string> path;
    //! 8-character hex master fingerprint. With xpub, this is an air-gapped
    //! key (no device required). Without xpub, the xpub is fetched from that
    //! connected signer.
    std::optional<std::string> fingerprint;
    //! Local HD xpub (see gethdkeys) or xprv when the key is derived in this
    //! wallet. An xprv does not need a prior unused() import.
    std::optional<std::string> hdkey;
    //! Public xpub already known (air-gapped export, coordinator transcript).
    std::optional<std::string> xpub;
    //! Human label for the backup transcript only.
    std::string label;
    //! If true, this key is absent from the MuSig2 key-path and appears only
    //! in the delayed recovery script (inheritance / recovery-only signer).
    bool recovery_only{false};
};

struct MultisigOptions {
    OutputType type{OutputType::BECH32};
    uint32_t account{0};
    std::optional<bool> internal_only;
    //! BIP 68 relative delay in blocks (miniscript older()). On bech32m this
    //! builds tr(musig(…),and_v(v:older(N),multi_a(nrequired,…))):
    //! n-of-n MuSig2 key-path now, m-of-n script-path after N confirmations.
    std::optional<uint32_t> fallback_older;
    //! Absolute CLTV height (miniscript after()). Mutually exclusive with
    //! fallback_older. Recovery is valid at and after this block height.
    std::optional<uint32_t> fallback_after;
};

struct MultisigDescriptorResult {
    int nrequired{0};
    std::vector<std::string> descs;
    std::vector<std::string> key_exprs;
    std::optional<uint32_t> fallback_older;
    std::optional<uint32_t> fallback_after;
    std::string policy_id;
};

//! Parsed Scrooge vault fields from a descriptor string.
struct InferredVaultPolicy {
    bool is_vault{false};
    std::optional<uint32_t> older;
    std::optional<uint32_t> after;
    int recovery_m{0};
};

//! BIP48 account path. Script type 0/1/2/3 = legacy / p2sh-segwit / bech32 / bech32m.
std::string DefaultMultisigPath(OutputType type, uint32_t account);
//! Wrap key expressions: sh/wsh(sortedmulti) for pre-taproot; for bech32m,
//! n-of-n is tr(musig(...)/<0;1>/*), m-of-n is tr(NUMS,sortedmulti_a(...)).
//! With fallback_older/after, bech32m is a Scrooge vault: tr(musig(active),
//! and_v(older|after, multi_a(m, recovery))). recovery_keys empty means keys.
std::string WrapSortedMulti(OutputType type, int nrequired, const std::vector<std::string>& keys,
                            std::optional<uint32_t> fallback_older = {},
                            std::optional<uint32_t> fallback_after = {},
                            const std::vector<std::string>& recovery_keys = {});

//! Type-aware key-count limits: 15 (P2SH), 20 (P2WSH), 999 (Taproot multi_a /
//! Scrooge vault fallback). n-of-n bech32m MuSig2 has no consensus cap.
bilingual_str ValidateMultisigPolicy(int nrequired, size_t nkeys,
                                     OutputType type = OutputType::BECH32,
                                     std::optional<uint32_t> fallback_older = {},
                                     std::optional<uint32_t> fallback_after = {},
                                     size_t n_recovery_keys = 0);

//! Parse older(N) out of a Scrooge vault descriptor, if present.
std::optional<uint32_t> InferTaprootRecoveryDelay(const std::string& desc);
//! Parse older(N) / after(H) / recovery m from a Scrooge vault descriptor.
InferredVaultPolicy InferVaultPolicy(const std::string& desc);
//! Short hex id of a checksummed receive descriptor (no private material).
std::string VaultPolicyId(std::string_view desc);
//! Empty if every signer looks independent; otherwise a same-seed warning.
bilingual_str DuplicateSignerWarning(const std::vector<MultisigKeySpec>& keys);

//! Printable backup in the spirit of Specter/Sparrow transcripts.
std::string FormatMultisigTranscript(const std::string& wallet_name,
                                     const std::string& chain,
                                     int nrequired,
                                     const std::vector<MultisigKeySpec>& keys,
                                     OutputType type,
                                     const std::vector<std::string>& public_descs,
                                     std::optional<uint32_t> fallback_older = {},
                                     std::optional<uint32_t> fallback_after = {});

//! Import an active sorted-multisig descriptor. Caller must hold cs_wallet
//! and, for wallets with private keys, have unlocked the wallet.
util::Result<MultisigDescriptorResult> CreateMultisigDescriptor(CWallet& wallet,
                                                                int nrequired,
                                                                const std::vector<MultisigKeySpec>& keys,
                                                                const MultisigOptions& options);

//! Infer a Scrooge vault from the wallet's active descriptors.
InferredVaultPolicy InferWalletVaultPolicy(const CWallet& wallet);

//! BIP68 older(N): mature when depth >= N. after(H): mature when tip_height >= H.
bool IsVaultUtxoMature(const InferredVaultPolicy& policy, int depth, int tip_height);

struct VaultBalanceBreakdown {
    bool is_vault{false};
    InferredVaultPolicy policy;
    CAmount immediate{0};
    CAmount recoverable_now{0};
    CAmount awaiting{0};
    std::optional<int> earliest_blocks_remaining;
};

//! Confirmed coins: key-path (immediate, 0 if a signer is marked lost),
//! script-path mature, and confirmed-but-immature.
VaultBalanceBreakdown GetVaultBalanceBreakdown(const CWallet& wallet);

//! Set nSequence/min_depth (older) or nLockTime/script_path (after) for recovery.
void ApplyVaultRecoveryToCoinControl(const CWallet& wallet, CCoinControl& coin_control);

struct VaultPolicyPackage {
    std::string format{"bitcoin-core-vault-policy"};
    int version{1};
    std::string policy_id;
    std::string network;
    int nrequired{0};
    std::optional<uint32_t> fallback_older;
    std::optional<uint32_t> fallback_after;
    std::vector<std::string> descs;
};

std::string FormatVaultPolicyPackage(const VaultPolicyPackage& pkg);
util::Result<VaultPolicyPackage> ParseVaultPolicyPackage(const std::string& json);
VaultPolicyPackage ExportWalletVaultPolicy(const CWallet& wallet);
util::Result<void> ImportWalletVaultPolicy(CWallet& wallet, const VaultPolicyPackage& pkg);
} // namespace wallet

#endif // BITCOIN_WALLET_MULTISIG_H
