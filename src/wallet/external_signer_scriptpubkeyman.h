// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H

#include <wallet/scriptpubkeyman.h>

#include <memory>
#include <optional>
#include <string>
#include <util/result.h>
#include <vector>

struct bilingual_str;

namespace wallet {
class ExternalSignerScriptPubKeyMan : public DescriptorScriptPubKeyMan
{
private:
    //! Create an ExternalSPKM from existing wallet data
    ExternalSignerScriptPubKeyMan(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size, const KeyMap& keys, const CryptedKeyMap& ckeys)
        : DescriptorScriptPubKeyMan(storage, descriptor, keypool_size, keys, ckeys)
    {}

    ExternalSignerScriptPubKeyMan(WalletStorage& storage, int64_t keypool_size)
        : DescriptorScriptPubKeyMan(storage, keypool_size)
    {}

public:
    static std::unique_ptr<ExternalSignerScriptPubKeyMan> LoadFromStorage(WalletStorage& storage, WalletDescriptor& descriptor, int64_t keypool_size, const KeyMap& keys, const CryptedKeyMap& ckeys);
    static std::unique_ptr<ExternalSignerScriptPubKeyMan> CreateNew(WalletStorage& storage, WalletBatch& batch, int64_t keypool_size, std::unique_ptr<Descriptor> desc);

  //! All devices currently reported by `-signer`. Fixed-vault operational
  //! callers may explicitly allow the built-in signer when the option is
  //! absent; an explicitly empty option remains disabled.
  static util::Result<std::vector<ExternalSigner>> GetExternalSigners(bool allow_native_default = false);

  //! One signer. If `fingerprint` is set, that device is required. Otherwise
  //! exactly one connected signer is required (used when creating a watch-only
  //! external-signer wallet).
  static util::Result<ExternalSigner> GetExternalSigner(const std::optional<std::string>& fingerprint = std::nullopt, bool allow_native_default = false);

  //! Ask each connected signer whose master fingerprint appears in `psbt` to
  //! sign, then optionally finalize. Used after local ScriptPubKeyMans have
  //! already filled in their keys.
  static std::optional<common::PSBTError> SignPSBT(PartiallySignedTransaction& psbt, bool finalize, bool allow_native_default = false);

  /**
  * Display address on the device and verify that the returned value matches.
  * @returns nothing or an error message
  */
 util::Result<void> DisplayAddress(const CTxDestination& dest, const ExternalSigner& signer) const;

  std::optional<common::PSBTError> FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, const common::PSBTFillOptions& options, int* n_signed = nullptr) const override;
};
} // namespace wallet
#endif // BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H
