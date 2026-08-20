// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/multisig.h>

#include <chainparams.h>
#include <external_signer.h>
#include <key_io.h>
#include <outputtype.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <sstream>

namespace wallet {
std::string DefaultMultisigPath(OutputType type, uint32_t account)
{
    const uint32_t coin = Params().GetChainType() == ChainType::MAIN ? 0 : 1;
    // BIP48 script types: 0=legacy, 1=p2sh-segwit, 2=bech32, 3=bech32m (Sparrow/Specter).
    uint32_t script = 2;
    switch (type) {
    case OutputType::LEGACY: script = 0; break;
    case OutputType::P2SH_SEGWIT: script = 1; break;
    case OutputType::BECH32: script = 2; break;
    case OutputType::BECH32M: script = 3; break;
    case OutputType::UNKNOWN:
        break;
    }
    return WriteHDKeypath({
        48 | BIP32_HARDENED_FLAG,
        coin | BIP32_HARDENED_FLAG,
        account | BIP32_HARDENED_FLAG,
        script | BIP32_HARDENED_FLAG,
    });
}

static std::string StripMultipath(const std::string& key)
{
    static const std::string suffix{"/<0;1>/*"};
    if (key.size() >= suffix.size() && key.ends_with(suffix)) {
        return key.substr(0, key.size() - suffix.size());
    }
    return key;
}

std::string WrapSortedMulti(OutputType type, int nrequired, const std::vector<std::string>& keys,
                            std::optional<uint32_t> fallback_older)
{
    auto sortedmulti = [&](const char* fn) {
        std::string inner = strprintf("%s(%d", fn, nrequired);
        for (const auto& key : keys) {
            inner += "," + key;
        }
        inner += ")";
        return inner;
    };
    switch (type) {
    case OutputType::LEGACY: return "sh(" + sortedmulti("sortedmulti") + ")";
    case OutputType::P2SH_SEGWIT: return "sh(wsh(" + sortedmulti("sortedmulti") + "))";
    case OutputType::BECH32: return "wsh(" + sortedmulti("sortedmulti") + ")";
    case OutputType::BECH32M: {
        if (keys.empty()) return {};
        if (fallback_older) {
            if (keys.size() < 2) return {};
            // 24861 vault: n-of-n MuSig2 key-path, m-of-n after a relative delay.
            std::string musig{"musig("};
            for (size_t i = 0; i < keys.size(); ++i) {
                if (i) musig += ",";
                musig += keys[i];
            }
            musig += ")";
            // multi_a (not sortedmulti_a) is a miniscript fragment and can sit under older().
            return strprintf("tr(%s,and_v(v:older(%u),%s))", musig, *fallback_older, sortedmulti("multi_a"));
        }
        if (keys.size() == 1 && nrequired == 1) {
            return "tr(" + keys[0] + ")";
        }
        if (nrequired == static_cast<int>(keys.size())) {
            // n-of-n: BIP 327 MuSig2 key aggregation, then BIP 328 unhardened receive/change.
            std::string inner{"musig("};
            for (size_t i = 0; i < keys.size(); ++i) {
                if (i) inner += ",";
                inner += StripMultipath(keys[i]);
            }
            inner += ")";
            return "tr(" + inner + "/<0;1>/*)";
        }
        // m-of-n: unspendable NUMS internal key, BIP 387 sortedmulti_a script path.
        return strprintf("tr(%s,%s)", HexStr(XOnlyPubKey::NUMS_H), sortedmulti("sortedmulti_a"));
    }
    case OutputType::UNKNOWN:
        break;
    }
    return {};
}

bilingual_str ValidateMultisigPolicy(int nrequired, size_t nkeys)
{
    if (nkeys == 0) {
        return Untranslated("keys must be a non-empty array");
    }
    if (nrequired <= 0 || static_cast<size_t>(nrequired) > nkeys) {
        return Untranslated("nrequired must be > 0 and <= the number of keys");
    }
    return {};
}

static std::string TypeLabel(OutputType type)
{
    switch (type) {
    case OutputType::LEGACY: return "legacy (P2SH)";
    case OutputType::P2SH_SEGWIT: return "p2sh-segwit (P2SH-P2WSH)";
    case OutputType::BECH32: return "bech32 (P2WSH)";
    case OutputType::BECH32M: return "bech32m (P2TR)";
    case OutputType::UNKNOWN:
        break;
    }
    return "unknown";
}

std::string FormatMultisigTranscript(const std::string& wallet_name,
                                     const std::string& chain,
                                     int nrequired,
                                     const std::vector<MultisigKeySpec>& keys,
                                     OutputType type,
                                     const std::vector<std::string>& public_descs,
                                     std::optional<uint32_t> fallback_older)
{
    std::ostringstream out;
    out << "# Bitcoin Core multisig wallet\n";
    out << "Name: " << wallet_name << "\n";
    out << "Network: " << chain << "\n";
    out << "Policy: " << nrequired << " of " << keys.size() << "\n";
    out << "Script: " << TypeLabel(type) << "\n";
    if (type == OutputType::BECH32M) {
        if (fallback_older) {
            out << "Immediate: all " << keys.size() << " keys (tr(musig) key-path, BIP 327)\n";
            out << "Fallback: " << nrequired << " of " << keys.size()
                << " after " << *fallback_older << " blocks (older(), BIP 68)\n";
        } else if (nrequired == static_cast<int>(keys.size()) && keys.size() >= 2) {
            out << "Construction: tr(musig) key-path (BIP 327 MuSig2)\n";
        } else if (keys.size() == 1) {
            out << "Construction: tr() Taproot singlesig\n";
        } else {
            out << "Construction: tr(NUMS,sortedmulti_a) script-path (BIP 387)\n";
        }
    }
    out << "\n## Cosigners\n";
    for (size_t i = 0; i < keys.size(); ++i) {
        const MultisigKeySpec& k = keys[i];
        const std::string label = k.label.empty() ? strprintf("key-%d", i + 1) : k.label;
        out << (i + 1) << ". " << label;
        if (k.fingerprint) out << "  fingerprint=" << *k.fingerprint;
        if (k.path) out << "  path=" << *k.path;
        if (k.xpub) out << "\n    xpub=" << *k.xpub;
        else if (k.hdkey) out << "\n    hdkey=" << *k.hdkey;
        else if (k.fingerprint && !k.xpub) out << "  (hardware, xpub fetched at creation)";
        out << "\n";
    }
    if (!public_descs.empty()) {
        out << "\n## Descriptors\n";
        for (const auto& d : public_descs) {
            out << d << "\n";
        }
    }
    out << "\nKeep this file offline. Anyone with the xpubs can see your\n";
    out << "addresses; spending still needs " << nrequired << " signatures.\n";
    return out.str();
}

static util::Result<std::string> KeyExprFromSpec(CWallet& wallet, const MultisigKeySpec& spec, const std::string& default_path)
{
    AssertLockHeld(wallet.cs_wallet);

    std::string path = spec.path.value_or(default_path);
    std::vector<uint32_t> parsed_path;
    if (!ParseHDKeypath(path, parsed_path)) {
        return util::Error{Untranslated("Invalid BIP32 keypath")};
    }
    if (!HasHardenedDerivation(parsed_path)) {
        return util::Error{Untranslated("Derivation path requires at least one hardened step")};
    }

    if (spec.xpub) {
        if (!spec.fingerprint || spec.fingerprint->size() != 8 || !IsHex(*spec.fingerprint)) {
            return util::Error{Untranslated("Air-gapped keys need an 8-character hex fingerprint plus xpub")};
        }
        const CExtPubKey xpub = DecodeExtPubKey(*spec.xpub);
        if (!xpub.pubkey.IsValid()) {
            return util::Error{Untranslated("Unable to parse xpub")};
        }
        return strprintf("[%s%s]%s/<0;1>/*",
                         *spec.fingerprint,
                         FormatHDKeypath(parsed_path),
                         *spec.xpub);
    }

    if (spec.fingerprint) {
        if (spec.fingerprint->size() != 8 || !IsHex(*spec.fingerprint)) {
            return util::Error{Untranslated("fingerprint must be 8 hex characters")};
        }
        auto signer = ExternalSignerScriptPubKeyMan::GetExternalSigner(*spec.fingerprint);
        if (!signer) {
            return util::Error{Untranslated(util::ErrorString(signer).original)};
        }
        const UniValue xpub_res = signer->GetXpub(path);
        if (!xpub_res.exists("xpub") || !xpub_res["xpub"].isStr()) {
            return util::Error{Untranslated("Signer getxpub did not return an xpub")};
        }
        return strprintf("[%s%s]%s/<0;1>/*",
                         *spec.fingerprint,
                         FormatHDKeypath(parsed_path),
                         xpub_res["xpub"].get_str());
    }

    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return util::Error{Untranslated("Watch-only wallets cannot use local keys; specify a signer fingerprint or xpub")};
    }

    CExtPubKey xpub;
    if (spec.hdkey) {
        xpub = DecodeExtPubKey(*spec.hdkey);
        if (!xpub.pubkey.IsValid()) {
            return util::Error{Untranslated("Unable to parse HD key. Please provide a valid xpub")};
        }
    } else {
        CWallet::HDPubKeyMap unused = wallet.GetHDPubKeys(CWallet::HDKeyFilter::UnusedKey);
        CWallet::HDPubKeyMap active = wallet.GetHDPubKeys(CWallet::HDKeyFilter::Active);
        if (unused.size() == 1) {
            xpub = unused.begin()->first;
        } else if (unused.empty() && active.size() == 1) {
            xpub = active.begin()->first;
        } else {
            return util::Error{Untranslated("Unable to determine which HD key to use. Please specify with 'hdkey'")};
        }
    }
    std::optional<CExtKey> xprv = wallet.GetExtKey(xpub);
    if (!xprv) {
        return util::Error{Untranslated(strprintf("Private key for %s is not known", EncodeExtPubKey(xpub)))};
    }
    auto child = DeriveExtKey(*xprv, parsed_path);
    if (!child) {
        return util::Error{Untranslated("Unable to derive HD key at the requested path")};
    }
    return strprintf("[%s%s]%s/<0;1>/*",
                     HexStr(child->second.fingerprint),
                     FormatHDKeypath(child->second.path),
                     EncodeExtKey(child->first));
}

util::Result<MultisigDescriptorResult> CreateMultisigDescriptor(CWallet& wallet,
                                                                int nrequired,
                                                                const std::vector<MultisigKeySpec>& keys,
                                                                const MultisigOptions& options)
{
    AssertLockHeld(wallet.cs_wallet);

    if (!wallet.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER) && wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return util::Error{Untranslated("createmultisigdescriptor requires a wallet with private keys or an external signer")};
    }
    if (const auto err = ValidateMultisigPolicy(nrequired, keys.size()); !err.empty()) {
        return util::Error{err};
    }
    if (options.type == OutputType::UNKNOWN) {
        return util::Error{Untranslated("Unknown or unsupported address type")};
    }
    if (options.fallback_older) {
        if (options.type != OutputType::BECH32M) {
            return util::Error{Untranslated("fallback_older is only valid with type bech32m")};
        }
        if (*options.fallback_older < 1 || *options.fallback_older >= (1u << 31)) {
            return util::Error{Untranslated("fallback_older must be between 1 and 2^31-1 blocks")};
        }
        if (keys.size() < 2) {
            return util::Error{Untranslated("fallback_older requires at least two keys")};
        }
    }

    const std::string default_path = DefaultMultisigPath(options.type, options.account);
    std::vector<std::string> key_exprs;
    key_exprs.reserve(keys.size());
    for (const auto& spec : keys) {
        auto expr = KeyExprFromSpec(wallet, spec, default_path);
        if (!expr) return util::Error{util::ErrorString(expr)};
        key_exprs.push_back(*expr);
    }

    std::string desc_str = WrapSortedMulti(options.type, nrequired, key_exprs, options.fallback_older);
    if (desc_str.empty()) {
        return util::Error{Untranslated("Unsupported address type")};
    }
    const std::string checksum = GetDescriptorChecksum(desc_str);
    if (!checksum.empty()) desc_str += "#" + checksum;

    FlatSigningProvider parse_keys;
    std::string parse_error;
    auto parsed = Parse(desc_str, parse_keys, parse_error, /*require_checksum=*/!checksum.empty());
    if (parsed.empty()) {
        return util::Error{Untranslated(parse_error)};
    }

    MultisigDescriptorResult out;
    out.nrequired = nrequired;
    out.key_exprs = key_exprs;
    for (size_t i = 0; i < parsed.size(); ++i) {
        const bool desc_internal = (parsed.size() == 2) ? (i == 1) : options.internal_only.value_or(false);
        if (options.internal_only && parsed.size() == 2 && desc_internal != *options.internal_only) {
            continue;
        }
        std::vector<CScript> scripts;
        FlatSigningProvider expand_keys;
        if (!parsed[i]->Expand(0, parse_keys, scripts, expand_keys)) {
            return util::Error{Untranslated("Cannot expand descriptor")};
        }
        WalletDescriptor w_desc(std::move(parsed[i]), GetTime(), 0, wallet.m_keypool_size, 0);
        auto spkm_res = wallet.AddWalletDescriptor(w_desc, parse_keys, /*label=*/"", desc_internal);
        if (!spkm_res) {
            return util::Error{util::ErrorString(spkm_res)};
        }
        auto& spkm = spkm_res.value().get();
        if (auto type = w_desc.descriptor->GetOutputType()) {
            wallet.AddActiveScriptPubKeyMan(spkm.GetID(), *type, desc_internal);
        }
        std::string out_desc;
        CHECK_NONFATAL(spkm.GetDescriptorString(out_desc, false));
        out.descs.push_back(out_desc);
    }
    return out;
}
} // namespace wallet
