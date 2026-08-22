// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/multisig.h>

#include <chainparams.h>
#include <external_signer.h>
#include <hash.h>
#include <key_io.h>
#include <outputtype.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <span.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/coincontrol.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <limits>
#include <sstream>
#include <string>

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
                            std::optional<uint32_t> fallback_older,
                            std::optional<uint32_t> fallback_after,
                            const std::vector<std::string>& recovery_keys)
{
    auto sortedmulti = [&](const char* fn, const std::vector<std::string>& inner_keys) {
        std::string inner = strprintf("%s(%d", fn, nrequired);
        for (const auto& key : inner_keys) {
            inner += "," + key;
        }
        inner += ")";
        return inner;
    };
    switch (type) {
    case OutputType::LEGACY: return "sh(" + sortedmulti("sortedmulti", keys) + ")";
    case OutputType::P2SH_SEGWIT: return "sh(wsh(" + sortedmulti("sortedmulti", keys) + "))";
    case OutputType::BECH32: return "wsh(" + sortedmulti("sortedmulti", keys) + ")";
    case OutputType::BECH32M: {
        if (keys.empty()) return {};
        if (fallback_older && fallback_after) return {};
        if (fallback_older || fallback_after) {
            const std::vector<std::string>& rec = recovery_keys.empty() ? keys : recovery_keys;
            if (keys.size() < 2 || rec.empty()) return {};
            // Scrooge vault (bitcoin#24861): n-of-n MuSig2 key-path, m-of-n after a delay.
            std::string musig{"musig("};
            for (size_t i = 0; i < keys.size(); ++i) {
                if (i) musig += ",";
                musig += keys[i];
            }
            musig += ")";
            const char* lock = fallback_older ? "older" : "after";
            const uint32_t lock_n = fallback_older ? *fallback_older : *fallback_after;
            // multi_a (not sortedmulti_a) is a miniscript fragment and can sit under older()/after().
            return strprintf("tr(%s,and_v(v:%s(%u),%s))", musig, lock, lock_n, sortedmulti("multi_a", rec));
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
        return strprintf("tr(%s,%s)", HexStr(XOnlyPubKey::NUMS_H), sortedmulti("sortedmulti_a", keys));
    }
    case OutputType::UNKNOWN:
        break;
    }
    return {};
}

bilingual_str ValidateMultisigPolicy(int nrequired, size_t nkeys, OutputType type,
                                     std::optional<uint32_t> fallback_older,
                                     std::optional<uint32_t> fallback_after,
                                     size_t n_recovery_keys)
{
    if (nkeys == 0) {
        return Untranslated("keys must be a non-empty array");
    }
    const size_t rec_n = n_recovery_keys == 0 ? nkeys : n_recovery_keys;
    if (nrequired <= 0 || static_cast<size_t>(nrequired) > rec_n) {
        return Untranslated("nrequired must be > 0 and <= the number of recovery keys");
    }
    if (fallback_older && fallback_after) {
        return Untranslated("fallback_older and fallback_after cannot both be set");
    }
    // P2SH redeemScript is capped at MAX_SCRIPT_ELEMENT_SIZE (520): 15 compressed keys.
    static constexpr size_t MAX_PUBKEYS_PER_P2SH_MULTISIG = 15;
    if (type == OutputType::LEGACY && nkeys > MAX_PUBKEYS_PER_P2SH_MULTISIG) {
        return Untranslated(strprintf("legacy P2SH multisig supports at most %d keys", MAX_PUBKEYS_PER_P2SH_MULTISIG));
    }
    if ((type == OutputType::P2SH_SEGWIT || type == OutputType::BECH32) && nkeys > MAX_PUBKEYS_PER_MULTISIG) {
        return Untranslated(strprintf("P2WSH multisig supports at most %d keys", MAX_PUBKEYS_PER_MULTISIG));
    }
    if (type == OutputType::BECH32M) {
        // Script-path multi_a / Scrooge vault fallback is BIP 342 stack-limited (n+1 ≤ 1000).
        const bool uses_multi_a = fallback_older.has_value() || fallback_after.has_value() || static_cast<size_t>(nrequired) < rec_n;
        if (uses_multi_a && rec_n > MAX_PUBKEYS_PER_MULTI_A) {
            return Untranslated(strprintf("Taproot script-path multisig supports at most %u keys (BIP 342 stack limit)", MAX_PUBKEYS_PER_MULTI_A));
        }
        if ((fallback_older || fallback_after) && nkeys < 2) {
            return Untranslated("A Scrooge vault key-path needs at least two active keys");
        }
    }
    return {};
}

static std::optional<uint32_t> ParseMiniscriptUint(const std::string& desc, const char* fn)
{
    const std::string needle = std::string(fn) + "(";
    const auto pos = desc.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    const auto start = pos + needle.size();
    const auto end = desc.find(')', start);
    if (end == std::string::npos || end == start) return std::nullopt;
    try {
        const unsigned long n = std::stoul(desc.substr(start, end - start));
        if (n == 0 || n >= (1UL << 31)) return std::nullopt;
        return static_cast<uint32_t>(n);
    } catch (...) {
        return std::nullopt;
    }
}

InferredVaultPolicy InferVaultPolicy(const std::string& desc)
{
    InferredVaultPolicy out;
    out.older = ParseMiniscriptUint(desc, "older");
    out.after = ParseMiniscriptUint(desc, "after");
    if (const auto m = ParseMiniscriptUint(desc, "multi_a")) {
        out.recovery_m = static_cast<int>(*m);
    }
    out.is_vault = desc.find("tr(musig(") != std::string::npos && (out.older || out.after) && out.recovery_m > 0;
    return out;
}

std::optional<uint32_t> InferTaprootRecoveryDelay(const std::string& desc)
{
    return InferVaultPolicy(desc).older;
}

std::string VaultPolicyId(std::string_view desc)
{
    return HexStr(Hash160(MakeUCharSpan(desc))).substr(0, 16);
}

bilingual_str DuplicateSignerWarning(const std::vector<MultisigKeySpec>& keys)
{
    for (size_t i = 0; i < keys.size(); ++i) {
        for (size_t j = i + 1; j < keys.size(); ++j) {
            if (keys[i].fingerprint && keys[j].fingerprint &&
                *keys[i].fingerprint == *keys[j].fingerprint) {
                return Untranslated(strprintf(
                    "Two keys share fingerprint %s. Devices restored from the same seed are copies of one signer, not independent security domains.",
                    *keys[i].fingerprint));
            }
            if (keys[i].xpub && keys[j].xpub && *keys[i].xpub == *keys[j].xpub) {
                return Untranslated("Two keys use the same xpub. They are copies of one signer, not independent security domains.");
            }
        }
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

static std::string GroupedNumber(uint32_t value)
{
    std::string number = std::to_string(value);
    for (int pos = static_cast<int>(number.size()) - 3; pos > 0; pos -= 3) {
        number.insert(static_cast<size_t>(pos), 1, ',');
    }
    return number;
}

std::string FormatMultisigTranscript(const std::string& wallet_name,
                                     const std::string& chain,
                                     int nrequired,
                                     const std::vector<MultisigKeySpec>& keys,
                                     OutputType type,
                                     const std::vector<std::string>& public_descs,
                                     std::optional<uint32_t> fallback_older,
                                     std::optional<uint32_t> fallback_after)
{
    std::ostringstream out;
    out << "# Bitcoin Core multisig wallet\n";
    out << "Name: " << wallet_name << "\n";
    out << "Network: " << chain << "\n";
    out << "Policy: " << nrequired << " of " << keys.size() << "\n";
    out << "Script: " << TypeLabel(type) << "\n";
    if (type == OutputType::BECH32M) {
        const size_t n_active = static_cast<size_t>(std::count_if(keys.begin(), keys.end(), [](const MultisigKeySpec& k) { return !k.recovery_only; }));
        const size_t n_rec = keys.empty() ? 0 : keys.size();
        if (fallback_older || fallback_after) {
            out << "Construction: Scrooge vault\n";
            out << "Immediate: all " << n_active << " active keys (tr(musig) key-path, BIP 327 MuSig2)\n";
            if (fallback_older) {
                out << "Fallback: " << nrequired << " of " << n_rec
                    << " after " << *fallback_older << (*fallback_older == 1 ? " block" : " blocks")
                    << " (older(), BIP 68, per coin)\n";
            } else {
                out << "Fallback: " << nrequired << " of " << n_rec
                    << " at block height " << GroupedNumber(*fallback_after) << " (after(), CLTV)\n";
            }
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
        if (k.recovery_only) out << "  role=recovery-only";
        else out << "  role=active";
        if (k.xpub) out << "\n    xpub=" << *k.xpub;
        else if (k.hdkey) out << "\n    private key material omitted from transcript";
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
    out << "addresses and transaction history. The package cannot spend.\n";
    if (fallback_older || fallback_after) {
        out << "Immediate spends still need every active key. Recovery needs "
            << nrequired << " of the recovery keys after the delay.\n";
    } else {
        out << "Ordinary m-of-n. Immediate spend needs " << nrequired << " of " << keys.size()
            << " keys. There is no delayed recovery path.\n";
    }
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

    if (spec.hdkey) {
        const CExtKey extkey = DecodeExtKey(*spec.hdkey);
        if (extkey.key.IsValid()) {
            if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                return util::Error{Untranslated("Watch-only wallets cannot use local keys; specify a signer fingerprint or xpub")};
            }
            auto child = DeriveExtKey(extkey, parsed_path);
            if (!child) {
                return util::Error{Untranslated("Unable to derive HD key at the requested path")};
            }
            return strprintf("[%s%s]%s/<0;1>/*",
                             HexStr(child->second.fingerprint),
                             FormatHDKeypath(child->second.path),
                             EncodeExtKey(child->first));
        }
    }

    CExtPubKey xpub;
    if (spec.hdkey) {
        xpub = DecodeExtPubKey(*spec.hdkey);
        if (!xpub.pubkey.IsValid()) {
            return util::Error{Untranslated("Unable to parse HD key. Please provide a valid xpub or xprv")};
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

    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !wallet.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        const bool all_xpub = std::all_of(keys.begin(), keys.end(), [](const MultisigKeySpec& k) { return k.xpub.has_value(); });
        if (!all_xpub) {
            return util::Error{Untranslated("createmultisigdescriptor requires a wallet with private keys or an external signer")};
        }
    }
    const size_t n_recovery_only = static_cast<size_t>(std::count_if(keys.begin(), keys.end(), [](const MultisigKeySpec& k) { return k.recovery_only; }));
    const size_t n_active = keys.size() - n_recovery_only;
    if (n_recovery_only > 0 && !options.fallback_older && !options.fallback_after) {
        return util::Error{Untranslated("recovery-only keys require fallback_older or fallback_after")};
    }
    if (const auto err = ValidateMultisigPolicy(nrequired, n_active, options.type, options.fallback_older, options.fallback_after, keys.size()); !err.empty()) {
        return util::Error{err};
    }
    if (options.type == OutputType::UNKNOWN) {
        return util::Error{Untranslated("Unknown or unsupported address type")};
    }
    auto check_lock = [&](std::optional<uint32_t> v, const char* name) -> util::Result<void> {
        if (!v) return {};
        if (options.type != OutputType::BECH32M) {
            return util::Error{Untranslated(strprintf("%s is only valid with type bech32m", name))};
        }
        if (*v < 1 || *v >= (1u << 31)) {
            return util::Error{Untranslated(strprintf("%s must be between 1 and 2^31-1", name))};
        }
        return {};
    };
    if (auto r = check_lock(options.fallback_older, "fallback_older"); !r) {
        return util::Error{util::ErrorString(r)};
    }
    if (auto r = check_lock(options.fallback_after, "fallback_after"); !r) {
        return util::Error{util::ErrorString(r)};
    }
    if ((options.fallback_older || options.fallback_after) && n_active < 2) {
        return util::Error{Untranslated("A Scrooge vault key-path needs at least two active keys")};
    }

    const std::string default_path = DefaultMultisigPath(options.type, options.account);
    std::vector<std::string> active_exprs;
    std::vector<std::string> recovery_exprs;
    active_exprs.reserve(n_active);
    recovery_exprs.reserve(keys.size());
    for (const auto& spec : keys) {
        auto expr = KeyExprFromSpec(wallet, spec, default_path);
        if (!expr) return util::Error{util::ErrorString(expr)};
        if (!spec.recovery_only) active_exprs.push_back(*expr);
        recovery_exprs.push_back(*expr);
    }

    const std::vector<std::string>& wrap_keys = (options.fallback_older || options.fallback_after) ? active_exprs : recovery_exprs;
    std::string desc_str = WrapSortedMulti(options.type, nrequired, wrap_keys, options.fallback_older, options.fallback_after, recovery_exprs);
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
    out.key_exprs = (options.fallback_older || options.fallback_after) ? active_exprs : recovery_exprs;
    out.fallback_older = options.fallback_older;
    out.fallback_after = options.fallback_after;
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
    if (!out.descs.empty()) out.policy_id = VaultPolicyId(out.descs.front());
    return out;
}

InferredVaultPolicy InferWalletVaultPolicy(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    for (auto* man : wallet.GetActiveScriptPubKeyMans()) {
        auto* desc_man = dynamic_cast<DescriptorScriptPubKeyMan*>(man);
        if (!desc_man) continue;
        std::string desc;
        if (!desc_man->GetDescriptorString(desc, /*priv=*/false)) continue;
        auto policy = InferVaultPolicy(desc);
        if (policy.is_vault) return policy;
    }
    return {};
}

bool IsVaultUtxoMature(const InferredVaultPolicy& policy, int depth, int tip_height)
{
    if (!policy.is_vault) return true;
    if (policy.older) return depth >= static_cast<int>(*policy.older);
    if (policy.after) return tip_height >= static_cast<int>(*policy.after);
    return true;
}

VaultBalanceBreakdown GetVaultBalanceBreakdown(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    VaultBalanceBreakdown out;
    out.policy = InferWalletVaultPolicy(wallet);
    out.is_vault = out.policy.is_vault;
    const int tip = wallet.HaveChain() ? wallet.GetLastBlockHeight() : 0;
    const auto coins = AvailableCoins(wallet);
    for (const auto& coin : coins.All()) {
        if (coin.depth <= 0) continue;
        if (wallet.m_lost_signers.empty()) {
            out.immediate += coin.txout.nValue;
        }
        if (!out.is_vault) continue;
        if (IsVaultUtxoMature(out.policy, coin.depth, tip)) {
            out.recoverable_now += coin.txout.nValue;
        } else {
            out.awaiting += coin.txout.nValue;
            int remaining = 0;
            if (out.policy.older) {
                remaining = std::max(0, static_cast<int>(*out.policy.older) - coin.depth);
            } else if (out.policy.after) {
                remaining = std::max(0, static_cast<int>(*out.policy.after) - tip);
            }
            if (!out.earliest_blocks_remaining || remaining < *out.earliest_blocks_remaining) {
                out.earliest_blocks_remaining = remaining;
            }
        }
    }
    return out;
}

void ApplyVaultRecoveryToCoinControl(const CWallet& wallet, CCoinControl& coin_control)
{
    AssertLockHeld(wallet.cs_wallet);
    const auto policy = InferWalletVaultPolicy(wallet);
    if (!policy.is_vault) return;
    if (policy.older) {
        coin_control.m_nSequence = *policy.older;
        coin_control.m_min_depth = static_cast<int>(*policy.older);
        coin_control.m_script_path = true;
    } else if (policy.after) {
        coin_control.m_locktime = *policy.after;
        coin_control.m_script_path = true;
        const int tip = wallet.HaveChain() ? wallet.GetLastBlockHeight() : 0;
        if (tip < static_cast<int>(*policy.after)) {
            coin_control.m_min_depth = std::numeric_limits<int>::max();
        }
    }
}

std::string FormatVaultPolicyPackage(const VaultPolicyPackage& pkg)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("format", pkg.format);
    obj.pushKV("version", pkg.version);
    obj.pushKV("policy_id", pkg.policy_id);
    obj.pushKV("network", pkg.network);
    obj.pushKV("nrequired", pkg.nrequired);
    if (pkg.fallback_older) obj.pushKV("fallback_older", static_cast<int>(*pkg.fallback_older));
    if (pkg.fallback_after) obj.pushKV("fallback_after", static_cast<int>(*pkg.fallback_after));
    UniValue descs(UniValue::VARR);
    for (const auto& d : pkg.descs) descs.push_back(d);
    obj.pushKV("descs", std::move(descs));
    return obj.write(2) + "\n";
}

util::Result<VaultPolicyPackage> ParseVaultPolicyPackage(const std::string& json)
{
    UniValue obj;
    if (!obj.read(json) || !obj.isObject()) {
        return util::Error{Untranslated("Vault policy package is not valid JSON")};
    }
    VaultPolicyPackage pkg;
    if (obj.exists("format")) pkg.format = obj["format"].get_str();
    if (pkg.format != "bitcoin-core-vault-policy") {
        return util::Error{Untranslated("Unknown vault policy package format")};
    }
    if (obj.exists("version")) pkg.version = obj["version"].getInt<int>();
    if (obj.exists("policy_id")) pkg.policy_id = obj["policy_id"].get_str();
    if (obj.exists("network")) pkg.network = obj["network"].get_str();
    if (obj.exists("nrequired")) pkg.nrequired = obj["nrequired"].getInt<int>();
    if (obj.exists("fallback_older")) pkg.fallback_older = static_cast<uint32_t>(obj["fallback_older"].getInt<int>());
    if (obj.exists("fallback_after")) pkg.fallback_after = static_cast<uint32_t>(obj["fallback_after"].getInt<int>());
    if (!obj.exists("descs") || !obj["descs"].isArray() || obj["descs"].empty()) {
        return util::Error{Untranslated("Vault policy package is missing descriptors")};
    }
    for (const UniValue& d : obj["descs"].getValues()) {
        pkg.descs.push_back(d.get_str());
    }
    if (pkg.policy_id.empty()) pkg.policy_id = VaultPolicyId(pkg.descs.front());
    return pkg;
}

VaultPolicyPackage ExportWalletVaultPolicy(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    VaultPolicyPackage pkg;
    pkg.network = Params().GetChainTypeString();
    const auto policy = InferWalletVaultPolicy(wallet);
    pkg.nrequired = policy.recovery_m;
    pkg.fallback_older = policy.older;
    pkg.fallback_after = policy.after;
    auto append = [&](bool internal) {
        for (OutputType type : {OutputType::BECH32M, OutputType::BECH32, OutputType::P2SH_SEGWIT, OutputType::LEGACY}) {
            auto* man = wallet.GetScriptPubKeyMan(type, internal);
            auto* desc_man = dynamic_cast<DescriptorScriptPubKeyMan*>(man);
            if (!desc_man) continue;
            std::string desc;
            if (!desc_man->GetDescriptorString(desc, /*priv=*/false)) continue;
            pkg.descs.push_back(desc);
        }
    };
    append(/*internal=*/false);
    append(/*internal=*/true);
    if (!pkg.descs.empty()) pkg.policy_id = VaultPolicyId(pkg.descs.front());
    return pkg;
}

util::Result<void> ImportWalletVaultPolicy(CWallet& wallet, const VaultPolicyPackage& pkg)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!pkg.network.empty() && pkg.network != Params().GetChainTypeString()) {
        return util::Error{Untranslated(strprintf("Policy package network %s does not match this node (%s)", pkg.network, Params().GetChainTypeString()))};
    }
    for (size_t i = 0; i < pkg.descs.size(); ++i) {
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(pkg.descs[i], keys, error, /*require_checksum=*/true);
        if (parsed.empty()) {
            return util::Error{Untranslated(error)};
        }
        const bool internal = i > 0;
        WalletDescriptor w_desc(std::move(parsed.at(0)), GetTime(), 0, wallet.m_keypool_size, 0);
        auto spkm_res = wallet.AddWalletDescriptor(w_desc, keys, /*label=*/"", internal);
        if (!spkm_res) return util::Error{util::ErrorString(spkm_res)};
        if (auto type = w_desc.descriptor->GetOutputType()) {
            wallet.AddActiveScriptPubKeyMan(spkm_res.value().get().GetID(), *type, internal);
        }
    }
    return {};
}
} // namespace wallet
