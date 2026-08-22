// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/multisig.h>

#include <chainparams.h>
#include <external_signer.h>
#include <hash.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
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
#include <cctype>
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
                            const std::vector<std::string>& recovery_keys,
                            std::optional<uint32_t> fallback_older_one_key)
{
    auto sortedmulti = [&](const char* fn, int threshold, const std::vector<std::string>& inner_keys) {
        std::string inner = strprintf("%s(%d", fn, threshold);
        for (const auto& key : inner_keys) {
            inner += "," + key;
        }
        inner += ")";
        return inner;
    };
    switch (type) {
    case OutputType::LEGACY: return "sh(" + sortedmulti("sortedmulti", nrequired, keys) + ")";
    case OutputType::P2SH_SEGWIT: return "sh(wsh(" + sortedmulti("sortedmulti", nrequired, keys) + "))";
    case OutputType::BECH32: return "wsh(" + sortedmulti("sortedmulti", nrequired, keys) + ")";
    case OutputType::BECH32M: {
        if (keys.empty()) return {};
        if (fallback_older && fallback_after) return {};
        if (fallback_older && (*fallback_older == 0 || *fallback_older > CTxIn::SEQUENCE_LOCKTIME_MASK)) return {};
        if (fallback_older_one_key && (*fallback_older_one_key == 0 || *fallback_older_one_key > CTxIn::SEQUENCE_LOCKTIME_MASK)) return {};
        if (fallback_older_one_key && (!fallback_older || fallback_after || *fallback_older_one_key <= *fallback_older || nrequired < 2)) return {};
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
            const std::string primary = strprintf("and_v(v:%s(%u),%s)", lock, lock_n, sortedmulti("multi_a", nrequired, rec));
            if (fallback_older_one_key) {
                const std::string one_key = strprintf("and_v(v:older(%u),%s)", *fallback_older_one_key, sortedmulti("multi_a", 1, rec));
                return strprintf("tr(%s,{%s,%s})", musig, primary, one_key);
            }
            return strprintf("tr(%s,%s)", musig, primary);
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
        return strprintf("tr(%s,%s)", HexStr(XOnlyPubKey::NUMS_H), sortedmulti("sortedmulti_a", nrequired, keys));
    }
    case OutputType::UNKNOWN:
        break;
    }
    return {};
}

bilingual_str ValidateMultisigPolicy(int nrequired, size_t nkeys, OutputType type,
                                     std::optional<uint32_t> fallback_older,
                                     std::optional<uint32_t> fallback_after,
                                     size_t n_recovery_keys,
                                     std::optional<uint32_t> fallback_older_one_key)
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
    if (fallback_older && (*fallback_older == 0 || *fallback_older > CTxIn::SEQUENCE_LOCKTIME_MASK)) {
        return Untranslated(strprintf("fallback_older must be between 1 and %u blocks", CTxIn::SEQUENCE_LOCKTIME_MASK));
    }
    if (fallback_older_one_key) {
        if (!fallback_older) {
            return Untranslated("fallback_older_one_key requires fallback_older");
        }
        if (fallback_after) {
            return Untranslated("fallback_older_one_key cannot be combined with fallback_after");
        }
        if (*fallback_older_one_key == 0 || *fallback_older_one_key > CTxIn::SEQUENCE_LOCKTIME_MASK) {
            return Untranslated(strprintf("fallback_older_one_key must be between 1 and %u blocks", CTxIn::SEQUENCE_LOCKTIME_MASK));
        }
        if (*fallback_older_one_key <= *fallback_older) {
            return Untranslated("fallback_older_one_key must be greater than fallback_older");
        }
        if (nrequired < 2) {
            return Untranslated("fallback_older_one_key requires nrequired of at least 2");
        }
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
        const bool uses_multi_a = fallback_older.has_value() || fallback_after.has_value() || fallback_older_one_key.has_value() || static_cast<size_t>(nrequired) < rec_n;
        if (uses_multi_a && rec_n > MAX_PUBKEYS_PER_MULTI_A) {
            return Untranslated(strprintf("Taproot script-path multisig supports at most %u keys (BIP 342 stack limit)", MAX_PUBKEYS_PER_MULTI_A));
        }
        if ((fallback_older || fallback_after || fallback_older_one_key) && nkeys < 2) {
            return Untranslated("A Scrooge vault key-path needs at least two active keys");
        }
    }
    return {};
}

static std::optional<uint32_t> ParseUint(const std::string& value)
{
    if (value.empty() || !std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c); })) return std::nullopt;
    try {
        const unsigned long n = std::stoul(value);
        if (n == 0 || n >= (1UL << 31)) return std::nullopt;
        return static_cast<uint32_t>(n);
    } catch (...) {
        return std::nullopt;
    }
}

static std::vector<VaultRecoveryStage> ParseRecoveryStages(const std::string& desc)
{
    static constexpr std::string_view OLDER_PREFIX{"and_v(v:older("};
    static constexpr std::string_view AFTER_PREFIX{"and_v(v:after("};
    static constexpr std::string_view MULTI_PREFIX{"),multi_a("};
    std::vector<VaultRecoveryStage> stages;
    size_t search_pos{0};
    while (search_pos < desc.size()) {
        const size_t older_pos = desc.find(OLDER_PREFIX, search_pos);
        const size_t after_pos = desc.find(AFTER_PREFIX, search_pos);
        if (older_pos == std::string::npos && after_pos == std::string::npos) break;
        const bool relative = after_pos == std::string::npos || (older_pos != std::string::npos && older_pos < after_pos);
        const size_t stage_pos = relative ? older_pos : after_pos;
        const std::string_view prefix = relative ? OLDER_PREFIX : AFTER_PREFIX;
        const size_t lock_start = stage_pos + prefix.size();
        const size_t lock_end = desc.find(')', lock_start);
        if (lock_end == std::string::npos || desc.compare(lock_end, MULTI_PREFIX.size(), MULTI_PREFIX) != 0) {
            search_pos = lock_start;
            continue;
        }
        const size_t threshold_start = lock_end + MULTI_PREFIX.size();
        const size_t threshold_end = desc.find(',', threshold_start);
        if (threshold_end == std::string::npos) break;
        const auto lock = ParseUint(desc.substr(lock_start, lock_end - lock_start));
        const auto threshold = ParseUint(desc.substr(threshold_start, threshold_end - threshold_start));
        if (lock && threshold && *threshold <= static_cast<uint32_t>(std::numeric_limits<int>::max())) {
            VaultRecoveryStage stage;
            stage.nrequired = static_cast<int>(*threshold);
            if (relative) stage.older = *lock;
            else stage.after = *lock;
            stages.push_back(stage);
        }
        search_pos = threshold_end + 1;
    }
    std::stable_sort(stages.begin(), stages.end(), [](const VaultRecoveryStage& a, const VaultRecoveryStage& b) {
        if (a.older && b.older) return *a.older < *b.older;
        if (a.after && b.after) return *a.after < *b.after;
        return a.older.has_value() && !b.older.has_value();
    });
    return stages;
}

static bool RecoveryStagesEqual(const std::vector<VaultRecoveryStage>& a, const std::vector<VaultRecoveryStage>& b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](const VaultRecoveryStage& x, const VaultRecoveryStage& y) {
        return x.nrequired == y.nrequired && x.older == y.older && x.after == y.after;
    });
}

InferredVaultPolicy InferVaultPolicy(const std::string& desc)
{
    InferredVaultPolicy out;
    if (desc.find("tr(musig(") == std::string::npos) return out;
    out.recovery_stages = ParseRecoveryStages(desc);
    if (std::any_of(out.recovery_stages.begin(), out.recovery_stages.end(), [](const VaultRecoveryStage& stage) {
            return stage.older && *stage.older > CTxIn::SEQUENCE_LOCKTIME_MASK;
        })) {
        out.recovery_stages.clear();
        return out;
    }
    if (!out.recovery_stages.empty()) {
        out.older = out.recovery_stages.front().older;
        out.after = out.recovery_stages.front().after;
        out.recovery_m = out.recovery_stages.front().nrequired;
        out.is_vault = true;
    }
    return out;
}

static std::optional<std::string> NormalizeDescriptorBranch(const std::string& desc, char expected_branch)
{
    std::string normalized = desc.substr(0, desc.find('#'));
    size_t search_pos{0};
    while (true) {
        const size_t wildcard = normalized.find("/*", search_pos);
        if (wildcard == std::string::npos) break;
        if (wildcard < 2 || normalized[wildcard - 2] != '/' || normalized[wildcard - 1] != expected_branch) {
            return std::nullopt;
        }
        normalized[wildcard - 1] = '?';
        search_pos = wildcard + 2;
    }
    return normalized;
}

static bool IsCanonicalDescriptorPair(const std::string& receive, const std::string& change)
{
    const auto receive_policy = InferVaultPolicy(receive);
    const auto change_policy = InferVaultPolicy(change);
    if (receive_policy.is_vault != change_policy.is_vault ||
        (receive_policy.is_vault && !RecoveryStagesEqual(receive_policy.recovery_stages, change_policy.recovery_stages))) {
        return false;
    }
    const auto normalized_receive = NormalizeDescriptorBranch(receive, '0');
    const auto normalized_change = NormalizeDescriptorBranch(change, '1');
    return normalized_receive && normalized_change && *normalized_receive == *normalized_change;
}

std::optional<uint32_t> InferTaprootRecoveryDelay(const std::string& desc)
{
    static constexpr std::string_view PREFIX{"older("};
    const size_t pos = desc.find(PREFIX);
    if (pos == std::string::npos) return std::nullopt;
    const size_t start = pos + PREFIX.size();
    const size_t end = desc.find(')', start);
    if (end == std::string::npos) return std::nullopt;
    return ParseUint(desc.substr(start, end - start));
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
                                     std::optional<uint32_t> fallback_after,
                                     std::optional<uint32_t> fallback_older_one_key)
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
                if (fallback_older_one_key) {
                    out << "Later fallback: any 1 of " << n_rec
                        << " after " << *fallback_older_one_key << (*fallback_older_one_key == 1 ? " block" : " blocks")
                        << " (older(), BIP 68, per coin)\n";
                }
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
        if (fallback_older_one_key) {
            out << "After the later delay, any one recovery key can spend.\n";
        }
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
    if (n_recovery_only > 0 && !options.fallback_older && !options.fallback_after && !options.fallback_older_one_key) {
        return util::Error{Untranslated("recovery-only keys require fallback_older or fallback_after")};
    }
    if (const auto err = ValidateMultisigPolicy(nrequired, n_active, options.type, options.fallback_older, options.fallback_after, keys.size(), options.fallback_older_one_key); !err.empty()) {
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
    if (auto r = check_lock(options.fallback_older_one_key, "fallback_older_one_key"); !r) {
        return util::Error{util::ErrorString(r)};
    }
    if ((options.fallback_older || options.fallback_after || options.fallback_older_one_key) && n_active < 2) {
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

    const std::vector<std::string>& wrap_keys = (options.fallback_older || options.fallback_after || options.fallback_older_one_key) ? active_exprs : recovery_exprs;
    std::string desc_str = WrapSortedMulti(options.type, nrequired, wrap_keys, options.fallback_older, options.fallback_after, recovery_exprs, options.fallback_older_one_key);
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
    out.key_exprs = (options.fallback_older || options.fallback_after || options.fallback_older_one_key) ? active_exprs : recovery_exprs;
    out.fallback_older = options.fallback_older;
    out.fallback_after = options.fallback_after;
    out.fallback_older_one_key = options.fallback_older_one_key;
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

static bool IsVaultRecoveryStageMature(const VaultRecoveryStage& stage, int depth, int tip_height)
{
    if (stage.older) return depth >= static_cast<int>(*stage.older);
    if (stage.after) return tip_height >= static_cast<int>(*stage.after);
    return true;
}

bool IsVaultUtxoMature(const InferredVaultPolicy& policy, int depth, int tip_height)
{
    if (!policy.is_vault) return true;
    if (policy.recovery_stages.empty()) {
        return IsVaultRecoveryStageMature({policy.recovery_m, policy.older, policy.after}, depth, tip_height);
    }
    return IsVaultRecoveryStageMature(policy.recovery_stages.front(), depth, tip_height);
}

VaultBalanceBreakdown GetVaultBalanceBreakdown(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    VaultBalanceBreakdown out;
    out.policy = InferWalletVaultPolicy(wallet);
    out.is_vault = out.policy.is_vault;
    for (const auto& stage : out.policy.recovery_stages) {
        VaultBalanceBreakdown::RecoveryStageBalance balance;
        balance.stage = stage;
        out.recovery_stages.push_back(std::move(balance));
    }
    const int tip = wallet.HaveChain() ? wallet.GetLastBlockHeight() : 0;
    const auto coins = AvailableCoins(wallet);
    for (const auto& coin : coins.All()) {
        if (coin.depth <= 0) continue;
        if (wallet.m_lost_signers.empty()) {
            out.immediate += coin.txout.nValue;
        }
        for (auto& stage_balance : out.recovery_stages) {
            if (IsVaultRecoveryStageMature(stage_balance.stage, coin.depth, tip)) {
                stage_balance.recoverable_now += coin.txout.nValue;
            } else {
                stage_balance.awaiting += coin.txout.nValue;
                int remaining = 0;
                if (stage_balance.stage.older) {
                    remaining = std::max(0, static_cast<int>(*stage_balance.stage.older) - coin.depth);
                } else if (stage_balance.stage.after) {
                    remaining = std::max(0, static_cast<int>(*stage_balance.stage.after) - tip);
                }
                if (!stage_balance.earliest_blocks_remaining || remaining < *stage_balance.earliest_blocks_remaining) {
                    stage_balance.earliest_blocks_remaining = remaining;
                }
            }
        }
    }
    if (!out.recovery_stages.empty()) {
        out.recoverable_now = out.recovery_stages.front().recoverable_now;
        out.awaiting = out.recovery_stages.front().awaiting;
        out.earliest_blocks_remaining = out.recovery_stages.front().earliest_blocks_remaining;
    }
    return out;
}

util::Result<void> ApplyVaultRecoveryToCoinControl(const CWallet& wallet,
                                                   CCoinControl& coin_control,
                                                   std::optional<uint32_t> selected_older)
{
    AssertLockHeld(wallet.cs_wallet);
    const auto policy = InferWalletVaultPolicy(wallet);
    if (!policy.is_vault || policy.recovery_stages.empty()) {
        if (selected_older) return util::Error{Untranslated("The wallet does not have the requested relative recovery stage")};
        return {};
    }
    const VaultRecoveryStage* selected = &policy.recovery_stages.front();
    if (selected_older) {
        const auto it = std::find_if(policy.recovery_stages.begin(), policy.recovery_stages.end(), [&](const VaultRecoveryStage& stage) {
            return stage.older == selected_older;
        });
        if (it == policy.recovery_stages.end()) {
            return util::Error{Untranslated(strprintf("The wallet does not have a recovery stage at older(%u)", *selected_older))};
        }
        selected = &*it;
    }
    if (selected->older) {
        coin_control.m_nSequence = *selected->older;
        coin_control.m_min_depth = static_cast<int>(*selected->older);
        coin_control.m_script_path = true;
    } else if (selected->after) {
        coin_control.m_locktime = *selected->after;
        coin_control.m_script_path = true;
        const int tip = wallet.HaveChain() ? wallet.GetLastBlockHeight() : 0;
        if (tip < static_cast<int>(*selected->after)) {
            coin_control.m_min_depth = std::numeric_limits<int>::max();
        }
    }
    return {};
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
    if (pkg.fallback_older_one_key) obj.pushKV("fallback_older_one_key", static_cast<int>(*pkg.fallback_older_one_key));
    if (!pkg.recovery_stages.empty()) {
        UniValue stages(UniValue::VARR);
        for (const auto& stage : pkg.recovery_stages) {
            UniValue value(UniValue::VOBJ);
            value.pushKV("nrequired", stage.nrequired);
            if (stage.older) value.pushKV("fallback_older", static_cast<int>(*stage.older));
            if (stage.after) value.pushKV("fallback_after", static_cast<int>(*stage.after));
            stages.push_back(std::move(value));
        }
        obj.pushKV("recovery_stages", std::move(stages));
    }
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
    if (pkg.version != 1) {
        return util::Error{Untranslated("Unsupported vault policy package version")};
    }
    if (obj.exists("policy_id")) pkg.policy_id = obj["policy_id"].get_str();
    if (obj.exists("network")) pkg.network = obj["network"].get_str();
    if (obj.exists("nrequired")) pkg.nrequired = obj["nrequired"].getInt<int>();
    auto read_lock = [&](const char* name, uint32_t max) -> util::Result<std::optional<uint32_t>> {
        if (!obj.exists(name)) return std::optional<uint32_t>{};
        const int64_t value = obj[name].getInt<int64_t>();
        if (value < 1 || value > max) {
            return util::Error{Untranslated(strprintf("Vault policy package %s is out of range", name))};
        }
        return std::optional<uint32_t>{static_cast<uint32_t>(value)};
    };
    auto fallback_older = read_lock("fallback_older", CTxIn::SEQUENCE_LOCKTIME_MASK);
    if (!fallback_older) return util::Error{util::ErrorString(fallback_older)};
    pkg.fallback_older = *fallback_older;
    auto fallback_after = read_lock("fallback_after", std::numeric_limits<int32_t>::max());
    if (!fallback_after) return util::Error{util::ErrorString(fallback_after)};
    pkg.fallback_after = *fallback_after;
    auto fallback_older_one_key = read_lock("fallback_older_one_key", CTxIn::SEQUENCE_LOCKTIME_MASK);
    if (!fallback_older_one_key) return util::Error{util::ErrorString(fallback_older_one_key)};
    pkg.fallback_older_one_key = *fallback_older_one_key;
    if (obj.exists("recovery_stages")) {
        if (!obj["recovery_stages"].isArray()) {
            return util::Error{Untranslated("Vault policy package recovery_stages must be an array")};
        }
        for (const UniValue& value : obj["recovery_stages"].getValues()) {
            if (!value.isObject() || !value.exists("nrequired")) {
                return util::Error{Untranslated("Vault policy package has an invalid recovery stage")};
            }
            VaultRecoveryStage stage;
            stage.nrequired = value["nrequired"].getInt<int>();
            if (value.exists("fallback_older")) {
                const int64_t older = value["fallback_older"].getInt<int64_t>();
                if (older < 1 || older > CTxIn::SEQUENCE_LOCKTIME_MASK) {
                    return util::Error{Untranslated("Vault policy package has an invalid recovery stage")};
                }
                stage.older = static_cast<uint32_t>(older);
            }
            if (value.exists("fallback_after")) {
                const int64_t after = value["fallback_after"].getInt<int64_t>();
                if (after < 1 || after > std::numeric_limits<int32_t>::max()) {
                    return util::Error{Untranslated("Vault policy package has an invalid recovery stage")};
                }
                stage.after = static_cast<uint32_t>(after);
            }
            if (stage.nrequired <= 0 || stage.older.has_value() == stage.after.has_value()) {
                return util::Error{Untranslated("Vault policy package has an invalid recovery stage")};
            }
            pkg.recovery_stages.push_back(stage);
        }
    }
    if (!obj.exists("descs") || !obj["descs"].isArray() || obj["descs"].empty()) {
        return util::Error{Untranslated("Vault policy package is missing descriptors")};
    }
    for (const UniValue& d : obj["descs"].getValues()) {
        pkg.descs.push_back(d.get_str());
    }
    if (pkg.descs.size() > 2) {
        return util::Error{Untranslated("Vault policy package may contain only a receive descriptor and its matching change descriptor")};
    }
    if (pkg.descs.size() == 2 && !IsCanonicalDescriptorPair(pkg.descs[0], pkg.descs[1])) {
        return util::Error{Untranslated("Vault policy package receive and change descriptors do not form a matching vault pair")};
    }
    const std::string inferred_policy_id = VaultPolicyId(pkg.descs.front());
    if (!pkg.policy_id.empty() && pkg.policy_id != inferred_policy_id) {
        return util::Error{Untranslated("Vault policy package policy_id does not match its receive descriptor")};
    }
    pkg.policy_id = inferred_policy_id;

    const auto descriptor_stages = ParseRecoveryStages(pkg.descs.front());
    if (std::any_of(descriptor_stages.begin(), descriptor_stages.end(), [](const VaultRecoveryStage& stage) {
            return stage.older && *stage.older > CTxIn::SEQUENCE_LOCKTIME_MASK;
        })) {
        return util::Error{Untranslated("Vault policy package descriptor has an out-of-range relative recovery delay")};
    }
    const InferredVaultPolicy inferred = InferVaultPolicy(pkg.descs.front());
    std::optional<uint32_t> inferred_one_key;
    for (size_t i = 1; i < inferred.recovery_stages.size(); ++i) {
        if (inferred.recovery_stages[i].nrequired == 1 && inferred.recovery_stages[i].older) {
            inferred_one_key = inferred.recovery_stages[i].older;
            break;
        }
    }
    if (inferred.is_vault) {
        if ((obj.exists("nrequired") && pkg.nrequired != inferred.recovery_m) ||
            (obj.exists("fallback_older") && pkg.fallback_older != inferred.older) ||
            (obj.exists("fallback_after") && pkg.fallback_after != inferred.after) ||
            (obj.exists("fallback_older_one_key") && pkg.fallback_older_one_key != inferred_one_key) ||
            (obj.exists("recovery_stages") && !RecoveryStagesEqual(pkg.recovery_stages, inferred.recovery_stages))) {
            return util::Error{Untranslated("Vault policy package recovery metadata does not match its receive descriptor")};
        }
        pkg.nrequired = inferred.recovery_m;
        pkg.fallback_older = inferred.older;
        pkg.fallback_after = inferred.after;
        pkg.fallback_older_one_key = inferred_one_key;
        pkg.recovery_stages = inferred.recovery_stages;
    } else {
        if (pkg.fallback_older || pkg.fallback_after || pkg.fallback_older_one_key || !pkg.recovery_stages.empty()) {
            return util::Error{Untranslated("Vault policy package recovery metadata does not match its receive descriptor")};
        }
    }
    return pkg;
}

VaultPolicyPackage ExportWalletVaultPolicy(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    VaultPolicyPackage pkg;
    pkg.network = Params().GetChainTypeString();
    auto vault_desc = [&](bool internal) -> std::optional<std::string> {
        auto* man = wallet.GetScriptPubKeyMan(OutputType::BECH32M, internal);
        auto* desc_man = dynamic_cast<DescriptorScriptPubKeyMan*>(man);
        if (!desc_man) return std::nullopt;
        std::string desc;
        if (!desc_man->GetDescriptorString(desc, /*priv=*/false) || !InferVaultPolicy(desc).is_vault) return std::nullopt;
        return desc;
    };
    const auto receive = vault_desc(/*internal=*/false);
    const auto change = vault_desc(/*internal=*/true);
    if (receive) {
        pkg.descs.push_back(*receive);
        if (change && IsCanonicalDescriptorPair(*receive, *change)) pkg.descs.push_back(*change);
    } else if (change) {
        // Version 1 has no explicit descriptor role. Preserve the historical
        // one-descriptor package for wallets that only have an internal vault.
        pkg.descs.push_back(*change);
    }
    if (!pkg.descs.empty()) {
        const auto policy = InferVaultPolicy(pkg.descs.front());
        pkg.nrequired = policy.recovery_m;
        pkg.fallback_older = policy.older;
        pkg.fallback_after = policy.after;
        pkg.recovery_stages = policy.recovery_stages;
        for (size_t i = 1; i < policy.recovery_stages.size(); ++i) {
            if (policy.recovery_stages[i].nrequired == 1 && policy.recovery_stages[i].older) {
                pkg.fallback_older_one_key = policy.recovery_stages[i].older;
                break;
            }
        }
        pkg.policy_id = VaultPolicyId(pkg.descs.front());
    }
    return pkg;
}

util::Result<void> ImportWalletVaultPolicy(CWallet& wallet, const VaultPolicyPackage& pkg)
{
    AssertLockHeld(wallet.cs_wallet);
    auto checked = ParseVaultPolicyPackage(FormatVaultPolicyPackage(pkg));
    if (!checked) return util::Error{util::ErrorString(checked)};
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
