// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/multisig.h>

#include <chainparams.h>
#include <external_signer.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <span.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/bip39.h>
#include <wallet/coincontrol.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>

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

FixedVaultSchedule ClassifyFixedVaultSchedule(const InferredVaultPolicy& policy)
{
    if (!policy.is_vault || policy.recovery_stages.size() != 2) {
        return FixedVaultSchedule::CUSTOM;
    }
    const VaultRecoveryStage& primary{policy.recovery_stages[0]};
    const VaultRecoveryStage& final{policy.recovery_stages[1]};
    if (primary.nrequired != 2 || !primary.older || primary.after ||
        final.nrequired != 1 || !final.older || final.after) {
        return FixedVaultSchedule::CUSTOM;
    }
    if (*primary.older == FIXED_VAULT_CURRENT_PRIMARY_DELAY &&
        *final.older == FIXED_VAULT_CURRENT_FINAL_DELAY) {
        return FixedVaultSchedule::CURRENT_90_180;
    }
    if (*primary.older == FIXED_VAULT_LEGACY_PRIMARY_DELAY &&
        *final.older == FIXED_VAULT_LEGACY_FINAL_DELAY) {
        return FixedVaultSchedule::LEGACY_30_60;
    }
    return FixedVaultSchedule::CUSTOM;
}

FixedVaultSchedule ClassifyFixedVaultSchedule(const VaultPolicyPackage& package)
{
    InferredVaultPolicy policy;
    policy.is_vault = !package.recovery_stages.empty();
    policy.recovery_stages = package.recovery_stages;
    const FixedVaultSchedule schedule{ClassifyFixedVaultSchedule(policy)};
    if (schedule == FixedVaultSchedule::CUSTOM) return schedule;

    const uint32_t primary_delay{schedule == FixedVaultSchedule::CURRENT_90_180 ? FIXED_VAULT_CURRENT_PRIMARY_DELAY : FIXED_VAULT_LEGACY_PRIMARY_DELAY};
    const uint32_t final_delay{schedule == FixedVaultSchedule::CURRENT_90_180 ? FIXED_VAULT_CURRENT_FINAL_DELAY : FIXED_VAULT_LEGACY_FINAL_DELAY};
    if (package.nrequired != 2 ||
        package.fallback_older != std::optional<uint32_t>{primary_delay} ||
        package.fallback_after ||
        package.fallback_older_one_key != std::optional<uint32_t>{final_delay} ||
        package.descs.empty()) {
        return FixedVaultSchedule::CUSTOM;
    }
    if (ClassifyFixedVaultSchedule(InferVaultPolicy(package.descs.front())) != schedule) {
        return FixedVaultSchedule::CUSTOM;
    }
    return schedule;
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
            if (keys[i].hdkey && keys[j].hdkey && *keys[i].hdkey == *keys[j].hdkey) {
                return Untranslated("Two keys use the same HD key. They are copies of one signer, not independent security domains.");
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
        else if (k.generate_local) out << "  (software key stored in this wallet)";
        else if (k.fingerprint && !k.xpub) out << "  (hardware, xpub fetched at creation)";
        out << "\n";
    }
    const size_t generated_local = static_cast<size_t>(std::count_if(keys.begin(), keys.end(), [](const MultisigKeySpec& key) {
        return key.generate_local;
    }));
    if (generated_local > 1) {
        out << "\nThese " << generated_local << " software keys are cryptographically distinct, but they share one wallet file, backup, and computer.\n";
        out << "They do not provide independent-device protection.\n";
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

struct ResolvedMultisigKey {
    std::string expression;
    //! Canonical derived account xpub, used to reject duplicate participants
    //! even when their private expressions or origin strings differ.
    std::string account_xpub;
    std::optional<GeneratedMnemonic> recovery;
};

static util::Result<ResolvedMultisigKey> ResolvePrivateMaster(const CExtKey& master,
                                                              const std::vector<uint32_t>& parsed_path,
                                                              size_t key_index,
                                                              bool private_expression,
                                                              std::optional<SecureString> generated_mnemonic = {})
{
    auto child = DeriveExtKey(master, parsed_path);
    if (!child) {
        return util::Error{Untranslated("Unable to derive HD key at the requested path")};
    }

    const std::string fingerprint{HexStr(child->second.fingerprint)};
    const std::string path{WriteHDKeypath(child->second.path)};
    const std::string xpub{EncodeExtPubKey(child->first.Neuter())};
    // Candidate preparation must never serialize an xprv into ordinary heap
    // memory. Wallet-backed advanced/RPC creation retains its established
    // private-expression path so Parse() can populate the signing provider.
    const std::string descriptor_key{private_expression ? EncodeExtKey(child->first) : xpub};
    ResolvedMultisigKey out{
        strprintf("[%s%s]%s/<0;1>/*",
                  fingerprint,
                  FormatHDKeypath(child->second.path),
                  descriptor_key),
        xpub,
        std::nullopt,
    };
    if (generated_mnemonic) {
        out.recovery.emplace(GeneratedMnemonic{
            key_index,
            std::move(*generated_mnemonic),
            fingerprint,
            path,
            xpub,
        });
    }
    return out;
}

static util::Result<ResolvedMultisigKey> KeyExprFromSpec(CWallet* wallet,
                                                         const MultisigKeySpec& spec,
                                                         const std::string& default_path,
                                                         size_t key_index) NO_THREAD_SAFETY_ANALYSIS
{
    // The nullable wallet separates pure candidate preparation from the
    // wallet-backed advanced API. Clang cannot express the conditional lock
    // requirement; every wallet-backed caller holds cs_wallet.
    if (wallet) AssertLockHeld(wallet->cs_wallet);

    std::string path = spec.path.value_or(default_path);
    std::vector<uint32_t> parsed_path;
    if (!ParseHDKeypath(path, parsed_path)) {
        return util::Error{Untranslated("Invalid BIP32 keypath")};
    }
    if (!HasHardenedDerivation(parsed_path)) {
        return util::Error{Untranslated("Derivation path requires at least one hardened step")};
    }

    if (spec.generate_local || spec.recovery_mnemonic) {
        if ((spec.generate_local && spec.recovery_mnemonic) || spec.fingerprint || spec.hdkey || spec.xpub) {
            return util::Error{Untranslated("A mnemonic local key cannot also specify another key source")};
        }
        if (wallet && wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            return util::Error{Untranslated("Watch-only wallets cannot generate local keys")};
        }

        SecureString mnemonic;
        if (spec.generate_local) {
            BIP39SecureBytes entropy(BIP39_ENTROPY_SIZE);
            GetStrongRandBytes(entropy);
            mnemonic = EncodeBIP39Mnemonic(
                std::span<const unsigned char, BIP39_ENTROPY_SIZE>{entropy.data(), entropy.size()});
        } else {
            mnemonic = *spec.recovery_mnemonic;
        }
        auto seed = BIP39MnemonicToSeed(std::string_view{mnemonic.data(), mnemonic.size()});
        if (!seed || seed->size() != BIP39_SEED_SIZE) {
            return util::Error{Untranslated("Invalid BIP39 English recovery mnemonic")};
        }
        CExtKey master;
        master.SetSeed(std::as_bytes(std::span{*seed}));
        return ResolvePrivateMaster(master, parsed_path, key_index, /*private_expression=*/wallet != nullptr,
                                    spec.generate_local ? std::optional<SecureString>{std::move(mnemonic)} : std::nullopt);
    }

    if (spec.xpub) {
        if (!spec.fingerprint || spec.fingerprint->size() != 8 || !IsHex(*spec.fingerprint)) {
            return util::Error{Untranslated("Air-gapped keys need an 8-character hex fingerprint plus xpub")};
        }
        const CExtPubKey xpub = DecodeExtPubKey(*spec.xpub);
        if (!xpub.pubkey.IsValid()) {
            return util::Error{Untranslated("Unable to parse xpub")};
        }
        return ResolvedMultisigKey{
            strprintf("[%s%s]%s/<0;1>/*",
                      *spec.fingerprint,
                      FormatHDKeypath(parsed_path),
                      *spec.xpub),
            EncodeExtPubKey(xpub),
            std::nullopt,
        };
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
        const std::string signer_xpub{xpub_res["xpub"].get_str()};
        const CExtPubKey xpub{DecodeExtPubKey(signer_xpub)};
        if (!xpub.pubkey.IsValid()) {
            return util::Error{Untranslated("Signer getxpub returned an invalid xpub")};
        }
        return ResolvedMultisigKey{
            strprintf("[%s%s]%s/<0;1>/*",
                      *spec.fingerprint,
                      FormatHDKeypath(parsed_path),
                      signer_xpub),
            EncodeExtPubKey(xpub),
            std::nullopt,
        };
    }

    if (wallet && wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return util::Error{Untranslated("Watch-only wallets cannot use local keys; specify a signer fingerprint or xpub")};
    }

    if (spec.hdkey) {
        const CExtKey extkey = DecodeExtKey(*spec.hdkey);
        if (extkey.key.IsValid()) {
            if (wallet && wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                return util::Error{Untranslated("Watch-only wallets cannot use local keys; specify a signer fingerprint or xpub")};
            }
            return ResolvePrivateMaster(extkey, parsed_path, key_index, /*private_expression=*/wallet != nullptr);
        }
    }

    CExtPubKey xpub;
    if (spec.hdkey) {
        xpub = DecodeExtPubKey(*spec.hdkey);
        if (!xpub.pubkey.IsValid()) {
            return util::Error{Untranslated("Unable to parse HD key. Please provide a valid xpub or xprv")};
        }
    } else {
        if (!wallet) {
            return util::Error{Untranslated("Preparing a multisig candidate requires every key source to be explicit")};
        }
        CWallet::HDPubKeyMap unused = wallet->GetHDPubKeys(CWallet::HDKeyFilter::UnusedKey);
        CWallet::HDPubKeyMap active = wallet->GetHDPubKeys(CWallet::HDKeyFilter::Active);
        if (unused.size() == 1) {
            xpub = unused.begin()->first;
        } else if (unused.empty() && active.size() == 1) {
            xpub = active.begin()->first;
        } else {
            return util::Error{Untranslated("Unable to determine which HD key to use. Please specify with 'hdkey'")};
        }
    }
    if (!wallet) {
        return util::Error{Untranslated("Preparing a multisig candidate cannot select private keys from a wallet")};
    }
    std::optional<CExtKey> xprv = wallet->GetExtKey(xpub);
    if (!xprv) {
        return util::Error{Untranslated(strprintf("Private key for %s is not known", EncodeExtPubKey(xpub)))};
    }
    return ResolvePrivateMaster(*xprv, parsed_path, key_index, /*private_expression=*/true);
}

static util::Result<MultisigDescriptorResult> BuildMultisigDescriptor(CWallet* wallet,
                                                                      int nrequired,
                                                                      const std::vector<MultisigKeySpec>& keys,
                                                                      const MultisigOptions& options) NO_THREAD_SAFETY_ANALYSIS
{
    // See KeyExprFromSpec: wallet-backed callers hold cs_wallet, while a null
    // wallet is a side-effect-free public candidate build.
    if (wallet) AssertLockHeld(wallet->cs_wallet);

    if (wallet && wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
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
    std::set<std::string> resolved_exprs;
    std::set<std::string> resolved_account_xpubs;
    std::vector<GeneratedMnemonic> generated_recovery;
    active_exprs.reserve(n_active);
    recovery_exprs.reserve(keys.size());
    generated_recovery.reserve(keys.size());
    for (size_t key_index = 0; key_index < keys.size(); ++key_index) {
        const auto& spec = keys[key_index];
        auto resolved = KeyExprFromSpec(wallet, spec, default_path, key_index);
        if (!resolved) return util::Error{util::ErrorString(resolved)};
        if (!resolved_account_xpubs.insert(resolved->account_xpub).second ||
            !resolved_exprs.insert(resolved->expression).second) {
            return util::Error{Untranslated("Each multisig participant must use a distinct key")};
        }
        if (!spec.recovery_only) active_exprs.push_back(resolved->expression);
        recovery_exprs.push_back(std::move(resolved->expression));
        if (resolved->recovery) generated_recovery.push_back(std::move(*resolved->recovery));
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
    out.recovery = std::move(generated_recovery);
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
        if (!wallet) {
            out.descs.push_back(parsed[i]->ToString());
            continue;
        }
        WalletDescriptor w_desc(std::move(parsed[i]), GetTime(), 0, wallet->m_keypool_size, 0);
        auto spkm_res = wallet->AddWalletDescriptor(w_desc, parse_keys, /*label=*/"", desc_internal);
        if (!spkm_res) {
            return util::Error{util::ErrorString(spkm_res)};
        }
        auto& spkm = spkm_res.value().get();
        if (auto type = w_desc.descriptor->GetOutputType()) {
            wallet->AddActiveScriptPubKeyMan(spkm.GetID(), *type, desc_internal);
        }
        std::string out_desc;
        CHECK_NONFATAL(spkm.GetDescriptorString(out_desc, false));
        out.descs.push_back(out_desc);
    }
    if (!out.descs.empty()) out.policy_id = VaultPolicyId(out.descs.front());
    return out;
}

util::Result<MultisigDescriptorResult> PrepareMultisigDescriptor(
    int nrequired,
    const std::vector<MultisigKeySpec>& keys,
    const MultisigOptions& options)
{
    return BuildMultisigDescriptor(/*wallet=*/nullptr, nrequired, keys, options);
}

util::Result<MultisigDescriptorResult> CreateMultisigDescriptor(CWallet& wallet,
                                                                int nrequired,
                                                                const std::vector<MultisigKeySpec>& keys,
                                                                const MultisigOptions& options)
{
    AssertLockHeld(wallet.cs_wallet);
    return BuildMultisigDescriptor(&wallet, nrequired, keys, options);
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

namespace {

struct VaultPolicySigners {
    std::set<std::string> active;
    std::set<std::string> recovery;
};

struct ActiveVaultDescriptors {
    VaultPolicyPackage package;
    InferredVaultPolicy policy;
    std::set<DescriptorScriptPubKeyMan*> managers;
};

std::optional<ActiveVaultDescriptors> GetActiveVaultDescriptors(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    ActiveVaultDescriptors out;
    out.package = ExportWalletVaultPolicy(wallet);
    if (out.package.descs.empty()) return std::nullopt;
    out.policy = InferVaultPolicy(out.package.descs.front());
    if (!out.policy.is_vault) return std::nullopt;

    // ExportWalletVaultPolicy deliberately identifies the active bech32m
    // receive/change pair. Match those exact descriptors back to their
    // managers so unrelated imported descriptors in the same wallet can
    // never contribute coins to Recovery Vault accounting or selection.
    for (const bool internal : {false, true}) {
        auto* manager = dynamic_cast<DescriptorScriptPubKeyMan*>(
            wallet.GetScriptPubKeyMan(OutputType::BECH32M, internal));
        if (!manager) continue;
        std::string descriptor;
        if (!manager->GetDescriptorString(descriptor, /*priv=*/false)) continue;
        if (std::find(out.package.descs.begin(), out.package.descs.end(), descriptor) != out.package.descs.end()) {
            out.managers.insert(manager);
        }
    }
    if (out.managers.empty()) return std::nullopt;
    return out;
}

bool IsActiveVaultOutput(const ActiveVaultDescriptors& vault, const CTxOut& output)
{
    return std::any_of(vault.managers.begin(), vault.managers.end(), [&](const DescriptorScriptPubKeyMan* manager) {
        return manager->IsMine(output.scriptPubKey);
    });
}

std::optional<VaultPolicySigners> ExtractVaultPolicySigners(
    const std::string& descriptor,
    const InferredVaultPolicy& policy)
{
    FlatSigningProvider provider;
    std::string error;
    auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/true);
    if (parsed.size() != 1 || !policy.is_vault || policy.recovery_stages.empty()) return std::nullopt;

    const size_t musig_start = descriptor.find("tr(musig(");
    if (musig_start == std::string::npos) return std::nullopt;
    const size_t musig_open = descriptor.find('(', musig_start + 3);
    if (musig_open == std::string::npos) return std::nullopt;
    size_t musig_close{std::string::npos};
    int nesting{0};
    for (size_t pos = musig_open; pos < descriptor.size(); ++pos) {
        if (descriptor[pos] == '(') {
            ++nesting;
        } else if (descriptor[pos] == ')' && --nesting == 0) {
            musig_close = pos;
            break;
        }
    }
    if (musig_close == std::string::npos) return std::nullopt;

    std::set<CPubKey> plain_pubkeys;
    std::set<CExtPubKey> account_xpubs;
    parsed.front()->GetPubKeys(plain_pubkeys, account_xpubs);
    if (account_xpubs.empty() || !plain_pubkeys.empty()) return std::nullopt;

    VaultPolicySigners signers;
    for (const CExtPubKey& account_xpub : account_xpubs) {
        const std::string xpub{EncodeExtPubKey(account_xpub)};
        std::optional<std::string> fingerprint;
        size_t active_occurrences{0};
        size_t recovery_occurrences{0};
        size_t search_pos{0};
        while (true) {
            const size_t xpub_pos = descriptor.find(xpub, search_pos);
            if (xpub_pos == std::string::npos) break;
            search_pos = xpub_pos + xpub.size();
            if (xpub_pos == 0 || descriptor[xpub_pos - 1] != ']') return std::nullopt;
            const size_t origin_begin = descriptor.rfind('[', xpub_pos - 1);
            if (origin_begin == std::string::npos || xpub_pos - origin_begin < 10) return std::nullopt;
            const std::string_view origin{descriptor.data() + origin_begin + 1,
                                          xpub_pos - origin_begin - 2};
            if (origin.size() < 8 || !IsHex(origin.substr(0, 8)) ||
                (origin.size() > 8 && origin[8] != '/')) {
                return std::nullopt;
            }
            const std::string current{ToLower(origin.substr(0, 8))};
            if (fingerprint && *fingerprint != current) return std::nullopt;
            fingerprint = current;
            if (xpub_pos > musig_open && xpub_pos < musig_close) {
                ++active_occurrences;
            } else {
                ++recovery_occurrences;
            }
        }
        if (!fingerprint || active_occurrences > 1 ||
            recovery_occurrences != policy.recovery_stages.size()) {
            return std::nullopt;
        }
        if (!signers.recovery.insert(*fingerprint).second) return std::nullopt;
        if (active_occurrences == 1) signers.active.insert(*fingerprint);
    }
    if (signers.active.empty()) return std::nullopt;
    return signers;
}

} // namespace

bool IsActiveVaultOutput(const CWallet& wallet, const CTxOut& output)
{
    AssertLockHeld(wallet.cs_wallet);
    const auto vault = GetActiveVaultDescriptors(wallet);
    return vault && IsActiveVaultOutput(*vault, output);
}

static DescriptorScriptPubKeyMan* GetUniqueActiveVaultManager(
    const CWallet& wallet, const CTxOut& output)
{
    AssertLockHeld(wallet.cs_wallet);
    const auto vault{GetActiveVaultDescriptors(wallet)};
    if (!vault) return nullptr;
    DescriptorScriptPubKeyMan* match{nullptr};
    for (DescriptorScriptPubKeyMan* manager : vault->managers) {
        if (!manager->IsMine(output.scriptPubKey)) continue;
        if (match) return nullptr;
        match = manager;
    }
    return match;
}

bool GetActiveVaultKeyOrigin(const CWallet& wallet, const CTxOut& output,
                             const CPubKey& pubkey, KeyOriginInfo& origin)
{
    DescriptorScriptPubKeyMan* manager{GetUniqueActiveVaultManager(wallet, output)};
    if (!manager) return false;
    const auto provider{manager->GetSigningProvider(output.scriptPubKey)};
    return provider && provider->GetKeyOrigin(pubkey.GetID(), origin);
}

bool GetActiveVaultKeyOrigin(const CWallet& wallet, const CTxOut& output,
                             const XOnlyPubKey& pubkey, KeyOriginInfo& origin)
{
    DescriptorScriptPubKeyMan* manager{GetUniqueActiveVaultManager(wallet, output)};
    if (!manager) return false;
    const auto provider{manager->GetSigningProvider(output.scriptPubKey)};
    return provider && provider->GetKeyOriginByXOnly(pubkey, origin);
}

VaultBalanceBreakdown GetVaultBalanceBreakdown(const CWallet& wallet,
                                               bool require_available_signers)
{
    AssertLockHeld(wallet.cs_wallet);
    VaultBalanceBreakdown out;
    const auto vault = GetActiveVaultDescriptors(wallet);
    if (vault) {
        out.policy = vault->policy;
        out.is_vault = true;
    }
    // Callers use the zeroed vault fields for ordinary wallets. Avoid walking
    // coins (and therefore consulting an as-yet-uninitialized processed tip)
    // when there is no vault policy at all.
    if (!out.is_vault) return out;
    for (const auto& stage : out.policy.recovery_stages) {
        VaultBalanceBreakdown::RecoveryStageBalance balance;
        balance.stage = stage;
        out.recovery_stages.push_back(std::move(balance));
    }
    // A WalletModel can be constructed before its wallet is attached and has
    // processed a chain tip. Policy/setup metadata is still useful then, but
    // amount maturity cannot be stated truthfully yet.
    if (!wallet.HasProcessedBlock()) return out;
    const auto signers = ExtractVaultPolicySigners(vault->package.descs.front(), vault->policy);
    const VaultPolicyPackage& active_package{vault->package};
    const bool metadata_matches_policy{
        !active_package.policy_id.empty() &&
        wallet.m_vault_metadata_policy_commitment == VaultPolicyCommitment(active_package)};
    const auto available_count = [&](const std::set<std::string>& participants) {
        return static_cast<size_t>(std::count_if(participants.begin(), participants.end(), [&](const std::string& fingerprint) {
            return !metadata_matches_policy || !wallet.m_lost_signers.contains(fingerprint);
        }));
    };
    const bool immediate_available = !require_available_signers || !out.is_vault ||
                                     (signers && available_count(signers->active) == signers->active.size());
    const size_t recovery_available = signers ? available_count(signers->recovery) : 0;
    const int tip = wallet.HaveChain() ? wallet.GetLastBlockHeight() : 0;
    const auto coins = AvailableCoins(wallet);
    for (const auto& coin : coins.All()) {
        if (coin.depth <= 0 || !IsActiveVaultOutput(*vault, coin.txout)) continue;
        if (immediate_available) {
            out.immediate += coin.txout.nValue;
        }
        for (auto& stage_balance : out.recovery_stages) {
            if (stage_balance.stage.nrequired <= 0 ||
                (require_available_signers &&
                 recovery_available < static_cast<size_t>(stage_balance.stage.nrequired))) {
                continue;
            }
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
                                                   std::optional<uint32_t> selected_older,
                                                   std::optional<uint32_t> selected_after,
                                                   bool sweep)
{
    AssertLockHeld(wallet.cs_wallet);
    if (selected_older && selected_after) {
        return util::Error{Untranslated("A recovery stage cannot use both older() and after()")};
    }
    const auto vault = GetActiveVaultDescriptors(wallet);
    if (!vault || vault->policy.recovery_stages.empty()) {
        if (selected_older || selected_after) {
            return util::Error{Untranslated("The wallet does not have the requested recovery stage")};
        }
        return {};
    }
    const VaultRecoveryStage* selected = &vault->policy.recovery_stages.front();
    if (selected_older || selected_after) {
        const auto it = std::find_if(vault->policy.recovery_stages.begin(), vault->policy.recovery_stages.end(), [&](const VaultRecoveryStage& stage) {
            return stage.older == selected_older && stage.after == selected_after;
        });
        if (it == vault->policy.recovery_stages.end()) {
            return util::Error{selected_older ? Untranslated(strprintf("The wallet does not have a recovery stage at older(%u)", *selected_older)) : Untranslated(strprintf("The wallet does not have a recovery stage at after(%u)", *selected_after))};
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

    // Respect an explicit vault-only subset, but reject selected ordinary or
    // imported-descriptor coins. Automatic selection remains available for
    // RPC compatibility, bounded by m_allowed_inputs below. Only the explicit
    // consumer sweep mode preselects every eligible vault coin.
    const bool had_explicit_selection{coin_control.HasSelected()};
    std::set<COutPoint> allowed_inputs;
    coin_control.m_allowed_inputs.reset();
    if (had_explicit_selection) {
        for (const COutPoint& outpoint : coin_control.ListSelected()) {
            const auto txo = wallet.GetTXO(outpoint);
            const CWalletTx* wtx = wallet.GetWalletTx(outpoint.hash);
            if (!txo || !wtx || !IsActiveVaultOutput(*vault, txo->GetTxOut())) {
                return util::Error{Untranslated("Delayed recovery inputs must belong to the active Recovery Vault policy")};
            }
            const int depth = wallet.GetTxDepthInMainChain(*wtx);
            if (depth <= 0 || !IsVaultRecoveryStageMature(*selected, depth,
                                                          wallet.HaveChain() ? wallet.GetLastBlockHeight() : 0)) {
                return util::Error{Untranslated("A selected Recovery Vault input is not yet eligible for this recovery stage")};
            }
            allowed_inputs.insert(outpoint);
        }
    }
    if (wallet.HasProcessedBlock()) {
        for (const COutput& coin : AvailableCoins(wallet, &coin_control).All()) {
            if (IsActiveVaultOutput(*vault, coin.txout)) allowed_inputs.insert(coin.outpoint);
        }
    }
    coin_control.m_allowed_inputs = allowed_inputs;
    if ((sweep || coin_control.m_vault_recovery_sweep) && !had_explicit_selection) {
        for (const COutPoint& outpoint : allowed_inputs)
            coin_control.Select(outpoint);
        coin_control.m_allow_other_inputs = false;
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

std::string VaultPolicyCommitment(const VaultPolicyPackage& pkg)
{
    const std::string canonical{FormatVaultPolicyPackage(pkg)};
    return Hash(MakeUCharSpan(canonical)).GetHex();
}

util::Result<VaultPolicyPackage> ParseVaultPolicyPackage(const std::string& json)
{
    try {
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
    } catch (const std::exception& e) {
        return util::Error{Untranslated(
            "Vault policy package is malformed: invalid field type: " + std::string{e.what()})};
    } catch (...) {
        return util::Error{Untranslated("Vault policy package is malformed: invalid field type")};
    }
}

namespace {

struct PreparedVaultDescriptor {
    std::unique_ptr<Descriptor> descriptor;
    FlatSigningProvider provider;
    bool internal{false};
};

struct PreparedVaultMnemonicRestore {
    std::vector<VaultMnemonicMatch> matches;
    std::vector<PreparedVaultDescriptor> descriptors;
    std::vector<FixedVaultParticipant> participants;
    std::vector<std::string> unavailable_fingerprints;
};

using ParticipantFingerprints = std::map<std::string, KeyFingerprint>;

util::Result<std::pair<KeyFingerprint, size_t>> DescriptorAccountOrigin(
    const std::string& descriptor,
    const std::string& xpub,
    const std::vector<uint32_t>& standard_path)
{
    std::optional<KeyFingerprint> fingerprint;
    size_t occurrences{0};
    size_t search_pos{0};
    while (true) {
        const size_t xpub_pos = descriptor.find(xpub, search_pos);
        if (xpub_pos == std::string::npos) break;
        search_pos = xpub_pos + xpub.size();

        if (xpub_pos == 0 || descriptor[xpub_pos - 1] != ']') {
            return util::Error{Untranslated("Vault participant xpub is missing its key origin")};
        }
        const size_t origin_begin = descriptor.rfind('[', xpub_pos - 1);
        if (origin_begin == std::string::npos || origin_begin + 9 > xpub_pos) {
            return util::Error{Untranslated("Vault participant has an invalid key origin")};
        }
        const std::string_view origin{descriptor.data() + origin_begin + 1,
                                      xpub_pos - origin_begin - 2};
        if (origin.size() < 8 || !IsHex(origin.substr(0, 8))) {
            return util::Error{Untranslated("Vault participant has an invalid master fingerprint")};
        }
        std::vector<uint32_t> origin_path;
        const std::string encoded_path{"m" + std::string{origin.substr(8)}};
        if (!ParseHDKeypath(encoded_path, origin_path) || origin_path != standard_path) {
            return util::Error{Untranslated("Vault participant does not use the standard account path")};
        }
        const auto decoded_fingerprint = TryParseHex<unsigned char>(origin.substr(0, 8));
        if (!decoded_fingerprint || decoded_fingerprint->size() != 4) {
            return util::Error{Untranslated("Vault participant has an invalid master fingerprint")};
        }
        KeyFingerprint current;
        std::copy(decoded_fingerprint->begin(), decoded_fingerprint->end(), current.begin());
        if (fingerprint && *fingerprint != current) {
            return util::Error{Untranslated("Vault participant has inconsistent key origins")};
        }
        fingerprint = current;
        ++occurrences;
    }
    if (!fingerprint || occurrences == 0) {
        return util::Error{Untranslated("Vault participant xpub is missing from the descriptor")};
    }
    return std::pair<KeyFingerprint, size_t>{*fingerprint, occurrences};
}

util::Result<PreparedVaultMnemonicRestore> PrepareVaultMnemonicRestore(
    const VaultPolicyPackage& package,
    const std::span<const SecureString> mnemonics,
    bool allow_empty)
{
    if ((!allow_empty && mnemonics.empty()) || mnemonics.size() > 3) {
        return util::Error{Untranslated(allow_empty
            ? "Fixed vault installation accepts at most three BIP39 phrases"
            : "Vault recovery requires between one and three BIP39 phrases")};
    }

    auto checked = ParseVaultPolicyPackage(FormatVaultPolicyPackage(package));
    if (!checked) return util::Error{util::ErrorString(checked)};
    if (checked->network.empty() || checked->network != Params().GetChainTypeString()) {
        return util::Error{Untranslated(strprintf("Vault policy network %s does not match this node (%s)",
                                                  checked->network.empty() ? "(missing)" : checked->network,
                                                  Params().GetChainTypeString()))};
    }
    if (checked->descs.size() != 2) {
        return util::Error{Untranslated("Vault mnemonic recovery requires matching receive and change descriptors")};
    }
    const InferredVaultPolicy policy = InferVaultPolicy(checked->descs.front());
    if (!policy.is_vault || policy.recovery_stages.empty()) {
        return util::Error{Untranslated("Policy package is not a staged Scrooge vault")};
    }

    const std::string standard_path_string = DefaultMultisigPath(OutputType::BECH32M, /*account=*/0);
    std::vector<uint32_t> standard_path;
    if (!ParseHDKeypath(standard_path_string, standard_path)) {
        return util::Error{Untranslated("Unable to determine the standard vault account path")};
    }

    PreparedVaultMnemonicRestore prepared;
    prepared.descriptors.reserve(checked->descs.size());
    ParticipantFingerprints participants;
    const size_t expected_occurrences = 1 + policy.recovery_stages.size();
    for (size_t descriptor_index = 0; descriptor_index < checked->descs.size(); ++descriptor_index) {
        FlatSigningProvider provider;
        std::string parse_error;
        auto parsed = Parse(checked->descs[descriptor_index], provider, parse_error, /*require_checksum=*/true);
        if (parsed.size() != 1) {
            return util::Error{Untranslated(parse_error.empty() ? "Vault policy descriptor did not parse uniquely" : parse_error)};
        }
        if (!provider.keys.empty()) {
            return util::Error{Untranslated("Vault policy package must contain public descriptors only")};
        }
        const auto output_type = parsed.front()->GetOutputType();
        if (!output_type || *output_type != OutputType::BECH32M) {
            return util::Error{Untranslated("Vault policy descriptors must be Taproot (bech32m)")};
        }

        std::set<CPubKey> plain_pubkeys;
        std::set<CExtPubKey> account_xpubs;
        parsed.front()->GetPubKeys(plain_pubkeys, account_xpubs);
        if (account_xpubs.size() != 3) {
            return util::Error{Untranslated("Vault mnemonic recovery requires exactly three distinct account xpubs")};
        }

        std::vector<CScript> scripts;
        FlatSigningProvider expanded;
        if (!parsed.front()->Expand(/*pos=*/0, provider, scripts, expanded)) {
            return util::Error{Untranslated("Unable to expand vault policy descriptor")};
        }

        ParticipantFingerprints branch_participants;
        for (const CExtPubKey& account_xpub : account_xpubs) {
            if (account_xpub.nDepth != standard_path.size() || account_xpub.nChild != standard_path.back()) {
                return util::Error{Untranslated("Vault participant xpub is not at the standard account depth")};
            }
            const std::string encoded_xpub = EncodeExtPubKey(account_xpub);
            auto origin = DescriptorAccountOrigin(checked->descs[descriptor_index], encoded_xpub, standard_path);
            if (!origin) return util::Error{util::ErrorString(origin)};
            if (origin->second != expected_occurrences) {
                return util::Error{Untranslated("Vault participant does not appear exactly once in every recovery stage")};
            }

            CExtPubKey branch;
            CExtPubKey address;
            if (!account_xpub.Derive(branch, descriptor_index) || !branch.Derive(address, /*nChild=*/0)) {
                return util::Error{Untranslated("Unable to derive a vault participant address key")};
            }
            const auto expanded_origin = expanded.origins.find(address.pubkey.GetID());
            std::vector<uint32_t> expected_path{standard_path};
            expected_path.push_back(descriptor_index);
            expected_path.push_back(0);
            if (expanded_origin == expanded.origins.end() ||
                expanded_origin->second.second.fingerprint != origin->first ||
                expanded_origin->second.second.path != expected_path) {
                return util::Error{Untranslated("Vault participant origin does not match descriptor derivation")};
            }
            branch_participants.emplace(encoded_xpub, origin->first);
        }
        if (descriptor_index == 0) {
            participants = branch_participants;
            std::set<KeyFingerprint> unique_fingerprints;
            for (const auto& [xpub, fingerprint] : participants) {
                if (!unique_fingerprints.insert(fingerprint).second) {
                    return util::Error{Untranslated("Vault participant master fingerprints are ambiguous")};
                }
                prepared.participants.push_back(FixedVaultParticipant{
                    HexStr(fingerprint), standard_path_string, xpub});
            }
        } else if (branch_participants != participants) {
            return util::Error{Untranslated("Receive and change descriptors do not contain the same vault participants")};
        }
        prepared.descriptors.push_back(PreparedVaultDescriptor{
            std::move(parsed.front()), std::move(provider), descriptor_index == 1});
    }

    std::set<std::string> matched_xpubs;
    std::vector<CExtKey> account_keys;
    account_keys.reserve(mnemonics.size());
    prepared.matches.reserve(mnemonics.size());
    for (size_t mnemonic_index = 0; mnemonic_index < mnemonics.size(); ++mnemonic_index) {
        const SecureString& mnemonic = mnemonics[mnemonic_index];
        auto seed = BIP39MnemonicToSeed(std::string_view{mnemonic.data(), mnemonic.size()});
        if (!seed || seed->size() != BIP39_SEED_SIZE) {
            return util::Error{Untranslated(strprintf("Recovery phrase %u is not a valid 24-word BIP39 English mnemonic", mnemonic_index + 1))};
        }
        CExtKey master;
        master.SetSeed(std::as_bytes(std::span{*seed}));
        auto derived = DeriveExtKey(master, standard_path);
        if (!derived) {
            return util::Error{Untranslated(strprintf("Unable to derive recovery phrase %u at the standard account path", mnemonic_index + 1))};
        }
        const std::string xpub = EncodeExtPubKey(derived->first.Neuter());
        const auto participant = participants.find(xpub);
        if (participant == participants.end()) {
            return util::Error{Untranslated(strprintf("Recovery phrase %u does not match any participant in this vault policy", mnemonic_index + 1))};
        }
        if (!matched_xpubs.insert(xpub).second) {
            return util::Error{Untranslated("Each recovery phrase must match a different vault participant")};
        }
        if (derived->second.fingerprint != participant->second) {
            return util::Error{Untranslated(strprintf("Recovery phrase %u matches an xpub but not its master fingerprint", mnemonic_index + 1))};
        }
        prepared.matches.push_back(VaultMnemonicMatch{
            mnemonic_index,
            HexStr(derived->second.fingerprint),
            standard_path_string,
            xpub,
        });
        account_keys.push_back(std::move(derived->first));
    }
    for (const auto& [xpub, fingerprint] : participants) {
        if (!matched_xpubs.contains(xpub)) {
            prepared.unavailable_fingerprints.push_back(HexStr(fingerprint));
        }
    }

    for (size_t descriptor_index = 0; descriptor_index < prepared.descriptors.size(); ++descriptor_index) {
        auto& item = prepared.descriptors[descriptor_index];
        for (const CExtKey& account_key : account_keys) {
            item.provider.keys.emplace(account_key.key.GetPubKey().GetID(), account_key.key);
        }
        FlatSigningProvider private_keys;
        item.descriptor->ExpandPrivate(/*pos=*/0, item.provider, private_keys);
        if (private_keys.keys.size() != account_keys.size()) {
            return util::Error{Untranslated("Vault descriptor did not accept every matched private account key")};
        }
        for (const CExtKey& account_key : account_keys) {
            CExtKey branch;
            CExtKey address;
            if (!account_key.Derive(branch, descriptor_index) || !branch.Derive(address, /*nChild=*/0) ||
                !private_keys.keys.contains(address.key.GetPubKey().GetID())) {
                return util::Error{Untranslated("Vault descriptor private-key derivation did not match its public branch")};
            }
        }
    }
    return prepared;
}

} // namespace

util::Result<void> ValidateFixedStagedVaultPolicy(const VaultPolicyPackage& package)
{
    auto checked = ParseVaultPolicyPackage(FormatVaultPolicyPackage(package));
    if (!checked) return util::Error{util::ErrorString(checked)};
    if (checked->network.empty() || checked->network != Params().GetChainTypeString()) {
        return util::Error{Untranslated(strprintf("Vault policy network %s does not match this node (%s)",
                                                  checked->network.empty() ? "(missing)" : checked->network,
                                                  Params().GetChainTypeString()))};
    }
    if (checked->descs.size() != 2) {
        return util::Error{Untranslated("The fixed staged vault requires matching receive and change descriptors")};
    }
    const FixedVaultSchedule schedule{ClassifyFixedVaultSchedule(*checked)};
    uint32_t primary_delay{0};
    uint32_t final_delay{0};
    switch (schedule) {
    case FixedVaultSchedule::CURRENT_90_180:
        primary_delay = FIXED_VAULT_CURRENT_PRIMARY_DELAY;
        final_delay = FIXED_VAULT_CURRENT_FINAL_DELAY;
        break;
    case FixedVaultSchedule::LEGACY_30_60:
        primary_delay = FIXED_VAULT_LEGACY_PRIMARY_DELAY;
        final_delay = FIXED_VAULT_LEGACY_FINAL_DELAY;
        break;
    case FixedVaultSchedule::CUSTOM:
        return util::Error{Untranslated("The policy is not a supported fixed 3-to-2-to-1 staged vault schedule")};
    }

    const std::string standard_path_string = DefaultMultisigPath(OutputType::BECH32M, /*account=*/0);
    std::vector<uint32_t> standard_path;
    if (!ParseHDKeypath(standard_path_string, standard_path)) {
        return util::Error{Untranslated("Unable to determine the standard vault account path")};
    }

    std::optional<VaultPolicySigners> expected_signers;
    ParticipantFingerprints expected_participants;
    std::vector<std::pair<size_t, std::string>> ordered_key_expressions;
    for (size_t descriptor_index = 0; descriptor_index < checked->descs.size(); ++descriptor_index) {
        const std::string& descriptor = checked->descs[descriptor_index];
        const InferredVaultPolicy policy{InferVaultPolicy(descriptor)};
        const auto signers{ExtractVaultPolicySigners(descriptor, policy)};
        if (!signers || signers->active.size() != 3 || signers->recovery.size() != 3 ||
            signers->active != signers->recovery) {
            return util::Error{Untranslated("The fixed staged vault requires the same three participants in its immediate and recovery paths")};
        }
        if (expected_signers &&
            (signers->active != expected_signers->active || signers->recovery != expected_signers->recovery)) {
            return util::Error{Untranslated("Vault receive and change descriptors contain different participants")};
        }
        expected_signers = signers;

        FlatSigningProvider provider;
        std::string parse_error;
        auto parsed = Parse(descriptor, provider, parse_error, /*require_checksum=*/true);
        if (parsed.size() != 1 || !provider.keys.empty()) {
            return util::Error{Untranslated("The fixed staged vault package must contain public descriptors only")};
        }
        const auto output_type = parsed.front()->GetOutputType();
        if (!output_type || *output_type != OutputType::BECH32M) {
            return util::Error{Untranslated("The fixed staged vault descriptors must be Taproot (bech32m)")};
        }

        std::set<CPubKey> plain_pubkeys;
        std::set<CExtPubKey> account_xpubs;
        parsed.front()->GetPubKeys(plain_pubkeys, account_xpubs);
        if (!plain_pubkeys.empty() || account_xpubs.size() != 3) {
            return util::Error{Untranslated("The fixed staged vault requires exactly three account xpubs")};
        }
        ParticipantFingerprints participants;
        for (const CExtPubKey& account_xpub : account_xpubs) {
            if (account_xpub.nDepth != standard_path.size() || account_xpub.nChild != standard_path.back()) {
                return util::Error{Untranslated("Vault participant xpub is not at the standard account depth")};
            }
            const std::string encoded_xpub{EncodeExtPubKey(account_xpub)};
            auto origin = DescriptorAccountOrigin(descriptor, encoded_xpub, standard_path);
            if (!origin) return util::Error{util::ErrorString(origin)};
            if (origin->second != 3) {
                return util::Error{Untranslated("Each fixed staged vault participant must appear once in the immediate path and both recovery stages")};
            }
            participants.emplace(encoded_xpub, origin->first);
            if (descriptor_index == 0) {
                ordered_key_expressions.emplace_back(
                    descriptor.find(encoded_xpub),
                    strprintf("[%s%s]%s/<0;1>/*",
                              HexStr(origin->first),
                              FormatHDKeypath(standard_path),
                              encoded_xpub));
            }
        }
        if (expected_participants.empty()) {
            expected_participants = std::move(participants);
        } else if (participants != expected_participants) {
            return util::Error{Untranslated("Vault receive and change descriptors contain different account xpubs")};
        }
    }

    // Participant occurrence counts alone cannot prove that each recovery
    // stage contains each signer exactly once: an extra Taproot leaf can
    // compensate for a signer omitted from another leaf. Reconstruct the only
    // policy this GUI supports from the ordered internal-key participants and
    // require both supplied descriptors to be byte-for-byte canonical output.
    std::sort(ordered_key_expressions.begin(), ordered_key_expressions.end());
    std::vector<std::string> key_expressions;
    key_expressions.reserve(ordered_key_expressions.size());
    for (auto& [position, expression] : ordered_key_expressions) {
        if (position == std::string::npos) {
            return util::Error{Untranslated("Vault participant is missing from the immediate signing path")};
        }
        key_expressions.push_back(std::move(expression));
    }
    std::string canonical = WrapSortedMulti(OutputType::BECH32M,
                                            /*nrequired=*/2,
                                            key_expressions,
                                            primary_delay,
                                            /*fallback_after=*/{},
                                            key_expressions,
                                            final_delay);
    const std::string checksum{GetDescriptorChecksum(canonical)};
    if (canonical.empty() || checksum.empty()) {
        return util::Error{Untranslated("Unable to reconstruct the canonical fixed staged vault")};
    }
    canonical += "#" + checksum;
    FlatSigningProvider canonical_provider;
    std::string canonical_error;
    auto canonical_descriptors = Parse(canonical, canonical_provider, canonical_error, /*require_checksum=*/true);
    if (canonical_descriptors.size() != checked->descs.size() ||
        !std::equal(canonical_descriptors.begin(), canonical_descriptors.end(), checked->descs.begin(),
                    [](const std::unique_ptr<Descriptor>& descriptor, const std::string& supplied) {
                        return descriptor->ToString() == supplied;
                    })) {
        return util::Error{Untranslated("Vault descriptors do not match the canonical fixed staged vault construction")};
    }
    return {};
}

util::Result<std::vector<VaultMnemonicMatch>> ValidateVaultPolicyMnemonics(
    const VaultPolicyPackage& package,
    const std::span<const SecureString> mnemonics)
{
    auto prepared = PrepareVaultMnemonicRestore(package, mnemonics, /*allow_empty=*/false);
    if (!prepared) return util::Error{util::ErrorString(prepared)};
    return std::move(prepared->matches);
}

util::Result<std::vector<VaultMnemonicMatch>> ValidateFixedVaultMnemonics(
    const VaultPolicyPackage& package,
    const std::span<const SecureString> mnemonics)
{
    if (auto fixed = ValidateFixedStagedVaultPolicy(package); !fixed) {
        return util::Error{util::ErrorString(fixed)};
    }
    auto prepared = PrepareVaultMnemonicRestore(package, mnemonics, /*allow_empty=*/true);
    if (!prepared) return util::Error{util::ErrorString(prepared)};
    return std::move(prepared->matches);
}

util::Result<std::vector<FixedVaultParticipant>> FixedVaultParticipants(const VaultPolicyPackage& package)
{
    if (auto fixed = ValidateFixedStagedVaultPolicy(package); !fixed) {
        return util::Error{util::ErrorString(fixed)};
    }
    auto prepared = PrepareVaultMnemonicRestore(package, /*mnemonics=*/{}, /*allow_empty=*/true);
    if (!prepared) return util::Error{util::ErrorString(prepared)};
    return std::move(prepared->participants);
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

bool IsFixedStagedVault(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    return bool(ValidateFixedStagedVaultPolicy(ExportWalletVaultPolicy(wallet)));
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

namespace {
util::Result<std::vector<VaultMnemonicMatch>> InstallPreparedVaultPolicy(
    CWallet& wallet,
    PreparedVaultMnemonicRestore prepared,
    uint64_t creation_time,
    bool persist_unavailable_as_lost)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return util::Error{Untranslated("Vault mnemonic recovery requires a descriptor wallet")};
    }
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !prepared.matches.empty()) {
        return util::Error{Untranslated("Vault mnemonic recovery requires a wallet that can store private keys")};
    }
    if (wallet.IsLocked()) {
        return util::Error{Untranslated("Unlock the wallet before restoring vault recovery phrases")};
    }
    if (wallet.m_keypool_size < 1 || wallet.m_keypool_size > std::numeric_limits<int32_t>::max()) {
        return util::Error{Untranslated("Wallet keypool size is outside the supported descriptor range")};
    }

    struct ImportItem {
        WalletDescriptor descriptor;
        FlatSigningProvider provider;
        bool internal{false};
    };
    std::vector<ImportItem> imports;
    imports.reserve(prepared.descriptors.size());
    for (auto& item : prepared.descriptors) {
        imports.push_back(ImportItem{
            WalletDescriptor{std::move(item.descriptor), creation_time,
                             /*range_start=*/0, static_cast<int32_t>(wallet.m_keypool_size), /*next_index=*/0},
            std::move(item.provider),
            item.internal,
        });
    }

    // Preflight both updates and active-manager conflicts before either branch
    // receives private material.
    for (auto& item : imports) {
        DescriptorScriptPubKeyMan* const matching = wallet.GetDescriptorScriptPubKeyMan(item.descriptor);
        if (matching) {
            std::string error;
            if (!matching->CanUpdateToWalletDescriptor(item.descriptor, error)) {
                return util::Error{Untranslated(error)};
            }
        }
        ScriptPubKeyMan* const active = wallet.GetScriptPubKeyMan(OutputType::BECH32M, item.internal);
        if (active && active != matching) {
            return util::Error{Untranslated("Wallet already has a different active Taproot descriptor")};
        }
    }

    std::vector<std::pair<DescriptorScriptPubKeyMan*, bool>> imported;
    imported.reserve(imports.size());
    for (auto& item : imports) {
        auto added = wallet.AddWalletDescriptor(item.descriptor, item.provider, /*label=*/"", item.internal);
        if (!added) return util::Error{util::ErrorString(added)};
        imported.emplace_back(&added->get(), item.internal);
    }
    for (const auto& [manager, internal] : imported) {
        wallet.AddActiveScriptPubKeyMan(manager->GetID(), OutputType::BECH32M, internal);
    }
    if (persist_unavailable_as_lost) {
        const std::set<std::string> lost_signers{prepared.unavailable_fingerprints.begin(),
                                                 prepared.unavailable_fingerprints.end()};
        if (!wallet.SetLostSigners(lost_signers)) {
            return util::Error{Untranslated("Vault keys were restored, but unavailable-signer metadata could not be saved")};
        }
    }
    return std::move(prepared.matches);
}
} // namespace

util::Result<std::vector<VaultMnemonicMatch>> InstallFixedVaultPolicy(
    CWallet& wallet,
    const VaultPolicyPackage& package,
    const std::span<const SecureString> mnemonics,
    uint64_t creation_time,
    bool persist_unavailable_as_lost)
{
    AssertLockHeld(wallet.cs_wallet);
    if (auto fixed = ValidateFixedStagedVaultPolicy(package); !fixed) {
        return util::Error{util::ErrorString(fixed)};
    }
    auto prepared = PrepareVaultMnemonicRestore(package, mnemonics, /*allow_empty=*/true);
    if (!prepared) return util::Error{util::ErrorString(prepared)};
    return InstallPreparedVaultPolicy(wallet, std::move(*prepared), creation_time,
                                      persist_unavailable_as_lost);
}

util::Result<std::vector<VaultMnemonicMatch>> RestoreWalletVaultPolicy(
    CWallet& wallet,
    const VaultPolicyPackage& package,
    const std::span<const SecureString> mnemonics)
{
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return util::Error{Untranslated("Vault mnemonic recovery requires a wallet that can store private keys")};
    }
    auto prepared = PrepareVaultMnemonicRestore(package, mnemonics, /*allow_empty=*/false);
    if (!prepared) return util::Error{util::ErrorString(prepared)};
    return InstallPreparedVaultPolicy(wallet, std::move(*prepared), /*creation_time=*/0,
                                      /*persist_unavailable_as_lost=*/true);
}
} // namespace wallet
