// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/recovery_vault_kit.h>

#include <crypto/sha256.h>
#include <support/cleanse.h>
#include <univalue.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/multisig.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <ranges>
#include <set>
#include <span>
#include <system_error>

namespace wallet {
namespace {

constexpr std::string_view KIT_FORMAT{"bitcoin-core-recovery-vault-kit"};
constexpr int KIT_VERSION{1};
constexpr size_t MAX_PUBLIC_FILE_SIZE{1024 * 1024};
constexpr size_t MAX_MNEMONIC_FILE_SIZE{512};
constexpr std::string_view MANIFEST_FILE{"manifest.json"};
constexpr std::string_view POLICY_FILE{"policy.json"};
constexpr std::string_view README_FILE{"README.txt"};

struct KitKey {
    size_t slot{0};
    std::string fingerprint;
    std::string path;
    std::string xpub;
    std::string file;
};

using FilePtr = std::unique_ptr<FILE, decltype(&std::fclose)>;

bool PathWithin(const fs::path& path, const fs::path& root)
{
    auto path_it{path.begin()};
    for (auto root_it{root.begin()}; root_it != root.end(); ++root_it, ++path_it) {
        if (path_it == path.end() || *path_it != *root_it) return false;
    }
    return true;
}

util::Result<fs::path> ResolveKitPath(
    const fs::path& input,
    const fs::path& forbidden_root,
    const bool must_exist)
{
    if (!input.is_absolute() || input.filename().empty()) {
        return util::Error{Untranslated("Recovery Kit path must be an absolute path naming one directory")};
    }
    std::error_code error;
    const fs::path parent{fs::canonical(input.parent_path(), error)};
    if (error || !fs::is_directory(parent)) {
        return util::Error{Untranslated("Recovery Kit parent directory does not exist or cannot be resolved")};
    }
    const fs::path resolved{fsbridge::AbsPathJoin(parent, input.filename()).lexically_normal()};
    const fs::path forbidden{fs::canonical(forbidden_root, error)};
    if (error) {
        return util::Error{Untranslated("Wallet data directory cannot be resolved for Recovery Kit isolation")};
    }
    if (PathWithin(resolved, forbidden)) {
        return util::Error{Untranslated("Recovery Kit must be stored outside the Bitcoin data directory")};
    }
    const fs::file_status target_status{fs::symlink_status(resolved, error)};
    if (error && error != std::errc::no_such_file_or_directory) {
        return util::Error{Untranslated("Recovery Kit path cannot be inspected")};
    }
    const bool exists{!error && fs::exists(target_status)};
    if (must_exist && !exists) {
        return util::Error{Untranslated("Recovery Kit directory does not exist")};
    }
    if (!must_exist && exists) {
        return util::Error{Untranslated("Recovery Kit path already exists; choose a new empty path")};
    }
    return resolved;
}

bool PrivatePermissions(const fs::path& path, const bool directory, bilingual_str& error)
{
    std::error_code code;
    const fs::file_status status{fs::symlink_status(path, code)};
    if (code || (directory ? status.type() != fs::file_type::directory : status.type() != fs::file_type::regular)) {
        error = Untranslated(directory ? "Recovery Kit path is not a real directory" : "Recovery Kit contains a non-regular file");
        return false;
    }
#ifndef WIN32
    const fs::perms forbidden{fs::perms::group_all | fs::perms::others_all};
    if ((status.permissions() & forbidden) != fs::perms::none) {
        error = Untranslated("Recovery Kit permissions allow access by another user");
        return false;
    }
    if (!directory && fs::hard_link_count(path, code) != 1) {
        error = Untranslated("Recovery Kit files must not have additional hard links");
        return false;
    }
    if (code) {
        error = Untranslated("Recovery Kit file identity cannot be inspected");
        return false;
    }
#endif
    return true;
}

bool SetPrivatePermissions(const fs::path& path, const bool directory, bilingual_str& error)
{
    std::error_code code;
    const fs::perms permissions{directory ? fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec : fs::perms::owner_read | fs::perms::owner_write};
    fs::permissions(path, permissions, fs::perm_options::replace, code);
    if (code) {
        error = Untranslated("Unable to restrict Recovery Kit permissions to the current user");
        return false;
    }
    return PrivatePermissions(path, directory, error);
}

bool WritePrivateFile(const fs::path& path, const std::span<const char> data, bilingual_str& error)
{
    FilePtr file{fsbridge::fopen(path,
#ifdef __MINGW64__
                                 // The containing directory was just created exclusively and remains
                                 // private. MinGW does not currently support the C11 "x" mode.
                                 "wb"
#else
                                 "wbx"
#endif
                                 ),
                 &std::fclose};
    if (!file) {
        error = Untranslated(strprintf("Unable to create Recovery Kit file: %s", std::strerror(errno)));
        return false;
    }
    if (!SetPrivatePermissions(path, /*directory=*/false, error)) return false;
    if ((!data.empty() && std::fwrite(data.data(), 1, data.size(), file.get()) != data.size()) ||
        std::fputc('\n', file.get()) == EOF || !FileCommit(file.get())) {
        error = Untranslated("Unable to durably write Recovery Kit file");
        return false;
    }
    if (std::fclose(file.release()) != 0) {
        error = Untranslated("Unable to close Recovery Kit file after writing");
        return false;
    }
    return true;
}

util::Result<std::string> ReadPublicFile(const fs::path& path)
{
    bilingual_str permission_error;
    if (!PrivatePermissions(path, /*directory=*/false, permission_error)) {
        return util::Error{permission_error};
    }
    std::error_code code;
    const uintmax_t size{fs::file_size(path, code)};
    if (code || size == 0 || size > MAX_PUBLIC_FILE_SIZE) {
        return util::Error{Untranslated("Recovery Kit public file has an invalid size")};
    }
    FilePtr file{fsbridge::fopen(path, "rb"), &std::fclose};
    if (!file) return util::Error{Untranslated("Unable to open Recovery Kit public file")};
    std::string out(static_cast<size_t>(size), '\0');
    if (std::fread(out.data(), 1, out.size(), file.get()) != out.size()) {
        return util::Error{Untranslated("Unable to read complete Recovery Kit public file")};
    }
    if (!out.empty() && out.back() == '\n') out.pop_back();
    if (out.empty() || out.find('\0') != std::string::npos) {
        return util::Error{Untranslated("Recovery Kit public file contains invalid data")};
    }
    return out;
}

util::Result<SecureString> ReadMnemonicFile(const fs::path& path)
{
    bilingual_str permission_error;
    if (!PrivatePermissions(path, /*directory=*/false, permission_error)) {
        return util::Error{permission_error};
    }
    std::error_code code;
    const uintmax_t size{fs::file_size(path, code)};
    if (code || size == 0 || size > MAX_MNEMONIC_FILE_SIZE) {
        return util::Error{Untranslated("Recovery Kit mnemonic file has an invalid size")};
    }
    FilePtr file{fsbridge::fopen(path, "rb"), &std::fclose};
    if (!file) return util::Error{Untranslated("Unable to open Recovery Kit mnemonic file")};
    SecureString out(static_cast<size_t>(size), '\0');
    if (std::fread(out.data(), 1, out.size(), file.get()) != out.size()) {
        return util::Error{Untranslated("Unable to read complete Recovery Kit mnemonic file")};
    }
    if (!out.empty() && out.back() == '\n') out.pop_back();
    if (!out.empty() && out.back() == '\r') out.pop_back();
    if (out.empty() || std::find(out.begin(), out.end(), '\0') != out.end() ||
        std::find(out.begin(), out.end(), '\n') != out.end() ||
        std::find(out.begin(), out.end(), '\r') != out.end()) {
        return util::Error{Untranslated("Recovery Kit mnemonic file contains invalid data")};
    }
    return out;
}

std::string HashText(const std::span<const char> text)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(text.data()), text.size()).Finalize(digest.data());
    return HexStr(digest);
}

void HashField(CSHA256& hasher, const std::span<const char> value)
{
    std::array<unsigned char, 8> size;
    uint64_t remaining{value.size()};
    for (unsigned char& byte : size) {
        byte = remaining & 0xff;
        remaining >>= 8;
    }
    hasher.Write(size.data(), size.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(value.data()), value.size());
}

std::string KitCommitment(
    const std::string& manifest,
    const std::string& readme,
    const std::string& policy,
    const std::span<const SecureString> mnemonics)
{
    CSHA256 hasher;
    constexpr std::string_view tag{"Bitcoin Core Recovery Vault Kit v1"};
    HashField(hasher, tag);
    HashField(hasher, manifest);
    HashField(hasher, readme);
    HashField(hasher, policy);
    for (const SecureString& mnemonic : mnemonics) {
        HashField(hasher, std::span<const char>{mnemonic.data(), mnemonic.size()});
    }
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest;
    hasher.Finalize(digest.data());
    return HexStr(digest);
}

std::string ReadmeText(const std::string& wallet_name, const std::string& policy_id)
{
    return strprintf(
        "BITCOIN CORE RECOVERY VAULT KIT - PRIVATE\n\n"
        "Wallet: %s\nPolicy ID: %s\nSchedule: 12,960 blocks (about 90 days) for two keys; "
        "25,920 blocks (about 180 days) for one key.\n\n"
        "This directory is an unencrypted bearer backup. Each software-key file contains one "
        "24-word BIP39 recovery phrase. The policy.json file is also required: a phrase alone "
        "does not reconstruct the other participants, Taproot scripts, or delays.\n\n"
        "Store a complete copy offline, away from this computer. Never upload, email, photograph, "
        "or paste the phrase files into a website. Recovery never happens automatically. Every "
        "received coin has its own timer, and change starts new timers.\n",
        wallet_name, policy_id);
}

std::string ManifestText(
    const RecoveryVaultKitSummary& summary,
    const std::span<const KitKey> keys)
{
    UniValue manifest{UniValue::VOBJ};
    manifest.pushKV("format", std::string{KIT_FORMAT});
    manifest.pushKV("version", KIT_VERSION);
    manifest.pushKV("wallet_name", summary.wallet_name);
    manifest.pushKV("network", summary.network);
    manifest.pushKV("policy_id", summary.policy_id);
    manifest.pushKV("policy_commitment", summary.policy_commitment);
    manifest.pushKV("policy_file", std::string{POLICY_FILE});
    manifest.pushKV("policy_sha256", HashText(summary.canonical_policy));
    manifest.pushKV("primary_delay", static_cast<int>(FIXED_VAULT_CURRENT_PRIMARY_DELAY));
    manifest.pushKV("final_delay", static_cast<int>(FIXED_VAULT_CURRENT_FINAL_DELAY));
    UniValue key_values{UniValue::VARR};
    for (const KitKey& key : keys) {
        UniValue value{UniValue::VOBJ};
        value.pushKV("slot", static_cast<int>(key.slot));
        value.pushKV("fingerprint", key.fingerprint);
        value.pushKV("path", key.path);
        value.pushKV("xpub", key.xpub);
        value.pushKV("file", key.file);
        key_values.push_back(std::move(value));
    }
    manifest.pushKV("software_keys", std::move(key_values));
    return manifest.write();
}

util::Result<std::pair<RecoveryVaultKitSummary, std::vector<KitKey>>> ParseManifest(
    const std::string& text,
    const fs::path& path)
{
    UniValue manifest;
    if (!manifest.read(text) || !manifest.isObject()) {
        return util::Error{Untranslated("Recovery Kit manifest is not valid JSON")};
    }
    try {
        if (!manifest.exists("format") || manifest["format"].get_str() != KIT_FORMAT ||
            !manifest.exists("version") || manifest["version"].getInt<int>() != KIT_VERSION) {
            return util::Error{Untranslated("Recovery Kit manifest uses an unsupported format or version")};
        }
        RecoveryVaultKitSummary summary;
        summary.path = path;
        summary.wallet_name = manifest["wallet_name"].get_str();
        summary.network = manifest["network"].get_str();
        summary.policy_id = manifest["policy_id"].get_str();
        summary.policy_commitment = manifest["policy_commitment"].get_str();
        if (!IsValidRecoveryVaultWalletName(summary.wallet_name) ||
            manifest["policy_file"].get_str() != POLICY_FILE ||
            manifest["primary_delay"].getInt<int>() != static_cast<int>(FIXED_VAULT_CURRENT_PRIMARY_DELAY) ||
            manifest["final_delay"].getInt<int>() != static_cast<int>(FIXED_VAULT_CURRENT_FINAL_DELAY) ||
            !manifest["software_keys"].isArray() || manifest["software_keys"].size() != 3) {
            return util::Error{Untranslated("Recovery Kit manifest does not describe the current fixed 90/180 vault")};
        }
        std::vector<KitKey> keys;
        std::set<std::string> files;
        for (size_t i = 0; i < manifest["software_keys"].size(); ++i) {
            const UniValue& value{manifest["software_keys"][i]};
            KitKey key;
            key.slot = value["slot"].getInt<int>();
            key.fingerprint = value["fingerprint"].get_str();
            key.path = value["path"].get_str();
            key.xpub = value["xpub"].get_str();
            key.file = value["file"].get_str();
            const std::string expected_file{strprintf("software-key-%u.txt", i + 1)};
            if (key.slot != i + 1 || key.file != expected_file ||
                key.fingerprint.size() != 8 || !IsHex(key.fingerprint) ||
                key.path.empty() || key.xpub.empty() || !files.insert(key.file).second) {
                return util::Error{Untranslated("Recovery Kit manifest contains invalid software-key metadata")};
            }
            keys.push_back(std::move(key));
        }
        summary.software_key_count = keys.size();
        return std::pair{std::move(summary), std::move(keys)};
    } catch (const std::exception&) {
        return util::Error{Untranslated("Recovery Kit manifest is missing a required field or has the wrong type")};
    }
}

bool ExactDirectoryEntries(const fs::path& path, const std::span<const KitKey> keys, bilingual_str& error)
{
    std::set<std::string> expected{
        std::string{MANIFEST_FILE}, std::string{POLICY_FILE}, std::string{README_FILE}};
    for (const KitKey& key : keys)
        expected.insert(key.file);
    std::error_code code;
    for (const fs::directory_entry& entry : fs::directory_iterator(path, code)) {
        if (code || !expected.erase(fs::PathToString(entry.path().filename()))) {
            error = Untranslated("Recovery Kit directory contains an unexpected or duplicate entry");
            return false;
        }
    }
    if (code || !expected.empty()) {
        error = Untranslated("Recovery Kit directory is incomplete or cannot be enumerated");
        return false;
    }
    return true;
}

} // namespace

bool IsValidRecoveryVaultWalletName(const std::string_view name)
{
    if (name.empty() || name.size() > 128) return false;
    const fs::path path{fs::PathFromString(std::string{name})};
    return !path.has_parent_path() && path.filename() == path &&
           std::ranges::none_of(name, [](const unsigned char c) { return c < 0x20 || c == 0x7f; });
}

RecoveryVaultKitMaterial::~RecoveryVaultKitMaterial()
{
    for (SecureString& mnemonic : mnemonics) {
        if (!mnemonic.empty()) memory_cleanse(mnemonic.data(), mnemonic.size());
        SecureString{}.swap(mnemonic);
    }
}

util::Result<RecoveryVaultKitSummary> PrepareRecoveryVaultKit(
    const fs::path& target,
    const std::string& wallet_name,
    const std::string& network,
    const fs::path& forbidden_root)
{
    if (!IsValidRecoveryVaultWalletName(wallet_name)) {
        return util::Error{Untranslated("Recovery Vault requires a simple wallet name without path components or control characters")};
    }
    auto resolved{ResolveKitPath(target, forbidden_root, /*must_exist=*/false)};
    if (!resolved) return util::Error{util::ErrorString(resolved)};

    std::vector<MultisigKeySpec> specs(3);
    for (MultisigKeySpec& spec : specs) {
        spec.path = DefaultMultisigPath(OutputType::BECH32M, 0);
        spec.generate_local = true;
    }
    MultisigOptions options;
    options.type = OutputType::BECH32M;
    options.account = 0;
    options.fallback_older = FIXED_VAULT_CURRENT_PRIMARY_DELAY;
    options.fallback_older_one_key = FIXED_VAULT_CURRENT_FINAL_DELAY;
    auto prepared{PrepareMultisigDescriptor(/*nrequired=*/2, specs, options)};
    if (!prepared) return util::Error{util::ErrorString(prepared)};
    if (prepared->descs.size() != 2 || prepared->recovery.size() != 3) {
        return util::Error{Untranslated("Recovery Vault preparation did not produce the expected descriptor and key count")};
    }
    std::ranges::sort(prepared->recovery, {}, &GeneratedMnemonic::key_index);

    VaultPolicyPackage package;
    package.network = network;
    package.nrequired = 2;
    package.fallback_older = FIXED_VAULT_CURRENT_PRIMARY_DELAY;
    package.fallback_older_one_key = FIXED_VAULT_CURRENT_FINAL_DELAY;
    package.recovery_stages = {
        {2, FIXED_VAULT_CURRENT_PRIMARY_DELAY, {}},
        {1, FIXED_VAULT_CURRENT_FINAL_DELAY, {}},
    };
    package.descs = prepared->descs;
    package.policy_id = VaultPolicyId(package.descs.front());
    auto valid{ValidateFixedStagedVaultPolicy(package)};
    if (!valid) return util::Error{util::ErrorString(valid)};
    if (ClassifyFixedVaultSchedule(package) != FixedVaultSchedule::CURRENT_90_180) {
        return util::Error{Untranslated("Recovery Vault preparation produced the wrong schedule")};
    }

    RecoveryVaultKitSummary summary;
    summary.path = *resolved;
    summary.wallet_name = wallet_name;
    summary.network = network;
    summary.policy_id = package.policy_id;
    summary.policy_commitment = VaultPolicyCommitment(package);
    summary.canonical_policy = FormatVaultPolicyPackage(package);
    summary.software_key_count = prepared->recovery.size();

    std::vector<KitKey> keys;
    std::vector<SecureString> mnemonics;
    keys.reserve(prepared->recovery.size());
    mnemonics.reserve(prepared->recovery.size());
    for (size_t index = 0; index < prepared->recovery.size(); ++index) {
        GeneratedMnemonic& recovery{prepared->recovery[index]};
        if (recovery.key_index != index || recovery.mnemonic.empty()) {
            return util::Error{Untranslated("Recovery Vault preparation returned invalid software-key ordering")};
        }
        keys.push_back({index + 1, recovery.fingerprint, recovery.path, recovery.xpub,
                        strprintf("software-key-%u.txt", index + 1)});
        mnemonics.push_back(std::move(recovery.mnemonic));
    }
    const std::string manifest{ManifestText(summary, keys)};
    const std::string readme{ReadmeText(wallet_name, package.policy_id)};
    summary.kit_commitment = KitCommitment(manifest, readme, summary.canonical_policy, mnemonics);

    std::error_code code;
    if (!fs::create_directory(*resolved, code) || code) {
        return util::Error{Untranslated("Unable to create the new Recovery Kit directory")};
    }
    struct DirectoryCleanup {
        fs::path path;
        bool keep{false};
        ~DirectoryCleanup()
        {
            if (keep) return;
            std::error_code error;
            fs::remove_all(path, error);
        }
    } cleanup{*resolved};
    bilingual_str write_error;
    if (!SetPrivatePermissions(*resolved, /*directory=*/true, write_error) ||
        !WritePrivateFile(*resolved / fs::PathFromString(std::string{README_FILE}), readme, write_error) ||
        !WritePrivateFile(*resolved / fs::PathFromString(std::string{POLICY_FILE}), summary.canonical_policy, write_error)) {
        return util::Error{write_error};
    }
    for (size_t index = 0; index < keys.size(); ++index) {
        const SecureString& mnemonic{mnemonics[index]};
        if (!WritePrivateFile(
                *resolved / fs::PathFromString(keys[index].file),
                std::span<const char>{mnemonic.data(), mnemonic.size()}, write_error)) {
            return util::Error{write_error};
        }
    }
    if (!WritePrivateFile(*resolved / fs::PathFromString(std::string{MANIFEST_FILE}), manifest, write_error)) {
        return util::Error{write_error};
    }
    DirectoryCommit(*resolved);
    DirectoryCommit(resolved->parent_path());
    cleanup.keep = true;
    return summary;
}

util::Result<RecoveryVaultKitMaterial> ReadRecoveryVaultKit(
    const fs::path& target,
    const std::string& expected_kit_commitment,
    const std::string& expected_network,
    const fs::path& forbidden_root)
{
    if (expected_kit_commitment.size() != 64 || !IsHex(expected_kit_commitment)) {
        return util::Error{Untranslated("Expected Recovery Kit commitment must be 64 hexadecimal characters")};
    }
    auto resolved{ResolveKitPath(target, forbidden_root, /*must_exist=*/true)};
    if (!resolved) return util::Error{util::ErrorString(resolved)};
    bilingual_str permission_error;
    if (!PrivatePermissions(*resolved, /*directory=*/true, permission_error)) {
        return util::Error{permission_error};
    }
    auto manifest_text{ReadPublicFile(*resolved / fs::PathFromString(std::string{MANIFEST_FILE}))};
    if (!manifest_text) return util::Error{util::ErrorString(manifest_text)};
    auto parsed_manifest{ParseManifest(*manifest_text, *resolved)};
    if (!parsed_manifest) return util::Error{util::ErrorString(parsed_manifest)};
    RecoveryVaultKitSummary summary{std::move(parsed_manifest->first)};
    std::vector<KitKey> keys{std::move(parsed_manifest->second)};
    if (!ExactDirectoryEntries(*resolved, keys, permission_error)) {
        return util::Error{permission_error};
    }
    auto readme{ReadPublicFile(*resolved / fs::PathFromString(std::string{README_FILE}))};
    auto policy{ReadPublicFile(*resolved / fs::PathFromString(std::string{POLICY_FILE}))};
    if (!readme) return util::Error{util::ErrorString(readme)};
    if (!policy) return util::Error{util::ErrorString(policy)};
    summary.canonical_policy = *policy;

    auto package{ParseVaultPolicyPackage(*policy)};
    if (!package || FormatVaultPolicyPackage(*package) != *policy ||
        !ValidateFixedStagedVaultPolicy(*package) ||
        ClassifyFixedVaultSchedule(*package) != FixedVaultSchedule::CURRENT_90_180) {
        return util::Error{Untranslated("Recovery Kit does not contain one canonical current 90/180 fixed-vault policy")};
    }
    if (package->network != expected_network || summary.network != expected_network ||
        summary.policy_id != package->policy_id ||
        summary.policy_commitment != VaultPolicyCommitment(*package)) {
        return util::Error{Untranslated("Recovery Kit manifest does not match its policy or this node's network")};
    }
    if (*manifest_text != ManifestText(summary, keys) ||
        *readme != ReadmeText(summary.wallet_name, summary.policy_id)) {
        return util::Error{Untranslated("Recovery Kit public files are not in canonical form")};
    }

    RecoveryVaultKitMaterial material;
    material.summary = summary;
    material.mnemonics.reserve(keys.size());
    for (const KitKey& key : keys) {
        auto mnemonic{ReadMnemonicFile(*resolved / fs::PathFromString(key.file))};
        if (!mnemonic) return util::Error{util::ErrorString(mnemonic)};
        material.mnemonics.push_back(std::move(*mnemonic));
    }
    material.summary.kit_commitment = KitCommitment(*manifest_text, *readme, *policy, material.mnemonics);
    if (ToLower(expected_kit_commitment) != material.summary.kit_commitment) {
        return util::Error{Untranslated("Recovery Kit commitment does not match the prepared kit")};
    }
    auto matches{ValidateFixedVaultMnemonics(*package, material.mnemonics)};
    if (!matches || matches->size() != keys.size()) {
        return util::Error{matches ? Untranslated("Recovery Kit does not contain every software key") : util::ErrorString(matches)};
    }
    for (const VaultMnemonicMatch& match : *matches) {
        if (match.mnemonic_index >= keys.size()) {
            return util::Error{Untranslated("Recovery Kit phrase matching returned an invalid index")};
        }
        const KitKey& key{keys[match.mnemonic_index]};
        if (match.fingerprint != key.fingerprint || match.path != key.path || match.xpub != key.xpub) {
            return util::Error{Untranslated("Recovery Kit phrase does not match its recorded public identity")};
        }
    }
    return material;
}

} // namespace wallet
