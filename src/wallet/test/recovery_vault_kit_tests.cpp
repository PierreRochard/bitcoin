// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <wallet/multisig.h>
#include <wallet/recovery_vault_kit.h>

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <memory>
#include <set>
#include <string>
#include <system_error>

namespace wallet {
namespace {

using FilePtr = std::unique_ptr<FILE, decltype(&std::fclose)>;

void AppendByte(const fs::path& path)
{
    FilePtr file{fsbridge::fopen(path, "ab"), &std::fclose};
    BOOST_REQUIRE(file);
    BOOST_REQUIRE_EQUAL(std::fputc('x', file.get()), 'x');
    BOOST_REQUIRE(FileCommit(file.get()));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(recovery_vault_kit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(prepare_read_and_commitment_validation)
{
    const fs::path forbidden{m_path_root / "node-data"};
    const fs::path kit_path{m_path_root / "offline-kit"};
    BOOST_REQUIRE(fs::create_directory(forbidden));

    auto prepared{PrepareRecoveryVaultKit(
        kit_path, "RPC Recovery Vault", Params().GetChainTypeString(), forbidden)};
    BOOST_REQUIRE_MESSAGE(prepared, util::ErrorString(prepared).original);
    BOOST_CHECK_EQUAL(prepared->wallet_name, "RPC Recovery Vault");
    BOOST_CHECK_EQUAL(prepared->software_key_count, 3U);
    BOOST_CHECK_EQUAL(prepared->policy_commitment.size(), 64U);
    BOOST_CHECK_EQUAL(prepared->kit_commitment.size(), 64U);

    std::set<std::string> entries;
    for (const fs::directory_entry& entry : fs::directory_iterator(kit_path)) {
        entries.insert(fs::PathToString(entry.path().filename()));
    }
    BOOST_CHECK_EQUAL(entries.size(), 6U);
    BOOST_CHECK(entries.contains("README.txt"));
    BOOST_CHECK(entries.contains("manifest.json"));
    BOOST_CHECK(entries.contains("policy.json"));
    BOOST_CHECK(entries.contains("software-key-1.txt"));
    BOOST_CHECK(entries.contains("software-key-2.txt"));
    BOOST_CHECK(entries.contains("software-key-3.txt"));

    auto read{ReadRecoveryVaultKit(
        kit_path, prepared->kit_commitment, Params().GetChainTypeString(), forbidden)};
    BOOST_REQUIRE_MESSAGE(read, util::ErrorString(read).original);
    BOOST_CHECK_EQUAL(read->summary.policy_id, prepared->policy_id);
    BOOST_CHECK_EQUAL(read->summary.policy_commitment, prepared->policy_commitment);
    BOOST_CHECK_EQUAL(read->summary.kit_commitment, prepared->kit_commitment);
    BOOST_CHECK_EQUAL(read->mnemonics.size(), 3U);
    auto package{ParseVaultPolicyPackage(read->summary.canonical_policy)};
    BOOST_REQUIRE(package);
    BOOST_CHECK(ClassifyFixedVaultSchedule(*package) == FixedVaultSchedule::CURRENT_90_180);
    BOOST_REQUIRE(ValidateFixedVaultMnemonics(*package, read->mnemonics));

    const std::string wrong_commitment(64, '0');
    auto wrong{ReadRecoveryVaultKit(
        kit_path, wrong_commitment, Params().GetChainTypeString(), forbidden)};
    BOOST_CHECK(!wrong);
    BOOST_CHECK(util::ErrorString(wrong).original.find("commitment does not match") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(fail_closed_paths_permissions_and_tampering)
{
    const fs::path forbidden{m_path_root / "node-data"};
    BOOST_REQUIRE(fs::create_directory(forbidden));

    auto inside{PrepareRecoveryVaultKit(
        forbidden / "kit", "Inside", Params().GetChainTypeString(), forbidden)};
    BOOST_CHECK(!inside);
    BOOST_CHECK(util::ErrorString(inside).original.find("outside the Bitcoin data directory") != std::string::npos);

    const fs::path tampered_path{m_path_root / "tampered-kit"};
    auto prepared{PrepareRecoveryVaultKit(
        tampered_path, "Tampered", Params().GetChainTypeString(), forbidden)};
    BOOST_REQUIRE(prepared);
    AppendByte(tampered_path / "policy.json");
    auto tampered{ReadRecoveryVaultKit(
        tampered_path, prepared->kit_commitment, Params().GetChainTypeString(), forbidden)};
    BOOST_CHECK(!tampered);

    const fs::path unexpected_path{m_path_root / "unexpected-kit"};
    auto unexpected_prepared{PrepareRecoveryVaultKit(
        unexpected_path, "Unexpected", Params().GetChainTypeString(), forbidden)};
    BOOST_REQUIRE(unexpected_prepared);
    FilePtr unexpected_file{fsbridge::fopen(unexpected_path / "extra.txt", "wb"), &std::fclose};
    BOOST_REQUIRE(unexpected_file);
    BOOST_REQUIRE_EQUAL(std::fputc('x', unexpected_file.get()), 'x');
    BOOST_REQUIRE(FileCommit(unexpected_file.get()));
    unexpected_file.reset();
    auto unexpected{ReadRecoveryVaultKit(
        unexpected_path, unexpected_prepared->kit_commitment,
        Params().GetChainTypeString(), forbidden)};
    BOOST_CHECK(!unexpected);
    BOOST_CHECK(util::ErrorString(unexpected).original.find("unexpected") != std::string::npos);

#ifndef WIN32
    const fs::path public_path{m_path_root / "public-kit"};
    auto public_prepared{PrepareRecoveryVaultKit(
        public_path, "Public", Params().GetChainTypeString(), forbidden)};
    BOOST_REQUIRE(public_prepared);
    std::error_code code;
    fs::permissions(public_path / "software-key-1.txt", fs::perms::group_read, fs::perm_options::add, code);
    BOOST_REQUIRE(!code);
    auto public_read{ReadRecoveryVaultKit(
        public_path, public_prepared->kit_commitment,
        Params().GetChainTypeString(), forbidden)};
    BOOST_CHECK(!public_read);
    BOOST_CHECK(util::ErrorString(public_read).original.find("another user") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
