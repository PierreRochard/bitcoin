// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <support/allocators/secure.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/rbf.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/multisig.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(taproot_vault_send_tests, TestChain100Setup)

static constexpr CFeeRate FEE_RATE{10000}; // 10 sat/vB

static CExtKey RandomMaster()
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    return master;
}

static std::string PathStr()
{
    return DefaultMultisigPath(OutputType::BECH32M, /*account=*/0);
}

static std::vector<uint32_t> Bip48TaprootPath()
{
    std::vector<uint32_t> path;
    BOOST_REQUIRE(ParseHDKeypath(PathStr(), path));
    return path;
}

static std::string MasterFpr(const CExtKey& master)
{
    const std::string hex = HexStr(master.id_key_fingerprint());
    return hex.size() == 8 ? hex : hex.substr(0, 8);
}

static void AddUnused(CWallet& wallet, const CExtKey& master)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::string unused = "unused(" + EncodeExtKey(master) + ")";
    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(unused, keys, error, false);
    BOOST_REQUIRE_MESSAGE(!descs.empty(), error);
    WalletDescriptor w(std::move(descs.at(0)), 1, 0, 0, 0);
    BOOST_REQUIRE(wallet.AddWalletDescriptor(w, keys, "", false));
}

static MultisigKeySpec LocalSpec(const CExtKey& master)
{
    MultisigKeySpec spec;
    spec.hdkey = EncodeExtPubKey(master.Neuter());
    spec.path = PathStr();
    spec.label = "computer";
    return spec;
}

static MultisigKeySpec XpubSpec(const CExtKey& master)
{
    MultisigKeySpec spec;
    spec.fingerprint = MasterFpr(master);
    spec.path = PathStr();
    auto child = DeriveExtKey(master, Bip48TaprootPath());
    BOOST_REQUIRE(child);
    spec.xpub = EncodeExtPubKey(child->first.Neuter());
    spec.label = "lost-computer";
    return spec;
}

static std::shared_ptr<CWallet> MakeChainWallet(interfaces::Chain& chain, const std::string& name, uint64_t extra_flags = 0)
{
    auto wallet = std::make_shared<CWallet>(&chain, name, CreateMockableWalletDatabase());
    wallet->m_keypool_size = 8;
    wallet->m_default_address_type = OutputType::BECH32M;
    wallet->InitWalletFlags(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED | extra_flags);
    wallet->SetBroadcastTransactions(true);
    return wallet;
}

static void ScanWallet(CWallet& wallet, ChainstateManager& chainman)
{
    const uint256 genesis = WITH_LOCK(::cs_main, return chainman.ActiveChain().Genesis()->GetBlockHash());
    {
        LOCK2(wallet.cs_wallet, ::cs_main);
        wallet.SetLastBlockProcessed(chainman.ActiveChain().Height(), chainman.ActiveChain().Tip()->GetBlockHash());
    }
    WalletRescanReserver reserver(wallet);
    BOOST_REQUIRE(reserver.reserve());
    const auto result = wallet.ScanForWalletTransactions(genesis, /*start_height=*/0, /*max_height=*/{}, reserver, /*save_progress=*/false);
    BOOST_REQUIRE_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
}

static CTxDestination DummyTap()
{
    return WitnessV1Taproot{XOnlyPubKey(GenerateRandomKey().GetPubKey())};
}

struct VaultSend {
    std::shared_ptr<CWallet> full;
    std::shared_ptr<CWallet> recover;
    CScript spk;
    CTxDestination dest;
    std::vector<std::string> fingerprints;
};

static std::string UnrelatedFingerprint(const std::vector<std::string>& fingerprints)
{
    for (const std::string& candidate : {"00000000", "11111111", "22222222", "ffffffff"}) {
        if (std::find(fingerprints.begin(), fingerprints.end(), candidate) == fingerprints.end()) return candidate;
    }
    BOOST_FAIL("three policy participants cannot exhaust four candidate fingerprints");
    return {};
}

static VaultSend MakeFundedVault(TestChain100Setup& test, int m, int n, std::optional<uint32_t> older, const std::set<int>& recover_priv, CAmount amount, size_t coinbase_index, std::optional<uint32_t> after = {}, std::optional<uint32_t> fallback_older_one_key = {})
{
    BOOST_REQUIRE(n >= 2);
    BOOST_REQUIRE(coinbase_index < test.m_coinbase_txns.size());
    std::vector<CExtKey> masters;
    for (int i = 0; i < n; ++i) masters.push_back(RandomMaster());

    VaultSend out;
    for (const CExtKey& master : masters) out.fingerprints.push_back(MasterFpr(master));
    out.full = MakeChainWallet(*test.m_node.chain, strprintf("vault_full_%d", coinbase_index));
    out.recover = MakeChainWallet(*test.m_node.chain, strprintf("vault_rec_%d", coinbase_index));

    std::vector<MultisigKeySpec> full_specs, rec_specs;
    {
        LOCK(out.full->cs_wallet);
        for (int i = 0; i < n; ++i) {
            AddUnused(*out.full, masters[i]);
            full_specs.push_back(LocalSpec(masters[i]));
        }
        auto created = CreateMultisigDescriptor(*out.full, m, full_specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, older, after, fallback_older_one_key});
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        out.dest = *Assert(out.full->GetNewDestination(OutputType::BECH32M, ""));
        out.spk = GetScriptForDestination(out.dest);
    }
    {
        LOCK(out.recover->cs_wallet);
        for (int i = 0; i < n; ++i) {
            if (recover_priv.count(i)) {
                AddUnused(*out.recover, masters[i]);
                rec_specs.push_back(LocalSpec(masters[i]));
            } else {
                rec_specs.push_back(XpubSpec(masters[i]));
            }
        }
        auto created = CreateMultisigDescriptor(*out.recover, m, rec_specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, older, after, fallback_older_one_key});
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        BOOST_CHECK(GetScriptForDestination(*Assert(out.recover->GetNewDestination(OutputType::BECH32M, ""))) == out.spk);
    }

    const int input_height = static_cast<int>(coinbase_index) + 1;
    CMutableTransaction fund = test.CreateValidMempoolTransaction(
        test.m_coinbase_txns.at(coinbase_index), /*input_vout=*/0, input_height, test.coinbaseKey,
        out.spk, amount, /*submit=*/false);
    test.CreateAndProcessBlock({fund}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    ScanWallet(*out.full, *Assert(test.m_node.chainman));
    ScanWallet(*out.recover, *Assert(test.m_node.chainman));
    BOOST_REQUIRE_GE(WITH_LOCK(out.full->cs_wallet, return AvailableCoins(*out.full).GetTotalAmount()), amount);
    return out;
}

static CCoinControl FeeCC(std::optional<uint32_t> sequence = std::nullopt)
{
    CCoinControl cc;
    cc.m_feerate = FEE_RATE;
    cc.fOverrideFeeRate = true;
    cc.m_change_type = OutputType::BECH32M;
    cc.m_signal_bip125_rbf = true;
    cc.m_nSequence = sequence;
    return cc;
}

static util::Result<CreatedTransactionResult> SendFrom(CWallet& wallet, CAmount amount, const CCoinControl& cc, bool sign = true)
{
    std::vector<CRecipient> rec{{DummyTap(), amount, /*fSubtractFeeFromAmount=*/false}};
    return CreateTransaction(wallet, rec, /*change_pos=*/std::nullopt, cc, sign);
}

BOOST_AUTO_TEST_CASE(vault_create_transaction_keypath_and_recovery)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);

    auto keypath = SendFrom(*vault.full, 1 * COIN, FeeCC());
    BOOST_REQUIRE_MESSAGE(keypath, util::ErrorString(keypath).original);
    BOOST_REQUIRE_EQUAL(keypath->tx->vin.size(), 1U);
    BOOST_CHECK_EQUAL(keypath->tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
    BOOST_CHECK_EQUAL(keypath->tx->vin[0].scriptWitness.stack.size(), 1U);
    const int64_t keypath_vsize = GetVirtualTransactionSize(*keypath->tx);
    BOOST_CHECK_LT(keypath_vsize, 180);
    BOOST_CHECK_GT(keypath->fee, 0);

    auto recover = SendFrom(*vault.full, 1 * COIN, FeeCC(/*sequence=*/1));
    BOOST_REQUIRE_MESSAGE(recover, util::ErrorString(recover).original);
    BOOST_REQUIRE_EQUAL(recover->tx->vin.size(), 1U);
    BOOST_CHECK_EQUAL(recover->tx->vin[0].nSequence, 1U);
    BOOST_CHECK_GT(recover->tx->vin[0].scriptWitness.stack.size(), 1U);
    const int64_t recover_vsize = GetVirtualTransactionSize(*recover->tx);
    BOOST_CHECK_GT(recover_vsize, 180);
    BOOST_CHECK_GT(recover_vsize, keypath_vsize);
    BOOST_CHECK_GT(recover->fee, keypath->fee);
}

BOOST_AUTO_TEST_CASE(vault_keypath_can_be_bumped)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);

    auto keypath = SendFrom(*vault.full, 1 * COIN, FeeCC());
    BOOST_REQUIRE_MESSAGE(keypath, util::ErrorString(keypath).original);
    vault.full->CommitTransaction(keypath->tx);
    const Txid txid = keypath->tx->GetHash();
    BOOST_CHECK(feebumper::TransactionCanBeBumped(*vault.full, txid));

    CCoinControl bump_cc;
    bump_cc.m_feerate = CFeeRate(50000);
    bump_cc.fOverrideFeeRate = true;
    bump_cc.m_signal_bip125_rbf = true;
    std::vector<bilingual_str> errors;
    CAmount old_fee{0}, new_fee{0};
    CMutableTransaction mtx;
    BOOST_REQUIRE(feebumper::CreateRateBumpTransaction(*vault.full, txid, bump_cc, errors, old_fee, new_fee, mtx, /*require_mine=*/true, /*outputs=*/{}) ==
                  feebumper::Result::OK);
    BOOST_CHECK_GT(new_fee, old_fee);
    BOOST_REQUIRE_MESSAGE(feebumper::SignTransaction(*vault.full, mtx), "bump SignTransaction");
    Txid bumped;
    errors.clear();
    BOOST_REQUIRE(feebumper::CommitTransaction(*vault.full, txid, std::move(mtx), errors, bumped) == feebumper::Result::OK);
    BOOST_CHECK(bumped != txid);
    BOOST_CHECK(!feebumper::TransactionCanBeBumped(*vault.full, txid));
}

BOOST_AUTO_TEST_CASE(vault_recovery_too_early_create_transaction)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);

    auto too_soon = SendFrom(*vault.recover, 1 * COIN, FeeCC());
    BOOST_CHECK_MESSAGE(!too_soon, "CreateTransaction key-path with missing keys should not finalize");
    if (!too_soon) {
        BOOST_CHECK(util::ErrorString(too_soon).original.find("Signing") != std::string::npos);
    }

    auto ready = SendFrom(*vault.recover, 1 * COIN, FeeCC(/*sequence=*/1));
    BOOST_REQUIRE_MESSAGE(ready, util::ErrorString(ready).original);
    BOOST_CHECK_EQUAL(ready->tx->vin[0].nSequence, 1U);
    BOOST_CHECK_GT(ready->tx->vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(nums_create_transaction_uses_script_path_fee)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/1, /*n=*/2, /*older=*/std::nullopt, {0, 1}, 10 * COIN, /*coinbase_index=*/0);

    auto sent = SendFrom(*vault.full, 1 * COIN, FeeCC());
    BOOST_REQUIRE_MESSAGE(sent, util::ErrorString(sent).original);
    BOOST_CHECK_EQUAL(sent->tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
    BOOST_CHECK_GT(sent->tx->vin[0].scriptWitness.stack.size(), 1U);
    const int64_t vsize = GetVirtualTransactionSize(*sent->tx);
    BOOST_CHECK_GT(vsize, 120);
    BOOST_CHECK_GT(sent->fee, FEE_RATE.GetFee(111));
}

BOOST_AUTO_TEST_CASE(vault_older_144_create_transaction)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/144, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    auto rec = SendFrom(*vault.full, 1 * COIN, FeeCC(/*sequence=*/144));
    BOOST_REQUIRE_MESSAGE(rec, util::ErrorString(rec).original);
    BOOST_CHECK_EQUAL(rec->tx->vin[0].nSequence, 144U);
    BOOST_CHECK_GT(rec->tx->vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_older_2_bip68_mempool)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/2, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    auto rec = SendFrom(*vault.recover, 1 * COIN, FeeCC(/*sequence=*/2));
    BOOST_REQUIRE_MESSAGE(rec, util::ErrorString(rec).original);
    BOOST_CHECK_EQUAL(rec->tx->vin[0].nSequence, 2U);
    {
        LOCK(cs_main);
        const auto too_soon = m_node.chainman->ProcessTransaction(rec->tx);
        BOOST_CHECK(too_soon.m_result_type != MempoolAcceptResult::ResultType::VALID);
    }
    mineBlocks(1);
    {
        LOCK(cs_main);
        const auto ready = m_node.chainman->ProcessTransaction(rec->tx);
        BOOST_CHECK(ready.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
}

BOOST_AUTO_TEST_CASE(vault_recovery_path_can_be_bumped)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    auto rec = SendFrom(*vault.recover, 1 * COIN, FeeCC(/*sequence=*/1));
    BOOST_REQUIRE_MESSAGE(rec, util::ErrorString(rec).original);
    vault.recover->CommitTransaction(rec->tx);
    const Txid txid = rec->tx->GetHash();
    BOOST_CHECK(feebumper::TransactionCanBeBumped(*vault.recover, txid));

    CCoinControl bump_cc;
    bump_cc.m_feerate = CFeeRate(50000);
    bump_cc.fOverrideFeeRate = true;
    std::vector<bilingual_str> errors;
    CAmount old_fee{0}, new_fee{0};
    CMutableTransaction mtx;
    BOOST_REQUIRE(feebumper::CreateRateBumpTransaction(*vault.recover, txid, bump_cc, errors, old_fee, new_fee, mtx, /*require_mine=*/true, /*outputs=*/{}) ==
                  feebumper::Result::OK);
    BOOST_CHECK_EQUAL(mtx.vin[0].nSequence, 1U);
    BOOST_CHECK_GT(new_fee, old_fee);
    BOOST_REQUIRE(feebumper::SignTransaction(*vault.recover, mtx));
    Txid bumped;
    BOOST_REQUIRE(feebumper::CommitTransaction(*vault.recover, txid, std::move(mtx), errors, bumped) == feebumper::Result::OK);
    BOOST_CHECK(bumped != txid);
}

BOOST_AUTO_TEST_CASE(vault_encrypted_create_transaction)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    SecureString pass;
    pass.reserve(100);
    pass = "testpass";
    BOOST_REQUIRE(vault.full->EncryptWallet(pass));
    BOOST_CHECK(vault.full->IsLocked());
    BOOST_CHECK(!SendFrom(*vault.full, 1 * COIN, FeeCC()));
    BOOST_REQUIRE(vault.full->Unlock(pass));
    auto sent = SendFrom(*vault.full, 1 * COIN, FeeCC());
    BOOST_REQUIRE_MESSAGE(sent, util::ErrorString(sent).original);
    BOOST_CHECK_EQUAL(sent->tx->vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_preset_input_keeps_recovery_sequence)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    COutPoint op;
    {
        LOCK(vault.full->cs_wallet);
        const auto coins = AvailableCoins(*vault.full);
        BOOST_REQUIRE(!coins.All().empty());
        op = coins.All()[0].outpoint;
    }
    CCoinControl cc = FeeCC();
    cc.Select(op).SetSequence(1);
    cc.m_allow_other_inputs = false;
    auto rec = SendFrom(*vault.full, 1 * COIN, cc);
    BOOST_REQUIRE_MESSAGE(rec, util::ErrorString(rec).original);
    BOOST_REQUIRE_EQUAL(rec->tx->vin.size(), 1U);
    BOOST_CHECK_EQUAL(rec->tx->vin[0].nSequence, 1U);
    BOOST_CHECK_GT(rec->tx->vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_create_transaction_two_recipients)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    std::vector<CRecipient> recips{{DummyTap(), 1 * COIN, false}, {DummyTap(), 1 * COIN, false}};
    auto sent = CreateTransaction(*vault.full, recips, /*change_pos=*/std::nullopt, FeeCC());
    BOOST_REQUIRE_MESSAGE(sent, util::ErrorString(sent).original);
    BOOST_CHECK_GE(sent->tx->vout.size(), 2U);
    BOOST_CHECK_EQUAL(sent->tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
    BOOST_CHECK_EQUAL(sent->tx->vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_max_satisfaction_weight_keypath_vs_script)
{
    auto wallet = MakeChainWallet(*m_node.chain, "sat_weight");
    std::vector<CExtKey> masters{RandomMaster(), RandomMaster(), RandomMaster()};
    std::vector<MultisigKeySpec> specs;
    {
        LOCK(wallet->cs_wallet);
        for (const auto& master : masters) {
            AddUnused(*wallet, master);
            specs.push_back(LocalSpec(master));
        }
        auto created = CreateMultisigDescriptor(*wallet, /*nrequired=*/2, specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, /*fallback_older=*/1});
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(created->descs.at(0), keys, error, /*require_checksum=*/false);
        BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
        const auto keypath = parsed[0]->MaxSatisfactionWeight(/*use_max_sig=*/true);
        const auto scriptpath = parsed[0]->MaxSatisfactionWeight(/*use_max_sig=*/true, /*script_path=*/true);
        BOOST_REQUIRE(keypath);
        BOOST_REQUIRE(scriptpath);
        BOOST_CHECK_EQUAL(*keypath, 1 + 65);
        BOOST_CHECK_GT(*scriptpath, *keypath);
        BOOST_CHECK_EQUAL(*parsed[0]->MaxSatisfactionElems(), 1);
        BOOST_CHECK_GT(*parsed[0]->MaxSatisfactionElems(/*script_path=*/true), 1);
    }
}

BOOST_AUTO_TEST_CASE(vault_input_size_uses_recovery_sequence)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    const CTxOut txout{10 * COIN, vault.spk};
    const int keypath = CalculateMaximumSignedInputSize(txout, vault.full.get(), /*coin_control=*/nullptr);
    CCoinControl rec_cc;
    rec_cc.m_nSequence = 1;
    const int scriptpath = CalculateMaximumSignedInputSize(txout, vault.full.get(), &rec_cc);
    BOOST_CHECK_GT(keypath, 0);
    BOOST_CHECK_GT(scriptpath, keypath);

    COutPoint op;
    {
        LOCK(vault.full->cs_wallet);
        const auto coins = AvailableCoins(*vault.full);
        BOOST_REQUIRE(!coins.All().empty());
        op = coins.All()[0].outpoint;
    }
    const auto provider = vault.full->GetSolvingProvider(vault.spk);
    BOOST_REQUIRE(provider);
    CCoinControl preset;
    preset.Select(op).SetSequence(1);
    const int preset_sz = CalculateMaximumSignedInputSize(txout, op, provider.get(), /*can_grind_r=*/true, &preset);
    BOOST_CHECK_EQUAL(preset_sz, scriptpath);
}

BOOST_AUTO_TEST_CASE(vault_produce_signature_cannot_finish_musig2)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    auto unsigned_tx = SendFrom(*vault.full, 1 * COIN, FeeCC(), /*sign=*/false);
    BOOST_REQUIRE_MESSAGE(unsigned_tx, util::ErrorString(unsigned_tx).original);
    CMutableTransaction mtx{*unsigned_tx->tx};
    std::map<COutPoint, Coin> coins;
    for (const auto& in : mtx.vin) coins[in.prevout];
    vault.full->chain().findCoins(coins);
    std::map<int, bilingual_str> errors;
    BOOST_CHECK_MESSAGE(!vault.full->SignTransaction(mtx, coins, SIGHASH_DEFAULT, errors),
                        "ProduceSignature (4-arg SignTransaction) must not finish tr(musig)");
    {
        LOCK(vault.full->cs_wallet);
        BOOST_REQUIRE_MESSAGE(vault.full->SignTransaction(mtx), "FillPSBTLocked SignTransaction finishes MuSig2");
    }
    BOOST_CHECK_EQUAL(mtx.vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_encrypted_recovery)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    SecureString pass;
    pass.reserve(100);
    pass = "testpass";
    BOOST_REQUIRE(vault.full->EncryptWallet(pass));
    BOOST_CHECK(vault.full->IsLocked());
    BOOST_CHECK(!SendFrom(*vault.full, 1 * COIN, FeeCC(/*sequence=*/1)));
    BOOST_REQUIRE(vault.full->Unlock(pass));
    auto rec = SendFrom(*vault.full, 1 * COIN, FeeCC(/*sequence=*/1));
    BOOST_REQUIRE_MESSAGE(rec, util::ErrorString(rec).original);
    BOOST_CHECK_EQUAL(rec->tx->vin[0].nSequence, 1U);
    BOOST_CHECK_GT(rec->tx->vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_multi_input_create_transaction)
{
    mineBlocks(2);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    CMutableTransaction fund2 = CreateValidMempoolTransaction(
        m_coinbase_txns.at(1), /*input_vout=*/0, /*input_height=*/2, coinbaseKey,
        vault.spk, 10 * COIN, /*submit=*/false);
    CreateAndProcessBlock({fund2}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    ScanWallet(*vault.full, *Assert(m_node.chainman));
    auto sent = SendFrom(*vault.full, 15 * COIN, FeeCC());
    BOOST_REQUIRE_MESSAGE(sent, util::ErrorString(sent).original);
    BOOST_CHECK_EQUAL(sent->tx->vin.size(), 2U);
    BOOST_CHECK_EQUAL(sent->tx->vin[0].scriptWitness.stack.size(), 1U);
    BOOST_CHECK_EQUAL(sent->tx->vin[1].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_nums_can_be_bumped)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/1, /*n=*/2, /*older=*/std::nullopt, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    auto sent = SendFrom(*vault.full, 1 * COIN, FeeCC());
    BOOST_REQUIRE_MESSAGE(sent, util::ErrorString(sent).original);
    vault.full->CommitTransaction(sent->tx);
    const Txid txid = sent->tx->GetHash();
    BOOST_CHECK(feebumper::TransactionCanBeBumped(*vault.full, txid));
    CCoinControl bump_cc;
    bump_cc.m_feerate = CFeeRate(50000);
    bump_cc.fOverrideFeeRate = true;
    bump_cc.m_signal_bip125_rbf = true;
    std::vector<bilingual_str> errors;
    CAmount old_fee{0}, new_fee{0};
    CMutableTransaction mtx;
    BOOST_REQUIRE(feebumper::CreateRateBumpTransaction(*vault.full, txid, bump_cc, errors, old_fee, new_fee, mtx, /*require_mine=*/true, /*outputs=*/{}) ==
                  feebumper::Result::OK);
    BOOST_CHECK_GT(new_fee, old_fee);
    BOOST_REQUIRE(feebumper::SignTransaction(*vault.full, mtx));
    Txid bumped;
    BOOST_REQUIRE(feebumper::CommitTransaction(*vault.full, txid, std::move(mtx), errors, bumped) == feebumper::Result::OK);
    BOOST_CHECK(bumped != txid);
}

BOOST_AUTO_TEST_CASE(vault_recovery_skips_immature_coins)
{
    mineBlocks(2);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/2, {0, 1}, 5 * COIN, /*coinbase_index=*/0);
    CMutableTransaction fund2 = CreateValidMempoolTransaction(
        m_coinbase_txns.at(1), 0, /*input_height=*/2, coinbaseKey, vault.spk, 5 * COIN, /*submit=*/false);
    CreateAndProcessBlock({fund2}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    ScanWallet(*vault.full, *Assert(m_node.chainman));
    CCoinControl rec = FeeCC(/*sequence=*/2);
    rec.m_min_depth = 2;
    rec.m_script_path = true;
    auto too_big = SendFrom(*vault.full, 8 * COIN, rec, /*sign=*/false);
    BOOST_CHECK_MESSAGE(!too_big, "immature UTXO must not be selected for older(2) recovery");
    auto mature_only = SendFrom(*vault.full, 1 * COIN, rec);
    BOOST_REQUIRE_MESSAGE(mature_only, util::ErrorString(mature_only).original);
    BOOST_CHECK_EQUAL(mature_only->tx->vin.size(), 1U);
    BOOST_CHECK_EQUAL(mature_only->tx->vin[0].nSequence, 2U);
}

BOOST_AUTO_TEST_CASE(vault_lost_signer_zeroes_immediate)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    {
        LOCK(vault.full->cs_wallet);
        const auto baseline = GetVaultBalanceBreakdown(*vault.full);
        BOOST_CHECK(baseline.is_vault);
        BOOST_CHECK_GT(baseline.immediate, 0);

        const std::string unrelated{UnrelatedFingerprint(vault.fingerprints)};
        BOOST_REQUIRE(vault.full->SetLostSigner(unrelated, true));
        const auto unrelated_lost = GetVaultBalanceBreakdown(*vault.full);
        BOOST_CHECK_EQUAL(unrelated_lost.immediate, baseline.immediate);
        BOOST_REQUIRE_EQUAL(unrelated_lost.recovery_stages.size(), baseline.recovery_stages.size());
        for (size_t index = 0; index < baseline.recovery_stages.size(); ++index) {
            BOOST_CHECK_EQUAL(unrelated_lost.recovery_stages[index].recoverable_now,
                              baseline.recovery_stages[index].recoverable_now);
            BOOST_CHECK_EQUAL(unrelated_lost.recovery_stages[index].awaiting,
                              baseline.recovery_stages[index].awaiting);
        }
        BOOST_REQUIRE(vault.full->SetLostSigner(unrelated, false));

        BOOST_REQUIRE(vault.full->SetLostSigner(vault.fingerprints.front(), true));
        const auto br = GetVaultBalanceBreakdown(*vault.full);
        BOOST_CHECK_EQUAL(br.immediate, 0);
        BOOST_CHECK_GT(br.recoverable_now, 0);
    }
}

BOOST_AUTO_TEST_CASE(vault_after_script_path_size)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    const CTxOut txout{10 * COIN, vault.spk};
    const int keypath = CalculateMaximumSignedInputSize(txout, vault.full.get(), /*coin_control=*/nullptr);
    CCoinControl rec;
    rec.m_script_path = true;
    rec.m_locktime = 500;
    const int scriptpath = CalculateMaximumSignedInputSize(txout, vault.full.get(), &rec);
    BOOST_CHECK_GT(keypath, 0);
    BOOST_CHECK_GT(scriptpath, keypath);
}

BOOST_AUTO_TEST_CASE(vault_after_create_transaction)
{
    mineBlocks(1);
    const int tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height());
    const uint32_t after_h = static_cast<uint32_t>(tip + 2);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/{}, {0, 1}, 10 * COIN, /*coinbase_index=*/0, after_h);
    CCoinControl too_early = FeeCC();
    {
        LOCK(vault.full->cs_wallet);
        BOOST_REQUIRE(ApplyVaultRecoveryToCoinControl(*vault.full, too_early));
        const auto br = GetVaultBalanceBreakdown(*vault.full);
        BOOST_CHECK(br.is_vault);
        BOOST_CHECK(*br.policy.after == after_h);
        BOOST_CHECK_GT(br.awaiting, 0);
        BOOST_REQUIRE(br.earliest_blocks_remaining);
        BOOST_CHECK_GT(*br.earliest_blocks_remaining, 0);
    }
    BOOST_CHECK_EQUAL(too_early.m_min_depth, std::numeric_limits<int>::max());
    BOOST_REQUIRE(too_early.m_locktime);
    BOOST_CHECK_EQUAL(*too_early.m_locktime, after_h);
    auto blocked = SendFrom(*vault.full, 1 * COIN, too_early, /*sign=*/false);
    BOOST_CHECK_MESSAGE(!blocked, "after() recovery before the height must fail");
    if (!blocked) {
        const std::string err = util::ErrorString(blocked).original;
        BOOST_CHECK(err.find("Insufficient") != std::string::npos || err.find("not yet recoverable") != std::string::npos);
    }

    mineBlocks(2);
    ScanWallet(*vault.full, *Assert(m_node.chainman));
    CCoinControl rec = FeeCC();
    {
        LOCK(vault.full->cs_wallet);
        BOOST_REQUIRE(ApplyVaultRecoveryToCoinControl(*vault.full, rec));
    }
    BOOST_CHECK_NE(rec.m_min_depth, std::numeric_limits<int>::max());
    BOOST_CHECK_EQUAL(rec.m_min_depth, DEFAULT_MIN_DEPTH);
    auto sent = SendFrom(*vault.full, 1 * COIN, rec);
    BOOST_REQUIRE_MESSAGE(sent, util::ErrorString(sent).original);
    BOOST_CHECK_EQUAL(sent->tx->nLockTime, after_h);
    BOOST_CHECK_EQUAL(sent->tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
    BOOST_CHECK_GT(sent->tx->vin[0].scriptWitness.stack.size(), 1U);
    {
        LOCK(vault.full->cs_wallet);
        const auto br = GetVaultBalanceBreakdown(*vault.full);
        BOOST_CHECK_EQUAL(br.awaiting, 0);
        BOOST_CHECK_GT(br.recoverable_now, 0);
        BOOST_CHECK(!br.earliest_blocks_remaining);
    }
}

BOOST_AUTO_TEST_CASE(vault_unconfirmed_excluded_from_breakdown)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    auto sent = SendFrom(*vault.full, 1 * COIN, FeeCC());
    BOOST_REQUIRE_MESSAGE(sent, util::ErrorString(sent).original);
    vault.full->CommitTransaction(sent->tx);
    LOCK(vault.full->cs_wallet);
    const auto br = GetVaultBalanceBreakdown(*vault.full);
    BOOST_CHECK_EQUAL(br.immediate, 0);
    BOOST_CHECK_EQUAL(br.recoverable_now, 0);
    BOOST_CHECK_EQUAL(br.awaiting, 0);
}

BOOST_AUTO_TEST_CASE(vault_subtract_fee_from_amount)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    std::vector<CRecipient> rec{{DummyTap(), 1 * COIN, /*fSubtractFeeFromAmount=*/true}};
    auto sent = CreateTransaction(*vault.full, rec, /*change_pos=*/std::nullopt, FeeCC());
    BOOST_REQUIRE_MESSAGE(sent, util::ErrorString(sent).original);
    BOOST_CHECK_EQUAL(sent->tx->vin[0].scriptWitness.stack.size(), 1U);
    CAmount paid{0};
    for (const auto& out : sent->tx->vout) {
        if (out.nValue <= 1 * COIN) paid = out.nValue;
    }
    BOOST_CHECK_GT(paid, 0);
    BOOST_CHECK_LT(paid, 1 * COIN);
}

BOOST_AUTO_TEST_CASE(vault_preset_immature_sequence_rejected)
{
    mineBlocks(2);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/2, {0, 1}, 5 * COIN, /*coinbase_index=*/0);
    CMutableTransaction fund2 = CreateValidMempoolTransaction(
        m_coinbase_txns.at(1), 0, /*input_height=*/2, coinbaseKey, vault.spk, 5 * COIN, /*submit=*/false);
    CreateAndProcessBlock({fund2}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    ScanWallet(*vault.full, *Assert(m_node.chainman));
    COutPoint young;
    {
        LOCK(vault.full->cs_wallet);
        auto coins = AvailableCoins(*vault.full).All();
        BOOST_REQUIRE_EQUAL(coins.size(), 2U);
        std::sort(coins.begin(), coins.end(), [](const COutput& a, const COutput& b) { return a.depth < b.depth; });
        BOOST_CHECK_EQUAL(coins.front().depth, 1);
        BOOST_CHECK_EQUAL(coins.back().depth, 2);
        young = coins.front().outpoint;
        auto br = GetVaultBalanceBreakdown(*vault.full);
        BOOST_CHECK(br.is_vault);
        BOOST_CHECK_GT(br.recoverable_now, 0);
        BOOST_CHECK_GT(br.awaiting, 0);
        BOOST_REQUIRE(br.earliest_blocks_remaining);
        BOOST_CHECK_EQUAL(*br.earliest_blocks_remaining, 1);
        const std::string desc_before = ExportWalletVaultPolicy(*vault.full).descs.front();
        BOOST_REQUIRE(vault.full->SetLostSigner(vault.fingerprints.front(), true));
        BOOST_CHECK_EQUAL(GetVaultBalanceBreakdown(*vault.full).immediate, 0);
        BOOST_CHECK_EQUAL(ExportWalletVaultPolicy(*vault.full).descs.front(), desc_before);
        BOOST_REQUIRE(vault.full->SetLostSigner(vault.fingerprints.front(), false));
        BOOST_CHECK_GT(GetVaultBalanceBreakdown(*vault.full).immediate, 0);
    }
    CCoinControl cc = FeeCC();
    cc.Select(young).SetSequence(2);
    cc.m_allow_other_inputs = false;
    auto blocked = SendFrom(*vault.full, 1 * COIN, cc, /*sign=*/false);
    BOOST_CHECK_MESSAGE(!blocked, "preset immature older() input must be rejected");
    if (!blocked) {
        BOOST_CHECK(util::ErrorString(blocked).original.find("not yet recoverable") != std::string::npos);
    }
    CCoinControl rbf = FeeCC();
    rbf.Select(young).SetSequence(CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG | 2);
    rbf.m_allow_other_inputs = false;
    auto allowed = SendFrom(*vault.full, 1 * COIN, rbf, /*sign=*/false);
    BOOST_CHECK_MESSAGE(allowed, "nSequence with the disable flag is not a BIP68 recovery lock");
}

BOOST_AUTO_TEST_CASE(vault_after_preset_locktime_rejected)
{
    mineBlocks(1);
    const int tip = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height());
    const uint32_t after_h = static_cast<uint32_t>(tip + 20);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/{}, {0, 1}, 10 * COIN, /*coinbase_index=*/0, after_h);
    COutPoint op;
    {
        LOCK(vault.full->cs_wallet);
        const auto coins = AvailableCoins(*vault.full);
        BOOST_REQUIRE(!coins.All().empty());
        op = coins.All()[0].outpoint;
    }
    CCoinControl cc = FeeCC();
    cc.Select(op);
    cc.m_allow_other_inputs = false;
    cc.m_script_path = true;
    cc.m_locktime = after_h;
    auto blocked = SendFrom(*vault.full, 1 * COIN, cc, /*sign=*/false);
    BOOST_CHECK_MESSAGE(!blocked, "preset after() input before the height must be rejected");
}

BOOST_AUTO_TEST_CASE(vault_recovery_only_cannot_keypath)
{
    mineBlocks(1);
    std::vector<CExtKey> masters{RandomMaster(), RandomMaster(), RandomMaster()};
    auto full = MakeChainWallet(*m_node.chain, "heir_full");
    auto recover = MakeChainWallet(*m_node.chain, "heir_rec");
    CScript spk;
    {
        LOCK(full->cs_wallet);
        std::vector<MultisigKeySpec> specs;
        for (int i = 0; i < 3; ++i) {
            AddUnused(*full, masters[i]);
            auto spec = LocalSpec(masters[i]);
            if (i == 2) spec.recovery_only = true;
            specs.push_back(spec);
        }
        auto created = CreateMultisigDescriptor(*full, /*nrequired=*/1, specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, /*fallback_older=*/1});
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        spk = GetScriptForDestination(*Assert(full->GetNewDestination(OutputType::BECH32M, "")));
    }
    {
        LOCK(recover->cs_wallet);
        std::vector<MultisigKeySpec> specs;
        AddUnused(*recover, masters[0]);
        specs.push_back(LocalSpec(masters[0]));
        specs.push_back(XpubSpec(masters[1]));
        AddUnused(*recover, masters[2]);
        auto heir = LocalSpec(masters[2]);
        heir.recovery_only = true;
        specs.push_back(heir);
        auto created = CreateMultisigDescriptor(*recover, 1, specs,
                                                MultisigOptions{OutputType::BECH32M, 0, {}, 1});
        BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
        BOOST_CHECK(GetScriptForDestination(*Assert(recover->GetNewDestination(OutputType::BECH32M, ""))) == spk);
    }
    CMutableTransaction fund = CreateValidMempoolTransaction(
        m_coinbase_txns.at(0), 0, /*input_height=*/1, coinbaseKey, spk, 10 * COIN, /*submit=*/false);
    CreateAndProcessBlock({fund}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    ScanWallet(*full, *Assert(m_node.chainman));
    ScanWallet(*recover, *Assert(m_node.chainman));

    auto keypath_full = SendFrom(*full, 1 * COIN, FeeCC());
    BOOST_REQUIRE_MESSAGE(keypath_full, util::ErrorString(keypath_full).original);
    BOOST_CHECK_EQUAL(keypath_full->tx->vin[0].scriptWitness.stack.size(), 1U);

    auto keypath_rec = SendFrom(*recover, 1 * COIN, FeeCC());
    BOOST_CHECK_MESSAGE(!keypath_rec, "one active key plus a recovery-only key cannot finish MuSig2");

    auto rec = SendFrom(*recover, 1 * COIN, FeeCC(/*sequence=*/1));
    BOOST_REQUIRE_MESSAGE(rec, util::ErrorString(rec).original);
    BOOST_CHECK_EQUAL(rec->tx->vin[0].nSequence, 1U);
    BOOST_CHECK_GT(rec->tx->vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_apply_recovery_relative)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/2, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    CCoinControl cc = FeeCC();
    {
        LOCK(vault.full->cs_wallet);
        BOOST_REQUIRE(ApplyVaultRecoveryToCoinControl(*vault.full, cc));
    }
    BOOST_REQUIRE(cc.m_nSequence);
    BOOST_CHECK_EQUAL(*cc.m_nSequence, 2U);
    BOOST_CHECK_EQUAL(cc.m_min_depth, 2);
    BOOST_CHECK(cc.m_script_path);
}

BOOST_AUTO_TEST_CASE(vault_two_stage_balances_and_one_key_send)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/2, /*recover_priv=*/{0},
                                 10 * COIN, /*coinbase_index=*/0, /*after=*/{}, /*fallback_older_one_key=*/4);
    {
        LOCK(vault.full->cs_wallet);
        BOOST_REQUIRE(vault.full->SetLostSigner(vault.fingerprints[2], true));
        const auto br = GetVaultBalanceBreakdown(*vault.full);
        BOOST_REQUIRE_EQUAL(br.recovery_stages.size(), 2U);
        BOOST_CHECK_EQUAL(br.recovery_stages[0].stage.nrequired, 2);
        BOOST_CHECK_EQUAL(br.recovery_stages[1].stage.nrequired, 1);
        BOOST_CHECK_GT(br.recovery_stages[0].awaiting, 0);
        BOOST_CHECK_GT(br.recovery_stages[1].awaiting, 0);
    }
    {
        LOCK(vault.recover->cs_wallet);
        BOOST_REQUIRE(vault.recover->SetLostSigner(vault.fingerprints[1], true));
        BOOST_REQUIRE(vault.recover->SetLostSigner(vault.fingerprints[2], true));
        const auto br = GetVaultBalanceBreakdown(*vault.recover);
        BOOST_REQUIRE_EQUAL(br.recovery_stages.size(), 2U);
        BOOST_CHECK_EQUAL(br.recovery_stages[0].recoverable_now, 0);
        BOOST_CHECK_EQUAL(br.recovery_stages[0].awaiting, 0);
        BOOST_CHECK(!br.recovery_stages[0].earliest_blocks_remaining);
        BOOST_CHECK_GT(br.recovery_stages[1].awaiting, 0);
    }

    mineBlocks(1);
    ScanWallet(*vault.full, *Assert(m_node.chainman));
    ScanWallet(*vault.recover, *Assert(m_node.chainman));
    {
        LOCK(vault.full->cs_wallet);
        const auto br = GetVaultBalanceBreakdown(*vault.full);
        BOOST_CHECK_GT(br.recovery_stages[0].recoverable_now, 0);
        BOOST_CHECK_GT(br.recovery_stages[1].awaiting, 0);
    }
    {
        LOCK(vault.recover->cs_wallet);
        const auto br = GetVaultBalanceBreakdown(*vault.recover);
        BOOST_CHECK_EQUAL(br.recovery_stages[0].recoverable_now, 0);
        BOOST_CHECK_EQUAL(br.recovery_stages[0].awaiting, 0);
        BOOST_CHECK_GT(br.recovery_stages[1].awaiting, 0);
    }

    mineBlocks(2);
    ScanWallet(*vault.full, *Assert(m_node.chainman));
    ScanWallet(*vault.recover, *Assert(m_node.chainman));
    {
        LOCK(vault.full->cs_wallet);
        const auto br = GetVaultBalanceBreakdown(*vault.full);
        BOOST_CHECK_GT(br.recovery_stages[0].recoverable_now, 0);
        BOOST_CHECK_GT(br.recovery_stages[1].recoverable_now, 0);
        BOOST_CHECK_EQUAL(br.recovery_stages[0].awaiting, 0);
        BOOST_CHECK_EQUAL(br.recovery_stages[1].awaiting, 0);
    }
    CCoinControl one_key = FeeCC();
    {
        LOCK(vault.recover->cs_wallet);
        const auto br = GetVaultBalanceBreakdown(*vault.recover);
        BOOST_CHECK_EQUAL(br.recovery_stages[0].recoverable_now, 0);
        BOOST_CHECK_EQUAL(br.recovery_stages[0].awaiting, 0);
        BOOST_CHECK(!br.recovery_stages[0].earliest_blocks_remaining);
        BOOST_CHECK_GT(br.recovery_stages[1].recoverable_now, 0);
        BOOST_CHECK_EQUAL(br.recovery_stages[1].awaiting, 0);
        BOOST_REQUIRE(ApplyVaultRecoveryToCoinControl(*vault.recover, one_key, 4));
    }
    auto recovered = SendFrom(*vault.recover, 1 * COIN, one_key);
    BOOST_REQUIRE_MESSAGE(recovered, util::ErrorString(recovered).original);
    BOOST_CHECK_EQUAL(recovered->tx->vin[0].nSequence, 4U);
    BOOST_CHECK_GT(recovered->tx->vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(vault_recovery_change_restarts_relative_clock)
{
    mineBlocks(1);
    auto vault = MakeFundedVault(*this, /*m=*/2, /*n=*/3, /*older=*/1, {0, 1}, 10 * COIN, /*coinbase_index=*/0);
    auto rec = SendFrom(*vault.full, 1 * COIN, FeeCC(/*sequence=*/1));
    BOOST_REQUIRE_MESSAGE(rec, util::ErrorString(rec).original);
    BOOST_CHECK_GT(rec->tx->vin[0].scriptWitness.stack.size(), 1U);
    COutPoint change_op;
    bool found_change = false;
    for (uint32_t i = 0; i < rec->tx->vout.size(); ++i) {
        if (rec->tx->vout[i].nValue > 1 * COIN) {
            change_op = COutPoint(rec->tx->GetHash(), i);
            found_change = true;
        }
    }
    BOOST_REQUIRE(found_change);
    vault.full->CommitTransaction(rec->tx);
    CCoinControl cc = FeeCC();
    cc.Select(change_op).SetSequence(1);
    cc.m_allow_other_inputs = false;
    auto blocked = SendFrom(*vault.full, 1 * COIN, cc, /*sign=*/false);
    BOOST_CHECK_MESSAGE(!blocked, "relative recovery change is a new UTXO; the delay starts over");
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
