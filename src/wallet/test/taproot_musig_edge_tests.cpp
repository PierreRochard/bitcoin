// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <common/args.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <hwi/mock.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <wallet/multisig.h>
#include <wallet/wallet.h>

#include <test/util/setup_common.h>
#include <wallet/test/util.h>

#include <tinyformat.h>
#include <util/result.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(taproot_musig_edge_tests, BasicTestingSetup)

using common::PSBTError;

enum class Part { Local, Hardware, Watch };

static uint64_t FlagsFor(const std::vector<Part>& parts)
{
    for (Part p : parts) {
        if (p == Part::Hardware) return WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_EXTERNAL_SIGNER;
    }
    return WALLET_FLAG_DESCRIPTORS;
}

static std::shared_ptr<CWallet> MakeBlankWallet(uint64_t flags)
{
    auto wallet = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "taproot_edge", CreateMockableWalletDatabase()));
    wallet->m_keypool_size = 2;
    wallet->InitWalletFlags(flags | WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
    return wallet;
}

static CExtKey RandomMaster()
{
    CKey seed = GenerateRandomKey();
    CExtKey master;
    master.SetSeed(seed);
    return master;
}

static CExtKey NumberedMockMaster(size_t n)
{
    std::array<std::byte, 16> seed{};
    seed[14] = std::byte((n >> 8) & 0xff);
    seed[15] = std::byte(static_cast<uint8_t>(n + 1));
    return hwi::MakeMockMaster(seed);
}

static std::vector<uint32_t> Bip48TaprootPath()
{
    std::vector<uint32_t> path;
    BOOST_REQUIRE(ParseHDKeypath(DefaultMultisigPath(OutputType::BECH32M, /*account=*/0), path));
    return path;
}

struct BareKey {
    std::string priv;
    std::string pub;
};

static BareKey BareLocal(const CExtKey& master, const std::vector<uint32_t>& path)
{
    auto child = DeriveExtKey(master, path);
    BOOST_REQUIRE(child);
    const std::string origin = strprintf("[%s%s]", HexStr(child->second.fingerprint), FormatHDKeypath(child->second.path));
    return {origin + EncodeExtKey(child->first), origin + EncodeExtPubKey(child->first.Neuter())};
}

static BareKey BareHw(hwi::MockRegistration& mock, const std::vector<uint32_t>& path)
{
    auto client = mock.Connect();
    BOOST_REQUIRE(client);
    const CExtPubKey xpub = client->GetPubkeyAtPath(WriteHDKeypath(path));
    const std::string origin = strprintf("[%s%s]", mock.Fingerprint(), FormatHDKeypath(path));
    const std::string expr = origin + EncodeExtPubKey(xpub);
    return {expr, expr};
}

static std::string Subst(std::string pat, const std::vector<std::string>& keys)
{
    const std::string h = HexStr(XOnlyPubKey::NUMS_H);
    for (size_t pos; (pos = pat.find("$H")) != std::string::npos;) {
        pat.replace(pos, 2, h);
    }
    for (int i = static_cast<int>(keys.size()) - 1; i >= 0; --i) {
        const std::string tok = strprintf("$%d", i);
        for (size_t pos; (pos = pat.find(tok)) != std::string::npos;) {
            pat.replace(pos, tok.size(), keys[i]);
        }
    }
    return pat;
}

static void ImportDesc(CWallet& wallet, const std::string& desc_str)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::string with_cs = desc_str;
    const std::string checksum = GetDescriptorChecksum(with_cs);
    if (!checksum.empty()) with_cs += "#" + checksum;
    FlatSigningProvider parse_keys;
    std::string parse_error;
    auto parsed = Parse(with_cs, parse_keys, parse_error, /*require_checksum=*/!checksum.empty());
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), parse_error + " desc=" + desc_str);
    for (size_t i = 0; i < parsed.size(); ++i) {
        const bool internal = parsed.size() >= 2 && i == 1;
        const auto out_type = parsed[i]->GetOutputType();
        WalletDescriptor w_desc(std::move(parsed[i]), /*creation_time=*/1, 0, 10, 0);
        auto spkm = wallet.AddWalletDescriptor(w_desc, parse_keys, "", internal);
        BOOST_REQUIRE_MESSAGE(spkm, util::ErrorString(spkm).original);
        if (i <= 1 && out_type) {
            wallet.AddActiveScriptPubKeyMan(spkm->get().GetID(), *out_type, internal);
        }
    }
}

static size_t CountPubnonces(const PSBTInput& in)
{
    size_t n = 0;
    for (const auto& [_, m] : in.m_musig2_pubnonces) n += m.size();
    return n;
}

static size_t CountPartialSigs(const PSBTInput& in)
{
    size_t n = 0;
    for (const auto& [_, m] : in.m_musig2_partial_sigs) n += m.size();
    return n;
}

struct EdgeOpts {
    std::vector<Part> parts;
    std::vector<bool> hw_connected;
    std::optional<int> sighash;
    uint32_t locktime{0};
    uint32_t sequence{CTxIn::SEQUENCE_FINAL};
    bool finalize{true};
};

struct EdgeOut {
    std::optional<PSBTError> error;
    bool complete{false};
    bool input_signed{false};
    size_t pubnonces{0};
    size_t partial_sigs{0};
    size_t witness_stack{0};
    size_t tap_key_sig{0};
    CMutableTransaction extracted;
    std::optional<PartiallySignedTransaction> psbt;
};

struct EdgeEnv {
    std::shared_ptr<CWallet> wallet;
    std::vector<std::unique_ptr<hwi::MockRegistration>> mocks;
    CScript spk;
};

static EdgeEnv SetupEdge(const std::string& pattern, const EdgeOpts& opts)
{
    const size_t n = opts.parts.size();
    BOOST_REQUIRE(n >= 1);
    const size_t n_hw = static_cast<size_t>(std::count(opts.parts.begin(), opts.parts.end(), Part::Hardware));
    std::vector<bool> hw_connected = opts.hw_connected;
    if (hw_connected.empty()) hw_connected.assign(n_hw, true);
    BOOST_REQUIRE_EQUAL(hw_connected.size(), n_hw);

    if (n_hw) gArgs.ForceSetArg("-signer", "internal");

    const std::vector<uint32_t> path{Bip48TaprootPath()};
    std::vector<CExtKey> local_masters;
    std::vector<std::unique_ptr<hwi::MockRegistration>> mocks;
    std::vector<BareKey> keys;
    keys.reserve(n);
    size_t mock_i = 0;
    for (Part p : opts.parts) {
        if (p == Part::Hardware) {
            mocks.push_back(std::make_unique<hwi::MockRegistration>(NumberedMockMaster(mock_i++)));
            keys.push_back(BareHw(*mocks.back(), path));
        } else {
            local_masters.push_back(RandomMaster());
            keys.push_back(BareLocal(local_masters.back(), path));
        }
    }

    std::vector<std::string> used;
    used.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        used.push_back(opts.parts[i] == Part::Watch ? keys[i].pub : keys[i].priv);
    }

    auto wallet = MakeBlankWallet(FlagsFor(opts.parts));
    LOCK(wallet->cs_wallet);
    ImportDesc(*wallet, Subst(pattern, used));

    size_t hi = 0;
    for (size_t i = 0; i < n; ++i) {
        if (opts.parts[i] != Part::Hardware) continue;
        if (!hw_connected[hi]) mocks[hi].reset();
        ++hi;
    }

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::BECH32M, ""));
    EdgeEnv env;
    env.wallet = std::move(wallet);
    env.mocks = std::move(mocks);
    env.spk = GetScriptForDestination(dest);
    return env;
}

static PartiallySignedTransaction MakeSpendPsbt(const CScript& spk, uint32_t locktime, uint32_t sequence)
{
    CMutableTransaction prev_tx;
    prev_tx.version = 2;
    prev_tx.vin.emplace_back();
    prev_tx.vout.emplace_back(COIN, spk);

    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = locktime;
    tx.vin.emplace_back(COutPoint{prev_tx.GetHash(), 0}, CScript(), sequence);
    tx.vout.emplace_back(COIN - 10000, spk);

    PartiallySignedTransaction psbt(tx, /*version=*/0);
    BOOST_REQUIRE_EQUAL(psbt.inputs.size(), 1U);
    psbt.inputs[0].non_witness_utxo = MakeTransactionRef(prev_tx);
    psbt.inputs[0].witness_utxo = CTxOut{COIN, spk};
    return psbt;
}

static EdgeOut SignEnv(EdgeEnv& env, const EdgeOpts& opts)
{
    LOCK(env.wallet->cs_wallet);
    auto psbt = MakeSpendPsbt(env.spk, opts.locktime, opts.sequence);
    EdgeOut out;
    bool complete = false;
    BOOST_REQUIRE(!env.wallet->FillPSBT(psbt, {.sign = false, .bip32_derivs = true}, complete));
    out.error = env.wallet->FillPSBT(psbt, {.sign = true, .sighash_type = opts.sighash, .finalize = opts.finalize, .bip32_derivs = false}, complete);
    out.complete = complete;
    out.input_signed = PSBTInputSigned(psbt.inputs[0]);
    out.pubnonces = CountPubnonces(psbt.inputs[0]);
    out.partial_sigs = CountPartialSigs(psbt.inputs[0]);
    out.tap_key_sig = psbt.inputs[0].m_tap_key_sig.size();
    out.witness_stack = psbt.inputs[0].final_script_witness.stack.size();
    if (complete || PSBTInputSigned(psbt.inputs[0])) {
        FinalizeAndExtractPSBT(psbt, out.extracted);
        if (out.witness_stack == 0) {
            out.witness_stack = out.extracted.vin.empty() ? 0 : out.extracted.vin[0].scriptWitness.stack.size();
        }
    }
    out.psbt = std::move(psbt);
    return out;
}

static EdgeOut RunEdge(const std::string& pattern, EdgeOpts opts)
{
    EdgeEnv env = SetupEdge(pattern, opts);
    return SignEnv(env, opts);
}

static void CheckComplete(const EdgeOut& out, std::optional<bool> scriptpath = std::nullopt)
{
    BOOST_REQUIRE_MESSAGE(!out.error, strprintf("unexpected FillPSBT error %d", out.error ? static_cast<int>(*out.error) : -1));
    BOOST_CHECK(out.complete);
    BOOST_CHECK(out.input_signed);
    if (!scriptpath) return;
    if (*scriptpath) {
        BOOST_CHECK_GT(out.witness_stack, 1U);
    } else {
        BOOST_CHECK_EQUAL(out.witness_stack, 1U);
    }
}

static void CheckIncomplete(const EdgeOut& out, std::optional<PSBTError> expect_error = std::nullopt)
{
    if (expect_error) {
        BOOST_REQUIRE(out.error);
        BOOST_CHECK(*out.error == *expect_error);
    } else {
        BOOST_REQUIRE_MESSAGE(!out.error, "unexpected FillPSBT error");
    }
    BOOST_CHECK(!out.complete);
}

static std::vector<Part> Locals(size_t n)
{
    return std::vector<Part>(n, Part::Local);
}

static std::vector<Part> MixedHwLast(size_t n)
{
    std::vector<Part> p(n, Part::Local);
    if (n >= 2) p.back() = Part::Hardware;
    return p;
}

static std::vector<Part> AllHw(size_t n)
{
    return std::vector<Part>(n, Part::Hardware);
}

BOOST_AUTO_TEST_CASE(aggregate_then_derive_and_derive_then_aggregate)
{
    const char* agg = "tr(musig($0,$1,$2)/<0;1>/*)";
    const char* der = "tr(musig($0/<0;1>/*,$1/<1;2>/*,$2/<2;3>/*))";
    for (const char* pat : {agg, der}) {
        CheckComplete(RunEdge(pat, {.parts = Locals(3)}));
        CheckComplete(RunEdge(pat, {.parts = MixedHwLast(3)}));
        CheckComplete(RunEdge(pat, {.parts = AllHw(3)}));
        CheckIncomplete(RunEdge(pat, {.parts = MixedHwLast(3), .hw_connected = {false}}),
                        PSBTError::EXTERNAL_SIGNER_NOT_FOUND);
    }
}

BOOST_AUTO_TEST_CASE(rawtr_musig)
{
    const char* pat = "rawtr(musig($0,$1)/<0;1>/*)";
    CheckComplete(RunEdge(pat, {.parts = Locals(2)}));
    CheckComplete(RunEdge(pat, {.parts = MixedHwLast(2)}));
    CheckComplete(RunEdge(pat, {.parts = AllHw(2)}));
}

BOOST_AUTO_TEST_CASE(three_index_multipath)
{
    const char* pat = "tr(musig($0/<0;1;2>/*,$1/<0;1;2>/*,$2/<0;1;2>/*))";
    CheckComplete(RunEdge(pat, {.parts = Locals(3)}));
    CheckComplete(RunEdge(pat, {.parts = MixedHwLast(3)}));
}

BOOST_AUTO_TEST_CASE(no_multipath)
{
    CheckComplete(RunEdge("tr(musig($0/0/*,$1/1/*,$2/2/*))", {.parts = Locals(3)}));
    CheckComplete(RunEdge("tr(musig($0/0/*,$1/1/*,$2/2/*))", {.parts = MixedHwLast(3)}));
}

BOOST_AUTO_TEST_CASE(musig_in_script_leaf)
{
    const char* pat = "tr($H,pk(musig($0,$1,$2)/<0;1>/*))";
    CheckComplete(RunEdge(pat, {.parts = Locals(3)}), /*scriptpath=*/true);
    CheckComplete(RunEdge(pat, {.parts = MixedHwLast(3)}), /*scriptpath=*/true);
    CheckComplete(RunEdge(pat, {.parts = AllHw(3)}), /*scriptpath=*/true);
}

BOOST_AUTO_TEST_CASE(two_musig_leaves)
{
    const char* pat = "tr($H,{pk(musig($0,$1)/<0;1>/*),pk(musig($2,$3)/0/*)})";
    CheckComplete(RunEdge(pat, {.parts = Locals(4)}), /*scriptpath=*/true);
    CheckComplete(RunEdge(pat, {.parts = MixedHwLast(4)}), /*scriptpath=*/true);
}

BOOST_AUTO_TEST_CASE(overlapping_musig_leaves)
{
    const char* pat = "tr($H,{pk(musig($0,$1,$2)/<0;1>/*),pk(musig($1,$2)/0/*)})";
    CheckComplete(RunEdge(pat, {.parts = Locals(3)}), /*scriptpath=*/true);
    CheckComplete(RunEdge(pat, {.parts = MixedHwLast(3)}), /*scriptpath=*/true);
}

BOOST_AUTO_TEST_CASE(keypath_plus_nested_musig_leaves)
{
    const char* pat = "tr(musig($0,$1,$2)/<3;4>/*,{pk(musig($0,$1)/<5;6>/*),pk(musig($1,$2)/7/*)})";
    // All participants present: spendable (key-path or a musig leaf).
    CheckComplete(RunEdge(pat, {.parts = Locals(3)}));
    CheckComplete(RunEdge(pat, {.parts = MixedHwLast(3)}));

    // $0 is watch-only: key-path and the first leaf need it; the $1+$2 leaf spends.
    CheckComplete(RunEdge(pat, {.parts = {Part::Watch, Part::Local, Part::Local}}), /*scriptpath=*/true);
    CheckComplete(RunEdge(pat, {.parts = {Part::Watch, Part::Local, Part::Hardware}}), /*scriptpath=*/true);
}

BOOST_AUTO_TEST_CASE(miniscript_around_musig)
{
    const uint32_t seq = CTxIn::MAX_SEQUENCE_NONFINAL;
    const struct {
        const char* pat;
        size_t n;
    } cases[] = {
        {"tr($H,and_v(v:pk(musig($0,$1,$2)/<0;1>/*),after(1)))", 3},
        {"tr($H,and_v(vc:pk_k(musig($0,$1)/<0;1>/*),after(1)))", 2},
        {"tr($H,and_v(v:pkh(musig($0,$1,$2)/<0;1>/*),after(1)))", 3},
        {"tr($H,and_v(vc:pk_h(musig($0,$1)/<0;1>/*),after(1)))", 2},
        {"tr($H,{and_v(v:pk(musig($0,$2)/0/*),after(1)),and_v(v:pk(musig($1,$2)/0/*),after(1))})", 3},
    };
    for (const auto& c : cases) {
        CheckComplete(RunEdge(c.pat, {.parts = Locals(c.n), .locktime = 1, .sequence = seq}), /*scriptpath=*/true);
        CheckComplete(RunEdge(c.pat, {.parts = MixedHwLast(c.n), .locktime = 1, .sequence = seq}), /*scriptpath=*/true);
    }
}

BOOST_AUTO_TEST_CASE(deep_sortedmulti_a_tree)
{
    const char* pat = "tr($1/<0;1>/*,{pk($1/<0;1>/*),{pk($1/<0;1>/*),sortedmulti_a(2,$0/<0;1>/*,$1/<0;1>/*,$2/<0;1>/*)}})";
    CheckComplete(RunEdge(pat, {.parts = Locals(3)}));
    CheckComplete(RunEdge(pat, {.parts = MixedHwLast(3)}));
    // 2-of-3: one hardware missing still meets the threshold if two locals sign.
    CheckComplete(RunEdge(pat, {.parts = {Part::Local, Part::Local, Part::Hardware}, .hw_connected = {false}}));
}

BOOST_AUTO_TEST_CASE(sighash_anyonecanpay)
{
    const int sh = SIGHASH_ALL | SIGHASH_ANYONECANPAY;
    for (const char* pat : {"tr(musig($0,$1)/<0;1>/*)", "tr($H,pk(musig($0,$1)/<0;1>/*))"}) {
        const bool scriptpath = std::string(pat).find("$H") != std::string::npos;
        EdgeOut out = RunEdge(pat, {.parts = MixedHwLast(2), .sighash = sh});
        CheckComplete(out, scriptpath);
        BOOST_REQUIRE(!out.extracted.vin.empty());
        const auto& stack = out.extracted.vin[0].scriptWitness.stack;
        BOOST_REQUIRE(!stack.empty());
        BOOST_REQUIRE_GE(stack[0].size(), 65U);
        BOOST_CHECK_EQUAL(stack[0].back(), static_cast<unsigned char>(sh));
    }
}

BOOST_AUTO_TEST_CASE(concurrent_musig_sessions)
{
    EdgeOpts opts{.parts = MixedHwLast(3)};
    EdgeEnv env = SetupEdge("tr(musig($0,$1,$2)/<0;1>/*)", opts);
    EdgeOut a = SignEnv(env, opts);
    EdgeOut b = SignEnv(env, opts);
    CheckComplete(a);
    CheckComplete(b);
    BOOST_REQUIRE(!a.extracted.vin.empty());
    BOOST_REQUIRE(!b.extracted.vin.empty());
    BOOST_CHECK(a.extracted.vin[0].scriptWitness.stack != b.extracted.vin[0].scriptWitness.stack);
}

BOOST_AUTO_TEST_CASE(protocol_missing_nonce)
{
    // 3-of-3 musig, one hardware unplugged: two pubnonces, no partials.
    EdgeOut out = RunEdge("tr(musig($0,$1,$2)/<0;1>/*)",
                          {.parts = {Part::Local, Part::Local, Part::Hardware}, .hw_connected = {false}});
    CheckIncomplete(out, PSBTError::EXTERNAL_SIGNER_NOT_FOUND);
    BOOST_CHECK_EQUAL(out.pubnonces, 2U);
    BOOST_CHECK_EQUAL(out.partial_sigs, 0U);

    out = RunEdge("tr(musig($0,$1,$2)/<0;1>/*)",
                  {.parts = AllHw(3), .hw_connected = {true, true, false}});
    CheckIncomplete(out);
    BOOST_CHECK_EQUAL(out.pubnonces, 2U);
    BOOST_CHECK_EQUAL(out.partial_sigs, 0U);
}

BOOST_AUTO_TEST_CASE(protocol_split_wallets_missing_partial_and_finalize)
{
    const std::string pat = "tr(musig($0,$1,$2)/<0;1>/*)";
    const std::vector<uint32_t> path{Bip48TaprootPath()};
    std::vector<CExtKey> masters{RandomMaster(), RandomMaster(), RandomMaster()};
    std::vector<BareKey> keys;
    for (const auto& m : masters) keys.push_back(BareLocal(m, path));

    std::vector<std::shared_ptr<CWallet>> wallets;
    for (size_t i = 0; i < 3; ++i) {
        std::vector<std::string> used;
        for (size_t j = 0; j < 3; ++j) used.push_back(j == i ? keys[j].priv : keys[j].pub);
        auto w = MakeBlankWallet(WALLET_FLAG_DESCRIPTORS);
        LOCK(w->cs_wallet);
        ImportDesc(*w, Subst(pat, used));
        wallets.push_back(std::move(w));
    }

    CScript spk;
    {
        LOCK(wallets[0]->cs_wallet);
        spk = GetScriptForDestination(*Assert(wallets[0]->GetNewDestination(OutputType::BECH32M, "")));
    }
    auto unsigned_psbt = MakeSpendPsbt(spk, 0, CTxIn::SEQUENCE_FINAL);
    {
        bool complete = false;
        LOCK(wallets[0]->cs_wallet);
        BOOST_REQUIRE(!wallets[0]->FillPSBT(unsigned_psbt, {.sign = false, .bip32_derivs = true}, complete));
    }

    std::vector<PartiallySignedTransaction> nonce_psbts;
    for (auto& w : wallets) {
        auto psbt = unsigned_psbt;
        bool complete = false;
        LOCK(w->cs_wallet);
        BOOST_REQUIRE(!w->FillPSBT(psbt, {.sign = true, .finalize = false, .bip32_derivs = false}, complete));
        BOOST_CHECK(!complete);
        nonce_psbts.push_back(std::move(psbt));
    }
    auto all_nonces = CombinePSBTs(nonce_psbts);
    BOOST_REQUIRE(all_nonces);
    BOOST_CHECK_EQUAL(CountPubnonces(all_nonces->inputs[0]), 3U);
    BOOST_CHECK_EQUAL(CountPartialSigs(all_nonces->inputs[0]), 0U);

    BOOST_CHECK(!FinalizePSBT(*all_nonces));
    BOOST_CHECK_EQUAL(CountPartialSigs(all_nonces->inputs[0]), 0U);

    std::vector<PartiallySignedTransaction> two_partials;
    for (size_t i = 0; i < 2; ++i) {
        auto psbt = *all_nonces;
        bool complete = false;
        LOCK(wallets[i]->cs_wallet);
        BOOST_REQUIRE(!wallets[i]->FillPSBT(psbt, {.sign = true, .finalize = false, .bip32_derivs = false}, complete));
        BOOST_CHECK(!complete);
        two_partials.push_back(std::move(psbt));
    }
    auto combined_two = CombinePSBTs(two_partials);
    BOOST_REQUIRE(combined_two);
    BOOST_CHECK_EQUAL(CountPartialSigs(combined_two->inputs[0]), 2U);
    BOOST_CHECK(!FinalizePSBT(*combined_two));

    std::vector<PartiallySignedTransaction> all_partials = two_partials;
    {
        auto psbt = *all_nonces;
        bool complete = false;
        LOCK(wallets[2]->cs_wallet);
        BOOST_REQUIRE(!wallets[2]->FillPSBT(psbt, {.sign = true, .finalize = false, .bip32_derivs = false}, complete));
        all_partials.push_back(std::move(psbt));
    }
    auto combined_all = CombinePSBTs(all_partials);
    BOOST_REQUIRE(combined_all);
    BOOST_CHECK_EQUAL(CountPartialSigs(combined_all->inputs[0]), 3U);
    BOOST_CHECK(FinalizePSBT(*combined_all));
    CMutableTransaction mtx;
    BOOST_CHECK(FinalizeAndExtractPSBT(*combined_all, mtx));
    BOOST_CHECK_EQUAL(mtx.vin[0].scriptWitness.stack.size(), 1U);
}

BOOST_AUTO_TEST_CASE(large_sortedmulti_a_padding)
{
    // One real key among many NUMS pads, like wallet_taproot.py's max-size leaf.
    std::string pat = "tr($H,sortedmulti_a(1";
    constexpr int pads = 32;
    for (int i = 0; i < pads; ++i) pat += ",$H";
    pat += ",$0/<0;1>/*))";
    CheckComplete(RunEdge(pat, {.parts = Locals(1)}), /*scriptpath=*/true);
    CheckComplete(RunEdge(pat, {.parts = {Part::Hardware}}), /*scriptpath=*/true);
}

BOOST_AUTO_TEST_CASE(delayed_musig_fallback_older)
{
    const char* pat =
        "tr(musig($0/<0;1>/*,$1/<0;1>/*,$2/<0;1>/*),and_v(v:older(1),multi_a(2,$0/<0;1>/*,$1/<0;1>/*,$2/<0;1>/*)))";

    CheckComplete(RunEdge(pat, {.parts = Locals(3)}), /*scriptpath=*/false);
    CheckComplete(RunEdge(pat, {.parts = MixedHwLast(3)}), /*scriptpath=*/false);
    CheckComplete(RunEdge(pat, {.parts = AllHw(3)}), /*scriptpath=*/false);

    // One key missing: key-path cannot finish; older(1) + two keys can.
    CheckComplete(RunEdge(pat, {.parts = {Part::Watch, Part::Local, Part::Local}, .sequence = 1}),
                  /*scriptpath=*/true);
    CheckComplete(RunEdge(pat, {.parts = {Part::Watch, Part::Local, Part::Hardware}, .sequence = 1}),
                  /*scriptpath=*/true);

    CheckIncomplete(RunEdge(pat, {.parts = {Part::Watch, Part::Local, Part::Local},
                                  .sequence = CTxIn::SEQUENCE_FINAL}));
    CheckIncomplete(RunEdge(pat, {.parts = {Part::Watch, Part::Watch, Part::Local}, .sequence = 1}));
}

BOOST_AUTO_TEST_CASE(max_pubkeys_sortedmulti_a_parse)
{
    std::string desc = "tr(" + HexStr(XOnlyPubKey::NUMS_H) + ",sortedmulti_a(1";
    for (unsigned i = 0; i < MAX_PUBKEYS_PER_MULTI_A; ++i) {
        desc += ",";
        desc += HexStr(XOnlyPubKey::NUMS_H);
    }
    desc += "))";
    const std::string checksum = GetDescriptorChecksum(desc);
    BOOST_REQUIRE(!checksum.empty());
    desc += "#" + checksum;
    FlatSigningProvider keys;
    std::string error;
    auto parsed = Parse(desc, keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), error);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    BOOST_REQUIRE(parsed[0]->Expand(0, keys, scripts, out));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
