// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <common/args.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <external_signer.h>
#include <hwi/mock.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/multisig.h>
#include <wallet/wallet.h>

#include <test/util/setup_common.h>
#include <wallet/test/util.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace wallet {
struct MockOnlyTestingSetup : BasicTestingSetup {
    hwi::UsbEnumerateSuppress no_usb;
};
BOOST_FIXTURE_TEST_SUITE(mixed_key_tests, MockOnlyTestingSetup)

using common::PSBTError;

enum class Role { Local, Hardware };

static uint64_t MixedFlags()
{
    return WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_EXTERNAL_SIGNER;
}

static uint64_t LocalOnlyFlags()
{
    return WALLET_FLAG_DESCRIPTORS;
}

static uint64_t WatchOnlyFlags()
{
    return WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_EXTERNAL_SIGNER | WALLET_FLAG_DISABLE_PRIVATE_KEYS;
}

static std::shared_ptr<CWallet> MakeBlankWallet(uint64_t flags)
{
    auto wallet = std::shared_ptr<CWallet>(new CWallet(/*chain=*/nullptr, "mixed", CreateMockableWalletDatabase()));
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

static std::vector<uint32_t> Bip48Path(OutputType type)
{
    std::vector<uint32_t> path;
    BOOST_REQUIRE(ParseHDKeypath(DefaultMultisigPath(type, /*account=*/0), path));
    return path;
}

static std::string KeyExprLocal(const CExtKey& master, const std::vector<uint32_t>& path)
{
    auto child = DeriveExtKey(master, path);
    BOOST_REQUIRE(child);
    return strprintf("[%s%s]%s/<0;1>/*",
                     HexStr(child->second.fingerprint),
                     FormatHDKeypath(child->second.path),
                     EncodeExtKey(child->first));
}

static std::string KeyExprHardware(hwi::MockRegistration& mock, const std::vector<uint32_t>& path)
{
    auto client = mock.Connect();
    BOOST_REQUIRE(client);
    const CExtPubKey xpub = client->GetPubkeyAtPath(WriteHDKeypath(path));
    return strprintf("[%s%s]%s/<0;1>/*",
                     mock.Fingerprint(),
                     FormatHDKeypath(path),
                     EncodeExtPubKey(xpub));
}

static void ImportSortedMulti(CWallet& wallet, int nrequired, const std::vector<std::string>& keys, OutputType type)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::string desc_str = WrapSortedMulti(type, nrequired, keys);
    BOOST_REQUIRE_MESSAGE(!desc_str.empty(), "unsupported address type");
    const std::string checksum = GetDescriptorChecksum(desc_str);
    if (!checksum.empty()) desc_str += "#" + checksum;

    FlatSigningProvider parse_keys;
    std::string parse_error;
    auto parsed = Parse(desc_str, parse_keys, parse_error, /*require_checksum=*/!checksum.empty());
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), parse_error);
    BOOST_REQUIRE_EQUAL(parsed.size(), 2U);

    for (size_t i = 0; i < parsed.size(); ++i) {
        WalletDescriptor w_desc(std::move(parsed[i]), /*creation_time=*/1, 0, 10, 0);
        auto spkm = wallet.AddWalletDescriptor(w_desc, parse_keys, "", /*internal=*/i == 1);
        BOOST_REQUIRE(spkm);
        wallet.AddActiveScriptPubKeyMan(spkm->get().GetID(), type, /*internal=*/i == 1);
    }
}

struct SignOutcome {
    std::optional<PSBTError> error;
    bool complete{false};
    bool input_signed{false};
    size_t hd_keypaths{0};
    size_t partial_sigs{0};
};

static SignOutcome ImportAndSign(int nrequired,
                                 const std::vector<Role>& roles,
                                 OutputType type = OutputType::BECH32,
                                 std::vector<bool> hw_connected = {},
                                 uint64_t flags = MixedFlags(),
                                 bool finalize = true)
{
    const size_t n_hw = static_cast<size_t>(std::count(roles.begin(), roles.end(), Role::Hardware));
    if (hw_connected.empty()) hw_connected.assign(n_hw, true);
    BOOST_REQUIRE_EQUAL(hw_connected.size(), n_hw);
    BOOST_REQUIRE(nrequired > 0);
    BOOST_REQUIRE(static_cast<size_t>(nrequired) <= roles.size());

    if (flags & WALLET_FLAG_EXTERNAL_SIGNER) {
        gArgs.ForceSetArg("-signer", "internal");
    }

    std::vector<CExtKey> local_masters;
    std::vector<std::unique_ptr<hwi::MockRegistration>> mocks;
    size_t mock_i = 0;
    for (Role role : roles) {
        if (role == Role::Local) {
            local_masters.push_back(RandomMaster());
        } else {
            mocks.push_back(std::make_unique<hwi::MockRegistration>(NumberedMockMaster(mock_i++)));
        }
    }

    auto wallet = MakeBlankWallet(flags);
    LOCK(wallet->cs_wallet);

    const std::vector<uint32_t> path{Bip48Path(type)};
    std::vector<std::string> exprs;
    size_t li = 0, hi = 0;
    for (Role role : roles) {
        if (role == Role::Local) {
            exprs.push_back(KeyExprLocal(local_masters[li++], path));
        } else {
            exprs.push_back(KeyExprHardware(*mocks[hi++], path));
        }
    }
    ImportSortedMulti(*wallet, nrequired, exprs, type);

    for (size_t i = 0; i < mocks.size(); ++i) {
        if (!hw_connected[i]) mocks[i].reset();
    }

    const CTxDestination dest = *Assert(wallet->GetNewDestination(type, ""));
    const CScript spk = GetScriptForDestination(dest);

    CMutableTransaction prev_tx;
    prev_tx.version = 2;
    prev_tx.vin.emplace_back();
    prev_tx.vout.emplace_back(COIN, spk);

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{prev_tx.GetHash(), 0});
    tx.vout.emplace_back(COIN - 10000, spk);

    PartiallySignedTransaction psbt(tx, /*version=*/0);
    BOOST_REQUIRE_EQUAL(psbt.inputs.size(), 1U);
    psbt.inputs[0].non_witness_utxo = MakeTransactionRef(prev_tx);
    psbt.inputs[0].witness_utxo = CTxOut{COIN, spk};

    SignOutcome out;
    bool complete = false;
    BOOST_REQUIRE(!wallet->FillPSBT(psbt, {.sign = false, .bip32_derivs = true}, complete));
    BOOST_CHECK(!complete);
    out.hd_keypaths = psbt.inputs[0].hd_keypaths.size();

    out.error = wallet->FillPSBT(psbt, {.sign = true, .finalize = finalize, .bip32_derivs = false}, complete);
    out.complete = complete;
    out.input_signed = PSBTInputSigned(psbt.inputs[0]);
    out.partial_sigs = psbt.inputs[0].partial_sigs.size();
    return out;
}

static std::string ErrorName(const std::optional<PSBTError>& error)
{
    if (!error) return "none";
    return strprintf("%d", static_cast<int>(*error));
}

static void CheckComplete(const SignOutcome& out)
{
    BOOST_REQUIRE_MESSAGE(!out.error, "unexpected FillPSBT error " + ErrorName(out.error));
    BOOST_CHECK(out.complete);
    BOOST_CHECK(out.input_signed);
}

static void CheckIncomplete(const SignOutcome& out, std::optional<PSBTError> expect_error = std::nullopt)
{
    if (expect_error) {
        BOOST_REQUIRE_MESSAGE(out.error, "expected FillPSBT error " + ErrorName(expect_error));
        BOOST_CHECK(*out.error == *expect_error);
    } else {
        BOOST_REQUIRE_MESSAGE(!out.error, "unexpected FillPSBT error " + ErrorName(out.error));
    }
    BOOST_CHECK(!out.complete);
    BOOST_CHECK(!out.input_signed);
}

BOOST_AUTO_TEST_CASE(select_signer_by_fingerprint)
{
    gArgs.ForceSetArg("-signer", "internal");
    hwi::MockRegistration a{hwi::MakeMockMasterFromHex()};
    hwi::MockRegistration b{hwi::MakeMockMasterFromHex("ffeeddccbbaa99887766554433221100")};

    auto none = ExternalSignerScriptPubKeyMan::GetExternalSigner();
    BOOST_CHECK(!none);
    BOOST_CHECK(util::ErrorString(none).original.find("More than one") != std::string::npos);

    auto one = ExternalSignerScriptPubKeyMan::GetExternalSigner(a.Fingerprint());
    BOOST_REQUIRE(one);
    BOOST_CHECK_EQUAL(one->m_fingerprint, a.Fingerprint());

    auto missing = ExternalSignerScriptPubKeyMan::GetExternalSigner(std::string{"deadbeef"});
    BOOST_CHECK(!missing);
    BOOST_CHECK(util::ErrorString(missing).original.find("deadbeef") != std::string::npos);

    auto all = ExternalSignerScriptPubKeyMan::GetExternalSigners();
    BOOST_REQUIRE(all);
    BOOST_CHECK_EQUAL(all->size(), 2U);
}

BOOST_AUTO_TEST_CASE(signer_command_required)
{
    gArgs.ForceSetArg("-signer", "");
    auto signers = ExternalSignerScriptPubKeyMan::GetExternalSigners();
    BOOST_CHECK(!signers);
    BOOST_CHECK(util::ErrorString(signers).original.find("-signer") != std::string::npos);

    auto one = ExternalSignerScriptPubKeyMan::GetExternalSigner();
    BOOST_CHECK(!one);
}

BOOST_AUTO_TEST_CASE(mixed_flag_allows_private_keys)
{
    auto wallet = MakeBlankWallet(MixedFlags());
    BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));
    BOOST_CHECK(!wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    auto watchonly = MakeBlankWallet(WatchOnlyFlags());
    BOOST_CHECK(watchonly->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));
    BOOST_CHECK(watchonly->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
}

BOOST_AUTO_TEST_CASE(mixed_multisig_uses_wallet_hd_seed)
{
    gArgs.ForceSetArg("-signer", "internal");
    const CExtKey mock_master{hwi::MakeMockMasterFromHex()};
    hwi::MockRegistration mock{mock_master};

    CExtKey local_master{RandomMaster()};

    auto wallet = MakeBlankWallet(MixedFlags());
    LOCK(wallet->cs_wallet);

    {
        std::string unused = "unused(" + EncodeExtKey(local_master) + ")";
        FlatSigningProvider unused_keys;
        std::string error;
        auto unused_descs = Parse(unused, unused_keys, error, false);
        BOOST_REQUIRE(!unused_descs.empty());
        WalletDescriptor unused_w(std::move(unused_descs.at(0)), 1, 0, 0, 0);
        BOOST_REQUIRE(wallet->AddWalletDescriptor(unused_w, unused_keys, "", false));
    }

    std::optional<CExtKey> local_xprv = wallet->GetExtKey(local_master.Neuter());
    BOOST_REQUIRE(local_xprv);

    const std::vector<uint32_t> path{Bip48Path(OutputType::BECH32)};
    auto local_child = DeriveExtKey(*local_xprv, path);
    BOOST_REQUIRE(local_child);
    const std::string k1 = strprintf("[%s%s]%s/<0;1>/*",
                                     HexStr(local_child->second.fingerprint),
                                     FormatHDKeypath(local_child->second.path),
                                     EncodeExtKey(local_child->first));
    const std::string k2 = KeyExprHardware(mock, path);
    ImportSortedMulti(*wallet, /*nrequired=*/2, {k1, k2}, OutputType::BECH32);

    BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
    BOOST_REQUIRE(wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::BECH32, ""));
    const CScript spk = GetScriptForDestination(dest);

    CMutableTransaction prev_tx;
    prev_tx.version = 2;
    prev_tx.vin.emplace_back();
    prev_tx.vout.emplace_back(COIN, spk);

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{prev_tx.GetHash(), 0});
    tx.vout.emplace_back(COIN - 10000, spk);
    PartiallySignedTransaction psbt(tx, /*version=*/0);
    psbt.inputs[0].non_witness_utxo = MakeTransactionRef(prev_tx);
    psbt.inputs[0].witness_utxo = CTxOut{COIN, spk};

    bool complete = false;
    BOOST_REQUIRE(!wallet->FillPSBT(psbt, {.sign = false, .bip32_derivs = true}, complete));
    BOOST_CHECK(!complete);
    BOOST_CHECK_EQUAL(psbt.inputs[0].hd_keypaths.size(), 2U);
    BOOST_REQUIRE(!wallet->FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete));
    BOOST_CHECK(complete);
    BOOST_CHECK(PSBTInputSigned(psbt.inputs[0]));
}

BOOST_AUTO_TEST_CASE(m_of_n_signing_matrix)
{
    // 1-of-1 local
    CheckComplete(ImportAndSign(1, {Role::Local}, OutputType::BECH32, {}, LocalOnlyFlags()));

    // 1-of-2 local + hardware: local signature is enough, even with the device offline.
    CheckComplete(ImportAndSign(1, {Role::Local, Role::Hardware}));
    CheckComplete(ImportAndSign(1, {Role::Local, Role::Hardware}, OutputType::BECH32, {false}));

    // 1-of-2 two hardware devices: either device can finish the PSBT.
    CheckComplete(ImportAndSign(1, {Role::Hardware, Role::Hardware}));
    CheckComplete(ImportAndSign(1, {Role::Hardware, Role::Hardware}, OutputType::BECH32, {true, false}));
    CheckComplete(ImportAndSign(1, {Role::Hardware, Role::Hardware}, OutputType::BECH32, {false, true}));

    // 2-of-2 local + hardware
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Hardware}));
    CheckIncomplete(ImportAndSign(2, {Role::Local, Role::Hardware}, OutputType::BECH32, {false}),
                    PSBTError::EXTERNAL_SIGNER_NOT_FOUND);

    // 2-of-2 two hardware devices
    CheckComplete(ImportAndSign(2, {Role::Hardware, Role::Hardware}));
    CheckIncomplete(ImportAndSign(2, {Role::Hardware, Role::Hardware}, OutputType::BECH32, {true, false}));
    CheckIncomplete(ImportAndSign(2, {Role::Hardware, Role::Hardware}, OutputType::BECH32, {false, false}),
                    PSBTError::EXTERNAL_SIGNER_NOT_FOUND);

    // 2-of-3 local + two hardware: local + one device meets the threshold.
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Hardware, Role::Hardware}));
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32, {true, false}));
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32, {false, true}));
    CheckIncomplete(ImportAndSign(2, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32, {false, false}),
                    PSBTError::EXTERNAL_SIGNER_NOT_FOUND);

    // 3-of-3 local + two hardware
    CheckComplete(ImportAndSign(3, {Role::Local, Role::Hardware, Role::Hardware}));
    CheckIncomplete(ImportAndSign(3, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32, {true, false}));
    CheckIncomplete(ImportAndSign(3, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32, {false, false}),
                    PSBTError::EXTERNAL_SIGNER_NOT_FOUND);

    // 3-of-5 two local + three hardware
    CheckComplete(ImportAndSign(3, {Role::Local, Role::Local, Role::Hardware, Role::Hardware, Role::Hardware}));
    CheckComplete(ImportAndSign(3, {Role::Local, Role::Local, Role::Hardware, Role::Hardware, Role::Hardware},
                                OutputType::BECH32, {true, false, false}));
    CheckIncomplete(ImportAndSign(3, {Role::Local, Role::Local, Role::Hardware, Role::Hardware, Role::Hardware},
                                  OutputType::BECH32, {false, false, false}),
                    PSBTError::EXTERNAL_SIGNER_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(all_local_m_of_n)
{
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Local}, OutputType::BECH32, {}, LocalOnlyFlags()));
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Local, Role::Local}, OutputType::BECH32, {}, LocalOnlyFlags()));
    CheckComplete(ImportAndSign(3, {Role::Local, Role::Local, Role::Local}, OutputType::BECH32, {}, LocalOnlyFlags()));
    CheckComplete(ImportAndSign(1, {Role::Local, Role::Local}, OutputType::BECH32, {}, LocalOnlyFlags()));

    // All-local keys on a mixed-key wallet: SignPSBT is a no-op once local FillPSBT completes.
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Local}, OutputType::BECH32, {}, MixedFlags()));
}

BOOST_AUTO_TEST_CASE(hardware_only_watchonly)
{
    CheckComplete(ImportAndSign(2, {Role::Hardware, Role::Hardware}, OutputType::BECH32, {}, WatchOnlyFlags()));
    CheckIncomplete(ImportAndSign(2, {Role::Hardware, Role::Hardware}, OutputType::BECH32, {true, false}, WatchOnlyFlags()));
    CheckComplete(ImportAndSign(1, {Role::Hardware, Role::Hardware, Role::Hardware}, OutputType::BECH32, {false, true, false}, WatchOnlyFlags()));
    CheckComplete(ImportAndSign(3, {Role::Hardware, Role::Hardware, Role::Hardware}, OutputType::BECH32, {}, WatchOnlyFlags()));
    CheckIncomplete(ImportAndSign(3, {Role::Hardware, Role::Hardware, Role::Hardware}, OutputType::BECH32, {true, true, false}, WatchOnlyFlags()));
}

BOOST_AUTO_TEST_CASE(address_types)
{
    for (OutputType type : {OutputType::BECH32, OutputType::P2SH_SEGWIT, OutputType::LEGACY}) {
        CheckComplete(ImportAndSign(2, {Role::Local, Role::Hardware}, type));
        CheckComplete(ImportAndSign(2, {Role::Local, Role::Local}, type, {}, LocalOnlyFlags()));
        CheckComplete(ImportAndSign(3, {Role::Local, Role::Hardware, Role::Hardware}, type));
        const SignOutcome filled = ImportAndSign(2, {Role::Local, Role::Hardware}, type, /*hw_connected=*/{}, MixedFlags(), /*finalize=*/false);
        BOOST_REQUIRE_MESSAGE(!filled.error, "unsigned fill error " + ErrorName(filled.error));
        BOOST_CHECK_EQUAL(filled.hd_keypaths, 2U);
        BOOST_CHECK_EQUAL(filled.partial_sigs, 2U);
        BOOST_CHECK(!filled.complete);
    }
}

BOOST_AUTO_TEST_CASE(reversed_key_order)
{
    gArgs.ForceSetArg("-signer", "internal");
    hwi::MockRegistration mock{NumberedMockMaster(7)};
    const std::vector<uint32_t> path{Bip48Path(OutputType::BECH32)};
    const std::string local = KeyExprLocal(RandomMaster(), path);
    const std::string hw = KeyExprHardware(mock, path);

    auto wallet = MakeBlankWallet(MixedFlags());
    LOCK(wallet->cs_wallet);
    ImportSortedMulti(*wallet, /*nrequired=*/2, {hw, local}, OutputType::BECH32);

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::BECH32, ""));
    const CScript spk = GetScriptForDestination(dest);
    CMutableTransaction prev_tx;
    prev_tx.version = 2;
    prev_tx.vin.emplace_back();
    prev_tx.vout.emplace_back(COIN, spk);
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{prev_tx.GetHash(), 0});
    tx.vout.emplace_back(COIN - 10000, spk);
    PartiallySignedTransaction psbt(tx, /*version=*/0);
    psbt.inputs[0].non_witness_utxo = MakeTransactionRef(prev_tx);
    psbt.inputs[0].witness_utxo = CTxOut{COIN, spk};

    bool complete = false;
    BOOST_REQUIRE(!wallet->FillPSBT(psbt, {.sign = false, .bip32_derivs = true}, complete));
    BOOST_REQUIRE(!wallet->FillPSBT(psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete));
    BOOST_CHECK(complete);
}

BOOST_AUTO_TEST_CASE(transcript_and_policy)
{
    BOOST_CHECK(!ValidateMultisigPolicy(0, 2).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(3, 2).empty());
    BOOST_CHECK(ValidateMultisigPolicy(2, 3).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(2, 21, OutputType::BECH32).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(1, 16, OutputType::LEGACY).empty());
    BOOST_CHECK(ValidateMultisigPolicy(20, 20, OutputType::BECH32).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(1, MAX_PUBKEYS_PER_MULTI_A + 1, OutputType::BECH32M).empty());
    BOOST_CHECK(ValidateMultisigPolicy(MAX_PUBKEYS_PER_MULTI_A, MAX_PUBKEYS_PER_MULTI_A, OutputType::BECH32M).empty());
    BOOST_CHECK(!ValidateMultisigPolicy(1, MAX_PUBKEYS_PER_MULTI_A + 1, OutputType::BECH32M, /*fallback_older=*/1).empty());
    BOOST_CHECK(ValidateMultisigPolicy(1, MAX_PUBKEYS_PER_MULTI_A, OutputType::BECH32M, /*fallback_older=*/1).empty());

    std::vector<MultisigKeySpec> keys(2);
    keys[0].label = "This computer";
    keys[1].fingerprint = "aabbccdd";
    keys[1].label = "Trezor";
    const std::string text = FormatMultisigTranscript("Family", "regtest", 2, keys, OutputType::BECH32, {"wsh(sortedmulti(2,a,b))#xxxx"});
    BOOST_CHECK(text.find("Policy: 2 of 2") != std::string::npos);
    BOOST_CHECK(text.find("This computer") != std::string::npos);
    BOOST_CHECK(text.find("aabbccdd") != std::string::npos);
    BOOST_CHECK(text.find("wsh(sortedmulti") != std::string::npos);

    const std::string tap = FormatMultisigTranscript("Family", "regtest", 2, keys, OutputType::BECH32M, {"tr(musig(a,b)/<0;1>/*)#xxxx"});
    BOOST_CHECK(tap.find("bech32m (P2TR)") != std::string::npos);
    BOOST_CHECK(tap.find("tr(musig)") != std::string::npos);
    const std::string scriptpath = FormatMultisigTranscript("Family", "regtest", 2, std::vector<MultisigKeySpec>(3), OutputType::BECH32M, {});
    BOOST_CHECK(scriptpath.find("sortedmulti_a") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(create_descriptor_airgapped_xpub)
{
    CExtKey local = RandomMaster();
    CExtKey offline = RandomMaster();
    const auto path = Bip48Path(OutputType::BECH32);
    auto child = DeriveExtKey(offline, path);
    BOOST_REQUIRE(child);
    const std::string fpr = HexStr(offline.id_key_fingerprint());

    auto wallet = MakeBlankWallet(MixedFlags());
    LOCK(wallet->cs_wallet);
    {
        std::string unused = "unused(" + EncodeExtKey(local) + ")";
        FlatSigningProvider keys;
        std::string error;
        auto descs = Parse(unused, keys, error, false);
        BOOST_REQUIRE(!descs.empty());
        WalletDescriptor w(std::move(descs.at(0)), 1, 0, 0, 0);
        BOOST_REQUIRE(wallet->AddWalletDescriptor(w, keys, "", false));
    }

    MultisigKeySpec k_local;
    k_local.hdkey = EncodeExtPubKey(local.Neuter());
    k_local.path = WriteHDKeypath(path);
    MultisigKeySpec k_air;
    k_air.fingerprint = fpr.size() == 8 ? fpr : fpr.substr(0, 8);
    k_air.path = WriteHDKeypath(path);
    k_air.xpub = EncodeExtPubKey(child->first.Neuter());
    k_air.label = "offline";

    auto created = CreateMultisigDescriptor(*wallet, 2, {k_local, k_air}, {});
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_REQUIRE_EQUAL(created->descs.size(), 2U);
    BOOST_CHECK(created->descs[0].find("wsh(sortedmulti(2,") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(bech32m_descriptor_wrappers)
{
    BOOST_CHECK_EQUAL(DefaultMultisigPath(OutputType::BECH32, 0), "m/48h/0h/0h/2h");
    BOOST_CHECK_EQUAL(DefaultMultisigPath(OutputType::BECH32M, 0), "m/48h/0h/0h/3h");
    BOOST_CHECK_EQUAL(DefaultMultisigPath(OutputType::BECH32M, 1), "m/48h/0h/1h/3h");

    const std::vector<std::string> two{
        "[aaaaaaaa/48h/1h/0h/3h]xpub1/<0;1>/*",
        "[bbbbbbbb/48h/1h/0h/3h]xpub2/<0;1>/*",
    };
    BOOST_CHECK_EQUAL(WrapSortedMulti(OutputType::BECH32M, 2, two),
                      "tr(musig([aaaaaaaa/48h/1h/0h/3h]xpub1,[bbbbbbbb/48h/1h/0h/3h]xpub2)/<0;1>/*)");
    BOOST_CHECK_EQUAL(WrapSortedMulti(OutputType::BECH32M, 1, {two[0]}), "tr(" + two[0] + ")");

    const std::vector<std::string> three{
        two[0], two[1], "[cccccccc/48h/1h/0h/3h]xpub3/<0;1>/*",
    };
    const std::string m_of_n = WrapSortedMulti(OutputType::BECH32M, 2, three);
    BOOST_CHECK(m_of_n.find("tr(" + HexStr(XOnlyPubKey::NUMS_H) + ",sortedmulti_a(2,") == 0);
    BOOST_CHECK(m_of_n.find(two[0]) != std::string::npos);

    const std::string vault = WrapSortedMulti(OutputType::BECH32M, 2, three, /*fallback_older=*/144);
    BOOST_CHECK(vault.find("tr(musig(") == 0);
    BOOST_CHECK(vault.find("and_v(v:older(144),multi_a(2,") != std::string::npos);
    BOOST_CHECK(vault.find("older(144)") != std::string::npos);
    BOOST_CHECK(vault.find(two[0]) != std::string::npos);
    BOOST_CHECK(WrapSortedMulti(OutputType::BECH32, 2, two, /*fallback_older=*/1).find("older") == std::string::npos);

    const std::string abs = WrapSortedMulti(OutputType::BECH32M, 2, two, /*fallback_older=*/{}, /*fallback_after=*/500);
    BOOST_CHECK(abs.find("and_v(v:after(500),multi_a(2,") != std::string::npos);
    BOOST_CHECK(abs.find("older") == std::string::npos);

    const std::string heir = WrapSortedMulti(OutputType::BECH32M, 1, two, /*fallback_older=*/144, {}, {two[0], two[1], three[2]});
    BOOST_CHECK(heir.find("musig(" + two[0] + "," + two[1] + ")") != std::string::npos);
    BOOST_CHECK(heir.find("multi_a(1," + two[0] + "," + two[1] + "," + three[2] + ")") != std::string::npos);
    BOOST_CHECK(heir.find("musig(" + two[0] + "," + two[1] + "," + three[2]) == std::string::npos);

    BOOST_CHECK(WrapSortedMulti(OutputType::BECH32M, 2, two, /*fallback_older=*/1, /*fallback_after=*/1).empty());
}

BOOST_AUTO_TEST_CASE(taproot_musig2)
{
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Local}, OutputType::BECH32M, {}, LocalOnlyFlags()));
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Hardware}, OutputType::BECH32M));
    CheckComplete(ImportAndSign(2, {Role::Hardware, Role::Hardware}, OutputType::BECH32M));
    CheckComplete(ImportAndSign(3, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32M));
    CheckIncomplete(ImportAndSign(2, {Role::Local, Role::Hardware}, OutputType::BECH32M, {false}),
                    PSBTError::EXTERNAL_SIGNER_NOT_FOUND);
    CheckIncomplete(ImportAndSign(2, {Role::Hardware, Role::Hardware}, OutputType::BECH32M, {true, false}));
    CheckIncomplete(ImportAndSign(3, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32M, {true, false}));
}

BOOST_AUTO_TEST_CASE(taproot_sortedmulti_a)
{
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Local, Role::Local}, OutputType::BECH32M, {}, LocalOnlyFlags()));
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32M));
    CheckComplete(ImportAndSign(2, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32M, {true, false}));
    CheckComplete(ImportAndSign(1, {Role::Local, Role::Hardware}, OutputType::BECH32M, {false}));
    CheckIncomplete(ImportAndSign(2, {Role::Local, Role::Hardware, Role::Hardware}, OutputType::BECH32M, {false, false}),
                    PSBTError::EXTERNAL_SIGNER_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(create_descriptor_bech32m_musig)
{
    CExtKey local = RandomMaster();
    CExtKey offline = RandomMaster();
    const auto path = Bip48Path(OutputType::BECH32M);
    auto child = DeriveExtKey(offline, path);
    BOOST_REQUIRE(child);
    const std::string fpr = HexStr(offline.id_key_fingerprint());

    auto wallet = MakeBlankWallet(MixedFlags());
    LOCK(wallet->cs_wallet);
    {
        std::string unused = "unused(" + EncodeExtKey(local) + ")";
        FlatSigningProvider keys;
        std::string error;
        auto descs = Parse(unused, keys, error, false);
        BOOST_REQUIRE(!descs.empty());
        WalletDescriptor w(std::move(descs.at(0)), 1, 0, 0, 0);
        BOOST_REQUIRE(wallet->AddWalletDescriptor(w, keys, "", false));
    }

    MultisigKeySpec k_local;
    k_local.hdkey = EncodeExtPubKey(local.Neuter());
    k_local.path = WriteHDKeypath(path);
    MultisigKeySpec k_air;
    k_air.fingerprint = fpr.size() == 8 ? fpr : fpr.substr(0, 8);
    k_air.path = WriteHDKeypath(path);
    k_air.xpub = EncodeExtPubKey(child->first.Neuter());

    auto created = CreateMultisigDescriptor(*wallet, 2, {k_local, k_air}, MultisigOptions{OutputType::BECH32M, 0, {}, {}});
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_REQUIRE_EQUAL(created->descs.size(), 2U);
    BOOST_CHECK(created->descs[0].find("tr(musig(") != std::string::npos);
    BOOST_CHECK(created->descs[0].find(DefaultMultisigPath(OutputType::BECH32M, 0).substr(1) + "]") != std::string::npos);

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::BECH32M, ""));
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));
}

BOOST_AUTO_TEST_CASE(create_descriptor_bech32m_delayed_fallback)
{
    CExtKey a = RandomMaster();
    CExtKey b = RandomMaster();
    CExtKey c = RandomMaster();
    const auto path = Bip48Path(OutputType::BECH32M);

    auto wallet = MakeBlankWallet(LocalOnlyFlags());
    LOCK(wallet->cs_wallet);
    auto add_unused = [&](const CExtKey& master) {
        std::string unused = "unused(" + EncodeExtKey(master) + ")";
        FlatSigningProvider keys;
        std::string error;
        auto descs = Parse(unused, keys, error, false);
        BOOST_REQUIRE(!descs.empty());
        WalletDescriptor w(std::move(descs.at(0)), 1, 0, 0, 0);
        BOOST_REQUIRE(wallet->AddWalletDescriptor(w, keys, "", false));
    };
    add_unused(a);
    add_unused(b);
    add_unused(c);

    MultisigKeySpec k1, k2, k3;
    k1.hdkey = EncodeExtPubKey(a.Neuter());
    k1.path = WriteHDKeypath(path);
    k2.hdkey = EncodeExtPubKey(b.Neuter());
    k2.path = WriteHDKeypath(path);
    k3.hdkey = EncodeExtPubKey(c.Neuter());
    k3.path = WriteHDKeypath(path);

    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, {k1, k2, k3}, MultisigOptions{OutputType::BECH32, 0, {}, 1}));

    auto created = CreateMultisigDescriptor(*wallet, 2, {k1, k2, k3}, MultisigOptions{OutputType::BECH32M, 0, {}, 1});
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_REQUIRE_EQUAL(created->descs.size(), 2U);
    BOOST_CHECK(created->descs[0].find("tr(musig(") != std::string::npos);
    BOOST_CHECK(created->descs[0].find("multi_a(2,") != std::string::npos);
    BOOST_CHECK(created->descs[0].find("older(1)") != std::string::npos);

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::BECH32M, ""));
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));
}

BOOST_AUTO_TEST_CASE(create_descriptor_watchonly_xpub_vault)
{
    CExtKey a = RandomMaster();
    CExtKey b = RandomMaster();
    const auto path = Bip48Path(OutputType::BECH32M);
    auto child_a = DeriveExtKey(a, path);
    auto child_b = DeriveExtKey(b, path);
    BOOST_REQUIRE(child_a);
    BOOST_REQUIRE(child_b);
    auto fpr = [](const CExtKey& master) {
        const std::string hex = HexStr(master.id_key_fingerprint());
        return hex.size() == 8 ? hex : hex.substr(0, 8);
    };

    auto wallet = MakeBlankWallet(WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    LOCK(wallet->cs_wallet);
    MultisigKeySpec ka, kb;
    ka.fingerprint = fpr(a);
    ka.path = WriteHDKeypath(path);
    ka.xpub = EncodeExtPubKey(child_a->first.Neuter());
    kb.fingerprint = fpr(b);
    kb.path = WriteHDKeypath(path);
    kb.xpub = EncodeExtPubKey(child_b->first.Neuter());

    auto created = CreateMultisigDescriptor(*wallet, 2, {ka, kb}, MultisigOptions{OutputType::BECH32M, 0, {}, 1});
    BOOST_REQUIRE_MESSAGE(created, util::ErrorString(created).original);
    BOOST_REQUIRE_EQUAL(created->descs.size(), 2U);
    BOOST_CHECK(created->descs[0].find("tr(musig(") != std::string::npos);
    BOOST_CHECK(created->descs[0].find("older(1)") != std::string::npos);

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::BECH32M, ""));
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(dest));

    MultisigKeySpec local;
    local.hdkey = EncodeExtPubKey(a.Neuter());
    local.path = WriteHDKeypath(path);
    BOOST_CHECK(!CreateMultisigDescriptor(*wallet, 2, {ka, local}, MultisigOptions{OutputType::BECH32M, 0, {}, 1}));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
