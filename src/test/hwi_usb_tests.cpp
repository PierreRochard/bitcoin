// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hwi/coldcard.h>
#include <hwi/hid.h>
#include <hwi/hwi.h>
#include <hwi/mock.h>
#include <hwi/protobuf.h>
#include <hwi/util.h>

#include <key.h>
#include <key_io.h>
#include <pubkey.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(hwi_usb_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(protobuf_roundtrip)
{
    hwi::PbWriter w;
    w.AddVarint(1, 42);
    w.AddString(2, "Bitcoin");
    w.AddBool(3, true);
    std::vector<unsigned char> inner{0xab, 0xcd};
    w.AddBytes(4, inner);
    const auto encoded = w.Finish();
    const auto fields = hwi::PbDecode(encoded);
    BOOST_CHECK_EQUAL(hwi::PbGetVarint(fields, 1).value_or(0), 42U);
    BOOST_CHECK_EQUAL(hwi::PbGetString(fields, 2).value_or(""), "Bitcoin");
    BOOST_CHECK_EQUAL(hwi::PbGetVarint(fields, 3).value_or(0), 1U);
    auto bytes = hwi::PbGetBytes(fields, 4);
    BOOST_REQUIRE(bytes);
    BOOST_CHECK_EQUAL_COLLECTIONS(bytes->begin(), bytes->end(), inner.begin(), inner.end());
}

BOOST_AUTO_TEST_CASE(aes256_ctr_roundtrip)
{
    const std::vector<unsigned char> key(32, 0x11);
    const std::vector<unsigned char> plain{'c', 'o', 'l', 'd', 'c', 'a', 'r', 'd'};
    const auto enc = hwi::Aes256Ctr(key, plain);
    BOOST_CHECK(enc != plain);
    const auto dec = hwi::Aes256Ctr(key, enc);
    BOOST_CHECK_EQUAL_COLLECTIONS(dec.begin(), dec.end(), plain.begin(), plain.end());
}

BOOST_AUTO_TEST_CASE(aes256_ctr_session_does_not_reset_per_message)
{
    const std::vector<unsigned char> key(32, 0x5a);
    const std::vector<unsigned char> first{'n', 'c', 'r', 'y', 1, 2, 3, 4};
    const std::vector<unsigned char> second{'x', 'p', 'u', 'b', 'm', '/', '8', '4', '\'', '/', '0', '\'', '/', '0', '\''};
    hwi::Aes256CtrStream tx{key};
    hwi::Aes256CtrStream rx{key};
    const auto e1 = tx.Crypt(first);
    const auto d1 = rx.Crypt(e1);
    BOOST_CHECK_EQUAL_COLLECTIONS(d1.begin(), d1.end(), first.begin(), first.end());
    const auto e2 = tx.Crypt(second);
    const auto d2 = rx.Crypt(e2);
    BOOST_CHECK_EQUAL_COLLECTIONS(d2.begin(), d2.end(), second.begin(), second.end());
    // A fresh counter (the old per-message bug) cannot decrypt the second frame.
    const auto naive = hwi::Aes256Ctr(key, e2);
    BOOST_CHECK(naive != second);
}

BOOST_AUTO_TEST_CASE(coldcard_vers_identifies_mk3_and_refuses_edge_taproot)
{
    const auto mk3 = hwi::ParseColdcardVersion(
        "2026-07-31T12:48:28\n4.2.0\n2.0.1\n260731124828\nmk3\n");
    BOOST_CHECK_EQUAL(mk3.hw_label, "mk3");
    BOOST_CHECK_EQUAL(mk3.version, "4.2.0");
    BOOST_CHECK(!mk3.is_edge);
    BOOST_CHECK_EQUAL(hwi::ColdcardModelName(mk3), "coldcard_mk3");

    const auto edge = hwi::ParseColdcardVersion("2026-01-01\n5.4.0X\n5.0.0\n260101000000\nmk4\n");
    BOOST_CHECK(edge.is_edge);
    BOOST_CHECK_EQUAL(hwi::ColdcardModelName(edge), "coldcard_edge");
}

BOOST_AUTO_TEST_CASE(xpub_any_version)
{
    CExtKey master = hwi::MakeMockMasterFromHex();
    const CExtPubKey xpub = master.Neuter();
    const std::string encoded = EncodeExtPubKey(xpub);
    const CExtPubKey decoded = hwi::DecodeXpubAnyVersion(encoded);
    BOOST_CHECK(decoded.pubkey == xpub.pubkey);
    BOOST_CHECK(decoded.chaincode == xpub.chaincode);
}

BOOST_AUTO_TEST_CASE(enumerate_without_devices_does_not_throw)
{
    BOOST_CHECK_NO_THROW(hwi::Enumerate());
    const bool usb = hwi::HidAvailable();
    (void)usb;
}

BOOST_AUTO_TEST_CASE(ecdh_uncompressed_hash_is_symmetric)
{
    const CKey a = GenerateRandomKey(/*compressed=*/false);
    const CKey b = GenerateRandomKey(/*compressed=*/false);
    CPubKey ap = a.GetPubKey();
    CPubKey bp = b.GetPubKey();
    ap.Decompress();
    bp.Decompress();
    BOOST_REQUIRE_EQUAL(ap.size(), 65U);
    BOOST_REQUIRE_EQUAL(bp.size(), 65U);
    std::vector<unsigned char> a_xy(ap.data() + 1, ap.data() + 65);
    std::vector<unsigned char> b_xy(bp.data() + 1, bp.data() + 65);
    const auto s1 = hwi::EcdhUncompressedHash(a, b_xy);
    const auto s2 = hwi::EcdhUncompressedHash(b, a_xy);
    BOOST_CHECK_EQUAL_COLLECTIONS(s1.begin(), s1.end(), s2.begin(), s2.end());
    BOOST_CHECK_EQUAL(s1.size(), 32U);
}

BOOST_AUTO_TEST_SUITE_END()
