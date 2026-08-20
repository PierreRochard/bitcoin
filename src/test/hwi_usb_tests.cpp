// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
