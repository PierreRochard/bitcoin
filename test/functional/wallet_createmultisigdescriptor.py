#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet createmultisigdescriptor RPC and mixed-key m-of-n wallets."""

import os
import sys

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import WalletUnlock


BIP48_BECH32 = "m/48h/1h/0h/2h"
BIP48_P2SH = "m/48h/1h/0h/1h"
BIP48_LEGACY = "m/48h/1h/0h/0h"
BIP48_BECH32M = "m/48h/1h/0h/3h"


class WalletCreateMultisigDescriptorTest(BitcoinTestFramework):
    def mock_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "mocks", "signer.py")
        return sys.executable + " " + path

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-keypool=10"],
            [f"-signer={self.mock_signer_path()}", "-keypool=10"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_external_signer()

    def run_test(self):
        self.generate(self.nodes[0], 101)
        self.test_parameter_errors()
        self.test_all_local_2of2()
        self.test_all_local_thresholds()
        self.test_address_types()
        self.test_taproot_musig2()
        self.test_taproot_sortedmulti_a()
        self.test_internal_and_account()
        self.test_multiple_hdkeys_require_explicit()
        self.test_encrypted()
        self.test_cross_wallet_2of2()
        self.test_mixed_key_wallet()
        self.test_airgapped_xpub()
        self.test_watchonly()

    def _blank(self, name, node=0, **kwargs):
        self.nodes[node].createwallet(wallet_name=name, blank=True, **kwargs)
        return self.nodes[node].get_wallet_rpc(name)

    def _two_hdkeys(self, wallet):
        return wallet.addhdkey()["xpub"], wallet.addhdkey()["xpub"]

    def _keys(self, xpubs, path=BIP48_BECH32):
        return [{"path": path, "hdkey": xpub} for xpub in xpubs]

    def test_parameter_errors(self):
        self.log.info("Test createmultisigdescriptor parameter errors")
        wallet = self._blank("err_params")
        xpub = wallet.addhdkey()["xpub"]

        assert_raises_rpc_error(
            -8, "keys must be a non-empty array",
            wallet.createmultisigdescriptor, 1, [],
        )
        assert_raises_rpc_error(
            -8, "nrequired must be > 0 and <= the number of keys",
            wallet.createmultisigdescriptor, 0, [BIP48_BECH32],
        )
        assert_raises_rpc_error(
            -8, "nrequired must be > 0 and <= the number of keys",
            wallet.createmultisigdescriptor, 2, [BIP48_BECH32],
        )
        assert_raises_rpc_error(
            -8, "Derivation path requires at least one hardened step",
            wallet.createmultisigdescriptor, 1, ["m/0/0/0"],
        )
        assert_raises_rpc_error(
            -8, "Unknown or unsupported address type",
            wallet.createmultisigdescriptor, 1, [BIP48_BECH32], {"type": "notatype"},
        )
        assert_raises_rpc_error(
            -8, "Each key must be a string or object",
            wallet.createmultisigdescriptor, 1, [1],
        )
        assert_raises_rpc_error(
            -8, "Invalid BIP32 keypath",
            wallet.createmultisigdescriptor, 1, ["abcd"],
        )
        assert_raises_rpc_error(
            -8, "fingerprint must be 8 hex characters",
            wallet.createmultisigdescriptor, 1, [{"fingerprint": "abcd"}],
        )
        assert_raises_rpc_error(
            -8, "fingerprint must be 8 hex characters",
            wallet.createmultisigdescriptor, 1, [{"fingerprint": "xyzxyzxy", "path": BIP48_BECH32}],
        )
        assert_raises_rpc_error(
            -5, "Unable to parse HD key. Please provide a valid xpub",
            wallet.createmultisigdescriptor, 1, [{"path": BIP48_BECH32, "hdkey": "not-an-xpub"}],
        )
        other = self.nodes[0].get_wallet_rpc(self.default_wallet_name).gethdkeys()[0]["xpub"]
        assert_raises_rpc_error(
            -5, f"Private key for {other} is not known",
            wallet.createmultisigdescriptor, 1, [{"path": BIP48_BECH32, "hdkey": other}],
        )

        self.nodes[0].createwallet(wallet_name="err_watch", disable_private_keys=True)
        watch = self.nodes[0].get_wallet_rpc("err_watch")
        assert_raises_rpc_error(
            -4, "createmultisigdescriptor requires a wallet with private keys or an external signer",
            watch.createmultisigdescriptor, 1, [BIP48_BECH32],
        )

        # A valid 1-of-1 so later tests can use getnewaddress on this wallet.
        res = wallet.createmultisigdescriptor(1, [{"path": BIP48_BECH32, "hdkey": xpub}])
        assert_equal(res["nrequired"], 1)
        assert_equal(len(res["descs"]), 2)
        assert "wsh(sortedmulti(1," in res["descs"][0]

    def test_all_local_2of2(self):
        self.log.info("Test 2-of-2 from two local HD seeds")
        funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        wallet = self._blank("local_2of2")
        x1, x2 = self._two_hdkeys(wallet)
        res = wallet.createmultisigdescriptor(2, self._keys([x1, x2]))
        assert_equal(res["nrequired"], 2)
        assert_equal(len(res["descs"]), 2)
        for desc in res["descs"]:
            assert desc.startswith("wsh(sortedmulti(2,")

        addr = wallet.getnewaddress("", "bech32")
        info = wallet.getaddressinfo(addr)
        assert_equal(info["isscript"], True)
        assert_equal(info["iswitness"], True)
        assert_equal(info["solvable"], True)
        assert_equal(info["ismine"], True)
        assert_equal(info["sigsrequired"], 2)

        funding.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)
        dest = funding.getnewaddress()
        psbt = wallet.walletcreatefundedpsbt([], {dest: 1})["psbt"]
        processed = wallet.walletprocesspsbt(psbt)
        assert processed["complete"]
        sent = wallet.send(outputs={dest: 1})
        assert sent["complete"]
        self.generate(self.nodes[0], 1)

    def test_all_local_thresholds(self):
        self.log.info("Test all-local 1-of-2, 2-of-3, and 3-of-3")
        funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        w12 = self._blank("local_1of2")
        x1, x2 = self._two_hdkeys(w12)
        w12.createmultisigdescriptor(1, self._keys([x1, x2]))
        funding.sendtoaddress(w12.getnewaddress("", "bech32"), 5)
        self.generate(self.nodes[0], 1)
        sent = w12.send(outputs={funding.getnewaddress(): 1})
        assert sent["complete"]

        w23 = self._blank("local_2of3")
        keys = [w23.addhdkey()["xpub"] for _ in range(3)]
        w23.createmultisigdescriptor(2, self._keys(keys))
        funding.sendtoaddress(w23.getnewaddress("", "bech32"), 5)
        self.generate(self.nodes[0], 1)
        sent = w23.send(outputs={funding.getnewaddress(): 1})
        assert sent["complete"]
        info = w23.getaddressinfo(w23.getnewaddress("", "bech32"))
        assert_equal(info["sigsrequired"], 2)

        w33 = self._blank("local_3of3")
        keys = [w33.addhdkey()["xpub"] for _ in range(3)]
        w33.createmultisigdescriptor(3, self._keys(keys))
        funding.sendtoaddress(w33.getnewaddress("", "bech32"), 5)
        self.generate(self.nodes[0], 1)
        sent = w33.send(outputs={funding.getnewaddress(): 1})
        assert sent["complete"]
        info = w33.getaddressinfo(w33.getnewaddress("", "bech32"))
        assert_equal(info["sigsrequired"], 3)

    def test_address_types(self):
        self.log.info("Test bech32, p2sh-segwit, and legacy wrappers")
        funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        cases = [
            ("bech32", BIP48_BECH32, "wsh(sortedmulti(2,", "bcrt1q"),
            ("p2sh-segwit", BIP48_P2SH, "sh(wsh(sortedmulti(2,", "2"),
            ("legacy", BIP48_LEGACY, "sh(sortedmulti(2,", None),
        ]
        for addr_type, path, prefix, addr_prefix in cases:
            wallet = self._blank(f"type_{addr_type}")
            x1, x2 = self._two_hdkeys(wallet)
            res = wallet.createmultisigdescriptor(2, self._keys([x1, x2], path=path), {"type": addr_type})
            assert res["descs"][0].startswith(prefix)
            addr = wallet.getnewaddress("", addr_type)
            if addr_prefix:
                assert addr.startswith(addr_prefix)
            funding.sendtoaddress(addr, 4)
            self.generate(self.nodes[0], 1)
            sent = wallet.send(outputs={funding.getnewaddress(): 1}, options={"change_type": addr_type})
            assert sent["complete"]

        wallet = self._blank("type_default_path")
        x1, x2 = self._two_hdkeys(wallet)
        res = wallet.createmultisigdescriptor(2, [{"hdkey": x1}, {"hdkey": x2}])
        assert "/48h/1h/0h/2h]" in res["descs"][0]

    def test_taproot_musig2(self):
        self.log.info("Test n-of-n bech32m as tr(musig)")
        funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        wallet = self._blank("type_bech32m_musig")
        x1, x2 = self._two_hdkeys(wallet)
        res = wallet.createmultisigdescriptor(
            2, self._keys([x1, x2], path=BIP48_BECH32M), {"type": "bech32m"},
        )
        assert res["descs"][0].startswith("tr(musig(")
        assert "/48h/1h/0h/3h]" in res["descs"][0]
        addr = wallet.getnewaddress("", "bech32m")
        assert addr.startswith("bcrt1p")
        info = wallet.getaddressinfo(addr)
        assert_equal(info["ischange"], False)
        funding.sendtoaddress(addr, 4)
        self.generate(self.nodes[0], 1)
        sent = wallet.send(outputs={funding.getnewaddress(): 1}, options={"change_type": "bech32m"})
        assert sent["complete"]

        default_path = self._blank("type_bech32m_default_path")
        d1, d2 = self._two_hdkeys(default_path)
        res = default_path.createmultisigdescriptor(2, [{"hdkey": d1}, {"hdkey": d2}], {"type": "bech32m"})
        assert "/48h/1h/0h/3h]" in res["descs"][0]
        assert res["descs"][0].startswith("tr(musig(")

    def test_taproot_sortedmulti_a(self):
        self.log.info("Test m-of-n bech32m as tr(NUMS,sortedmulti_a)")
        funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        wallet = self._blank("type_bech32m_multi_a")
        x1, x2, x3 = wallet.addhdkey()["xpub"], wallet.addhdkey()["xpub"], wallet.addhdkey()["xpub"]
        res = wallet.createmultisigdescriptor(
            2, self._keys([x1, x2, x3], path=BIP48_BECH32M), {"type": "bech32m"},
        )
        assert "sortedmulti_a(2," in res["descs"][0]
        assert res["descs"][0].startswith("tr(")
        assert "musig(" not in res["descs"][0]
        addr = wallet.getnewaddress("", "bech32m")
        assert addr.startswith("bcrt1p")
        funding.sendtoaddress(addr, 4)
        self.generate(self.nodes[0], 1)
        sent = wallet.send(outputs={funding.getnewaddress(): 1}, options={"change_type": "bech32m"})
        assert sent["complete"]

    def test_internal_and_account(self):
        self.log.info("Test internal and account options")
        wallet = self._blank("opts_internal")
        x1, x2 = self._two_hdkeys(wallet)
        res = wallet.createmultisigdescriptor(2, self._keys([x1, x2]), {"internal": False})
        assert_equal(len(res["descs"]), 1)
        recv = wallet.getnewaddress("", "bech32")
        assert_raises_rpc_error(-4, "Error: This wallet has no available keys", wallet.getrawchangeaddress, "bech32")

        res_change = wallet.createmultisigdescriptor(2, self._keys([x1, x2]), {"internal": True})
        assert_equal(len(res_change["descs"]), 1)
        change = wallet.getrawchangeaddress("bech32")
        assert recv != change

        acct = self._blank("opts_account")
        a1, a2 = self._two_hdkeys(acct)
        res = acct.createmultisigdescriptor(2, [{"hdkey": a1}, {"hdkey": a2}], {"account": 1})
        assert "/48h/1h/1h/2h]" in res["descs"][0]

    def test_multiple_hdkeys_require_explicit(self):
        self.log.info("Test ambiguous unused HD keys require hdkey")
        wallet = self._blank("ambiguous")
        wallet.addhdkey()
        wallet.addhdkey()
        assert_raises_rpc_error(
            -5, "Unable to determine which HD key to use. Please specify with 'hdkey'",
            wallet.createmultisigdescriptor, 2, [BIP48_BECH32, BIP48_BECH32],
        )

    def test_encrypted(self):
        self.log.info("Test createmultisigdescriptor on an encrypted wallet")
        self.nodes[0].createwallet("enc_ms", blank=True, passphrase="pass")
        wallet = self.nodes[0].get_wallet_rpc("enc_ms")
        assert_raises_rpc_error(
            -13, "Error: Please enter the wallet passphrase with walletpassphrase first.",
            wallet.addhdkey,
        )
        with WalletUnlock(wallet, "pass"):
            x1, x2 = self._two_hdkeys(wallet)
        assert_raises_rpc_error(
            -13, "Error: Please enter the wallet passphrase with walletpassphrase first.",
            wallet.createmultisigdescriptor, 2, self._keys([x1, x2]),
        )
        with WalletUnlock(wallet, "pass"):
            res = wallet.createmultisigdescriptor(2, self._keys([x1, x2]))
            assert_equal(res["nrequired"], 2)
            wallet.getnewaddress("", "bech32")

    def test_cross_wallet_2of2(self):
        self.log.info("Test 2-of-2 partial signing across two wallets")
        funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        w1 = self._blank("cross_a")
        w2 = self._blank("cross_b")
        w1.addhdkey()
        w2.addhdkey()
        k1 = w1.derivehdkey(BIP48_BECH32, private=True)
        k2 = w2.derivehdkey(BIP48_BECH32, private=True)
        expr1_prv = f"{k1['origin']}{k1['xprv']}/<0;1>/*"
        expr1_pub = f"{k1['origin']}{k1['xpub']}/<0;1>/*"
        expr2_prv = f"{k2['origin']}{k2['xprv']}/<0;1>/*"
        expr2_pub = f"{k2['origin']}{k2['xpub']}/<0;1>/*"
        desc_w1 = descsum_create(f"wsh(sortedmulti(2,{expr1_prv},{expr2_pub}))")
        desc_w2 = descsum_create(f"wsh(sortedmulti(2,{expr1_pub},{expr2_prv}))")
        assert_equal(w1.importdescriptors([{"desc": desc_w1, "timestamp": "now", "active": True}])[0]["success"], True)
        assert_equal(w2.importdescriptors([{"desc": desc_w2, "timestamp": "now", "active": True}])[0]["success"], True)

        addr1 = w1.getnewaddress("", "bech32")
        addr2 = w2.getnewaddress("", "bech32")
        assert_equal(addr1, addr2)

        funding.sendtoaddress(addr1, 6)
        self.generate(self.nodes[0], 1)
        dest = funding.getnewaddress()
        psbt = w1.walletcreatefundedpsbt([], {dest: 1})["psbt"]
        first = w1.walletprocesspsbt(psbt)
        assert not first["complete"]
        second = w2.walletprocesspsbt(first["psbt"])
        assert second["complete"]
        assert w2.testmempoolaccept([second["hex"]])[0]["allowed"]

    def test_mixed_key_wallet(self):
        self.log.info("Test mixed-key createwallet and createmultisigdescriptor with a signer fingerprint")
        self.nodes[1].createwallet(wallet_name="mixed_ms", disable_private_keys=False, external_signer=True)
        wallet = self.nodes[1].get_wallet_rpc("mixed_ms")
        info = wallet.getwalletinfo()
        assert_equal(info["external_signer"], True)
        assert_equal(info["private_keys_enabled"], True)
        unused = [k for k in wallet.gethdkeys() if any(d["desc"].startswith("unused(") for d in k["descriptors"])]
        assert_equal(len(unused), 1)

        assert_raises_rpc_error(
            -4, "No external signer with fingerprint deadbeef",
            wallet.createmultisigdescriptor, 2, [BIP48_BECH32, "deadbeef"],
        )
        assert_raises_rpc_error(
            -8, "fingerprint must be 8 hex characters",
            wallet.createmultisigdescriptor, 2, [BIP48_BECH32, {"fingerprint": "gggggggg"}],
        )

        res = wallet.createmultisigdescriptor(2, [BIP48_BECH32, "00000001"])
        assert_equal(res["nrequired"], 2)
        joined = "".join(res["descs"])
        assert "00000001" in joined
        assert "sortedmulti(2," in joined
        addr = wallet.getnewaddress("", "bech32")
        assert addr.startswith("bcrt1")
        info = wallet.getaddressinfo(addr)
        assert_equal(info["sigsrequired"], 2)
        assert_equal(info["solvable"], True)

        obj = wallet.createmultisigdescriptor(
            2,
            [BIP48_BECH32, {"fingerprint": "00000001", "path": "m/48h/1h/1h/2h"}],
            {"type": "bech32", "account": 1},
        )
        assert "00000001" in "".join(obj["descs"])

    def test_airgapped_xpub(self):
        self.log.info("Test air-gapped xpub (device not connected)")
        funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        offline = self._blank("air_src")
        offline.addhdkey()
        derived = offline.derivehdkey(BIP48_BECH32)
        origin = derived["origin"]
        fpr = origin[1:9]
        xpub = derived["xpub"]
        wallet = self._blank("air_ms")
        local = wallet.addhdkey()["xpub"]
        res = wallet.createmultisigdescriptor(2, [
            {"path": BIP48_BECH32, "hdkey": local},
            {"path": BIP48_BECH32, "fingerprint": fpr, "xpub": xpub},
        ])
        assert_equal(res["nrequired"], 2)
        assert fpr in "".join(res["descs"])
        addr = wallet.getnewaddress("", "bech32")
        funding.sendtoaddress(addr, 3)
        self.generate(self.nodes[0], 1)
        dest = funding.getnewaddress()
        first = wallet.walletcreatefundedpsbt([], {dest: 1})["psbt"]
        signed = wallet.walletprocesspsbt(first)
        assert not signed["complete"]
        # The other seed lives in `offline` but at a different descriptor; combine
        # is covered by test_cross_wallet_2of2. Here we only need an incomplete PSBT.

    def test_watchonly(self):
        self.log.info("Test watch-only external-signer wallets cannot use local keys")
        self.nodes[1].createwallet(wallet_name="hww_ms", disable_private_keys=True, external_signer=True)
        wallet = self.nodes[1].get_wallet_rpc("hww_ms")
        assert_equal(wallet.getwalletinfo()["external_signer"], True)
        assert_equal(wallet.getwalletinfo()["private_keys_enabled"], False)
        assert_raises_rpc_error(
            -4, "Watch-only wallets cannot use local keys; specify a signer fingerprint",
            wallet.createmultisigdescriptor, 1, [BIP48_BECH32],
        )
        res = wallet.createmultisigdescriptor(1, ["00000001"])
        assert_equal(res["nrequired"], 1)
        assert "00000001" in res["descs"][0]


if __name__ == "__main__":
    WalletCreateMultisigDescriptorTest(__file__).main()
