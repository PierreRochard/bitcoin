#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Advanced Taproot / MuSig2 edge cases through one wallet (FillPSBT loop)
and split wallets (nonce/partial protocol)."""

from test_framework.descriptors import descsum_create
from test_framework.key import H_POINT
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_not_equal,
)

PATH = "m/48h/1h/0h/3h"


class WalletTaprootMultisigEdgeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-keypool=10"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.generate(self.nodes[0], 101)
        self.def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.n = 0

        self.test_single_wallet_send(
            "aggregate-then-derive musig",
            "tr(musig($0,$1,$2)/<0;1>/*)",
            3,
        )
        self.test_single_wallet_send(
            "derive-then-aggregate musig",
            "tr(musig($0/<0;1>/*,$1/<1;2>/*,$2/<2;3>/*))",
            3,
        )
        self.test_single_wallet_send(
            "rawtr musig",
            "rawtr(musig($0,$1)/<0;1>/*)",
            2,
        )
        self.test_single_wallet_send(
            "3-index multipath",
            "tr(musig($0/<0;1;2>/*,$1/<0;1;2>/*,$2/<0;1;2>/*))",
            3,
            has_change=False,
        )
        self.test_single_wallet_send(
            "musig in script leaf",
            "tr($H,pk(musig($0,$1,$2)/<0;1>/*))",
            3,
            scriptpath=True,
        )
        self.test_single_wallet_send(
            "two musig leaves",
            "tr($H,{pk(musig($0,$1)/<0;1>/*),pk(musig($2,$3)/0/*)})",
            4,
            scriptpath=True,
        )
        self.test_single_wallet_send(
            "key-path musig plus nested leaves",
            "tr(musig($0,$1,$2)/<3;4>/*,{pk(musig($0,$1)/<5;6>/*),pk(musig($1,$2)/7/*)})",
            3,
        )
        self.test_watch_forces_scriptpath()
        self.test_single_wallet_send(
            "miniscript after(1) around musig",
            "tr($H,and_v(v:pk(musig($0,$1)/<0;1>/*),after(1)))",
            2,
            scriptpath=True,
            locktime=True,
        )
        self.test_single_wallet_send(
            "pkh(musig) after(1)",
            "tr($H,and_v(v:pkh(musig($0,$1,$2)/<0;1>/*),after(1)))",
            3,
            scriptpath=True,
            locktime=True,
        )
        self.test_single_wallet_send(
            "deep sortedmulti_a tree",
            "tr($1/<0;1>/*,{pk($1/<0;1>/*),{pk($1/<0;1>/*),sortedmulti_a(2,$0/<0;1>/*,$1/<0;1>/*,$2/<0;1>/*)}})",
            3,
        )
        self.test_sighash_anyonecanpay()
        self.test_concurrent_sessions()
        self.test_protocol_failures()
        self.test_large_sortedmulti_a()

    def _blank(self, name):
        self.nodes[0].createwallet(wallet_name=name, blank=True)
        return self.nodes[0].get_wallet_rpc(name)

    def _one_wallet_keys(self, n):
        name = f"edge_{self.n}"
        self.n += 1
        wallet = self._blank(name)
        keys = []
        for _ in range(n):
            xpub = wallet.addhdkey()["xpub"]
            info = wallet.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"] + info["xprv"], info["origin"] + info["xpub"]))
        return wallet, keys

    def _subst(self, pat, keys, priv_mask=None):
        desc = pat.replace("$H", H_POINT)
        for i in range(len(keys) - 1, -1, -1):
            use_priv = priv_mask is None or i in priv_mask
            desc = desc.replace(f"${i}", keys[i][0] if use_priv else keys[i][1])
        return descsum_create(desc)

    def test_single_wallet_send(self, comment, pat, nkeys, scriptpath=False, locktime=False, has_change=True):
        self.log.info(f"Single-wallet send: {comment}")
        wallet, keys = self._one_wallet_keys(nkeys)
        desc = self._subst(pat, keys)
        res = wallet.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])
        for r in res:
            assert_equal(r["success"], True)

        addr = wallet.getnewaddress("", "bech32m")
        assert addr.startswith("bcrt1p")
        if has_change and "<" in pat and ";" in pat:
            change = wallet.getrawchangeaddress("bech32m")
            assert change.startswith("bcrt1p")
            assert_not_equal(addr, change)

        self.def_wallet.sendtoaddress(addr, 4)
        self.generate(self.nodes[0], 1)

        options = {}
        if locktime:
            options["locktime"] = self.nodes[0].getblockcount()
        dest = self.def_wallet.getnewaddress()
        if has_change:
            options["change_type"] = "bech32m"
            sent = wallet.send(outputs={dest: 1}, options=options)
        else:
            amt = wallet.getbalances()["mine"]["trusted"]
            options["subtract_fee_from_outputs"] = [0]
            sent = wallet.send(outputs={dest: amt}, options=options)
        assert sent["complete"]
        raw = sent.get("hex") or wallet.gettransaction(sent["txid"])["hex"]
        dec = self.nodes[0].decoderawtransaction(raw)
        witness = dec["vin"][0]["txinwitness"]
        if scriptpath:
            assert_greater_than(len(witness), 1)
        else:
            assert_equal(len(witness), 1)
        self.generate(self.nodes[0], 1)

    def test_watch_forces_scriptpath(self):
        self.log.info("Watch-only participant forces nested musig script-path")
        wallet, keys = self._one_wallet_keys(3)
        pat = "tr(musig($0,$1,$2)/<3;4>/*,{pk(musig($0,$1)/<5;6>/*),pk(musig($1,$2)/7/*)})"
        # $0 public only: key-path and first leaf cannot finish.
        desc = self._subst(pat, keys, priv_mask={1, 2})
        res = wallet.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])
        for r in res:
            assert_equal(r["success"], True)
        addr = wallet.getnewaddress("", "bech32m")
        self.def_wallet.sendtoaddress(addr, 4)
        self.generate(self.nodes[0], 1)
        sent = wallet.send(outputs={self.def_wallet.getnewaddress(): 1}, options={"change_type": "bech32m"})
        assert sent["complete"]
        raw = sent.get("hex") or wallet.gettransaction(sent["txid"])["hex"]
        witness = self.nodes[0].decoderawtransaction(raw)["vin"][0]["txinwitness"]
        assert_greater_than(len(witness), 1)

    def test_sighash_anyonecanpay(self):
        self.log.info("MuSig2 with ALL|ANYONECANPAY")
        wallet, keys = self._one_wallet_keys(2)
        desc = self._subst("tr(musig($0,$1)/<0;1>/*)", keys)
        assert_equal(wallet.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = wallet.getnewaddress("", "bech32m")
        self.def_wallet.sendtoaddress(addr, 4)
        self.generate(self.nodes[0], 1)
        utxo = wallet.listunspent()[0]
        psbt = wallet.walletcreatefundedpsbt(
            outputs=[{self.def_wallet.getnewaddress(): 1}],
            inputs=[utxo],
            change_type="bech32m",
        )["psbt"]
        proc = wallet.walletprocesspsbt(psbt=psbt, sighashtype="ALL|ANYONECANPAY")
        assert proc["complete"]
        dec = self.nodes[0].decoderawtransaction(proc["hex"])
        sig = bytes.fromhex(dec["vin"][0]["txinwitness"][0])
        assert_equal(len(sig), 65)
        assert_equal(sig[-1], 0x81)

    def test_concurrent_sessions(self):
        self.log.info("Two MuSig2 sessions on the same UTXO use distinct nonces")
        wallet, keys = self._one_wallet_keys(2)
        desc = self._subst("tr(musig($0,$1)/<0;1>/*)", keys)
        assert_equal(wallet.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = wallet.getnewaddress("", "bech32m")
        self.def_wallet.sendtoaddress(addr, 4)
        self.generate(self.nodes[0], 1)
        utxo = wallet.listunspent()[0]
        psbt = wallet.walletcreatefundedpsbt(
            outputs=[{self.def_wallet.getnewaddress(): 1}],
            inputs=[utxo],
            change_type="bech32m",
            changePosition=1,
        )["psbt"]
        a = wallet.walletprocesspsbt(psbt=psbt, finalize=False)
        b = wallet.walletprocesspsbt(psbt=psbt, finalize=False)
        # One-wallet FillPSBT loop completes both rounds; witnesses must still differ.
        dec_a = self.nodes[0].decodepsbt(a["psbt"])
        dec_b = self.nodes[0].decodepsbt(b["psbt"])
        fa = self.nodes[0].finalizepsbt(a["psbt"])
        fb = self.nodes[0].finalizepsbt(b["psbt"])
        assert fa["complete"] and fb["complete"]
        wa = self.nodes[0].decoderawtransaction(fa["hex"])["vin"][0]["txinwitness"]
        wb = self.nodes[0].decoderawtransaction(fb["hex"])["vin"][0]["txinwitness"]
        assert_not_equal(wa, wb)
        # If the loop left nonces visible, they must not be reused.
        if "musig2_pubnonces" in dec_a["inputs"][0] and "musig2_pubnonces" in dec_b["inputs"][0]:
            assert_not_equal(dec_a["inputs"][0]["musig2_pubnonces"], dec_b["inputs"][0]["musig2_pubnonces"])

    def test_protocol_failures(self):
        self.log.info("Split-wallet missing nonce / missing partial / finalize-without-partials")
        keys = []
        wallets = []
        for i in range(3):
            w = self._blank(f"split_{self.n}_{i}")
            xpub = w.addhdkey()["xpub"]
            info = w.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"] + info["xprv"], info["origin"] + info["xpub"]))
            wallets.append(w)
        self.n += 1
        pat = "tr(musig($0,$1,$2)/<0;1>/*)"
        for i, w in enumerate(wallets):
            desc = self._subst(pat, keys, priv_mask={i})
            assert_equal(w.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)

        addr = wallets[0].getnewaddress("", "bech32m")
        assert_equal(addr, wallets[1].getnewaddress("", "bech32m"))
        self.def_wallet.sendtoaddress(addr, 4)
        self.generate(self.nodes[0], 1)
        utxo = wallets[0].listunspent()[0]
        psbt = wallets[0].walletcreatefundedpsbt(
            outputs=[{self.def_wallet.getnewaddress(): 1}],
            inputs=[utxo],
            change_type="bech32m",
            changePosition=1,
        )["psbt"]

        def process(w, p):
            return w.walletprocesspsbt(psbt=p, finalize=False)["psbt"]

        two_nonces = self.nodes[0].combinepsbt([process(wallets[i], psbt) for i in range(2)])
        dec = self.nodes[0].decodepsbt(two_nonces)
        assert_equal(len(dec["inputs"][0].get("musig2_pubnonces", [])), 2)
        proc = wallets[0].walletprocesspsbt(psbt=two_nonces, finalize=False)
        assert_equal(proc["complete"], False)
        assert "musig2_partial_sigs" not in self.nodes[0].decodepsbt(proc["psbt"])["inputs"][0]

        all_nonces = self.nodes[0].combinepsbt([process(wallets[i], psbt) for i in range(3)])
        finalized = self.nodes[0].finalizepsbt(all_nonces)
        assert_equal(finalized["complete"], False)
        dec = self.nodes[0].decodepsbt(all_nonces)
        assert "musig2_pubnonces" in dec["inputs"][0]
        assert "musig2_partial_sigs" not in dec["inputs"][0]

        partial_psbts = [process(wallets[i], all_nonces) for i in range(3)]
        two_psigs = self.nodes[0].combinepsbt(partial_psbts[:2])
        finalized = self.nodes[0].finalizepsbt(two_psigs)
        assert_equal(finalized["complete"], False)
        dec = self.nodes[0].decodepsbt(two_psigs)
        assert_equal(len(dec["inputs"][0]["musig2_partial_sigs"]), 2)

        all_psigs = self.nodes[0].combinepsbt(partial_psbts)
        dec = self.nodes[0].decodepsbt(all_psigs)
        assert_equal(len(dec["inputs"][0]["musig2_partial_sigs"]), 3)
        finalized = self.nodes[0].finalizepsbt(all_psigs)
        assert finalized["complete"]
        self.nodes[0].sendrawtransaction(finalized["hex"])
        self.generate(self.nodes[0], 1)

    def test_large_sortedmulti_a(self):
        self.log.info("sortedmulti_a with NUMS padding")
        wallet, keys = self._one_wallet_keys(1)
        pads = ",".join(["$H"] * 32)
        pat = f"tr($H,sortedmulti_a(1,{pads},$0/<0;1>/*))"
        desc = self._subst(pat, keys)
        assert_equal(wallet.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = wallet.getnewaddress("", "bech32m")
        self.def_wallet.sendtoaddress(addr, 4)
        self.generate(self.nodes[0], 1)
        sent = wallet.send(outputs={self.def_wallet.getnewaddress(): 1}, options={"change_type": "bech32m"})
        assert sent["complete"]
        raw = sent.get("hex") or wallet.gettransaction(sent["txid"])["hex"]
        witness = self.nodes[0].decoderawtransaction(raw)["vin"][0]["txinwitness"]
        assert_greater_than(len(witness), 1)


if __name__ == "__main__":
    WalletTaprootMultisigEdgeTest(__file__).main()
