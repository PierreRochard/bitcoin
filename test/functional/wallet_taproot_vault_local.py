#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regtest matrix: Taproot vault from computer HD seeds only.

createmultisigdescriptor(type=bech32m, fallback_older=N) with n addhdkey
seeds. Immediate spend is n-of-n MuSig2 (witness length 1). After older(N),
any m of those seeds can recover on the script path. No hardware.
"""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

PATH = "m/48h/1h/0h/3h"
POLICIES = [(m, n) for n in (2, 3, 4) for m in range(1, n + 1)]
NOT_FINAL = "non-BIP68-final"


class WalletTaprootVaultLocalTest(BitcoinTestFramework):
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
        self.test_rpc_matrix_keypath()
        self.test_rpc_matrix_recovery()
        self.test_keypath_after_csv()
        self.test_split_wallets_keypath()
        self.test_split_wallets_recovery()
        self.test_older_2_mempool_bip68()

    def _blank(self, name):
        self.nodes[0].createwallet(wallet_name=name, blank=True)
        return self.nodes[0].get_wallet_rpc(name)

    def _coord(self, nkeys):
        w = self._blank(f"coord_{self.n}")
        self.n += 1
        xpubs = [w.addhdkey()["xpub"] for _ in range(nkeys)]
        specs = [{"path": PATH, "hdkey": x} for x in xpubs]
        return w, xpubs, specs

    def _derived(self, wallet, xpubs):
        keys = []
        for xpub in xpubs:
            info = wallet.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"] + info["xprv"], info["origin"] + info["xpub"]))
        return keys

    def _vault_pat(self, m, n, older):
        inner = ",".join(f"${i}/<0;1>/*" for i in range(n))
        return f"tr(musig({inner}),and_v(v:older({older}),multi_a({m},{inner})))"

    def _subst(self, pat, keys, priv_mask=None):
        desc = pat
        for i in range(len(keys) - 1, -1, -1):
            use_priv = priv_mask is None or i in priv_mask
            desc = desc.replace(f"${i}", keys[i][0] if use_priv else keys[i][1])
        return descsum_create(desc)

    def _witness(self, raw_or_txid, wallet=None):
        raw = raw_or_txid
        if wallet is not None and len(raw) < 128:
            raw = wallet.gettransaction(raw)["hex"]
        return self.nodes[0].decoderawtransaction(raw)["vin"][0]["txinwitness"]

    def _fund_to(self, addr, amount=5):
        self.def_wallet.sendtoaddress(addr, amount)
        self.generate(self.nodes[0], 1)

    def _assert_vault_desc(self, desc, m, older):
        assert "tr(musig(" in desc
        assert f"older({older})" in desc
        assert f"multi_a({m}," in desc

    def test_rpc_matrix_keypath(self):
        self.log.info("createmultisigdescriptor all-local vault: immediate MuSig2 for every m-of-n")
        for m, n in POLICIES:
            self.log.info(f"  key-path {m}-of-{n}")
            w, xpubs, specs = self._coord(n)
            res = w.createmultisigdescriptor(m, specs, {"type": "bech32m", "fallback_older": 1})
            assert_equal(res["nrequired"], m)
            assert_equal(res["fallback_older"], 1)
            self._assert_vault_desc(res["descs"][0], m, 1)
            addr = w.getnewaddress("", "bech32m")
            assert addr.startswith("bcrt1p")
            self._fund_to(addr)
            sent = w.send(outputs={self.def_wallet.getnewaddress(): 1}, options={"change_type": "bech32m"})
            assert sent["complete"]
            raw = sent.get("hex") or w.gettransaction(sent["txid"])["hex"]
            assert_equal(len(self._witness(raw)), 1)
            self.generate(self.nodes[0], 1)

    def test_rpc_matrix_recovery(self):
        self.log.info("Lost seeds: m-of-n script-path after older(1); too soon and m-1 fail")
        for m, n in POLICIES:
            self.log.info(f"  recover {m}-of-{n}")
            coord, xpubs, specs = self._coord(n)
            res = coord.createmultisigdescriptor(m, specs, {"type": "bech32m", "fallback_older": 1})
            self._assert_vault_desc(res["descs"][0], m, 1)
            keys = self._derived(coord, xpubs)
            rec = self._blank(f"rec_{self.n}")
            self.n += 1
            pat = self._vault_pat(m, n, 1)
            desc = self._subst(pat, keys, priv_mask=set(range(m)))
            assert_equal(rec.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
            addr = rec.getnewaddress("", "bech32m")
            assert_equal(addr, coord.getnewaddress("", "bech32m"))
            self._fund_to(addr)
            utxo = rec.listunspent()[0]
            dest = self.def_wallet.getnewaddress()
            amt = utxo["amount"]

            def process(seq):
                psbt = rec.walletcreatefundedpsbt(
                    [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": seq}],
                    [{dest: amt}],
                    0,
                    {"change_type": "bech32m", "subtractFeeFromOutputs": [0], "replaceable": False},
                )["psbt"]
                return rec.walletprocesspsbt(psbt=psbt)

            too_soon = process(0xFFFFFFFE)
            if m < n:
                assert_equal(too_soon["complete"], False)
                self.generate(self.nodes[0], 1)
                ready = process(1)
                assert ready["complete"]
                witness = self._witness(ready["hex"])
                assert_greater_than(len(witness), 1)
                self.nodes[0].sendrawtransaction(ready["hex"])
                self.generate(self.nodes[0], 1)
            else:
                # n-of-n: every seed is present, so the key-path spends immediately.
                assert too_soon["complete"]
                assert_equal(len(self._witness(too_soon["hex"])), 1)

            if m >= 2:
                short = self._blank(f"short_{self.n}")
                self.n += 1
                desc_short = self._subst(pat, keys, priv_mask=set(range(m - 1)))
                assert_equal(short.importdescriptors([{"desc": desc_short, "timestamp": "now", "active": True}])[0]["success"], True)
                addr_s = short.getnewaddress("", "bech32m")
                self._fund_to(addr_s)
                self.generate(self.nodes[0], 1)
                utxo_s = short.listunspent()[0]
                psbt = short.walletcreatefundedpsbt(
                    [{"txid": utxo_s["txid"], "vout": utxo_s["vout"], "sequence": 1}],
                    [{dest: utxo_s["amount"]}],
                    0,
                    {"change_type": "bech32m", "subtractFeeFromOutputs": [0], "replaceable": False},
                )["psbt"]
                proc = short.walletprocesspsbt(psbt=psbt)
                assert_equal(proc["complete"], False)

    def test_keypath_after_csv(self):
        self.log.info("After CSV matures, all-local 2-of-3 still spends on the MuSig2 key-path")
        w, xpubs, specs = self._coord(3)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        addr = w.getnewaddress("", "bech32m")
        self._fund_to(addr)
        self.generate(self.nodes[0], 1)
        sent = w.send(outputs={self.def_wallet.getnewaddress(): 1}, options={"change_type": "bech32m"})
        assert sent["complete"]
        raw = sent.get("hex") or w.gettransaction(sent["txid"])["hex"]
        assert_equal(len(self._witness(raw)), 1)
        self.generate(self.nodes[0], 1)

    def test_split_wallets_keypath(self):
        self.log.info("Three computers, one seed each: 2-of-3 vault key-path via combined PSBTs")
        keys = []
        wallets = []
        for i in range(3):
            w = self._blank(f"split_kp_{self.n}_{i}")
            xpub = w.addhdkey()["xpub"]
            info = w.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"] + info["xprv"], info["origin"] + info["xpub"]))
            wallets.append(w)
        self.n += 1
        pat = self._vault_pat(2, 3, 1)
        for i, w in enumerate(wallets):
            desc = self._subst(pat, keys, priv_mask={i})
            assert_equal(w.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = wallets[0].getnewaddress("", "bech32m")
        assert_equal(addr, wallets[1].getnewaddress("", "bech32m"))
        assert_equal(addr, wallets[2].getnewaddress("", "bech32m"))
        self._fund_to(addr)
        utxo = wallets[0].listunspent()[0]
        dest = self.def_wallet.getnewaddress()
        psbt = wallets[0].walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "replaceable": False, "subtractFeeFromOutputs": [0]},
        )["psbt"]

        def process(w, p):
            return w.walletprocesspsbt(psbt=p, finalize=False)["psbt"]

        all_nonces = self.nodes[0].combinepsbt([process(w, psbt) for w in wallets])
        partials = [process(w, all_nonces) for w in wallets]
        combined = self.nodes[0].combinepsbt(partials)
        finalized = self.nodes[0].finalizepsbt(combined)
        assert finalized["complete"]
        assert_equal(len(self._witness(finalized["hex"])), 1)
        self.nodes[0].sendrawtransaction(finalized["hex"])
        self.generate(self.nodes[0], 1)

    def test_split_wallets_recovery(self):
        self.log.info("Two computers recover a 2-of-3 vault after older(1); third seed is missing")
        keys = []
        wallets = []
        for i in range(3):
            w = self._blank(f"split_rec_{self.n}_{i}")
            xpub = w.addhdkey()["xpub"]
            info = w.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"] + info["xprv"], info["origin"] + info["xpub"]))
            wallets.append(w)
        self.n += 1
        pat = self._vault_pat(2, 3, 1)
        rec = wallets[:2]
        for i, w in enumerate(rec):
            desc = self._subst(pat, keys, priv_mask={i})
            assert_equal(w.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = rec[0].getnewaddress("", "bech32m")
        assert_equal(addr, rec[1].getnewaddress("", "bech32m"))
        self._fund_to(addr)
        utxo = rec[0].listunspent()[0]
        dest = self.def_wallet.getnewaddress()
        amt = utxo["amount"]

        def funded(seq):
            return rec[0].walletcreatefundedpsbt(
                [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": seq}],
                [{dest: amt}],
                0,
                {"change_type": "bech32m", "subtractFeeFromOutputs": [0], "replaceable": False},
            )["psbt"]

        too_soon_base = funded(0xFFFFFFFE)
        too_soon = self.nodes[0].combinepsbt(
            [w.walletprocesspsbt(psbt=too_soon_base, finalize=False)["psbt"] for w in rec]
        )
        assert_equal(self.nodes[0].finalizepsbt(too_soon)["complete"], False)

        self.generate(self.nodes[0], 1)
        ready = funded(1)
        combined = self.nodes[0].combinepsbt(
            [w.walletprocesspsbt(psbt=ready, finalize=False)["psbt"] for w in rec]
        )
        finalized = self.nodes[0].finalizepsbt(combined)
        assert finalized["complete"]
        assert_greater_than(len(self._witness(finalized["hex"])), 1)
        self.nodes[0].sendrawtransaction(finalized["hex"])
        self.generate(self.nodes[0], 1)

    def test_older_2_mempool_bip68(self):
        self.log.info("older(2): recovery is signed at nSequence=2 but BIP68-invalid until 2 confirmations")
        coord, xpubs, specs = self._coord(3)
        coord.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 2})
        keys = self._derived(coord, xpubs)
        rec = self._blank(f"old2_{self.n}")
        self.n += 1
        desc = self._subst(self._vault_pat(2, 3, 2), keys, priv_mask={0, 1})
        assert_equal(rec.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = rec.getnewaddress("", "bech32m")
        self.def_wallet.sendtoaddress(addr, 5)
        self.generate(self.nodes[0], 1)
        utxo = rec.listunspent()[0]
        dest = self.def_wallet.getnewaddress()
        psbt = rec.walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 2}],
            [{dest: utxo["amount"]}],
            0,
            {"change_type": "bech32m", "subtractFeeFromOutputs": [0], "replaceable": False},
        )["psbt"]
        proc = rec.walletprocesspsbt(psbt=psbt)
        assert proc["complete"]
        assert_raises_rpc_error(-26, NOT_FINAL, self.nodes[0].sendrawtransaction, proc["hex"])
        self.generate(self.nodes[0], 1)
        self.nodes[0].sendrawtransaction(proc["hex"])
        self.generate(self.nodes[0], 1)


if __name__ == "__main__":
    WalletTaprootVaultLocalTest(__file__).main()
