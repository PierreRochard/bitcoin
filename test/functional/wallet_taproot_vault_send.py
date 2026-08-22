#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""RPC send / walletcreatefundedpsbt / bumpfee for Scrooge vaults.

Asserts nSequence, vsize, fee, replaceable key-path bump, recovery too early
via send(), and that NUMS m-of-n is not charged as a key-path.
"""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import WalletUnlock

PATH = "m/48h/1h/0h/3h"
RBF_SEQUENCE = 0xFFFFFFFD


class WalletTaprootVaultSendTest(BitcoinTestFramework):
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
        self.test_send_keypath_rbf_and_bump()
        self.test_walletcreatefundedpsbt_sequence_fee()
        self.test_recovery_too_early_send()
        self.test_nums_send_not_keypath()
        self.test_send_two_outputs_and_sendall()
        self.test_fundrawtransaction_recovery_sequence()
        self.test_psbtbumpfee_and_recovery_bump()
        self.test_encrypted_send()
        self.test_backup_restore()
        self.test_airgapped_psbt_roundtrip()
        self.test_older_2_reorg_evicts_recovery()
        self.test_sendmany_sendtoaddress_unload_load()
        self.test_older_144_and_signraw_musig()
        self.test_watchonly_xpub_vault_psbt()
        self.test_encrypted_recovery()
        self.test_nums_bumpfee()
        self.test_airgapped_recovery_psbt()
        self.test_multi_input_send()

    def _blank(self, name, **kwargs):
        self.nodes[0].createwallet(wallet_name=name, blank=True, **kwargs)
        return self.nodes[0].get_wallet_rpc(name)

    def _coord(self, nkeys):
        w = self._blank(f"send_coord_{self.n}")
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

    def _fund(self, addr, amount=5):
        self.def_wallet.sendtoaddress(addr, amount)
        self.generate(self.nodes[0], 1)

    def _decode_send(self, wallet, raw_or_result):
        if isinstance(raw_or_result, dict):
            raw = raw_or_result.get("hex") or wallet.gettransaction(raw_or_result["txid"])["hex"]
        elif len(raw_or_result) == 64:
            raw = wallet.gettransaction(raw_or_result)["hex"]
        else:
            raw = raw_or_result
        return self.nodes[0].decoderawtransaction(raw)

    def test_send_keypath_rbf_and_bump(self):
        self.log.info("send() key-path is BIP125 RBF, small vsize, and bumpfee replaces it")
        w, xpubs, specs = self._coord(3)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        addr = w.getnewaddress("", "bech32m")
        self._fund(addr)
        dest = self.def_wallet.getnewaddress()
        drafted = w.send(
            outputs={dest: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False, "replaceable": True},
        )
        assert drafted["complete"]
        dec = self._decode_send(w, drafted)
        assert_equal(dec["vin"][0]["sequence"], RBF_SEQUENCE)
        assert_equal(len(dec["vin"][0]["txinwitness"]), 1)
        assert_greater_than(180, dec["vsize"])
        sent = w.send(
            outputs={dest: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "replaceable": True},
        )
        assert sent["complete"]
        txid = sent["txid"]
        assert txid in self.nodes[0].getrawmempool()
        bumped = w.bumpfee(txid, {"fee_rate": 10})
        assert_equal(bumped["errors"], [])
        assert_greater_than(bumped["fee"], bumped["origfee"])
        assert bumped["txid"] in self.nodes[0].getrawmempool()
        assert txid not in self.nodes[0].getrawmempool()
        self.generate(self.nodes[0], 1)

    def test_walletcreatefundedpsbt_sequence_fee(self):
        self.log.info("walletcreatefundedpsbt: replaceable key-path is cheaper than sequence=1 recovery")
        w, xpubs, specs = self._coord(3)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        addr = w.getnewaddress("", "bech32m")
        self._fund(addr)
        utxo = w.listunspent()[0]
        dest = self.def_wallet.getnewaddress()
        kp = w.walletcreatefundedpsbt(
            [],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "replaceable": True, "fee_rate": 1},
        )
        rec = w.walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 1}],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "fee_rate": 1, "add_inputs": False},
        )
        assert_greater_than(rec["fee"], kp["fee"])
        kp_proc = w.walletprocesspsbt(psbt=kp["psbt"])
        assert kp_proc["complete"]
        kp_dec = self.nodes[0].decoderawtransaction(kp_proc["hex"])
        assert_equal(kp_dec["vin"][0]["sequence"], RBF_SEQUENCE)
        assert_equal(len(kp_dec["vin"][0]["txinwitness"]), 1)
        rec_proc = w.walletprocesspsbt(psbt=rec["psbt"])
        assert rec_proc["complete"]
        rec_dec = self.nodes[0].decoderawtransaction(rec_proc["hex"])
        assert_equal(rec_dec["vin"][0]["sequence"], 1)
        assert_greater_than(len(rec_dec["vin"][0]["txinwitness"]), 1)
        assert_greater_than(rec_dec["vsize"], kp_dec["vsize"])

    def test_recovery_too_early_send(self):
        self.log.info("send() with missing keys does not finalize; sequence=1 script-path does")
        coord, xpubs, specs = self._coord(3)
        coord.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        keys = self._derived(coord, xpubs)
        rec = self._blank(f"send_rec_{self.n}")
        self.n += 1
        desc = self._subst(self._vault_pat(2, 3, 1), keys, priv_mask={0, 1})
        assert_equal(rec.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = rec.getnewaddress("", "bech32m")
        self._fund(addr)
        dest = self.def_wallet.getnewaddress()
        too_soon = rec.send(
            outputs={dest: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False, "replaceable": True},
        )
        assert_equal(too_soon["complete"], False)
        assert "hex" not in too_soon or too_soon.get("complete") is False
        utxo = rec.listunspent()[0]
        ready = rec.send(
            outputs={dest: 1},
            options={
                "change_type": "bech32m",
                "fee_rate": 1,
                "add_to_wallet": False,
                "inputs": [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 1}],
                "add_inputs": False,
            },
        )
        assert ready["complete"]
        dec = self._decode_send(rec, ready)
        assert_equal(dec["vin"][0]["sequence"], 1)
        assert_greater_than(len(dec["vin"][0]["txinwitness"]), 1)

    def test_nums_send_not_keypath(self):
        self.log.info("NUMS sortedmulti_a send is not charged as a 1-signature key-path")
        w, xpubs, specs = self._coord(2)
        res = w.createmultisigdescriptor(1, specs, {"type": "bech32m"})
        assert "sortedmulti_a(1," in res["descs"][0]
        assert "musig(" not in res["descs"][0]
        addr = w.getnewaddress("", "bech32m")
        self._fund(addr)
        dest = self.def_wallet.getnewaddress()
        sent = w.send(
            outputs={dest: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False},
        )
        assert sent["complete"]
        dec = self._decode_send(w, sent)
        assert_greater_than(len(dec["vin"][0]["txinwitness"]), 1)
        assert_greater_than(dec["vsize"], 120)

    def test_send_two_outputs_and_sendall(self):
        self.log.info("send() two outputs and sendall from a Scrooge vault")
        w, xpubs, specs = self._coord(3)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        self._fund(w.getnewaddress("", "bech32m"), 8)
        dest_a = self.def_wallet.getnewaddress()
        dest_b = self.def_wallet.getnewaddress()
        two = w.send(
            outputs={dest_a: 1, dest_b: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False},
        )
        assert two["complete"]
        dec = self._decode_send(w, two)
        assert_equal(dec["vin"][0]["sequence"], RBF_SEQUENCE)
        assert_equal(len(dec["vin"][0]["txinwitness"]), 1)
        assert_greater_than(len(dec["vout"]), 1)
        swept = w.sendall(
            recipients=[self.def_wallet.getnewaddress()],
            fee_rate=1,
            add_to_wallet=False,
        )
        assert swept["complete"]
        sweep_dec = self._decode_send(w, swept)
        assert_equal(len(sweep_dec["vin"][0]["txinwitness"]), 1)

    def test_fundrawtransaction_recovery_sequence(self):
        self.log.info("fundrawtransaction + converttopsbt preserves recovery nSequence")
        w, xpubs, specs = self._coord(3)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        self._fund(w.getnewaddress("", "bech32m"))
        utxo = w.listunspent()[0]
        dest = self.def_wallet.getnewaddress()
        raw = w.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 1}],
            [{dest: 1}],
        )
        funded = w.fundrawtransaction(raw, {"change_type": "bech32m", "fee_rate": 1, "add_inputs": False})
        psbt = w.converttopsbt(funded["hex"])
        proc = w.walletprocesspsbt(psbt=psbt)
        assert proc["complete"]
        dec = self.nodes[0].decoderawtransaction(proc["hex"])
        assert_equal(dec["vin"][0]["sequence"], 1)
        assert_greater_than(len(dec["vin"][0]["txinwitness"]), 1)

    def test_psbtbumpfee_and_recovery_bump(self):
        self.log.info("psbtbumpfee on key-path; bumpfee preserves recovery nSequence")
        w, xpubs, specs = self._coord(3)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        addr = w.getnewaddress("", "bech32m")
        self._fund(addr, 8)
        self._fund(addr, 8)
        dest = self.def_wallet.getnewaddress()
        kp = w.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "replaceable": True})
        psbt_bump = w.psbtbumpfee(kp["txid"], {"fee_rate": 10})
        assert "psbt" in psbt_bump
        assert_greater_than(psbt_bump["fee"], psbt_bump["origfee"])
        signed_bump = w.walletprocesspsbt(psbt=psbt_bump["psbt"])
        assert signed_bump["complete"]

        utxo = [u for u in w.listunspent() if u["amount"] > 2][0]
        rec = w.send(
            outputs={dest: 1},
            options={
                "change_type": "bech32m",
                "fee_rate": 1,
                "inputs": [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 1}],
                "add_inputs": False,
            },
        )
        assert rec["complete"]
        rec_dec = self._decode_send(w, rec)
        assert_equal(rec_dec["vin"][0]["sequence"], 1)
        bumped = w.bumpfee(rec["txid"], {"fee_rate": 10})
        assert_equal(bumped["errors"], [])
        bump_dec = self.nodes[0].decoderawtransaction(w.gettransaction(bumped["txid"])["hex"])
        assert_equal(bump_dec["vin"][0]["sequence"], 1)
        assert_greater_than(len(bump_dec["vin"][0]["txinwitness"]), 1)
        self.generate(self.nodes[0], 1)

    def test_encrypted_send(self):
        self.log.info("encryptwallet: send requires unlock")
        w, xpubs, specs = self._coord(2)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        self._fund(w.getnewaddress("", "bech32m"))
        w.encryptwallet("pass")
        dest = self.def_wallet.getnewaddress()
        w.walletlock()
        locked = w.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
        assert_equal(locked["complete"], False)
        with WalletUnlock(w, "pass"):
            sent = w.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
            assert sent["complete"]
            assert_equal(len(self._decode_send(w, sent)["vin"][0]["txinwitness"]), 1)

    def test_backup_restore(self):
        self.log.info("backupwallet/restorewallet keeps Scrooge vault descriptors and UTXOs")
        w, xpubs, specs = self._coord(2)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        addr = w.getnewaddress("", "bech32m")
        self._fund(addr)
        bak = self.nodes[0].datadir_path / "scrooge.bak"
        w.backupwallet(str(bak))
        self.nodes[0].restorewallet("scrooge_restored", str(bak))
        rest = self.nodes[0].get_wallet_rpc("scrooge_restored")
        assert_equal(rest.getaddressinfo(addr)["ismine"], True)
        descs = [d["desc"] for d in rest.listdescriptors()["descriptors"]]
        assert any("older(1)" in d and "tr(musig(" in d for d in descs)
        dest = self.def_wallet.getnewaddress()
        sent = rest.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
        assert sent["complete"]
        assert_equal(len(self._decode_send(rest, sent)["vin"][0]["txinwitness"]), 1)

    def test_airgapped_psbt_roundtrip(self):
        self.log.info("xpub-only watch wallet: two offline signers complete a vault key-path PSBT")
        keys = []
        signers = []
        for i in range(2):
            s = self._blank(f"air_sign_{self.n}_{i}")
            xpub = s.addhdkey()["xpub"]
            info = s.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"] + info["xprv"], info["origin"] + info["xpub"]))
            signers.append(s)
        self.n += 1
        pat = self._vault_pat(2, 2, 1)
        watch = self._blank(f"air_watch_{self.n}", disable_private_keys=True)
        self.n += 1
        pub = self._subst(pat, keys, priv_mask=set())
        assert_equal(watch.importdescriptors([{"desc": pub, "timestamp": "now", "active": True}])[0]["success"], True)
        for i, s in enumerate(signers):
            desc = self._subst(pat, keys, priv_mask={i})
            assert_equal(s.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = watch.getnewaddress("", "bech32m")
        assert_equal(addr, signers[0].getnewaddress("", "bech32m"))
        self._fund(addr)
        dest = self.def_wallet.getnewaddress()
        psbt = watch.walletcreatefundedpsbt([], [{dest: 1}], 0, {"change_type": "bech32m", "replaceable": True, "fee_rate": 1})["psbt"]
        unsigned = watch.walletprocesspsbt(psbt=psbt, finalize=False)
        assert_equal(unsigned["complete"], False)
        nonces = self.nodes[0].combinepsbt([s.walletprocesspsbt(psbt=psbt, finalize=False)["psbt"] for s in signers])
        partials = [s.walletprocesspsbt(psbt=nonces, finalize=False)["psbt"] for s in signers]
        combined = self.nodes[0].combinepsbt(partials)
        done = self.nodes[0].finalizepsbt(combined)
        assert done["complete"]
        assert_equal(len(self._decode_send(watch, done["hex"])["vin"][0]["txinwitness"]), 1)

    def test_older_2_reorg_evicts_recovery(self):
        self.log.info("older(2) recovery is BIP68-invalid after reorg drops the second confirmation")
        coord, xpubs, specs = self._coord(3)
        coord.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 2})
        keys = self._derived(coord, xpubs)
        rec = self._blank(f"reorg_rec_{self.n}")
        self.n += 1
        desc = self._subst(self._vault_pat(2, 3, 2), keys, priv_mask={0, 1})
        assert_equal(rec.importdescriptors([{"desc": desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = rec.getnewaddress("", "bech32m")
        self._fund(addr)
        utxo = rec.listunspent()[0]
        dest = self.def_wallet.getnewaddress()
        assert_raises_rpc_error(-4, "not yet recoverable", rec.walletcreatefundedpsbt,
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 2}],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "fee_rate": 1, "add_inputs": False},
        )
        extra = self.generate(self.nodes[0], 1)[0]
        proc = rec.walletprocesspsbt(psbt=rec.walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 2}],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "fee_rate": 1, "add_inputs": False},
        )["psbt"])
        assert proc["complete"]
        txid = self.nodes[0].sendrawtransaction(proc["hex"])
        assert txid in self.nodes[0].getrawmempool()
        self.nodes[0].invalidateblock(extra)
        assert txid not in self.nodes[0].getrawmempool()
        self.generatetoaddress(self.nodes[0], 1, self.def_wallet.getnewaddress())
        self.nodes[0].sendrawtransaction(proc["hex"])
        assert txid in self.nodes[0].getrawmempool()

    def test_sendmany_sendtoaddress_unload_load(self):
        self.log.info("sendtoaddress, sendmany, then unloadwallet/loadwallet still spend a Scrooge vault")
        w, xpubs, specs = self._coord(2)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        self._fund(w.getnewaddress("", "bech32m"), 8)
        dest = self.def_wallet.getnewaddress()
        txid = w.sendtoaddress(dest, 1)
        dec = self._decode_send(w, txid)
        assert_equal(len(dec["vin"][0]["txinwitness"]), 1)
        self.generate(self.nodes[0], 1)
        dest_a = self.def_wallet.getnewaddress()
        dest_b = self.def_wallet.getnewaddress()
        many = w.sendmany(dummy="", amounts={dest_a: 1, dest_b: 1})
        many_dec = self._decode_send(w, many)
        assert_equal(len(many_dec["vin"][0]["txinwitness"]), 1)
        assert_greater_than(len(many_dec["vout"]), 1)
        self.generate(self.nodes[0], 1)
        name = w.getwalletinfo()["walletname"]
        self.nodes[0].unloadwallet(name)
        self.nodes[0].loadwallet(name)
        rest = self.nodes[0].get_wallet_rpc(name)
        sent = rest.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
        assert sent["complete"]
        assert_equal(len(self._decode_send(rest, sent)["vin"][0]["txinwitness"]), 1)

    def test_older_144_and_signraw_musig(self):
        self.log.info("older(144) recovery sequence; signrawtransactionwithwallet cannot finish MuSig2")
        w, xpubs, specs = self._coord(2)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 144})
        self._fund(w.getnewaddress("", "bech32m"), 8)
        utxo = w.listunspent()[0]
        dest = self.def_wallet.getnewaddress()
        assert_raises_rpc_error(-4, "not yet recoverable", w.walletcreatefundedpsbt,
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 144}],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "fee_rate": 1, "add_inputs": False},
        )

        raw = w.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{dest: 1}],
        )
        funded = w.fundrawtransaction(raw, {"change_type": "bech32m", "fee_rate": 1, "add_inputs": False})
        signed = w.signrawtransactionwithwallet(funded["hex"])
        assert_equal(signed["complete"], False)
        psbt = w.converttopsbt(funded["hex"])
        proc = w.walletprocesspsbt(psbt=psbt)
        assert proc["complete"]
        assert_equal(len(self.nodes[0].decoderawtransaction(proc["hex"])["vin"][0]["txinwitness"]), 1)

    def test_watchonly_xpub_vault_psbt(self):
        self.log.info("RPC createmultisigdescriptor on a disable_private_keys wallet from xpubs")
        keys = []
        for i in range(2):
            s = self._blank(f"watch_src_{self.n}_{i}")
            xpub = s.addhdkey()["xpub"]
            info = s.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"][1:9], info["xpub"]))
        self.n += 1
        name = f"watch_vault_xpub_{self.n}"
        self.n += 1
        self.nodes[0].createwallet(wallet_name=name, disable_private_keys=True, blank=True)
        watch = self.nodes[0].get_wallet_rpc(name)
        res = watch.createmultisigdescriptor(2, [
            {"path": PATH, "fingerprint": keys[0][0], "xpub": keys[0][1]},
            {"path": PATH, "fingerprint": keys[1][0], "xpub": keys[1][1]},
        ], {"type": "bech32m", "fallback_older": 1})
        assert "tr(musig(" in res["descs"][0]
        addr = watch.getnewaddress("", "bech32m")
        self._fund(addr)
        dest = self.def_wallet.getnewaddress()
        drafted = watch.walletcreatefundedpsbt([], [{dest: 1}], 0, {"change_type": "bech32m", "fee_rate": 1, "replaceable": True})
        unsigned = watch.walletprocesspsbt(psbt=drafted["psbt"])
        assert_equal(unsigned["complete"], False)

    def test_encrypted_recovery(self):
        self.log.info("encryptwallet: recovery script-path send after unlock")
        w, xpubs, specs = self._coord(3)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        self._fund(w.getnewaddress("", "bech32m"))
        w.encryptwallet("pass")
        dest = self.def_wallet.getnewaddress()
        utxo = None
        with WalletUnlock(w, "pass"):
            utxo = w.listunspent()[0]
            rec = w.send(
                outputs={dest: 1},
                options={
                    "change_type": "bech32m",
                    "fee_rate": 1,
                    "add_to_wallet": False,
                    "inputs": [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 1}],
                    "add_inputs": False,
                },
            )
            assert rec["complete"]
            dec = self._decode_send(w, rec)
            assert_equal(dec["vin"][0]["sequence"], 1)
            assert_greater_than(len(dec["vin"][0]["txinwitness"]), 1)

    def test_nums_bumpfee(self):
        self.log.info("NUMS m-of-n script-path send can be fee-bumped")
        w, xpubs, specs = self._coord(2)
        res = w.createmultisigdescriptor(1, specs, {"type": "bech32m"})
        assert "sortedmulti_a(1," in res["descs"][0]
        self._fund(w.getnewaddress("", "bech32m"))
        dest = self.def_wallet.getnewaddress()
        sent = w.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "replaceable": True})
        assert sent["complete"]
        bumped = w.bumpfee(sent["txid"], {"fee_rate": 10})
        assert_equal(bumped["errors"], [])
        bump_dec = self.nodes[0].decoderawtransaction(w.gettransaction(bumped["txid"])["hex"])
        assert_greater_than(len(bump_dec["vin"][0]["txinwitness"]), 1)
        self.generate(self.nodes[0], 1)

    def test_airgapped_recovery_psbt(self):
        self.log.info("1-of-2 air-gapped recovery: one offline signer completes the script-path")
        keys = []
        signers = []
        for i in range(2):
            s = self._blank(f"air_rec_sign_{self.n}_{i}")
            xpub = s.addhdkey()["xpub"]
            info = s.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"] + info["xprv"], info["origin"] + info["xpub"]))
            signers.append(s)
        self.n += 1
        pat = self._vault_pat(1, 2, 1)
        watch = self._blank(f"air_rec_watch_{self.n}", disable_private_keys=True)
        self.n += 1
        pub = self._subst(pat, keys, priv_mask=set())
        assert_equal(watch.importdescriptors([{"desc": pub, "timestamp": "now", "active": True}])[0]["success"], True)
        rec_desc = self._subst(pat, keys, priv_mask={0})
        assert_equal(signers[0].importdescriptors([{"desc": rec_desc, "timestamp": "now", "active": True}])[0]["success"], True)
        addr = watch.getnewaddress("", "bech32m")
        self._fund(addr)
        utxo = watch.listunspent()[0]
        dest = self.def_wallet.getnewaddress()
        psbt = watch.walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 1}],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "fee_rate": 1, "add_inputs": False},
        )["psbt"]
        too_soon = signers[0].walletprocesspsbt(psbt=watch.walletcreatefundedpsbt(
            [], [{dest: 1}], 0, {"change_type": "bech32m", "fee_rate": 1, "replaceable": True},
        )["psbt"], finalize=True)
        assert_equal(too_soon["complete"], False)
        done = signers[0].walletprocesspsbt(psbt=psbt)
        assert done["complete"]
        rec_dec = self.nodes[0].decoderawtransaction(done["hex"])
        assert_equal(rec_dec["vin"][0]["sequence"], 1)
        assert_greater_than(len(rec_dec["vin"][0]["txinwitness"]), 1)

    def test_multi_input_send(self):
        self.log.info("send() spends two Scrooge vault UTXOs on the MuSig2 key-path")
        w, xpubs, specs = self._coord(2)
        w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        addr = w.getnewaddress("", "bech32m")
        self._fund(addr, 5)
        self._fund(addr, 5)
        dest = self.def_wallet.getnewaddress()
        sent = w.send(outputs={dest: 8}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
        assert sent["complete"]
        dec = self._decode_send(w, sent)
        assert_equal(len(dec["vin"]), 2)
        assert_equal(len(dec["vin"][0]["txinwitness"]), 1)
        assert_equal(len(dec["vin"][1]["txinwitness"]), 1)


if __name__ == "__main__":
    WalletTaprootVaultSendTest(__file__).main()
