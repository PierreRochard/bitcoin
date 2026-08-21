#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regtest rehearsal: 999-key 24861 vault round-trip.

Send-back is the 1-of-999 script-path after older(1) (safety hatch), plus an
OP_RETURN attribution memo. n-of-n MuSig2 key-path is left for a later spend.
"""

import time

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


PATH = "m/48h/1h/0h/3h"
NKEYS = 999
OLDER = 1
FUND_BTC = 5
# X: "@BitcoinPierre"
ATTRIBUTION_HEX = "583a202240426974636f696e50696572726522"


class WalletTaprootVault999Test(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.rpc_timeout = 1200
        self.extra_args = [["-keypool=8"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _witness(self, raw):
        return self.nodes[0].decoderawtransaction(raw)["vin"][0]["txinwitness"]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        you = node.get_wallet_rpc(self.default_wallet_name)

        self.log.info(f"Creating {NKEYS}-key vault (1-of-{NKEYS} after older({OLDER}))")
        t0 = time.monotonic()
        node.createwallet(wallet_name="vault999", blank=True)
        vault = node.get_wallet_rpc("vault999")
        xpubs = []
        specs = []
        for i in range(NKEYS):
            xpub = vault.addhdkey()["xpub"]
            xpubs.append(xpub)
            specs.append({"path": PATH, "hdkey": xpub})
            if (i + 1) % 100 == 0:
                self.log.info(f"  addhdkey {i + 1}/{NKEYS}")
        created = vault.createmultisigdescriptor(
            1, specs, {"type": "bech32m", "fallback_older": OLDER}
        )
        assert_equal(created["nrequired"], 1)
        assert_equal(created["fallback_older"], OLDER)
        desc = created["descs"][0]
        assert "tr(musig(" in desc
        assert f"older({OLDER})" in desc
        assert f"multi_a(1," in desc
        create_s = time.monotonic() - t0
        self.log.info(f"Vault created in {create_s:.1f}s")

        # 1) I give you an address
        vault_addr = vault.getnewaddress("", "bech32m")
        assert vault_addr.startswith("bcrt1p")
        self.log.info(f"GIVE: vault receive address {vault_addr}")

        # Recovery wallet holds only key 0's xprv (safety hatch).
        self.log.info("Importing 1-of-999 recovery descriptor (key 0 xprv, rest xpub)")
        keys = []
        for xpub in xpubs:
            info = vault.derivehdkey(PATH, {"private": True, "hdkey": xpub})
            keys.append((info["origin"] + info["xprv"], info["origin"] + info["xpub"]))
        musig = ",".join(f"{k[1]}/<0;1>/*" for k in keys)
        multi = ",".join(f"{keys[i][0 if i == 0 else 1]}/<0;1>/*" for i in range(NKEYS))
        rec_desc = descsum_create(
            f"tr(musig({musig}),and_v(v:older({OLDER}),multi_a(1,{multi})))"
        )
        node.createwallet(wallet_name="recover999", blank=True)
        rec = node.get_wallet_rpc("recover999")
        imported = rec.importdescriptors([{
            "desc": rec_desc,
            "timestamp": 0,
            "active": True,
        }])
        assert imported[0]["success"], imported[0]
        rec_addr = rec.getnewaddress("", "bech32m")
        assert_equal(rec_addr, vault_addr)

        # 2) You send to it
        fund_txid = you.sendtoaddress(vault_addr, FUND_BTC)
        self.generate(node, 1)
        assert_equal(len(vault.listunspent()), 1)
        self.log.info(f"YOU SENT: {FUND_BTC} BTC in {fund_txid}")

        # 3) You give me an address
        return_addr = you.getnewaddress("", "bech32")
        self.log.info(f"RETURN TO: {return_addr}")
        bal_before = you.getbalance()

        # 4) Send back via 1-of-999 script-path after older(1), with OP_RETURN.
        self.generate(node, 1)
        rec_utxos = rec.listunspent()
        assert_equal(len(rec_utxos), 1)
        utxo = rec_utxos[0]
        t1 = time.monotonic()
        psbt = rec.walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": OLDER}],
            [{return_addr: utxo["amount"]}, {"data": ATTRIBUTION_HEX}],
            0,
            {
                "change_type": "bech32m",
                "subtractFeeFromOutputs": [0],
                "replaceable": False,
                "fee_rate": 1,
            },
        )["psbt"]
        proc = rec.walletprocesspsbt(psbt=psbt)
        spend_s = time.monotonic() - t1
        assert proc["complete"], proc
        raw = proc["hex"]
        decoded = node.decoderawtransaction(raw)
        witness = decoded["vin"][0]["txinwitness"]
        assert_greater_than(len(witness), 1)
        vouts = decoded["vout"]
        assert_equal(len(vouts), 2)
        pay = next(o for o in vouts if o["scriptPubKey"].get("address") == return_addr)
        opreturn = next(o for o in vouts if o["scriptPubKey"]["type"] == "nulldata")
        assert_equal(opreturn["value"], 0)
        assert ATTRIBUTION_HEX in opreturn["scriptPubKey"]["hex"]
        node.sendrawtransaction(raw)
        self.generate(node, 1)
        assert_greater_than(you.getbalance(), bal_before)
        self.log.info(
            f"SENT BACK: txid={decoded['txid']} vsize={decoded['vsize']} vB "
            f"witness_stack={len(witness)} script-path 1-of-{NKEYS} "
            f"pay={pay['value']} opreturn=X:@BitcoinPierre in {spend_s:.1f}s"
        )
        self.log.info(
            f"Rehearsal done. create={create_s:.1f}s scriptpath_send={spend_s:.1f}s "
            f"addr={vault_addr} return={return_addr}"
        )


if __name__ == "__main__":
    WalletTaprootVault999Test(__file__).main()
