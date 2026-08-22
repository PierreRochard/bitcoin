#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regtest: mixed-key Scrooge vault (computer HD seed + external signer).

Python signer.py cannot complete MuSig2, so key-path send is not asserted.
Recovery after older(N) uses only the computer keys that still sit in the
wallet (1-of-2 with one local, 2-of-3 with two locals). Full mock-hardware
MuSig2 signing is covered by taproot_vault_mixed_tests.
"""

import os
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


PATH = "m/48h/1h/0h/3h"
HW_FPR = "00000001"


class WalletTaprootVaultMixedTest(BitcoinTestFramework):
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
        self.funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.n = 0
        self.test_mixed_vault_descriptor()
        self.test_1of2_local_recovers()
        self.test_2of3_two_locals_recover()

    def _mixed(self, name, n_local):
        self.nodes[1].createwallet(wallet_name=name, disable_private_keys=False, external_signer=True)
        w = self.nodes[1].get_wallet_rpc(name)
        locals_ = [w.addhdkey()["xpub"] for _ in range(n_local)]
        specs = [{"path": PATH, "hdkey": x} for x in locals_]
        specs.append(HW_FPR)
        return w, locals_, specs

    def _fund(self, addr, amount=5):
        self.funding.sendtoaddress(addr, amount)
        self.generate(self.nodes[0], 1)

    def _import_vault_on_node0(self, src):
        """Recovery wallet without -signer, holding the same xprvs/xpubs."""
        name = f"rec_{self.n}"
        self.n += 1
        self.nodes[0].createwallet(wallet_name=name, blank=True)
        rec = self.nodes[0].get_wallet_rpc(name)
        imports = []
        for d in src.listdescriptors(True)["descriptors"]:
            if "musig(" not in d["desc"]:
                continue
            imports.append({
                "desc": d["desc"],
                "timestamp": "now",
                "active": d.get("active", True),
                "internal": d.get("internal", False),
            })
        assert imports
        for r in rec.importdescriptors(imports):
            assert_equal(r["success"], True)
        return rec

    def _recover_scriptpath(self, mixed_wallet, older):
        rec = self._import_vault_on_node0(mixed_wallet)
        addr = rec.getnewaddress("", "bech32m")
        assert addr.startswith("bcrt1p")
        assert_equal(addr, mixed_wallet.getnewaddress("", "bech32m"))
        self._fund(addr)
        utxo = rec.listunspent()[0]
        dest = self.funding.getnewaddress()
        too_soon = rec.walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 0xFFFFFFFE}],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "replaceable": False},
        )["psbt"]
        proc = rec.walletprocesspsbt(psbt=too_soon)
        assert_equal(proc["complete"], False)

        self.generate(self.nodes[0], 1)
        ready = rec.walletcreatefundedpsbt(
            [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": older}],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "replaceable": False},
        )["psbt"]
        proc = rec.walletprocesspsbt(psbt=ready)
        assert proc["complete"]
        raw = proc["hex"]
        witness = self.nodes[0].decoderawtransaction(raw)["vin"][0]["txinwitness"]
        assert_greater_than(len(witness), 1)
        self.nodes[0].sendrawtransaction(raw)
        self.generate(self.nodes[0], 1)

    def test_mixed_vault_descriptor(self):
        self.log.info("createmultisigdescriptor mixed 2-of-2 vault (local + signer fingerprint)")
        w, locals_, specs = self._mixed("mix_desc", 1)
        res = w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        assert_equal(res["nrequired"], 2)
        assert_equal(res["fallback_older"], 1)
        desc = res["descs"][0]
        assert "tr(musig(" in desc
        assert "older(1)" in desc
        assert "multi_a(2," in desc
        assert HW_FPR in desc
        addr = w.getnewaddress("", "bech32m")
        assert addr.startswith("bcrt1p")
        self._fund(addr)

    def test_1of2_local_recovers(self):
        self.log.info("1-of-2 mixed vault: computer key recovers after older(1) without the signer")
        w, locals_, specs = self._mixed("mix_1of2", 1)
        res = w.createmultisigdescriptor(1, specs, {"type": "bech32m", "fallback_older": 1})
        assert "multi_a(1," in res["descs"][0]
        self._recover_scriptpath(w, older=1)

    def test_2of3_two_locals_recover(self):
        self.log.info("2-of-3 mixed vault: two computer keys recover after older(1)")
        w, locals_, specs = self._mixed("mix_2of3", 2)
        res = w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        assert "multi_a(2," in res["descs"][0]
        assert HW_FPR in res["descs"][0]
        self._recover_scriptpath(w, older=1)


if __name__ == "__main__":
    WalletTaprootVaultMixedTest(__file__).main()
