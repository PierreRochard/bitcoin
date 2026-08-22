#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end regtest lifecycles for Scrooge vault recovery clocks.

The broader vault tests cover policy matrices and individual RPCs. This test
keeps each policy in one coherent journey from creation and public backup,
through funding and ordinary spending, to delayed recovery and recovery
change. In particular it asserts the user-visible distinction that relative
recovery starts a new clock for change while an absolute height does not.
"""

import json
import re

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


PATH = "m/48h/1h/0h/3h"
RBF_SEQUENCE = 0xFFFFFFFD


class WalletTaprootVaultLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-keypool=10"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        self.funding = node.get_wallet_rpc(self.default_wallet_name)
        self.test_relative_policy_lifecycle_and_change_clock()
        self.test_absolute_policy_lifecycle_and_change_clock()

    def _blank(self, name, *, watch_only=False):
        self.nodes[0].createwallet(
            wallet_name=name,
            blank=True,
            disable_private_keys=watch_only,
        )
        return self.nodes[0].get_wallet_rpc(name)

    def _create_vault(self, name, *, nrequired, nkeys, older=None, after=None):
        wallet = self._blank(name)
        specs = [
            {"path": PATH, "hdkey": wallet.addhdkey()["xpub"]}
            for _ in range(nkeys)
        ]
        options = {"type": "bech32m"}
        if older is not None:
            options["fallback_older"] = older
        if after is not None:
            options["fallback_after"] = after
        created = wallet.createmultisigdescriptor(nrequired, specs, options)
        assert_equal(created["nrequired"], nrequired)
        assert_equal(len(created["descs"]), 2)
        assert all("tr(musig(" in desc for desc in created["descs"])
        return wallet, created

    def _decode(self, wallet, sent):
        raw = sent.get("hex")
        if raw is None:
            raw = wallet.gettransaction(sent["txid"])["hex"]
        return self.nodes[0].decoderawtransaction(raw)

    def _assert_recovery_spend(self, wallet, sent, *, sequence=None, locktime=None):
        assert sent["complete"]
        decoded = self._decode(wallet, sent)
        assert_greater_than(len(decoded["vin"][0]["txinwitness"]), 1)
        if sequence is not None:
            assert_equal(decoded["vin"][0]["sequence"], sequence)
        if locktime is not None:
            assert_equal(decoded["locktime"], locktime)
        return decoded

    def _send_recovery(self, wallet, amount=1):
        return wallet.send(
            outputs={self.funding.getnewaddress(): amount},
            options={
                "change_type": "bech32m",
                "fee_rate": 1,
                "replaceable": True,
                "vault_recovery": True,
            },
        )

    def test_relative_policy_lifecycle_and_change_clock(self):
        self.log.info("Relative lifecycle: public restore, lost signer, RBF key path, and restarted change clock")
        node = self.nodes[0]
        delay = 3
        vault, created = self._create_vault(
            "lifecycle_relative",
            nrequired=2,
            nkeys=3,
            older=delay,
        )

        package_text = vault.exportvaultpolicy()
        package = json.loads(package_text)
        assert_equal(package["format"], "bitcoin-core-vault-policy")
        assert_equal(package["version"], 1)
        assert_equal(package["network"], "regtest")
        assert_equal(package["policy_id"], created["policy_id"])
        assert_equal(package["nrequired"], 2)
        assert_equal(package["fallback_older"], delay)
        assert_equal(len(package["descs"]), 2)
        assert "xprv" not in package_text
        assert "tprv" not in package_text

        watch = self._blank("lifecycle_relative_watch", watch_only=True)
        imported = watch.importvaultpolicy(package_text)
        assert_equal(imported["policy_id"], created["policy_id"])
        address = vault.getnewaddress("", "bech32m")
        assert_equal(watch.getnewaddress("", "bech32m"), address)

        self.funding.sendtoaddress(address, 10)
        self.generate(node, delay)
        mature = vault.getvaultinfo()
        assert_equal(mature["fallback_older"], delay)
        assert_equal(float(mature["spendable_now"]), 10)
        assert_equal(float(mature["recoverable_now"]), 10)
        assert_equal(float(mature["awaiting_maturity"]), 0)
        assert_equal(watch.getvaultinfo()["recoverable_now"], mature["recoverable_now"])
        watch_draft = watch.send(
            outputs={self.funding.getnewaddress(): 1},
            options={"fee_rate": 1, "add_to_wallet": False},
        )
        assert_equal(watch_draft["complete"], False)
        assert "txid" not in watch_draft

        descriptors = vault.listdescriptors()
        signer_fingerprint = re.search(r"\[([0-9a-fA-F]{8})/", created["descs"][0]).group(1)
        vault.setlostsigner(signer_fingerprint, True)
        lost = vault.getvaultinfo()
        assert_equal(float(lost["spendable_now"]), 0)
        assert_equal(float(lost["recoverable_now"]), 10)
        assert_equal(vault.listdescriptors(), descriptors)
        vault.setlostsigner(signer_fingerprint, False)

        ordinary = vault.send(
            outputs={self.funding.getnewaddress(): 1},
            options={
                "change_type": "bech32m",
                "fee_rate": 1,
                "replaceable": True,
            },
        )
        assert ordinary["complete"]
        ordinary_decoded = self._decode(vault, ordinary)
        assert_equal(ordinary_decoded["vin"][0]["sequence"], RBF_SEQUENCE)
        assert_equal(len(ordinary_decoded["vin"][0]["txinwitness"]), 1)
        bumped = vault.bumpfee(ordinary["txid"], {"fee_rate": 5})
        assert_equal(bumped["errors"], [])
        assert_greater_than(bumped["fee"], bumped["origfee"])
        assert bumped["txid"] in node.getrawmempool()
        assert ordinary["txid"] not in node.getrawmempool()

        self.generate(node, delay)
        assert_greater_than(float(vault.getvaultinfo()["recoverable_now"]), 8)
        recovered = self._send_recovery(vault)
        self._assert_recovery_spend(vault, recovered, sequence=delay)
        self.generate(node, 1)

        # Recovery spends return change to the same vault. For older(N), that
        # change is a new UTXO at depth one and must wait N-1 more blocks.
        waiting = vault.getvaultinfo()
        assert_equal(float(waiting["recoverable_now"]), 0)
        assert_greater_than(float(waiting["awaiting_maturity"]), 7)
        assert_equal(waiting["earliest_blocks_remaining"], delay - 1)
        assert_equal(watch.getvaultinfo()["awaiting_maturity"], waiting["awaiting_maturity"])
        assert_raises_rpc_error(
            -4,
            None,
            self._send_recovery,
            vault,
        )

        self.generate(node, delay - 1)
        ready = vault.getvaultinfo()
        assert_equal(float(ready["awaiting_maturity"]), 0)
        assert_greater_than(float(ready["recoverable_now"]), 7)
        self._assert_recovery_spend(
            vault,
            self._send_recovery(vault),
            sequence=delay,
        )
        self.generate(node, 1)

    def test_absolute_policy_lifecycle_and_change_clock(self):
        self.log.info("Absolute lifecycle: height-gated recovery and change with no restarted clock")
        node = self.nodes[0]
        recovery_height = node.getblockcount() + 3
        vault, created = self._create_vault(
            "lifecycle_absolute",
            nrequired=1,
            nkeys=2,
            after=recovery_height,
        )
        assert_equal(created["fallback_after"], recovery_height)

        address = vault.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(address, 10)
        self.generate(node, 1)
        waiting = vault.getvaultinfo()
        assert_equal(waiting["fallback_after"], recovery_height)
        assert_equal(waiting["earliest_blocks_remaining"], 2)
        assert_equal(float(waiting["recoverable_now"]), 0)
        assert_equal(float(waiting["awaiting_maturity"]), 10)
        assert_raises_rpc_error(
            -4,
            None,
            self._send_recovery,
            vault,
        )

        self.generate(node, 2)
        ready = vault.getvaultinfo()
        assert_equal(float(ready["awaiting_maturity"]), 0)
        assert_equal(float(ready["recoverable_now"]), 10)
        recovered = self._send_recovery(vault)
        self._assert_recovery_spend(
            vault,
            recovered,
            locktime=recovery_height,
        )
        self.generate(node, 1)

        # after(H) is global. Once H has passed, confirmed recovery change is
        # already recoverable; unlike older(N), it has no per-UTXO clock.
        change_ready = vault.getvaultinfo()
        assert_equal(float(change_ready["awaiting_maturity"]), 0)
        assert_greater_than(float(change_ready["recoverable_now"]), 8)
        self._assert_recovery_spend(
            vault,
            self._send_recovery(vault),
            locktime=recovery_height,
        )
        self.generate(node, 1)


if __name__ == "__main__":
    WalletTaprootVaultLifecycleTest(__file__).main()
