#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Vault policy package, lost signer, and mixed-maturity recovery."""

import json
import os
import re
import stat

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

PATH = "m/48h/1h/0h/3h"


class WalletTaprootVaultPolicyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-keypool=8"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.generate(self.nodes[0], 101)
        self.funding = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.test_journey1_keypath_hides_policy()
        self.test_package_roundtrip()
        self.test_two_stage_policy_status()
        self.test_restore_core_key()
        self.test_package_errors()
        self.test_getvaultinfo_nonvault_and_unload_lost()
        self.test_lost_signer_and_mixed_maturity()
        self.test_no_silent_path_switch()
        self.test_recovery_only_key()
        self.test_after_recovery()
        self.test_vault_recovery_option_edges()
        self.test_rpc_recovery_vault_creation()

    def test_rpc_recovery_vault_creation(self):
        self.log.info("Two-phase RPC creation durably validates a private kit before atomic 90/180 wallet install")
        node = self.nodes[0]
        invalid_kit_path = os.path.join(self.options.tmpdir, "rpc-invalid-name-kit")
        assert_raises_rpc_error(
            -8,
            "without path components",
            node.preparerecoveryvault,
            "../rpc_escape",
            invalid_kit_path,
        )
        assert not os.path.exists(invalid_kit_path)
        kit_path = os.path.join(self.options.tmpdir, "rpc-recovery-kit-pending")
        prepared = node.preparerecoveryvault("rpc_fixed_pending", kit_path)
        assert_equal(prepared["wallet_name"], "rpc_fixed_pending")
        assert_equal(prepared["wallet_created"], False)
        assert_equal(prepared["primary_delay"], 12960)
        assert_equal(prepared["final_delay"], 25920)
        assert_equal(prepared["software_keys"], 3)
        assert_equal(len(prepared["policy_commitment"]), 64)
        assert_equal(len(prepared["kit_commitment"]), 64)
        assert "mnemonic" not in json.dumps(prepared).lower()
        assert "xprv" not in json.dumps(prepared).lower()
        assert "rpc_fixed_pending" not in node.listwallets()
        assert_equal(
            sorted(os.listdir(kit_path)),
            ["README.txt", "manifest.json", "policy.json", "software-key-1.txt", "software-key-2.txt", "software-key-3.txt"],
        )
        if os.name != "nt":
            assert_equal(stat.S_IMODE(os.stat(kit_path).st_mode), 0o700)
            for filename in os.listdir(kit_path):
                assert_equal(stat.S_IMODE(os.stat(os.path.join(kit_path, filename)).st_mode), 0o600)

        assert_raises_rpc_error(
            -4,
            "commitment does not match",
            node.createrecoveryvault,
            kit_path,
            "00" * 32,
        )
        assert "rpc_fixed_pending" not in [entry["name"] for entry in node.listwalletdir()["wallets"]]

        created = node.createrecoveryvault(kit_path, prepared["kit_commitment"])
        assert_equal(created["name"], "rpc_fixed_pending")
        assert_equal(created["policy_commitment"], prepared["policy_commitment"])
        assert_equal(created["kit_commitment"], prepared["kit_commitment"])
        assert_equal(created["schedule"], "current_90_180")
        assert_equal(created["setup_state"], "address_verification_required")
        assert_equal(created["verification_state"], "recovery_kit_matched")
        pending = node.get_wallet_rpc("rpc_fixed_pending")
        status = pending.getvaultinfo()
        assert_equal(status["schedule"], "current_90_180")
        assert_equal(status["fallback_older"], 12960)
        assert_equal(status["fallback_older_one_key"], 25920)
        assert_equal(status["setup_state"], "address_verification_required")
        assert_equal(status["verification_state"], "recovery_kit_matched")

        node.unloadwallet("rpc_fixed_pending")
        node.loadwallet("rpc_fixed_pending")
        pending = node.get_wallet_rpc("rpc_fixed_pending")
        assert_equal(pending.getvaultinfo()["verification_state"], "recovery_kit_matched")

        finished_kit = os.path.join(self.options.tmpdir, "rpc-recovery-kit-finished")
        finished_prepared = node.preparerecoveryvault("rpc_fixed_finished", finished_kit)
        finished_created = node.createrecoveryvault(
            finished_kit,
            finished_prepared["kit_commitment"],
            True,
        )
        assert_equal(finished_created["setup_state"], "complete")
        assert_equal(finished_created["verification_state"], "finished_unverified")
        assert "not independently verified" in " ".join(finished_created["warnings"]).lower()
        finished = node.get_wallet_rpc("rpc_fixed_finished")
        finished_status = finished.getvaultinfo()
        assert_equal(finished_status["schedule"], "current_90_180")
        assert_equal(finished_status["setup_state"], "complete")
        assert_equal(finished_status["verification_state"], "finished_unverified")

        self.funding.sendtoaddress(finished_created["address"], 1)
        self.generate(node, 1)
        destination = self.funding.getnewaddress()
        spend = finished.send(
            outputs={destination: 0.5},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False},
        )
        assert spend["complete"]
        assert_equal(len(node.decoderawtransaction(spend["hex"])["vin"][0]["txinwitness"]), 1)

        assert_raises_rpc_error(
            -4,
            "outside the Bitcoin data directory",
            node.preparerecoveryvault,
            "rpc_inside_data",
            os.path.join(node.datadir_path, "inside-kit"),
        )

    def test_journey1_keypath_hides_policy(self):
        self.log.info("Journey 1: 3-of-3 now / 2-of-3 later key-path spend does not reveal the policy")
        node = self.nodes[0]
        node.createwallet(wallet_name="j1_vault", blank=True)
        w = node.get_wallet_rpc("j1_vault")
        specs = [{"path": PATH, "hdkey": w.addhdkey()["xpub"]} for _ in range(3)]
        created = w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 1})
        assert created["policy_id"]
        addr = w.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 1)
        dest = self.funding.getnewaddress()
        rec = w.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
        assert rec["complete"]
        dec = node.decoderawtransaction(rec["hex"])
        assert_equal(len(dec["vin"][0]["txinwitness"]), 1)

    def test_package_roundtrip(self):
        self.log.info("Journey 5: export public policy, restore watch-only, same policy_id, original still spends")
        node = self.nodes[0]
        node.createwallet(wallet_name="pkg_src", blank=True)
        src = node.get_wallet_rpc("pkg_src")
        specs = [{"path": PATH, "hdkey": src.addhdkey()["xpub"]} for _ in range(2)]
        created = src.createmultisigdescriptor(1, specs, {"type": "bech32m", "fallback_older": 1})
        addr = src.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 1)
        pkg = src.exportvaultpolicy()
        assert "xprv" not in pkg
        assert created["policy_id"] in pkg
        node.createwallet(wallet_name="pkg_watch", blank=True, disable_private_keys=True)
        watch = node.get_wallet_rpc("pkg_watch")
        imported = watch.importvaultpolicy(pkg)
        assert_equal(imported["policy_id"], created["policy_id"])
        assert_equal(watch.getnewaddress("", "bech32m"), addr)
        info = watch.getvaultinfo()
        assert info["is_vault"]
        assert_equal(info["fallback_older"], 1)
        dest = self.funding.getnewaddress()
        assert_raises_rpc_error(-4, None, watch.send, outputs={dest: 1}, options={"fee_rate": 1, "add_to_wallet": False})
        spent = src.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
        assert spent["complete"]
        dec = node.decoderawtransaction(spent["hex"])
        assert_equal(len(dec["vin"][0]["txinwitness"]), 1)

    def test_two_stage_policy_status(self):
        self.log.info("Two-stage policy package and per-stage maturity status")
        node = self.nodes[0]
        node.createwallet(wallet_name="tiered_policy", blank=True)
        src = node.get_wallet_rpc("tiered_policy")
        specs = [{"path": PATH, "hdkey": src.addhdkey()["xpub"]} for _ in range(3)]
        created = src.createmultisigdescriptor(
            2,
            specs,
            {"type": "bech32m", "fallback_older": 2, "fallback_older_one_key": 4},
        )
        # Export must select only the vault pair even when unrelated active
        # receive/change descriptors exist in the same wallet.
        src.createmultisigdescriptor(2, specs, {"type": "bech32"})
        addr = src.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 1)

        info = src.getvaultinfo()
        assert_equal(info["fallback_older"], 2)
        assert_equal(info["fallback_older_one_key"], 4)
        assert_equal(len(info["recovery_stages"]), 2)
        assert_equal(info["recovery_stages"][0]["nrequired"], 2)
        assert_equal(info["recovery_stages"][0]["fallback_older"], 2)
        assert_equal(info["recovery_stages"][1]["nrequired"], 1)
        assert_equal(info["recovery_stages"][1]["fallback_older"], 4)
        assert_greater_than(float(info["recovery_stages"][0]["awaiting_maturity"]), 0)
        assert_greater_than(float(info["recovery_stages"][1]["awaiting_maturity"]), 0)

        package_text = src.exportvaultpolicy()
        package = json.loads(package_text)
        assert_equal(package["version"], 1)
        assert_equal(package["fallback_older_one_key"], 4)
        assert_equal(len(package["recovery_stages"]), 2)
        assert_equal(len(package["descs"]), 2)
        node.createwallet(wallet_name="tiered_policy_watch", blank=True, disable_private_keys=True)
        watch = node.get_wallet_rpc("tiered_policy_watch")
        assert_equal(watch.importvaultpolicy(package_text)["policy_id"], created["policy_id"])
        assert_equal(watch.getnewaddress("", "bech32m"), addr)

        tampered = dict(package)
        tampered["fallback_older_one_key"] = 5
        assert_raises_rpc_error(-8, "recovery metadata does not match", watch.importvaultpolicy, json.dumps(tampered))
        tampered = dict(package)
        tampered["policy_id"] = "0000000000000000"
        assert_raises_rpc_error(-8, "policy_id does not match", watch.importvaultpolicy, json.dumps(tampered))
        node.createwallet(wallet_name="tiered_policy_attacker", blank=True)
        attacker = node.get_wallet_rpc("tiered_policy_attacker")
        attacker_specs = [{"path": PATH, "hdkey": attacker.addhdkey()["xpub"]} for _ in range(3)]
        attacker.createmultisigdescriptor(
            2,
            attacker_specs,
            {"type": "bech32m", "fallback_older": 2, "fallback_older_one_key": 4},
        )
        attacker_package = json.loads(attacker.exportvaultpolicy())
        tampered = dict(package)
        tampered["descs"] = [package["descs"][0], attacker_package["descs"][1]]
        assert_raises_rpc_error(-8, "do not form a matching vault pair", watch.importvaultpolicy, json.dumps(tampered))

        self.generate(node, 1)
        info = src.getvaultinfo()
        assert_greater_than(float(info["recovery_stages"][0]["recoverable_now"]), 0)
        assert_greater_than(float(info["recovery_stages"][1]["awaiting_maturity"]), 0)
        self.generate(node, 2)
        info = src.getvaultinfo()
        assert_greater_than(float(info["recovery_stages"][1]["recoverable_now"]), 0)
        assert_equal(float(info["recovery_stages"][1]["awaiting_maturity"]), 0)

    def test_restore_core_key(self):
        self.log.info("Journey 5: restore Core keys via addhdkey xprv; same policy_id, address, and spend")
        node = self.nodes[0]
        node.createwallet(wallet_name="core_src", blank=True)
        src = node.get_wallet_rpc("core_src")
        src.addhdkey()
        src.addhdkey()
        hd = src.gethdkeys(private=True)
        specs = [{"path": PATH, "hdkey": k["xprv"]} for k in hd]
        created = src.createmultisigdescriptor(1, specs, {"type": "bech32m", "fallback_older": 1})
        addr = src.getnewaddress("", "bech32m")
        node.createwallet(wallet_name="core_rst", blank=True)
        rst = node.get_wallet_rpc("core_rst")
        restored = rst.createmultisigdescriptor(1, specs, {"type": "bech32m", "fallback_older": 1})
        assert_equal(restored["policy_id"], created["policy_id"])
        assert_equal(rst.getnewaddress("", "bech32m"), addr)
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 1)
        dest = self.funding.getnewaddress()
        rec = rst.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
        assert rec["complete"]
        assert_equal(len(node.decoderawtransaction(rec["hex"])["vin"][0]["txinwitness"]), 1)

    def test_package_errors(self):
        self.log.info("Policy package rejects garbage, unknown format, and missing descriptors")
        node = self.nodes[0]
        node.createwallet(wallet_name="pkg_err", blank=True, disable_private_keys=True)
        w = node.get_wallet_rpc("pkg_err")
        assert_raises_rpc_error(-8, None, w.importvaultpolicy, "not-json")
        assert_raises_rpc_error(-8, "Unknown vault policy package format", w.importvaultpolicy, '{"format":"other"}')
        assert_raises_rpc_error(-8, "missing descriptors", w.importvaultpolicy, '{"format":"bitcoin-core-vault-policy","descs":[]}')
        assert_raises_rpc_error(-8, "missing descriptors", w.importvaultpolicy, '{"format":"bitcoin-core-vault-policy"}')
        assert_raises_rpc_error(-8, "Unsupported vault policy package version", w.importvaultpolicy, '{"format":"bitcoin-core-vault-policy","version":2,"descs":["d"]}')
        assert_raises_rpc_error(-8, "fallback_older is out of range", w.importvaultpolicy, '{"format":"bitcoin-core-vault-policy","fallback_older":-1,"descs":["d"]}')
        assert_raises_rpc_error(-4, None, w.importvaultpolicy, '{"format":"bitcoin-core-vault-policy","descs":["tr(musig(a,b))"]}')
        assert_raises_rpc_error(-8, "fingerprint must be 8 hex", w.setlostsigner, "zz", True)
        assert_raises_rpc_error(-8, "fingerprint must be 8 hex", w.setlostsigner, "aabbccddee", True)

    def test_getvaultinfo_nonvault_and_unload_lost(self):
        self.log.info("getvaultinfo on a non-vault; lost-signer metadata survives unload")
        node = self.nodes[0]
        info = self.funding.getvaultinfo()
        assert_equal(info["is_vault"], False)
        assert_equal(info["lost_signers"], [])
        pkg = json.loads(self.funding.exportvaultpolicy())
        assert_equal(pkg["format"], "bitcoin-core-vault-policy")
        assert "xprv" not in json.dumps(pkg)
        dest = self.funding.getnewaddress()
        non_vault = self.funding.send(outputs={dest: 1}, options={"vault_recovery": True, "fee_rate": 1, "add_to_wallet": False})
        assert non_vault["complete"]
        node.createwallet(wallet_name="lost_tmp", blank=True)
        w = node.get_wallet_rpc("lost_tmp")
        specs = [{"path": PATH, "hdkey": w.addhdkey()["xpub"]} for _ in range(2)]
        w.createmultisigdescriptor(1, specs, {"type": "bech32m", "fallback_older": 1})
        assert_raises_rpc_error(-8, "fallback_after must be between 1 and 2^31-1",
                                w.createmultisigdescriptor, 1, specs, {"type": "bech32m", "fallback_after": 0})
        pkg = json.loads(w.exportvaultpolicy())
        pkg["network"] = "main" if pkg.get("network") != "main" else "regtest"
        node.createwallet(wallet_name="pkg_net", blank=True, disable_private_keys=True)
        watch = node.get_wallet_rpc("pkg_net")
        assert_raises_rpc_error(-4, "does not match this node", watch.importvaultpolicy, json.dumps(pkg))
        w.setlostsigner("aabbccdd")
        assert "aabbccdd" in w.getvaultinfo()["lost_signers"]
        node.unloadwallet("lost_tmp")
        node.loadwallet("lost_tmp")
        w = node.get_wallet_rpc("lost_tmp")
        assert "aabbccdd" in w.getvaultinfo()["lost_signers"]

    def test_lost_signer_and_mixed_maturity(self):
        self.log.info("Journeys 3/4: lost signer freezes immediate; recover only mature UTXOs")
        node = self.nodes[0]
        node.createwallet(wallet_name="mat_vault", blank=True)
        w = node.get_wallet_rpc("mat_vault")
        specs = [{"path": PATH, "hdkey": w.addhdkey()["xpub"]} for _ in range(3)]
        created = w.createmultisigdescriptor(2, specs, {"type": "bech32m", "fallback_older": 2})
        signer_fingerprint = re.search(r"\[([0-9a-fA-F]{8})/", created["descs"][0]).group(1)
        addr = w.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 1)
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 1)
        # After two generates the first UTXO has depth 2, the second depth 1.
        info = w.getvaultinfo()
        assert info["is_vault"]
        assert_greater_than(info["awaiting_maturity"], 0)
        assert_greater_than(float(info["spendable_now"]), 0)
        assert_equal(info["earliest_blocks_remaining"], 1)
        descs_before = w.listdescriptors()
        lost = w.setlostsigner(signer_fingerprint, True)
        assert signer_fingerprint in lost["lost_signers"]
        frozen = w.getvaultinfo()
        assert_equal(float(frozen["spendable_now"]), 0)
        assert_greater_than(float(frozen["recoverable_now"]), 0)
        assert_equal(w.listdescriptors(), descs_before)
        cleared = w.setlostsigner(signer_fingerprint, False)
        assert signer_fingerprint not in cleared["lost_signers"]
        assert_greater_than(float(w.getvaultinfo()["spendable_now"]), 0)
        w.setlostsigner(signer_fingerprint, True)
        dest = self.funding.getnewaddress()
        utxos = sorted(w.listunspent(), key=lambda u: u["confirmations"])
        young, old = utxos[0], utxos[-1]
        assert_equal(old["confirmations"], 2)
        assert_equal(young["confirmations"], 1)
        assert_raises_rpc_error(-4, "not yet recoverable", w.send,
                                outputs={dest: 1},
                                options={
                                    "change_type": "bech32m",
                                    "fee_rate": 1,
                                    "add_to_wallet": False,
                                    "add_inputs": False,
                                    "inputs": [{"txid": young["txid"], "vout": young["vout"], "sequence": 2}],
                                })
        # This deliberately custom one-stage policy has no durable exact
        # participant roster. Marking a signer lost therefore keeps signing
        # fail-closed even on a mature branch. Fixed 30/60 and 90/180 Recovery
        # Vaults test participant-scoped reduced-quorum signing separately.
        mature_options = {
            "change_type": "bech32m",
            "fee_rate": 1,
            "add_to_wallet": False,
            "add_inputs": False,
            "inputs": [{"txid": old["txid"], "vout": old["vout"], "sequence": 2}],
        }
        assert_raises_rpc_error(
            -25,
            "additional signatures",
            w.send,
            outputs={dest: 1},
            options=mature_options,
        )
        w.setlostsigner(signer_fingerprint, False)
        rec = w.send(outputs={dest: 1}, options=mature_options)
        assert rec["complete"]
        dec = node.decoderawtransaction(rec["hex"])
        assert_equal(dec["vin"][0]["sequence"], 2)
        assert_greater_than(len(dec["vin"][0]["txinwitness"]), 1)
        w.setlostsigner(signer_fingerprint, True)
        assert_raises_rpc_error(
            -25,
            "additional signatures",
            w.send,
            outputs={dest: 1},
            options={
                "change_type": "bech32m",
                "fee_rate": 1,
                "add_to_wallet": False,
                "vault_recovery": True,
            },
        )
        w.setlostsigner(signer_fingerprint, False)
        mature_auto = w.send(
            outputs={dest: 1},
            options={
                "change_type": "bech32m",
                "fee_rate": 1,
                "add_to_wallet": False,
                "vault_recovery": True,
            },
        )
        assert mature_auto["complete"]
        auto_dec = node.decoderawtransaction(mature_auto["hex"])
        assert_equal(auto_dec["vin"][0]["sequence"], 2)
        assert_greater_than(len(auto_dec["vin"][0]["txinwitness"]), 1)

    def test_after_recovery(self):
        self.log.info("after() recovery uses nLockTime and is blocked until the height")
        node = self.nodes[0]
        node.createwallet(wallet_name="after_vault", blank=True)
        w = node.get_wallet_rpc("after_vault")
        specs = [{"path": PATH, "hdkey": w.addhdkey()["xpub"]} for _ in range(2)]
        tip = node.getblockcount()
        after_h = tip + 3
        created = w.createmultisigdescriptor(1, specs, {"type": "bech32m", "fallback_after": after_h})
        assert_equal(created["fallback_after"], after_h)
        info = w.getvaultinfo()
        assert info["is_vault"]
        assert_equal(info["fallback_after"], after_h)
        assert "fallback_older" not in info
        addr = w.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 1)
        dest = self.funding.getnewaddress()
        early = w.getvaultinfo()
        assert_greater_than(early["awaiting_maturity"], 0)
        assert_greater_than(early["earliest_blocks_remaining"], 0)
        pkg = json.loads(w.exportvaultpolicy())
        assert_equal(pkg["fallback_after"], after_h)
        assert "fallback_older" not in pkg
        assert "xprv" not in json.dumps(pkg)
        assert_raises_rpc_error(-4, None, w.send,
                                outputs={dest: 1},
                                options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False, "vault_recovery": True})
        self.generate(node, 3)
        assert_raises_rpc_error(
            -8,
            "locktime conflicts with the selected vault recovery stage",
            w.send,
            outputs={dest: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False, "vault_recovery": True, "locktime": after_h - 1},
        )
        assert_raises_rpc_error(
            -8,
            "locktime conflicts with the selected vault recovery stage",
            w.send,
            outputs={dest: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False, "vault_recovery": True, "locktime": 500000000},
        )
        rec = w.send(
            outputs={dest: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False, "vault_recovery": True},
        )
        assert rec["complete"]
        dec = node.decoderawtransaction(rec["hex"])
        assert_equal(dec["locktime"], after_h)
        assert_greater_than(len(dec["vin"][0]["txinwitness"]), 1)
        funded = w.walletcreatefundedpsbt(
            [],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "fee_rate": 1, "vault_recovery": True},
        )
        proc = w.walletprocesspsbt(psbt=funded["psbt"])
        assert proc["complete"]
        funded_dec = node.decoderawtransaction(proc["hex"])
        assert_equal(funded_dec["locktime"], after_h)
        mature = w.getvaultinfo()
        assert_greater_than(float(mature["recoverable_now"]), 0)
        assert_equal(mature["awaiting_maturity"], 0)

    def test_no_silent_path_switch(self):
        self.log.info("Invariant: after the delay, send still uses the key-path unless vault_recovery is set")
        node = self.nodes[0]
        node.createwallet(wallet_name="nosilent", blank=True)
        w = node.get_wallet_rpc("nosilent")
        specs = [{"path": PATH, "hdkey": w.addhdkey()["xpub"]} for _ in range(2)]
        w.createmultisigdescriptor(1, specs, {"type": "bech32m", "fallback_older": 1})
        addr = w.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 2)
        dest = self.funding.getnewaddress()
        rec = w.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False, "vault_recovery": False})
        assert rec["complete"]
        dec = node.decoderawtransaction(rec["hex"])
        assert_equal(len(dec["vin"][0]["txinwitness"]), 1)
        assert_greater_than(dec["vin"][0]["sequence"], 0xffffff00)
        assert_equal(w.getvaultinfo()["nrequired"], 1)
        funded = w.walletcreatefundedpsbt(
            [],
            [{dest: 1}],
            0,
            {"change_type": "bech32m", "fee_rate": 1, "vault_recovery": True},
        )
        proc = w.walletprocesspsbt(psbt=funded["psbt"])
        assert proc["complete"]
        rec_dec = node.decoderawtransaction(proc["hex"])
        assert_equal(rec_dec["vin"][0]["sequence"], 1)
        assert_greater_than(len(rec_dec["vin"][0]["txinwitness"]), 1)

    def test_recovery_only_key(self):
        self.log.info("Recovery-only key is omitted from musig and cannot be used without a delay")
        node = self.nodes[0]
        node.createwallet(wallet_name="heir_vault", blank=True)
        w = node.get_wallet_rpc("heir_vault")
        a, b, c = w.addhdkey()["xpub"], w.addhdkey()["xpub"], w.addhdkey()["xpub"]
        keys = [
            {"path": PATH, "hdkey": a},
            {"path": PATH, "hdkey": b},
            {"path": PATH, "hdkey": c, "recovery_only": True},
        ]
        assert_raises_rpc_error(-8, "recovery-only keys require", w.createmultisigdescriptor, 1, keys, {"type": "bech32m"})
        created = w.createmultisigdescriptor(1, keys, {"type": "bech32m", "fallback_older": 1})
        desc = created["descs"][0]
        assert "older(1)" in desc
        assert "multi_a(1," in desc
        addr = w.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(addr, 5)
        self.generate(node, 1)
        dest = self.funding.getnewaddress()
        rec = w.send(outputs={dest: 1}, options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False})
        assert rec["complete"]
        assert_equal(len(node.decoderawtransaction(rec["hex"])["vin"][0]["txinwitness"]), 1)
        recov = w.send(
            outputs={dest: 1},
            options={"change_type": "bech32m", "fee_rate": 1, "add_to_wallet": False, "vault_recovery": True},
        )
        assert recov["complete"]
        recov_dec = node.decoderawtransaction(recov["hex"])
        assert_equal(recov_dec["vin"][0]["sequence"], 1)
        assert_greater_than(len(recov_dec["vin"][0]["txinwitness"]), 1)

    def test_vault_recovery_option_edges(self):
        self.log.info("vault_recovery is ignored on non-vaults; sendmany/sendtoaddress stay on the key-path")
        node = self.nodes[0]
        dest = self.funding.getnewaddress()
        node.createwallet(wallet_name="opt_vault", blank=True)
        w = node.get_wallet_rpc("opt_vault")
        specs = [{"path": PATH, "hdkey": w.addhdkey()["xpub"]} for _ in range(2)]
        w.createmultisigdescriptor(1, specs, {"type": "bech32m", "fallback_older": 1})
        addr = w.getnewaddress("", "bech32m")
        self.funding.sendtoaddress(addr, 8)
        self.generate(node, 2)
        sent = w.sendtoaddress(dest, 1)
        dec = node.decoderawtransaction(w.gettransaction(sent)["hex"])
        assert_equal(len(dec["vin"][0]["txinwitness"]), 1)
        many = w.sendmany("", {dest: 1})
        many_dec = node.decoderawtransaction(w.gettransaction(many)["hex"])
        assert_equal(len(many_dec["vin"][0]["txinwitness"]), 1)
        assert_raises_rpc_error(-8, "fallback_older must be between 1 and 65535",
                                w.createmultisigdescriptor, 1, specs, {"type": "bech32m", "fallback_older": 0})
        node.createwallet(wallet_name="opt_watch", blank=True, disable_private_keys=True)
        watch = node.get_wallet_rpc("opt_watch")
        pkg = w.exportvaultpolicy()
        first = watch.importvaultpolicy(pkg)
        again = watch.importvaultpolicy(pkg)
        assert_equal(first["policy_id"], again["policy_id"])
        assert_equal(watch.getvaultinfo()["is_vault"], True)


if __name__ == "__main__":
    WalletTaprootVaultPolicyTest(__file__).main()
