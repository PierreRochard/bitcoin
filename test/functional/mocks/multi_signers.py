#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import argparse
import json
import sys

def enumerate(args):
    sys.stdout.write(json.dumps([{"fingerprint": "00000001", "type": "trezor", "model": "trezor_t"},
        {"fingerprint": "00000002", "type": "trezor", "model": "trezor_one"}]))

def getdescriptors(args):
    xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
    sys.stdout.write(json.dumps({
        "receive": [
            "pkh([00000001/44h/1h/" + args.account + "']" + xpub + "/0/*)#aqllu46s",
            "sh(wpkh([00000001/49h/1h/" + args.account + "']" + xpub + "/0/*))#5dh56mgg",
            "wpkh([00000001/84h/1h/" + args.account + "']" + xpub + "/0/*)#h62dxaej",
            "tr([00000001/86h/1h/" + args.account + "']" + xpub + "/0/*)#pcd5w87f"
        ],
        "internal": [
            "pkh([00000001/44h/1h/" + args.account + "']" + xpub + "/1/*)#v567pq2g",
            "sh(wpkh([00000001/49h/1h/" + args.account + "']" + xpub + "/1/*))#pvezzyah",
            "wpkh([00000001/84h/1h/" + args.account + "']" + xpub + "/1/*)#xw0vmgf2",
            "tr([00000001/86h/1h/" + args.account + "']" + xpub + "/1/*)#svg4njw3"
        ]
    }))

parser = argparse.ArgumentParser(prog='./multi_signers.py', description='External multi-signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--chain', default='main')
parser.add_argument('--stdin', action='store_true')

subparsers = parser.add_subparsers(description='Commands', dest='command')
subparsers.required = True

parser_enumerate = subparsers.add_parser('enumerate', help='list available signers')
parser_enumerate.set_defaults(func=enumerate)

parser_getdescriptors = subparsers.add_parser('getdescriptors')
parser_getdescriptors.set_defaults(func=getdescriptors)
parser_getdescriptors.add_argument('--account', metavar='account')


if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
        sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()

args.func(args)
