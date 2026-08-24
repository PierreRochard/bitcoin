// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_EXTERNAL_SIGNER_DISCOVERY_H
#define BITCOIN_EXTERNAL_SIGNER_DISCOVERY_H

#include <interfaces/external_signer.h>

#include <string>

/** Enumerate external signers without discarding diagnostic evidence.
 *
 * This API is intentionally separate from ExternalSigner::Enumerate(), whose
 * duplicate filtering, errors, and RPC-facing behavior remain unchanged.
 */
interfaces::ExternalSignerDiscovery DiscoverExternalSigners(
    const std::string& command,
    const std::string& chain,
    const std::string& account_path);

#endif // BITCOIN_EXTERNAL_SIGNER_DISCOVERY_H
