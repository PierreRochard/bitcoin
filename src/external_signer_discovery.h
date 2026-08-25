// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_EXTERNAL_SIGNER_DISCOVERY_H
#define BITCOIN_EXTERNAL_SIGNER_DISCOVERY_H

#include <interfaces/external_signer.h>
#include <util/result.h>

#include <functional>
#include <string>
#include <vector>

class PartiallySignedTransaction;

/** Enumerate external signers without discarding diagnostic evidence.
 *
 * This API is intentionally separate from ExternalSigner::Enumerate(), whose
 * duplicate filtering, errors, and RPC-facing behavior remain unchanged.
 */
interfaces::ExternalSignerDiscovery DiscoverExternalSigners(
    const std::string& command,
    const std::string& chain,
    const std::string& account_path);

/** Re-enumerate and display a descriptor on one exact fixed-vault signer.
 *
 * The complete expected roster is checked immediately before display. Native
 * signers are then connected by the enumerated physical path, and their
 * fingerprint, account xpub, and display capability are re-derived on that
 * same connection. Subprocess signers are addressed by device path and have
 * their account xpub queried again immediately before display.
 */
util::Result<interfaces::ExternalSignerAddressVerification> VerifyAddressOnExactExternalSigner(
    const std::string& command,
    const std::string& chain,
    const std::vector<interfaces::ExternalSignerExpectedIdentity>& expected_roster,
    const std::string& preferred_fingerprint,
    const std::string& descriptor);

/** Sign a PSBT only with freshly revalidated fixed-vault hardware identities.
 *
 * `allowed_signers` must already exclude lost, air-gapped, and otherwise
 * unauthorized participants. Only allowed identities referenced by a PSBT key
 * origin and presently connected are contacted. Each contacted identity must
 * be unique and must match its fingerprint, account path, complete account
 * xpub, and staged-vault signing capabilities. A missing authorized identity
 * is left for a later/offline signing pass, which lets a threshold recovery
 * use any sufficient subset without weakening identity checks. Native signers
 * are rechecked and signed on the same physical connection; subprocess
 * signers are selected by device path and have their account xpub queried
 * again immediately before the PSBT is sent.
 *
 * If supplied, `validate_response` runs on the isolated merged PSBT after each
 * device response and before another device can receive it. The returned
 * fingerprints are the exact devices that received the PSBT. The input PSBT
 * is updated atomically only after every response succeeds validation.
 */
util::Result<std::vector<std::string>> SignPSBTWithExactExternalSigners(
    const std::string& command,
    const std::string& chain,
    const std::vector<interfaces::ExternalSignerExpectedIdentity>& allowed_signers,
    PartiallySignedTransaction& psbt,
    const std::function<bool(const PartiallySignedTransaction&)>& validate_response = {});

#endif // BITCOIN_EXTERNAL_SIGNER_DISCOVERY_H
