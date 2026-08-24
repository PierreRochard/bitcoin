// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_INTERFACES_EXTERNAL_SIGNER_H
#define BITCOIN_INTERFACES_EXTERNAL_SIGNER_H

#include <optional>
#include <string>
#include <vector>

namespace interfaces {

//! Outcome of a diagnostic-preserving external signer discovery attempt.
enum class ExternalSignerDiscoveryStatus {
    NOT_CONFIGURED, //!< No -signer command was configured.
    SUCCESS,        //!< Enumeration completed, possibly with zero devices.
    FAILED,         //!< Enumeration could not be completed reliably.
};

//! Raw evidence for one enumerated external signer device.
struct ExternalSignerDeviceDiagnostics {
    std::string path;
    std::string type;
    std::string model;
    std::string fingerprint;
    bool locked{false};
    bool duplicate{false};
    std::optional<std::string> error;
    std::optional<bool> supports_staged_vault;
    //! Explicit physical-display capability. Missing and false both mean the
    //! UI must use the honest Review state rather than claim verification.
    std::optional<bool> supports_multisig_address_display;
    std::optional<std::string> account_xpub;
    std::optional<std::string> account_xpub_error;

    //! Fixed-vault callers must reject every device for which this is false.
    bool IsUsableForStagedVault() const
    {
        return !locked && !duplicate && !error && supports_staged_vault.value_or(false) &&
               account_xpub.has_value() && !account_xpub_error;
    }
};

struct ExternalSignerDiscovery {
    ExternalSignerDiscoveryStatus status{ExternalSignerDiscoveryStatus::FAILED};
    std::string account_path;
    std::vector<ExternalSignerDeviceDiagnostics> devices;
    std::optional<std::string> error;
};

} // namespace interfaces

#endif // BITCOIN_INTERFACES_EXTERNAL_SIGNER_H
