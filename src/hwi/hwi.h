// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HWI_HWI_H
#define BITCOIN_HWI_HWI_H

#include <key.h>
#include <outputtype.h>
#include <pubkey.h>
#include <util/chaintype.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

class PartiallySignedTransaction;

//! Native C++ Hardware Wallet Interface.
//!
//! This is a rewrite of bitcoin-core/HWI (Python) that lives in-process with
//! Bitcoin Core. It reuses Core's PSBT, descriptor, and key types instead of
//! porting hwilib's copies of those.
//!
//! USB device drivers are added incrementally. Until then, a software mock
//! (see hwi/mock.h) stands in for hardware so wallet and GUI work can proceed.
namespace hwi {

//! `-signer` value that selects this in-process implementation instead of
//! shelling out to Python HWI or another command.
inline constexpr std::string_view NATIVE_SIGNER_COMMAND{"internal"};

inline bool IsNativeSignerCommand(std::string_view command)
{
    return command == NATIVE_SIGNER_COMMAND || command == "hwi";
}

//! Error codes match bitcoin-core/HWI hwilib/errors.py so the two
//! implementations can be compared and so JSON error objects stay compatible.
enum class ErrorCode : int {
    NO_DEVICE_TYPE = -1,
    MISSING_ARGUMENTS = -2,
    DEVICE_CONN_ERROR = -3,
    UNKNOWN_DEVICE_TYPE = -4,
    INVALID_TX = -5,
    NO_PASSWORD = -6,
    BAD_ARGUMENT = -7,
    NOT_IMPLEMENTED = -8,
    UNAVAILABLE_ACTION = -9,
    UNKNOWN_ERROR = -13,
    ACTION_CANCELED = -14,
    DEVICE_BUSY = -15,
};

class HWIError : public std::runtime_error
{
public:
    HWIError(const std::string& msg, ErrorCode code);
    ErrorCode code() const { return m_code; }

private:
    ErrorCode m_code;
};

struct DeviceInfo {
    std::string type;
    std::string model;
    std::string path;
    std::string fingerprint; //!< 8 lowercase hex characters; empty if locked
    bool needs_pin{false};
    bool needs_passphrase{false};
    std::optional<std::string> error;
};

struct DescriptorSets {
    std::vector<std::string> receive;
    std::vector<std::string> internal;
};

//! Per-device driver. Mirrors hwilib.hwwclient.HardwareWalletClient.
//! Device implementations supply key export and signing; descriptor assembly
//! lives in the command helpers below so it can use Core's descriptor language.
class HardwareWalletClient
{
public:
    HardwareWalletClient(std::string path, ChainType chain);
    virtual ~HardwareWalletClient() = default;

    const std::string& Path() const { return m_path; }
    ChainType GetChain() const { return m_chain; }
    void SetChain(ChainType chain) { m_chain = chain; }

    virtual std::string Type() const = 0;
    virtual CExtPubKey GetPubkeyAtPath(const std::string& bip32_path) const = 0;
    virtual PartiallySignedTransaction SignTx(PartiallySignedTransaction psbt) const = 0;
    virtual std::string SignMessage(const std::string& message, const std::string& bip32_path) const = 0;
    virtual bool CanSignTaproot() const = 0;
    virtual void Close() = 0;

    virtual KeyFingerprint GetMasterFingerprint() const;
    virtual CExtPubKey GetMasterXpub(OutputType type, uint32_t account = 0) const;
    virtual std::string DisplaySinglesigAddress(const std::string& bip32_path, OutputType type) const;
    virtual std::string DisplayMultisigAddress(const std::string& descriptor) const;

protected:
    std::string m_path;
    ChainType m_chain;
};

std::vector<DeviceInfo> Enumerate();
std::unique_ptr<HardwareWalletClient> FindDevice(const std::string& fingerprint,
                                                 std::optional<std::string> type = std::nullopt);

DescriptorSets GetDescriptors(const HardwareWalletClient& client, int account = 0);
std::string DisplayAddress(const HardwareWalletClient& client, const std::string& descriptor);

uint32_t BIP44Purpose(OutputType type);
uint32_t BIP44CoinType(ChainType chain);
std::string FingerprintHex(const KeyFingerprint& fingerprint);

} // namespace hwi

#endif // BITCOIN_HWI_HWI_H
