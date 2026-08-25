// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_WALLET_H
#define BITCOIN_INTERFACES_WALLET_H

#include <addresstype.h>
#include <common/signmessage.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <primitives/transaction_identifier.h>
#include <pubkey.h>
#include <script/script.h>
#include <support/allocators/secure.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/ui_change_type.h>
#include <wallet/vault_state.h>
#include <wallet/vault_renewal.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

class CFeeRate;
class CKey;
enum class FeeReason;
enum class OutputType;
class PartiallySignedTransaction;
struct bilingual_str;
namespace common {
enum class PSBTError;
} // namespace common
namespace node {
enum class TransactionError;
} // namespace node
namespace wallet {
struct CreatedTransactionResult;
class CCoinControl;
class CWallet;
enum class AddressPurpose;
struct CRecipient;
struct WalletContext;
} // namespace wallet

namespace interfaces {

class Handler;
struct WalletAddress;
struct WalletBalances;
struct WalletTx;
struct WalletTxOut;
struct WalletTxStatus;
struct WalletMigrationResult;

//! Interface for accessing a wallet.
class Wallet
{
public:
    using VaultSetupState = wallet::VaultSetupState;
    using VaultVerificationState = wallet::VaultVerificationState;
    using VaultParticipantType = wallet::VaultParticipantType;
    using VaultSignerAvailability = wallet::VaultSignerAvailability;

    virtual ~Wallet() = default;

    //! Encrypt wallet.
    virtual bool encryptWallet(const SecureString& wallet_passphrase) = 0;

    //! Return whether wallet is encrypted.
    virtual bool isCrypted() = 0;

    //! Lock wallet.
    virtual bool lock() = 0;

    //! Unlock wallet.
    virtual bool unlock(const SecureString& wallet_passphrase) = 0;

    //! Return whether wallet is locked.
    virtual bool isLocked() = 0;

    //! Change wallet passphrase.
    virtual bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) = 0;

    //! Abort a rescan.
    virtual void abortRescan() = 0;

    //! Back up wallet.
    virtual bool backupWallet(const std::string& filename) = 0;

    //! Get wallet name.
    virtual std::string getWalletName() = 0;

    // Get a new address.
    virtual util::Result<CTxDestination> getNewDestination(OutputType type, const std::string& label) = 0;

    //! Get public key.
    virtual bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) = 0;

    //! Sign message
    virtual SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) = 0;

    //! Return whether wallet has private key.
    virtual bool isSpendable(const CTxDestination& dest) = 0;

    //! Add or update address.
    virtual bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::optional<wallet::AddressPurpose>& purpose) = 0;

    // Remove address.
    virtual bool delAddressBook(const CTxDestination& dest) = 0;

    //! Look up address in wallet, return whether exists.
    virtual bool getAddress(const CTxDestination& dest,
        std::string* name,
        wallet::AddressPurpose* purpose) = 0;

    //! Get wallet address list.
    virtual std::vector<WalletAddress> getAddresses() = 0;

    //! Get receive requests.
    virtual std::vector<std::string> getAddressReceiveRequests() = 0;

    //! Save or remove receive request.
    virtual bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) = 0;

    //! Display address on an external signer. If fingerprint is set, that
    //! device is required (multisig verification). Otherwise any matching
    //! connected signer is used.
    virtual util::Result<void> displayAddress(const CTxDestination& dest, const std::optional<std::string>& fingerprint = {}) = 0;

    //! One key for createMultisigDescriptor (mirrors wallet::MultisigKeySpec).
    struct MultisigKey {
        std::optional<std::string> path;
        std::optional<std::string> fingerprint;
        std::optional<std::string> hdkey;
        std::optional<std::string> xpub;
        bool recovery_only{false};
        bool generate_local{false};
        //! Private in-process restore input. Never exposed by the wallet RPC.
        std::optional<SecureString> recovery_mnemonic;
    };

    struct GeneratedMnemonic {
        size_t key_index{0};
        SecureString mnemonic;
        std::string fingerprint;
        std::string path;
        std::string xpub;
    };

    struct CreateMultisigResult {
        std::vector<std::string> descs;
        std::vector<GeneratedMnemonic> recovery;
    };

    //! Public metadata for a software key matched while restoring a vault.
    struct VaultMnemonicMatch {
        size_t mnemonic_index{0};
        std::string fingerprint;
        std::string path;
        std::string xpub;
    };

    //! Import an active sorted-multisig descriptor (see createmultisigdescriptor).
    virtual util::Result<CreateMultisigResult> createMultisigDescriptor(int nrequired,
        const std::vector<MultisigKey>& keys,
        OutputType type,
        std::optional<uint32_t> fallback_older = {},
        std::optional<uint32_t> fallback_after = {},
        std::optional<uint32_t> fallback_older_one_key = {}) = 0;

    //! Lock coin.
    virtual bool lockCoin(const COutPoint& output, bool write_to_db) = 0;

    //! Unlock coin.
    virtual bool unlockCoin(const COutPoint& output) = 0;

    //! Return whether coin is locked.
    virtual bool isLockedCoin(const COutPoint& output) = 0;

    //! List locked coins.
    virtual void listLockedCoins(std::vector<COutPoint>& outputs) = 0;

    //! Create transaction.
    virtual util::Result<wallet::CreatedTransactionResult> createTransaction(const std::vector<wallet::CRecipient>& recipients,
                                                                             const wallet::CCoinControl& coin_control,
                                                                             bool sign,
                                                                             std::optional<unsigned int> change_pos,
                                                                             std::optional<std::string> expected_vault_policy_commitment = std::nullopt) = 0;

    //! Commit transaction. If supplied, expected_vault_state is compared under
    //! the wallet lock before the transaction is added or broadcast.
    virtual bool commitTransaction(
        CTransactionRef tx,
        const std::vector<std::string>& messages,
        const std::optional<wallet::VaultCommitState>& expected_vault_state = std::nullopt) = 0;

    //! Return whether transaction can be abandoned.
    virtual bool transactionCanBeAbandoned(const Txid& txid) = 0;

    //! Abandon transaction.
    virtual bool abandonTransaction(const Txid& txid) = 0;

    //! Return whether transaction can be bumped.
    virtual bool transactionCanBeBumped(const Txid& txid) = 0;

    //! Create bump transaction.
    virtual bool createBumpTransaction(const Txid& txid,
        const wallet::CCoinControl& coin_control,
        std::vector<bilingual_str>& errors,
        CAmount& old_fee,
        CAmount& new_fee,
        CMutableTransaction& mtx) = 0;

    //! Sign bump transaction.
    virtual bool signBumpTransaction(
        CMutableTransaction& mtx,
        std::optional<wallet::VaultCommitState>* signed_vault_state = nullptr) = 0;

    //! Commit bump transaction.
    virtual bool commitBumpTransaction(const Txid& txid,
                                       CMutableTransaction&& mtx,
                                       std::vector<bilingual_str>& errors,
                                       Txid& bumped_txid,
                                       const std::optional<wallet::VaultCommitState>& expected_vault_state = std::nullopt) = 0;

    //! Get a transaction.
    virtual CTransactionRef getTx(const Txid& txid) = 0;

    //! Get transaction information.
    virtual WalletTx getWalletTx(const Txid& txid) = 0;

    //! Get list of all wallet transactions.
    virtual std::set<WalletTx> getWalletTxs() = 0;

    //! Try to get updated status for a particular transaction, if possible without blocking.
    virtual bool tryGetTxStatus(const Txid& txid,
        WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) = 0;

    //! Get transaction details.
    virtual WalletTx getWalletTxDetails(const Txid& txid,
        WalletTxStatus& tx_status,
        std::vector<std::string>& messages,
        std::vector<std::string>& payment_requests,
        bool& in_mempool,
        int& num_blocks) = 0;

    //! Fill PSBT.
    virtual std::optional<common::PSBTError> fillPSBT(const common::PSBTFillOptions& options,
                                                      size_t* n_signed,
                                                      PartiallySignedTransaction& psbtx,
                                                      bool& complete,
                                                      std::optional<wallet::VaultCommitState>* signed_vault_state = nullptr) = 0;

    //! Get balances.
    virtual WalletBalances getBalances() = 0;

    //! Get balances if possible without blocking.
    virtual bool tryGetBalances(WalletBalances& balances, uint256& block_hash) = 0;

    //! Get balance.
    virtual CAmount getBalance() = 0;

    //! Get available balance.
    virtual CAmount getAvailableBalance(const wallet::CCoinControl& coin_control) = 0;

    //! Return whether transaction input belongs to wallet.
    virtual bool txinIsMine(const CTxIn& txin) = 0;

    //! Return whether transaction output belongs to wallet.
    virtual bool txoutIsMine(const CTxOut& txout) = 0;

    //! Return debit amount if transaction input belongs to wallet.
    virtual CAmount getDebit(const CTxIn& txin) = 0;

    //! Return credit amount if transaction input belongs to wallet.
    virtual CAmount getCredit(const CTxOut& txout) = 0;

    //! Return AvailableCoins + LockedCoins grouped by wallet address.
    //! (put change in one group with wallet address)
    using CoinsList = std::map<CTxDestination, std::vector<std::tuple<COutPoint, WalletTxOut>>>;
    virtual CoinsList listCoins() = 0;

    //! Return wallet transaction output information.
    virtual std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) = 0;

    //! Get required fee.
    virtual CAmount getRequiredFee(unsigned int tx_bytes) = 0;

    //! Get minimum fee.
    virtual CAmount getMinimumFee(unsigned int tx_bytes,
        const wallet::CCoinControl& coin_control,
        int* returned_target,
        FeeReason* reason) = 0;

    //! Get tx confirm target.
    virtual unsigned int getConfirmTarget() = 0;

    // Return whether HD enabled.
    virtual bool hdEnabled() = 0;

    // Return whether the wallet can generate any receiving address.
    virtual bool canGetAddresses() = 0;

    // Return whether the wallet can generate a receiving address of the given type.
    virtual bool canGetAddresses(OutputType type) = 0;

    // Return whether private keys enabled.
    virtual bool privateKeysDisabled() = 0;

    // Return whether the wallet contains a Taproot scriptPubKeyMan.
    virtual bool taprootEnabled() = 0;

    //! BIP68 older(N) from an active Scrooge vault tr(musig,and_v(v:older(N),…)), if any.
    virtual std::optional<uint32_t> taprootRecoveryDelay() = 0;

    struct VaultStatus {
        struct VaultParticipant {
            std::string fingerprint;
            std::string path;
            std::string xpub;
            VaultParticipantType type{VaultParticipantType::UNKNOWN};
            VaultSignerAvailability availability{VaultSignerAvailability::UNKNOWN};
            bool is_lost{false};
        };
        struct VaultRecoveryStage {
            int nrequired{0};
            std::optional<uint32_t> older;
            std::optional<uint32_t> after;
            CAmount recoverable_now{0};
            CAmount awaiting_maturity{0};
            std::optional<int> earliest_blocks_remaining;
        };
        bool is_vault{false};
        bool is_fixed_staged_vault{false};
        //! Full commitment to the active policy, used as an internal
        //! compare-and-set token rather than as a user-facing identifier.
        std::string policy_commitment;
        bool genesis_rescan_required{false};
        VaultSetupState setup_state{VaultSetupState::NOT_RECORDED};
        VaultVerificationState verification_state{VaultVerificationState::NOT_RECORDED};
        bool signer_discovery_complete{false};
        std::optional<uint32_t> older;
        std::optional<uint32_t> after;
        int recovery_m{0};
        //! Confirmed value eligible for the immediate policy path. Signer
        //! availability is reported separately and never erases this amount.
        CAmount immediate{0};
        CAmount recoverable_now{0};
        CAmount awaiting_maturity{0};
        std::optional<int> earliest_blocks_remaining;
        std::vector<std::string> lost_signers;
        std::vector<std::string> manually_lost_signers;
        std::vector<VaultParticipant> participants;
        std::vector<VaultRecoveryStage> recovery_stages;
    };
    virtual VaultStatus getVaultStatus() = 0;
    //! Read the current 90/180-day protection-renewal state. Unsupported or
    //! legacy schedules return a truthful status with supported=false.
    virtual wallet::VaultRenewalStatus getVaultRenewalStatus() = 0;
    //! Select whole privacy clusters without reserving a destination.
    virtual util::Result<wallet::VaultRenewalPlan> planVaultRenewal(
        const wallet::VaultRenewalRequest& request) = 0;
    //! Create exact unsigned transactions, one fresh internal output per
    //! cluster (split only when required by transaction weight).
    virtual util::Result<wallet::VaultRenewalBatch> createVaultRenewalBatch(
        const wallet::VaultRenewalPlan& plan,
        const wallet::CCoinControl& fee_control) = 0;
    //! Directly sign one item through the immediate all-participant key path.
    virtual util::Result<void> signVaultRenewalTransaction(
        wallet::VaultRenewalBatch& batch, size_t transaction_index) = 0;
    //! Refuse to commit any item until the whole batch is signed and
    //! revalidated, then report immediate relay truth per transaction.
    virtual util::Result<wallet::VaultRenewalCommitResult> commitVaultRenewalBatch(
        const wallet::VaultRenewalBatch& batch) = 0;
    //! Persist an explicit user decision that a signer is lost. This is local
    //! metadata only and never changes the on-chain policy.
    virtual bool setLostSigner(
        const std::string& fingerprint, bool lost,
        const std::optional<std::string>& expected_policy_commitment = std::nullopt) = 0;
    //! Clear discovery-created unavailable metadata only when the signer has
    //! not subsequently been marked lost by the user or RPC. The check and
    //! mutation are atomic under the wallet lock.
    virtual bool clearAutomaticallyLostSigner(
        const std::string& fingerprint,
        const std::optional<std::string>& expected_policy_commitment = std::nullopt) = 0;
    //! Atomically persist setup progress and address-verification truth. When
    //! supplied, expected_policy_commitment makes this a compare-and-set
    //! against the complete active public policy.
    virtual bool setVaultSetupState(
        VaultSetupState setup, VaultVerificationState verification,
        const std::optional<std::string>& expected_policy_commitment = std::nullopt) = 0;
    //! Persist how a participant is expected to sign. Availability remains a
    //! fresh runtime observation and is never written to the wallet database.
    //! The optional commitment provides the same policy compare-and-set as
    //! setup-state writes.
    virtual bool setVaultParticipantType(
        const std::string& fingerprint, VaultParticipantType type,
        const std::optional<std::string>& expected_policy_commitment = std::nullopt) = 0;
    virtual std::string exportVaultPolicy() = 0;
    virtual util::Result<void> importVaultPolicy(const std::string& json) = 0;
    //! Restore private vault participants from BIP39 phrases and a public
    //! policy package, then synchronously rescan from genesis. Recovery
    //! phrases are accepted only in-process.
    virtual util::Result<std::vector<VaultMnemonicMatch>> restoreVaultPolicy(
        const std::string& package_json, const std::vector<SecureString>& mnemonics) = 0;
    //! Rescan a fully installed timestamp-zero vault from genesis. This is
    //! deliberately separate from secret import so callers can cleanse phrase
    //! buffers before a potentially long scan and safely retry scan failures.
    virtual util::Result<void> rescanFromGenesis() = 0;

    // Return whether wallet uses an external signer.
    virtual bool hasExternalSigner() = 0;

    // Get default address type.
    virtual OutputType getDefaultAddressType() = 0;

    //! Get max tx fee.
    virtual CAmount getDefaultMaxTxFee() = 0;

    // Remove wallet.
    virtual void remove() = 0;

    //! Register handler for unload message.
    using UnloadFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleUnload(UnloadFn fn) = 0;

    //! Register handler for show progress messages.
    using ShowProgressFn = std::function<void(const std::string& title, int progress)>;
    virtual std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) = 0;

    //! Register handler for status changed messages.
    using StatusChangedFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) = 0;

    //! Register handler for address book changed messages.
    using AddressBookChangedFn = std::function<void(const CTxDestination& address,
        const std::string& label,
        bool is_mine,
        wallet::AddressPurpose purpose,
        ChangeType status)>;
    virtual std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) = 0;

    //! Register handler for transaction changed messages.
    using TransactionChangedFn = std::function<void(const Txid& txid, ChangeType status)>;
    virtual std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) = 0;

    //! Register handler for keypool changed messages.
    using CanGetAddressesChangedFn = std::function<void()>;
    virtual std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) = 0;

    //! Return pointer to internal wallet class, useful for testing.
    virtual wallet::CWallet* wallet() { return nullptr; }

    //! Export a watchonly wallet file. See CWallet::ExportWatchOnlyWallet
    virtual util::Result<std::string> exportWatchOnlyWallet(const fs::path& destination) = 0;
};

enum class FixedVaultInstallMode {
    CREATE,
    RESTORE,
};

//! Whether an installed fixed vault may dispatch signing operations to HWI.
//! Restore authority is an explicit user choice; the number of supplied local
//! mnemonics must never silently enable connected devices.
enum class FixedVaultExternalSigning {
    DISABLED,
    ENABLED,
};

struct FixedVaultInstallResult {
    std::unique_ptr<Wallet> wallet;
    std::vector<Wallet::VaultMnemonicMatch> matches;
};

//! Wallet chain client that in addition to having chain client methods for
//! starting up, shutting down, and registering RPCs, also has additional
//! methods (called by the GUI) to load and create wallets.
class WalletLoader : public ChainClient
{
public:
    //! Check that the active chain is synchronized and retains every block
    //! needed for a wallet rescan beginning at genesis. This is a read-only
    //! preflight; callers must still handle the chain changing afterward.
    virtual util::Result<void> checkRescanFromGenesis() = 0;

    //! Atomically publish a complete supported fixed Recovery Vault. New
    //! creation uses the current schedule; restore also accepts the legacy
    //! fixed schedule. The package must be exact canonical public JSON and
    //! phrases may be empty. CREATE timestamps descriptors at installation
    //! time; RESTORE uses timestamp zero. Before publication, the staged
    //! database is durably bound to the exact policy with an incomplete setup
    //! state. The final wallet name is not created until that complete SQLite
    //! staging wallet has been closed and is ready for atomic publication.
    virtual util::Result<FixedVaultInstallResult> installFixedVault(
        const std::string& name,
        const std::string& canonical_package,
        const std::vector<SecureString>& mnemonics,
        FixedVaultInstallMode mode,
        std::vector<bilingual_str>& warnings,
        FixedVaultExternalSigning external_signing = FixedVaultExternalSigning::ENABLED) = 0;

    //! Create new wallet.
    virtual util::Result<std::unique_ptr<Wallet>> createWallet(const std::string& name, const SecureString& passphrase, uint64_t wallet_creation_flags, std::vector<bilingual_str>& warnings) = 0;

    //! Load existing wallet.
    virtual util::Result<std::unique_ptr<Wallet>> loadWallet(const std::string& name, std::vector<bilingual_str>& warnings) = 0;

    //! Return default wallet directory.
    virtual std::string getWalletDir() = 0;

    //! Restore backup wallet
    virtual util::Result<std::unique_ptr<Wallet>> restoreWallet(const fs::path& backup_file, const std::string& wallet_name, std::vector<bilingual_str>& warnings, bool load_after_restore) = 0;

    //! Migrate a wallet
    virtual util::Result<WalletMigrationResult> migrateWallet(const std::string& name, const SecureString& passphrase, bool load_wallet) = 0;

    //! Returns true if wallet stores encryption keys
    virtual bool isEncrypted(const std::string& wallet_name) = 0;

    //! Return available wallets in wallet directory.
    virtual std::vector<std::pair<std::string, std::string>> listWalletDir() = 0;

    //! Return interfaces for accessing wallets (if any).
    virtual std::vector<std::unique_ptr<Wallet>> getWallets() = 0;

    //! Register handler for load wallet messages. This callback is triggered by
    //! createWallet and loadWallet above, and also triggered when wallets are
    //! loaded at startup or by RPC.
    using LoadWalletFn = std::function<void(std::unique_ptr<Wallet> wallet)>;
    virtual std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) = 0;

    //! Return pointer to internal context, useful for testing.
    virtual wallet::WalletContext* context() { return nullptr; }
};

//! Information about one wallet address.
struct WalletAddress
{
    CTxDestination dest;
    bool is_mine;
    wallet::AddressPurpose purpose;
    std::string name;

    WalletAddress(CTxDestination dest, bool is_mine, wallet::AddressPurpose purpose, std::string name)
        : dest(std::move(dest)), is_mine(is_mine), purpose(std::move(purpose)), name(std::move(name))
    {
    }
};

//! Collection of wallet balances.
struct WalletBalances
{
    CAmount balance = 0;
    CAmount unconfirmed_balance = 0;
    CAmount immature_balance = 0;
    CAmount used_balance = 0;
    CAmount nonmempool_balance = 0;
    bool is_vault{false};
    CAmount vault_immediate{0};
    CAmount vault_recoverable{0};
    CAmount vault_awaiting{0};
    std::optional<int> vault_blocks_remaining;

    bool balanceChanged(const WalletBalances& prev) const
    {
        return balance != prev.balance || unconfirmed_balance != prev.unconfirmed_balance ||
               immature_balance != prev.immature_balance ||
               used_balance != prev.used_balance || nonmempool_balance != prev.nonmempool_balance ||
               is_vault != prev.is_vault || vault_immediate != prev.vault_immediate ||
               vault_recoverable != prev.vault_recoverable ||
               vault_awaiting != prev.vault_awaiting || vault_blocks_remaining != prev.vault_blocks_remaining;
    }
};

// Wallet transaction information.
struct WalletTx
{
    CTransactionRef tx;
    std::vector<bool> txin_is_mine;
    std::vector<bool> txout_is_mine;
    std::vector<bool> txout_is_change;
    std::vector<CTxDestination> txout_address;
    std::vector<bool> txout_address_is_mine;
    CAmount credit;
    CAmount debit;
    CAmount change;
    int64_t time;
    std::optional<std::string> from; // Deprecated
    std::optional<std::string> message; // Deprecated
    std::optional<std::string> comment;
    std::optional<std::string> comment_to;
    bool is_coinbase;

    bool operator<(const WalletTx& a) const { return tx->GetHash() < a.tx->GetHash(); }
};

//! Updated transaction status.
struct WalletTxStatus
{
    int block_height;
    int blocks_to_maturity;
    int depth_in_main_chain;
    unsigned int time_received;
    uint32_t lock_time;
    bool is_trusted;
    bool is_abandoned;
    bool is_coinbase;
    bool is_in_main_chain;
};

//! Wallet transaction output.
struct WalletTxOut
{
    CTxOut txout;
    int64_t time;
    int depth_in_main_chain = -1;
    bool is_spent = false;
};

//! Migrated wallet info
struct WalletMigrationResult
{
    std::unique_ptr<Wallet> wallet;
    std::optional<std::string> watchonly_wallet_name;
    std::optional<std::string> solvables_wallet_name;
    fs::path backup_path;
};

//! Return implementation of Wallet interface. This function is defined in
//! dummywallet.cpp and throws if the wallet component is not compiled.
std::unique_ptr<Wallet> MakeWallet(wallet::WalletContext& context, const std::shared_ptr<wallet::CWallet>& wallet);

//! Return implementation of ChainClient interface for a wallet loader. This
//! function will be undefined in builds where ENABLE_WALLET is false.
std::unique_ptr<WalletLoader> MakeWalletLoader(Chain& chain, ArgsManager& args);

} // namespace interfaces

#endif // BITCOIN_INTERFACES_WALLET_H
