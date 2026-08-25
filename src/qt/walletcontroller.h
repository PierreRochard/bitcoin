// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETCONTROLLER_H
#define BITCOIN_QT_WALLETCONTROLLER_H

#include <qt/sendcoinsrecipient.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <util/result.h>
#include <util/translation.h>

#include <QLockFile>
#include <QMessageBox>
#include <QMutex>
#include <QPointer>
#include <QProgressDialog>
#include <QString>
#include <QThread>
#include <QTimer>

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

class ClientModel;
class OptionsModel;
class PlatformStyle;
class WalletModel;

namespace interfaces {
class Handler;
class Node;
class Wallet;
} // namespace interfaces

namespace fs {
class path;
}

class AskPassphraseDialog;
class CreateWalletActivity;
class CreateWalletDialog;
class MigrateWalletActivity;
class MnemonicRestoreActivity;
class OpenWalletActivity;
class WalletControllerActivity;

/**
 * Controller between interfaces::Node, WalletModel instances and the GUI.
 */
class WalletController : public QObject
{
    Q_OBJECT

    void removeAndDeleteWallet(WalletModel* wallet_model);

public:
    WalletController(ClientModel& client_model, const PlatformStyle* platform_style, QObject* parent);
    ~WalletController();

    WalletModel* getOrCreateWallet(std::unique_ptr<interfaces::Wallet> wallet);

    //! Returns all wallet names in the wallet dir mapped to whether the wallet
    //! is loaded.
    std::map<std::string, std::pair<bool, std::string>> listWalletDir() const;

    void closeWallet(WalletModel* wallet_model, QWidget* parent = nullptr);
    void closeAllWallets(QWidget* parent = nullptr);

    //! Retain ownership of a private Recovery Kit PDF that could not be
    //! deleted while its external viewer was still using it. The controller
    //! retries without keeping the setup surface open.
    void retainRecoveryKitCleanup(QString path, std::unique_ptr<QLockFile> lock);
    void retryPendingRecoveryKitCleanup();
    size_t pendingRecoveryKitCleanupCount() const { return m_recovery_kit_cleanup.size(); }

Q_SIGNALS:
    void walletAdded(WalletModel* wallet_model);
    void walletRemoved(WalletModel* wallet_model);

    void coinsSent(WalletModel* wallet_model, SendCoinsRecipient recipient, QByteArray transaction);

private:
    QThread* const m_activity_thread;
    QObject* const m_activity_worker;
    ClientModel& m_client_model;
    interfaces::Node& m_node;
    const PlatformStyle* const m_platform_style;
    OptionsModel* const m_options_model;
    mutable QMutex m_mutex;
    std::vector<WalletModel*> m_wallets;
    std::unique_ptr<interfaces::Handler> m_handler_load_wallet;
    struct RecoveryKitCleanup {
        QString path;
        std::unique_ptr<QLockFile> lock;
    };
    std::vector<RecoveryKitCleanup> m_recovery_kit_cleanup;
    QTimer m_recovery_kit_cleanup_timer;

    friend class WalletControllerActivity;
    friend class MigrateWalletActivity;

    //! Starts the wallet closure procedure
    void removeWallet(WalletModel* wallet_model);
};

class WalletControllerActivity : public QObject
{
    Q_OBJECT

public:
    WalletControllerActivity(WalletController* wallet_controller, QWidget* parent_widget);
    virtual ~WalletControllerActivity() = default;

Q_SIGNALS:
    void finished();

protected:
    interfaces::Node& node() const { return m_wallet_controller->m_node; }
    QObject* worker() const { return m_wallet_controller->m_activity_worker; }

    void showProgressDialog(const QString& title_text, const QString& label_text, bool show_minimized=false);
    void closeProgressDialog();

    WalletController* const m_wallet_controller;
    QPointer<QWidget> m_parent_widget;
    QPointer<QProgressDialog> m_progress_dialog;
    WalletModel* m_wallet_model{nullptr};
    bilingual_str m_error_message;
    std::vector<bilingual_str> m_warning_message;
};


class CreateWalletActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    CreateWalletActivity(WalletController* wallet_controller, QWidget* parent_widget);
    virtual ~CreateWalletActivity();

    void create();

Q_SIGNALS:
    void created(WalletModel* wallet_model);

private:
    void askPassphrase();
    void createWallet();
    void finish();

    SecureString m_passphrase;
    CreateWalletDialog* m_create_wallet_dialog{nullptr};
    AskPassphraseDialog* m_passphrase_dialog{nullptr};
};

class OpenWalletActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    OpenWalletActivity(WalletController* wallet_controller, QWidget* parent_widget);

    void open(const std::string& path);

Q_SIGNALS:
    void opened(WalletModel* wallet_model);

private:
    void finish();
};

class LoadWalletsActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    LoadWalletsActivity(WalletController* wallet_controller, QWidget* parent_widget);

    void load(bool show_loading_minimized);
};

class RestoreWalletActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    RestoreWalletActivity(WalletController* wallet_controller, QWidget* parent_widget);

    void restore(const fs::path& backup_file, const std::string& wallet_name);

Q_SIGNALS:
    void restored(WalletModel* wallet_model);

private:
    void finish();
};

/** Restore a vault from its public policy and printed BIP39 recovery sheets. */
class MnemonicRestoreActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    using RescanFn = std::function<util::Result<void>(interfaces::Wallet&)>;

    MnemonicRestoreActivity(WalletController* wallet_controller, QWidget* parent_widget,
                            RescanFn rescan_override = {});
    ~MnemonicRestoreActivity() override;

    void restore(const std::string& wallet_name, const std::string& policy_json,
                 std::vector<SecureString> mnemonics,
                 std::set<std::string> local_fingerprints,
                 std::set<std::string> hardware_fingerprints,
                 bool enable_external_signing);
    //! Resume the timestamp-zero historical scan of an already installed
    //! vault from a safe checkpoint when available. No mnemonic material is
    //! needed or retained for this operation.
    void rescan(WalletModel* wallet_model);

Q_SIGNALS:
    /** The restored wallet is installed and safe to display, but remains
     * blocked from sending until its required genesis rescan completes. */
    void installed(WalletModel* wallet_model);
    void rescanStarted(WalletModel* wallet_model);
    void restored(WalletModel* wallet_model);
    void failed(const QString& error);
    void rescanFailed(WalletModel* wallet_model, const QString& error);

private:
    void beginInstalledRescan();
    void startRescanWorker();
    void finish();

    std::string m_wallet_name;
    std::string m_policy_json;
    std::string m_expected_policy_commitment;
    std::vector<SecureString> m_mnemonics;
    std::set<std::string> m_local_fingerprints;
    std::set<std::string> m_hardware_fingerprints;
    bool m_enable_external_signing{false};
    bool m_participant_provenance_valid{true};
    std::unique_ptr<interfaces::Wallet> m_installed_wallet;
    QPointer<WalletModel> m_active_wallet_model;
    QString m_rescan_error;
    RescanFn m_rescan_override;
};

class MigrateWalletActivity : public WalletControllerActivity
{
    Q_OBJECT

public:
    MigrateWalletActivity(WalletController* wallet_controller, QWidget* parent) : WalletControllerActivity(wallet_controller, parent) {}

    void restore_and_migrate(const fs::path& path, const std::string& wallet_name);
    void migrate(const std::string& path);

Q_SIGNALS:
    void migrated(WalletModel* wallet_model);

private:
    QString m_success_message;

    void do_migrate(const std::string& name, bool load_wallet);
    void finish();
};

#endif // BITCOIN_QT_WALLETCONTROLLER_H
