// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletcontroller.h>

#include <external_signer.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <qt/askpassphrasedialog.h>
#include <qt/clientmodel.h>
#include <qt/createwalletdialog.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/walletmodel.h>
#include <support/cleanse.h>
#include <util/string.h>
#include <util/threadnames.h>
#include <util/translation.h>
#include <wallet/multisig.h>
#include <wallet/wallet.h>

#include <QApplication>
#include <QCheckBox>
#include <QFile>
#include <QFileInfo>
#include <QMessageBox>
#include <QMetaObject>
#include <QMutexLocker>
#include <QThread>
#include <QTimer>
#include <QWindow>

#include <algorithm>
#include <chrono>
#include <exception>

using util::Join;
using wallet::WALLET_FLAG_BLANK_WALLET;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WALLET_FLAG_EXTERNAL_SIGNER;

WalletController::WalletController(ClientModel& client_model, const PlatformStyle* platform_style, QObject* parent)
    : QObject(parent)
    , m_activity_thread(new QThread(this))
    , m_activity_worker(new QObject)
    , m_client_model(client_model)
    , m_node(client_model.node())
    , m_platform_style(platform_style)
    , m_options_model(client_model.getOptionsModel())
{
    m_recovery_kit_cleanup_timer.setInterval(5000);
    connect(&m_recovery_kit_cleanup_timer, &QTimer::timeout,
            this, &WalletController::retryPendingRecoveryKitCleanup);
    m_handler_load_wallet = m_node.walletLoader().handleLoadWallet([this](std::unique_ptr<interfaces::Wallet> wallet) {
        getOrCreateWallet(std::move(wallet));
    });

    m_activity_worker->moveToThread(m_activity_thread);
    m_activity_thread->start();
    QTimer::singleShot(0, m_activity_worker, []() {
        util::ThreadRename("qt-walletctrl");
    });
}

// Not using the default destructor because not all member types definitions are
// available in the header, just forward declared.
WalletController::~WalletController()
{
    retryPendingRecoveryKitCleanup();
    m_activity_thread->quit();
    m_activity_thread->wait();
    delete m_activity_worker;
}

void WalletController::retainRecoveryKitCleanup(QString path, std::unique_ptr<QLockFile> lock)
{
    if (path.isEmpty()) return;
    const auto existing{std::find_if(
        m_recovery_kit_cleanup.begin(), m_recovery_kit_cleanup.end(),
        [&](const auto& pending) { return pending.path == path; })};
    if (existing == m_recovery_kit_cleanup.end()) {
        m_recovery_kit_cleanup.push_back({std::move(path), std::move(lock)});
    }
    if (!m_recovery_kit_cleanup_timer.isActive()) m_recovery_kit_cleanup_timer.start();
}

void WalletController::retryPendingRecoveryKitCleanup()
{
    std::erase_if(m_recovery_kit_cleanup, [](RecoveryKitCleanup& pending) {
        if (QFileInfo::exists(pending.path) && !QFile::remove(pending.path)) return false;
        // Releasing the adjacent live-owner lock only after deletion lets
        // another setup safely scavenge the artifact if the process exits
        // before a viewer releases it.
        pending.lock.reset();
        return !QFileInfo::exists(pending.path);
    });
    if (m_recovery_kit_cleanup.empty()) m_recovery_kit_cleanup_timer.stop();
}

std::map<std::string, std::pair<bool, std::string>> WalletController::listWalletDir() const
{
    QMutexLocker locker(&m_mutex);
    std::map<std::string, std::pair<bool, std::string>> wallets;
    for (const auto& [name, format] : m_node.walletLoader().listWalletDir()) {
        wallets[name] = std::make_pair(false, format);
    }
    for (WalletModel* wallet_model : m_wallets) {
        auto it = wallets.find(wallet_model->wallet().getWalletName());
        if (it != wallets.end()) it->second.first = true;
    }
    return wallets;
}

void WalletController::removeWallet(WalletModel* wallet_model)
{
    // Once the wallet is successfully removed from the node, the model will emit the 'WalletModel::unload' signal.
    // This signal is already connected and will complete the removal of the view from the GUI.
    // Look at 'WalletController::getOrCreateWallet' for the signal connection.
    wallet_model->wallet().remove();
}

void WalletController::closeWallet(WalletModel* wallet_model, QWidget* parent)
{
    QMessageBox box(parent);
    box.setWindowTitle(tr("Close wallet"));
    box.setText(tr("Are you sure you wish to close the wallet <i>%1</i>?").arg(GUIUtil::HtmlEscape(wallet_model->getDisplayName())));
    box.setInformativeText(tr("Closing the wallet for too long can result in having to resync the entire chain if pruning is enabled."));
    box.setStandardButtons(QMessageBox::Yes|QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Yes);
    if (box.exec() != QMessageBox::Yes) return;

    removeWallet(wallet_model);
}

void WalletController::closeAllWallets(QWidget* parent)
{
    QMessageBox::StandardButton button = QMessageBox::question(parent, tr("Close all wallets"),
        tr("Are you sure you wish to close all wallets?"),
        QMessageBox::Yes|QMessageBox::Cancel,
        QMessageBox::Yes);
    if (button != QMessageBox::Yes) return;

    QMutexLocker locker(&m_mutex);
    for (WalletModel* wallet_model : m_wallets) {
        removeWallet(wallet_model);
    }
}

WalletModel* WalletController::getOrCreateWallet(std::unique_ptr<interfaces::Wallet> wallet)
{
    QMutexLocker locker(&m_mutex);

    // Return model instance if exists.
    if (!m_wallets.empty()) {
        std::string name = wallet->getWalletName();
        for (WalletModel* wallet_model : m_wallets) {
            if (wallet_model->wallet().getWalletName() == name) {
                return wallet_model;
            }
        }
    }

    // Instantiate model and register it.
    WalletModel* wallet_model = new WalletModel(std::move(wallet), m_client_model, m_platform_style,
                                                nullptr /* required for the following moveToThread() call */);

    // Move WalletModel object to the thread that created the WalletController
    // object (GUI main thread), instead of the current thread, which could be
    // an outside wallet thread or RPC thread sending a LoadWallet notification.
    // This ensures queued signals sent to the WalletModel object will be
    // handled on the GUI event loop.
    wallet_model->moveToThread(thread());
    // setParent(parent) must be called in the thread which created the parent object. More details in #18948.
    QMetaObject::invokeMethod(this, [wallet_model, this] {
        wallet_model->setParent(this);
    }, GUIUtil::blockingGUIThreadConnection());

    m_wallets.push_back(wallet_model);

    // WalletModel::startPollBalance needs to be called in a thread managed by
    // Qt because of startTimer. Considering the current thread can be a RPC
    // thread, better delegate the calling to Qt with Qt::AutoConnection.
    const bool called = QMetaObject::invokeMethod(wallet_model, "startPollBalance");
    assert(called);

    connect(wallet_model, &WalletModel::unload, this, [this, wallet_model] {
        // Defer removeAndDeleteWallet when no modal widget is actively waiting for an action.
        // TODO: remove this workaround by removing usage of QDialog::exec.
        QWidget* active_dialog = QApplication::activeModalWidget();
        if (active_dialog && dynamic_cast<QProgressDialog*>(active_dialog) == nullptr) {
            connect(qApp, &QApplication::focusWindowChanged, wallet_model, [this, wallet_model]() {
                if (!QApplication::activeModalWidget()) {
                    removeAndDeleteWallet(wallet_model);
                }
            }, Qt::QueuedConnection);
        } else {
            removeAndDeleteWallet(wallet_model);
        }
    }, Qt::QueuedConnection);

    // Re-emit coinsSent signal from wallet model.
    connect(wallet_model, &WalletModel::coinsSent, this, &WalletController::coinsSent);

    Q_EMIT walletAdded(wallet_model);

    return wallet_model;
}

void WalletController::removeAndDeleteWallet(WalletModel* wallet_model)
{
    // Unregister wallet model.
    {
        QMutexLocker locker(&m_mutex);
        m_wallets.erase(std::remove(m_wallets.begin(), m_wallets.end(), wallet_model));
    }
    Q_EMIT walletRemoved(wallet_model);
    // Currently this can trigger the unload since the model can hold the last
    // CWallet shared pointer.
    delete wallet_model;
}

WalletControllerActivity::WalletControllerActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : QObject(wallet_controller)
    , m_wallet_controller(wallet_controller)
    , m_parent_widget(parent_widget)
{
    connect(this, &WalletControllerActivity::finished, this, &QObject::deleteLater);
}

void WalletControllerActivity::showProgressDialog(const QString& title_text, const QString& label_text, bool show_minimized)
{
    closeProgressDialog();
    auto progress_dialog = new QProgressDialog(m_parent_widget.data());
    m_progress_dialog = progress_dialog;
    progress_dialog->setAttribute(Qt::WA_DeleteOnClose);
    connect(this, &WalletControllerActivity::finished, progress_dialog, &QWidget::close);

    progress_dialog->setWindowTitle(title_text);
    progress_dialog->setLabelText(label_text);
    progress_dialog->setRange(0, 0);
    progress_dialog->setCancelButton(nullptr);
    progress_dialog->setWindowModality(Qt::ApplicationModal);
    GUIUtil::PolishProgressDialog(progress_dialog);
    // The setValue call forces QProgressDialog to start the internal duration estimation.
    // See details in https://bugreports.qt.io/browse/QTBUG-47042.
    progress_dialog->setValue(0);
    // When requested, launch dialog minimized
    if (show_minimized) progress_dialog->showMinimized();
}

void WalletControllerActivity::closeProgressDialog()
{
    if (!m_progress_dialog) return;
    m_progress_dialog->close();
    m_progress_dialog = nullptr;
}

CreateWalletActivity::CreateWalletActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : WalletControllerActivity(wallet_controller, parent_widget)
{
    m_passphrase.reserve(MAX_PASSPHRASE_SIZE);
}

CreateWalletActivity::~CreateWalletActivity()
{
    delete m_create_wallet_dialog;
    delete m_passphrase_dialog;
}

void CreateWalletActivity::askPassphrase()
{
    m_passphrase_dialog = new AskPassphraseDialog(AskPassphraseDialog::Encrypt, m_parent_widget, &m_passphrase);
    m_passphrase_dialog->setWindowModality(Qt::ApplicationModal);
    m_passphrase_dialog->show();

    connect(m_passphrase_dialog, &QObject::destroyed, [this] {
        m_passphrase_dialog = nullptr;
    });
    connect(m_passphrase_dialog, &QDialog::accepted, [this] {
        createWallet();
    });
    connect(m_passphrase_dialog, &QDialog::rejected, [this] {
        Q_EMIT finished();
    });
}

void CreateWalletActivity::createWallet()
{
    showProgressDialog(
        //: Title of window indicating the progress of creation of a new wallet.
        tr("Create Wallet"),
        /*: Descriptive text of the create wallet progress window which indicates
            to the user which wallet is currently being created. */
        tr("Creating Wallet <b>%1</b>…").arg(m_create_wallet_dialog->walletName().toHtmlEscaped()));

    std::string name = m_create_wallet_dialog->walletName().toStdString();
    uint64_t flags = 0;
    // Enable descriptors by default.
    flags |= WALLET_FLAG_DESCRIPTORS;
    if (m_create_wallet_dialog->isDisablePrivateKeysChecked()) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }
    if (m_create_wallet_dialog->isMakeBlankWalletChecked()) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }
    if (m_create_wallet_dialog->isExternalSignerChecked()) {
        flags |= WALLET_FLAG_EXTERNAL_SIGNER;
    }

    QTimer::singleShot(500ms, worker(), [this, name, flags] {
        auto wallet{node().walletLoader().createWallet(name, m_passphrase, flags, m_warning_message)};

        if (wallet) {
            m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*wallet));
        } else {
            m_error_message = util::ErrorString(wallet);
        }

        QTimer::singleShot(500ms, this, &CreateWalletActivity::finish);
    });
}

void CreateWalletActivity::finish()
{
    if (!m_error_message.empty()) {
        QMessageBox::critical(m_parent_widget, tr("Create wallet failed"), QString::fromStdString(m_error_message.translated));
    } else if (!m_warning_message.empty()) {
        QMessageBox::warning(m_parent_widget, tr("Create wallet warning"), QString::fromStdString(Join(m_warning_message, Untranslated("\n")).translated));
    }

    if (m_wallet_model) Q_EMIT created(m_wallet_model);

    Q_EMIT finished();
}

void CreateWalletActivity::create()
{
    m_create_wallet_dialog = new CreateWalletDialog(m_parent_widget);

    std::vector<std::unique_ptr<interfaces::ExternalSigner>> signers;
    try {
        signers = node().listExternalSigners();
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(nullptr, tr("Can't list signers"), e.what());
    }
    if (signers.size() > 1) {
        QMessageBox::critical(nullptr, tr("Too many external signers found"), QString::fromStdString("More than one external signer found. Please connect only one at a time."));
        signers.clear();
    }
    m_create_wallet_dialog->setSigners(signers);

    m_create_wallet_dialog->setWindowModality(Qt::ApplicationModal);
    m_create_wallet_dialog->show();

    connect(m_create_wallet_dialog, &QObject::destroyed, [this] {
        m_create_wallet_dialog = nullptr;
    });
    connect(m_create_wallet_dialog, &QDialog::rejected, [this] {
        Q_EMIT finished();
    });
    connect(m_create_wallet_dialog, &QDialog::accepted, [this] {
        if (m_create_wallet_dialog->isEncryptWalletChecked()) {
            askPassphrase();
        } else {
            createWallet();
        }
    });
}

OpenWalletActivity::OpenWalletActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : WalletControllerActivity(wallet_controller, parent_widget)
{
}

void OpenWalletActivity::finish()
{
    if (!m_error_message.empty()) {
        QMessageBox::critical(m_parent_widget, tr("Open wallet failed"), QString::fromStdString(m_error_message.translated));
    } else if (!m_warning_message.empty()) {
        QMessageBox::warning(m_parent_widget, tr("Open wallet warning"), QString::fromStdString(Join(m_warning_message, Untranslated("\n")).translated));
    }

    if (m_wallet_model) Q_EMIT opened(m_wallet_model);

    Q_EMIT finished();
}

void OpenWalletActivity::open(const std::string& path)
{
    QString name = GUIUtil::WalletDisplayName(path);

    showProgressDialog(
        //: Title of window indicating the progress of opening of a wallet.
        tr("Open Wallet"),
        /*: Descriptive text of the open wallet progress window which indicates
            to the user which wallet is currently being opened. */
        tr("Opening Wallet <b>%1</b>…").arg(name.toHtmlEscaped()));

    QTimer::singleShot(0, worker(), [this, path] {
        auto wallet{node().walletLoader().loadWallet(path, m_warning_message)};

        if (wallet) {
            m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*wallet));
        } else {
            m_error_message = util::ErrorString(wallet);
        }

        QTimer::singleShot(0, this, &OpenWalletActivity::finish);
    });
}

LoadWalletsActivity::LoadWalletsActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : WalletControllerActivity(wallet_controller, parent_widget)
{
}

void LoadWalletsActivity::load(bool show_loading_minimized)
{
    showProgressDialog(
        //: Title of progress window which is displayed when wallets are being loaded.
        tr("Load Wallets"),
        /*: Descriptive text of the load wallets progress window which indicates to
            the user that wallets are currently being loaded.*/
        tr("Loading wallets…"),
        /*show_minimized=*/show_loading_minimized);

    QTimer::singleShot(0, worker(), [this] {
        for (auto& wallet : node().walletLoader().getWallets()) {
            m_wallet_controller->getOrCreateWallet(std::move(wallet));
        }

        QTimer::singleShot(0, this, [this] { Q_EMIT finished(); });
    });
}

RestoreWalletActivity::RestoreWalletActivity(WalletController* wallet_controller, QWidget* parent_widget)
    : WalletControllerActivity(wallet_controller, parent_widget)
{
}

void RestoreWalletActivity::restore(const fs::path& backup_file, const std::string& wallet_name)
{
    QString name = QString::fromStdString(wallet_name);

    showProgressDialog(
        //: Title of progress window which is displayed when wallets are being restored.
        tr("Restore Wallet"),
        /*: Descriptive text of the restore wallets progress window which indicates to
            the user that wallets are currently being restored.*/
        tr("Restoring Wallet <b>%1</b>…").arg(name.toHtmlEscaped()));

    QTimer::singleShot(0, worker(), [this, backup_file, wallet_name] {
        auto wallet{node().walletLoader().restoreWallet(backup_file, wallet_name, m_warning_message, /*load_after_restore=*/true)};

        if (wallet) {
            m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*wallet));
        } else {
            m_error_message = util::ErrorString(wallet);
        }

        QTimer::singleShot(0, this, &RestoreWalletActivity::finish);
    });
}

void RestoreWalletActivity::finish()
{
    if (!m_error_message.empty()) {
        //: Title of message box which is displayed when the wallet could not be restored.
        QMessageBox::critical(m_parent_widget, tr("Restore wallet failed"), QString::fromStdString(m_error_message.translated));
    } else if (!m_warning_message.empty()) {
        //: Title of message box which is displayed when the wallet is restored with some warning.
        QMessageBox::warning(m_parent_widget, tr("Restore wallet warning"), QString::fromStdString(Join(m_warning_message, Untranslated("\n")).translated));
    } else {
        //: Title of message box which is displayed when the wallet is successfully restored.
        QMessageBox::information(m_parent_widget, tr("Restore wallet message"), QString::fromStdString(Untranslated("Wallet restored successfully \n").translated));
    }

    if (m_wallet_model) Q_EMIT restored(m_wallet_model);

    Q_EMIT finished();
}

MnemonicRestoreActivity::MnemonicRestoreActivity(WalletController* wallet_controller, QWidget* parent_widget,
                                                 RescanFn rescan_override)
    : WalletControllerActivity(wallet_controller, parent_widget)
    , m_rescan_override(std::move(rescan_override))
{
}

MnemonicRestoreActivity::~MnemonicRestoreActivity()
{
    for (SecureString& mnemonic : m_mnemonics) {
        if (!mnemonic.empty()) memory_cleanse(mnemonic.data(), mnemonic.size());
    }
    m_mnemonics.clear();
}

void MnemonicRestoreActivity::restore(const std::string& wallet_name, const std::string& policy_json,
                                      std::vector<SecureString> mnemonics,
                                      std::set<std::string> local_fingerprints,
                                      std::set<std::string> hardware_fingerprints,
                                      bool enable_external_signing)
{
    const auto package{wallet::ParseVaultPolicyPackage(policy_json)};
    if (!package) {
        m_error_message = util::ErrorString(package);
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
        return;
    }
    if (const auto fixed{wallet::ValidateFixedStagedVaultPolicy(*package)}; !fixed) {
        m_error_message = util::ErrorString(fixed);
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
        return;
    }
    m_expected_policy_commitment = wallet::VaultPolicyCommitment(*package);

    // Restore authority is an explicit boundary. A watch-only or
    // printed-phrases restore must never acquire hardware signing merely
    // because a matching device happens to be connected.
    if (!enable_external_signing && !hardware_fingerprints.empty()) {
        m_error_message = Untranslated(
            "Hardware participant provenance was supplied for a restore that explicitly disabled external signing");
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
        return;
    }
    if (enable_external_signing && (!local_fingerprints.empty() || !mnemonics.empty())) {
        m_error_message = Untranslated(
            "Local software-key provenance was supplied for an exact-hardware restore");
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
        return;
    }
    if (enable_external_signing && hardware_fingerprints.empty()) {
        m_error_message = Untranslated(
            "Exact-hardware restore was selected without any freshly matched hardware participant");
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
        return;
    }
    if (!enable_external_signing && local_fingerprints.size() != mnemonics.size()) {
        m_error_message = Untranslated(
            "The restored software-key provenance does not match the explicitly supplied printed phrases");
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
        return;
    }
    const auto authoritative_matches{
        wallet::ValidateFixedVaultMnemonics(*package, mnemonics)};
    if (!authoritative_matches) {
        m_error_message = util::ErrorString(authoritative_matches);
        for (SecureString& mnemonic : mnemonics) {
            if (!mnemonic.empty()) memory_cleanse(mnemonic.data(), mnemonic.size());
        }
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
        return;
    }
    std::set<std::string> authoritative_local_fingerprints;
    for (const auto& match : *authoritative_matches) {
        authoritative_local_fingerprints.insert(match.fingerprint);
    }
    if (authoritative_local_fingerprints.size() != authoritative_matches->size() ||
        authoritative_local_fingerprints != local_fingerprints) {
        m_error_message = Untranslated(
            "The reviewed software-key participants do not match the supplied Recovery Kit phrases");
        for (SecureString& mnemonic : mnemonics) {
            if (!mnemonic.empty()) memory_cleanse(mnemonic.data(), mnemonic.size());
        }
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
        return;
    }
    m_wallet_name = wallet_name;
    m_policy_json = policy_json;
    m_mnemonics = std::move(mnemonics);
    m_local_fingerprints = std::move(local_fingerprints);
    m_hardware_fingerprints = std::move(hardware_fingerprints);
    m_enable_external_signing = enable_external_signing;
    m_participant_provenance_valid = true;
    showProgressDialog(
        tr("Restore Recovery Vault"),
        tr("Installing <b>%1</b> from its Recovery Kit…")
            .arg(QString::fromStdString(wallet_name).toHtmlEscaped()));

    QTimer::singleShot(0, worker(), [this] {
        // Secret cleanup must not depend on a backend returning normally.
        // installFixedVault implementations are permitted to throw, and this
        // activity must still report a retryable failure on the GUI thread.
        auto cleanse = interfaces::MakeCleanupHandler([this] {
            for (SecureString& mnemonic : m_mnemonics) {
                if (!mnemonic.empty()) memory_cleanse(mnemonic.data(), mnemonic.size());
            }
            std::vector<SecureString>{}.swap(m_mnemonics);
            m_policy_json.clear();
        });
        try {
            auto installed{node().walletLoader().installFixedVault(
                m_wallet_name, m_policy_json, m_mnemonics,
                interfaces::FixedVaultInstallMode::RESTORE, m_warning_message,
                m_enable_external_signing ? interfaces::FixedVaultExternalSigning::ENABLED : interfaces::FixedVaultExternalSigning::DISABLED)};
            if (!installed) {
                m_error_message = util::ErrorString(installed);
            } else {
                std::set<std::string> backend_local_fingerprints;
                for (const auto& match : installed->matches) {
                    backend_local_fingerprints.insert(match.fingerprint);
                }
                const bool authoritative_match{
                    backend_local_fingerprints.size() == installed->matches.size() &&
                    backend_local_fingerprints == m_local_fingerprints};
                if (!authoritative_match) {
                    // Preflight above makes this unreachable unless the
                    // backend violates its own validation contract. Keep the
                    // safely installed wallet visible but with setup marked
                    // incomplete; `remove()` only unloads and must never be
                    // misrepresented as deleting the published database.
                    m_participant_provenance_valid = false;
                    m_local_fingerprints.clear();
                    m_warning_message.push_back(Untranslated(
                        "The installed Recovery Vault reported different software-key authority than preflight. Participant provenance was not trusted; setup remains not recorded."));
                    m_installed_wallet = std::move(installed->wallet);
                } else {
                    m_local_fingerprints = std::move(backend_local_fingerprints);
                    m_installed_wallet = std::move(installed->wallet);
                }
            }
        } catch (const std::exception& e) {
            m_error_message = Untranslated(strprintf("Recovery Vault installation failed: %s", e.what()));
        } catch (...) {
            m_error_message = Untranslated("Recovery Vault installation failed with an unknown backend error");
        }
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::beginInstalledRescan);
    });
}

void MnemonicRestoreActivity::beginInstalledRescan()
{
    closeProgressDialog();
    if (!m_error_message.empty() || !m_installed_wallet) {
        finish();
        return;
    }

    // Publish the wallet before scanning. Its durable genesis-rescan flag
    // keeps sending disabled, while WalletModel can now relay actual scan
    // progress and the operation can continue if the restore surface closes.
    m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(m_installed_wallet));
    m_active_wallet_model = m_wallet_model;
    // Provenance belongs to the durable restore operation, not to the surface
    // that launched it. Persist it before emitting installed so closing or
    // destroying the wizard cannot strand exact participants as UNKNOWN.
    bool participant_sources_saved{m_participant_provenance_valid};
    for (const std::string& fingerprint : m_local_fingerprints) {
        if (!m_active_wallet_model->setVaultParticipantType(
                fingerprint, interfaces::Wallet::VaultParticipantType::LOCAL_SOFTWARE,
                m_expected_policy_commitment)) {
            participant_sources_saved = false;
            m_warning_message.push_back(Untranslated(
                "The restored local software-key source for participant " + fingerprint +
                " could not be saved for the exact restored policy. Its authority remains Unknown and direct signing stays unavailable. Finish setup for the current policy and retry."));
        }
    }
    for (const std::string& fingerprint : m_hardware_fingerprints) {
        if (!m_active_wallet_model->setVaultParticipantType(
                fingerprint, interfaces::Wallet::VaultParticipantType::HARDWARE,
                m_expected_policy_commitment)) {
            participant_sources_saved = false;
            m_warning_message.push_back(Untranslated(
                "The restored exact hardware source for participant " + fingerprint +
                " could not be saved for the exact restored policy. Its authority remains Unknown and direct signing stays unavailable. Finish setup for the current policy and retry."));
        }
    }
    m_local_fingerprints.clear();
    m_hardware_fingerprints.clear();
    // Successful installation proves that the canonical public policy copy
    // reproduced the vault. It does not prove independent address
    // verification, and a failed metadata write deliberately remains the
    // actionable NOT_RECORDED legacy state.
    if (!participant_sources_saved) {
        // Do not let a later address-display check turn a partially recorded
        // authority roster into Ready. The exact wallet is safely installed,
        // but setup remains explicitly NOT_RECORDED until every requested
        // source has been durably reconciled for the current policy.
        if (!m_active_wallet_model->setVaultSetupState(
                interfaces::Wallet::VaultSetupState::NOT_RECORDED,
                interfaces::Wallet::VaultVerificationState::NOT_RECORDED,
                m_expected_policy_commitment)) {
            m_warning_message.push_back(Untranslated(
                "The incomplete restore state could not be saved for the wallet's current policy. The dashboard will still fail closed because no completed setup record exists."));
        }
        m_warning_message.push_back(Untranslated(
            "Restore setup remains incomplete because not every requested signer source was saved. Use Finish Setup for the current policy; the vault will not be shown as Ready."));
    } else if (!m_active_wallet_model->setVaultSetupState(
                   interfaces::Wallet::VaultSetupState::ADDRESS_VERIFICATION_REQUIRED,
                   interfaces::Wallet::VaultVerificationState::RECOVERY_KIT_MATCHED,
                   m_expected_policy_commitment)) {
        m_warning_message.push_back(Untranslated(
            "The Recovery Kit policy matched, but that setup result could not be saved for the wallet's current policy. The vault will show verification status not recorded; use Finish Setup for the current policy."));
    }
    Q_EMIT installed(m_active_wallet_model);
    startRescanWorker();
}

void MnemonicRestoreActivity::startRescanWorker()
{
    if (!m_active_wallet_model) {
        m_error_message = Untranslated("The restored Recovery Vault could not be opened");
        finish();
        return;
    }

    // Capture a shared interface handle before leaving the GUI thread. This
    // prevents a wallet unload from deleting the object beneath the worker;
    // the backend can then abort/unwind safely while the GUI model disappears.
    const std::shared_ptr<interfaces::Wallet> wallet{m_active_wallet_model->walletShared()};
    Q_EMIT rescanStarted(m_active_wallet_model);
    QTimer::singleShot(0, worker(), [this, wallet] {
        try {
            auto rescanned{m_rescan_override ? m_rescan_override(*wallet) : wallet->rescanFromGenesis()};
            if (!rescanned) {
                m_rescan_error = QString::fromStdString(
                    "The Recovery Vault is installed, but its blockchain history is incomplete. "
                    "Sending remains blocked. Resume the scan when the required block history is available: " +
                    util::ErrorString(rescanned).original);
            }
        } catch (const std::exception& e) {
            m_rescan_error = tr("The Recovery Vault is installed, but its blockchain scan failed unexpectedly. Sending remains blocked; retry the scan. %1")
                                 .arg(QString::fromLocal8Bit(e.what()));
        } catch (...) {
            m_rescan_error = tr("The Recovery Vault is installed, but its blockchain scan failed with an unknown backend error. Sending remains blocked; retry the scan.");
        }
        QTimer::singleShot(0, this, &MnemonicRestoreActivity::finish);
    });
}

void MnemonicRestoreActivity::rescan(WalletModel* wallet_model)
{
    m_wallet_model = wallet_model;
    m_active_wallet_model = wallet_model;
    m_rescan_error.clear();
    startRescanWorker();
}

void MnemonicRestoreActivity::finish()
{
    // The setup surface may already be closed. Refresh the durable scan flag
    // here so the surviving dashboard never remains blocked on stale cache
    // state merely because its wizard receiver was destroyed.
    if (m_active_wallet_model) {
        m_active_wallet_model->pollBalanceChanged();
        m_active_wallet_model->refreshVaultSignerStatus();
    }
    if (!m_error_message.empty()) {
        if (m_parent_widget && m_parent_widget->isVisible()) {
            QMessageBox::critical(m_parent_widget.data(), tr("Restore Recovery Vault failed"),
                                  QString::fromStdString(m_error_message.translated));
        }
        Q_EMIT failed(QString::fromStdString(m_error_message.translated));
    } else if (!m_rescan_error.isEmpty()) {
        if (m_parent_widget && m_parent_widget->isVisible()) {
            QMessageBox::warning(m_parent_widget.data(), tr("Recovery Vault scan incomplete"), m_rescan_error);
        }
        Q_EMIT rescanFailed(m_active_wallet_model, m_rescan_error);
    } else if (!m_warning_message.empty()) {
        if (m_parent_widget && m_parent_widget->isVisible()) {
            QMessageBox::warning(m_parent_widget.data(), tr("Restore Recovery Vault warning"),
                                 QString::fromStdString(Join(m_warning_message, Untranslated("\n")).translated));
        }
    }
    if (m_active_wallet_model && m_error_message.empty() && m_rescan_error.isEmpty()) Q_EMIT restored(m_active_wallet_model);
    Q_EMIT finished();
}

void MigrateWalletActivity::do_migrate(const std::string& name, bool load_wallet)
{
    SecureString passphrase;
    if (node().walletLoader().isEncrypted(name)) {
        // Get the passphrase for the wallet
        AskPassphraseDialog dlg(AskPassphraseDialog::UnlockMigration, m_parent_widget, &passphrase);
        if (dlg.exec() == QDialog::Rejected) return;
    }

    showProgressDialog(tr("Migrate Wallet"), tr("Migrating Wallet <b>%1</b>…").arg(GUIUtil::HtmlEscape(name)));

    QTimer::singleShot(0, worker(), [this, name, passphrase, load_wallet] {
        auto res{node().walletLoader().migrateWallet(name, passphrase, load_wallet)};

        if (res) {
            m_success_message = tr("The wallet '%1' was migrated successfully.").arg(GUIUtil::HtmlEscape(GUIUtil::WalletDisplayName(name)));
            if (res->watchonly_wallet_name) {
                m_success_message += QChar(' ') + tr("Watchonly scripts have been migrated to a new wallet named '%1'.").arg(GUIUtil::HtmlEscape(GUIUtil::WalletDisplayName(res->watchonly_wallet_name.value())));
            }
            if (res->solvables_wallet_name) {
                m_success_message += QChar(' ') + tr("Solvable but not watched scripts have been migrated to a new wallet named '%1'.").arg(GUIUtil::HtmlEscape(GUIUtil::WalletDisplayName(res->solvables_wallet_name.value())));
            }
            if (load_wallet) {
                assert(res->wallet);
                m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(res->wallet));
            } else {
                m_success_message += QChar(' ') + tr("The wallet was not loaded after migration. You can open it from the \"File > Open wallet\" menu.");
            }
        } else {
            m_error_message = util::ErrorString(res);
        }

        QTimer::singleShot(0, this, &MigrateWalletActivity::finish);
    });
}

void MigrateWalletActivity::migrate(const std::string& name)
{
    // Warn the user about migration
    QMessageBox box(m_parent_widget);
    box.setWindowTitle(tr("Migrate wallet"));
    box.setText(tr("Are you sure you wish to migrate the wallet <i>%1</i>?").arg(GUIUtil::HtmlEscape(GUIUtil::WalletDisplayName(name))));
    box.setInformativeText(tr("Migrating the wallet will convert this wallet to one or more descriptor wallets. A new wallet backup will need to be made.\n"
                "If this wallet contains any watchonly scripts, a new wallet will be created which contains those watchonly scripts.\n"
                "If this wallet contains any solvable but not watched scripts, a different and new wallet will be created which contains those scripts.\n\n"
                "The migration process will create a backup of the wallet before migrating. This backup file will be named "
                "<wallet name>-<timestamp>.legacy.bak and can be found in the directory for this wallet. In the event of "
                "an incorrect migration, the backup can be restored with the \"Restore Wallet\" functionality."));
    auto* load_wallet_checkbox = new QCheckBox(tr("Load wallet after migration"), &box);
    load_wallet_checkbox->setToolTip(tr("If the node is pruned and the wallet was created before the pruned height, the migration process may fail trying to load the migrated wallet."));
    load_wallet_checkbox->setChecked(true);
    box.setCheckBox(load_wallet_checkbox);
    box.setStandardButtons(QMessageBox::Yes|QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Yes);
    if (box.exec() != QMessageBox::Yes) return;

    do_migrate(name, load_wallet_checkbox->isChecked());
}

void MigrateWalletActivity::restore_and_migrate(const fs::path& path, const std::string& wallet_name)
{
    // Warn the user about migration
    QMessageBox box(m_parent_widget);
    box.setWindowTitle(tr("Restore and Migrate wallet"));
    box.setText(tr("Are you sure you wish to restore the wallet file <i>%1</i> to <i>%2</i> and migrate it?").arg(GUIUtil::HtmlEscape(fs::PathToString(path)), GUIUtil::HtmlEscape(GUIUtil::WalletDisplayName(wallet_name))));
    box.setInformativeText(tr("Restoring the wallet will copy the backup file to the wallets directory and place it in the standard "
                "wallet directory layout. The original file will not be modified.\n\n"
                "Migrating the wallet will convert the restored wallet to one or more descriptor wallets. A new wallet backup will need to be made.\n"
                "If this wallet contains any watchonly scripts, a new wallet will be created which contains those watchonly scripts.\n"
                "If this wallet contains any solvable but not watched scripts, a different and new wallet will be created which contains those scripts.\n\n"
                "The migration process will create a backup of the wallet before migrating. This backup file will be named "
                "<wallet name>-<timestamp>.legacy.bak and can be found in the directory for this wallet. In the event of "
                "an incorrect migration, the backup can be restored with the \"Restore Wallet\" functionality."));
    box.setStandardButtons(QMessageBox::Yes|QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Yes);
    if (box.exec() != QMessageBox::Yes) return;

    showProgressDialog(
        //: Title of progress window which is displayed when wallets are being restored.
        tr("Restore Wallet"),
        /*: Descriptive text of the restore wallets progress window which indicates to
            the user that wallets are currently being restored.*/
        tr("Restoring Wallet <b>%1</b>…").arg(GUIUtil::HtmlEscape(GUIUtil::WalletDisplayName(wallet_name))));

    QTimer::singleShot(0, worker(), [this, path, wallet_name] {
        auto res{node().walletLoader().restoreWallet(path, wallet_name, m_warning_message, /*load_after_restore=*/false)};

        if (!res) {
            m_error_message = util::ErrorString(res);
            QTimer::singleShot(0, this, &MigrateWalletActivity::finish);
            return;
        }
        QTimer::singleShot(0, this, [this, wallet_name] {
            do_migrate(wallet_name, /*load_wallet=*/true);
        });
    });
}

void MigrateWalletActivity::finish()
{
    if (!m_error_message.empty()) {
        QMessageBox::critical(m_parent_widget, tr("Migration failed"), QString::fromStdString(m_error_message.translated));
    } else {
        QMessageBox::information(m_parent_widget, tr("Migration Successful"), m_success_message);
    }

    if (m_wallet_model) Q_EMIT migrated(m_wallet_model);

    Q_EMIT finished();
}
