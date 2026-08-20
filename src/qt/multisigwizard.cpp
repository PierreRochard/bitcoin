// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/multisigwizard.h>

#include <addresstype.h>
#include <chainparams.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <qt/guiutil.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <support/allocators/secure.h>
#include <wallet/walletutil.h>

#include <algorithm>

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWizardPage>

using wallet::MultisigKeySpec;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WALLET_FLAG_EXTERNAL_SIGNER;

namespace {
QString PolicySentence(int m, int n)
{
    return QObject::tr("Spending will require <b>%1 of %2</b> signatures.")
        .arg(m)
        .arg(n);
}

class AirgappedKeyDialog : public QDialog
{
public:
    QLineEdit* fingerprint{nullptr};
    QLineEdit* path{nullptr};
    QLineEdit* xpub{nullptr};
    QLineEdit* label{nullptr};

    explicit AirgappedKeyDialog(QWidget* parent) : QDialog(parent, GUIUtil::dialog_flags)
    {
        setWindowTitle(tr("Add air-gapped key"));
        auto* layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel(tr(
            "Paste an xpub exported from an offline signer (Sparrow, Specter, Coldcard, …). "
            "The device does not need to be connected. Spending later uses PSBT export.")));
        auto* form = new QFormLayout;
        label = new QLineEdit;
        label->setPlaceholderText(tr("Coldcard (vault)"));
        fingerprint = new QLineEdit;
        fingerprint->setPlaceholderText(tr("aabbccdd"));
        fingerprint->setMaxLength(8);
        path = new QLineEdit;
        path->setPlaceholderText(tr("m/48h/1h/0h/2h"));
        xpub = new QLineEdit;
        xpub->setPlaceholderText(tr("xpub… / tpub…"));
        form->addRow(tr("Label"), label);
        form->addRow(tr("Fingerprint"), fingerprint);
        form->addRow(tr("Path"), path);
        form->addRow(tr("xpub"), xpub);
        layout->addLayout(form);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        layout->addWidget(buttons);
    }
};
} // namespace

class MultisigIntroPage : public QWizardPage
{
public:
    explicit MultisigIntroPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Create a multisig wallet"));
        setSubTitle(tr("Several keys together, like a vault."));
        auto* layout = new QVBoxLayout(this);
        auto* copy = new QLabel(tr(
            "<p>A multisig wallet needs more than one signature to spend. "
            "Typical setups:</p>"
            "<ul>"
            "<li><b>2 of 3</b> — this computer plus two hardware wallets (Sparrow/BlueWallet default).</li>"
            "<li><b>2 of 2</b> — this computer and one device you keep elsewhere.</li>"
            "<li>Air-gapped keys — paste an xpub now, sign later with a PSBT file.</li>"
            "</ul>"
            "<p>You will pick the keys, choose how many signatures are required, "
            "save a backup of the public keys, and verify the first address on each "
            "connected device.</p>"));
        copy->setWordWrap(true);
        copy->setTextFormat(Qt::RichText);
        layout->addWidget(copy);
        layout->addStretch();
    }
    int nextId() const override { return MultisigWizard::Page_Setup; }

private:
    MultisigWizard* m_wizard;
};

class MultisigSetupPage : public QWizardPage
{
public:
    QLineEdit* name{nullptr};
    QComboBox* type{nullptr};

    explicit MultisigSetupPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Name and address type"));
        setSubTitle(tr("Native SegWit (P2WSH) is the usual choice."));
        auto* form = new QFormLayout(this);
        name = new QLineEdit;
        name->setObjectName("walletNameEdit");
        name->setText(wizard->walletName());
        name->setPlaceholderText(tr("Family vault"));
        type = new QComboBox;
        type->setObjectName("scriptTypeCombo");
        type->addItem(tr("Native SegWit (bech32, P2WSH) — recommended"), QVariant::fromValue(static_cast<int>(OutputType::BECH32)));
        type->addItem(tr("Nested SegWit (p2sh-segwit, P2SH-P2WSH)"), QVariant::fromValue(static_cast<int>(OutputType::P2SH_SEGWIT)));
        type->addItem(tr("Legacy (P2SH)"), QVariant::fromValue(static_cast<int>(OutputType::LEGACY)));
        form->addRow(tr("Wallet name"), name);
        form->addRow(tr("Script type"), type);
        connect(name, &QLineEdit::textChanged, this, &QWizardPage::completeChanged);
        registerField("walletName*", name);
    }
    void initializePage() override
    {
        name->setText(m_wizard->walletName());
    }
    bool isComplete() const override { return !name->text().trimmed().isEmpty(); }
    bool validatePage() override
    {
        m_wizard->setWalletName(name->text().trimmed());
        m_wizard->setOutputType(static_cast<OutputType>(type->currentData().toInt()));
        return true;
    }
    int nextId() const override { return MultisigWizard::Page_Keys; }

private:
    MultisigWizard* m_wizard;
};

class MultisigKeysPage : public QWizardPage
{
public:
    QCheckBox* local{nullptr};
    QListWidget* hardware{nullptr};
    QListWidget* airgapped{nullptr};

    explicit MultisigKeysPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Keys"));
        setSubTitle(tr("Add every key that will be part of the vault. Hardware can be unplugged later."));
        auto* layout = new QVBoxLayout(this);

        local = new QCheckBox(tr("Include a key from this computer"));
        local->setObjectName("includeLocalCheck");
        local->setChecked(true);
        local->setToolTip(tr("Core keeps a local HD seed and co-signs. Uncheck for a hardware-only or watch-only vault."));
        layout->addWidget(local);

        auto* hw_box = new QGroupBox(tr("Connected hardware"));
        auto* hw_layout = new QVBoxLayout(hw_box);
        hardware = new QListWidget;
        hardware->setObjectName("hardwareList");
        hardware->setSelectionMode(QAbstractItemView::NoSelection);
        hw_layout->addWidget(hardware);
        auto* refresh = new QPushButton(tr("Refresh devices"));
        refresh->setObjectName("refreshDevicesButton");
        hw_layout->addWidget(refresh);
        layout->addWidget(hw_box);

        auto* air_box = new QGroupBox(tr("Air-gapped / xpub"));
        auto* air_layout = new QVBoxLayout(air_box);
        airgapped = new QListWidget;
        airgapped->setObjectName("airgappedList");
        air_layout->addWidget(airgapped);
        auto* air_btns = new QHBoxLayout;
        auto* add_air = new QPushButton(tr("Add xpub…"));
        add_air->setObjectName("addXpubButton");
        auto* remove_air = new QPushButton(tr("Remove selected"));
        air_btns->addWidget(add_air);
        air_btns->addWidget(remove_air);
        air_btns->addStretch();
        air_layout->addLayout(air_btns);
        layout->addWidget(air_box);

        connect(local, &QCheckBox::toggled, this, [this](bool checked) {
            m_wizard->setIncludeLocalKey(checked);
            Q_EMIT completeChanged();
        });
        connect(refresh, &QPushButton::clicked, this, [this] {
            m_wizard->refreshHardware();
            populateHardware();
            Q_EMIT completeChanged();
        });
        connect(hardware, &QListWidget::itemChanged, this, [this](QListWidgetItem* item) {
            const QString fpr = item->data(Qt::UserRole).toString();
            if (item->checkState() == Qt::Checked) {
                m_wizard->addHardwareKey(fpr.toStdString(), item->text().toStdString());
            } else {
                // Rebuild from remaining checked items.
                std::vector<std::pair<std::string, std::string>> keep;
                for (int i = 0; i < hardware->count(); ++i) {
                    auto* it = hardware->item(i);
                    if (it->checkState() == Qt::Checked) {
                        keep.emplace_back(it->data(Qt::UserRole).toString().toStdString(), it->text().toStdString());
                    }
                }
                m_wizard->m_hardware.clear();
                for (const auto& [fp, label] : keep) m_wizard->addHardwareKey(fp, label);
            }
            Q_EMIT completeChanged();
        });
        connect(add_air, &QPushButton::clicked, this, [this] {
            AirgappedKeyDialog dlg(this);
            if (dlg.exec() != QDialog::Accepted) return;
            const QString fpr = dlg.fingerprint->text().trimmed().toLower();
            const QString xpub = dlg.xpub->text().trimmed();
            if (fpr.size() != 8 || xpub.isEmpty()) {
                QMessageBox::warning(this, tr("Incomplete key"), tr("Fingerprint must be 8 hex characters and xpub must not be empty."));
                return;
            }
            QString path = dlg.path->text().trimmed();
            m_wizard->addAirgappedKey(fpr.toStdString(), path.toStdString(), xpub.toStdString(),
                                      dlg.label->text().trimmed().toStdString());
            populateAirgapped();
            Q_EMIT completeChanged();
        });
        connect(remove_air, &QPushButton::clicked, this, [this] {
            auto* item = airgapped->currentItem();
            if (!item) return;
            const int row = airgapped->row(item);
            if (row >= 0 && static_cast<size_t>(row) < m_wizard->m_airgapped.size()) {
                m_wizard->m_airgapped.erase(m_wizard->m_airgapped.begin() + row);
            }
            populateAirgapped();
            Q_EMIT completeChanged();
        });
    }
    void initializePage() override
    {
        local->setChecked(m_wizard->includeLocalKey());
        m_wizard->refreshHardware();
        populateHardware();
        populateAirgapped();
    }
    bool isComplete() const override
    {
        m_wizard->rebuildKeyList();
        return m_wizard->keys().size() >= 2;
    }
    bool validatePage() override
    {
        m_wizard->rebuildKeyList();
        if (m_wizard->keys().size() < 2) {
            QMessageBox::warning(this, tr("Need more keys"),
                                 tr("A multisig wallet needs at least two keys. Add a hardware device, an xpub, or keep the key on this computer."));
            return false;
        }
        return true;
    }
    int nextId() const override { return MultisigWizard::Page_Threshold; }

private:
    void populateHardware()
    {
        hardware->clear();
        try {
            auto signers = m_wizard->node().listExternalSigners();
            for (const auto& signer : signers) {
                auto* item = new QListWidgetItem(QString::fromStdString(signer->getName() + "  (" + signer->getFingerprint() + ")"));
                item->setData(Qt::UserRole, QString::fromStdString(signer->getFingerprint()));
                item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
                bool checked = false;
                for (const auto& k : m_wizard->m_hardware) {
                    if (k.fingerprint && *k.fingerprint == signer->getFingerprint()) checked = true;
                }
                item->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
                hardware->addItem(item);
            }
            if (signers.empty()) {
                auto* item = new QListWidgetItem(tr("No devices found. Connect a signer or set -signer=internal."));
                item->setFlags(Qt::NoItemFlags);
                hardware->addItem(item);
            }
        } catch (const std::exception& e) {
            auto* item = new QListWidgetItem(QString::fromStdString(e.what()));
            item->setFlags(Qt::NoItemFlags);
            hardware->addItem(item);
        }
    }
    void populateAirgapped()
    {
        airgapped->clear();
        for (const auto& k : m_wizard->m_airgapped) {
            const QString line = QString::fromStdString(
                (k.label.empty() ? "xpub" : k.label) + "  " + (k.fingerprint ? *k.fingerprint : ""));
            airgapped->addItem(line);
        }
    }
    MultisigWizard* m_wizard;
};

class MultisigThresholdPage : public QWizardPage
{
public:
    QSpinBox* required{nullptr};
    QLabel* sentence{nullptr};

    explicit MultisigThresholdPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("How many signatures to spend?"));
        setSubTitle(tr("2 of 3 is the usual vault: one key lost still spends; a thief needs two."));
        auto* layout = new QVBoxLayout(this);
        sentence = new QLabel;
        sentence->setObjectName("policySentence");
        sentence->setTextFormat(Qt::RichText);
        sentence->setWordWrap(true);
        auto* row = new QHBoxLayout;
        required = new QSpinBox;
        required->setObjectName("nrequiredSpin");
        required->setMinimum(1);
        row->addWidget(new QLabel(tr("Required signatures")));
        row->addWidget(required);
        row->addStretch();
        layout->addLayout(row);
        layout->addWidget(sentence);
        layout->addStretch();
        connect(required, qOverload<int>(&QSpinBox::valueChanged), this, [this](int v) {
            m_wizard->setNRequired(v);
            updateSentence();
            Q_EMIT completeChanged();
        });
    }
    void initializePage() override
    {
        m_wizard->rebuildKeyList();
        const int n = static_cast<int>(m_wizard->keys().size());
        required->setMaximum(std::max(1, n));
        int def = m_wizard->nrequired();
        if (def < 1 || def > n) def = std::min(2, n);
        required->setValue(def);
        m_wizard->setNRequired(def);
        updateSentence();
    }
    bool isComplete() const override
    {
        return wallet::ValidateMultisigPolicy(m_wizard->nrequired(), m_wizard->keys().size()).empty();
    }
    int nextId() const override { return MultisigWizard::Page_Backup; }

private:
    void updateSentence()
    {
        sentence->setText(PolicySentence(m_wizard->nrequired(), static_cast<int>(m_wizard->keys().size())) +
                          QStringLiteral("<p>") +
                          tr("Write this down. Changing the threshold later means a new wallet and moving funds.") +
                          QStringLiteral("</p>"));
    }
    MultisigWizard* m_wizard;
};

class MultisigBackupPage : public QWizardPage
{
public:
    QPlainTextEdit* text{nullptr};
    QCheckBox* ack{nullptr};

    explicit MultisigBackupPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Save the public backup"));
        setSubTitle(tr("Anyone with this file can see addresses. Spending still needs the signatures."));
        auto* layout = new QVBoxLayout(this);
        text = new QPlainTextEdit;
        text->setObjectName("transcriptEdit");
        text->setReadOnly(true);
        text->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        layout->addWidget(text);
        auto* btns = new QHBoxLayout;
        auto* copy = new QPushButton(tr("Copy"));
        auto* save = new QPushButton(tr("Save to file…"));
        btns->addWidget(copy);
        btns->addWidget(save);
        btns->addStretch();
        layout->addLayout(btns);
        ack = new QCheckBox(tr("I have saved this backup somewhere I will still have if this computer is gone."));
        ack->setObjectName("backupAckCheck");
        layout->addWidget(ack);
        connect(copy, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(text->toPlainText());
        });
        connect(save, &QPushButton::clicked, this, [this] {
            const QString path = QFileDialog::getSaveFileName(this, tr("Save transcript"),
                                                              m_wizard->walletName() + QStringLiteral("-multisig.txt"),
                                                              tr("Text files (*.txt)"));
            if (path.isEmpty()) return;
            QFile f(path);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                QMessageBox::critical(this, tr("Save failed"), f.errorString());
                return;
            }
            f.write(text->toPlainText().toUtf8());
        });
        connect(ack, &QCheckBox::toggled, this, &QWizardPage::completeChanged);
    }
    void initializePage() override
    {
        m_wizard->rebuildKeyList();
        text->setPlainText(m_wizard->transcript());
        ack->setChecked(false);
    }
    bool isComplete() const override { return ack->isChecked(); }
    bool validatePage() override
    {
        if (!ack->isChecked()) return false;
        if (!m_wizard->createWallet()) {
            QMessageBox::critical(this, tr("Could not create wallet"), m_wizard->m_create_error);
            return false;
        }
        return true;
    }
    int nextId() const override { return MultisigWizard::Page_Verify; }

private:
    MultisigWizard* m_wizard;
};

class MultisigVerifyPage : public QWizardPage
{
public:
    QLineEdit* address{nullptr};
    QListWidget* devices{nullptr};
    QLabel* status{nullptr};

    explicit MultisigVerifyPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Verify the first address"));
        setSubTitle(tr("Compare this address with what each device displays. Specter and Sparrow do this before the first receive."));
        auto* layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel(tr("Receive address")));
        address = new QLineEdit;
        address->setObjectName("verifyAddressEdit");
        address->setReadOnly(true);
        layout->addWidget(address);
        devices = new QListWidget;
        devices->setObjectName("verifyDeviceList");
        layout->addWidget(devices);
        auto* show = new QPushButton(tr("Show on selected device"));
        show->setObjectName("showOnDeviceButton");
        layout->addWidget(show);
        status = new QLabel;
        status->setWordWrap(true);
        layout->addWidget(status);
        layout->addWidget(new QLabel(tr(
            "Air-gapped keys cannot display here. Import this address into the offline signer and confirm it matches.")));
        connect(show, &QPushButton::clicked, this, [this] {
            auto* item = devices->currentItem();
            if (!item) {
                status->setText(tr("Select a device."));
                return;
            }
            const std::string fpr = item->data(Qt::UserRole).toString().toStdString();
            auto res = m_wizard->verifyOnDevice(fpr);
            if (res) {
                status->setText(tr("Device showed the same address."));
                item->setCheckState(Qt::Checked);
            } else {
                status->setText(QString::fromStdString(util::ErrorString(res).original));
            }
            Q_EMIT completeChanged();
        });
    }
    void initializePage() override
    {
        auto dest = m_wizard->firstReceiveAddress();
        if (dest) {
            address->setText(QString::fromStdString(EncodeDestination(*dest)));
        } else {
            address->setText(QString::fromStdString(util::ErrorString(dest).original));
        }
        devices->clear();
        for (const auto& k : m_wizard->keys()) {
            if (!k.fingerprint || k.xpub) continue; // skip air-gapped; they have xpub
            // Hardware-without-xpub-at-spec-time still has fingerprint and no xpub
            // After create, hardware keys may still have no xpub on the spec.
            auto* item = new QListWidgetItem(QString::fromStdString(k.label.empty() ? *k.fingerprint : k.label + " (" + *k.fingerprint + ")"));
            item->setData(Qt::UserRole, QString::fromStdString(*k.fingerprint));
            item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
            item->setCheckState(Qt::Unchecked);
            devices->addItem(item);
        }
        if (devices->count() == 0) {
            devices->addItem(tr("No connected hardware in this vault. Skip this step."));
        }
    }
    bool isComplete() const override { return true; }
    int nextId() const override { return MultisigWizard::Page_Done; }

private:
    MultisigWizard* m_wizard;
};

class MultisigDonePage : public QWizardPage
{
public:
    explicit MultisigDonePage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Wallet is ready"));
        setFinalPage(true);
        auto* layout = new QVBoxLayout(this);
        m_summary = new QLabel;
        m_summary->setWordWrap(true);
        m_summary->setTextFormat(Qt::RichText);
        layout->addWidget(m_summary);
        layout->addStretch();
    }
    void initializePage() override
    {
        m_summary->setText(
            tr("<p>The <b>%1</b> wallet is a <b>%2 of %3</b> vault.</p>"
               "<ul>"
               "<li>Receive — Request payment. Use Verify on hardware when you can.</li>"
               "<li>Send — Core signs with any local keys, then connected hardware. "
               "If signatures are still missing, save the PSBT and take it to an air-gapped signer.</li>"
               "<li>File → Load PSBT to bring a signed transaction back.</li>"
               "</ul>")
                .arg(m_wizard->walletName().toHtmlEscaped())
                .arg(m_wizard->nrequired())
                .arg(m_wizard->keys().size()));
    }

private:
    MultisigWizard* m_wizard;
    QLabel* m_summary;
};

MultisigWizard::MultisigWizard(interfaces::Node& node, WalletController* wallet_controller, QWidget* parent)
    : QWizard(parent, GUIUtil::dialog_flags),
      m_node(node),
      m_wallet_controller(wallet_controller)
{
    setWindowTitle(tr("Create Multisig Wallet"));
    setOption(QWizard::NoBackButtonOnStartPage, true);
    setWizardStyle(QWizard::ModernStyle);
    setMinimumSize(680, 520);
    setPage(Page_Intro, new MultisigIntroPage(this));
    setPage(Page_Setup, new MultisigSetupPage(this));
    setPage(Page_Keys, new MultisigKeysPage(this));
    setPage(Page_Threshold, new MultisigThresholdPage(this));
    setPage(Page_Backup, new MultisigBackupPage(this));
    setPage(Page_Verify, new MultisigVerifyPage(this));
    setPage(Page_Done, new MultisigDonePage(this));
    setStartId(Page_Intro);
}

void MultisigWizard::setWalletName(const QString& name) { m_wallet_name = name; }
void MultisigWizard::setIncludeLocalKey(bool include) { m_include_local = include; }
void MultisigWizard::setOutputType(OutputType type) { m_type = type; }
void MultisigWizard::setNRequired(int n) { m_nrequired = n; }

void MultisigWizard::addHardwareKey(const std::string& fingerprint, const std::string& label)
{
    for (auto& k : m_hardware) {
        if (k.fingerprint && *k.fingerprint == fingerprint) {
            k.label = label;
            return;
        }
    }
    MultisigKeySpec spec;
    spec.fingerprint = fingerprint;
    spec.label = label;
    m_hardware.push_back(std::move(spec));
}

void MultisigWizard::addAirgappedKey(const std::string& fingerprint, const std::string& path, const std::string& xpub, const std::string& label)
{
    MultisigKeySpec spec;
    spec.fingerprint = fingerprint;
    if (!path.empty()) spec.path = path;
    spec.xpub = xpub;
    spec.label = label.empty() ? "air-gapped" : label;
    m_airgapped.push_back(std::move(spec));
}

void MultisigWizard::rebuildKeyList()
{
    m_keys.clear();
    if (m_include_local) {
        MultisigKeySpec local;
        local.label = "This computer";
        m_keys.push_back(std::move(local));
    }
    m_keys.insert(m_keys.end(), m_hardware.begin(), m_hardware.end());
    m_keys.insert(m_keys.end(), m_airgapped.begin(), m_airgapped.end());
}

void MultisigWizard::refreshHardware()
{
    // Listing happens in the keys page; this exists so tests can call it.
}

QString MultisigWizard::transcript() const
{
    return QString::fromStdString(wallet::FormatMultisigTranscript(
        m_wallet_name.toStdString(),
        Params().GetChainTypeString(),
        m_nrequired,
        m_keys,
        m_type,
        m_public_descs));
}

bilingual_str MultisigWizard::policyError() const
{
    return wallet::ValidateMultisigPolicy(m_nrequired, m_keys.size());
}

bool MultisigWizard::createWallet()
{
    m_create_error.clear();
    m_wallet_model = nullptr;
    rebuildKeyList();
    if (const auto err = policyError(); !err.empty()) {
        m_create_error = QString::fromStdString(err.translated);
        return false;
    }

    const bool has_device = std::any_of(m_keys.begin(), m_keys.end(), [](const MultisigKeySpec& k) {
        return k.fingerprint.has_value() && !k.xpub;
    });
    const bool has_ext = std::any_of(m_keys.begin(), m_keys.end(), [](const MultisigKeySpec& k) {
        return k.fingerprint.has_value();
    });
    uint64_t flags = WALLET_FLAG_DESCRIPTORS;
    if (has_ext) flags |= WALLET_FLAG_EXTERNAL_SIGNER;
    if (!m_include_local) flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_EXTERNAL_SIGNER;
    (void)has_device;

    std::vector<bilingual_str> warnings;
    auto created = m_node.walletLoader().createWallet(m_wallet_name.toStdString(), SecureString{}, flags, warnings);
    if (!created) {
        m_create_error = QString::fromStdString(util::ErrorString(created).translated);
        return false;
    }
    if (m_wallet_controller) {
        m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*created));
    } else {
        m_create_error = tr("Wallet created but the GUI could not attach it.");
        return false;
    }

    std::vector<interfaces::Wallet::MultisigKey> iface_keys;
    iface_keys.reserve(m_keys.size());
    for (const auto& k : m_keys) {
        iface_keys.push_back({k.path, k.fingerprint, k.hdkey, k.xpub});
    }
    auto imported = m_wallet_model->wallet().createMultisigDescriptor(m_nrequired, iface_keys, m_type);
    if (!imported) {
        m_create_error = QString::fromStdString(util::ErrorString(imported).original);
        return false;
    }
    m_public_descs = *imported;
    Q_EMIT this->created(m_wallet_model);
    return true;
}

util::Result<CTxDestination> MultisigWizard::firstReceiveAddress()
{
    if (!m_receive_address.isEmpty()) {
        const CTxDestination dest = DecodeDestination(m_receive_address.toStdString());
        if (IsValidDestination(dest)) return dest;
    }
    if (!m_wallet_model) {
        return util::Error{Untranslated("Wallet was not created")};
    }
    auto dest = m_wallet_model->wallet().getNewDestination(m_type, "");
    if (dest) m_receive_address = QString::fromStdString(EncodeDestination(*dest));
    return dest;
}

util::Result<void> MultisigWizard::verifyOnDevice(const std::string& fingerprint)
{
    if (!m_wallet_model) {
        return util::Error{Untranslated("Wallet was not created")};
    }
    CTxDestination dest = DecodeDestination(m_receive_address.toStdString());
    if (m_receive_address.isEmpty()) {
        auto got = firstReceiveAddress();
        if (!got) return util::Error{util::ErrorString(got)};
        dest = *got;
        m_receive_address = QString::fromStdString(EncodeDestination(dest));
    }
    return m_wallet_model->wallet().displayAddress(dest, fingerprint);
}
