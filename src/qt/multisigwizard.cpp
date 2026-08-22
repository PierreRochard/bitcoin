// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/multisigwizard.h>

#include <addresstype.h>
#include <chainparams.h>
#include <external_signer.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <node/context.h>
#include <key_io.h>
#include <qt/guiutil.h>
#include <qt/qrimagewidget.h>
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <support/allocators/secure.h>
#include <util/bip32.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <memory>
#include <set>

#include <QAbstractItemView>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QLocale>
#include <QMessageBox>
#include <QPalette>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QSizePolicy>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWizardPage>

using wallet::MultisigKeySpec;
using wallet::WALLET_FLAG_BLANK_WALLET;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WALLET_FLAG_EXTERNAL_SIGNER;

namespace {
// 10-minute block target, same approximation the policy page shows.
QString ApproxDuration(uint32_t blocks)
{
    const qint64 minutes = static_cast<qint64>(blocks) * 10;
    if (minutes < 90) return QObject::tr("~%1 minutes").arg(minutes);
    if (minutes < 36 * 60) return QObject::tr("~%1 hours").arg((minutes + 30) / 60);
    return QObject::tr("~%1 days").arg((minutes + 12 * 60) / (24 * 60));
}

QString BlockCount(uint32_t blocks)
{
    return blocks == 1 ? QObject::tr("1 block") : QObject::tr("%1 blocks").arg(blocks);
}

QString FormattedHeight(uint32_t height)
{
    return QLocale().toString(static_cast<qulonglong>(height));
}

QString ValidatePublicKeyInput(const std::string& fingerprint, const std::string& path, const std::string& xpub)
{
    if (fingerprint.size() != 8 || !IsHex(fingerprint)) {
        return QObject::tr("Fingerprint must be exactly 8 hexadecimal characters.");
    }
    std::vector<uint32_t> parsed_path;
    if (!ParseHDKeypath(path, parsed_path)) {
        return QObject::tr("Derivation path is not a valid BIP32 path.");
    }
    if (std::none_of(parsed_path.begin(), parsed_path.end(), [](uint32_t step) {
            return (step & BIP32_HARDENED_FLAG) != 0;
        })) {
        return QObject::tr("Derivation path needs at least one hardened step.");
    }
    const CExtPubKey decoded = DecodeExtPubKey(xpub);
    if (!decoded.pubkey.IsValid()) {
        return QObject::tr("The xpub is not valid for this network.");
    }
    return {};
}

bool PublicOnlyPolicy(const wallet::VaultPolicyPackage& package, QString& error)
{
    for (const std::string& encoded : package.descs) {
        FlatSigningProvider keys;
        std::string parse_error;
        auto descriptors = Parse(encoded, keys, parse_error, /*require_checksum=*/true);
        if (descriptors.empty()) {
            error = QObject::tr("The policy package contains an invalid descriptor: %1")
                        .arg(QString::fromStdString(parse_error));
            return false;
        }
        for (const auto& descriptor : descriptors) {
            std::string private_form;
            if (descriptor->ToPrivateString(keys, private_form)) {
                error = QObject::tr("The policy package unexpectedly contains private key material.");
                return false;
            }
        }
        if (!keys.keys.empty()) {
            error = QObject::tr("The policy package unexpectedly contains private keys.");
            return false;
        }
    }
    return true;
}

// Vertical step list shown as QWizard::sideWidget. ClassicStyle +
// ExtendedWatermarkPixmap (qwizard.cpp) paints this as a full-height column
// next to the page and the Back/Continue row — Fusion's native wizard chrome,
// not MacStyle (which reserves a 181px empty gutter and hides Cancel when it
// is the default SH_WizardStyle).
class StepNav : public QFrame
{
public:
    explicit StepNav(MultisigWizard* wizard) : QFrame(wizard), m_wizard(wizard)
    {
        setObjectName("vaultStepNav");
        setFrameShape(QFrame::NoFrame);
        setFixedWidth(188);
        setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
        setStyleSheet(QStringLiteral(
            "QFrame#vaultStepNav { border: none; border-right: 1px solid palette(mid); }"));

        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(16, 18, 12, 16);
        layout->setSpacing(4);

        auto* heading = new QLabel(tr("Steps"));
        QFont heading_font = heading->font();
        heading_font.setBold(true);
        heading->setFont(heading_font);
        layout->addWidget(heading);
        layout->addSpacing(6);

        const QStringList names{
            tr("Intro"), tr("Template"), tr("Type"), tr("Keys"), tr("Policy"),
            tr("Backup"), tr("Verify"), tr("Done")};
        m_dots.reserve(names.size());
        m_names.reserve(names.size());
        for (int i = 0; i < names.size(); ++i) {
            auto* row = new QWidget;
            auto* h = new QHBoxLayout(row);
            h->setContentsMargins(0, 1, 0, 1);
            h->setSpacing(8);
            auto* dot = new QLabel;
            dot->setFixedSize(22, 22);
            dot->setAlignment(Qt::AlignCenter);
            auto* name = new QLabel(names.at(i));
            h->addWidget(dot, 0, Qt::AlignVCenter);
            h->addWidget(name, 1, Qt::AlignVCenter);
            layout->addWidget(row);
            m_dots.push_back(dot);
            m_names.push_back(name);
        }
        layout->addStretch();
        m_policy = new QLabel;
        m_policy->setObjectName("vaultPolicySummary");
        m_policy->setWordWrap(true);
        m_policy->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(m_policy);
        setCurrent(0);
    }

    void setCurrent(int page_id)
    {
        const int nsteps = static_cast<int>(m_dots.size());
        const int current = std::clamp(page_id, 0, nsteps - 1);
        for (int i = 0; i < nsteps; ++i) {
            QLabel* dot = m_dots[i];
            QLabel* name = m_names[i];
            QFont name_font = name->font();
            name_font.setBold(i == current);
            name->setFont(name_font);
            if (i == current) {
                // Same orange as BitcoinGUI's progress bar (#FF8000). Fusion's
                // Highlight is white-on-white in the offscreen/minimal palette.
                dot->setText(QString::number(i + 1));
                dot->setStyleSheet(QStringLiteral(
                    "QLabel { background: #FF8000; color: white; border-radius: 11px; font-weight: 600; }"));
                name->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
            } else if (i < current) {
                dot->setText(QStringLiteral("✓"));
                dot->setStyleSheet(QStringLiteral(
                    "QLabel { background: palette(mid); color: white; border-radius: 11px; }"));
                name->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
            } else {
                dot->setText(QString::number(i + 1));
                dot->setStyleSheet(QStringLiteral(
                    "QLabel { border: 1px solid palette(mid); color: palette(mid); border-radius: 11px; }"));
                name->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
            }
        }
        refreshPolicy();
    }

    void refreshPolicy()
    {
        m_wizard->rebuildKeyList();
        const int n = static_cast<int>(m_wizard->keys().size());
        const int n_active = m_wizard->nActiveKeys();
        if (n >= 2) {
            if (m_wizard->outputType() == OutputType::BECH32M && (m_wizard->fallbackOlder() || m_wizard->fallbackAfter())) {
                QString summary = tr("Immediate all %1\nRecovery %2 of %3").arg(n_active).arg(m_wizard->nrequired()).arg(n);
                if (m_wizard->fallbackOlderOneKey()) {
                    summary += tr("\nFinal recovery 1 of %1").arg(n);
                }
                m_policy->setText(summary);
            } else {
                m_policy->setText(tr("%1 of %2 keys").arg(m_wizard->nrequired()).arg(n));
            }
        } else {
            m_policy->clear();
        }
    }

private:
    std::vector<QLabel*> m_dots;
    std::vector<QLabel*> m_names;
    QLabel* m_policy{nullptr};
    MultisigWizard* m_wizard;
};

QFrame* MakeTitledCard(const QString& title, const QString& body)
{
    auto* inner = new QWidget;
    auto* v = new QVBoxLayout(inner);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(4);
    auto* t = new QLabel(title);
    QFont f = t->font();
    f.setBold(true);
    t->setFont(f);
    auto* b = new QLabel(body);
    b->setWordWrap(true);
    v->addWidget(t);
    v->addWidget(b);
    auto* card = new QFrame;
    card->setFrameShape(QFrame::StyledPanel);
    auto* lay = new QVBoxLayout(card);
    lay->setContentsMargins(12, 10, 12, 10);
    lay->addWidget(inner);
    return card;
}

class AirgappedKeyDialog : public QDialog
{
public:
    QLineEdit* fingerprint{nullptr};
    QLineEdit* path{nullptr};
    QLineEdit* xpub{nullptr};
    QLineEdit* label{nullptr};
    QComboBox* role{nullptr};

    explicit AirgappedKeyDialog(QWidget* parent) : QDialog(parent, GUIUtil::dialog_flags)
    {
        setWindowTitle(tr("Add air-gapped key"));
        setMinimumWidth(520);
        auto* layout = new QVBoxLayout(this);
        auto* copy = new QLabel(tr(
            "Paste an xpub exported from an offline signer (Sparrow, Specter, Coldcard, …). "
            "The device does not need to be connected. Spending later uses PSBT export."));
        copy->setWordWrap(true);
        layout->addWidget(copy);
        auto* form = new QFormLayout;
        label = new QLineEdit;
        label->setPlaceholderText(tr("Coldcard (vault)"));
        fingerprint = new QLineEdit;
        fingerprint->setPlaceholderText(tr("aabbccdd"));
        fingerprint->setMaxLength(8);
        fingerprint->setFont(GUIUtil::fixedPitchFont());
        path = new QLineEdit;
        path->setPlaceholderText(tr("m/48h/1h/0h/2h (P2WSH) or m/48h/1h/0h/3h (P2TR)"));
        path->setFont(GUIUtil::fixedPitchFont());
        xpub = new QLineEdit;
        xpub->setPlaceholderText(tr("xpub… / tpub…"));
        xpub->setFont(GUIUtil::fixedPitchFont());
        role = new QComboBox;
        role->setObjectName("airgapRoleCombo");
        role->addItem(tr("Active (eligible for every recovery stage)"), 0);
        role->addItem(tr("Recovery-only (eligible for every stage)"), 1);
        form->addRow(tr("Label"), label);
        form->addRow(tr("Fingerprint"), fingerprint);
        form->addRow(tr("Path"), path);
        form->addRow(tr("xpub"), xpub);
        form->addRow(tr("Role"), role);
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
    explicit MultisigIntroPage(MultisigWizard* wizard) : QWizardPage(wizard)
    {
        setTitle(tr("Create a vault wallet"));
        setSubTitle(tr("All active keys are required for an immediate spend. If one or more keys are permanently lost, the configured recovery group can spend after the waiting period."));
        auto* layout = new QVBoxLayout(this);
        layout->setSpacing(10);
        auto* path = new QLabel(tr("You will: pick a template → add keys → set recovery timing → save the public backup → verify the first address."));
        path->setWordWrap(true);
        layout->addWidget(path);
        layout->addWidget(MakeTitledCard(
            tr("A lost key freezes spending now"),
            tr("This is not ordinary 2-of-3. In a 3-of-3-now, 2-of-3-later vault, the remaining keys cannot spend until the delay. Losing one key freezes immediate spending.")));
        layout->addWidget(MakeTitledCard(
            tr("Recovery is not automatic"),
            tr("Mature coins do not move themselves. Someone still has to construct a recovery spend. Bitcoin Core cannot reset keys, change the delay, or override the on-chain policy.")));
        layout->addWidget(MakeTitledCard(
            tr("Each coin has its own clock"),
            tr("A relative delay applies separately to each received coin. Change and consolidation start a new wait. Calendar dates derived from block times are estimates.")));
        layout->addWidget(MakeTitledCard(
            tr("Every active key still spends after maturity"),
            tr("The delayed path is a backup. If every active key is still available, an immediate MuSig2 spend works at any time, including after the delay.")));
        layout->addStretch();
    }
    int nextId() const override { return MultisigWizard::Page_Template; }
};

class MultisigTemplatePage : public QWizardPage
{
public:
    explicit MultisigTemplatePage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Choose a starting template"));
        setSubTitle(tr("These are starting points. You can still change keys, roles, and the delay on the next pages."));
        auto* layout = new QVBoxLayout(this);
        layout->setSpacing(8);
        m_group = new QButtonGroup(this);
        auto add = [this, layout](const QString& name, const QString& title, const QString& body, MultisigWizard::VaultTemplate tmpl, bool checked) {
            auto* radio = new QRadioButton(title);
            radio->setObjectName(name);
            radio->setChecked(checked);
            m_group->addButton(radio, static_cast<int>(tmpl));
            layout->addWidget(radio);
            auto* hint = new QLabel(body);
            hint->setWordWrap(true);
            hint->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); margin-left: 22px; margin-bottom: 6px; }"));
            layout->addWidget(hint);
        };
        add(QStringLiteral("templateRecoverRadio"),
            tr("Recover from one lost key (recommended)"),
            tr("All three active keys spend now. Any two recovery keys can spend after about 90 days (12960 blocks)."),
            MultisigWizard::VaultTemplate::RecoverOneLost, /*checked=*/true);
        add(QStringLiteral("templateStagedRadio"),
            tr("Staged recovery (30 / 60 days)"),
            tr("All active keys spend now. Any two recovery keys can spend after about 30 days; any one recovery key can spend after about 60 days."),
            MultisigWizard::VaultTemplate::StagedRecovery, false);
        add(QStringLiteral("templateMaximumRadio"),
            tr("Maximum protection"),
            tr("n-of-n MuSig2 only. No delayed recovery path. Losing any key freezes the funds."),
            MultisigWizard::VaultTemplate::Maximum, false);
        add(QStringLiteral("templateHardwareRadio"),
            tr("Hardware-only coordinator"),
            tr("This computer does not hold a key. Hardware devices or offline xpubs provide every signature."),
            MultisigWizard::VaultTemplate::HardwareCoordinator, false);
        add(QStringLiteral("templateInheritRadio"),
            tr("Separate inheritance keys"),
            tr("Last air-gapped key is recovery-only: it is not in the immediate MuSig2 group and can only sign after the delay."),
            MultisigWizard::VaultTemplate::Inheritance, false);
        add(QStringLiteral("templateCustomRadio"),
            tr("Custom"),
            tr("Use the type, keys, roles, threshold, and delay already chosen."),
            MultisigWizard::VaultTemplate::Custom, false);
        connect(m_group, &QButtonGroup::idToggled, this, [this](int id, bool checked) {
            if (!checked || id < 0) return;
            m_wizard->setVaultTemplate(static_cast<MultisigWizard::VaultTemplate>(id));
            m_wizard->applyTemplate();
            Q_EMIT completeChanged();
        });
        layout->addStretch();
    }
    bool validatePage() override
    {
        m_wizard->applyTemplate();
        return true;
    }
    int nextId() const override { return MultisigWizard::Page_Setup; }

private:
    MultisigWizard* m_wizard;
    QButtonGroup* m_group{nullptr};
};

class MultisigSetupPage : public QWizardPage
{
public:
    QLineEdit* name{nullptr};
    QComboBox* type{nullptr};

    explicit MultisigSetupPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Wallet name and type"));
        setSubTitle(tr("A Scrooge vault is Taproot n-of-n now and fewer keys later. Pick Native SegWit only if a device cannot sign Taproot — that is ordinary m-of-n, not a vault."));
        auto* layout = new QVBoxLayout(this);
        auto* form = new QFormLayout;
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        name = new QLineEdit;
        name->setObjectName("walletNameEdit");
        name->setText(wizard->walletName());
        name->setPlaceholderText(tr("Family vault"));
        name->setText(wizard->walletName());
        type = new QComboBox;
        type->setObjectName("scriptTypeCombo");
        type->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        type->setMinimumContentsLength(32);
        type->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
        type->addItem(tr("Scrooge vault (MuSig2 + recovery)"), QVariant::fromValue(static_cast<int>(OutputType::BECH32M)));
        type->addItem(tr("Native SegWit (P2WSH)"), QVariant::fromValue(static_cast<int>(OutputType::BECH32)));
        type->addItem(tr("Nested SegWit (P2SH-P2WSH)"), QVariant::fromValue(static_cast<int>(OutputType::P2SH_SEGWIT)));
        type->addItem(tr("Legacy (P2SH)"), QVariant::fromValue(static_cast<int>(OutputType::LEGACY)));
        form->addRow(tr("Wallet name"), name);
        form->addRow(tr("Script type"), type);
        layout->addLayout(form);
        m_hint = new QLabel;
        m_hint->setWordWrap(true);
        m_hint->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(m_hint);
        layout->addStretch();
        connect(name, &QLineEdit::textChanged, this, &QWizardPage::completeChanged);
        connect(type, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] {
            m_wizard->setOutputType(static_cast<OutputType>(type->currentData().toInt()));
            updateHint();
            Q_EMIT completeChanged();
        });
        registerField("walletName*", name);
        updateHint();
    }
    void initializePage() override
    {
        name->setText(m_wizard->walletName());
        for (int i = 0; i < type->count(); ++i) {
            if (type->itemData(i).toInt() == static_cast<int>(m_wizard->outputType())) {
                type->setCurrentIndex(i);
                break;
            }
        }
        updateHint();
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
    void updateHint()
    {
        const bool taproot = type && type->currentData().toInt() == static_cast<int>(OutputType::BECH32M);
        if (taproot) {
            setSubTitle(tr("Scrooge vault: every active key spends now as one on-chain signature. Fewer keys can recover after a delay you set later."));
            m_hint->setText(tr("Recovery is always a separate, explicit spend. The wallet never switches paths automatically."));
        } else {
            setSubTitle(tr("Ordinary multisig. There is no delayed recovery path. Use this only if a device cannot sign Taproot."));
            m_hint->setText(tr("Each spend uses the signature threshold you choose on the Policy page."));
        }
    }
    MultisigWizard* m_wizard;
    QLabel* m_hint{nullptr};
};

class MultisigKeysPage : public QWizardPage
{
public:
    QCheckBox* local{nullptr};
    QListWidget* hardware{nullptr};
    QListWidget* airgapped{nullptr};
    QCheckBox* inherit{nullptr};

    explicit MultisigKeysPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Keys"));
        setSubTitle(tr("Add every key that will be part of the vault. Hardware can be unplugged later."));
        auto* layout = new QVBoxLayout(this);
        layout->setSpacing(10);

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
        hardware->setMinimumHeight(72);
        hardware->setMaximumHeight(140);
        hardware->setAlternatingRowColors(true);
        hw_empty = new QLabel(tr("No hardware wallets detected. Plug in a device or add an xpub below."));
        hw_empty->setObjectName("hardwareEmptyLabel");
        hw_empty->setWordWrap(true);
        hw_empty->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        hw_layout->addWidget(hw_empty);
        hw_layout->addWidget(hardware);
        auto* refresh = new QPushButton(tr("Refresh devices"));
        refresh->setObjectName("refreshDevicesButton");
        refresh->setAutoDefault(false);
        hw_layout->addWidget(refresh, 0, Qt::AlignLeft);
        layout->addWidget(hw_box);

        auto* air_box = new QGroupBox(tr("Air-gapped / xpub"));
        auto* air_layout = new QVBoxLayout(air_box);
        airgapped = new QListWidget;
        airgapped->setObjectName("airgappedList");
        airgapped->setMinimumHeight(48);
        airgapped->setMaximumHeight(96);
        airgapped->setAlternatingRowColors(true);
        air_layout->addWidget(airgapped);
        auto* air_btns = new QHBoxLayout;
        auto* add_air = new QPushButton(tr("Add xpub…"));
        add_air->setObjectName("addXpubButton");
        add_air->setAutoDefault(false);
        auto* remove_air = new QPushButton(tr("Remove selected"));
        remove_air->setObjectName("removeXpubButton");
        remove_air->setAutoDefault(false);
        air_btns->addWidget(add_air);
        air_btns->addWidget(remove_air);
        air_btns->addStretch();
        air_layout->addLayout(air_btns);
        layout->addWidget(air_box);

        m_count = new QLabel;
        m_count->setObjectName("vaultKeyCount");
        m_count->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(m_count);
        inherit = new QCheckBox(tr("Last air-gapped key is recovery-only (inheritance)"));
        inherit->setObjectName("recoveryOnlyCheck");
        inherit->setToolTip(tr("That key is not in the immediate MuSig2 group. It can only sign after the recovery delay."));
        layout->addWidget(inherit);

        connect(local, &QCheckBox::toggled, this, [this](bool checked) {
            m_wizard->setIncludeLocalKey(checked);
            updateCount();
            Q_EMIT completeChanged();
        });
        connect(inherit, &QCheckBox::toggled, this, [this](bool checked) {
            m_wizard->m_last_airgap_recovery_only = checked;
            if (!m_wizard->m_airgapped.empty()) {
                m_wizard->m_airgapped.back().recovery_only = checked;
            }
            m_wizard->rebuildKeyList();
            populateAirgapped();
            updateCount();
            Q_EMIT completeChanged();
        });
        connect(refresh, &QPushButton::clicked, this, [this] {
            m_wizard->refreshHardware();
            populateHardware();
            updateCount();
            Q_EMIT completeChanged();
        });
        connect(hardware, &QListWidget::itemChanged, this, [this](QListWidgetItem* item) {
            const QString fpr = item->data(Qt::UserRole).toString();
            if (item->checkState() == Qt::Checked) {
                m_wizard->addHardwareKey(fpr.toStdString(), item->text().toStdString());
            } else {
                std::vector<std::pair<std::string, std::string>> keep;
                for (int i = 0; i < hardware->count(); ++i) {
                    auto* it = hardware->item(i);
                    if (it->flags() & Qt::ItemIsUserCheckable && it->checkState() == Qt::Checked) {
                        keep.emplace_back(it->data(Qt::UserRole).toString().toStdString(), it->text().toStdString());
                    }
                }
                m_wizard->m_hardware.clear();
                for (const auto& [fp, lab] : keep) m_wizard->addHardwareKey(fp, lab);
            }
            updateCount();
            Q_EMIT completeChanged();
        });
        connect(add_air, &QPushButton::clicked, this, [this] {
            AirgappedKeyDialog dlg(this);
            dlg.path->setText(QString::fromStdString(wallet::DefaultMultisigPath(m_wizard->outputType(), 0)));
            if (m_wizard->vaultTemplate() == MultisigWizard::VaultTemplate::Inheritance) {
                dlg.role->setCurrentIndex(1);
            }
            if (dlg.exec() != QDialog::Accepted) return;
            const QString fpr = dlg.fingerprint->text().trimmed().toLower();
            const QString xpub = dlg.xpub->text().trimmed();
            QString path = dlg.path->text().trimmed();
            const QString input_error = ValidatePublicKeyInput(fpr.toStdString(), path.toStdString(), xpub.toStdString());
            if (!input_error.isEmpty()) {
                QMessageBox::warning(this, tr("Invalid key"), input_error);
                return;
            }
            m_wizard->addAirgappedKey(fpr.toStdString(), path.toStdString(), xpub.toStdString(),
                                      dlg.label->text().trimmed().toStdString(),
                                      dlg.role && dlg.role->currentData().toInt() == 1);
            populateAirgapped();
            updateCount();
            Q_EMIT completeChanged();
        });
        connect(remove_air, &QPushButton::clicked, this, [this] {
            auto* item = airgapped->currentItem();
            if (!item) return;
            const int row = airgapped->row(item);
            if (row >= 0 && static_cast<size_t>(row) < m_wizard->m_airgapped.size()) {
                m_wizard->m_airgapped.erase(m_wizard->m_airgapped.begin() + row);
            }
            m_wizard->m_last_airgap_recovery_only = m_wizard->m_airgapped.empty()
                ? m_wizard->vaultTemplate() == MultisigWizard::VaultTemplate::Inheritance
                : m_wizard->m_airgapped.back().recovery_only;
            inherit->blockSignals(true);
            inherit->setChecked(m_wizard->m_last_airgap_recovery_only);
            inherit->blockSignals(false);
            populateAirgapped();
            updateCount();
            Q_EMIT completeChanged();
        });
    }
    void initializePage() override
    {
        local->setChecked(m_wizard->includeLocalKey());
        const bool taproot = m_wizard->outputType() == OutputType::BECH32M;
        inherit->setVisible(taproot);
        if (!taproot) {
            for (auto& k : m_wizard->m_airgapped) k.recovery_only = false;
            m_wizard->m_last_airgap_recovery_only = false;
        } else {
            m_wizard->m_last_airgap_recovery_only = m_wizard->m_airgapped.empty()
                ? m_wizard->m_last_airgap_recovery_only
                : m_wizard->m_airgapped.back().recovery_only;
        }
        inherit->blockSignals(true);
        inherit->setChecked(m_wizard->m_last_airgap_recovery_only);
        inherit->blockSignals(false);
        m_wizard->refreshHardware();
        populateHardware();
        populateAirgapped();
        updateCount();
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
                                 tr("A vault wallet needs at least two keys. Add a hardware device, an xpub, or keep the key on this computer."));
            return false;
        }
        const auto dup = wallet::DuplicateSignerWarning(m_wizard->keys());
        if (!dup.empty()) {
            QMessageBox::warning(this, tr("Same signer twice"), QString::fromStdString(dup.original));
        }
        return true;
    }
    int nextId() const override { return MultisigWizard::Page_Threshold; }

private:
    void updateCount()
    {
        m_wizard->rebuildKeyList();
        const int n = static_cast<int>(m_wizard->keys().size());
        const int n_active = m_wizard->nActiveKeys();
        if (n < 2) {
            m_count->setText(tr("%1 key so far — add at least two.").arg(n));
        } else {
            m_count->setText(tr("%1 keys (%2 active, %3 recovery-only).")
                                 .arg(n)
                                 .arg(n_active)
                                 .arg(n - n_active));
        }
        m_wizard->refreshSidebar();
    }
    void populateHardware()
    {
        hardware->clear();
        hw_empty->hide();
        hardware->show();
        try {
            // AppTests shuts the GUI node down before this wizard is constructed
            // in test_bitcoin-qt; listing then hits NodeImpl::args() on a null
            // ArgsManager. A live bitcoin-qt always has context()->args.
            std::vector<std::unique_ptr<interfaces::ExternalSigner>> signers;
            if (auto* ctx = m_wizard->node().context(); ctx && ctx->args) {
                signers = m_wizard->node().listExternalSigners();
            }
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
                hardware->hide();
                hw_empty->setText(tr("No hardware wallets detected. Plug in a device or add an xpub below."));
                hw_empty->show();
            }
        } catch (const std::exception& e) {
            hardware->hide();
            hw_empty->setText(QString::fromStdString(e.what()));
            hw_empty->show();
        }
    }
    void populateAirgapped()
    {
        airgapped->clear();
        if (m_wizard->m_airgapped.empty()) {
            auto* item = new QListWidgetItem(tr("No air-gapped keys yet."));
            item->setFlags(Qt::NoItemFlags);
            item->setForeground(palette().placeholderText());
            airgapped->addItem(item);
            return;
        }
        for (const auto& k : m_wizard->m_airgapped) {
            QString line = QString::fromStdString(k.label.empty() ? "xpub" : k.label);
            if (k.fingerprint) line += QStringLiteral("  ") + QString::fromStdString(*k.fingerprint);
            if (k.path) line += QStringLiteral("  ") + QString::fromStdString(*k.path);
            line += k.recovery_only ? tr("  · recovery-only") : tr("  · active");
            airgapped->addItem(line);
        }
    }
    MultisigWizard* m_wizard;
    QLabel* m_count{nullptr};
    QLabel* hw_empty{nullptr};
};

class MultisigThresholdPage : public QWizardPage
{
public:
    QSpinBox* required{nullptr};
    QSpinBox* delay{nullptr};
    QSpinBox* after{nullptr};
    QSpinBox* final_delay{nullptr};
    QComboBox* delay_kind{nullptr};
    QCheckBox* staged{nullptr};
    QLabel* delay_label{nullptr};
    QLabel* after_label{nullptr};
    QLabel* final_delay_label{nullptr};
    QLabel* kind_label{nullptr};
    QLabel* required_label{nullptr};
    QLabel* delay_hint{nullptr};
    QLabel* sentence{nullptr};
    QLabel* headline{nullptr};
    QLabel* stages_summary{nullptr};

    explicit MultisigThresholdPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setCommitPage(true);
        setTitle(tr("Immediate spend and recovery"));
        setSubTitle(tr("Choose how many keys can recover after the delay. Immediate spend always needs every active key."));
        auto* layout = new QVBoxLayout(this);
        headline = new QLabel;
        headline->setObjectName("policyHeadline");
        headline->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        QFont big = headline->font();
        big.setPointSize(big.pointSize() + 8);
        big.setBold(true);
        headline->setFont(big);
        layout->addWidget(headline);
        layout->addSpacing(8);

        auto* form = new QFormLayout;
        form->setFieldGrowthPolicy(QFormLayout::FieldsStayAtSizeHint);
        required = new QSpinBox;
        required->setObjectName("nrequiredSpin");
        required->setMinimum(1);
        required->setMinimumWidth(88);
        form->addRow(tr("Recovery keys required"), required);
        required_label = qobject_cast<QLabel*>(form->labelForField(required));
        delay_kind = new QComboBox;
        delay_kind->setObjectName("delayKindCombo");
        delay_kind->addItem(tr("Relative delay (per coin)"), 0);
        delay_kind->addItem(tr("Absolute block height"), 1);
        form->addRow(tr("Delay type"), delay_kind);
        kind_label = qobject_cast<QLabel*>(form->labelForField(delay_kind));
        delay = new QSpinBox;
        delay->setObjectName("fallbackOlderSpin");
        delay->setMinimum(0);
        delay->setMaximum(0xffff);
        delay->setSpecialValueText(tr("Off"));
        delay->setMinimumWidth(120);
        delay->setSuffix(QStringLiteral(" ") + tr("blocks"));
        form->addRow(tr("Recovery delay"), delay);
        delay_label = qobject_cast<QLabel*>(form->labelForField(delay));
        after = new QSpinBox;
        after->setObjectName("fallbackAfterSpin");
        after->setMinimum(2);
        after->setMaximum((1 << 30) - 1);
        after->setMinimumWidth(120);
        after->setGroupSeparatorShown(true);
        after->setValue(static_cast<int>(MultisigWizard::kDefaultVaultDelay));
        form->addRow(tr("Recovery height"), after);
        after_label = qobject_cast<QLabel*>(form->labelForField(after));
        staged = new QCheckBox(tr("Add a later one-key recovery stage"));
        staged->setObjectName("stagedRecoveryCheck");
        form->addRow(QString(), staged);
        final_delay = new QSpinBox;
        final_delay->setObjectName("finalRecoveryOlderSpin");
        final_delay->setMinimum(2);
        final_delay->setMaximum(0xffff);
        final_delay->setMinimumWidth(120);
        final_delay->setSuffix(QStringLiteral(" ") + tr("blocks"));
        form->addRow(tr("Any 1 recovery key after"), final_delay);
        final_delay_label = qobject_cast<QLabel*>(form->labelForField(final_delay));
        layout->addLayout(form);
        layout->addSpacing(6);
        delay_hint = new QLabel;
        delay_hint->setWordWrap(true);
        delay_hint->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(delay_hint);

        stages_summary = new QLabel;
        stages_summary->setObjectName("recoveryStagesSummaryLabel");
        stages_summary->setWordWrap(true);
        layout->addWidget(stages_summary);

        sentence = new QLabel;
        sentence->setObjectName("policySentence");
        sentence->setTextFormat(Qt::RichText);
        sentence->setWordWrap(true);
        layout->addWidget(sentence);
        layout->addStretch();
        connect(required, qOverload<int>(&QSpinBox::valueChanged), this, [this](int v) {
            m_wizard->setNRequired(v);
            updateSentence();
            Q_EMIT completeChanged();
        });
        connect(delay, qOverload<int>(&QSpinBox::valueChanged), this, [this](int v) {
            delay->setSuffix(QStringLiteral(" ") + (v == 1 ? tr("block") : tr("blocks")));
            m_wizard->setFallbackOlder(v > 0 ? std::optional<uint32_t>{static_cast<uint32_t>(v)} : std::nullopt);
            if (staged->isChecked() && v > 0 && final_delay->value() <= v) {
                final_delay->setValue(std::min(0xffff, std::max(v + 1, v * 2)));
            }
            if (delay_kind->currentData().toInt() == 0) {
                after->blockSignals(true);
                after->setValue(safeAfterHeight());
                after->blockSignals(false);
            }
            updateStageControls();
            updateSentence();
            Q_EMIT completeChanged();
        });
        connect(staged, &QCheckBox::toggled, this, [this](bool checked) {
            if (checked) {
                const int first = std::max(1, delay->value());
                if (final_delay->value() <= first) {
                    final_delay->setValue(std::min(0xffff, std::max(first + 1, first * 2)));
                }
                m_wizard->setFallbackOlderOneKey(static_cast<uint32_t>(final_delay->value()));
            } else {
                m_wizard->setFallbackOlderOneKey(std::nullopt);
            }
            updateStageControls();
            updateSentence();
            Q_EMIT completeChanged();
        });
        connect(final_delay, qOverload<int>(&QSpinBox::valueChanged), this, [this](int v) {
            final_delay->setSuffix(QStringLiteral(" ") + (v == 1 ? tr("block") : tr("blocks")));
            if (staged->isChecked()) m_wizard->setFallbackOlderOneKey(static_cast<uint32_t>(v));
            updateSentence();
            Q_EMIT completeChanged();
        });
        connect(after, qOverload<int>(&QSpinBox::valueChanged), this, [this](int v) {
            m_wizard->setFallbackAfter(static_cast<uint32_t>(v));
            updateSentence();
            Q_EMIT completeChanged();
        });
        connect(delay_kind, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) {
            applyDelayKind();
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
        if (m_wizard->vaultTemplate() == MultisigWizard::VaultTemplate::Maximum) {
            def = n;
        } else if (m_wizard->vaultTemplate() != MultisigWizard::VaultTemplate::Custom && m_wizard->preferNMinus1()) {
            def = std::max(1, n - 1);
        } else if (def < 1 || def > n) {
            def = std::min(2, n);
        }
        required->setValue(def);
        m_wizard->setNRequired(def);
        const bool taproot = m_wizard->outputType() == OutputType::BECH32M;
        if (taproot) {
            setTitle(tr("Immediate spend and recovery"));
            setSubTitle(tr("All active keys spend now as one signature. Choose how many of the recovery keys can spend after the delay — that is a different threshold."));
        } else {
            setTitle(tr("Signature threshold"));
            setSubTitle(tr("This is ordinary m-of-n. There is no delayed recovery path."));
        }
        delay_kind->setVisible(taproot);
        if (kind_label) kind_label->setVisible(taproot);
        delay_hint->setVisible(taproot);
        const std::optional<uint32_t> configured_after = m_wizard->fallbackAfter();
        delay_kind->blockSignals(true);
        delay->blockSignals(true);
        after->blockSignals(true);
        staged->blockSignals(true);
        final_delay->blockSignals(true);
        if (!taproot) {
            delay->setValue(0);
            m_wizard->setFallbackOlder(std::nullopt);
            m_wizard->setFallbackOlderOneKey(std::nullopt);
            m_wizard->setFallbackAfter(std::nullopt);
            delay_kind->setCurrentIndex(0);
        } else if (configured_after && *configured_after > 1) {
            delay_kind->setCurrentIndex(1);
            after->setValue(static_cast<int>(*configured_after));
        } else {
            delay_kind->setCurrentIndex(0);
            const int cur = m_wizard->fallbackOlder() ? static_cast<int>(*m_wizard->fallbackOlder()) : 0;
            delay->setValue(cur);
            delay->setSuffix(QStringLiteral(" ") + (cur == 1 ? tr("block") : tr("blocks")));
            after->setValue(safeAfterHeight());
            m_wizard->setFallbackOlder(cur > 0 ? std::optional<uint32_t>{static_cast<uint32_t>(cur)} : std::nullopt);
        }
        const auto configured_final = m_wizard->fallbackOlderOneKey();
        staged->setChecked(configured_final.has_value());
        final_delay->setValue(static_cast<int>(configured_final.value_or(
            std::min<uint32_t>(0xffff, std::max<uint32_t>(2, m_wizard->fallbackOlder().value_or(1) * 2)))));
        after->blockSignals(false);
        delay->blockSignals(false);
        delay_kind->blockSignals(false);
        final_delay->blockSignals(false);
        staged->blockSignals(false);
        applyDelayKind();
        updateStageControls();
        updateSentence();
    }
    bool isComplete() const override
    {
        const size_t n_active = static_cast<size_t>(std::count_if(
            m_wizard->keys().begin(), m_wizard->keys().end(),
            [](const wallet::MultisigKeySpec& k) { return !k.recovery_only; }));
        return wallet::ValidateMultisigPolicy(m_wizard->nrequired(), n_active,
                                              m_wizard->outputType(), m_wizard->fallbackOlder(),
                                              m_wizard->fallbackAfter(), m_wizard->keys().size(),
                                              m_wizard->fallbackOlderOneKey()).empty();
    }
    bool validatePage() override
    {
        if (!isComplete()) return false;
        if (m_wizard->createdWallet() && !m_wizard->m_policy_package.isEmpty()) {
            m_wizard->lockCommittedJourney();
            return true;
        }
        if (m_wizard->createWallet()) {
            m_wizard->lockCommittedJourney();
            return true;
        }
        QMessageBox::critical(this, tr("Could not create wallet"), m_wizard->createError());
        return false;
    }
    int nextId() const override { return MultisigWizard::Page_Backup; }

private:
    int safeAfterHeight() const
    {
        uint64_t tip{0};
        if (m_wizard->m_wallet_controller) {
            tip = static_cast<uint64_t>(std::max(0, m_wizard->node().getNumBlocks()));
        }
        const uint64_t delay_blocks = m_wizard->fallbackOlder().value_or(MultisigWizard::kDefaultVaultDelay);
        return static_cast<int>(std::min<uint64_t>((1U << 30) - 1, std::max<uint64_t>(2, tip + std::max<uint64_t>(1, delay_blocks))));
    }

    void applyDelayKind()
    {
        const bool taproot = m_wizard->outputType() == OutputType::BECH32M;
        const bool abs = taproot && delay_kind->currentData().toInt() == 1;
        delay->setVisible(taproot && !abs);
        if (delay_label) delay_label->setVisible(taproot && !abs);
        after->setVisible(abs);
        if (after_label) after_label->setVisible(abs);
        if (!taproot) return;
        if (abs) {
            m_wizard->setFallbackOlder(std::nullopt);
            m_wizard->setFallbackOlderOneKey(std::nullopt);
            m_wizard->setFallbackAfter(static_cast<uint32_t>(after->value()));
        } else {
            m_wizard->setFallbackAfter(std::nullopt);
            m_wizard->setFallbackOlder(delay->value() > 0 ? std::optional<uint32_t>{static_cast<uint32_t>(delay->value())} : std::nullopt);
            if (staged->isChecked() && delay->value() > 0) {
                m_wizard->setFallbackOlderOneKey(static_cast<uint32_t>(final_delay->value()));
            }
        }
        updateStageControls();
    }
    void updateStageControls()
    {
        const bool relative = m_wizard->outputType() == OutputType::BECH32M &&
                              delay_kind->currentData().toInt() == 0 && delay->value() > 0;
        staged->setVisible(relative);
        staged->setEnabled(relative);
        const bool show_final = relative && staged->isChecked();
        final_delay->setVisible(show_final);
        if (final_delay_label) final_delay_label->setVisible(show_final);
        stages_summary->setVisible(show_final);
        if (!relative && staged->isChecked()) {
            staged->blockSignals(true);
            staged->setChecked(false);
            staged->blockSignals(false);
            m_wizard->setFallbackOlderOneKey(std::nullopt);
        }
    }
    void updateSentence()
    {
        const int n = static_cast<int>(m_wizard->keys().size());
        const int n_active = static_cast<int>(std::count_if(
            m_wizard->keys().begin(), m_wizard->keys().end(),
            [](const wallet::MultisigKeySpec& k) { return !k.recovery_only; }));
        const int can_lose = std::max(0, n - m_wizard->nrequired());
        const QString lose = (can_lose == 1) ? tr("1 key") : tr("%1 keys").arg(can_lose);
        if (required_label) {
            required_label->setText(m_wizard->outputType() == OutputType::BECH32M ? tr("Recovery keys required")
                                                                                : tr("Signatures required"));
        }
        if (m_wizard->outputType() != OutputType::BECH32M) {
            headline->setText(tr("Ordinary multisig"));
            sentence->setText(tr("<p>Every spend uses the signature threshold above. There is no delayed recovery path.</p>"));
            delay_hint->clear();
            stages_summary->clear();
            return;
        }
        headline->setText(tr("All %1 active keys now").arg(n_active));
        QString extra = tr("<p>Changing keys or timing later requires a new wallet and an on-chain transfer.</p>");
        if (m_wizard->fallbackOlder() && m_wizard->fallbackOlderOneKey()) {
            extra = tr("<p><b>Immediate:</b> all %1 active keys are required.</p>"
                       "<p><b>First recovery:</b> after approximately %2 (%3), any %4 of %5 recovery keys can spend.</p>"
                       "<p><b>Final recovery:</b> after approximately %6 (%7), any 1 of %5 recovery keys can spend.</p>"
                       "<p>After the final delay, both recovery paths remain available. Each received coin waits separately; spending and change restart both clocks. Recovery never happens automatically.</p>")
                        .arg(n_active)
                        .arg(ApproxDuration(*m_wizard->fallbackOlder()))
                        .arg(BlockCount(*m_wizard->fallbackOlder()))
                        .arg(m_wizard->nrequired())
                        .arg(n)
                        .arg(ApproxDuration(*m_wizard->fallbackOlderOneKey()))
                        .arg(BlockCount(*m_wizard->fallbackOlderOneKey()));
            delay_hint->setText(tr("Relative delays are measured from when each coin is received. Calendar dates are estimates."));
            stages_summary->setText(tr("First: %1 of %2 after %3 blocks. Final: any 1 of %2 after %4 blocks.")
                                        .arg(m_wizard->nrequired()).arg(n)
                                        .arg(*m_wizard->fallbackOlder()).arg(*m_wizard->fallbackOlderOneKey()));
        } else if (m_wizard->fallbackOlder()) {
            extra = tr("<p><b>Immediate:</b> all %1 active keys are required.</p>"
                       "<p><b>Recovery:</b> after approximately %2 (%3), any %4 of %5 recovery keys can spend. You can lose %6 and still recover.</p>"
                       "<p>Each received coin waits separately. Spending and change restart its clock. Recovery never happens automatically.</p>")
                        .arg(n_active)
                        .arg(ApproxDuration(*m_wizard->fallbackOlder()))
                        .arg(BlockCount(*m_wizard->fallbackOlder()))
                        .arg(m_wizard->nrequired())
                        .arg(n)
                        .arg(lose);
            delay_hint->setText(tr("Measured from when each coin is received. 144 blocks ≈ 1 day, 1008 ≈ 1 week, 12960 ≈ 90 days. Calendar dates are estimates."));
            stages_summary->clear();
        } else if (m_wizard->fallbackAfter()) {
            extra = tr("<p><b>Immediate:</b> all %1 active keys are required.</p>"
                       "<p><b>Recovery:</b> at block height %2, any %3 of %4 recovery keys can spend. Coins received later may already be recoverable.</p>"
                       "<p>Recovery never happens automatically.</p>")
                        .arg(n_active)
                        .arg(FormattedHeight(*m_wizard->fallbackAfter()))
                        .arg(m_wizard->nrequired())
                        .arg(n);
            delay_hint->setText(tr("The recovery condition uses a block height, not a calendar date."));
            stages_summary->clear();
        } else if (m_wizard->nrequired() == n && n >= 2) {
            extra = tr("<p>Every active key must participate. There is no delayed recovery path.</p>");
            delay_hint->setText(tr("Set a recovery delay to make a Scrooge vault: fewer keys can spend after that many blocks."));
            stages_summary->clear();
        } else {
            extra = tr("<p>This is ordinary Taproot multisig. There is no delayed recovery path.</p>");
            delay_hint->setText(tr("A recovery delay turns this into a Scrooge vault: fewer keys can spend after a delay."));
            stages_summary->clear();
        }
        sentence->setText(extra);
    }
    MultisigWizard* m_wizard;
};

class MultisigBackupPage : public QWizardPage
{
public:
    QPlainTextEdit* policy{nullptr};
    QPlainTextEdit* human{nullptr};
    QCheckBox* ack{nullptr};

    explicit MultisigBackupPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Save the backup"));
        setSubTitle(tr("Save the importable policy JSON. The separate human transcript is for review and is not directly importable."));
        auto* layout = new QVBoxLayout(this);
        auto* warn = new QLabel(tr(
            "Keep four distinct backups: (1) this computer's secret if it holds a key, (2) each hardware seed, "
            "(3) this public policy package, (4) PINs or passphrases. A seed without the policy is not enough. "
            "The package without seeds cannot spend."));
        warn->setWordWrap(true);
        layout->addWidget(warn);
        auto* tabs = new QTabWidget;
        tabs->setObjectName("backupTabs");
        policy = new QPlainTextEdit;
        policy->setObjectName("policyPackageEdit");
        policy->setReadOnly(true);
        policy->setFont(GUIUtil::fixedPitchFont());
        policy->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        tabs->addTab(policy, tr("Policy JSON (importable)"));
        human = new QPlainTextEdit;
        human->setObjectName("humanTranscriptEdit");
        human->setReadOnly(true);
        human->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        tabs->addTab(human, tr("Human transcript"));
        layout->addWidget(tabs);

        auto* policy_btns = new QHBoxLayout;
        m_copy_policy = new QPushButton(tr("Copy policy JSON"));
        m_copy_policy->setObjectName("copyPolicyButton");
        m_copy_policy->setAutoDefault(false);
        m_save_policy = new QPushButton(tr("Save policy JSON…"));
        m_save_policy->setObjectName("savePolicyButton");
        m_save_policy->setAutoDefault(false);
        auto* copy_human = new QPushButton(tr("Copy transcript"));
        copy_human->setObjectName("copyTranscriptButton");
        copy_human->setAutoDefault(false);
        auto* save_human = new QPushButton(tr("Save transcript…"));
        save_human->setObjectName("saveTranscriptButton");
        save_human->setAutoDefault(false);
        policy_btns->addWidget(m_copy_policy);
        policy_btns->addWidget(m_save_policy);
        policy_btns->addWidget(copy_human);
        policy_btns->addWidget(save_human);
        policy_btns->addStretch();
        layout->addLayout(policy_btns);
        m_status = new QLabel;
        m_status->setObjectName("policyPackageStatus");
        m_status->setWordWrap(true);
        layout->addWidget(m_status);
        ack = new QCheckBox(tr("I saved the policy JSON somewhere I will still have if this computer is gone."));
        ack->setObjectName("backupAckCheck");
        layout->addWidget(ack);
        connect(m_copy_policy, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(policy->toPlainText());
        });
        connect(m_save_policy, &QPushButton::clicked, this, [this] {
            saveText(tr("Save policy JSON"), m_wizard->walletName() + QStringLiteral("-vault-policy.json"),
                     tr("JSON files (*.json)"), policy->toPlainText());
        });
        connect(copy_human, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(human->toPlainText());
        });
        connect(save_human, &QPushButton::clicked, this, [this] {
            saveText(tr("Save human transcript"), m_wizard->walletName() + QStringLiteral("-vault-transcript.txt"),
                     tr("Text files (*.txt)"), human->toPlainText());
        });
        connect(ack, &QCheckBox::toggled, this, &QWizardPage::completeChanged);
    }
    void initializePage() override
    {
        m_wizard->rebuildKeyList();
        ack->setChecked(false);
        refreshPackage();
    }
    bool isComplete() const override { return m_package_valid && ack->isChecked(); }
    bool validatePage() override { return isComplete(); }
    int nextId() const override { return MultisigWizard::Page_Verify; }

private:
    void saveText(const QString& title, const QString& suggested, const QString& filter, const QString& contents)
    {
        const QString path = QFileDialog::getSaveFileName(this, title, suggested, filter);
        if (path.isEmpty()) return;
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QMessageBox::critical(this, tr("Save failed"), file.errorString());
            return;
        }
        file.write(contents.toUtf8());
    }

    void refreshPackage()
    {
        policy->setPlainText(m_wizard->m_policy_package);
        human->setPlainText(m_wizard->transcript());
        m_package_valid = false;
        if (!m_wizard->m_policy_package.isEmpty()) {
            auto parsed = wallet::ParseVaultPolicyPackage(m_wizard->m_policy_package.toStdString());
            if (!parsed) {
                m_status->setText(QString::fromStdString(util::ErrorString(parsed).original));
            } else {
                QString public_error;
                m_package_valid = PublicOnlyPolicy(*parsed, public_error);
                if (!m_package_valid) m_status->setText(public_error);
            }
        }
        if (m_package_valid) m_status->setText(tr("This JSON contains public descriptors and no private keys."));
        if (m_wizard->m_policy_package.isEmpty()) m_status->setText(tr("No valid policy package is available."));
        m_copy_policy->setEnabled(m_package_valid);
        m_save_policy->setEnabled(m_package_valid);
        ack->setEnabled(m_package_valid);
        if (!m_package_valid) ack->setChecked(false);
        Q_EMIT completeChanged();
    }
    MultisigWizard* m_wizard;
    QPushButton* m_copy_policy{nullptr};
    QPushButton* m_save_policy{nullptr};
    QLabel* m_status{nullptr};
    bool m_package_valid{false};
};

class MultisigVerifyPage : public QWizardPage
{
public:
    QLineEdit* address{nullptr};
    QListWidget* devices{nullptr};
    QLabel* status{nullptr};
    QRImageWidget* qr{nullptr};

    explicit MultisigVerifyPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Verify the first address"));
        setSubTitle(tr("Compare this address with what each device displays before the first receive."));
        auto* layout = new QVBoxLayout(this);
        auto* row = new QHBoxLayout;
        qr = new QRImageWidget;
        qr->setObjectName("verifyQr");
        qr->setAlignment(Qt::AlignCenter);
        qr->setFixedSize(168, 168);
        row->addWidget(qr, 0, Qt::AlignTop);

        auto* addr_col = new QVBoxLayout;
        addr_col->addWidget(new QLabel(tr("Receive address")));
        address = new QLineEdit;
        address->setObjectName("verifyAddressEdit");
        address->setReadOnly(true);
        address->setFont(GUIUtil::fixedPitchFont());
        addr_col->addWidget(address);
        auto* copy = new QPushButton(tr("Copy address"));
        copy->setObjectName("copyAddressButton");
        copy->setAutoDefault(false);
        addr_col->addWidget(copy, 0, Qt::AlignLeft);
        addr_col->addStretch();
        row->addLayout(addr_col, 1);
        layout->addLayout(row);

        devices = new QListWidget;
        devices->setObjectName("verifyDeviceList");
        devices->setMaximumHeight(96);
        m_devices_empty = new QLabel(tr("No hardware verification is required for this wallet."));
        m_devices_empty->setWordWrap(true);
        m_devices_empty->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(m_devices_empty);
        layout->addWidget(devices);
        auto* show = new QPushButton(tr("Show on selected device"));
        show->setObjectName("showOnDeviceButton");
        show->setAutoDefault(false);
        layout->addWidget(show, 0, Qt::AlignLeft);
        m_show_button = show;
        status = new QLabel;
        status->setObjectName("verifyStatusLabel");
        status->setWordWrap(true);
        layout->addWidget(status);
        m_airgap_help = new QLabel(tr(
            "Air-gapped keys cannot display here. Import this address into the offline signer and confirm it matches."));
        m_airgap_help->setObjectName("airgapVerifyHelp");
        m_airgap_help->setWordWrap(true);
        m_airgap_help->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(m_airgap_help);
        m_airgap_ack = new QCheckBox(tr("I compared this address on each offline signer."));
        m_airgap_ack->setObjectName("airgapVerifyCheck");
        layout->addWidget(m_airgap_ack);
        layout->addStretch();
        connect(m_airgap_ack, &QCheckBox::toggled, this, &QWizardPage::completeChanged);
        connect(copy, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(address->text());
            status->setText(tr("Address copied."));
        });
        connect(show, &QPushButton::clicked, this, [this] {
            auto* item = devices->currentItem();
            if (!item || !(item->flags() & Qt::ItemIsEnabled)) {
                status->setText(tr("Select a device."));
                return;
            }
            const std::string fpr = item->data(Qt::UserRole).toString().toStdString();
            auto res = m_wizard->verifyOnDevice(fpr);
            if (res) {
                status->setText(tr("Device showed the same address."));
                m_verified_hardware.insert(fpr);
                item->setText(item->data(Qt::UserRole + 1).toString() + tr(" — verified"));
            } else {
                status->setText(QString::fromStdString(util::ErrorString(res).original));
            }
            Q_EMIT completeChanged();
        });
    }
    void initializePage() override
    {
        m_verified_hardware.clear();
        m_address_valid = false;
        QString shown;
        auto dest = m_wizard->firstReceiveAddress();
        if (dest) {
            shown = QString::fromStdString(EncodeDestination(*dest));
            m_address_valid = true;
            address->setText(shown);
        } else {
            shown = m_wizard->m_receive_address;
            const CTxDestination decoded = DecodeDestination(shown.toStdString());
            m_address_valid = !shown.isEmpty() && IsValidDestination(decoded);
            address->setText(m_address_valid ? shown : QString::fromStdString(util::ErrorString(dest).original));
        }
        if (m_address_valid && qr->setQR(shown)) {
            if (GUIUtil::HasPixmap(qr)) {
                qr->setPixmap(qr->pixmap(Qt::ReturnByValue).scaled(168, 168, Qt::KeepAspectRatio, Qt::SmoothTransformation));
            }
            qr->show();
        } else {
            qr->hide();
        }
        devices->clear();
        bool has_airgap = false;
        for (const auto& k : m_wizard->keys()) {
            if (k.xpub) has_airgap = true;
            if (!k.fingerprint || k.xpub) continue;
            const QString item_text = QString::fromStdString(k.label.empty() ? *k.fingerprint : k.label + " (" + *k.fingerprint + ")");
            auto* item = new QListWidgetItem(item_text);
            item->setData(Qt::UserRole, QString::fromStdString(*k.fingerprint));
            item->setData(Qt::UserRole + 1, item_text);
            item->setFlags(item->flags() & ~Qt::ItemIsUserCheckable);
            devices->addItem(item);
        }
        const bool have_hw = devices->count() > 0;
        devices->setVisible(have_hw);
        m_devices_empty->setVisible(!have_hw && !has_airgap);
        if (m_show_button) m_show_button->setVisible(have_hw);
        m_airgap_help->setVisible(has_airgap);
        m_airgap_ack->blockSignals(true);
        m_airgap_ack->setVisible(has_airgap);
        m_airgap_ack->setChecked(false);
        m_airgap_ack->blockSignals(false);
        status->clear();
        Q_EMIT completeChanged();
    }
    bool isComplete() const override
    {
        if (!m_address_valid) return false;
        for (int row = 0; row < devices->count(); ++row) {
            const std::string fingerprint = devices->item(row)->data(Qt::UserRole).toString().toStdString();
            if (!m_verified_hardware.count(fingerprint)) return false;
        }
        bool has_airgap = false;
        for (const auto& k : m_wizard->keys()) {
            if (k.xpub) has_airgap = true;
        }
        if (has_airgap) return m_airgap_ack && m_airgap_ack->isChecked();
        return true;
    }
    bool validatePage() override
    {
        if (!isComplete()) return false;
        m_wizard->publishCreatedWallet();
        return true;
    }
    int nextId() const override { return MultisigWizard::Page_Done; }

private:
    MultisigWizard* m_wizard;
    QPushButton* m_show_button{nullptr};
    QLabel* m_devices_empty{nullptr};
    QLabel* m_airgap_help{nullptr};
    QCheckBox* m_airgap_ack{nullptr};
    std::set<std::string> m_verified_hardware;
    bool m_address_valid{false};
};

class MultisigDonePage : public QWizardPage
{
public:
    explicit MultisigDonePage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Wallet is ready"));
        setSubTitle(tr("Send a small test amount first. Skipping that is an explicit choice, not the default."));
        setFinalPage(true);
        auto* layout = new QVBoxLayout(this);
        m_summary = new QLabel;
        m_summary->setObjectName("doneSummaryLabel");
        m_summary->setWordWrap(true);
        m_summary->setTextFormat(Qt::RichText);
        m_summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(m_summary);
        layout->addStretch();
    }
    void initializePage() override
    {
        const int n_active = m_wizard->nActiveKeys();
        const int n = static_cast<int>(m_wizard->keys().size());
        const bool vault = m_wizard->outputType() == OutputType::BECH32M &&
                           (m_wizard->fallbackOlder() || m_wizard->fallbackAfter());
        QString extra;
        if (vault) {
            if (const auto older = m_wizard->fallbackOlder()) {
                if (const auto final = m_wizard->fallbackOlderOneKey()) {
                    extra = tr("<p>This is a <b>staged Scrooge vault</b>. After <b>%1</b> (%2), %3 of %4 recovery keys can spend. "
                               "After <b>%5</b> (%6), any 1 recovery key can spend. Both paths remain available.</p>")
                                .arg(BlockCount(*older)).arg(ApproxDuration(*older))
                                .arg(m_wizard->nrequired()).arg(n)
                                .arg(BlockCount(*final)).arg(ApproxDuration(*final));
                } else {
                    extra = tr("<p>This is a <b>Scrooge vault</b>. After <b>%1</b> (%2), %3 of %4 can recover without the missing keys.</p>")
                                .arg(BlockCount(*older))
                                .arg(ApproxDuration(*older))
                                .arg(m_wizard->nrequired())
                                .arg(n);
                }
            } else if (const auto after = m_wizard->fallbackAfter()) {
                extra = tr("<p>This is a <b>Scrooge vault</b>. At block height <b>%1</b>, %2 of %3 can recover. Coins received after that height may already be recoverable.</p>")
                            .arg(FormattedHeight(*after))
                            .arg(m_wizard->nrequired())
                            .arg(n);
            }
        }
        if (!m_wizard->m_policy_id.isEmpty()) {
            extra += tr("<p>Policy ID: <code>%1</code></p>").arg(m_wizard->m_policy_id.toHtmlEscaped());
        }
        const QString lead = vault
            ? tr("<p>The <b>%1</b> wallet requires <b>all %2 active keys</b> to spend immediately. "
                 "First recovery is <b>%3 of %4</b> after its delay.</p>")
                  .arg(m_wizard->walletName().toHtmlEscaped())
                  .arg(n_active)
                  .arg(m_wizard->nrequired())
                  .arg(n)
            : tr("<p>The <b>%1</b> wallet is ordinary <b>%2 of %3</b> multisig. There is no delayed recovery path.</p>")
                  .arg(m_wizard->walletName().toHtmlEscaped())
                  .arg(m_wizard->nrequired())
                  .arg(n);
        const QString send_item = vault
            ? tr("<li><b>Send</b> — Immediate spends need every active signer. Recovery is an explicit choice after the delay.</li>")
            : tr("<li><b>Send</b> — Needs %1 of %2 signatures.</li>").arg(m_wizard->nrequired()).arg(n);
        m_summary->setText(
            lead + extra +
            tr("<ul>"
               "<li><b>Test deposit</b> — Receive a small amount and confirm it arrived before moving a main balance.</li>"
               "<li><b>Receive</b> — The first address was checked during setup. Repeat your normal signer check for later addresses.</li>"
               "%1"
               "</ul>")
                .arg(send_item));
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
    setWindowTitle(tr("Create Vault Wallet"));
    // Fusion reports ClassicStyle (qfusionstyle.cpp SH_WizardStyle). Keep it:
    // header with title+subtitle, bottom ruler, Cancel visible. MacStyle is the
    // macOS setup-assistant look and leaves a 181px empty left column without a
    // BackgroundPixmap (third_party/qtbase/.../qwizard.cpp recreateLayout).
    setWizardStyle(QWizard::ClassicStyle);
#ifdef Q_OS_MACOS
    // Qt 6.11 queries the macOS setup-assistant image even for ClassicStyle;
    // seed an unused pixmap so offscreen tests do not dereference a nil bundle.
    QPixmap background(1, 1);
    background.fill(Qt::transparent);
    setPixmap(QWizard::BackgroundPixmap, background);
#endif
    setOption(QWizard::NoBackButtonOnStartPage, true);
    setOption(QWizard::NoCancelButtonOnLastPage, true);
    setOption(QWizard::ExtendedWatermarkPixmap, true);
    setButtonLayout({QWizard::BackButton, QWizard::Stretch,
                     QWizard::CancelButton, QWizard::NextButton, QWizard::CommitButton, QWizard::FinishButton});
    setButtonText(QWizard::BackButton, tr("Back"));
    setButtonText(QWizard::NextButton, tr("Continue"));
    setButtonText(QWizard::CommitButton, tr("Create wallet"));
    setButtonText(QWizard::FinishButton, tr("Done"));
    setButtonText(QWizard::CancelButton, tr("Cancel"));
    setMinimumSize(900, 620);
    auto* nav = new StepNav(this);
    setSideWidget(nav);
    connect(this, &QWizard::currentIdChanged, nav, &StepNav::setCurrent);

    setPage(Page_Intro, new MultisigIntroPage(this));
    setPage(Page_Template, new MultisigTemplatePage(this));
    setPage(Page_Setup, new MultisigSetupPage(this));
    setPage(Page_Keys, new MultisigKeysPage(this));
    setPage(Page_Threshold, new MultisigThresholdPage(this));
    setPage(Page_Backup, new MultisigBackupPage(this));
    setPage(Page_Verify, new MultisigVerifyPage(this));
    setPage(Page_Done, new MultisigDonePage(this));
    setStartId(Page_Intro);
}

void MultisigWizard::lockCommittedJourney()
{
    m_setup_committed = true;
    setOption(QWizard::NoCancelButton, true);
    setButtonLayout({QWizard::BackButton, QWizard::Stretch,
                     QWizard::NextButton, QWizard::CommitButton, QWizard::FinishButton});
}

void MultisigWizard::publishCreatedWallet()
{
    if (m_created_emitted || !m_wallet_model) return;
    m_created_emitted = true;
    Q_EMIT created(m_wallet_model);
}

void MultisigWizard::reject()
{
    if (m_setup_committed && currentId() != Page_Done) {
        QMessageBox::warning(this, tr("Finish vault setup"),
                             tr("The wallet has already been created. Save its policy JSON and verify the first address before closing."));
        return;
    }
    QWizard::reject();
}

void MultisigWizard::closeEvent(QCloseEvent* event)
{
    if (m_setup_committed && currentId() != Page_Done) {
        event->ignore();
        QMessageBox::warning(this, tr("Finish vault setup"),
                             tr("The wallet has already been created. Save its policy JSON and verify the first address before closing."));
        return;
    }
    QWizard::closeEvent(event);
}

void MultisigWizard::setWalletName(const QString& name) { m_wallet_name = name; }
void MultisigWizard::setIncludeLocalKey(bool include)
{
    m_include_local = include;
    refreshSidebar();
}
void MultisigWizard::setOutputType(OutputType type)
{
    m_type = type;
    if (type != OutputType::BECH32M) {
        for (auto& key : m_airgapped) key.recovery_only = false;
        m_last_airgap_recovery_only = false;
        m_fallback_older_one_key.reset();
    }
    refreshSidebar();
}
void MultisigWizard::setNRequired(int n)
{
    m_nrequired = n;
    refreshSidebar();
}
void MultisigWizard::setFallbackOlder(std::optional<uint32_t> blocks)
{
    m_fallback_older = blocks;
    if (!blocks) m_fallback_older_one_key.reset();
    refreshSidebar();
}
void MultisigWizard::setFallbackOlderOneKey(std::optional<uint32_t> blocks)
{
    m_fallback_older_one_key = blocks;
    refreshSidebar();
}
void MultisigWizard::setFallbackAfter(std::optional<uint32_t> height)
{
    m_fallback_after = height;
    if (height) m_fallback_older_one_key.reset();
    refreshSidebar();
}
void MultisigWizard::setVaultTemplate(VaultTemplate tmpl) { m_template = tmpl; }

void MultisigWizard::refreshSidebar()
{
    if (auto* nav = sideWidget()) static_cast<StepNav*>(nav)->refreshPolicy();
}

void MultisigWizard::applyTemplate()
{
    if (m_template != VaultTemplate::Custom) {
        for (auto& key : m_airgapped) key.recovery_only = false;
        m_last_airgap_recovery_only = false;
    }
    switch (m_template) {
    case VaultTemplate::RecoverOneLost:
        m_type = OutputType::BECH32M;
        m_include_local = true;
        m_fallback_older = kDefaultVaultDelay;
        m_fallback_older_one_key.reset();
        m_fallback_after.reset();
        m_prefer_n_minus_1 = true;
        m_last_airgap_recovery_only = false;
        break;
    case VaultTemplate::StagedRecovery:
        m_type = OutputType::BECH32M;
        m_include_local = true;
        m_fallback_older = kThirtyDayVaultDelay;
        m_fallback_older_one_key = kSixtyDayVaultDelay;
        m_fallback_after.reset();
        m_prefer_n_minus_1 = false;
        m_nrequired = 2;
        m_last_airgap_recovery_only = false;
        break;
    case VaultTemplate::Maximum:
        m_type = OutputType::BECH32M;
        m_fallback_older.reset();
        m_fallback_older_one_key.reset();
        m_fallback_after.reset();
        m_prefer_n_minus_1 = false;
        m_nrequired = std::max(2, static_cast<int>(m_keys.size()));
        break;
    case VaultTemplate::HardwareCoordinator:
        m_type = OutputType::BECH32M;
        m_include_local = false;
        m_fallback_older = kDefaultVaultDelay;
        m_fallback_older_one_key.reset();
        m_fallback_after.reset();
        m_prefer_n_minus_1 = true;
        break;
    case VaultTemplate::Inheritance:
        m_type = OutputType::BECH32M;
        m_last_airgap_recovery_only = true;
        if (!m_airgapped.empty()) m_airgapped.back().recovery_only = true;
        m_fallback_older = kDefaultVaultDelay;
        m_fallback_older_one_key.reset();
        m_fallback_after.reset();
        m_prefer_n_minus_1 = true;
        break;
    case VaultTemplate::Custom:
        m_prefer_n_minus_1 = false;
        if (!m_airgapped.empty()) m_last_airgap_recovery_only = m_airgapped.back().recovery_only;
        break;
    }
    rebuildKeyList();
    refreshSidebar();
}

void MultisigWizard::addHardwareKey(const std::string& fingerprint, const std::string& label)
{
    for (auto& k : m_hardware) {
        if (k.fingerprint && *k.fingerprint == fingerprint) {
            k.label = label;
            refreshSidebar();
            return;
        }
    }
    MultisigKeySpec spec;
    spec.fingerprint = fingerprint;
    spec.label = label;
    m_hardware.push_back(std::move(spec));
    refreshSidebar();
}

void MultisigWizard::addAirgappedKey(const std::string& fingerprint, const std::string& path, const std::string& xpub, const std::string& label, bool recovery_only)
{
    if (m_template == VaultTemplate::Inheritance) {
        for (auto& key : m_airgapped) key.recovery_only = false;
    }
    MultisigKeySpec spec;
    spec.fingerprint = fingerprint;
    if (!path.empty()) spec.path = path;
    spec.xpub = xpub;
    spec.label = label.empty() ? "air-gapped" : label;
    spec.recovery_only = m_template == VaultTemplate::Inheritance
        ? recovery_only
        : recovery_only || (m_airgapped.empty() && m_last_airgap_recovery_only);
    m_airgapped.push_back(std::move(spec));
    m_last_airgap_recovery_only = m_airgapped.back().recovery_only;
    refreshSidebar();
}

int MultisigWizard::nActiveKeys() const
{
    return static_cast<int>(std::count_if(m_keys.begin(), m_keys.end(), [](const wallet::MultisigKeySpec& k) { return !k.recovery_only; }));
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
        m_public_descs,
        m_fallback_older,
        m_fallback_after,
        m_fallback_older_one_key));
}

bilingual_str MultisigWizard::policyError() const
{
    const size_t n_active = static_cast<size_t>(std::count_if(m_keys.begin(), m_keys.end(), [](const MultisigKeySpec& k) { return !k.recovery_only; }));
    return wallet::ValidateMultisigPolicy(m_nrequired, n_active, m_type, m_fallback_older, m_fallback_after, m_keys.size(), m_fallback_older_one_key);
}

bool MultisigWizard::createWallet()
{
    m_create_error.clear();
    m_wallet_model = nullptr;
    m_public_descs.clear();
    m_policy_id.clear();
    m_policy_package.clear();
    rebuildKeyList();
    if (const auto err = policyError(); !err.empty()) {
        m_create_error = QString::fromStdString(err.translated);
        return false;
    }
    if (!m_wallet_controller) {
        m_create_error = tr("The GUI wallet controller is not available.");
        return false;
    }

    const bool has_device = std::any_of(m_keys.begin(), m_keys.end(), [](const MultisigKeySpec& k) {
        return k.fingerprint.has_value() && !k.xpub;
    });
    uint64_t flags = WALLET_FLAG_DESCRIPTORS;
    if (has_device) flags |= WALLET_FLAG_EXTERNAL_SIGNER;
    if (!m_include_local) flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET;

    try {
        // Resolve and validate every public signer before creating a persistent
        // wallet. A malformed paste or disconnected device must not strand an
        // empty wallet with the requested name.
        const std::string default_path = wallet::DefaultMultisigPath(m_type, 0);
        std::vector<interfaces::Wallet::MultisigKey> iface_keys;
        iface_keys.reserve(m_keys.size());
        for (const auto& k : m_keys) {
            interfaces::Wallet::MultisigKey resolved{k.path, k.fingerprint, k.hdkey, k.xpub, k.recovery_only};
            const std::string path = k.path.value_or(default_path);
            std::vector<uint32_t> parsed_path;
            if (!ParseHDKeypath(path, parsed_path)) {
                m_create_error = tr("Derivation path is not a valid BIP32 path.");
                return false;
            }
            if (std::none_of(parsed_path.begin(), parsed_path.end(), [](uint32_t step) {
                    return (step & BIP32_HARDENED_FLAG) != 0;
                })) {
                m_create_error = tr("Derivation path needs at least one hardened step.");
                return false;
            }
            if (k.xpub) {
                const QString input_error = ValidatePublicKeyInput(k.fingerprint.value_or(""), path, *k.xpub);
                if (!input_error.isEmpty()) {
                    m_create_error = input_error;
                    return false;
                }
            } else if (k.fingerprint) {
                if (k.fingerprint->size() != 8 || !IsHex(*k.fingerprint)) {
                    m_create_error = tr("Fingerprint must be exactly 8 hexadecimal characters.");
                    return false;
                }
                auto signer = wallet::ExternalSignerScriptPubKeyMan::GetExternalSigner(*k.fingerprint);
                if (!signer) {
                    m_create_error = QString::fromStdString(util::ErrorString(signer).original);
                    return false;
                }
                const UniValue result = signer->GetXpub(path);
                if (!result.exists("xpub") || !result["xpub"].isStr()) {
                    m_create_error = tr("Signer getxpub did not return an xpub.");
                    return false;
                }
                const std::string fetched = result["xpub"].get_str();
                if (!DecodeExtPubKey(fetched).pubkey.IsValid()) {
                    m_create_error = tr("Signer returned an invalid xpub.");
                    return false;
                }
                resolved.xpub = fetched;
            }
            iface_keys.push_back(std::move(resolved));
        }

        std::vector<bilingual_str> warnings;
        auto created = m_node.walletLoader().createWallet(m_wallet_name.toStdString(), SecureString{}, flags, warnings);
        if (!created) {
            m_create_error = QString::fromStdString(util::ErrorString(created).translated);
            return false;
        }
        WalletModel* const wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*created));

        auto imported = wallet_model->wallet().createMultisigDescriptor(m_nrequired, iface_keys, m_type, m_fallback_older, m_fallback_after, m_fallback_older_one_key);
        if (!imported) {
            m_create_error = QString::fromStdString(util::ErrorString(imported).original);
            return false;
        }
        if (imported->size() != 2) {
            m_create_error = tr("Wallet creation did not produce one receive descriptor and one change descriptor.");
            return false;
        }
        wallet::VaultPolicyPackage package;
        package.network = Params().GetChainTypeString();
        package.nrequired = m_nrequired;
        package.fallback_older = m_fallback_older;
        package.fallback_after = m_fallback_after;
        package.fallback_older_one_key = m_fallback_older_one_key;
        if (m_fallback_older || m_fallback_after) {
            package.recovery_stages.push_back({m_nrequired, m_fallback_older, m_fallback_after});
            if (m_fallback_older_one_key) {
                package.recovery_stages.push_back({1, m_fallback_older_one_key, {}});
            }
        }
        package.descs = *imported;
        package.policy_id = wallet::VaultPolicyId(package.descs.front());
        const QString policy_package = QString::fromStdString(wallet::FormatVaultPolicyPackage(package));
        auto parsed_package = wallet::ParseVaultPolicyPackage(policy_package.toStdString());
        if (!parsed_package) {
            m_create_error = QString::fromStdString(util::ErrorString(parsed_package).original);
            return false;
        }
        QString public_error;
        if (!PublicOnlyPolicy(*parsed_package, public_error)) {
            m_create_error = public_error;
            return false;
        }
        m_public_descs = *imported;
        if (!m_public_descs.empty()) m_policy_id = QString::fromStdString(wallet::VaultPolicyId(m_public_descs.front()));
        m_policy_package = policy_package;
        m_wallet_model = wallet_model;
        return true;
    } catch (const std::exception& e) {
        m_create_error = QString::fromStdString(e.what());
        return false;
    }
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
    auto displayed = m_wallet_model->wallet().displayAddress(dest, fingerprint);
    if (displayed || m_public_descs.empty()) return displayed;

    // The wallet display path currently infers a descriptor from the concrete
    // script. For an n-of-n MuSig2 key path that can lose the participant key
    // origins, so retry with the original public receive descriptor. The signer
    // must still echo the exact address the wizard is showing.
    auto signer = wallet::ExternalSignerScriptPubKeyMan::GetExternalSigner(std::optional<std::string>{fingerprint});
    if (!signer) return util::Error{Untranslated(util::ErrorString(signer).original)};
    try {
        const UniValue result = signer->DisplayAddress(m_public_descs.front());
        const UniValue& error = result.find_value("error");
        if (error.isStr()) {
            return util::Error{Untranslated("Signer returned error: " + error.getValStr())};
        }
        const UniValue& shown = result.find_value("address");
        if (!shown.isStr()) {
            return util::Error{Untranslated("Signer did not echo an address")};
        }
        if (shown.getValStr() != EncodeDestination(dest)) {
            return util::Error{Untranslated("Signer displayed a different address")};
        }
        return {};
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}
