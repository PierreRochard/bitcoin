// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/multisigwizard.h>

#include <addresstype.h>
#include <chainparams.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <node/context.h>
#include <key_io.h>
#include <qt/guiutil.h>
#include <qt/qrimagewidget.h>
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
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPalette>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSizePolicy>
#include <QSpinBox>
#include <QVBoxLayout>
#include <QWizardPage>

using wallet::MultisigKeySpec;
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

// Vertical step list shown as QWizard::sideWidget. ClassicStyle +
// ExtendedWatermarkPixmap (qwizard.cpp) paints this as a full-height column
// next to the page and the Back/Continue row — Fusion's native wizard chrome,
// not MacStyle (which reserves a 181px empty gutter and hides Cancel when it
// is the default SH_WizardStyle).
class StepNav : public QFrame
{
public:
    explicit StepNav(QWidget* parent = nullptr) : QFrame(parent)
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
            tr("Intro"), tr("Name"), tr("Keys"), tr("Policy"),
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
        m_policy->setWordWrap(true);
        m_policy->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
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
        if (auto* wiz = qobject_cast<MultisigWizard*>(window())) {
            wiz->rebuildKeyList();
            const int n = static_cast<int>(wiz->keys().size());
            if (n >= 2) {
                m_policy->setText(tr("%1 of %2 keys").arg(wiz->nrequired()).arg(n));
            } else {
                m_policy->clear();
            }
        }
    }

private:
    std::vector<QLabel*> m_dots;
    std::vector<QLabel*> m_names;
    QLabel* m_policy{nullptr};
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
    explicit MultisigIntroPage(MultisigWizard* wizard) : QWizardPage(wizard)
    {
        setTitle(tr("Create a multisig wallet"));
        setSubTitle(tr("Several keys together, like a vault. Spending needs more than one signature."));
        auto* layout = new QVBoxLayout(this);
        layout->setSpacing(10);
        layout->addWidget(MakeTitledCard(
            tr("2 of 3 — typical vault"),
            tr("This computer plus two hardware wallets. One key lost still spends; a thief needs two. "
               "Sparrow and BlueWallet use this as the default.")));
        layout->addWidget(MakeTitledCard(
            tr("Taproot vault"),
            tr("Every key spends immediately as one MuSig2 signature. After a delay, fewer keys can recover "
               "the coins (bitcoin#24861).")));
        layout->addWidget(MakeTitledCard(
            tr("Air-gapped keys"),
            tr("Paste an xpub now. Sign later with a PSBT file — the device never has to be plugged in here.")));
        auto* next = new QLabel(tr("Next: name the wallet, add every key, choose the threshold, save a public backup, then verify the first address on hardware."));
        next->setWordWrap(true);
        next->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
        layout->addWidget(next);
        layout->addStretch();
    }
    int nextId() const override { return MultisigWizard::Page_Setup; }
};

class MultisigSetupPage : public QWizardPage
{
public:
    QLineEdit* name{nullptr};
    QComboBox* type{nullptr};

    explicit MultisigSetupPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Name and address type"));
        setSubTitle(tr("P2WSH works on every device today. Taproot is n-of-n MuSig2 immediately, with an optional delayed recovery path."));
        auto* layout = new QVBoxLayout(this);
        auto* form = new QFormLayout;
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        name = new QLineEdit;
        name->setObjectName("walletNameEdit");
        name->setText(wizard->walletName());
        name->setPlaceholderText(tr("Family vault"));
        type = new QComboBox;
        type->setObjectName("scriptTypeCombo");
        type->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        type->setMinimumContentsLength(32);
        type->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
        type->addItem(tr("Native SegWit (P2WSH)"), QVariant::fromValue(static_cast<int>(OutputType::BECH32)));
        type->addItem(tr("Taproot vault (MuSig2 + recovery)"), QVariant::fromValue(static_cast<int>(OutputType::BECH32M)));
        type->addItem(tr("Nested SegWit (P2SH-P2WSH)"), QVariant::fromValue(static_cast<int>(OutputType::P2SH_SEGWIT)));
        type->addItem(tr("Legacy (P2SH)"), QVariant::fromValue(static_cast<int>(OutputType::LEGACY)));
        form->addRow(tr("Wallet name"), name);
        form->addRow(tr("Script type"), type);
        layout->addLayout(form);
        m_hint = new QLabel;
        m_hint->setWordWrap(true);
        m_hint->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
        layout->addWidget(m_hint);
        layout->addStretch();
        connect(name, &QLineEdit::textChanged, this, &QWizardPage::completeChanged);
        connect(type, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] { updateHint(); });
        registerField("walletName*", name);
        updateHint();
    }
    void initializePage() override
    {
        name->setText(m_wizard->walletName());
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
        m_hint->setText(taproot
                            ? tr("Taproot vault: every key signs as one on-chain signature. After the recovery delay, "
                                 "the threshold you pick on the next pages can spend without the missing keys.")
                            : tr("Native SegWit is a wsh(sortedmulti) descriptor. Hardware that cannot do Taproot still works."));
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
        hw_empty = new QLabel(tr("No devices found. Connect a signer or set -signer=internal, or add an xpub below."));
        hw_empty->setObjectName("hardwareEmptyLabel");
        hw_empty->setWordWrap(true);
        hw_empty->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
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
        m_count->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
        layout->addWidget(m_count);

        connect(local, &QCheckBox::toggled, this, [this](bool checked) {
            m_wizard->setIncludeLocalKey(checked);
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
            populateAirgapped();
            updateCount();
            Q_EMIT completeChanged();
        });
    }
    void initializePage() override
    {
        local->setChecked(m_wizard->includeLocalKey());
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
                                 tr("A multisig wallet needs at least two keys. Add a hardware device, an xpub, or keep the key on this computer."));
            return false;
        }
        return true;
    }
    int nextId() const override { return MultisigWizard::Page_Threshold; }

private:
    void updateCount()
    {
        m_wizard->rebuildKeyList();
        const int n = static_cast<int>(m_wizard->keys().size());
        if (n < 2) {
            m_count->setText(tr("%1 key so far — add at least two.").arg(n));
        } else {
            m_count->setText(tr("%1 keys in this vault.").arg(n));
        }
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
                hw_empty->setText(tr("No devices found. Connect a signer or set -signer=internal, or add an xpub below."));
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
    QLabel* delay_label{nullptr};
    QLabel* delay_hint{nullptr};
    QLabel* sentence{nullptr};
    QLabel* headline{nullptr};

    explicit MultisigThresholdPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("How many signatures to spend?"));
        setSubTitle(tr("2 of 3 is the usual vault: one key lost still spends; a thief needs two."));
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
        form->addRow(tr("Required signatures"), required);
        delay = new QSpinBox;
        delay->setObjectName("fallbackOlderSpin");
        delay->setMinimum(0);
        delay->setMaximum((1 << 30) - 1);
        delay->setSpecialValueText(tr("Off"));
        delay->setMinimumWidth(120);
        delay->setSuffix(QStringLiteral(" ") + tr("blocks"));
        form->addRow(tr("Recovery delay"), delay);
        delay_label = qobject_cast<QLabel*>(form->labelForField(delay));
        layout->addLayout(form);
        layout->addSpacing(6);
        delay_hint = new QLabel;
        delay_hint->setWordWrap(true);
        delay_hint->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
        layout->addWidget(delay_hint);

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
            m_wizard->setFallbackOlder(v > 0 ? std::optional<uint32_t>{static_cast<uint32_t>(v)} : std::nullopt);
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
        const bool taproot = m_wizard->outputType() == OutputType::BECH32M;
        delay->setVisible(taproot);
        delay_label->setVisible(taproot);
        delay_hint->setVisible(taproot);
        if (taproot) {
            const int cur = m_wizard->fallbackOlder() ? static_cast<int>(*m_wizard->fallbackOlder()) : 144;
            delay->setValue(cur);
            m_wizard->setFallbackOlder(cur > 0 ? std::optional<uint32_t>{static_cast<uint32_t>(cur)} : std::nullopt);
        } else {
            delay->setValue(0);
            m_wizard->setFallbackOlder(std::nullopt);
        }
        updateSentence();
    }
    bool isComplete() const override
    {
        return wallet::ValidateMultisigPolicy(m_wizard->nrequired(), m_wizard->keys().size(),
                                              m_wizard->outputType(), m_wizard->fallbackOlder()).empty();
    }
    int nextId() const override { return MultisigWizard::Page_Backup; }

private:
    void updateSentence()
    {
        const int n = static_cast<int>(m_wizard->keys().size());
        headline->setText(tr("%1 of %2").arg(m_wizard->nrequired()).arg(n));
        QString extra = tr("Write this down. Changing the threshold later means a new wallet and moving funds.");
        if (m_wizard->outputType() == OutputType::BECH32M) {
            if (m_wizard->fallbackOlder()) {
                extra = tr("Immediately every key signs as one MuSig2 signature. After %1 blocks (%2), %3 of %4 can recover.")
                            .arg(*m_wizard->fallbackOlder())
                            .arg(ApproxDuration(*m_wizard->fallbackOlder()))
                            .arg(m_wizard->nrequired())
                            .arg(n);
                delay_hint->setText(tr("BIP 68 relative lock time. 144 blocks ≈ 1 day, 1008 ≈ 1 week, 4320 ≈ 1 month."));
            } else if (m_wizard->nrequired() == n && n >= 2) {
                extra = tr("Taproot n-of-n spends as one MuSig2 signature (BIP 327). Every key still has to participate.");
                delay_hint->setText(tr("Set a recovery delay to allow fewer keys to spend after that many blocks."));
            } else {
                extra = tr("Taproot m-of-n uses an unspendable key-path and a sortedmulti_a script path (BIP 387).");
                delay_hint->setText(tr("A recovery delay wraps this as tr(musig, and_v(older, multi_a))."));
            }
        }
        sentence->setText(extra);
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
        auto* warn = new QLabel(tr(
            "If this computer is lost and you do not have this file, the coins cannot be recovered even with the hardware devices. "
            "Store a copy offline."));
        warn->setWordWrap(true);
        layout->addWidget(warn);
        text = new QPlainTextEdit;
        text->setObjectName("transcriptEdit");
        text->setReadOnly(true);
        text->setFont(GUIUtil::fixedPitchFont());
        text->setLineWrapMode(QPlainTextEdit::NoWrap);
        layout->addWidget(text);
        auto* btns = new QHBoxLayout;
        auto* copy = new QPushButton(tr("Copy"));
        copy->setAutoDefault(false);
        auto* save = new QPushButton(tr("Save to file…"));
        save->setAutoDefault(false);
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
        if (m_wizard->createdWallet()) return true;
        if (!m_wizard->createWallet()) {
            // Tests and screenshot grabs construct the wizard without a WalletController.
            if (!m_wizard->m_wallet_controller) return true;
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
    QRImageWidget* qr{nullptr};

    explicit MultisigVerifyPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Verify the first address"));
        setSubTitle(tr("Compare this address with what each device displays. Specter and Sparrow do this before the first receive."));
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
        m_devices_empty = new QLabel(tr("No connected hardware in this vault. Skip this step."));
        m_devices_empty->setWordWrap(true);
        m_devices_empty->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
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
        auto* air = new QLabel(tr(
            "Air-gapped keys cannot display here. Import this address into the offline signer and confirm it matches."));
        air->setWordWrap(true);
        air->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
        layout->addWidget(air);
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
                item->setCheckState(Qt::Checked);
            } else {
                status->setText(QString::fromStdString(util::ErrorString(res).original));
            }
            Q_EMIT completeChanged();
        });
    }
    void initializePage() override
    {
        QString shown;
        auto dest = m_wizard->firstReceiveAddress();
        if (dest) {
            shown = QString::fromStdString(EncodeDestination(*dest));
            address->setText(shown);
        } else {
            shown = m_wizard->m_receive_address;
            address->setText(shown.isEmpty() ? QString::fromStdString(util::ErrorString(dest).original) : shown);
        }
        if (!shown.isEmpty() && qr->setQR(shown)) {
            if (GUIUtil::HasPixmap(qr)) {
                qr->setPixmap(qr->pixmap(Qt::ReturnByValue).scaled(168, 168, Qt::KeepAspectRatio, Qt::SmoothTransformation));
            }
            qr->show();
        } else {
            qr->hide();
        }
        devices->clear();
        for (const auto& k : m_wizard->keys()) {
            if (!k.fingerprint || k.xpub) continue;
            auto* item = new QListWidgetItem(QString::fromStdString(k.label.empty() ? *k.fingerprint : k.label + " (" + *k.fingerprint + ")"));
            item->setData(Qt::UserRole, QString::fromStdString(*k.fingerprint));
            item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
            item->setCheckState(Qt::Unchecked);
            devices->addItem(item);
        }
        const bool have_hw = devices->count() > 0;
        devices->setVisible(have_hw);
        m_devices_empty->setVisible(!have_hw);
        if (m_show_button) m_show_button->setVisible(have_hw);
        status->clear();
    }
    bool isComplete() const override { return true; }
    int nextId() const override { return MultisigWizard::Page_Done; }

private:
    MultisigWizard* m_wizard;
    QPushButton* m_show_button{nullptr};
    QLabel* m_devices_empty{nullptr};
};

class MultisigDonePage : public QWizardPage
{
public:
    explicit MultisigDonePage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Wallet is ready"));
        setSubTitle(tr("The vault is on this node. Receive, then co-sign spends with every required key."));
        setFinalPage(true);
        auto* layout = new QVBoxLayout(this);
        m_summary = new QLabel;
        m_summary->setWordWrap(true);
        m_summary->setTextFormat(Qt::RichText);
        m_summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(m_summary);
        layout->addStretch();
    }
    void initializePage() override
    {
        QString extra;
        if (const auto older = m_wizard->fallbackOlder()) {
            extra = tr("<p>After <b>%1 blocks</b> (%2), %3 of %4 can recover without the missing keys.</p>")
                        .arg(*older)
                        .arg(ApproxDuration(*older))
                        .arg(m_wizard->nrequired())
                        .arg(m_wizard->keys().size());
        }
        m_summary->setText(
            tr("<p>The <b>%1</b> wallet is a <b>%2 of %3</b> vault.</p>"
               "%4"
               "<ul>"
               "<li><b>Receive</b> — Request payment. Use Verify on hardware when you can.</li>"
               "<li><b>Send</b> — Core signs with any local keys, then connected hardware. "
               "If signatures are still missing, save the PSBT and take it to an air-gapped signer.</li>"
               "<li><b>File → Load PSBT</b> to bring a signed transaction back.</li>"
               "</ul>")
                .arg(m_wizard->walletName().toHtmlEscaped())
                .arg(m_wizard->nrequired())
                .arg(m_wizard->keys().size())
                .arg(extra));
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
    // Fusion reports ClassicStyle (qfusionstyle.cpp SH_WizardStyle). Keep it:
    // header with title+subtitle, bottom ruler, Cancel visible. MacStyle is the
    // macOS setup-assistant look and leaves a 181px empty left column without a
    // BackgroundPixmap (third_party/qtbase/.../qwizard.cpp recreateLayout).
    setWizardStyle(QWizard::ClassicStyle);
    setOption(QWizard::NoBackButtonOnStartPage, true);
    setOption(QWizard::NoCancelButtonOnLastPage, true);
    setOption(QWizard::ExtendedWatermarkPixmap, true);
    setButtonLayout({QWizard::BackButton, QWizard::Stretch,
                     QWizard::CancelButton, QWizard::NextButton, QWizard::FinishButton});
    setButtonText(QWizard::BackButton, tr("Back"));
    setButtonText(QWizard::NextButton, tr("Continue"));
    setButtonText(QWizard::FinishButton, tr("Done"));
    setButtonText(QWizard::CancelButton, tr("Cancel"));
    setMinimumSize(900, 620);
    auto* nav = new StepNav;
    setSideWidget(nav);
    connect(this, &QWizard::currentIdChanged, nav, &StepNav::setCurrent);

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
void MultisigWizard::setFallbackOlder(std::optional<uint32_t> blocks) { m_fallback_older = blocks; }

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
        m_public_descs,
        m_fallback_older));
}

bilingual_str MultisigWizard::policyError() const
{
    return wallet::ValidateMultisigPolicy(m_nrequired, m_keys.size(), m_type, m_fallback_older);
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
    if (!m_wallet_controller) {
        m_create_error = tr("Wallet created but the GUI could not attach it.");
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
    m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*created));

    std::vector<interfaces::Wallet::MultisigKey> iface_keys;
    iface_keys.reserve(m_keys.size());
    for (const auto& k : m_keys) {
        iface_keys.push_back({k.path, k.fingerprint, k.hdkey, k.xpub});
    }
    auto imported = m_wallet_model->wallet().createMultisigDescriptor(m_nrequired, iface_keys, m_type, m_fallback_older);
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
