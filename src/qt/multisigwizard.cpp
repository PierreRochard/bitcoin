// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <qt/multisigwizard.h>

#include <addresstype.h>
#include <chainparams.h>
#include <common/args.h>
#include <crypto/sha256.h>
#include <external_signer.h>
#include <interfaces/external_signer.h>
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
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/bip32.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/bip39.h>
#include <wallet/vault_policy_qr.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <array>
#include <memory>
#include <set>

#include <QAbstractItemView>
#include <QButtonGroup>
#include <QBuffer>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QKeyEvent>
#include <QLineEdit>
#include <QListWidget>
#include <QLockFile>
#include <QLocale>
#include <QMessageBox>
#include <QPageLayout>
#include <QPageSize>
#include <QPalette>
#include <QPainter>
#ifndef QT_NO_PDF
#include <QPdfWriter>
#endif
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QSaveFile>
#include <QSizePolicy>
#include <QSpinBox>
#include <QTabWidget>
#include <QTemporaryFile>
#include <QTextDocument>
#include <QTimer>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>
#include <QWizardPage>

using wallet::MultisigKeySpec;
using wallet::WALLET_FLAG_BLANK_WALLET;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WALLET_FLAG_EXTERNAL_SIGNER;

namespace {
/** Secret mnemonic entry whose persistent backing store is cleansing locked
 * memory. It intentionally offers no clipboard or context-menu path and never
 * mirrors plaintext into a QString/QLineEdit property. */
class SecureMnemonicEdit final : public QFrame
{
public:
    explicit SecureMnemonicEdit(QWidget* parent = nullptr) : QFrame(parent)
    {
        setFrameShape(QFrame::StyledPanel);
        setFrameShadow(QFrame::Sunken);
        setFocusPolicy(Qt::StrongFocus);
        setContextMenuPolicy(Qt::NoContextMenu);
        setMinimumHeight(fontMetrics().height() + 18);
        setProperty("secureMnemonicBacking", true);
        setAccessibleDescription(tr("Secret phrase entry. Plaintext is held only in cleansing locked memory; the screen shows only a word count."));
    }

    ~SecureMnemonicEdit() override { clearSecure(); }

    bool trimmedEmpty() const
    {
        return std::ranges::all_of(m_value, [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; });
    }

    SecureString takeTrimmed()
    {
        while (!m_value.empty() && IsSpace(m_value.front())) m_value.erase(m_value.begin());
        while (!m_value.empty() && IsSpace(m_value.back())) m_value.pop_back();
        SecureString result;
        result.swap(m_value);
        update();
        return result;
    }

    void restoreSecure(SecureString value)
    {
        clearSecure();
        m_value = std::move(value);
        update();
    }

    void clearSecure()
    {
        if (!m_value.empty()) memory_cleanse(m_value.data(), m_value.size());
        SecureString{}.swap(m_value);
        update();
    }

protected:
    void keyPressEvent(QKeyEvent* event) override
    {
        if (event->matches(QKeySequence::Paste) || event->matches(QKeySequence::Copy) ||
            event->matches(QKeySequence::Cut)) {
            event->accept();
            return;
        }
        if (event->key() == Qt::Key_Backspace) {
            if (!m_value.empty()) {
                m_value.back() = 0;
                m_value.pop_back();
                update();
            }
            event->accept();
            return;
        }
        if (event->key() == Qt::Key_Delete) {
            clearSecure();
            event->accept();
            return;
        }
        QByteArray typed{event->text().toUtf8()};
        bool accepted{false};
        for (char c : typed) {
            const unsigned char byte{static_cast<unsigned char>(c)};
            if (byte >= 'A' && byte <= 'Z') {
                m_value.push_back(static_cast<char>(byte - 'A' + 'a'));
                accepted = true;
            } else if ((byte >= 'a' && byte <= 'z') || byte == ' ') {
                m_value.push_back(static_cast<char>(byte));
                accepted = true;
            }
        }
        if (!typed.isEmpty()) memory_cleanse(typed.data(), typed.size());
        if (accepted) {
            update();
            event->accept();
            return;
        }
        QFrame::keyPressEvent(event);
    }

    void paintEvent(QPaintEvent* event) override
    {
        QFrame::paintEvent(event);
        size_t words{0};
        bool in_word{false};
        for (char c : m_value) {
            if (IsSpace(c)) {
                in_word = false;
            } else if (!in_word) {
                ++words;
                in_word = true;
            }
        }
        const QString display{words == 0 ? tr("Type the 24-word phrase (paste is disabled)")
                                         : tr("%1 of 24 words entered • phrase hidden").arg(words)};
        QPainter painter(this);
        painter.setPen(palette().color(words == 0 ? QPalette::PlaceholderText : QPalette::Text));
        painter.drawText(rect().adjusted(8, 2, -8, -2), Qt::AlignVCenter | Qt::AlignLeft, display);
    }

private:
    static bool IsSpace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
    SecureString m_value;
};

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

util::Result<std::string> DecodeVaultPolicyInput(const QString& input)
{
    const QString trimmed{input.trimmed()};
    if (!trimmed.startsWith(QString::fromStdString(std::string{wallet::VAULT_POLICY_QR_FORMAT}) + "|")) {
        std::string bytes{trimmed.toStdString()};
        // QPlainTextEdit omits a terminal newline from toPlainText(). The
        // canonical package format includes one, so restore that one byte only
        // when every parsed field otherwise reproduces the canonical bytes.
        if (auto package = wallet::ParseVaultPolicyPackage(bytes)) {
            const std::string canonical{wallet::FormatVaultPolicyPackage(*package)};
            if (canonical == bytes ||
                (canonical.size() == bytes.size() + 1 && canonical.back() == '\n' &&
                 std::equal(bytes.begin(), bytes.end(), canonical.begin()))) {
                return canonical;
            }
        }
        return bytes;
    }
    std::vector<std::string> parts;
    for (const QString& line : trimmed.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QString part{line.trimmed()};
        if (!part.isEmpty()) parts.push_back(part.toStdString());
    }
    return wallet::ReassembleVaultPolicyQrParts(parts);
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

util::Result<CTxDestination> FirstDescriptorDestination(const std::string& encoded)
{
    FlatSigningProvider keys;
    std::string parse_error;
    auto descriptors = Parse(encoded, keys, parse_error, /*require_checksum=*/true);
    if (descriptors.size() != 1) {
        return util::Error{Untranslated(parse_error.empty() ? "The imported receive descriptor is ambiguous" : parse_error)};
    }
    std::vector<CScript> scripts;
    FlatSigningProvider expanded;
    if (!descriptors.front()->Expand(/*pos=*/0, keys, scripts, expanded) || scripts.size() != 1) {
        return util::Error{Untranslated("The imported receive descriptor cannot derive its first address")};
    }
    CTxDestination destination;
    if (!ExtractDestination(scripts.front(), destination) || !IsValidDestination(destination)) {
        return util::Error{Untranslated("The imported receive descriptor did not produce a valid address")};
    }
    return destination;
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

        struct StepTitle { int page; QString advanced; QString fixed; };
        const std::vector<StepTitle> steps{
            {MultisigWizard::Page_Intro, tr("Start"), {}},
            {MultisigWizard::Page_Template, tr("Template"), {}},
            {MultisigWizard::Page_Setup, tr("Type"), {}},
            {MultisigWizard::Page_Keys, tr("Keys"), tr("Review Vault")},
            {MultisigWizard::Page_Threshold, tr("Policy"), {}},
            {MultisigWizard::Page_Backup, tr("Backup"), tr("Secure Recovery")},
            {MultisigWizard::Page_Verify, tr("Verify"), tr("Confirm Address")},
            {MultisigWizard::Page_Done, tr("Ready"), tr("Ready")},
        };
        m_dots.reserve(steps.size());
        m_names.reserve(steps.size());
        for (const auto& step : steps) {
            auto* row = new QWidget;
            auto* h = new QHBoxLayout(row);
            h->setContentsMargins(0, 1, 0, 1);
            h->setSpacing(8);
            auto* dot = new QLabel;
            dot->setFixedSize(22, 22);
            dot->setAlignment(Qt::AlignCenter);
            auto* name = new QLabel(step.advanced);
            h->addWidget(dot, 0, Qt::AlignVCenter);
            h->addWidget(name, 1, Qt::AlignVCenter);
            layout->addWidget(row);
            m_dots.push_back(dot);
            m_names.push_back(name);
            m_rows.push_back(row);
            m_page_ids.push_back(step.page);
            m_advanced_titles.push_back(step.advanced);
            m_fixed_titles.push_back(step.fixed);
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
        std::vector<int> visible;
        for (int i = 0; i < static_cast<int>(m_page_ids.size()); ++i) {
            const int id = m_page_ids[i];
            const bool show = m_wizard->advancedFlow() ||
                id == MultisigWizard::Page_Keys ||
                id == MultisigWizard::Page_Backup || id == MultisigWizard::Page_Verify ||
                id == MultisigWizard::Page_Done;
            m_rows[i]->setVisible(show);
            m_names[i]->setText(m_wizard->advancedFlow() ? m_advanced_titles[i] : m_fixed_titles[i]);
            if (show) visible.push_back(i);
        }
        int current_step{0};
        for (int pos = 0; pos < static_cast<int>(visible.size()); ++pos) {
            if (m_page_ids[visible[pos]] == page_id) current_step = pos;
        }
        for (int pos = 0; pos < static_cast<int>(visible.size()); ++pos) {
            const int i = visible[pos];
            QLabel* dot = m_dots[i];
            QLabel* name = m_names[i];
            const bool unnumbered_ready = !m_wizard->advancedFlow() &&
                m_page_ids[i] == MultisigWizard::Page_Done;
            QFont name_font = name->font();
            name_font.setBold(pos == current_step);
            name->setFont(name_font);
            if (pos == current_step) {
                dot->setText(unnumbered_ready ? QStringLiteral("✓") : QString::number(pos + 1));
                dot->setStyleSheet(QStringLiteral(
                    "QLabel { background: palette(highlight); color: palette(highlighted-text); border-radius: 11px; font-weight: 600; }"));
                name->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
            } else if (pos < current_step) {
                dot->setText(QStringLiteral("✓"));
                dot->setStyleSheet(QStringLiteral(
                    "QLabel { background: palette(mid); color: white; border-radius: 11px; }"));
                name->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
            } else {
                dot->setText(unnumbered_ready ? QString{} : QString::number(pos + 1));
                dot->setStyleSheet(QStringLiteral(
                    "QLabel { border: 1px solid palette(mid); color: palette(mid); border-radius: 11px; }"));
                name->setStyleSheet(QStringLiteral("QLabel { color: palette(mid); }"));
            }
        }
        refreshPolicyText();
    }

    void refreshPolicy()
    {
        setCurrent(m_wizard->currentId());
    }

private:
    void refreshPolicyText()
    {
        m_wizard->rebuildKeyList();
        const int n = static_cast<int>(m_wizard->keys().size());
        const int n_active = m_wizard->nActiveKeys();
        if (!m_wizard->advancedFlow()) {
            m_policy->setText(tr("All 3 now\nAny 2 after ~30 days\nAny 1 after ~60 days"));
            return;
        }
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

    std::vector<QWidget*> m_rows;
    std::vector<int> m_page_ids;
    std::vector<QLabel*> m_dots;
    std::vector<QLabel*> m_names;
    std::vector<QString> m_advanced_titles;
    std::vector<QString> m_fixed_titles;
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

class VaultRestoreWizard final : public QWizard
{
public:
    enum PageId { Policy, RecoveryKeys, Authority, Rescan };

    explicit VaultRestoreWizard(MultisigWizard* wizard) : QWizard(wizard, GUIUtil::dialog_flags), m_wizard(wizard)
    {
        setWindowTitle(tr("Restore a Recovery Vault"));
        setWizardStyle(QWizard::ClassicStyle);
#ifdef Q_OS_MACOS
        QPixmap background(1, 1);
        background.fill(Qt::transparent);
        setPixmap(QWizard::BackgroundPixmap, background);
#endif
        setMinimumSize(760, 600);
        setButtonText(QWizard::NextButton, tr("Continue"));
        setButtonText(QWizard::BackButton, tr("Back"));
        setButtonText(QWizard::FinishButton, tr("Restore and Rescan"));
        setButtonText(QWizard::CancelButton, tr("Cancel"));

        auto* policy_page = new QWizardPage;
        policy_page->setTitle(tr("Policy"));
        policy_page->setSubTitle(tr("Load the public Recovery Kit before entering any private phrase."));
        auto* policy_layout = new QVBoxLayout(policy_page);
        auto* form = new QFormLayout;
        m_name = new QLineEdit(wizard->walletName());
        m_name->setObjectName("restoreWalletNameEdit");
        m_name->setAccessibleName(tr("Restored wallet name"));
        form->addRow(tr("New wallet name"), m_name);
        policy_layout->addLayout(form);

        auto* policy_row = new QHBoxLayout;
        auto* policy_label = new QLabel(tr("Public Recovery Kit policy"));
        auto* load_policy = new QPushButton(tr("Load Policy…"));
        load_policy->setObjectName("loadRestorePolicyButton");
        load_policy->setAutoDefault(false);
        policy_row->addWidget(policy_label);
        policy_row->addStretch();
        policy_row->addWidget(load_policy);
        policy_layout->addLayout(policy_row);
        m_policy = new QPlainTextEdit;
        m_policy->setObjectName("restorePolicyEdit");
        m_policy->setPlaceholderText(tr("Paste the exact public policy JSON, or newline-separated BCVP QR parts"));
        m_policy->setFont(GUIUtil::fixedPitchFont());
        policy_layout->addWidget(m_policy, 1);
        m_policy_summary = new QLabel;
        m_policy_summary->setObjectName("restorePolicySummary");
        m_policy_summary->setWordWrap(true);
        m_policy_summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
        policy_layout->addWidget(m_policy_summary);
        m_policy_status = new QLabel;
        m_policy_status->setObjectName("restorePolicyStatus");
        m_policy_status->setWordWrap(true);
        policy_layout->addWidget(m_policy_status);
        setPage(Policy, policy_page);

        auto* keys_page = new QWizardPage;
        keys_page->setTitle(tr("Recovery Keys"));
        keys_page->setSubTitle(tr("Add only printed software-key phrases that belong to this policy."));
        auto* keys_layout = new QVBoxLayout(keys_page);
        auto* seed_warning = new QLabel(tr("Never enter a hardware-wallet seed here."));
        seed_warning->setObjectName("restoreHardwareSeedWarning");
        QFont warning_font = seed_warning->font();
        warning_font.setBold(true);
        seed_warning->setFont(warning_font);
        keys_layout->addWidget(seed_warning);
        auto* phrase_help = new QLabel(tr(
            "Enter one 24-word software-key phrase at a time. Bitcoin Core checks its BIP39 checksum, derivation path, fingerprint, and complete account xpub, then matches it by identity rather than entry order. BIP39 passphrase: none."));
        phrase_help->setWordWrap(true);
        keys_layout->addWidget(phrase_help);
        m_phrase = new SecureMnemonicEdit;
        m_phrase->setObjectName("restoreMnemonicEdit");
        m_phrase->setAccessibleName(tr("Software-key recovery phrase"));
        keys_layout->addWidget(m_phrase);
        m_add_key = new QPushButton(tr("Add Another Key"));
        m_add_key->setObjectName("restoreAddKeyButton");
        m_add_key->setAutoDefault(false);
        keys_layout->addWidget(m_add_key, 0, Qt::AlignLeft);
        m_key_list = new QListWidget;
        m_key_list->setObjectName("restoreAcceptedKeys");
        m_key_list->setSelectionMode(QAbstractItemView::NoSelection);
        keys_layout->addWidget(m_key_list);
        m_key_status = new QLabel;
        m_key_status->setObjectName("restoreKeyStatus");
        m_key_status->setWordWrap(true);
        keys_layout->addWidget(m_key_status);
        m_key_authority = new QLabel;
        m_key_authority->setObjectName("restoreIncrementalAuthority");
        m_key_authority->setWordWrap(true);
        keys_layout->addWidget(m_key_authority);
        setPage(RecoveryKeys, keys_page);

        auto* authority_page = new QWizardPage;
        authority_page->setTitle(tr("Recovered Authority"));
        authority_page->setSubTitle(tr("Review what the restored wallet can authorize before it is created."));
        auto* authority_layout = new QVBoxLayout(authority_page);
        m_authority_summary = new QLabel;
        m_authority_summary->setObjectName("restoreAuthoritySummary");
        m_authority_summary->setWordWrap(true);
        QFont authority_font = m_authority_summary->font();
        authority_font.setPointSize(authority_font.pointSize() + 1);
        m_authority_summary->setFont(authority_font);
        authority_layout->addWidget(m_authority_summary);
        auto* authority_rules = new QLabel(tr(
            "The policy itself remains unchanged: all three participants are required now, any two can make an explicit recovery spend after 4,320 blocks, and any one can recover after 8,640 blocks. Recovery is never automatic."));
        authority_rules->setWordWrap(true);
        authority_layout->addWidget(authority_rules);
        authority_layout->addStretch();
        setPage(Authority, authority_page);

        auto* rescan_page = new QWizardPage;
        rescan_page->setTitle(tr("Rescan"));
        rescan_page->setSubTitle(tr("Create the restored wallet and search the complete blockchain history."));
        rescan_page->setFinalPage(true);
        auto* rescan_layout = new QVBoxLayout(rescan_page);
        m_rescan_summary = new QLabel;
        m_rescan_summary->setObjectName("restoreRescanSummary");
        m_rescan_summary->setWordWrap(true);
        rescan_layout->addWidget(m_rescan_summary);
        auto* rescan_note = new QLabel(tr(
            "Descriptors are imported with timestamp zero. The rescan begins at genesis and may take time. If it is interrupted, the restored public policy remains identifiable by its policy ID."));
        rescan_note->setWordWrap(true);
        rescan_layout->addWidget(rescan_note);
        rescan_layout->addStretch();
        setPage(Rescan, rescan_page);

        connect(load_policy, &QPushButton::clicked, this, [this] {
            const QString path = QFileDialog::getOpenFileName(
                this, tr("Open public vault policy"), {}, tr("Vault policy (*.json *.txt);;All files (*)"));
            if (path.isEmpty()) return;
            QFile file(path);
            if (!file.open(QIODevice::ReadOnly) || file.size() > 1024 * 1024) {
                m_policy_status->setText(tr("Could not read a public policy smaller than 1 MiB from that file."));
                return;
            }
            m_policy->setPlainText(QString::fromUtf8(file.readAll()));
        });
        connect(m_add_key, &QPushButton::clicked, this, [this] { addCurrentPhrase(); });
        connect(this, &QWizard::currentIdChanged, this, [this](int page_id) {
            if (page_id == Authority || page_id == Rescan) updateAuthority();
        });
        connect(m_wizard, &MultisigWizard::restoreAttemptFailed, this, [this](const QString& error) {
            if (!m_restore_started) return;
            m_restore_started = false;
            m_rescan_summary->setText(error);
            setButtonText(QWizard::FinishButton, tr("Restore and Rescan"));
            button(QWizard::FinishButton)->setEnabled(true);
            button(QWizard::BackButton)->setEnabled(true);
            button(QWizard::CancelButton)->setEnabled(true);
        });
        connect(m_wizard, &MultisigWizard::restoreRescanRetryRequired, this,
                [this](WalletModel* wallet_model, const QString& error) {
            if (!m_restore_started) return;
            m_retry_wallet = wallet_model;
            m_restore_started = false;
            m_rescan_summary->setText(tr("The vault is installed, but its historical rescan is incomplete. No recovery phrase is needed again. %1")
                                          .arg(error.toHtmlEscaped()));
            setButtonText(QWizard::FinishButton, tr("Retry Rescan from Genesis"));
            button(QWizard::FinishButton)->setEnabled(true);
            button(QWizard::BackButton)->setEnabled(false);
            button(QWizard::CancelButton)->setEnabled(true);
        });
        connect(m_wizard, &MultisigWizard::restoreCompleted, this, [this] {
            if (m_restore_started) QWizard::accept();
        });
        updateAuthority();
    }

    ~VaultRestoreWizard() override { clearPhrases(); }

private:
    void clearPhrases()
    {
        if (m_phrase) m_phrase->clearSecure();
        for (SecureString& phrase : m_phrases) {
            if (!phrase.empty()) memory_cleanse(phrase.data(), phrase.size());
        }
        std::vector<SecureString>{}.swap(m_phrases);
    }

    bool preflightPolicy()
    {
        m_policy_status->clear();
        if (const QString name_error = m_wizard->walletNameError(m_name->text()); !name_error.isEmpty()) {
            m_policy_status->setText(name_error);
            m_name->setFocus();
            return false;
        }
        if (m_policy->toPlainText().toUtf8().size() > 1024 * 1024) {
            m_policy_status->setText(tr("The public policy is larger than 1 MiB."));
            return false;
        }
        auto decoded = DecodeVaultPolicyInput(m_policy->toPlainText());
        if (!decoded) {
            m_policy_status->setText(QString::fromStdString(util::ErrorString(decoded).original));
            return false;
        }
        auto package = wallet::ParseVaultPolicyPackage(*decoded);
        if (!package) {
            m_policy_status->setText(QString::fromStdString(util::ErrorString(package).original));
            return false;
        }
        auto fixed = wallet::ValidateFixedStagedVaultPolicy(*package);
        if (!fixed) {
            m_policy_status->setText(QString::fromStdString(util::ErrorString(fixed).original));
            return false;
        }
        auto participants = wallet::FixedVaultParticipants(*package);
        if (!participants) {
            m_policy_status->setText(QString::fromStdString(util::ErrorString(participants).original));
            return false;
        }
        const std::string canonical{wallet::FormatVaultPolicyPackage(*package)};
        if (canonical != *decoded) {
            m_policy_status->setText(tr("The public policy must use the exact canonical Recovery Kit format."));
            return false;
        }
        auto rescan_ready = m_wizard->node().walletLoader().checkRescanFromGenesis();
        if (!rescan_ready) {
            m_policy_status->setText(QString::fromStdString(util::ErrorString(rescan_ready).translated));
            return false;
        }
        clearPhrases();
        m_recovered_software.clear();
        m_connected_hardware.clear();
        m_package = *package;
        m_canonical_policy = *decoded;
        const interfaces::ExternalSignerDiscovery discovery{
            m_wizard->node().discoverExternalSigners(participants->front().path)};
        if (discovery.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS) {
            for (const auto& device : discovery.devices) {
                if (!device.IsUsableForStagedVault()) continue;
                const auto match = std::find_if(participants->begin(), participants->end(), [&](const auto& participant) {
                    return participant.path == discovery.account_path &&
                           participant.fingerprint == device.fingerprint &&
                           participant.xpub == *device.account_xpub;
                });
                if (match != participants->end()) m_connected_hardware.insert(match->fingerprint);
            }
        }
        m_policy_summary->setText(tr(
            "Network: %1\nPolicy ID: %2\nNow: all 3 participants\nAfter 4,320 blocks: any 2\nAfter 8,640 blocks: any 1\nExact hardware participants connected: %3")
            .arg(QString::fromStdString(m_package.network),
                 QString::fromStdString(m_package.policy_id),
                 QString::number(m_connected_hardware.size())));
        m_policy_status->setText(discovery.status == interfaces::ExternalSignerDiscoveryStatus::SUCCESS
                ? tr("Policy and rescan preflight complete. No private phrase has been requested yet.")
                : tr("Policy and rescan preflight complete. Hardware discovery is unavailable, so no device is counted as signing authority. No private phrase has been requested yet."));
        updateAuthority();
        return true;
    }

    bool addCurrentPhrase()
    {
        if (m_phrase->trimmedEmpty()) return true;
        if (m_phrases.size() >= 3) {
            m_key_status->setText(tr("This fixed policy has only three participants."));
            return false;
        }
        m_phrases.push_back(m_phrase->takeTrimmed());
        auto matches = wallet::ValidateVaultPolicyMnemonics(m_package, m_phrases);
        if (!matches || matches->size() != m_phrases.size()) {
            SecureString rejected{std::move(m_phrases.back())};
            m_phrases.pop_back();
            m_phrase->restoreSecure(std::move(rejected));
            m_key_status->setText(matches
                ? tr("That phrase did not match the complete public policy.")
                : QString::fromStdString(util::ErrorString(matches).original));
            return false;
        }
        const size_t added_index = m_phrases.size() - 1;
        const auto match = std::find_if(matches->begin(), matches->end(), [added_index](const wallet::VaultMnemonicMatch& item) {
            return item.mnemonic_index == added_index;
        });
        if (match == matches->end()) {
            SecureString rejected{std::move(m_phrases.back())};
            m_phrases.pop_back();
            m_phrase->restoreSecure(std::move(rejected));
            m_key_status->setText(tr("That phrase could not be matched by identity."));
            return false;
        }
        m_recovered_software.insert(match->fingerprint);
        m_key_list->addItem(tr("Software key %1 matched · fingerprint %2")
            .arg(m_phrases.size()).arg(QString::fromStdString(match->fingerprint)));
        m_key_status->setText(tr("Key matched by fingerprint, derivation path, and full account xpub."));
        m_add_key->setEnabled(m_phrases.size() < 3);
        updateAuthority();
        return true;
    }

    void updateAuthority()
    {
        std::set<std::string> available{m_connected_hardware};
        available.insert(m_recovered_software.begin(), m_recovered_software.end());
        const size_t count{available.size()};
        const QString sources{tr("%1 software, %2 exact hardware")
                                  .arg(m_recovered_software.size())
                                  .arg(m_connected_hardware.size())};
        QString authority;
        switch (count) {
        case 0:
            authority = tr("Public policy only. No software signing key is restored. Reconnect exact hardware participants to regain signing capability.");
            break;
        case 1:
            authority = tr("One participant is available (%1). It can use only the 8,640-block (~60 day) recovery path by itself.").arg(sources);
            break;
        case 2:
            authority = tr("Two participants are available (%1). Together they can use the 4,320-block (~30 day) recovery path; either one can use the final path.").arg(sources);
            break;
        default:
            authority = tr("All three participants are available (%1). Immediate spending and both explicit recovery paths are available.").arg(sources);
            break;
        }
        if (m_key_authority) m_key_authority->setText(authority);
        if (m_authority_summary) m_authority_summary->setText(authority);
        if (m_rescan_summary) {
            m_rescan_summary->setText(tr("Restore %1 with policy ID %2. %3")
                .arg(m_name ? m_name->text().trimmed().toHtmlEscaped() : QString{},
                     QString::fromStdString(m_package.policy_id).toHtmlEscaped(),
                     authority.toHtmlEscaped()));
        }
    }

    bool validateCurrentPage() override
    {
        if (currentId() == Policy) return preflightPolicy();
        if (currentId() == RecoveryKeys) return addCurrentPhrase();
        return QWizard::validateCurrentPage();
    }

    void accept() override
    {
        if (currentId() != Rescan || m_restore_started) return;
        QString error;
        const bool started{m_retry_wallet
                ? m_wizard->retryRecoveryRescan(m_retry_wallet, error)
                : m_wizard->restoreFromRecoverySheets(m_name->text().trimmed(),
                                                       QString::fromStdString(m_canonical_policy),
                                                       m_phrases, error)};
        if (!started) {
            m_rescan_summary->setText(error);
            return;
        }
        m_restore_started = true;
        button(QWizard::FinishButton)->setEnabled(false);
        button(QWizard::BackButton)->setEnabled(false);
        button(QWizard::CancelButton)->setEnabled(false);
        clearPhrases();
    }

    MultisigWizard* m_wizard;
    QLineEdit* m_name{nullptr};
    QPlainTextEdit* m_policy{nullptr};
    QLabel* m_policy_summary{nullptr};
    QLabel* m_policy_status{nullptr};
    SecureMnemonicEdit* m_phrase{nullptr};
    QPushButton* m_add_key{nullptr};
    QListWidget* m_key_list{nullptr};
    QLabel* m_key_status{nullptr};
    QLabel* m_key_authority{nullptr};
    QLabel* m_authority_summary{nullptr};
    QLabel* m_rescan_summary{nullptr};
    wallet::VaultPolicyPackage m_package;
    std::string m_canonical_policy;
    std::vector<SecureString> m_phrases;
    std::set<std::string> m_recovered_software;
    std::set<std::string> m_connected_hardware;
    bool m_restore_started{false};
    WalletModel* m_retry_wallet{nullptr};
};
} // namespace

class MultisigIntroPage : public QWizardPage
{
public:
    explicit MultisigIntroPage(MultisigWizard* wizard) : QWizardPage(wizard)
    {
        setTitle(tr("Create a vault wallet"));
        setSubTitle(tr("Review the recovery model before choosing a template, key sources, and policy details."));
        auto* layout = new QVBoxLayout(this);
        layout->setSpacing(10);
        layout->addWidget(MakeTitledCard(
            tr("A lost key can freeze spending now"),
            tr("A delayed recovery policy is not ordinary multisig. If an immediate-path key is lost, the remaining keys cannot spend until the configured recovery condition is satisfied.")));
        layout->addWidget(MakeTitledCard(
            tr("Recovery is not automatic"),
            tr("Mature coins do not move themselves. Someone must explicitly construct and sign a recovery spend.")));
        layout->addWidget(MakeTitledCard(
            tr("Each coin has its own clock"),
            tr("Relative delays apply separately to each received coin. Change and consolidation start a new wait; block-time calendar estimates vary.")));
        layout->addStretch();
    }
    void refreshMode()
    {
        setTitle(tr("Create a vault wallet"));
        setSubTitle(tr("Review the recovery model before choosing a template, key sources, and policy details."));
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
            tr("For a three-key setup, all three active keys spend now. Any two recovery keys can spend after about 90 days (12960 blocks)."),
            MultisigWizard::VaultTemplate::RecoverOneLost, /*checked=*/false);
        add(QStringLiteral("templateStagedRadio"),
            tr("Staged recovery (30 / 60 days)"),
            tr("All active keys spend now. Any two recovery keys can spend after about 30 days; any one recovery key can spend after about 60 days."),
            MultisigWizard::VaultTemplate::StagedRecovery, true);
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
    QSpinBox* local_count{nullptr};
    QListWidget* hardware{nullptr};
    QListWidget* airgapped{nullptr};
    QCheckBox* inherit{nullptr};

    explicit MultisigKeysPage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Create a Recovery Vault"));
        setSubTitle(tr("Review who can spend now and how recovery changes over time."));
        auto* layout = new QVBoxLayout(this);
        layout->setSpacing(8);

        m_fixed_review = new QWidget;
        auto* review_layout = new QVBoxLayout(m_fixed_review);
        review_layout->setContentsMargins(0, 0, 0, 0);
        review_layout->setSpacing(9);
        auto* name_form = new QFormLayout;
        m_name = new QLineEdit;
        m_name->setObjectName("stagedWalletNameEdit");
        m_name->setText(wizard->walletName());
        m_name->setPlaceholderText(tr("Family vault"));
        m_name->setAccessibleName(tr("Vault wallet name"));
        name_form->addRow(tr("Wallet name"), m_name);
        review_layout->addLayout(name_form);
        m_name_error = new QLabel;
        m_name_error->setObjectName("walletNameErrorLabel");
        m_name_error->setWordWrap(true);
        m_name_error->setStyleSheet(QStringLiteral("QLabel { color: palette(bright-text); }"));
        review_layout->addWidget(m_name_error);

        auto* timeline = new QHBoxLayout;
        timeline->setSpacing(20);
        const std::array<QString, 3> timeline_copy{
            tr("Now\nall 3 keys"),
            tr("After ~30 days\nany 2 keys"),
            tr("After ~60 days\nany 1 key"),
        };
        for (const QString& copy : timeline_copy) {
            auto* label = new QLabel(copy);
            label->setAlignment(Qt::AlignCenter);
            QFont font = label->font();
            font.setBold(true);
            font.setPointSize(font.pointSize() + 1);
            label->setFont(font);
            label->setMinimumHeight(44);
            timeline->addWidget(label, 1);
        }
        review_layout->addLayout(timeline);

        m_authority = new QLabel;
        m_authority->setObjectName("fixedAuthorityLabel");
        m_authority->setWordWrap(true);
        QFont authority_font = m_authority->font();
        authority_font.setPointSize(authority_font.pointSize() + 1);
        m_authority->setFont(authority_font);
        review_layout->addWidget(m_authority);

        m_fixed_roster = new QWidget;
        auto* roster_layout = new QVBoxLayout(m_fixed_roster);
        roster_layout->setContentsMargins(0, 0, 0, 0);
        roster_layout->setSpacing(5);
        for (int slot = 0; slot < MultisigWizard::kStagedVaultKeyCount; ++slot) {
            auto* row = new QWidget;
            auto* row_layout = new QHBoxLayout(row);
            row_layout->setContentsMargins(10, 5, 10, 5);
            row_layout->setSpacing(12);
            auto* number = new QLabel(QString::number(slot + 1));
            number->setAlignment(Qt::AlignCenter);
            number->setFixedWidth(22);
            m_slot_primary[slot] = new QLabel;
            QFont primary_font = m_slot_primary[slot]->font();
            primary_font.setBold(true);
            m_slot_primary[slot]->setFont(primary_font);
            m_slot_secondary[slot] = new QLabel;
            m_slot_secondary[slot]->setStyleSheet(QStringLiteral("QLabel { color: palette(placeholder-text); }"));
            m_slot_secondary[slot]->setTextInteractionFlags(Qt::TextSelectableByMouse);
            row_layout->addWidget(number);
            row_layout->addWidget(m_slot_primary[slot], 1);
            row_layout->addWidget(m_slot_secondary[slot]);
            roster_layout->addWidget(row);
        }
        review_layout->addWidget(m_fixed_roster);

        auto* discovery_row = new QHBoxLayout;
        m_discovery_status = new QLabel;
        m_discovery_status->setObjectName("hardwareDiscoveryStatus");
        m_discovery_status->setWordWrap(true);
        m_retry = new QPushButton(tr("Retry"));
        m_retry->setObjectName("refreshDevicesButton");
        m_retry->setAutoDefault(false);
        discovery_row->addWidget(m_discovery_status, 1);
        discovery_row->addWidget(m_retry, 0, Qt::AlignTop);
        review_layout->addLayout(discovery_row);

        auto* details = new QToolButton;
        details->setObjectName("technicalDetailsButton");
        details->setText(tr("Technical details"));
        details->setCheckable(true);
        details->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        details->setArrowType(Qt::RightArrow);
        m_technical = new QLabel(tr(
            "Taproot (Bech32m). Immediate spending uses all three participants. "
            "Explicit recovery uses any two after exactly 4,320 blocks or any one after exactly 8,640 blocks. "
            "Each received or change output has its own relative-delay clock."));
        m_technical->setObjectName("fixedTechnicalDetails");
        m_technical->setWordWrap(true);
        m_technical->setVisible(false);
        review_layout->addWidget(details, 0, Qt::AlignLeft);
        review_layout->addWidget(m_technical);
        connect(details, &QToolButton::toggled, this, [this, details](bool shown) {
            details->setArrowType(shown ? Qt::DownArrow : Qt::RightArrow);
            m_technical->setVisible(shown);
        });

        auto* boundary = new QLabel(tr("Next, you’ll print and secure one complete Recovery Kit before this wallet is created."));
        boundary->setObjectName("recoveryKitNextLabel");
        boundary->setWordWrap(true);
        review_layout->addWidget(boundary);
        auto* secondary_actions = new QHBoxLayout;
        m_restore = new QPushButton(tr("Restore a Vault…"));
        m_restore->setObjectName("restoreFromMnemonicButton");
        m_restore->setAutoDefault(false);
        m_advanced = new QPushButton(tr("Advanced…"));
        m_advanced->setObjectName("advancedVaultButton");
        m_advanced->setAutoDefault(false);
        secondary_actions->addWidget(m_restore);
        secondary_actions->addWidget(m_advanced);
        secondary_actions->addStretch();
        review_layout->addLayout(secondary_actions);
        layout->addWidget(m_fixed_review);

        m_plan = new QLabel;
        m_plan->setObjectName("automaticKeyPlanLabel");
        m_plan->setWordWrap(true);
        m_plan->setTextFormat(Qt::RichText);
        layout->addWidget(m_plan);

        m_local_box = new QGroupBox(tr("Software keys on this computer"));
        auto* local_layout = new QVBoxLayout(m_local_box);
        auto* local_row = new QHBoxLayout;
        m_local_count_label = new QLabel(tr("Number of software keys"));
        local_row->addWidget(m_local_count_label);
        local_count = new QSpinBox;
        local_count->setObjectName("localSoftwareKeyCountSpin");
        local_count->setRange(0, MultisigWizard::kMaxLocalSoftwareKeys);
        local_count->setSpecialValueText(tr("None"));
        local_count->setValue(MultisigWizard::kStagedVaultKeyCount);
        local_count->setToolTip(tr("Core generates a separate HD key for each slot and stores every private key in this wallet."));
        local_row->addWidget(local_count);
        local_row->addStretch();
        local_layout->addLayout(local_row);
        m_local_warning = new QLabel;
        m_local_warning->setObjectName("localSoftwareKeysWarningLabel");
        m_local_warning->setWordWrap(true);
        local_layout->addWidget(m_local_warning);
        m_local_risk = new QCheckBox(tr("I understand one computer and wallet backup control all these keys."));
        m_local_risk->setObjectName("localSoftwareKeysRiskCheck");
        local_layout->addWidget(m_local_risk);
        layout->addWidget(m_local_box);

        m_hardware_box = new QGroupBox(tr("Connected hardware"));
        auto* hw_layout = new QVBoxLayout(m_hardware_box);
        hardware = new QListWidget;
        hardware->setObjectName("hardwareList");
        hardware->setSelectionMode(QAbstractItemView::NoSelection);
        hardware->setMinimumHeight(48);
        hardware->setMaximumHeight(96);
        hardware->setAlternatingRowColors(true);
        hw_empty = new QLabel(tr("No hardware wallets detected. Plug in a device or add an xpub below."));
        hw_empty->setObjectName("hardwareEmptyLabel");
        hw_empty->setWordWrap(true);
        hw_empty->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        hw_layout->addWidget(hw_empty);
        hw_layout->addWidget(hardware);
        auto* refresh = new QPushButton(tr("Refresh devices"));
        refresh->setObjectName("advancedRefreshDevicesButton");
        refresh->setAutoDefault(false);
        hw_layout->addWidget(refresh, 0, Qt::AlignLeft);
        layout->addWidget(m_hardware_box);

        m_air_box = new QGroupBox(tr("Air-gapped / xpub"));
        auto* air_layout = new QVBoxLayout(m_air_box);
        airgapped = new QListWidget;
        airgapped->setObjectName("airgappedList");
        airgapped->setMinimumHeight(42);
        airgapped->setMaximumHeight(72);
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
        layout->addWidget(m_air_box);

        m_count = new QLabel;
        m_count->setObjectName("vaultKeyCount");
        m_count->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(m_count);
        inherit = new QCheckBox(tr("Last air-gapped key is recovery-only (inheritance)"));
        inherit->setObjectName("recoveryOnlyCheck");
        inherit->setToolTip(tr("That key is not in the immediate MuSig2 group. It can only sign after the recovery delay."));
        layout->addWidget(inherit);

        connect(local_count, qOverload<int>(&QSpinBox::valueChanged), this, [this](int count) {
            m_wizard->setLocalKeyCount(count);
            updateLocalWarning();
            updateCount();
            Q_EMIT completeChanged();
        });
        connect(m_local_risk, &QCheckBox::toggled, this, &QWizardPage::completeChanged);
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
        });
        connect(m_retry, &QPushButton::clicked, this, [this] { m_wizard->refreshHardware(); });
        connect(m_name, &QLineEdit::textChanged, this, [this] {
            refreshNameAvailability();
            Q_EMIT completeChanged();
        });
        connect(m_restore, &QPushButton::clicked, this, [this] {
            m_wizard->setWalletName(m_name->text().trimmed());
            VaultRestoreWizard dialog(m_wizard);
            dialog.exec();
        });
        connect(m_advanced, &QPushButton::clicked, this, [this] {
            m_wizard->enableAdvancedFlow();
            m_wizard->restart();
        });
        connect(hardware, &QListWidget::itemChanged, this, [this](QListWidgetItem* item) {
            if (!m_wizard->advancedFlow()) return;
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
    void refreshDevices()
    {
        populateHardware();
        updateLocalWarning();
        updateCount();
        Q_EMIT completeChanged();
    }

    void initializePage() override
    {
        const bool advanced = m_wizard->advancedFlow();
        setCommitPage(false);
        setTitle(advanced ? tr("Keys") : tr("Create a Recovery Vault"));
        setSubTitle(advanced
            ? tr("Choose software, hardware, or offline keys. Hardware is optional.")
            : tr("Review who can spend now and how recovery changes over time."));
        m_fixed_review->setVisible(!advanced);
        m_plan->setVisible(false);
        m_local_box->setVisible(advanced);
        m_hardware_box->setVisible(advanced);
        m_air_box->setVisible(advanced);
        m_count->setVisible(advanced);
        if (!advanced) {
            m_name->setText(m_wizard->walletName());
            refreshNameAvailability();
        }

        local_count->blockSignals(true);
        local_count->setValue(m_wizard->localKeyCount());
        local_count->blockSignals(false);
        const bool taproot = m_wizard->outputType() == OutputType::BECH32M;
        inherit->setVisible(advanced && taproot);
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
        if (advanced) populateAirgapped();
    }
    bool isComplete() const override
    {
        m_wizard->rebuildKeyList();
        if (!m_wizard->advancedFlow()) {
            return m_discovery_valid && m_wizard->keys().size() == MultisigWizard::kStagedVaultKeyCount &&
                   m_wizard->nActiveKeys() == MultisigWizard::kStagedVaultKeyCount && m_name_available;
        }
        return m_wizard->keys().size() >= 2 &&
               (m_wizard->localKeyCount() <= 1 || (m_local_risk && m_local_risk->isChecked()));
    }
    bool validatePage() override
    {
        if (!m_wizard->advancedFlow()) {
#ifdef QT_NO_PDF
            QMessageBox::critical(this, tr("PDF printing unavailable"),
                                  tr("This build cannot create the required recovery PDF, so no wallet was created."));
            return false;
#endif
            m_wizard->setWalletName(m_name->text().trimmed());
            refreshNameAvailability();
            if (!m_name_available) return false;
            if (const QString name_error = m_wizard->walletNameError(m_wizard->walletName()); !name_error.isEmpty()) {
                QMessageBox::warning(this, tr("Choose another wallet name"), name_error);
                m_name->setFocus();
                return false;
            }
            // Re-enumerate at the commit boundary. A disconnected, newly
            // connected, or reordered device must never be silently replaced
            // after the user acknowledged the roster.
            populateHardware(/*require_unchanged=*/true);
            updateLocalWarning();
            updateCount();
            m_wizard->rebuildKeyList();
            if (!isComplete()) return false;
            if (m_wizard->outputType() != OutputType::BECH32M ||
                m_wizard->keys().size() != MultisigWizard::kStagedVaultKeyCount ||
                m_wizard->nActiveKeys() != MultisigWizard::kStagedVaultKeyCount ||
                m_wizard->nrequired() != 2 ||
                m_wizard->fallbackOlder() != MultisigWizard::kThirtyDayVaultDelay ||
                m_wizard->fallbackOlderOneKey() != MultisigWizard::kSixtyDayVaultDelay ||
                m_wizard->fallbackAfter()) {
                QMessageBox::critical(this, tr("Invalid fixed policy"),
                                      tr("The fixed three-key 30 / 60 day policy changed unexpectedly. No wallet was created."));
                return false;
            }
            const auto dup = wallet::DuplicateSignerWarning(m_wizard->keys());
            if (!dup.empty()) {
                QMessageBox::warning(this, tr("Same signer twice"), QString::fromStdString(dup.original));
                return false;
            }
            if (!m_wizard->createWallet()) {
                // Close the narrow race where another process creates this
                // wallet after the Intro-page check but before our create.
                // The backend never overwrites it; return to the name field
                // with the same friendly, actionable collision message.
                if (const QString name_error = m_wizard->walletNameError(m_wizard->walletName()); !name_error.isEmpty()) {
                    QMessageBox::warning(this, tr("Choose another wallet name"), name_error);
                    m_name->setFocus();
                    return false;
                }
                QMessageBox::critical(this, tr("Could not prepare vault"), m_wizard->createError());
                return false;
            }
            return true;
        }
        m_wizard->rebuildKeyList();
        if (m_wizard->keys().size() < 2) {
            QMessageBox::warning(this, tr("Need more keys"),
                                 tr("Choose at least two total keys. Increase software keys, connect hardware, or add an xpub."));
            return false;
        }
        if (m_wizard->localKeyCount() > 1 && (!m_local_risk || !m_local_risk->isChecked())) return false;
        const auto dup = wallet::DuplicateSignerWarning(m_wizard->keys());
        if (!dup.empty()) {
            QMessageBox::warning(this, tr("Same signer twice"), QString::fromStdString(dup.original));
            return false;
        }
        return true;
    }
    int nextId() const override
    {
        return m_wizard->advancedFlow() ? MultisigWizard::Page_Threshold : MultisigWizard::Page_Backup;
    }

    void showNameError(const QString& error)
    {
        m_name_available = false;
        m_name_error->setText(error);
        m_name_error->setVisible(true);
        m_name->setFocus();
        Q_EMIT completeChanged();
    }

private:
    void refreshNameAvailability()
    {
        if (m_wizard->advancedFlow()) {
            m_name_available = true;
            return;
        }
        const QString error = m_wizard->walletNameError(m_name->text());
        m_name_available = error.isEmpty();
        m_name_error->setText(error);
        m_name_error->setVisible(!error.isEmpty());
    }

    void updateLocalWarning()
    {
        const int count = m_wizard->localKeyCount();
        if (!m_wizard->advancedFlow()) {
            const int connected = static_cast<int>(m_wizard->m_hardware.size());
            if (!m_discovery_valid && !m_discovery_error.isEmpty()) {
                m_authority->setText(tr("The key roster is not ready. No software slot was substituted."));
                m_discovery_status->setText(m_discovery_error);
                m_retry->setVisible(true);
                return;
            }
            m_discovery_status->setText(tr("Compatible hardware wallets refresh automatically."));
            m_retry->setVisible(false);
            if (connected == 0) {
                m_authority->setText(tr("This computer holds all three keys. This wallet or its recovery kit can spend immediately."));
            } else if (connected == 1) {
                m_authority->setText(tr("This computer holds two keys. Together they can recover after about 30 days; the hardware wallet is also required to spend immediately."));
            } else if (connected == 2) {
                m_authority->setText(tr("This computer holds one key. It can recover alone after about 60 days."));
            } else {
                m_authority->setText(tr("No private keys are stored on this computer. Any two devices can recover after about 30 days; any one can recover after about 60 days."));
            }
            return;
        }
        if (count == 0) {
            m_local_warning->setText(tr("This wallet will not store a software signing key."));
        } else if (count == 1) {
            m_local_warning->setText(tr("Core will generate one HD key and store it in this wallet."));
        } else {
            m_local_warning->setText(tr("Core will generate %1 separate HD keys, but all of them share this wallet file, backup, and computer. They are not independent security domains.").arg(count));
        }
        m_local_risk->setVisible(count > 1);
    }

    void updateCount()
    {
        m_wizard->rebuildKeyList();
        const int n = static_cast<int>(m_wizard->keys().size());
        const int n_active = m_wizard->nActiveKeys();
        const int software = m_wizard->localKeyCount();
        const int connected = static_cast<int>(m_wizard->m_hardware.size());
        const int offline = static_cast<int>(m_wizard->m_airgapped.size());
        if (!m_wizard->advancedFlow()) {
            if (!m_discovery_valid) {
                m_count->setText(tr("Key roster is not ready. No wallet will be created."));
            } else {
                m_count->setText(tr("3 active keys — %1 hardware, %2 software on this computer.")
                                     .arg(connected).arg(software));
            }
            m_wizard->refreshSidebar();
            return;
        }
        if (n < 2) {
            m_count->setText(tr("%1 key total — %2 software, %3 hardware, %4 offline. Add at least two.")
                                 .arg(n).arg(software).arg(connected).arg(offline));
        } else {
            m_count->setText(tr("%1 keys total — %2 software, %3 hardware, %4 offline. %5 active; %6 recovery-only.")
                                 .arg(n).arg(software).arg(connected).arg(offline)
                                 .arg(n_active).arg(n - n_active));
        }
        m_wizard->refreshSidebar();
    }
    void populateHardware(bool require_unchanged = false)
    {
        hardware->clear();
        hw_empty->hide();
        hardware->show();
        if (!m_wizard->advancedFlow()) {
            m_discovery_valid = true;
            m_discovery_error.clear();
            std::vector<MultisigKeySpec> detected;
            std::map<std::string, std::pair<std::string, std::string>> accounts;
            std::set<std::string> address_display_devices;
            std::vector<std::string> signature;
            try {
                interfaces::ExternalSignerDiscovery discovery;
                const std::string account_path{wallet::DefaultMultisigPath(OutputType::BECH32M, 0)};
                if (auto* ctx = m_wizard->node().context(); ctx && ctx->args) {
                    discovery = m_wizard->node().discoverExternalSigners(account_path);
                } else {
                    discovery.status = interfaces::ExternalSignerDiscoveryStatus::NOT_CONFIGURED;
                    discovery.account_path = account_path;
                }

                if (discovery.status == interfaces::ExternalSignerDiscoveryStatus::NOT_CONFIGURED) {
                    m_discovery_valid = false;
                    m_discovery_error = tr("Hardware-wallet discovery is not configured. Configure native HWI, then retry. No software keys were substituted.");
                } else if (discovery.status == interfaces::ExternalSignerDiscoveryStatus::FAILED) {
                    m_discovery_valid = false;
                    m_discovery_error = tr("Hardware-wallet discovery failed: %1. Check the signer backend, then retry. No software keys were substituted.")
                                            .arg(QString::fromStdString(discovery.error.value_or("unknown discovery error")));
                }

                signature.reserve(discovery.devices.size());
                for (const auto& device : discovery.devices) {
                    signature.push_back(strprintf("%s|%s|%s|%s", device.path,
                                                  device.fingerprint,
                                                  device.account_xpub.value_or(""),
                                                  device.IsUsableForStagedVault() ? "ready" : "blocked"));
                    if (!m_discovery_valid) continue;

                    const QString device_name = QString::fromStdString(
                        !device.model.empty() ? device.model : (!device.type.empty() ? device.type : "Hardware wallet"));
                    const QString fingerprint = QString::fromStdString(device.fingerprint);
                    if (device.locked) {
                        m_discovery_valid = false;
                        m_discovery_error = tr("%1 is locked or did not provide a fingerprint. Unlock it, then retry. No software key was substituted.").arg(device_name);
                    } else if (device.duplicate) {
                        m_discovery_valid = false;
                        m_discovery_error = tr("%1 (%2) was discovered more than once. Disconnect the duplicate path, then retry. No software key was substituted.")
                                                .arg(device_name, fingerprint);
                    } else if (device.error) {
                        m_discovery_valid = false;
                        m_discovery_error = tr("%1 could not be inspected: %2. Fix or disconnect it, then retry. No software key was substituted.")
                                                .arg(device_name, QString::fromStdString(*device.error));
                    } else if (!device.supports_staged_vault.has_value()) {
                        m_discovery_valid = false;
                        m_discovery_error = tr("%1 does not report whether it supports Taproot MuSig2 vault signing. Update or disconnect it, then retry.").arg(device_name);
                    } else if (!*device.supports_staged_vault) {
                        m_discovery_valid = false;
                        m_discovery_error = tr("%1 cannot complete Taproot MuSig2 vault signing. Disconnect it, then retry. No software key was substituted.").arg(device_name);
                    } else if (device.account_xpub_error || !device.account_xpub) {
                        m_discovery_valid = false;
                        m_discovery_error = tr("%1 could not provide the required account key: %2. Reconnect it, then retry.")
                                                .arg(device_name, QString::fromStdString(device.account_xpub_error.value_or("no account xpub returned")));
                    } else if (!device.IsUsableForStagedVault()) {
                        m_discovery_valid = false;
                        m_discovery_error = tr("%1 is not ready for this vault. Fix or disconnect it, then retry.").arg(device_name);
                    }
                    if (!m_discovery_valid) continue;

                    MultisigKeySpec spec;
                    spec.fingerprint = device.fingerprint;
                    spec.path = account_path;
                    spec.label = device_name.toStdString();
                    detected.push_back(std::move(spec));
                    accounts.emplace(device.fingerprint, std::pair{account_path, *device.account_xpub});
                    if (device.supports_multisig_address_display.value_or(false)) {
                        address_display_devices.insert(device.fingerprint);
                    }
                }
                std::sort(detected.begin(), detected.end(), [](const MultisigKeySpec& a, const MultisigKeySpec& b) {
                    return a.fingerprint.value_or("") < b.fingerprint.value_or("");
                });
            } catch (const std::exception& e) {
                m_discovery_valid = false;
                m_discovery_error = tr("Hardware-wallet discovery failed: %1").arg(QString::fromStdString(e.what()));
            }

            if (m_discovery_valid && detected.size() > MultisigWizard::kStagedVaultKeyCount) {
                m_discovery_valid = false;
                m_discovery_error = tr("%1 hardware wallets were detected. Disconnect extras until at most three remain, then refresh. No devices were selected automatically.")
                                        .arg(detected.size());
            }

            const bool roster_changed = m_roster_initialized && signature != m_roster_signature;
            if (m_discovery_valid && require_unchanged && roster_changed) {
                m_discovery_valid = false;
                m_discovery_error = tr("The hardware-wallet roster changed at the boundary. Review the devices shown, press Retry, and continue only after the roster remains stable. No wallet was created.");
            }
            if (!signature.empty() || m_discovery_valid) {
                m_roster_initialized = true;
                m_roster_signature = signature;
            }

            if (!m_discovery_valid) {
                m_wizard->m_hardware.clear();
                m_wizard->m_fixed_hardware_accounts.clear();
                m_wizard->m_fixed_address_display_devices.clear();
                m_wizard->m_local_key_count = 0;
                m_wizard->rebuildKeyList();
                renderFixedRoster();
                updateLocalWarning();
                Q_EMIT completeChanged();
                return;
            }

            const int local_keys = MultisigWizard::kStagedVaultKeyCount - static_cast<int>(detected.size());
            m_wizard->m_hardware = std::move(detected);
            m_wizard->m_fixed_hardware_accounts = std::move(accounts);
            m_wizard->m_fixed_address_display_devices = std::move(address_display_devices);
            m_wizard->m_local_key_count = local_keys;
            if (local_keys > 0) m_wizard->m_last_local_key_count = local_keys;
            m_wizard->rebuildKeyList();
            local_count->blockSignals(true);
            local_count->setValue(local_keys);
            local_count->blockSignals(false);

            renderFixedRoster();
            updateLocalWarning();
            Q_EMIT completeChanged();
            return;
        }

        m_discovery_valid = true;
        m_discovery_error.clear();
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

    void renderFixedRoster()
    {
        m_wizard->rebuildKeyList();
        const auto& keys = m_wizard->keys();
        for (int slot = 0; slot < MultisigWizard::kStagedVaultKeyCount; ++slot) {
            if (slot >= static_cast<int>(keys.size())) {
                m_slot_primary[slot]->setText(tr("Unavailable"));
                m_slot_secondary[slot]->setText({});
                continue;
            }
            const auto& key = keys[static_cast<size_t>(slot)];
            if (key.fingerprint) {
                m_slot_primary[slot]->setText(QString::fromStdString(
                    key.label.empty() ? std::string{"Hardware wallet"} : key.label));
                m_slot_secondary[slot]->setText(tr("Fingerprint %1")
                    .arg(QString::fromStdString(*key.fingerprint)));
            } else {
                m_slot_primary[slot]->setText(tr("Software key"));
                m_slot_secondary[slot]->setText(tr("Stored in this wallet on this computer"));
            }
        }
    }
    MultisigWizard* m_wizard;
    QWidget* m_fixed_review{nullptr};
    QLineEdit* m_name{nullptr};
    QLabel* m_name_error{nullptr};
    QLabel* m_authority{nullptr};
    QWidget* m_fixed_roster{nullptr};
    std::array<QLabel*, MultisigWizard::kStagedVaultKeyCount> m_slot_primary{};
    std::array<QLabel*, MultisigWizard::kStagedVaultKeyCount> m_slot_secondary{};
    QLabel* m_discovery_status{nullptr};
    QPushButton* m_retry{nullptr};
    QLabel* m_technical{nullptr};
    QPushButton* m_restore{nullptr};
    QPushButton* m_advanced{nullptr};
    QLabel* m_plan{nullptr};
    QGroupBox* m_local_box{nullptr};
    QLabel* m_local_count_label{nullptr};
    QGroupBox* m_hardware_box{nullptr};
    QGroupBox* m_air_box{nullptr};
    QLabel* m_count{nullptr};
    QLabel* hw_empty{nullptr};
    QLabel* m_local_warning{nullptr};
    QCheckBox* m_local_risk{nullptr};
    bool m_discovery_valid{true};
    bool m_name_available{false};
    QString m_discovery_error;
    bool m_roster_initialized{false};
    std::vector<std::string> m_roster_signature;
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
        setSubTitle(tr("The importable policy JSON is saved automatically in the Bitcoin data directory. Print or copy it somewhere separate."));
        auto* layout = new QVBoxLayout(this);
        m_warning = new QLabel(tr(
            "Back up every signing source. If this wallet holds software keys, one separate wallet backup contains all of them. "
            "Also keep every hardware or offline seed, this public policy JSON, and any PINs or passphrases. "
            "The public policy cannot restore software keys or spend."));
        m_warning->setWordWrap(true);
        layout->addWidget(m_warning);
        m_tabs = new QTabWidget;
        m_tabs->setObjectName("backupTabs");
        policy = new QPlainTextEdit;
        policy->setObjectName("policyPackageEdit");
        policy->setReadOnly(true);
        policy->setFont(GUIUtil::fixedPitchFont());
        policy->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        m_tabs->addTab(policy, tr("Policy JSON (importable)"));
        human = new QPlainTextEdit;
        human->setObjectName("humanTranscriptEdit");
        human->setReadOnly(true);
        human->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        m_tabs->addTab(human, tr("Human transcript"));
        layout->addWidget(m_tabs);

        auto* policy_btns = new QHBoxLayout;
        m_copy_policy = new QPushButton(tr("Copy policy JSON"));
        m_copy_policy->setObjectName("copyPolicyButton");
        m_copy_policy->setAutoDefault(false);
        m_print_policy = new QPushButton(tr("Print recovery material…"));
        m_print_policy->setObjectName("printPolicyButton");
        m_print_policy->setAutoDefault(false);
        m_print_policy->setToolTip(tr("Create a printable PDF with the human transcript and exact importable JSON, then open it in your PDF viewer."));
        m_copy_human = new QPushButton(tr("Copy transcript"));
        m_copy_human->setObjectName("copyTranscriptButton");
        m_copy_human->setAutoDefault(false);
        m_save_human = new QPushButton(tr("Save transcript…"));
        m_save_human->setObjectName("saveTranscriptButton");
        m_save_human->setAutoDefault(false);
        policy_btns->addWidget(m_copy_policy);
        policy_btns->addWidget(m_print_policy);
        policy_btns->addWidget(m_copy_human);
        policy_btns->addWidget(m_save_human);
        policy_btns->addStretch();
        layout->addLayout(policy_btns);
        m_status = new QLabel;
        m_status->setObjectName("policyPackageStatus");
        m_status->setWordWrap(true);
        layout->addWidget(m_status);

        auto* path_row = new QHBoxLayout;
        m_path_caption = new QLabel(tr("Automatically saved JSON:"));
        path_row->addWidget(m_path_caption);
        m_policy_path = new QLabel;
        m_policy_path->setObjectName("policyPackagePathLabel");
        m_policy_path->setWordWrap(true);
        m_policy_path->setTextInteractionFlags(Qt::TextSelectableByMouse);
        path_row->addWidget(m_policy_path, 1);
        m_retry_policy_save = new QPushButton(tr("Retry automatic save"));
        m_retry_policy_save->setObjectName("retryPolicySaveButton");
        m_retry_policy_save->setAutoDefault(false);
        m_retry_policy_save->setVisible(false);
        path_row->addWidget(m_retry_policy_save);
        layout->addLayout(path_row);
        m_print_status = new QLabel;
        m_print_status->setObjectName("printPolicyStatus");
        m_print_status->setWordWrap(true);
        layout->addWidget(m_print_status);
        auto* wallet_backup_row = new QHBoxLayout;
        m_backup_wallet = new QPushButton(tr("Save software-key wallet backup…"));
        m_backup_wallet->setObjectName("backupSoftwareWalletButton");
        m_backup_wallet->setAutoDefault(false);
        m_wallet_backup_status = new QLabel;
        m_wallet_backup_status->setObjectName("softwareWalletBackupStatus");
        m_wallet_backup_status->setWordWrap(true);
        wallet_backup_row->addWidget(m_backup_wallet);
        wallet_backup_row->addWidget(m_wallet_backup_status, 1);
        layout->addLayout(wallet_backup_row);
        m_wallet_backup_ack = new QCheckBox;
        m_wallet_backup_ack->setObjectName("localWalletBackupAckCheck");
        layout->addWidget(m_wallet_backup_ack);

        m_ack_definition = new QLabel;
        m_ack_definition->setObjectName("backupAcknowledgmentDefinition");
        m_ack_definition->setWordWrap(true);
        layout->addWidget(m_ack_definition);
        ack = new QCheckBox(tr("I printed or copied the policy JSON somewhere I will still have if this computer is gone."));
        ack->setObjectName("backupAckCheck");
        layout->addWidget(ack);
        connect(m_copy_policy, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(policy->toPlainText());
        });
        connect(m_print_policy, &QPushButton::clicked, this, [this] { printRecoveryMaterial(); });
        connect(m_retry_policy_save, &QPushButton::clicked, this, [this] { refreshPackage(); });
        connect(m_copy_human, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(human->toPlainText());
        });
        connect(m_save_human, &QPushButton::clicked, this, [this] {
            saveText(tr("Save human transcript"), m_wizard->walletName() + QStringLiteral("-vault-transcript.txt"),
                     tr("Text files (*.txt)"), human->toPlainText());
        });
        connect(m_backup_wallet, &QPushButton::clicked, this, [this] { saveWalletBackup(); });
        connect(m_wallet_backup_ack, &QCheckBox::toggled, this, &QWizardPage::completeChanged);
        connect(ack, &QCheckBox::toggled, this, [this] {
            Q_EMIT completeChanged();
            if (m_wizard->advancedFlow()) return;
            const bool ready{isComplete()};
            m_print_policy->setDefault(!m_private_print_prepared || !m_print_opened);
            if (auto* next = qobject_cast<QPushButton*>(m_wizard->button(QWizard::NextButton))) {
                next->setDefault(ready);
            }
        });
    }

    ~MultisigBackupPage() override { removePrivatePrintFile(); }

    void initializePage() override
    {
        m_wizard->rebuildKeyList();
        const int local_count = m_wizard->localKeyCount();
        const bool needs_wallet_backup = local_count > 0;
        const bool simple = !m_wizard->advancedFlow();
        if (simple) {
            setTitle(tr("Secure Recovery"));
            setSubTitle(tr("Print one complete Recovery Kit before the vault is created."));
            m_warning->setText(tr(
                "<p><b>Private — this recovery kit can control your bitcoin.</b></p>"
                "<ol><li>Print every page.</li><li>Store the complete kit offline.</li>"
                "<li>Close the PDF viewer, then confirm.</li></ol>"
                "<p>Use a trusted local printer. PDF viewers, cloud services, printer memory, print queues, and caches may retain copies. Hardware-wallet seeds are not included.</p>"));
            m_warning->setTextFormat(Qt::RichText);
            ack->setText(tr("I understand"));
            ack->setToolTip(tr("Confirm the printed recovery kit is complete, legible, stored off this computer, and no longer open in the PDF viewer."));
            m_ack_definition->setText(tr("“I understand” confirms that every page was printed legibly, the complete kit is stored offline, any hardware-wallet seeds were backed up separately, and the PDF viewer is closed."));
        } else {
            setTitle(tr("Save the backup"));
            setSubTitle(tr("The importable policy JSON is saved automatically in the Bitcoin data directory. Print or copy it somewhere separate."));
            m_warning->setText(tr(
                "Back up every signing source. If this wallet holds software keys, one separate wallet backup contains all of them. "
                "Also keep every hardware or offline seed, this public policy JSON, and any PINs or passphrases. "
                "The public policy cannot restore software keys or spend."));
            ack->setText(tr("I printed or copied the policy JSON somewhere I will still have if this computer is gone."));
            ack->setToolTip({});
        }
        m_ack_definition->setVisible(simple);
        m_tabs->setVisible(!simple);
        m_copy_policy->setVisible(!simple);
        m_copy_human->setVisible(!simple);
        m_save_human->setVisible(!simple);
        m_status->setVisible(!simple);
        m_path_caption->setVisible(!simple);
        m_policy_path->setVisible(!simple);
        m_retry_policy_save->setVisible(false);
        m_backup_wallet->setVisible(!simple && needs_wallet_backup);
        m_wallet_backup_status->setVisible(!simple && needs_wallet_backup);
        m_wallet_backup_ack->setVisible(!simple && needs_wallet_backup);
        m_private_print_prepared = false;
        m_print_opened = false;
        m_private_print_cleanup_blocked = !removePrivatePrintFile();
        m_wallet_backup_saved = false;
        m_wallet_backup_ack->setChecked(false);
        m_wallet_backup_ack->setEnabled(false);
        m_wallet_backup_ack->setText(tr("I stored this unencrypted wallet backup somewhere separate and secure."));
        if (simple) {
            m_print_policy->setAutoDefault(true);
            updatePrivatePrintButton();
            m_print_policy->setToolTip(tr("Create and open one PDF containing the complete recovery kit."));
        } else {
            m_print_policy->setDefault(false);
            m_print_policy->setAutoDefault(false);
            m_print_policy->setText(tr("Print public recovery policy…"));
            m_print_policy->setToolTip(tr("Create a printable PDF with the human transcript and exact importable JSON, then open it in your PDF viewer."));
            if (needs_wallet_backup) {
                m_wallet_backup_status->setText(local_count == 1
                    ? tr("Required: save an unencrypted wallet-file backup containing this software key.")
                    : tr("Required: save an unencrypted wallet-file backup containing all %1 software keys.").arg(local_count));
            }
        }
        ack->setChecked(false);
        ack->setEnabled(false);
        m_print_status->clear();
        if (m_private_print_cleanup_blocked) {
            m_print_status->setText(tr("A previous private recovery PDF could not be deleted. Close its viewer, then press Continue again."));
        }
        refreshPackage();
        if (simple) {
            QTimer::singleShot(0, this, [this] {
                m_print_policy->setDefault(true);
                m_print_policy->setFocus(Qt::OtherFocusReason);
            });
        }
    }
    bool isComplete() const override
    {
        if (!m_wizard->advancedFlow()) {
            return m_package_valid && m_policy_auto_saved && m_private_print_prepared && m_print_opened && ack->isChecked();
        }
        const bool wallet_backup_complete = m_wallet_backup_saved && m_wallet_backup_ack->isChecked();
        const bool local_backup_complete = m_wizard->localKeyCount() == 0 || wallet_backup_complete;
        return !m_private_print_file && !m_private_print_cleanup_blocked && m_package_valid &&
            m_policy_auto_saved && ack->isChecked() && local_backup_complete;
    }
    bool validatePage() override
    {
        // The user may delete or replace the automatic copy while this page is
        // open. Recheck it at the navigation boundary instead of trusting the
        // cached result from initializePage().
        refreshPackage();
        if (!m_wizard->advancedFlow() && m_private_print_file) {
            if (!removePrivatePrintFile()) {
                m_private_print_cleanup_blocked = true;
                ack->setChecked(false);
                ack->setEnabled(true);
                m_print_status->setText(tr("Bitcoin Core could not delete the temporary private PDF. Close its viewer, check “I understand” again, then press Continue."));
                updatePrivatePrintButton();
                Q_EMIT completeChanged();
                return false;
            }
            m_private_print_cleanup_blocked = false;
            updatePrivatePrintButton();
        }
        if (!isComplete()) return false;
        if (!m_wizard->advancedFlow()) {
            if (!m_wizard->commitWalletCandidate()) {
                const QString commit_error{m_wizard->createError()};
                QMessageBox::critical(this, tr("Could not create vault"), commit_error);
                // The final name can lose a race after the Recovery Kit was
                // printed. Return to Review Vault so the user can choose a
                // new name; re-entering this page requires a fresh print and
                // acknowledgment while no partial wallet exists.
                QTimer::singleShot(0, m_wizard, [wizard = m_wizard, commit_error] {
                    wizard->back();
                    if (auto* keys = dynamic_cast<MultisigKeysPage*>(wizard->page(MultisigWizard::Page_Keys))) {
                        keys->showNameError(commit_error);
                    }
                });
                return false;
            }
            m_wizard->lockCommittedJourney();
        }
        return true;
    }
    int nextId() const override { return MultisigWizard::Page_Verify; }

private:
    void updatePrivatePrintButton()
    {
        if (m_wizard->advancedFlow()) return;
        m_print_policy->setText(tr("Print PDF…"));
        const bool needs_private_recovery = m_wizard->localKeyCount() > 0;
        const bool have_private_recovery = !needs_private_recovery ||
            m_wizard->m_software_recovery.size() == static_cast<size_t>(m_wizard->localKeyCount());
        m_print_policy->setEnabled(m_package_valid && have_private_recovery);
    }

    bool removePrivatePrintFile()
    {
        if (!m_private_print_file) {
            m_private_print_lock.reset();
            return true;
        }
        const QString path{m_private_print_file->fileName()};
        m_private_print_file->close();
        if (QFileInfo::exists(path) && !m_private_print_file->remove()) return false;
        if (QFileInfo::exists(path)) return false;
        m_private_print_file.reset();
        m_private_print_lock.reset();
        return true;
    }

    void saveWalletBackup()
    {
        WalletModel* const wallet_model = m_wizard->createdWallet();
        if (!wallet_model) {
            QMessageBox::critical(this, tr("Backup failed"), tr("The wallet is not available."));
            return;
        }
        const QString suggested = m_wizard->walletName() + QStringLiteral("-software-keys-wallet.dat");
        const QString path = QFileDialog::getSaveFileName(this, tr("Save software-key wallet backup"), suggested,
                                                          tr("Wallet data (*.dat)"));
        if (path.isEmpty()) return;
        if (!wallet_model->wallet().backupWallet(path.toLocal8Bit().constData())) {
            QMessageBox::critical(this, tr("Backup failed"),
                                  tr("There was an error saving the wallet backup to %1.").arg(path));
            return;
        }
        m_wallet_backup_saved = true;
        m_wallet_backup_status->setText(tr("Wallet backup saved to %1.").arg(QDir::toNativeSeparators(path)));
        m_wallet_backup_ack->setEnabled(true);
        Q_EMIT completeChanged();
    }

    bool savePolicyAutomatically(const wallet::VaultPolicyPackage& package, QString& error)
    {
        if (package.policy_id.empty() || !IsHex(package.policy_id)) {
            error = tr("The policy ID is invalid, so no automatic backup path can be created.");
            return false;
        }
        const QString filename = QStringLiteral("vault-policy-%1.json").arg(QString::fromStdString(package.policy_id));
        m_policy_file = QDir(GUIUtil::PathToQString(gArgs.GetDataDirNet())).filePath(filename);
        m_policy_path->setText(QDir::toNativeSeparators(m_policy_file));
        const QByteArray encoded = policy->toPlainText().toUtf8();

        // Serialize cooperating GUI instances so the existence check and the
        // atomic replacement cannot race one another.
        QLockFile lock(m_policy_file + QStringLiteral(".lock"));
        if (!lock.tryLock()) {
            error = tr("Another Bitcoin process is saving this policy. Wait a moment, then retry.");
            return false;
        }

        QFile existing(m_policy_file);
        const QFileInfo info(m_policy_file);
        if (info.isSymLink()) {
            error = tr("The policy path is a symbolic link. It was not changed.");
            return false;
        }
        if (existing.exists()) {
            if (!info.isFile()) {
                error = tr("The policy path is not a regular file. It was not changed.");
                return false;
            }
            if (info.size() != encoded.size()) {
                error = tr("A different file already exists at this policy path. It was not overwritten. Move or inspect it, then retry.");
                return false;
            }
            if (!existing.open(QIODevice::ReadOnly)) {
                error = tr("Could not read the existing policy file: %1").arg(existing.errorString());
                return false;
            }
            const QByteArray current = existing.readAll();
            if (existing.error() != QFileDevice::NoError) {
                error = tr("Could not verify the existing policy file: %1").arg(existing.errorString());
                return false;
            }
            if (current != encoded) {
                error = tr("A different file already exists at this policy path. It was not overwritten. Move or inspect it, then retry.");
                return false;
            }
            return true;
        }

        QSaveFile file(m_policy_file);
        if (!file.open(QIODevice::WriteOnly)) {
            error = file.errorString();
            return false;
        }
        file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        if (file.write(encoded) != encoded.size()) {
            error = file.errorString();
            file.cancelWriting();
            return false;
        }
        if (!file.commit()) {
            error = file.errorString();
            return false;
        }

        QFile verify(m_policy_file);
        if (!verify.open(QIODevice::ReadOnly) || verify.readAll() != encoded || verify.error() != QFileDevice::NoError) {
            error = tr("The policy file could not be verified after saving.");
            return false;
        }
        return true;
    }

    void printRecoveryMaterial()
    {
        if (!m_wizard->advancedFlow()) {
            // The same sole action retries the automatic policy save before
            // printing, so the simplified page needs no separate retry button.
            refreshPackage();
            if (!m_package_valid || !m_policy_auto_saved) return;
            auto package = wallet::ParseVaultPolicyPackage(m_wizard->m_policy_package.toStdString());
            if (!package) {
                m_print_status->setText(QString::fromStdString(util::ErrorString(package).original));
                return;
            }
            auto fixed_policy = wallet::ValidateFixedStagedVaultPolicy(*package);
            if (!fixed_policy) {
                m_print_status->setText(QString::fromStdString(util::ErrorString(fixed_policy).original));
                return;
            }
        }
        if (!m_package_valid || m_policy_id.isEmpty()) return;
        if (!m_wizard->advancedFlow()) {
            printPrivateRecoveryKit();
            return;
        }
#ifndef QT_NO_PDF
        if (!m_wizard->advancedFlow()) {
            m_private_print_prepared = false;
            m_print_opened = false;
            ack->setChecked(false);
            ack->setEnabled(false);
        }
        const QString pdf_path = QDir(GUIUtil::PathToQString(gArgs.GetDataDirNet())).filePath(
            QStringLiteral("vault-policy-%1-printable.pdf").arg(m_policy_id));
        QSaveFile file(pdf_path);
        if (!file.open(QIODevice::WriteOnly)) {
            QMessageBox::critical(this, tr("Print failed"), file.errorString());
            return;
        }
        file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        {
            QPdfWriter writer(&file);
            writer.setTitle(tr("Scrooge Vault recovery material"));
            writer.setCreator(QStringLiteral("Bitcoin Core"));
            QTextDocument document;
            document.setPlainText(
                human->toPlainText().trimmed() +
                QStringLiteral("\n\n========================================\n") +
                tr("IMPORTABLE POLICY JSON") +
                QStringLiteral("\n========================================\n") +
                policy->toPlainText().trimmed() + QLatin1Char('\n'));
            document.print(&writer);
        }
        if (file.error() != QFileDevice::NoError || !file.commit()) {
            QMessageBox::critical(this, tr("Print failed"), file.errorString());
            return;
        }
        const bool opened = QDesktopServices::openUrl(QUrl::fromLocalFile(pdf_path));
        if (!opened) {
            QMessageBox::warning(this, tr("Open printable PDF"),
                                 tr("The PDF was saved, but no PDF viewer could be opened. Open it manually at %1.")
                                     .arg(QDir::toNativeSeparators(pdf_path)));
        }
        if (!m_wizard->advancedFlow()) {
            m_private_print_prepared = true;
            if (opened) {
                m_print_opened = true;
                ack->setEnabled(true);
                m_print_status->setText(tr("The recovery PDF was validated and opened. Print every page, close the viewer, then check “I understand”."));
            } else {
                m_print_status->setText(tr("The recovery PDF was validated but could not be opened. Press “Print PDF” to retry after configuring a PDF viewer."));
            }
            Q_EMIT completeChanged();
        } else {
            m_print_status->setText(tr("Printable PDF saved to %1. Opening it in your PDF viewer; use its Print command.")
                                        .arg(QDir::toNativeSeparators(pdf_path)));
        }
#else
        if (!m_wizard->advancedFlow()) {
            QMessageBox::critical(this, tr("PDF printing unavailable"),
                                  tr("This build cannot create the required recovery PDF."));
            return;
        }
        const QString html_path = QDir(GUIUtil::PathToQString(gArgs.GetDataDirNet())).filePath(
            QStringLiteral("vault-policy-%1-printable.html").arg(m_policy_id));
        QSaveFile file(html_path);
        if (!file.open(QIODevice::WriteOnly)) {
            QMessageBox::critical(this, tr("Print failed"), file.errorString());
            return;
        }
        file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        const QString printable = QStringLiteral("<!doctype html><meta charset=\"utf-8\"><title>%1</title><pre>%2\n\n%3\n%4</pre>")
            .arg(tr("Scrooge Vault recovery material").toHtmlEscaped(),
                 human->toPlainText().toHtmlEscaped(),
                 tr("IMPORTABLE POLICY JSON").toHtmlEscaped(),
                 policy->toPlainText().toHtmlEscaped());
        const QByteArray encoded = printable.toUtf8();
        if (file.write(encoded) != encoded.size() || !file.commit()) {
            file.cancelWriting();
            QMessageBox::critical(this, tr("Print failed"), file.errorString());
            return;
        }
        m_print_status->setText(tr("Printable page saved to %1. Opening it in your browser; use its Print command.")
                                    .arg(QDir::toNativeSeparators(html_path)));
        if (!QDesktopServices::openUrl(QUrl::fromLocalFile(html_path))) {
            QMessageBox::warning(this, tr("Open printable page"),
                                 tr("The printable page was saved, but no browser could be opened. Open it manually at %1.")
                                     .arg(QDir::toNativeSeparators(html_path)));
        }
#endif
    }

    void printPrivateRecoveryKit()
    {
#ifndef QT_NO_PDF
        const int local_count = m_wizard->localKeyCount();
        if (local_count < 0 || m_wizard->m_software_recovery.size() != static_cast<size_t>(local_count)) {
            QMessageBox::critical(this, tr("Print failed"),
                                  tr("The software-key recovery material is incomplete, so the recovery PDF cannot be created."));
            return;
        }

        // A complete kit is deliberately a single printable bearer document.
        // Reuse it rather than ever creating a second managed private copy.
        if (m_private_print_file) {
            if (m_private_print_cleanup_blocked && !m_private_print_prepared) {
                if (!removePrivatePrintFile()) {
                    m_print_status->setText(tr("Bitcoin Core still cannot delete the failed temporary private PDF. Close any viewer, then press “Print PDF” to retry cleanup."));
                } else {
                    m_private_print_cleanup_blocked = false;
                    m_print_status->setText(tr("The failed temporary private PDF was deleted. Press “Print PDF” again to create a fresh recovery kit."));
                }
                updatePrivatePrintButton();
                Q_EMIT completeChanged();
                return;
            }
            const QString pdf_path{m_private_print_file->fileName()};
            if (!QFileInfo::exists(pdf_path)) {
                m_private_print_file.reset();
                m_private_print_lock.reset();
                m_private_print_prepared = false;
                m_print_opened = false;
                m_private_print_cleanup_blocked = false;
                ack->setChecked(false);
                ack->setEnabled(false);
                m_print_status->setText(tr("The temporary recovery PDF is no longer available. Print it again."));
                updatePrivatePrintButton();
                Q_EMIT completeChanged();
                return;
            }
            ack->setChecked(false);
            ack->setEnabled(false);
            m_print_opened = false;
            const bool opened = QDesktopServices::openUrl(QUrl::fromLocalFile(pdf_path));
            if (!opened) {
                QMessageBox::warning(this, tr("Open recovery PDF"),
                                     tr("No PDF viewer could be opened. Open the existing recovery PDF manually at %1.")
                                         .arg(QDir::toNativeSeparators(pdf_path)));
            } else {
                m_print_opened = true;
                ack->setEnabled(true);
            }
            if (!opened) {
                m_print_status->setText(tr("The existing recovery PDF could not be opened. Press “Print PDF” to retry after configuring a PDF viewer."));
            } else if (m_private_print_cleanup_blocked) {
                m_print_status->setText(tr("The same PDF was reopened. Close its viewer, check “I understand” again, then press Continue so Bitcoin Core can delete the temporary file."));
            } else {
                m_print_status->setText(tr("The same complete recovery PDF was reopened. Print every page; no second private copy was created."));
            }
            Q_EMIT completeChanged();
            return;
        }

        // A new print invalidates the sole acknowledgment. The checkbox is
        // enabled only after Core has validated and opened the complete PDF.
        m_private_print_prepared = false;
        m_print_opened = false;
        m_private_print_cleanup_blocked = false;
        ack->setChecked(false);
        ack->setEnabled(false);
        const QString private_dir_path{QDir::temp().filePath(QStringLiteral("bitcoin-core-vault-recovery"))};
        const QFileInfo private_dir_info{private_dir_path};
        if (private_dir_info.isSymLink() ||
            (!private_dir_info.exists() && !QDir{}.mkpath(private_dir_path)) ||
            !QFileInfo{private_dir_path}.isDir() ||
            !QFile::setPermissions(private_dir_path, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)) {
            QMessageBox::critical(this, tr("Print failed"),
                                  tr("Bitcoin Core could not create a private owner-only recovery-print directory."));
            return;
        }

        // Serialize stale-file scavenging with creation. A live PDF owns its
        // adjacent lock; a PDF left by a crashed process is removed before a
        // new bearer document is created.
        QLockFile cleanup_lock{QDir{private_dir_path}.filePath(QStringLiteral("cleanup.lock"))};
        cleanup_lock.setStaleLockTime(0);
        if (!cleanup_lock.tryLock()) {
            QMessageBox::critical(this, tr("Print failed"),
                                  tr("Another Bitcoin Core process is preparing recovery material. Wait, then retry."));
            return;
        }
        QDir private_dir{private_dir_path};
        const auto stale_cleanup_failed = [this](const QString& detail) {
            m_private_print_cleanup_blocked = true;
            m_print_status->setText(tr("Bitcoin Core found an existing private recovery PDF and could not confirm its deletion. No new PDF was created. Close any other recovery wizard, then press “Print PDF” to retry cleanup."));
            updatePrivatePrintButton();
            Q_EMIT completeChanged();
            QMessageBox::critical(this, tr("Print failed"), detail);
        };
        for (const QString& stale_name : private_dir.entryList({QStringLiteral("*.pdf")}, QDir::Files)) {
            const QString stale_path{private_dir.filePath(stale_name)};
            QLockFile stale_lock{stale_path + QStringLiteral(".lock")};
            stale_lock.setStaleLockTime(0);
            if (!stale_lock.tryLock()) {
                if (QFileInfo::exists(stale_path)) {
                    stale_cleanup_failed(tr("An existing private recovery PDF is still owned by another Bitcoin Core process. No new recovery PDF was created."));
                    return;
                }
                continue;
            }
            const bool removed{m_wizard->removePrivatePrintPath(stale_path)};
            const bool still_exists{QFileInfo::exists(stale_path)};
            stale_lock.unlock();
            if (!removed || still_exists) {
                stale_cleanup_failed(tr("Bitcoin Core could not delete an existing temporary private recovery PDF. No new recovery PDF was created."));
                return;
            }
        }

        auto output = std::make_unique<QTemporaryFile>(
            private_dir.filePath(QStringLiteral("complete-recovery-XXXXXX.pdf")));
        output->setAutoRemove(true);
        if (!output->open()) {
            QMessageBox::critical(this, tr("Print failed"), output->errorString());
            return;
        }
        const QString pdf_path = output->fileName();
        auto private_lock = std::make_unique<QLockFile>(pdf_path + QStringLiteral(".lock"));
        private_lock->setStaleLockTime(0);
        if (!private_lock->tryLock()) {
            output->close();
            output->remove();
            QMessageBox::critical(this, tr("Print failed"),
                                  tr("The temporary recovery PDF could not be exclusively locked."));
            return;
        }
        cleanup_lock.unlock();
        const auto fail_private_pdf = [&](const QString& detail) {
            output->close();
            const bool removed = !QFileInfo::exists(pdf_path) || output->remove();
            if (!removed || QFileInfo::exists(pdf_path)) {
                m_private_print_file = std::move(output);
                m_private_print_lock = std::move(private_lock);
                m_private_print_cleanup_blocked = true;
                m_print_status->setText(tr("PDF creation failed, and Bitcoin Core could not delete its temporary private file. Close any viewer, then press “Print PDF” to retry cleanup."));
            }
            updatePrivatePrintButton();
            Q_EMIT completeChanged();
            QMessageBox::critical(this, tr("Print failed"), detail);
        };
        if (!QFile::setPermissions(pdf_path, QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
            fail_private_pdf(tr("The temporary recovery PDF could not be restricted to the current user."));
            return;
        }
        QString html = m_wizard->privateRecoveryKitHtml();
        if (html.isEmpty()) {
            fail_private_pdf(tr("The complete private recovery kit could not be validated."));
            return;
        }
        auto qr_parts = wallet::EncodeVaultPolicyQrParts(m_wizard->m_policy_package.toStdString());
        if (!qr_parts) {
            html.fill(QChar{0});
            fail_private_pdf(tr("The public-policy QR parts could not be validated."));
            return;
        }
        constexpr int qr_parts_per_page{2};
        const int expected_pages = local_count + 3 +
            (static_cast<int>(qr_parts->size()) + qr_parts_per_page - 1) / qr_parts_per_page;

        bool rendered{false};
        int rendered_pages{0};
        {
            QPdfWriter writer(output.get());
            writer.setTitle(tr("Complete private Scrooge Vault recovery kit"));
            writer.setCreator(QStringLiteral("Bitcoin Core"));
            writer.setResolution(144);
            writer.setPageSize(QPageSize{QPageSize::A4});
            writer.setPageMargins(QMarginsF{12, 12, 12, 12}, QPageLayout::Millimeter);
            QTextDocument document;
            document.setHtml(html);
            document.setPageSize(QSizeF{static_cast<qreal>(writer.width()), static_cast<qreal>(writer.height())});
            rendered_pages = document.pageCount();
            document.print(&writer);
            document.clear();
            rendered = true;
        }
        const bool device_ok = output->flush() && output->error() == QFileDevice::NoError;
        output->close();
        html.fill(QChar{0});

        if (rendered_pages != expected_pages) {
            fail_private_pdf(tr("The recovery kit rendered as %1 pages instead of the required %2 pages. Check the page layout and retry.")
                                 .arg(rendered_pages)
                                 .arg(expected_pages));
            return;
        }
        if (!rendered || !device_ok || !QFile::setPermissions(pdf_path, QFileDevice::ReadOwner | QFileDevice::WriteOwner) ||
            QFileInfo{pdf_path}.size() < 100) {
            fail_private_pdf(tr("The private recovery PDF could not be created securely."));
            return;
        }
        QFile verify_pdf{pdf_path};
        if (!verify_pdf.open(QIODevice::ReadOnly) || verify_pdf.read(5) != QByteArray{"%PDF-"} ||
            !verify_pdf.seek(std::max<qint64>(0, verify_pdf.size() - 128)) ||
            !verify_pdf.read(128).contains("%%EOF")) {
            verify_pdf.close();
            fail_private_pdf(tr("The private recovery PDF failed its integrity check."));
            return;
        }
        verify_pdf.close();
        m_private_print_file = std::move(output);
        m_private_print_lock = std::move(private_lock);
        m_private_print_prepared = true;
        updatePrivatePrintButton();
        const bool opened = QDesktopServices::openUrl(QUrl::fromLocalFile(pdf_path));
        if (!opened) {
            QMessageBox::warning(this, tr("Open complete private recovery kit"),
                                 tr("The private PDF was created, but no PDF viewer could be opened. Open it manually at %1 before leaving this wizard.")
                                     .arg(QDir::toNativeSeparators(pdf_path)));
            m_print_status->setText(tr("The complete recovery PDF was validated but could not be opened. Press “Print PDF” to retry after configuring a PDF viewer."));
        } else {
            m_print_opened = true;
            ack->setEnabled(true);
            m_print_status->setText(local_count == 0
                ? tr("The complete recovery PDF was validated and opened with restore instructions and the exact public policy. It contains no hardware-wallet seeds. Print every page, close the viewer, then check “I understand”.")
                : local_count == 1
                    ? tr("The complete recovery PDF was validated and opened with the software-key mnemonic, instructions, and exact policy JSON. Print every page, close the viewer, then check “I understand”.")
                    : tr("The complete recovery PDF was validated and opened with all %1 software-key mnemonics, instructions, and exact policy JSON. Print every page, close the viewer, then check “I understand”.").arg(local_count));
        }
        Q_EMIT completeChanged();
#else
        QMessageBox::critical(this, tr("Private printing unavailable"),
                              tr("This Qt build cannot create the required private recovery PDF."));
#endif
    }

    void saveText(const QString& title, const QString& suggested, const QString& filter, const QString& contents)
    {
        const QString path = QFileDialog::getSaveFileName(this, title, suggested, filter);
        if (path.isEmpty()) return;
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly)) {
            QMessageBox::critical(this, tr("Save failed"), file.errorString());
            return;
        }
        const QByteArray encoded = contents.toUtf8();
        if (file.write(encoded) != encoded.size()) {
            file.cancelWriting();
            QMessageBox::critical(this, tr("Save failed"), file.errorString());
            return;
        }
        if (!file.commit()) {
            QMessageBox::critical(this, tr("Save failed"), file.errorString());
        }
    }

    void refreshPackage()
    {
        const bool simple = !m_wizard->advancedFlow();
        policy->setPlainText(m_wizard->m_policy_package);
        human->setPlainText(m_wizard->transcript());
        m_package_valid = false;
        m_policy_auto_saved = false;
        m_policy_id.clear();
        m_policy_file.clear();
        m_policy_path->clear();
        m_retry_policy_save->setVisible(false);
        if (!m_wizard->m_policy_package.isEmpty()) {
            auto parsed = wallet::ParseVaultPolicyPackage(m_wizard->m_policy_package.toStdString());
            if (!parsed) {
                m_status->setText(QString::fromStdString(util::ErrorString(parsed).original));
                if (simple) m_print_status->setText(m_status->text());
            } else {
                QString public_error;
                m_package_valid = PublicOnlyPolicy(*parsed, public_error);
                if (!m_package_valid) {
                    m_status->setText(public_error);
                    if (simple) m_print_status->setText(public_error);
                } else {
                    m_policy_id = QString::fromStdString(parsed->policy_id);
                    QString save_error;
                    m_policy_auto_saved = savePolicyAutomatically(*parsed, save_error);
                    if (m_policy_auto_saved) {
                        m_status->setText(tr("This JSON contains public descriptors and no private keys. The automatic copy is on this computer; print or copy it elsewhere."));
                        if (simple && !m_private_print_prepared && !m_private_print_cleanup_blocked) {
                            m_print_status->setText(tr("Ready. Print the complete recovery PDF, inspect every page, then confirm “I understand”."));
                        }
                    } else {
                        m_status->setText(tr("Automatic policy save failed: %1").arg(save_error));
                        if (simple) {
                            m_print_status->setText(tr("Automatic policy save failed: %1 Press “Print PDF” to retry.").arg(save_error));
                        } else {
                            m_retry_policy_save->setVisible(true);
                        }
                    }
                }
            }
        }
        if (m_wizard->m_policy_package.isEmpty()) {
            m_status->setText(tr("No valid policy package is available."));
            if (simple) m_print_status->setText(m_status->text());
        }
        m_copy_policy->setEnabled(m_package_valid);
        const bool needs_private_recovery = !m_wizard->advancedFlow() && m_wizard->localKeyCount() > 0;
        const bool have_private_recovery = !needs_private_recovery ||
            m_wizard->m_software_recovery.size() == static_cast<size_t>(m_wizard->localKeyCount());
        if (simple) {
            updatePrivatePrintButton();
            if (!have_private_recovery) m_print_policy->setEnabled(false);
        } else if (needs_private_recovery) {
            updatePrivatePrintButton();
            if (!have_private_recovery) m_print_policy->setEnabled(false);
        } else {
            m_print_policy->setEnabled(m_package_valid);
        }
        if (m_package_valid && !have_private_recovery) {
            m_print_status->setText(simple
                ? tr("The private recovery phrases are not available. This wallet cannot complete the printable recovery kit.")
                : tr("The private recovery phrases are not available. Save a software-key wallet backup instead."));
        }
        ack->setEnabled(simple
            ? m_package_valid && m_policy_auto_saved && m_private_print_prepared && m_print_opened
            : m_package_valid && m_policy_auto_saved);
        if (!m_package_valid || !m_policy_auto_saved) ack->setChecked(false);
        Q_EMIT completeChanged();
    }
    MultisigWizard* m_wizard;
    QLabel* m_warning{nullptr};
    QLabel* m_ack_definition{nullptr};
    QTabWidget* m_tabs{nullptr};
    QPushButton* m_copy_policy{nullptr};
    QPushButton* m_copy_human{nullptr};
    QPushButton* m_save_human{nullptr};
    QPushButton* m_print_policy{nullptr};
    QLabel* m_status{nullptr};
    QLabel* m_path_caption{nullptr};
    QLabel* m_policy_path{nullptr};
    QPushButton* m_retry_policy_save{nullptr};
    QLabel* m_print_status{nullptr};
    QPushButton* m_backup_wallet{nullptr};
    QLabel* m_wallet_backup_status{nullptr};
    QCheckBox* m_wallet_backup_ack{nullptr};
    bool m_wallet_backup_saved{false};
    bool m_private_print_prepared{false};
    bool m_print_opened{false};
    bool m_private_print_cleanup_blocked{false};
    bool m_package_valid{false};
    bool m_policy_auto_saved{false};
    QString m_policy_id;
    QString m_policy_file;
    std::unique_ptr<QTemporaryFile> m_private_print_file;
    std::unique_ptr<QLockFile> m_private_print_lock;
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
        setSubTitle(tr("Check that each connected device derives the key used in this address before the first receive."));
        auto* layout = new QVBoxLayout(this);
        auto* row = new QHBoxLayout;
        qr = new QRImageWidget;
        qr->setObjectName("verifyQr");
        qr->setAlignment(Qt::AlignCenter);
        qr->setFixedSize(220, 220);
        row->addWidget(qr, 0, Qt::AlignTop);

        auto* addr_col = new QVBoxLayout;
        addr_col->addWidget(new QLabel(tr("Receive address")));
        address = new QLineEdit;
        address->setObjectName("verifyAddressEdit");
        address->setReadOnly(true);
        address->setFont(GUIUtil::fixedPitchFont());
        addr_col->addWidget(address);
        auto* copy = new QPushButton(tr("Copy Address"));
        copy->setObjectName("copyAddressButton");
        copy->setAutoDefault(false);
        addr_col->addWidget(copy, 0, Qt::AlignLeft);
        addr_col->addStretch();
        row->addLayout(addr_col, 1);
        layout->addLayout(row);

        devices = new QListWidget;
        devices->setObjectName("verifyDeviceList");
        devices->setMaximumHeight(96);
        devices->setSelectionMode(QAbstractItemView::NoSelection);
        m_devices_empty = new QLabel(tr("No hardware verification is required for this wallet."));
        m_devices_empty->setWordWrap(true);
        m_devices_empty->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(m_devices_empty);
        layout->addWidget(devices);
        auto* show = new QPushButton(tr("Check selected device key"));
        show->setObjectName("showOnDeviceButton");
        show->setAutoDefault(false);
        layout->addWidget(show, 0, Qt::AlignLeft);
        m_show_button = show;
        status = new QLabel;
        status->setObjectName("verifyStatusLabel");
        status->setWordWrap(true);
        layout->addWidget(status);
        m_independent_state = new QLabel;
        m_independent_state->setObjectName("independentVerificationState");
        m_independent_state->setWordWrap(true);
        setIndependentState({}, /*warning=*/false);
        layout->addWidget(m_independent_state);
        m_import_policy = new QPushButton(tr("Verify with Imported Policy…"));
        m_import_policy->setObjectName("verifyImportedPolicyButton");
        m_import_policy->setAutoDefault(false);
        layout->addWidget(m_import_policy, 0, Qt::AlignLeft);
        m_airgap_help = new QLabel(tr(
            "Air-gapped keys cannot display here. Import this address into the offline signer and confirm it matches."));
        m_airgap_help->setObjectName("airgapVerifyHelp");
        m_airgap_help->setWordWrap(true);
        m_airgap_help->setStyleSheet(QStringLiteral("QLabel { color: palette(window-text); }"));
        layout->addWidget(m_airgap_help);
        m_airgap_ack = new QCheckBox(tr("I compared this address on each offline signer."));
        m_airgap_ack->setObjectName("airgapVerifyCheck");
        layout->addWidget(m_airgap_ack);
        m_local_ack = new QCheckBox(tr("I understand no independent device verified this address."));
        m_local_ack->setObjectName("localOnlyVerifyCheck");
        layout->addWidget(m_local_ack);
        layout->addStretch();
        connect(m_airgap_ack, &QCheckBox::toggled, this, &QWizardPage::completeChanged);
        connect(m_local_ack, &QCheckBox::toggled, this, &QWizardPage::completeChanged);
        connect(m_import_policy, &QPushButton::clicked, this, [this] {
            const QString path = QFileDialog::getOpenFileName(
                this, tr("Open an independent public policy"), {}, tr("JSON files (*.json);;All files (*)"));
            if (path.isEmpty()) return;
            QFile file(path);
            if (!file.open(QIODevice::ReadOnly) || file.size() > 1024 * 1024) {
                status->setText(tr("Could not read a policy JSON smaller than 1 MiB from that file."));
                return;
            }
            const QByteArray bytes = file.readAll();
            auto decoded = DecodeVaultPolicyInput(QString::fromUtf8(bytes));
            if (!decoded) {
                status->setText(QString::fromStdString(util::ErrorString(decoded).original));
                return;
            }
            auto imported = wallet::ParseVaultPolicyPackage(*decoded);
            auto expected = wallet::ParseVaultPolicyPackage(m_wizard->m_policy_package.toStdString());
            if (!imported || !expected || imported->policy_id != expected->policy_id ||
                imported->descs != expected->descs ||
                wallet::FormatVaultPolicyPackage(*imported) != wallet::FormatVaultPolicyPackage(*expected)) {
                status->setText(tr("That policy does not reproduce this vault exactly."));
                return;
            }
            auto independently_derived = FirstDescriptorDestination(imported->descs.front());
            if (!independently_derived ||
                QString::fromStdString(EncodeDestination(*independently_derived)) != address->text()) {
                status->setText(tr("That policy does not derive the receive address shown here."));
                return;
            }
            m_wizard->m_address_independently_verified = true;
            setIndependentState(tr("Independently verified with the imported public policy."), /*warning=*/false);
            Q_EMIT completeChanged();
        });
        connect(copy, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(address->text());
            status->setText(tr("Address copied."));
        });
        connect(show, &QPushButton::clicked, this, [this] {
            QListWidgetItem* item{nullptr};
            for (int row = 0; row < devices->count(); ++row) {
                const std::string fingerprint = devices->item(row)->data(Qt::UserRole).toString().toStdString();
                if (!m_verified_hardware.count(fingerprint)) {
                    item = devices->item(row);
                    break;
                }
            }
            if (!item || !(item->flags() & Qt::ItemIsEnabled)) {
                status->setText(tr("Every connected device has completed its check."));
                return;
            }
            const std::string fpr = item->data(Qt::UserRole).toString().toStdString();
            auto res = m_wizard->verifyOnDevice(fpr);
            if (res) {
                status->setText(tr("The address shown on the physical device matches this wallet."));
                m_verified_hardware.insert(fpr);
                item->setText(QStringLiteral("✓ ") + item->data(Qt::UserRole + 1).toString());
                if (m_verified_hardware.size() == static_cast<size_t>(devices->count())) {
                    m_wizard->m_address_independently_verified = true;
                    setIndependentState(tr("Verified by every connected hardware wallet."), /*warning=*/false);
                } else {
                    updateNextDeviceButton();
                }
            } else {
                status->setText(QString::fromStdString(util::ErrorString(res).original));
            }
            Q_EMIT completeChanged();
        });
    }
    void initializePage() override
    {
        m_verified_hardware.clear();
        m_wizard->m_address_independently_verified = false;
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
                qr->setPixmap(qr->pixmap(Qt::ReturnByValue).scaled(220, 220, Qt::KeepAspectRatio, Qt::SmoothTransformation));
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
            if (!m_wizard->advancedFlow() &&
                !m_wizard->m_fixed_address_display_devices.contains(*k.fingerprint)) {
                continue;
            }
            const QString item_text = QString::fromStdString(k.label.empty() ? *k.fingerprint : k.label + " (" + *k.fingerprint + ")");
            auto* item = new QListWidgetItem(item_text);
            item->setData(Qt::UserRole, QString::fromStdString(*k.fingerprint));
            item->setData(Qt::UserRole + 1, item_text);
            item->setFlags(item->flags() & ~Qt::ItemIsUserCheckable);
            devices->addItem(item);
        }
        const bool have_hw = devices->count() > 0;
        const bool local_only = !have_hw && !has_airgap && m_wizard->localKeyCount() > 0;
        devices->setVisible(have_hw);
        m_devices_empty->setVisible(!have_hw && !has_airgap);
        m_devices_empty->setText(local_only
            ? tr("No independent signer can verify this address. All software keys are stored in this wallet on this computer.")
            : (!m_wizard->advancedFlow() && !m_wizard->m_hardware.empty()
                  ? tr("The connected hardware wallets can sign this vault, but none reports a physical multisig-address display capability.")
                  : tr("No hardware verification is required for this wallet.")));
        if (m_show_button) m_show_button->setVisible(have_hw);
        m_airgap_help->setVisible(m_wizard->advancedFlow() && has_airgap);
        m_airgap_ack->blockSignals(true);
        m_airgap_ack->setVisible(m_wizard->advancedFlow() && has_airgap);
        m_airgap_ack->setChecked(false);
        m_airgap_ack->blockSignals(false);
        m_local_ack->blockSignals(true);
        m_local_ack->setVisible(m_wizard->advancedFlow() && local_only);
        m_local_ack->setChecked(false);
        m_local_ack->blockSignals(false);
        if (!m_wizard->advancedFlow()) {
            setTitle(have_hw ? tr("Verify Your First Address") : tr("Review Your First Address"));
            setSubTitle(have_hw
                ? tr("Check the same address on each device, one at a time.")
                : tr("This computer cannot independently prove the address. Review it before funding."));
            m_independent_state->setVisible(true);
            setIndependentState(have_hw ? tr("Waiting for the first hardware-wallet check.")
                                        : tr("Not independently verified"),
                                /*warning=*/!have_hw);
            m_import_policy->setVisible(!have_hw);
            updateNextDeviceButton();
        } else {
            setTitle(tr("Verify the first address"));
            setSubTitle(local_only
                ? tr("Review the address carefully. A separate watch-only import or device is needed for independent verification.")
                : tr("Check that each connected device derives the key used in this address. Also compare the address independently before funding."));
            m_independent_state->setVisible(false);
            m_import_policy->setVisible(false);
        }
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
        if (m_wizard->advancedFlow() && has_airgap) return m_airgap_ack && m_airgap_ack->isChecked();
        // QWizard evaluates completeness while the page itself is still
        // hidden. isVisible() would therefore be false even though this gate
        // is explicitly shown for the page.
        if (m_wizard->advancedFlow() && m_local_ack && !m_local_ack->isHidden()) return m_local_ack->isChecked();
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
    void setIndependentState(const QString& text, bool warning)
    {
        m_independent_state->setText(text);
        m_independent_state->setContentsMargins(10, 10, 10, 10);
        m_independent_state->setAutoFillBackground(true);
        m_independent_state->setBackgroundRole(warning ? QPalette::ToolTipBase : QPalette::AlternateBase);
        m_independent_state->setForegroundRole(warning ? QPalette::ToolTipText : QPalette::WindowText);
    }

    void updateNextDeviceButton()
    {
        if (!m_show_button || devices->count() == 0) return;
        for (int row = 0; row < devices->count(); ++row) {
            auto* item = devices->item(row);
            const std::string fingerprint = item->data(Qt::UserRole).toString().toStdString();
            if (!m_verified_hardware.count(fingerprint)) {
                m_show_button->setText(tr("Verify on %1").arg(item->data(Qt::UserRole + 1).toString()));
                m_show_button->setEnabled(true);
                return;
            }
        }
        m_show_button->setText(tr("All devices verified"));
        m_show_button->setEnabled(false);
    }

    MultisigWizard* m_wizard;
    QPushButton* m_show_button{nullptr};
    QLabel* m_devices_empty{nullptr};
    QLabel* m_airgap_help{nullptr};
    QCheckBox* m_airgap_ack{nullptr};
    QCheckBox* m_local_ack{nullptr};
    QLabel* m_independent_state{nullptr};
    QPushButton* m_import_policy{nullptr};
    std::set<std::string> m_verified_hardware;
    bool m_address_valid{false};
};

class MultisigDonePage : public QWizardPage
{
public:
    explicit MultisigDonePage(MultisigWizard* wizard) : QWizardPage(wizard), m_wizard(wizard)
    {
        setTitle(tr("Ready"));
        setSubTitle(tr("Your recovery vault is ready for a small test payment."));
        setFinalPage(true);
        auto* layout = new QVBoxLayout(this);
        m_summary = new QLabel;
        m_summary->setObjectName("doneSummaryLabel");
        m_summary->setWordWrap(true);
        m_summary->setTextFormat(Qt::RichText);
        layout->addWidget(m_summary);
        auto* policy_label = new QLabel(tr("Technical policy ID"));
        m_policy_id = new QLineEdit;
        m_policy_id->setObjectName("readyPolicyId");
        m_policy_id->setReadOnly(true);
        m_policy_id->setFont(GUIUtil::fixedPitchFont());
        m_policy_id->setAccessibleName(tr("Technical policy ID"));
        auto* policy_row = new QHBoxLayout;
        policy_row->addWidget(m_policy_id, 1);
        auto* copy_policy = new QPushButton(tr("Copy"));
        copy_policy->setObjectName("copyReadyPolicyIdButton");
        copy_policy->setAutoDefault(false);
        policy_row->addWidget(copy_policy);
        layout->addWidget(policy_label);
        layout->addLayout(policy_row);
        layout->addStretch();
        m_receive = new QPushButton(tr("Receive a Small Test Payment"));
        m_receive->setObjectName("receiveTestPaymentButton");
        m_receive->setAccessibleName(tr("Receive a Small Test Payment"));
        m_receive->setAutoDefault(true);
        layout->addWidget(m_receive, 0, Qt::AlignLeft);
        connect(copy_policy, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(m_policy_id->text());
        });
        connect(m_receive, &QPushButton::clicked, this, [this] {
            if (!m_wizard->createdWallet()) return;
            Q_EMIT m_wizard->receiveRequested(m_wizard->createdWallet(), m_wizard->m_receive_address);
            m_wizard->accept();
        });
    }
    void initializePage() override
    {
        QTimer::singleShot(0, this, [this] {
            if (auto* done = qobject_cast<QPushButton*>(m_wizard->button(QWizard::FinishButton))) {
                done->setDefault(false);
                done->setAutoDefault(false);
            }
            m_receive->setDefault(true);
            m_receive->setFocus(Qt::OtherFocusReason);
        });
        if (m_wizard->advancedFlow()) {
            setTitle(tr("Wallet is ready"));
            setSubTitle(tr("Review the policy that was created before receiving a test amount."));
            const int n_active = m_wizard->nActiveKeys();
            const int n = static_cast<int>(m_wizard->keys().size());
            const bool vault = m_wizard->outputType() == OutputType::BECH32M &&
                               (m_wizard->fallbackOlder() || m_wizard->fallbackAfter());
            QString detail;
            if (vault) {
                if (const auto older = m_wizard->fallbackOlder()) {
                    if (const auto final = m_wizard->fallbackOlderOneKey()) {
                        detail = tr("<p>After <b>%1</b> (%2), %3 of %4 recovery keys can spend. "
                                    "After <b>%5</b> (%6), any one recovery key can spend.</p>")
                                     .arg(BlockCount(*older), ApproxDuration(*older))
                                     .arg(m_wizard->nrequired()).arg(n)
                                     .arg(BlockCount(*final), ApproxDuration(*final));
                    } else {
                        detail = tr("<p>After <b>%1</b> (%2), %3 of %4 keys can make an explicit recovery spend.</p>")
                                     .arg(BlockCount(*older), ApproxDuration(*older))
                                     .arg(m_wizard->nrequired()).arg(n);
                    }
                } else if (const auto after = m_wizard->fallbackAfter()) {
                    detail = tr("<p>At block height <b>%1</b>, %2 of %3 keys can make an explicit recovery spend.</p>")
                                 .arg(FormattedHeight(*after)).arg(m_wizard->nrequired()).arg(n);
                }
            }
            const QString lead = vault
                ? tr("<p><b>%1</b> requires all %2 active keys to spend immediately.</p>")
                      .arg(m_wizard->walletName().toHtmlEscaped()).arg(n_active)
                : tr("<p><b>%1</b> is ordinary %2 of %3 multisig with no delayed recovery path.</p>")
                      .arg(m_wizard->walletName().toHtmlEscaped()).arg(m_wizard->nrequired()).arg(n);
            m_summary->setText(lead + detail +
                tr("<p>The first receive address was completed during setup. Send a small test amount before moving a main balance.</p>"));
            m_policy_id->setText(m_wizard->m_policy_id);
            return;
        }
        setTitle(tr("Ready"));
        setSubTitle(tr("Your recovery vault is ready for a small test payment."));
        m_summary->setText(tr(
            "<p><b>Vault created.</b></p>"
            "<p>✓ Recovery Kit secured<br>"
            "%1<br>"
            "✓ All 3 keys now · any 2 after ~30 days · any 1 after ~60 days</p>")
            .arg(m_wizard->m_address_independently_verified
                ? tr("✓ First address independently verified")
                : tr("◦ First address reviewed — not independently verified")));
        m_policy_id->setText(m_wizard->m_policy_id);
    }

private:
    MultisigWizard* m_wizard;
    QLabel* m_summary;
    QLineEdit* m_policy_id{nullptr};
    QPushButton* m_receive{nullptr};
};

MultisigWizard::MultisigWizard(interfaces::Node& node, WalletController* wallet_controller, QWidget* parent)
    : QWizard(parent, GUIUtil::dialog_flags),
      m_node(node),
      m_wallet_controller(wallet_controller)
{
    m_wallet_name = suggestedWalletName(QStringLiteral("Vault"));
    setWindowTitle(tr("Create Scrooge Vault"));
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
    connect(this, &QWizard::currentIdChanged, this, [this](int id) {
        // The fixed Backup page intentionally exposes just Print PDF,
        // I understand, and Continue.
        const bool simple_backup = id == Page_Backup && !advancedFlow();
        if (simple_backup) {
            setButtonLayout({QWizard::Stretch, QWizard::NextButton});
        } else if (!m_setup_committed) {
            setButtonLayout({QWizard::BackButton, QWizard::Stretch,
                             QWizard::CancelButton, QWizard::NextButton,
                             QWizard::CommitButton, QWizard::FinishButton});
        }
    });

    setPage(Page_Intro, new MultisigIntroPage(this));
    setPage(Page_Template, new MultisigTemplatePage(this));
    setPage(Page_Setup, new MultisigSetupPage(this));
    setPage(Page_Keys, new MultisigKeysPage(this));
    setPage(Page_Threshold, new MultisigThresholdPage(this));
    setPage(Page_Backup, new MultisigBackupPage(this));
    setPage(Page_Verify, new MultisigVerifyPage(this));
    setPage(Page_Done, new MultisigDonePage(this));
    setStartId(Page_Keys);
}

void MultisigWizard::lockCommittedJourney()
{
    m_setup_committed = true;
    setOption(QWizard::NoCancelButton, true);
    setButtonLayout({QWizard::Stretch, QWizard::NextButton,
                     QWizard::CommitButton, QWizard::FinishButton});
}

void MultisigWizard::publishCreatedWallet()
{
    if (m_created_emitted || !m_wallet_model) return;
    m_created_emitted = true;
    Q_EMIT created(m_wallet_model);
}

MultisigWizard::~MultisigWizard()
{
    clearSoftwareRecovery();
}

void MultisigWizard::clearSoftwareRecovery()
{
    for (auto& item : m_software_recovery) {
        if (!item.mnemonic.empty()) memory_cleanse(item.mnemonic.data(), item.mnemonic.size());
    }
    std::vector<wallet::GeneratedMnemonic>{}.swap(m_software_recovery);
}

bool MultisigWizard::removePrivatePrintPath(const QString& path) const
{
    return m_private_print_remover ? m_private_print_remover(path) : QFile::remove(path);
}

void MultisigWizard::accept()
{
    clearSoftwareRecovery();
    QWizard::accept();
}

void MultisigWizard::reject()
{
    if (m_setup_committed && currentId() != Page_Done) {
        QMessageBox::warning(this, tr("Finish vault setup"),
                             tr("The wallet has already been created. Finish backing up its recovery material and verify the first address before closing."));
        return;
    }
    QWizard::reject();
}

void MultisigWizard::closeEvent(QCloseEvent* event)
{
    if (m_setup_committed && currentId() != Page_Done) {
        event->ignore();
        QMessageBox::warning(this, tr("Finish vault setup"),
                             tr("The wallet has already been created. Finish backing up its recovery material and verify the first address before closing."));
        return;
    }
    QWizard::closeEvent(event);
}

void MultisigWizard::setWalletName(const QString& name) { m_wallet_name = name; }

void MultisigWizard::enableAdvancedFlow()
{
    m_advanced_flow = true;
    if (currentId() < 0 || currentId() == Page_Keys) setStartId(Page_Intro);
}

QString MultisigWizard::walletNameError(const QString& name) const
{
    const QString trimmed = name.trimmed();
    if (trimmed.isEmpty()) return tr("Enter a wallet name.");
    if (!m_wallet_controller) return {};
    try {
        for (const auto& [existing, metadata] : m_wallet_controller->listWalletDir()) {
            Q_UNUSED(metadata);
            if (QString::fromStdString(existing).compare(trimmed, Qt::CaseInsensitive) == 0) {
                return tr("A wallet named “%1” already exists. Choose another name; the existing wallet will not be changed.").arg(trimmed);
            }
        }
    } catch (const std::exception& e) {
        return tr("Could not check whether this wallet name is available: %1").arg(QString::fromStdString(e.what()));
    }
    return {};
}

QString MultisigWizard::suggestedWalletName(const QString& base) const
{
    if (!m_wallet_controller) return base;
    try {
        std::set<QString> existing;
        for (const auto& [name, metadata] : m_wallet_controller->listWalletDir()) {
            Q_UNUSED(metadata);
            existing.insert(QString::fromStdString(name).toCaseFolded());
        }
        for (int suffix = 1;; ++suffix) {
            const QString candidate = suffix == 1 ? base : QStringLiteral("%1 %2").arg(base).arg(suffix);
            if (!existing.contains(candidate.toCaseFolded())) return candidate;
        }
    } catch (const std::exception&) {
        return base;
    }
}
void MultisigWizard::setLocalKeyCount(int count)
{
    enableAdvancedFlow();
    m_local_key_count = std::clamp(count, 0, kMaxLocalSoftwareKeys);
    if (m_local_key_count > 0) m_last_local_key_count = m_local_key_count;
    rebuildKeyList();
    refreshSidebar();
}
void MultisigWizard::setIncludeLocalKey(bool include)
{
    setLocalKeyCount(include ? std::max(1, m_last_local_key_count) : 0);
}
void MultisigWizard::setOutputType(OutputType type)
{
    enableAdvancedFlow();
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
    enableAdvancedFlow();
    m_nrequired = n;
    refreshSidebar();
}
void MultisigWizard::setFallbackOlder(std::optional<uint32_t> blocks)
{
    enableAdvancedFlow();
    m_fallback_older = blocks;
    if (!blocks) m_fallback_older_one_key.reset();
    refreshSidebar();
}
void MultisigWizard::setFallbackOlderOneKey(std::optional<uint32_t> blocks)
{
    enableAdvancedFlow();
    m_fallback_older_one_key = blocks;
    refreshSidebar();
}
void MultisigWizard::setFallbackAfter(std::optional<uint32_t> height)
{
    enableAdvancedFlow();
    m_fallback_after = height;
    if (height) m_fallback_older_one_key.reset();
    refreshSidebar();
}
void MultisigWizard::setVaultTemplate(VaultTemplate tmpl)
{
    enableAdvancedFlow();
    m_template = tmpl;
    refreshSidebar();
}

void MultisigWizard::refreshSidebar()
{
    if (auto* intro_page = dynamic_cast<MultisigIntroPage*>(page(Page_Intro))) {
        intro_page->refreshMode();
    }
    if (auto* nav = sideWidget()) static_cast<StepNav*>(nav)->refreshPolicy();
}

void MultisigWizard::applyTemplate()
{
    enableAdvancedFlow();
    if (m_template != VaultTemplate::Custom) {
        for (auto& key : m_airgapped) key.recovery_only = false;
        m_last_airgap_recovery_only = false;
    }
    switch (m_template) {
    case VaultTemplate::RecoverOneLost:
        m_type = OutputType::BECH32M;
        if (m_local_key_count == 0) m_local_key_count = std::max(1, m_last_local_key_count);
        m_fallback_older = kDefaultVaultDelay;
        m_fallback_older_one_key.reset();
        m_fallback_after.reset();
        m_prefer_n_minus_1 = true;
        m_last_airgap_recovery_only = false;
        break;
    case VaultTemplate::StagedRecovery:
        m_type = OutputType::BECH32M;
        if (m_local_key_count == 0) m_local_key_count = std::max(1, m_last_local_key_count);
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
        m_local_key_count = 0;
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
    enableAdvancedFlow();
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
    enableAdvancedFlow();
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
    auto append_local = [this] {
        for (int i = 0; i < m_local_key_count; ++i) {
            MultisigKeySpec local;
            local.label = m_local_key_count == 1
                ? "This computer"
                : strprintf("This computer (software key %d)", i + 1);
            local.generate_local = true;
            m_keys.push_back(std::move(local));
        }
    };
    if (!m_advanced_flow) {
        // The fixed wizard binds devices deterministically first, then fills
        // the remaining slots with generated software keys.
        m_keys.insert(m_keys.end(), m_hardware.begin(), m_hardware.end());
        append_local();
    } else {
        append_local();
        m_keys.insert(m_keys.end(), m_hardware.begin(), m_hardware.end());
    }
    m_keys.insert(m_keys.end(), m_airgapped.begin(), m_airgapped.end());
}

void MultisigWizard::refreshHardware()
{
    if (auto* keys_page = dynamic_cast<MultisigKeysPage*>(page(Page_Keys))) {
        keys_page->refreshDevices();
    }
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

QString MultisigWizard::privateRecoveryKitHtml() const
{
    if (m_advanced_flow || m_local_key_count < 0 ||
        m_software_recovery.size() != static_cast<size_t>(m_local_key_count)) return {};

    auto package = wallet::ParseVaultPolicyPackage(m_policy_package.toStdString());
    if (!package || !wallet::ValidateFixedStagedVaultPolicy(*package)) return {};
    auto qr_parts_result = wallet::EncodeVaultPolicyQrParts(m_policy_package.toStdString());
    if (!qr_parts_result) return {};
    const std::vector<std::string>& qr_parts{*qr_parts_result};

    // Re-derive every phrase immediately before rendering. This proves that
    // each printed secret maps to the exact fingerprint/path/account xpub in
    // the canonical policy, rather than merely trusting cached GUI metadata.
    std::vector<SecureString> phrases;
    phrases.reserve(m_software_recovery.size());
    for (const auto& recovery : m_software_recovery) {
        phrases.emplace_back(recovery.mnemonic.begin(), recovery.mnemonic.end());
    }
    if (!phrases.empty()) {
        auto matches = wallet::ValidateVaultPolicyMnemonics(*package, phrases);
        if (!matches || matches->size() != m_software_recovery.size()) return {};
        for (const auto& recovery : m_software_recovery) {
            const auto match = std::find_if(matches->begin(), matches->end(), [&](const wallet::VaultMnemonicMatch& item) {
                return item.mnemonic_index < m_software_recovery.size() &&
                    &recovery == &m_software_recovery[item.mnemonic_index];
            });
            if (match == matches->end() || match->fingerprint != recovery.fingerprint ||
                match->path != recovery.path || match->xpub != recovery.xpub) return {};
        }
    }

    const int local_count = static_cast<int>(m_software_recovery.size());
    const int hardware_count = kStagedVaultKeyCount - local_count;
    constexpr int qr_parts_per_page{2};
    const int qr_page_count = (static_cast<int>(qr_parts.size()) + qr_parts_per_page - 1) / qr_parts_per_page;
    const int total_pages = local_count + 3 + qr_page_count; // cover, key pages, restore, QR pages, JSON
    const QString network = QString::fromStdString(package->network).toHtmlEscaped();
    const QString policy_id = QString::fromStdString(package->policy_id).toHtmlEscaped();
    const QString wallet_name = m_wallet_name.toHtmlEscaped();
    const QByteArray policy_bytes = m_policy_package.toUtf8();
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> policy_digest;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(policy_bytes.constData()), policy_bytes.size()).Finalize(policy_digest.data());
    const QString policy_sha256 = QString::fromStdString(HexStr(policy_digest));

    const QString authority = local_count == 3
        ? tr("This kit contains all three software keys. The document alone can spend the vault immediately.")
        : local_count == 2
            ? tr("This kit contains two software keys. The document alone can make an explicit recovery spend after 4,320 blocks (about 30 days); either phrase can recover after 8,640 blocks (about 60 days). The hardware key is still required for an immediate spend.")
            : local_count == 1
                ? tr("This kit contains one software key. The document alone can make an explicit recovery spend after 8,640 blocks (about 60 days). A second key is required at 4,320 blocks, and all three keys are required immediately.")
                : tr("This kit contains the complete public policy but no private keys. Reconnect the exact hardware wallets to sign: all three spend immediately, any two recover after 4,320 blocks, and any one recovers after 8,640 blocks.");
    const QString hardware_note = hardware_count == 0
        ? tr("This vault has no hardware-wallet participant.")
        : tr("This PDF does not contain the %n hardware-wallet seed(s). Back those up separately.", nullptr, hardware_count);
    const QString kit_banner = local_count > 0
        ? tr("PRIVATE — COMPLETE SCROOGE VAULT RECOVERY KIT")
        : tr("PUBLIC POLICY — SCROOGE VAULT RECOVERY KIT");

    auto page_header = [&](int page, const QString& title, bool last = false) {
        return QStringLiteral("<div class=\"page%1\"><div class=\"banner\">%2</div>"
                              "<div class=\"meta\">%3: <b>%4</b> &nbsp;|&nbsp; %5: <b>%6</b> &nbsp;|&nbsp; %7 %8/%9</div>"
                              "<h1>%10</h1>")
            .arg(last ? QStringLiteral(" last") : QString{},
                 kit_banner.toHtmlEscaped(),
                 tr("Network").toHtmlEscaped(), network,
                 tr("Policy ID").toHtmlEscaped(), policy_id,
                 tr("Page").toHtmlEscaped())
            .arg(page)
            .arg(total_pages)
            .arg(title.toHtmlEscaped());
    };
    auto page_footer = [&] {
        return QStringLiteral("<div class=\"footer\">%1</div></div>")
            .arg((local_count > 0
                ? tr("PRIVATE: possession of these mnemonic words grants signing authority. Never photograph, email, upload, or share this document.")
                : tr("PUBLIC POLICY ONLY: this page has no private keys, but it reveals the vault structure and transaction history."))
                     .toHtmlEscaped());
    };
    auto qr_image_uri = [](const std::string& part) -> QString {
        QRImageWidget widget;
        if (!widget.setQR(QString::fromStdString(part))) return {};
        const QImage image{widget.exportImage()};
        if (image.isNull()) return {};
        QByteArray png;
        QBuffer buffer{&png};
        if (!buffer.open(QIODevice::WriteOnly) || !image.save(&buffer, "PNG")) return {};
        return QStringLiteral("data:image/png;base64,") + QString::fromLatin1(png.toBase64());
    };

    QString html;
    html.reserve(30000);
    html += QStringLiteral(
        "<!doctype html><html><head><meta charset=\"utf-8\"><style>"
        "body{font-family:sans-serif;color:#111;font-size:10.5pt;}"
        ".page{page-break-after:always;} .page.last{page-break-after:auto;}"
        ".banner{background:#8b0000;color:white;font-weight:bold;font-size:15pt;padding:9px;}"
        ".meta{font-size:8.5pt;border-bottom:1px solid #555;padding:6px 0;}"
        "h1{font-size:21pt;margin:13px 0 8px;} h2{font-size:14pt;margin:12px 0 5px;}"
        ".danger{border:3px solid #8b0000;background:#fff0f0;padding:10px;font-size:12pt;}"
        ".box{border:1px solid #555;background:#f5f5f5;padding:9px;}"
        "li{margin:5px 0;} code,pre{font-family:monospace;}"
        ".words{width:100%;border-collapse:collapse;font-size:14pt;margin:10px 0;}"
        ".words td{border:1px solid #555;padding:7px;width:33%;}"
        ".crosscheck{font-size:8pt;overflow-wrap:anywhere;}"
        ".footer{border-top:1px solid #8b0000;color:#8b0000;font-weight:bold;font-size:8pt;margin-top:14px;padding-top:6px;}"
        ".policy{font-size:7.5pt;white-space:pre-wrap;overflow-wrap:anywhere;}"
        ".qrrow{width:100%;border-collapse:collapse;} .qrrow td{width:50%;text-align:center;vertical-align:top;padding:4px;}"
        ".qrpart{font-size:7pt;overflow-wrap:anywhere;}"
        "</style></head><body>");

    html += page_header(1, tr("Read this before printing"));
    html += QStringLiteral("<div class=\"danger\"><b>%1</b><br>%2<br><br>%3</div>")
        .arg((local_count > 0 ? tr("THIS IS AN UNENCRYPTED BEARER BACKUP.")
                              : tr("THIS COPY CONTAINS PUBLIC POLICY ONLY.")).toHtmlEscaped(),
             authority.toHtmlEscaped(), hardware_note.toHtmlEscaped());
    html += QStringLiteral("<p><b>%1:</b> %2</p>")
        .arg(tr("Wallet label").toHtmlEscaped(), wallet_name);
    html += QStringLiteral("<h2>%1</h2><ul><li>%2</li><li>%3</li><li>%4</li></ul>")
        .arg(tr("What the vault does").toHtmlEscaped(),
             tr("Immediate spend: all three active keys combine into one MuSig2 signature.").toHtmlEscaped(),
             tr("30-day recovery: after exactly 4,320 blocks, any two of the three keys can make an explicit recovery spend.").toHtmlEscaped(),
             tr("60-day recovery: after exactly 8,640 blocks, any one key can make an explicit recovery spend.").toHtmlEscaped());
    html += QStringLiteral("<div class=\"box\"><b>%1</b> %2</div>")
        .arg(tr("The delays belong to each received coin.").toHtmlEscaped(),
             tr("A new output or change output starts both clocks again. Recovery never happens automatically; the spender must explicitly choose the recovery path. Thirty and sixty days are estimates because block times vary.").toHtmlEscaped());
    html += QStringLiteral("<h2>%1</h2><ol><li>%2</li><li>%3</li><li>%4</li><li>%5</li></ol>")
        .arg(tr("Print and storage checklist").toHtmlEscaped(),
             tr("Use a trusted, directly connected local printer. Avoid cloud, office, or shared printers.").toHtmlEscaped(),
             (local_count > 0
                 ? tr("Print every page. Confirm that each software-key page has 24 numbered words and that the public-policy QR and JSON appendices are present.")
                 : tr("Print every page. Confirm that the public-policy QR and JSON appendices are present.")).toHtmlEscaped(),
             tr("Store the complete paper kit offline, away from this computer, protected from theft, fire, and water.").toHtmlEscaped(),
             tr("Close the PDF viewer and ask Bitcoin Core to delete its temporary file. Viewer caches, recent-file lists, printer memory, and print queues may still retain copies.").toHtmlEscaped());
    html += page_footer();

    for (size_t recovery_index = 0; recovery_index < m_software_recovery.size(); ++recovery_index) {
        const auto& recovery = m_software_recovery[recovery_index];
        std::vector<std::string_view> words;
        const std::string_view phrase{recovery.mnemonic.data(), recovery.mnemonic.size()};
        for (size_t begin = 0; begin < phrase.size();) {
            while (begin < phrase.size() && phrase[begin] == ' ') ++begin;
            if (begin == phrase.size()) break;
            const size_t end = phrase.find(' ', begin);
            words.push_back(phrase.substr(begin, end == std::string_view::npos ? phrase.size() - begin : end - begin));
            begin = end == std::string_view::npos ? phrase.size() : end + 1;
        }
        if (words.size() != 24) {
            html.fill(QChar{0});
            return {};
        }

        html += page_header(static_cast<int>(recovery_index) + 2,
                            tr("Software key %1 of %2 — 24-word mnemonic")
                                .arg(recovery_index + 1).arg(local_count));
        html += QStringLiteral("<div class=\"danger\"><b>%1</b> %2</div>")
            .arg(tr("PRIVATE KEY MATERIAL.").toHtmlEscaped(),
                 tr("This one phrase can recover after 8,640 blocks; with any other vault key it can recover after 4,320 blocks; all three vault keys can spend immediately.").toHtmlEscaped());
        html += QStringLiteral("<p><b>%1:</b> %2<br><b>%3:</b> %4<br><b>%5:</b> %6<br><b>%7:</b> <b>%8</b></p>")
            .arg(tr("Vault slot").toHtmlEscaped()).arg(recovery.key_index + 1)
            .arg(tr("Master fingerprint").toHtmlEscaped(), QString::fromStdString(recovery.fingerprint).toHtmlEscaped(),
                 tr("Derivation path").toHtmlEscaped(), QString::fromStdString(recovery.path).toHtmlEscaped(),
                 tr("BIP39 passphrase").toHtmlEscaped(), tr("NONE — leave the passphrase empty").toHtmlEscaped());
        html += QStringLiteral("<table class=\"words\">");
        for (int row = 0; row < 8; ++row) {
            html += QStringLiteral("<tr>");
            for (int column = 0; column < 3; ++column) {
                const int word_index = column * 8 + row;
                html += QStringLiteral("<td><b>%1.</b>&nbsp; %2</td>")
                    .arg(word_index + 1)
                    .arg(QString::fromUtf8(words[word_index].data(), static_cast<qsizetype>(words[word_index].size())).toHtmlEscaped());
            }
            html += QStringLiteral("</tr>");
        }
        html += QStringLiteral("</table><p class=\"crosscheck\"><b>%1:</b><br><code>%2</code></p>")
            .arg(tr("Derived account xpub — public identity cross-check").toHtmlEscaped(),
                 QString::fromStdString(recovery.xpub).toHtmlEscaped());
        html += page_footer();
    }

    html += page_header(local_count + 2, tr("How to restore this vault"));
    html += QStringLiteral("<div class=\"danger\"><b>%1</b> %2</div>")
        .arg(tr("Restore only in trusted Bitcoin Core software.").toHtmlEscaped(),
             tr("Never type these words into a website. A restored software key is stored in a new unencrypted hot wallet.").toHtmlEscaped());
    html += QStringLiteral("<ol><li>%1</li><li>%2</li><li>%3</li><li>%4</li><li>%5</li><li>%6</li></ol>")
        .arg(tr("Use a fully synchronized, unpruned node with block history back to genesis.").toHtmlEscaped(),
             tr("Open the 30 / 60 day Scrooge Vault wizard and choose “Restore from a printed recovery kit”.").toHtmlEscaped(),
             tr("Choose a new wallet name and scan every public-policy QR part, or paste the exact policy JSON appendix. Verify the network and policy ID shown above.").toHtmlEscaped(),
             (local_count > 0
                 ? tr("Enter one, two, or all available 24-word software-key phrases. Entry order does not matter; Bitcoin Core matches each phrase by its derived account xpub. Leave the BIP39 passphrase empty. Never enter a hardware-wallet seed.")
                 : tr("This kit has no software-key phrase to enter. Restore it as a public watch/external-signer wallet, then reconnect the exact hardware wallets.")).toHtmlEscaped(),
             tr("Wait for the rescan from genesis to finish. Compare the restored policy ID and first receive address with an independent copy before accepting funds.").toHtmlEscaped(),
             tr("One recovered key enables the 8,640-block path; any two enable the 4,320-block path; all three enable immediate spending. Hardware-wallet seeds are still required for hardware participants.").toHtmlEscaped());
    html += QStringLiteral("<h2>%1</h2><p>%2</p><p><b>%3:</b> <code>%4</code></p>")
        .arg(tr("Why the JSON is required").toHtmlEscaped(),
             tr("A mnemonic restores one signer, but it does not describe the other keys, their order, the Taproot scripts, or the recovery delays. The exact policy JSON reconstructs those public rules.").toHtmlEscaped(),
             tr("Policy JSON SHA-256").toHtmlEscaped(), policy_sha256);
    html += page_footer();

    for (int qr_page = 0; qr_page < qr_page_count; ++qr_page) {
        const int first_part = qr_page * qr_parts_per_page;
        const int last_part = std::min(first_part + qr_parts_per_page, static_cast<int>(qr_parts.size()));
        html += page_header(local_count + 3 + qr_page,
                            tr("Machine-readable public policy — parts %1–%2 of %3")
                                .arg(first_part + 1).arg(last_part).arg(qr_parts.size()));
        html += QStringLiteral("<p>%1</p><table class=\"qrrow\"><tr>")
            .arg(tr("Scan every part in numbered order. Missing, reordered, duplicate, mixed, or damaged parts are rejected. These QR codes never contain mnemonic words.").toHtmlEscaped());
        for (int part_index = first_part; part_index < last_part; ++part_index) {
            const QString uri{qr_image_uri(qr_parts[part_index])};
            if (uri.isEmpty()) {
                html.fill(QChar{0});
                return {};
            }
            html += QStringLiteral("<td><b>%1 %2/%3</b><br><img width=\"210\" height=\"210\" src=\"%4\"><div class=\"qrpart\"><code>%5</code></div></td>")
                .arg(tr("Part").toHtmlEscaped()).arg(part_index + 1).arg(qr_parts.size())
                .arg(uri, QString::fromStdString(qr_parts[part_index]).toHtmlEscaped());
        }
        html += QStringLiteral("</tr></table>");
        html += page_footer();
    }

    html += page_header(total_pages, tr("Exact importable public policy JSON"), true);
    html += QStringLiteral("<p>%1</p><p><b>%2:</b> <code>%3</code></p><pre class=\"policy\">%4</pre>")
        .arg(tr("This appendix is public-key material: it cannot spend by itself, but it reveals the vault structure and can expose transaction history. Preserve it exactly with the mnemonic pages.").toHtmlEscaped(),
             tr("SHA-256").toHtmlEscaped(), policy_sha256,
             m_policy_package.toHtmlEscaped());
    html += page_footer();
    html += QStringLiteral("</body></html>");
    return html;
}

bilingual_str MultisigWizard::policyError() const
{
    const size_t n_active = static_cast<size_t>(std::count_if(m_keys.begin(), m_keys.end(), [](const MultisigKeySpec& k) { return !k.recovery_only; }));
    return wallet::ValidateMultisigPolicy(m_nrequired, n_active, m_type, m_fallback_older, m_fallback_after, m_keys.size(), m_fallback_older_one_key);
}

bool MultisigWizard::createWallet()
{
    clearSoftwareRecovery();
    m_create_error.clear();
    m_wallet_model = nullptr;
    m_public_descs.clear();
    m_candidate_keys.clear();
    m_policy_id.clear();
    m_policy_package.clear();
    rebuildKeyList();
    if (!m_advanced_flow) {
        const bool fixed_policy = m_type == OutputType::BECH32M &&
            m_keys.size() == kStagedVaultKeyCount && nActiveKeys() == kStagedVaultKeyCount &&
            m_nrequired == 2 && m_fallback_older == kThirtyDayVaultDelay &&
            m_fallback_older_one_key == kSixtyDayVaultDelay && !m_fallback_after &&
            std::none_of(m_keys.begin(), m_keys.end(), [](const MultisigKeySpec& key) { return key.recovery_only; });
        if (!fixed_policy) {
            m_create_error = tr("The fixed three-key 30 / 60 day Scrooge Vault policy changed unexpectedly.");
            return false;
        }
        if (const auto duplicate = wallet::DuplicateSignerWarning(m_keys); !duplicate.empty()) {
            m_create_error = QString::fromStdString(duplicate.original);
            return false;
        }
    }
    if (const auto err = policyError(); !err.empty()) {
        m_create_error = QString::fromStdString(err.translated);
        return false;
    }
    if (!m_wallet_controller) {
        m_create_error = tr("The GUI wallet controller is not available.");
        return false;
    }
    if (const QString name_error = walletNameError(m_wallet_name); !name_error.isEmpty()) {
        m_create_error = name_error;
        return false;
    }

    try {
        // Resolve and validate every public signer before any persistent
        // wallet is created. Fixed-flow software keys are also generated here,
        // entirely in memory, so Secure Recovery can protect the exact final
        // candidate before the chosen wallet name is committed.
        const std::string default_path = wallet::DefaultMultisigPath(m_type, 0);
        std::vector<wallet::MultisigKeySpec> resolved_specs;
        resolved_specs.reserve(m_keys.size());
        for (const auto& k : m_keys) {
            wallet::MultisigKeySpec resolved{k};
            const std::string path = k.path.value_or(default_path);
            resolved.path = path;
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
                std::string fetched;
                if (!m_advanced_flow) {
                    const auto account = m_fixed_hardware_accounts.find(*k.fingerprint);
                    if (account == m_fixed_hardware_accounts.end() || account->second.first != path) {
                        m_create_error = tr("The reviewed hardware-wallet account binding is missing or changed. Return to Review Vault and retry discovery.");
                        return false;
                    }
                    fetched = account->second.second;
                } else {
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
                    fetched = result["xpub"].get_str();
                }
                if (!DecodeExtPubKey(fetched).pubkey.IsValid()) {
                    m_create_error = tr("Signer returned an invalid xpub.");
                    return false;
                }
                resolved.xpub = fetched;
            }
            resolved_specs.push_back(std::move(resolved));
        }

        std::vector<std::string> descriptors;
        std::vector<wallet::GeneratedMnemonic> generated_recovery;
        if (!m_advanced_flow) {
            wallet::MultisigOptions options;
            options.type = m_type;
            options.account = 0;
            options.fallback_older = m_fallback_older;
            options.fallback_after = m_fallback_after;
            options.fallback_older_one_key = m_fallback_older_one_key;
            auto prepared = wallet::PrepareMultisigDescriptor(m_nrequired, resolved_specs, options);
            if (!prepared) {
                m_create_error = QString::fromStdString(util::ErrorString(prepared).original);
                return false;
            }
            descriptors = std::move(prepared->descs);
            generated_recovery = std::move(prepared->recovery);
            m_candidate_keys = std::move(resolved_specs);
        } else {
            const bool has_device = std::any_of(m_keys.begin(), m_keys.end(), [](const MultisigKeySpec& k) {
                return k.fingerprint.has_value() && !k.xpub;
            });
            uint64_t flags = WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_BLANK_WALLET;
            if (has_device) flags |= WALLET_FLAG_EXTERNAL_SIGNER;
            if (m_local_key_count == 0) flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;

            std::vector<interfaces::Wallet::MultisigKey> iface_keys;
            iface_keys.reserve(resolved_specs.size());
            for (const auto& key : resolved_specs) {
                iface_keys.push_back({key.path, key.fingerprint, key.hdkey, key.xpub,
                                      key.recovery_only, key.generate_local, key.recovery_mnemonic});
            }
            std::vector<bilingual_str> warnings;
            auto created = m_node.walletLoader().createWallet(m_wallet_name.toStdString(), SecureString{}, flags, warnings);
            if (!created) {
                m_create_error = QString::fromStdString(util::ErrorString(created).translated);
                return false;
            }
            auto imported = (*created)->createMultisigDescriptor(m_nrequired, iface_keys, m_type,
                                                                  m_fallback_older, m_fallback_after,
                                                                  m_fallback_older_one_key);
            if (!imported) {
                m_create_error = QString::fromStdString(util::ErrorString(imported).original);
                return false;
            }
            descriptors = std::move(imported->descs);
            generated_recovery.reserve(imported->recovery.size());
            for (auto& item : imported->recovery) {
                generated_recovery.push_back(wallet::GeneratedMnemonic{
                    item.key_index,
                    std::move(item.mnemonic),
                    std::move(item.fingerprint),
                    std::move(item.path),
                    std::move(item.xpub),
                });
            }
            m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(*created));
        }

        if (descriptors.size() != 2) {
            m_create_error = tr("Wallet creation did not produce one receive descriptor and one change descriptor.");
            return false;
        }
        const size_t expected_recovery = static_cast<size_t>(std::count_if(
            m_keys.begin(), m_keys.end(), [](const MultisigKeySpec& key) { return key.generate_local; }));
        if (generated_recovery.size() != expected_recovery) {
            m_create_error = tr("Wallet creation did not return one recovery phrase for every generated software key.");
            return false;
        }
        std::set<size_t> recovery_indexes;
        std::set<std::string> recovery_xpubs;
        std::vector<wallet::GeneratedMnemonic> software_recovery;
        software_recovery.reserve(generated_recovery.size());
        for (auto& item : generated_recovery) {
            if (item.key_index >= m_keys.size() || !m_keys[item.key_index].generate_local ||
                item.mnemonic.empty() || item.fingerprint.size() != 8 || !IsHex(item.fingerprint) ||
                item.path.empty() || !DecodeExtPubKey(item.xpub).pubkey.IsValid() ||
                !recovery_indexes.insert(item.key_index).second ||
                !recovery_xpubs.insert(item.xpub).second) {
                m_create_error = tr("Wallet creation returned invalid or duplicate software-key recovery material.");
                return false;
            }
            software_recovery.push_back(wallet::GeneratedMnemonic{
                item.key_index,
                std::move(item.mnemonic),
                std::move(item.fingerprint),
                std::move(item.path),
                std::move(item.xpub),
            });
        }
        std::sort(software_recovery.begin(), software_recovery.end(), [](const auto& a, const auto& b) {
            return a.key_index < b.key_index;
        });
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
        package.descs = descriptors;
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
        if (!m_advanced_flow) {
            auto fixed = wallet::ValidateFixedStagedVaultPolicy(*parsed_package);
            if (!fixed) {
                m_create_error = QString::fromStdString(util::ErrorString(fixed).original);
                return false;
            }
        }
        m_public_descs = std::move(descriptors);
        if (!m_public_descs.empty()) m_policy_id = QString::fromStdString(wallet::VaultPolicyId(m_public_descs.front()));
        m_policy_package = policy_package;
        m_software_recovery = std::move(software_recovery);
        return true;
    } catch (const std::exception& e) {
        m_create_error = QString::fromStdString(e.what());
        return false;
    }
}

bool MultisigWizard::commitWalletCandidate()
{
    if (m_advanced_flow) return m_wallet_model != nullptr;
    if (m_wallet_model) return true;
    m_create_error.clear();
    if (!m_wallet_controller) {
        m_create_error = tr("The GUI wallet controller is not available.");
        return false;
    }
    if (const QString name_error = walletNameError(m_wallet_name); !name_error.isEmpty()) {
        m_create_error = name_error;
        return false;
    }
    auto package = wallet::ParseVaultPolicyPackage(m_policy_package.toStdString());
    if (!package || !wallet::ValidateFixedStagedVaultPolicy(*package) ||
        package->descs != m_public_descs || m_candidate_keys.size() != kStagedVaultKeyCount ||
        m_software_recovery.size() != static_cast<size_t>(m_local_key_count)) {
        m_create_error = tr("The prepared Recovery Kit no longer matches the fixed vault candidate.");
        return false;
    }

    std::vector<SecureString> mnemonics;
    mnemonics.reserve(m_software_recovery.size());
    for (const auto& recovery : m_software_recovery) {
        mnemonics.emplace_back(recovery.mnemonic.begin(), recovery.mnemonic.end());
    }

    try {
        std::vector<bilingual_str> warnings;
        auto installed = m_node.walletLoader().installFixedVault(
            m_wallet_name.toStdString(), m_policy_package.toStdString(), mnemonics,
            interfaces::FixedVaultInstallMode::CREATE, warnings);
        for (SecureString& mnemonic : mnemonics) {
            if (!mnemonic.empty()) memory_cleanse(mnemonic.data(), mnemonic.size());
        }
        if (!installed) {
            m_create_error = tr("The Recovery Kit is safe, but the wallet could not be committed: %1")
                                 .arg(QString::fromStdString(util::ErrorString(installed).translated));
            return false;
        }
        m_wallet_model = m_wallet_controller->getOrCreateWallet(std::move(installed->wallet));
        clearSoftwareRecovery();
        std::vector<wallet::MultisigKeySpec>{}.swap(m_candidate_keys);
        return true;
    } catch (const std::exception& e) {
        for (SecureString& mnemonic : mnemonics) {
            if (!mnemonic.empty()) memory_cleanse(mnemonic.data(), mnemonic.size());
        }
        m_create_error = tr("The Recovery Kit is safe, but the wallet could not be committed: %1")
                             .arg(QString::fromStdString(e.what()));
        return false;
    }
}

bool MultisigWizard::restoreFromRecoverySheets(const QString& wallet_name, const QString& policy_json,
                                               const std::vector<SecureString>& mnemonics, QString& error)
{
    error.clear();
    if (!m_wallet_controller) {
        error = tr("The GUI wallet controller is not available.");
        return false;
    }
    if (const QString name_error = walletNameError(wallet_name); !name_error.isEmpty()) {
        error = name_error;
        return false;
    }
    auto decoded_policy = DecodeVaultPolicyInput(policy_json);
    if (!decoded_policy) {
        error = QString::fromStdString(util::ErrorString(decoded_policy).original);
        return false;
    }
    auto package = wallet::ParseVaultPolicyPackage(*decoded_policy);
    if (!package) {
        error = QString::fromStdString(util::ErrorString(package).original);
        return false;
    }
    auto fixed_policy = wallet::ValidateFixedStagedVaultPolicy(*package);
    if (!fixed_policy) {
        error = QString::fromStdString(util::ErrorString(fixed_policy).original);
        return false;
    }
    size_t recovered_count{0};
    if (!mnemonics.empty()) {
        auto preflight = wallet::ValidateVaultPolicyMnemonics(*package, mnemonics);
        if (!preflight) {
            error = QString::fromStdString(util::ErrorString(preflight).original);
            return false;
        }
        recovered_count = preflight->size();
    }

    m_pending_restore_package = *package;
    m_pending_restore_name = wallet_name;
    m_pending_restore_recovered_count = recovered_count;

    auto* activity = new MnemonicRestoreActivity(m_wallet_controller, this, m_restore_rescan_override);
    connect(activity, &MnemonicRestoreActivity::failed, this,
            [this](const QString& activity_error) {
        m_pending_restore_package.reset();
        Q_EMIT restoreAttemptFailed(activity_error);
    });
    connect(activity, &MnemonicRestoreActivity::rescanFailed, this,
            [this](WalletModel* wallet_model, const QString& activity_error) {
        Q_EMIT restoreRescanRetryRequired(wallet_model, activity_error);
    });
    connect(activity, &MnemonicRestoreActivity::restored, this,
            [this](WalletModel* wallet_model) { completeRecoveryRestore(wallet_model); });
    activity->restore(wallet_name.toStdString(), *decoded_policy, mnemonics);
    return true;
}

bool MultisigWizard::retryRecoveryRescan(WalletModel* wallet_model, QString& error)
{
    error.clear();
    if (!m_wallet_controller || !wallet_model) {
        error = tr("The installed vault is no longer available for rescanning.");
        return false;
    }
    auto* activity = new MnemonicRestoreActivity(m_wallet_controller, this, m_restore_rescan_override);
    connect(activity, &MnemonicRestoreActivity::failed, this,
            [this](const QString& activity_error) { Q_EMIT restoreAttemptFailed(activity_error); });
    connect(activity, &MnemonicRestoreActivity::rescanFailed, this,
            [this](WalletModel* failed_wallet, const QString& activity_error) {
        Q_EMIT restoreRescanRetryRequired(failed_wallet, activity_error);
    });
    connect(activity, &MnemonicRestoreActivity::restored, this, [this](WalletModel* restored_wallet) {
        completeRecoveryRestore(restored_wallet);
    });
    activity->rescan(wallet_model);
    return true;
}

void MultisigWizard::completeRecoveryRestore(WalletModel* wallet_model)
{
    if (!wallet_model || !m_pending_restore_package) {
        const QString error{tr("The completed rescan could not be matched to its pending vault restore.")};
        QMessageBox::critical(this, tr("Restore vault failed"), error);
        Q_EMIT restoreAttemptFailed(error);
        return;
    }
    const wallet::VaultPolicyPackage package{*m_pending_restore_package};
    auto exported = wallet::ParseVaultPolicyPackage(wallet_model->wallet().exportVaultPolicy());
    if (!exported || exported->policy_id != package.policy_id || exported->descs != package.descs) {
        const QString error{tr("The restored wallet does not reproduce the printed public policy exactly.")};
        QMessageBox::critical(this, tr("Restore vault failed"), error);
        Q_EMIT restoreAttemptFailed(error);
        return;
    }

    clearSoftwareRecovery();
    m_wallet_name = m_pending_restore_name;
    m_type = OutputType::BECH32M;
    m_local_key_count = static_cast<int>(m_pending_restore_recovered_count);
    m_nrequired = package.nrequired;
    m_fallback_older = package.fallback_older;
    m_fallback_after = package.fallback_after;
    m_fallback_older_one_key = package.fallback_older_one_key;
    m_public_descs = package.descs;
    m_policy_id = QString::fromStdString(package.policy_id);
    m_policy_package = QString::fromStdString(wallet::FormatVaultPolicyPackage(package));
    m_wallet_model = wallet_model;
    m_pending_restore_package.reset();
    m_pending_restore_name.clear();
    m_pending_restore_recovered_count = 0;

    const auto reconciled = wallet_model->reconcileVaultHardwareSigners();
    const size_t available_count = kStagedVaultKeyCount -
        std::min<size_t>(kStagedVaultKeyCount, reconciled.lost_signers.size());
    publishCreatedWallet();
    QMessageBox::information(this, tr("Vault restored"),
                             tr("The restored wallet is loaded and its historical rescan has completed. %1 of 3 participant identities are available now; reconnect any missing exact hardware wallets to regain their signing authority.")
                                 .arg(available_count));
    Q_EMIT restoreCompleted();
    // The parent wizard is still on Review Vault. The nested restore journey
    // already performed validation, installation, and a complete rescan.
    QDialog::done(QDialog::Accepted);
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
    auto signer = wallet::ExternalSignerScriptPubKeyMan::GetExternalSigner(
        std::optional<std::string>{fingerprint}, /*allow_native_default=*/true);
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
