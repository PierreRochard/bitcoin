// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MULTISIGWIZARD_H
#define BITCOIN_QT_MULTISIGWIZARD_H

#include <addresstype.h>
#include <cstdint>
#include <optional>
#include <outputtype.h>
#include <util/result.h>
#include <util/translation.h>
#include <wallet/multisig.h>

#include <QString>
#include <QWizard>

#include <vector>

class WalletController;
class WalletModel;

namespace interfaces {
class Node;
} // namespace interfaces

/** Guided m-of-n wallet setup: keys, threshold, backup, on-device verify.
 *
 * Modeled on Sparrow's keystore list, Specter's device-then-wallet flow, and
 * BlueWallet's plain-language vault copy. The wallet itself is Core's mixed-key
 * descriptor wallet plus createmultisigdescriptor.
 */
class MultisigWizard : public QWizard
{
    Q_OBJECT

public:
    enum PageId {
        Page_Intro,
        Page_Setup,
        Page_Keys,
        Page_Threshold,
        Page_Backup,
        Page_Verify,
        Page_Done,
    };

    explicit MultisigWizard(interfaces::Node& node, WalletController* wallet_controller, QWidget* parent = nullptr);

    QString walletName() const { return m_wallet_name; }
    int nrequired() const { return m_nrequired; }
    std::optional<uint32_t> fallbackOlder() const { return m_fallback_older; }
    const std::vector<wallet::MultisigKeySpec>& keys() const { return m_keys; }
    OutputType outputType() const { return m_type; }
    bool includeLocalKey() const { return m_include_local; }
    WalletModel* createdWallet() const { return m_wallet_model; }

    void setWalletName(const QString& name);
    void setIncludeLocalKey(bool include);
    void setOutputType(OutputType type);
    void setNRequired(int n);
    void setFallbackOlder(std::optional<uint32_t> blocks);
    void setReceiveAddress(const QString& address) { m_receive_address = address; }
    void addHardwareKey(const std::string& fingerprint, const std::string& label);
    void addAirgappedKey(const std::string& fingerprint, const std::string& path, const std::string& xpub, const std::string& label);
    void rebuildKeyList();
    void refreshHardware();

    QString transcript() const;
    bilingual_str policyError() const;

    bool createWallet();
    QString createError() const { return m_create_error; }
    util::Result<CTxDestination> firstReceiveAddress();
    util::Result<void> verifyOnDevice(const std::string& fingerprint);

    interfaces::Node& node() const { return m_node; }

Q_SIGNALS:
    void created(WalletModel* wallet_model);

private:
    friend class MultisigIntroPage;
    friend class MultisigSetupPage;
    friend class MultisigKeysPage;
    friend class MultisigThresholdPage;
    friend class MultisigBackupPage;
    friend class MultisigVerifyPage;
    friend class MultisigDonePage;

    interfaces::Node& m_node;
    WalletController* m_wallet_controller;
    QString m_wallet_name{"Multisig"};
    OutputType m_type{OutputType::BECH32};
    bool m_include_local{true};
    std::vector<wallet::MultisigKeySpec> m_hardware;
    std::vector<wallet::MultisigKeySpec> m_airgapped;
    std::vector<wallet::MultisigKeySpec> m_keys;
    int m_nrequired{2};
    std::optional<uint32_t> m_fallback_older;
    std::vector<std::string> m_public_descs;
    WalletModel* m_wallet_model{nullptr};
    QString m_create_error;
    QString m_receive_address;
};

#endif // BITCOIN_QT_MULTISIGWIZARD_H
