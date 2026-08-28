// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/qrimagewidget.h>

#include <qt/guiutil.h>

#include <QApplication>
#include <QClipboard>
#include <QDrag>
#include <QFontDatabase>
#include <QMenu>
#include <QMimeData>
#include <QMouseEvent>
#include <QPainter>

#include <bitcoin-build-config.h> // IWYU pragma: keep

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

QRImageWidget::QRImageWidget(QWidget* parent)
    : QLabel(parent)
{
    contextMenu = new QMenu(this);
    contextMenu->addAction(tr("&Save Image…"), this, &QRImageWidget::saveImage);
    contextMenu->addAction(tr("&Copy Image"), this, &QRImageWidget::copyImage);
}

bool QRImageWidget::setQR(const QString& data, const QString& text, int requested_size)
{
#ifdef USE_QRCODE
    m_export_image = QImage{};
    setText("");
    if (data.isEmpty()) return false;

    // limit length
    if (data.length() > MAX_URI_LENGTH) {
        setText(tr("Resulting URI too long, try to reduce the text for label / message."));
        return false;
    }

    QRcode *code = QRcode_encodeString(data.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);

    if (!code) {
        setText(tr("Error encoding URI into QR Code."));
        return false;
    }

    static constexpr int QUIET_ZONE_MODULES{4};
    const int module_grid_size{code->width + 2 * QUIET_ZONE_MODULES};
    const int module_size{requested_size / module_grid_size};
    if (module_size < 1) {
        QRcode_free(code);
        setText(tr("QR code image size is too small."));
        return false;
    }

    QImage qr_image{requested_size, requested_size, QImage::Format_RGB32};
    if (qr_image.isNull()) {
        QRcode_free(code);
        setText(tr("Error creating QR Code image."));
        return false;
    }
    qr_image.fill(Qt::white);
    {
        QPainter painter{&qr_image};
        painter.setRenderHint(QPainter::Antialiasing, false);
        painter.setRenderHint(QPainter::SmoothPixmapTransform, false);

        const int rendered_size{module_grid_size * module_size};
        const int offset{(requested_size - rendered_size) / 2};
        const int data_offset{offset + QUIET_ZONE_MODULES * module_size};
        const unsigned char* module{code->data};
        for (int y = 0; y < code->width; ++y) {
            for (int x = 0; x < code->width; ++x, ++module) {
                if (*module & 1) {
                    painter.fillRect(data_offset + x * module_size,
                                     data_offset + y * module_size,
                                     module_size, module_size, Qt::black);
                }
            }
        }
    }
    QRcode_free(code);

    if (text.isEmpty()) {
        m_export_image = qr_image;
    } else {
        const int composite_size{requested_size + 2 * QR_IMAGE_MARGIN};
        m_export_image = QImage{composite_size, composite_size, QImage::Format_RGB32};
        if (m_export_image.isNull()) {
            setText(tr("Error creating QR Code image."));
            return false;
        }
        m_export_image.fill(Qt::white);

        QPainter painter{&m_export_image};
        painter.drawImage(QR_IMAGE_MARGIN, 0, qr_image);

        const QRect text_rect{QR_IMAGE_TEXT_MARGIN,
                              requested_size + QR_IMAGE_TEXT_MARGIN,
                              composite_size - 2 * QR_IMAGE_TEXT_MARGIN,
                              QR_IMAGE_MARGIN};
        QFont font = GUIUtil::fixedPitchFont();
        font.setStretch(QFont::SemiCondensed);
        font.setLetterSpacing(QFont::AbsoluteSpacing, 1);
        const qreal font_size = GUIUtil::calculateIdealFontSize(text_rect.width(), text, font);
        font.setPointSizeF(font_size);

        painter.setFont(font);
        painter.drawText(text_rect, Qt::AlignTop | Qt::AlignHCenter, text);
    }

    setPixmap(QPixmap::fromImage(m_export_image));

    return true;
#else
    setText(tr("QR code support not available."));
    return false;
#endif
}

QImage QRImageWidget::exportImage()
{
    return m_export_image;
}

void QRImageWidget::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton && GUIUtil::HasPixmap(this)) {
        event->accept();
        QMimeData *mimeData = new QMimeData;
        mimeData->setImageData(exportImage());

        QDrag *drag = new QDrag(this);
        drag->setMimeData(mimeData);
        drag->exec();
    } else {
        QLabel::mousePressEvent(event);
    }
}

void QRImageWidget::saveImage()
{
    if (!GUIUtil::HasPixmap(this))
        return;
    QString fn = GUIUtil::getSaveFileName(
        this, tr("Save QR Code"), QString(),
        /*: Expanded name of the PNG file format.
            See: https://en.wikipedia.org/wiki/Portable_Network_Graphics. */
        tr("PNG Image") + QLatin1String(" (*.png)"), nullptr);
    if (!fn.isEmpty())
    {
        exportImage().save(fn);
    }
}

void QRImageWidget::copyImage()
{
    if (!GUIUtil::HasPixmap(this))
        return;
    QApplication::clipboard()->setImage(exportImage());
}

void QRImageWidget::contextMenuEvent(QContextMenuEvent *event)
{
    if (!GUIUtil::HasPixmap(this))
        return;
    contextMenu->exec(event->globalPos());
}
