#include "viewerdialog.h"
#include <QPlainTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFontDatabase>
#include <QShortcut>
#include <QKeySequence>
#include <cstdio>

ViewerDialog::ViewerDialog(const QString &title, const QByteArray &data, QWidget *parent)
    : QDialog(parent), m_data(data) {
    setWindowTitle(title);
    resize(760, 560);

    m_edit = new QPlainTextEdit(this);
    m_edit->setReadOnly(true);
    m_edit->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_edit->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    auto *btnText = new QPushButton(tr("Text"), this);
    auto *btnHex  = new QPushButton(tr("Hex"), this);
    auto *btnClose = new QPushButton(tr("Close"), this);
    btnText->setCheckable(true); btnHex->setCheckable(true);

    connect(btnText, &QPushButton::clicked, this, [this, btnText, btnHex]{
        btnText->setChecked(true); btnHex->setChecked(false); showText(); });
    connect(btnHex, &QPushButton::clicked, this, [this, btnText, btnHex]{
        btnHex->setChecked(true); btnText->setChecked(false); showHex(); });
    connect(btnClose, &QPushButton::clicked, this, &QDialog::accept);

    auto *bar = new QHBoxLayout;
    bar->addWidget(btnText);
    bar->addWidget(btnHex);
    bar->addStretch();
    bar->addWidget(btnClose);

    auto *lay = new QVBoxLayout(this);
    lay->addLayout(bar);
    lay->addWidget(m_edit);

    new QShortcut(QKeySequence(Qt::Key_Escape), this, SLOT(accept()));

    if (looksText(m_data)) { btnText->setChecked(true); showText(); }
    else                   { btnHex->setChecked(true);  showHex();  }
}

bool ViewerDialog::looksText(const QByteArray &d) {
    if (d.isEmpty()) return true;
    int ctrl = 0, n = qMin(d.size(), 4096);
    for (int i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)d[i];
        if (ch == 0) return false;
        if (ch < 0x09 || (ch > 0x0d && ch < 0x20)) ctrl++;
    }
    return ctrl * 50 <= n;   /* <= 2% control bytes */
}

void ViewerDialog::showText() {
    m_edit->setPlainText(QString::fromUtf8(m_data));
}

void ViewerDialog::showHex() {
    m_edit->setPlainText(hexDump(m_data));
}

QString ViewerDialog::hexDump(const QByteArray &d) {
    QString out;
    out.reserve(d.size() * 4 + 64);
    char line[128];
    for (int off = 0; off < d.size(); off += 16) {
        int n = qMin(16, d.size() - off);
        QString hex, asc;
        for (int i = 0; i < 16; i++) {
            if (i < n) {
                unsigned char c = (unsigned char)d[off + i];
                std::snprintf(line, sizeof line, "%02x ", c);
                hex += line;
                asc += (c >= 0x20 && c < 0x7f) ? QChar(c) : QChar('.');
            } else {
                hex += "   ";
            }
            if (i == 7) hex += ' ';
        }
        std::snprintf(line, sizeof line, "%08x  ", (unsigned)off);
        out += line; out += hex; out += ' '; out += asc; out += '\n';
    }
    return out;
}
