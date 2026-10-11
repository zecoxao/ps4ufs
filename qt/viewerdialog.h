/* viewerdialog.h - simple read-only text / hex file viewer */
#ifndef PS4UFS_VIEWERDIALOG_H
#define PS4UFS_VIEWERDIALOG_H

#include <QDialog>
#include <QByteArray>
class QPlainTextEdit;

class ViewerDialog : public QDialog {
    Q_OBJECT
public:
    ViewerDialog(const QString &title, const QByteArray &data, QWidget *parent = nullptr);
private slots:
    void showText();
    void showHex();
private:
    QByteArray m_data;
    QPlainTextEdit *m_edit;
    static QString hexDump(const QByteArray &d);
    static bool looksText(const QByteArray &d);
};

#endif
