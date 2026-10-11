/* mainwindow.h - Explorer-style browser for an encrypted PS4 UFS2 image */
#ifndef PS4UFS_MAINWINDOW_H
#define PS4UFS_MAINWINDOW_H

#include <QMainWindow>
#include <vector>
#include <functional>
#include "core_bridge.h"

class QLineEdit;
class QComboBox;
class QCheckBox;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;
class QTableWidget;
class QPlainTextEdit;
class QProgressBar;
class QLabel;
class QAction;
class Worker;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent *) override;
    void dragEnterEvent(QDragEnterEvent *) override;
    void dropEvent(QDropEvent *) override;

private slots:
    void browseImage();
    void browseKeys();
    void openImage();
    void closeImage();
    void partitionChanged(int);
    void navigate(const QString &path);
    void goPath();
    void goUp();
    void treeItemExpanded(QTreeWidgetItem *);
    void treeSelectionChanged();
    void listDoubleClicked(int row, int col);
    void listHeaderClicked(int col);
    void listContextMenu(const QPoint &);
    void doFind();
    void extractSelected();
    void extractCurrentFolder();
    void doScan();
    void doRecover();
    void showInfo();
    void showPartitions();
    void showProperties();
    void viewSelected();
    void copyPath();
    void cancelJob();
    void clearLog();
    void about();

private:
    void buildUi();
    void buildMenus();
    bool loadKeyFile(unsigned char out[32]);
    void refreshPartitions();
    void setBusy(bool busy, const QString &label);
    void populateList(const std::vector<ps4ufs_row> &rows, bool searchMode);
    void sortRows();
    void log(const QString &s);
    QString currentSelectionPath() const;        /* first selected list row path */
    QStringList selectedPaths() const;
    void startJob(const QString &label, std::function<int(QString &)> body,
                  std::function<void(int, const QString &)> done, bool determinate);

    /* config widgets */
    QLineEdit   *m_imgEdit, *m_keysEdit, *m_ivEdit, *m_pathEdit, *m_searchEdit;
    QComboBox   *m_partCombo;
    QCheckBox   *m_pkgChk;
    QPushButton *m_openBtn, *m_closeBtn, *m_cancelBtn;
    QTreeWidget *m_tree;
    QTableWidget*m_list;
    QPlainTextEdit *m_log;
    QProgressBar *m_prog;
    QLabel      *m_status;

    /* state */
    ps4ufs_ctx *m_ctx = nullptr;
    QString     m_cwd = "/";
    bool        m_searchMode = false;
    std::vector<ps4ufs_row> m_rows;
    std::vector<ps4ufs_row> m_foundRows;     /* search results pending display */
    ps4ufs_extract_stats    m_lastStats{};   /* last extract summary */
    int         m_sortCol = 0;
    bool        m_sortDesc = false;
    Worker     *m_worker = nullptr;
    bool        m_busy = false;

    /* options (menu toggles) */
    QAction *m_optSkipPkg, *m_optScanDry, *m_optScanDefrag, *m_optScanGeom, *m_optRecDry;
};

#endif
