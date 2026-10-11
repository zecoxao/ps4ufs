#include "mainwindow.h"
#include "worker.h"
#include "viewerdialog.h"

#include <QtWidgets>
#include <QSettings>
#include <QDateTime>
#include <QMimeData>
#include <algorithm>

/* ----------------------------------------------------------------------- */
static QString humanSize(quint64 n) {
    const char *u[] = {"B", "K", "M", "G", "T", "P"};
    double d = (double)n; int i = 0;
    while (d >= 1024.0 && i < 5) { d /= 1024.0; i++; }
    if (i == 0) return QString::number(n) + " B";
    return QString::asprintf("%.1f%s", d, u[i]);
}
static QString modeStr(quint16 mode) {
    static const char *t = "?pc?d?b?-?l?s???";
    char s[11];
    s[0] = t[(mode >> 12) & 0xf];
    const char *rwx = "rwxrwxrwx";
    for (int i = 0; i < 9; i++) s[1 + i] = (mode & (1 << (8 - i))) ? rwx[i] : '-';
    s[10] = 0;
    return QString::fromLatin1(s);
}
static QString rowType(const ps4ufs_row &r) {
    if (r.is_dir) return "Folder";
    if (r.is_lnk) return "Symlink";
    if (r.is_pkg) return "PKG (plaintext)";
    QString n = QString::fromUtf8(r.name);
    int dot = n.lastIndexOf('.');
    if (dot > 0 && dot < n.size() - 1) return n.mid(dot + 1).toUpper() + " file";
    return "File";
}

/* ============================= construction ============================ */
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("ps4ufs - PS4 UFS2 image browser");
    setAcceptDrops(true);
    buildUi();
    buildMenus();

    QSettings s;
    m_imgEdit->setText(s.value("Image", "").toString());
    m_keysEdit->setText(s.value("Keys", "").toString());
    m_ivEdit->setText(s.value("IvOffset", "0").toString());
    m_pkgChk->setChecked(s.value("PkgPlain", true).toBool());
    m_optSkipPkg->setChecked(s.value("SkipPkg", false).toBool());
    m_optScanDry->setChecked(s.value("ScanDryRun", false).toBool());
    m_optScanDefrag->setChecked(s.value("ScanDefrag", false).toBool());
    m_optScanGeom->setChecked(s.value("ScanGeom", false).toBool());
    m_optRecDry->setChecked(s.value("RecoverDryRun", false).toBool());
    restoreGeometry(s.value("Geometry").toByteArray());

    m_status->setText("Open an image to begin.");
}

MainWindow::~MainWindow() {
    if (m_ctx) ps4ufs_close(m_ctx);
}

void MainWindow::buildUi() {
    auto *central = new QWidget;
    auto *root = new QVBoxLayout(central);
    root->setContentsMargins(6, 6, 6, 6);

    /* ---- config row ---- */
    auto *cfg = new QGridLayout;
    cfg->addWidget(new QLabel(tr("Image:")), 0, 0);
    m_imgEdit = new QLineEdit;
    cfg->addWidget(m_imgEdit, 0, 1);
    auto *imgBr = new QPushButton("...");
    imgBr->setFixedWidth(32);
    cfg->addWidget(imgBr, 0, 2);

    cfg->addWidget(new QLabel(tr("keys.bin:")), 1, 0);
    m_keysEdit = new QLineEdit;
    cfg->addWidget(m_keysEdit, 1, 1);
    auto *keysBr = new QPushButton("...");
    keysBr->setFixedWidth(32);
    cfg->addWidget(keysBr, 1, 2);

    auto *row3 = new QHBoxLayout;
    row3->addWidget(new QLabel(tr("Partition:")));
    m_partCombo = new QComboBox;
    m_partCombo->setMinimumWidth(320);
    row3->addWidget(m_partCombo, 1);
    row3->addWidget(new QLabel(tr("IV offset:")));
    m_ivEdit = new QLineEdit("0");
    m_ivEdit->setFixedWidth(120);
    row3->addWidget(m_ivEdit);
    m_pkgChk = new QCheckBox(tr(".pkg passthrough"));
    row3->addWidget(m_pkgChk);
    m_openBtn = new QPushButton(tr("Open"));
    m_closeBtn = new QPushButton(tr("Close"));
    m_closeBtn->setEnabled(false);
    row3->addWidget(m_openBtn);
    row3->addWidget(m_closeBtn);
    cfg->addLayout(row3, 2, 0, 1, 3);
    root->addLayout(cfg);

    /* ---- nav row ---- */
    auto *nav = new QHBoxLayout;
    auto *upBtn = new QPushButton(tr("Up"));
    nav->addWidget(upBtn);
    m_pathEdit = new QLineEdit("/");
    nav->addWidget(m_pathEdit, 1);
    auto *goBtn = new QPushButton(tr("Go"));
    nav->addWidget(goBtn);
    nav->addSpacing(12);
    m_searchEdit = new QLineEdit;
    m_searchEdit->setPlaceholderText(tr("search name..."));
    nav->addWidget(m_searchEdit);
    auto *findBtn = new QPushButton(tr("Find"));
    nav->addWidget(findBtn);

    /* ---- main split: tree | list ---- */
    m_tree = new QTreeWidget;
    m_tree->setHeaderLabel(tr("Folders"));
    m_tree->setMinimumWidth(220);

    m_list = new QTableWidget(0, 6);
    QStringList cols{tr("Name"), tr("Size"), tr("Type"), tr("Modified"), tr("Mode"), tr("Inode")};
    m_list->setHorizontalHeaderLabels(cols);
    m_list->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_list->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_list->setSortingEnabled(false);
    m_list->verticalHeader()->setVisible(false);
    m_list->horizontalHeader()->setStretchLastSection(false);
    m_list->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_list->setContextMenuPolicy(Qt::CustomContextMenu);

    auto *rightW = new QWidget;
    auto *rightL = new QVBoxLayout(rightW);
    rightL->setContentsMargins(0, 0, 0, 0);
    rightL->addLayout(nav);
    rightL->addWidget(m_list, 1);

    auto *mainSplit = new QSplitter(Qt::Horizontal);
    mainSplit->addWidget(m_tree);
    mainSplit->addWidget(rightW);
    mainSplit->setStretchFactor(0, 0);
    mainSplit->setStretchFactor(1, 1);
    mainSplit->setSizes({260, 640});

    /* ---- log ---- */
    m_log = new QPlainTextEdit;
    m_log->setReadOnly(true);
    m_log->setMaximumBlockCount(20000);
    m_log->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    auto *vSplit = new QSplitter(Qt::Vertical);
    vSplit->addWidget(mainSplit);
    vSplit->addWidget(m_log);
    vSplit->setStretchFactor(0, 1);
    vSplit->setStretchFactor(1, 0);
    vSplit->setSizes({500, 150});
    root->addWidget(vSplit, 1);

    /* ---- progress + cancel ---- */
    auto *progRow = new QHBoxLayout;
    m_prog = new QProgressBar;
    m_prog->setTextVisible(true);
    progRow->addWidget(m_prog, 1);
    m_cancelBtn = new QPushButton(tr("Cancel"));
    m_cancelBtn->setEnabled(false);
    progRow->addWidget(m_cancelBtn);
    root->addLayout(progRow);

    setCentralWidget(central);

    m_status = new QLabel;
    statusBar()->addWidget(m_status, 1);

    resize(960, 680);

    /* ---- wiring ---- */
    connect(imgBr, &QPushButton::clicked, this, &MainWindow::browseImage);
    connect(keysBr, &QPushButton::clicked, this, &MainWindow::browseKeys);
    connect(m_openBtn, &QPushButton::clicked, this, &MainWindow::openImage);
    connect(m_closeBtn, &QPushButton::clicked, this, &MainWindow::closeImage);
    connect(m_partCombo, QOverload<int>::of(&QComboBox::activated), this, &MainWindow::partitionChanged);
    connect(upBtn, &QPushButton::clicked, this, &MainWindow::goUp);
    connect(goBtn, &QPushButton::clicked, this, &MainWindow::goPath);
    connect(m_pathEdit, &QLineEdit::returnPressed, this, &MainWindow::goPath);
    connect(findBtn, &QPushButton::clicked, this, &MainWindow::doFind);
    connect(m_searchEdit, &QLineEdit::returnPressed, this, &MainWindow::doFind);
    connect(m_pkgChk, &QCheckBox::toggled, this, [this](bool on){
        if (m_ctx) { ps4ufs_set_pkg_plaintext(m_ctx, on); navigate(m_cwd); } });
    connect(m_tree, &QTreeWidget::itemExpanded, this, &MainWindow::treeItemExpanded);
    connect(m_tree, &QTreeWidget::itemSelectionChanged, this, &MainWindow::treeSelectionChanged);
    connect(m_list, &QTableWidget::cellDoubleClicked, this, &MainWindow::listDoubleClicked);
    connect(m_list->horizontalHeader(), &QHeaderView::sectionClicked, this, &MainWindow::listHeaderClicked);
    connect(m_list, &QTableWidget::customContextMenuRequested, this, &MainWindow::listContextMenu);
    connect(m_cancelBtn, &QPushButton::clicked, this, &MainWindow::cancelJob);
}

void MainWindow::buildMenus() {
    auto *file = menuBar()->addMenu(tr("&File"));
    file->addAction(tr("&Open..."), QKeySequence::Open, this, &MainWindow::openImage);
    file->addAction(tr("&Close"), this, &MainWindow::closeImage);
    file->addSeparator();
    file->addAction(tr("E&xit"), this, &QWidget::close);

    auto *act = menuBar()->addMenu(tr("&Actions"));
    act->addAction(tr("&Extract selected..."), QKeySequence("Ctrl+E"), this, &MainWindow::extractSelected);
    act->addAction(tr("Extract current &folder..."), this, &MainWindow::extractCurrentFolder);
    act->addSeparator();
    act->addAction(tr("&Scan for packages..."), this, &MainWindow::doScan);
    act->addAction(tr("&Recover deleted packages..."), this, &MainWindow::doRecover);
    act->addSeparator();
    act->addAction(tr("Find"), QKeySequence("Ctrl+F"), this, [this]{ m_searchEdit->setFocus(); m_searchEdit->selectAll(); });
    act->addAction(tr("Refresh"), QKeySequence("F5"), this, [this]{ if (m_ctx) navigate(m_cwd); });
    act->addAction(tr("Up"), QKeySequence("Alt+Up"), this, &MainWindow::goUp);
    act->addSeparator();
    act->addAction(tr("FS info"), this, &MainWindow::showInfo);
    act->addAction(tr("List GPT partitions"), this, &MainWindow::showPartitions);
    act->addAction(tr("Properties"), QKeySequence("Alt+Return"), this, &MainWindow::showProperties);
    act->addAction(tr("Clear log"), this, &MainWindow::clearLog);

    auto *opt = menuBar()->addMenu(tr("&Options"));
    auto mkChk = [&](const char *t) { auto *a = opt->addAction(tr(t)); a->setCheckable(true); return a; };
    m_optSkipPkg    = mkChk("Skip .pkg files on extract");
    opt->addSeparator();
    m_optScanDry    = mkChk("Scan: dry run");
    m_optScanDefrag = mkChk("Scan: --defrag (free-bitmap reassembly)");
    m_optScanGeom   = mkChk("Scan: --geom (cg geometry reassembly)");
    opt->addSeparator();
    m_optRecDry     = mkChk("Recover: dry run");

    auto *help = menuBar()->addMenu(tr("&Help"));
    help->addAction(tr("About"), this, &MainWindow::about);
}

/* =============================== open ================================== */
void MainWindow::browseImage() {
    QString f = QFileDialog::getOpenFileName(this, tr("Select PS4 image"),
        m_imgEdit->text(), tr("Images (*.img *.bin *.raw);;All files (*)"));
    if (!f.isEmpty()) { m_imgEdit->setText(f); refreshPartitions(); }
}
void MainWindow::browseKeys() {
    QString f = QFileDialog::getOpenFileName(this, tr("Select keys.bin (32 bytes)"),
        m_keysEdit->text(), tr("Key files (*.bin *.key);;All files (*)"));
    if (!f.isEmpty()) { m_keysEdit->setText(f); refreshPartitions(); }
}

bool MainWindow::loadKeyFile(unsigned char out[32]) {
    QFile f(m_keysEdit->text());
    if (!f.open(QIODevice::ReadOnly)) return false;
    QByteArray d = f.read(33);
    if (d.size() < 32) return false;
    memcpy(out, d.constData(), 32);
    return true;
}

void MainWindow::refreshPartitions() {
    m_partCombo->clear();
    QString img = m_imgEdit->text();
    if (img.isEmpty() || !QFileInfo::exists(img)) return;

    unsigned char key[32]; int haveKey = loadKeyFile(key) ? 1 : 0;
    quint64 iv = m_ivEdit->text().trimmed().toULongLong(nullptr, 0);

    ps4ufs_part parts[260]; char err[256] = {0};
    int n = ps4ufs_scan_parts(img.toUtf8().constData(), key, haveKey, iv, parts, 260, err, sizeof err);
    m_partCombo->addItem(tr("Auto-detect (largest UFS2)"), QVariant::fromValue<int>(-2));
    if (n < 0) { log(QString("scan partitions: %1").arg(err)); return; }
    for (int i = 0; i < n; i++) {
        QString label;
        if (parts[i].index < 0) {
            label = tr("Bare partition (offset 0)");
        } else {
            label = QString("GPT #%1  base=0x%2  %3")
                        .arg(parts[i].index)
                        .arg(parts[i].base, 0, 16)
                        .arg(humanSize(parts[i].size));
        }
        if (parts[i].is_plain)      label += tr("  [UFS2 decrypted]");
        else if (parts[i].is_ufs2)  label += tr("  [UFS2]");
        /* encode base/plain into the item data: pack base, plus flags */
        m_partCombo->addItem(label, QVariant::fromValue<int>(i));
    }
    /* stash the raw parts on the combo via dynamic properties */
    QVariantList store;
    for (int i = 0; i < n; i++) {
        QVariantMap m;
        m["index"] = parts[i].index;
        m["base"]  = (qulonglong)parts[i].base;
        m["plain"] = parts[i].is_plain;
        m["ufs2"]  = parts[i].is_ufs2;
        store << m;
    }
    m_partCombo->setProperty("parts", store);
}

void MainWindow::partitionChanged(int) { /* selection used at Open time */ }

void MainWindow::openImage() {
    if (m_busy) return;
    if (m_ctx) closeImage();

    QString img = m_imgEdit->text();
    if (img.isEmpty() || !QFileInfo::exists(img)) {
        QMessageBox::warning(this, tr("Open"), tr("Select a valid image file.")); return;
    }
    if (m_partCombo->count() == 0) refreshPartitions();

    unsigned char key[32]; int haveKey = loadKeyFile(key) ? 1 : 0;
    quint64 iv = m_ivEdit->text().trimmed().toULongLong(nullptr, 0);

    /* decide partition offset / plain from the combo selection */
    quint64 base = 0; int plain = 0; bool chosen = false;
    QVariantList store = m_partCombo->property("parts").toList();
    int sel = m_partCombo->currentIndex();
    int tag = m_partCombo->currentData().toInt();
    if (tag >= 0 && tag < store.size()) {
        QVariantMap m = store[tag].toMap();
        base = m["base"].toULongLong();
        plain = m["plain"].toBool() ? 1 : 0;
        chosen = true;
    }
    (void)sel;

    if (!chosen) {
        /* auto-detect: prefer a plain/ufs2 entry from the scan */
        quint64 bestBase = 0; int bestPlain = 0; qulonglong bestSize = 0; bool found = false;
        for (const QVariant &v : store) {
            QVariantMap m = v.toMap();
            if (!(m["plain"].toBool() || m["ufs2"].toBool())) continue;
            qulonglong b = m["base"].toULongLong();
            /* approximate "largest": the scan doesn't carry size here for bare,
             * so take the first UFS2 GPT entry, else bare */
            if (!found || m["index"].toInt() >= 0) { bestBase = b; bestPlain = m["plain"].toBool(); found = true; bestSize = 0; }
        }
        (void)bestSize;
        base = found ? bestBase : 0;
        plain = bestPlain;
        if (!found && !haveKey) {
            QMessageBox::warning(this, tr("Open"),
                tr("No UFS2 partition detected and no key loaded.")); return;
        }
    }

    if (!plain && !haveKey) {
        QMessageBox::warning(this, tr("Open"),
            tr("This partition is encrypted - load a 32-byte keys.bin first.")); return;
    }

    char err[256] = {0};
    m_ctx = ps4ufs_open(img.toUtf8().constData(), key, haveKey, iv, base, plain,
                        m_pkgChk->isChecked() ? 1 : 0, 0, err, sizeof err);
    if (!m_ctx) {
        QMessageBox::critical(this, tr("Open"), tr("Failed to open:\n%1").arg(err));
        return;
    }
    m_closeBtn->setEnabled(true);
    char info[1024]; ps4ufs_info_text(m_ctx, info, sizeof info);
    log(QString("Opened %1 (base=0x%2, %3)\n%4")
            .arg(img).arg(base, 0, 16).arg(plain ? "decrypted" : "XTS").arg(info));

    /* seed tree root */
    m_tree->clear();
    auto *root = new QTreeWidgetItem(m_tree, QStringList("/"));
    root->setData(0, Qt::UserRole, "/");
    root->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    m_tree->addTopLevelItem(root);
    m_tree->setCurrentItem(root);
    navigate("/");

    QSettings s;
    s.setValue("Image", img);
    s.setValue("Keys", m_keysEdit->text());
    s.setValue("IvOffset", m_ivEdit->text());
    s.setValue("PkgPlain", m_pkgChk->isChecked());
}

void MainWindow::closeImage() {
    if (m_busy) return;
    if (m_ctx) { ps4ufs_close(m_ctx); m_ctx = nullptr; }
    m_tree->clear();
    m_list->setRowCount(0);
    m_rows.clear();
    m_closeBtn->setEnabled(false);
    m_status->setText("Closed.");
}

/* ============================= navigation ============================== */
void MainWindow::navigate(const QString &path) {
    if (!m_ctx) return;
    ps4ufs_row *rows = nullptr; int count = 0; char err[256] = {0};
    QByteArray p = path.toUtf8();
    if (ps4ufs_list(m_ctx, p.constData(), &rows, &count, err, sizeof err) != 0) {
        m_status->setText(QString("navigate: %1").arg(err));
        return;
    }
    m_cwd = path.isEmpty() ? "/" : path;
    m_pathEdit->setText(m_cwd);
    m_searchMode = false;
    std::vector<ps4ufs_row> v(rows, rows + count);
    ps4ufs_free_rows(rows);
    populateList(v, false);
}

void MainWindow::goPath() {
    QString p = m_pathEdit->text().trimmed();
    if (p.isEmpty()) p = "/";
    if (!p.startsWith('/')) p = (m_cwd == "/" ? "/" : m_cwd + "/") + p;
    navigate(p);
}
void MainWindow::goUp() {
    if (m_cwd == "/") return;
    int i = m_cwd.lastIndexOf('/');
    navigate(i <= 0 ? "/" : m_cwd.left(i));
}

void MainWindow::treeItemExpanded(QTreeWidgetItem *it) {
    if (!m_ctx) return;
    if (it->data(0, Qt::UserRole + 1).toBool()) return; /* already loaded */
    it->setData(0, Qt::UserRole + 1, true);
    QString base = it->data(0, Qt::UserRole).toString();
    ps4ufs_row *rows = nullptr; int count = 0; char err[256] = {0};
    if (ps4ufs_list(m_ctx, base.toUtf8().constData(), &rows, &count, err, sizeof err) != 0) return;
    for (int i = 0; i < count; i++) {
        if (!rows[i].is_dir) continue;
        QString name = QString::fromUtf8(rows[i].name);
        auto *child = new QTreeWidgetItem(it, QStringList(name));
        child->setData(0, Qt::UserRole, QString::fromUtf8(rows[i].path));
        child->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    }
    ps4ufs_free_rows(rows);
}

void MainWindow::treeSelectionChanged() {
    auto *it = m_tree->currentItem();
    if (!it || !m_ctx) return;
    navigate(it->data(0, Qt::UserRole).toString());
}

/* =============================== list ================================== */
void MainWindow::populateList(const std::vector<ps4ufs_row> &rows, bool searchMode) {
    m_rows = rows;
    m_searchMode = searchMode;
    sortRows();
    quint64 total = 0; int folders = 0;
    for (const auto &r : m_rows) { if (r.is_dir) folders++; else total += r.size; }
    m_status->setText(QString("%1 items (%2 folders), %3")
                          .arg(m_rows.size()).arg(folders).arg(humanSize(total)));
}

void MainWindow::sortRows() {
    int col = m_sortCol; bool desc = m_sortDesc;
    std::stable_sort(m_rows.begin(), m_rows.end(), [col, desc](const ps4ufs_row &a, const ps4ufs_row &b) {
        if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;   /* folders first */
        int c = 0;
        switch (col) {
            case 1: c = (a.size < b.size) ? -1 : (a.size > b.size) ? 1 : 0; break;
            case 3: c = (a.mtime < b.mtime) ? -1 : (a.mtime > b.mtime) ? 1 : 0; break;
            case 4: c = (int)a.mode - (int)b.mode; break;
            case 5: c = (int)a.ino - (int)b.ino; break;
            default: c = QString::fromUtf8(a.name).compare(QString::fromUtf8(b.name), Qt::CaseInsensitive); break;
        }
        if (c == 0) c = QString::fromUtf8(a.name).compare(QString::fromUtf8(b.name), Qt::CaseInsensitive);
        return desc ? (c > 0) : (c < 0);
    });

    m_list->setRowCount((int)m_rows.size());
    for (int i = 0; i < (int)m_rows.size(); i++) {
        const ps4ufs_row &r = m_rows[i];
        QString name = QString::fromUtf8(r.name);
        if (r.is_lnk && r.link[0]) name += " -> " + QString::fromUtf8(r.link);
        auto mk = [&](const QString &t, bool rightAlign = false) {
            auto *it = new QTableWidgetItem(t);
            it->setData(Qt::UserRole, i);
            if (rightAlign) it->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            return it;
        };
        m_list->setItem(i, 0, mk(name));
        m_list->setItem(i, 1, mk(r.is_dir ? QString() : humanSize(r.size), true));
        m_list->setItem(i, 2, mk(rowType(r)));
        m_list->setItem(i, 3, mk(r.mtime > 0 ? QDateTime::fromSecsSinceEpoch(r.mtime).toString("yyyy-MM-dd HH:mm") : QString()));
        m_list->setItem(i, 4, mk(QString("%1 %2").arg(modeStr(r.mode)).arg(r.mode & 07777, 4, 8, QChar('0'))));
        m_list->setItem(i, 5, mk(QString::number(r.ino), true));
    }
}

void MainWindow::listHeaderClicked(int col) {
    if (col == m_sortCol) m_sortDesc = !m_sortDesc;
    else { m_sortCol = col; m_sortDesc = (col == 1 || col == 3); }
    sortRows();
}

int rowOf(QTableWidget *t, int visualRow) {
    auto *it = t->item(visualRow, 0);
    return it ? it->data(Qt::UserRole).toInt() : -1;
}

void MainWindow::listDoubleClicked(int visualRow, int) {
    int i = rowOf(m_list, visualRow);
    if (i < 0 || i >= (int)m_rows.size()) return;
    const ps4ufs_row &r = m_rows[i];
    QString path = QString::fromUtf8(r.path);
    if (r.is_dir) { navigate(path); }
    else if (r.is_lnk) {
        int cls = ps4ufs_classify(m_ctx, path.toUtf8().constData());
        if (cls == 1) navigate(path); else viewSelected();
    } else viewSelected();
}

QString MainWindow::currentSelectionPath() const {
    auto sel = m_list->selectionModel()->selectedRows();
    if (sel.isEmpty()) return QString();
    int i = rowOf(m_list, sel.first().row());
    if (i < 0 || i >= (int)m_rows.size()) return QString();
    return QString::fromUtf8(m_rows[i].path);
}
QStringList MainWindow::selectedPaths() const {
    QStringList out;
    for (const auto &idx : m_list->selectionModel()->selectedRows()) {
        int i = rowOf(m_list, idx.row());
        if (i >= 0 && i < (int)m_rows.size()) out << QString::fromUtf8(m_rows[i].path);
    }
    return out;
}

void MainWindow::listContextMenu(const QPoint &pos) {
    if (m_rows.empty()) return;
    QMenu menu;
    menu.addAction(tr("Open / View"), this, [this]{ viewSelected(); });
    menu.addAction(tr("Extract..."), this, &MainWindow::extractSelected);
    menu.addAction(tr("Copy path"), this, &MainWindow::copyPath);
    menu.addAction(tr("Properties"), this, &MainWindow::showProperties);
    menu.exec(m_list->viewport()->mapToGlobal(pos));
}

void MainWindow::copyPath() {
    QString p = currentSelectionPath();
    if (!p.isEmpty()) QApplication::clipboard()->setText(p);
}

void MainWindow::viewSelected() {
    if (!m_ctx) return;
    QString p = currentSelectionPath();
    if (p.isEmpty()) return;
    if (ps4ufs_classify(m_ctx, p.toUtf8().constData()) == 1) { navigate(p); return; }
    const qint64 MAX = 512 * 1024;
    QByteArray buf; buf.resize((int)MAX);
    char err[256] = {0};
    qint64 n = ps4ufs_read_head(m_ctx, p.toUtf8().constData(), (unsigned char *)buf.data(), MAX, err, sizeof err);
    if (n < 0) { QMessageBox::warning(this, tr("View"), err); return; }
    buf.resize((int)n);
    ViewerDialog dlg(p, buf, this);
    dlg.exec();
}

void MainWindow::showProperties() {
    if (!m_ctx) return;
    QString p = currentSelectionPath();
    if (p.isEmpty()) return;
    ps4ufs_row r; char err[256] = {0};
    if (ps4ufs_stat(m_ctx, p.toUtf8().constData(), &r, err, sizeof err) != 0) {
        QMessageBox::warning(this, tr("Properties"), err); return;
    }
    QString t = QString("Path:  %1\nInode: %2\nMode:  %3 (%4)\nSize:  %5 (%6 bytes)\nMTime: %7\n")
        .arg(p).arg(r.ino)
        .arg(modeStr(r.mode)).arg(r.mode & 07777, 4, 8, QChar('0'))
        .arg(humanSize(r.size)).arg(r.size)
        .arg(r.mtime > 0 ? QDateTime::fromSecsSinceEpoch(r.mtime).toString(Qt::ISODate) : "-");
    if (r.is_lnk) t += QString("Target: %1\n").arg(QString::fromUtf8(r.link));
    if (r.is_pkg) t += "Storage: plaintext .pkg\n";
    QMessageBox::information(this, tr("Properties"), t);
}

/* =============================== find ================================== */
void MainWindow::doFind() {
    if (!m_ctx) return;
    QString needle = m_searchEdit->text().trimmed();
    if (needle.isEmpty()) { navigate(m_cwd); return; }
    QString base = m_cwd;
    startJob(QString("Searching for \"%1\"...").arg(needle),
        [this, base, needle](QString &err) -> int {
            ps4ufs_row *rows = nullptr; int count = 0; char e[256] = {0};
            int rc = ps4ufs_find(m_ctx, base.toUtf8().constData(), needle.toUtf8().constData(),
                                 &rows, &count, &Worker::progressCb, m_worker, e, sizeof e);
            if (rc != 0) { err = e; return -1; }
            m_foundRows.assign(rows, rows + count);
            ps4ufs_free_rows(rows);
            return 0;
        },
        [this, needle](int rc, const QString &err) {
            if (rc != 0) { log("find: " + err); return; }
            populateList(m_foundRows, true);
            m_pathEdit->setText(QString("Search: %1").arg(needle));
            m_status->setText(QString("%1 matches").arg(m_foundRows.size()));
        },
        /*determinate=*/false);
}

/* ============================= extraction ============================== */
void MainWindow::extractSelected() {
    if (!m_ctx) return;
    QStringList paths = selectedPaths();
    if (paths.isEmpty()) {
        QMessageBox::information(this, tr("Extract"),
            tr("Select files/folders, or use Actions > Extract current folder.")); return;
    }
    QString out = QFileDialog::getExistingDirectory(this, tr("Extract to folder"));
    if (out.isEmpty()) return;
    QStringList keep = paths;
    startJob(tr("Extracting..."),
        [this, keep, out](QString &err) -> int {
            std::vector<QByteArray> store; std::vector<const char *> cp;
            for (const auto &p : keep) { store.push_back(p.toUtf8()); }
            for (auto &b : store) cp.push_back(b.constData());
            ps4ufs_extract_stats st; char e[256] = {0};
            int rc = ps4ufs_extract(m_ctx, cp.data(), (int)cp.size(), out.toUtf8().constData(),
                                    m_optSkipPkg->isChecked() ? 1 : 0,
                                    &Worker::progressCb, m_worker, &Worker::logCb, m_worker,
                                    &st, e, sizeof e);
            if (rc < 0) { err = e; return -1; }
            m_lastStats = st;
            return rc;   /* 0 done, 1 canceled */
        },
        [this](int rc, const QString &err) {
            if (rc < 0) { log("extract: " + err); return; }
            log(QString("%1: %2 files (%3), %4 folders, %5 links, %6 skipped, %7 errors")
                .arg(rc == 1 ? "canceled" : "done")
                .arg(m_lastStats.files).arg(humanSize(m_lastStats.bytes))
                .arg(m_lastStats.dirs).arg(m_lastStats.links)
                .arg(m_lastStats.skipped).arg(m_lastStats.errors));
        }, /*determinate=*/true);
}

void MainWindow::extractCurrentFolder() {
    if (!m_ctx) return;
    QString out = QFileDialog::getExistingDirectory(this, tr("Extract current folder to"));
    if (out.isEmpty()) return;
    QString cwd = m_cwd;
    startJob(tr("Extracting folder..."),
        [this, cwd, out](QString &err) -> int {
            QByteArray p = cwd.toUtf8();
            const char *cp = p.constData();
            ps4ufs_extract_stats st; char e[256] = {0};
            int rc = ps4ufs_extract(m_ctx, &cp, 1, out.toUtf8().constData(),
                                    m_optSkipPkg->isChecked() ? 1 : 0,
                                    &Worker::progressCb, m_worker, &Worker::logCb, m_worker,
                                    &st, e, sizeof e);
            if (rc < 0) { err = e; return -1; }
            m_lastStats = st; return rc;
        },
        [this](int rc, const QString &err) {
            if (rc < 0) { log("extract: " + err); return; }
            log(QString("%1: %2 files (%3), %4 folders, %5 links, %6 skipped, %7 errors")
                .arg(rc == 1 ? "canceled" : "done")
                .arg(m_lastStats.files).arg(humanSize(m_lastStats.bytes))
                .arg(m_lastStats.dirs).arg(m_lastStats.links)
                .arg(m_lastStats.skipped).arg(m_lastStats.errors));
        }, /*determinate=*/true);
}

/* ========================= scan / recover ============================== */
void MainWindow::doScan() {
    if (!m_ctx) return;
    QString out = QFileDialog::getExistingDirectory(this, tr("Scan output folder"));
    if (out.isEmpty()) return;
    int dry = m_optScanDry->isChecked(), defrag = m_optScanDefrag->isChecked(), geom = m_optScanGeom->isChecked();
    if (QMessageBox::question(this, tr("Scan"),
            tr("Carve .pkg packages from the raw partition into:\n%1\n\nContinue?").arg(out))
        != QMessageBox::Yes) return;
    startJob(tr("Scanning for packages..."),
        [this, out, dry, defrag, geom](QString &err) -> int {
            char e[256] = {0};
            int rc = ps4ufs_scan(m_ctx, dry, defrag, geom, out.toUtf8().constData(),
                                 &Worker::logCb, m_worker, e, sizeof e);
            if (rc != 0) { err = e; return -1; }
            return 0;
        },
        [this](int rc, const QString &err) { if (rc != 0) log("scan: " + err); else log("scan: done"); },
        /*determinate=*/false);
}

void MainWindow::doRecover() {
    if (!m_ctx) return;
    QString out = QFileDialog::getExistingDirectory(this, tr("Recover output folder"));
    if (out.isEmpty()) return;
    int dry = m_optRecDry->isChecked();
    if (QMessageBox::question(this, tr("Recover"),
            tr("Recover deleted .pkg packages into:\n%1\n\nContinue?").arg(out))
        != QMessageBox::Yes) return;
    startJob(tr("Recovering deleted packages..."),
        [this, out, dry](QString &err) -> int {
            char e[256] = {0};
            int rc = ps4ufs_recover(m_ctx, 0x40000, dry, 0, out.toUtf8().constData(),
                                    &Worker::logCb, m_worker, e, sizeof e);
            if (rc != 0) { err = e; return -1; }
            return 0;
        },
        [this](int rc, const QString &err) { if (rc != 0) log("recover: " + err); else log("recover: done"); },
        /*determinate=*/false);
}

/* ============================== info =================================== */
void MainWindow::showInfo() {
    if (!m_ctx) return;
    char info[1024]; ps4ufs_info_text(m_ctx, info, sizeof info);
    log(QString::fromUtf8(info));
}
void MainWindow::showPartitions() {
    refreshPartitions();
    log(tr("Partitions re-scanned (see the Partition box)."));
}

/* ============================== jobs =================================== */
void MainWindow::startJob(const QString &label, std::function<int(QString &)> body,
                          std::function<void(int, const QString &)> done, bool determinate) {
    if (m_busy) return;
    setBusy(true, label);
    m_worker = new Worker(this);
    m_worker->cancelFlag = false;
    m_worker->job = std::move(body);

    connect(m_worker, &Worker::logLine, this, [this](QString s){ log(s); }, Qt::QueuedConnection);
    connect(m_worker, &Worker::progress, this, [this, determinate](qint64 d, qint64 t){
        if (determinate && t > 0) { m_prog->setRange(0, 1000); m_prog->setValue((int)(d * 1000 / t)); }
        else { m_prog->setRange(0, 0); }
    }, Qt::QueuedConnection);
    connect(m_worker, &Worker::jobFinished, this, [this, done](int rc, QString err){
        setBusy(false, QString());
        if (done) done(rc, err);
        m_worker->deleteLater(); m_worker = nullptr;
        if (m_ctx && !m_searchMode) { /* keep listing as-is */ }
    }, Qt::QueuedConnection);

    if (determinate) { m_prog->setRange(0, 1000); m_prog->setValue(0); }
    else m_prog->setRange(0, 0);
    m_worker->start();
}

void MainWindow::setBusy(bool busy, const QString &label) {
    m_busy = busy;
    m_cancelBtn->setEnabled(busy);
    m_openBtn->setEnabled(!busy);
    if (busy) m_status->setText(label);
    else { m_prog->setRange(0, 1); m_prog->setValue(0); }
}

void MainWindow::cancelJob() {
    if (m_worker) m_worker->cancelFlag = true;
    ps4ufs_set_abort(1);
    m_status->setText(tr("Canceling..."));
}

/* ============================ misc / log =============================== */
void MainWindow::log(const QString &s) {
    for (const QString &line : s.split('\n')) m_log->appendPlainText(line);
}
void MainWindow::clearLog() { m_log->clear(); }

void MainWindow::about() {
    QMessageBox::about(this, tr("About ps4ufs"),
        tr("<b>ps4ufs</b> - PS4 UFS2 encrypted-image browser (Qt port)<br><br>"
           "Browses an AES-128-XTS encrypted PS4 EAP/user partition, extracts files, "
           "and carves/recovers .pkg packages.<br><br>"
           "Core by zecoxao; cross-platform Qt front-end."));
}

void MainWindow::closeEvent(QCloseEvent *e) {
    if (m_busy) {
        if (QMessageBox::question(this, tr("Quit"), tr("A job is running. Quit anyway?"))
            != QMessageBox::Yes) { e->ignore(); return; }
        if (m_worker) { m_worker->cancelFlag = true; ps4ufs_set_abort(1); m_worker->wait(3000); }
    }
    QSettings s;
    s.setValue("Image", m_imgEdit->text());
    s.setValue("Keys", m_keysEdit->text());
    s.setValue("IvOffset", m_ivEdit->text());
    s.setValue("PkgPlain", m_pkgChk->isChecked());
    s.setValue("SkipPkg", m_optSkipPkg->isChecked());
    s.setValue("ScanDryRun", m_optScanDry->isChecked());
    s.setValue("ScanDefrag", m_optScanDefrag->isChecked());
    s.setValue("ScanGeom", m_optScanGeom->isChecked());
    s.setValue("RecoverDryRun", m_optRecDry->isChecked());
    s.setValue("Geometry", saveGeometry());
    QMainWindow::closeEvent(e);
}

void MainWindow::dragEnterEvent(QDragEnterEvent *e) {
    if (e->mimeData()->hasUrls()) e->acceptProposedAction();
}
void MainWindow::dropEvent(QDropEvent *e) {
    const auto urls = e->mimeData()->urls();
    if (urls.isEmpty()) return;
    QString f = urls.first().toLocalFile();
    QFileInfo fi(f);
    if (fi.size() == 32 || f.endsWith(".key", Qt::CaseInsensitive)) {
        m_keysEdit->setText(f);
    } else {
        m_imgEdit->setText(f);
        refreshPartitions();
        openImage();
    }
}
