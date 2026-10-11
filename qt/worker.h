/* worker.h - runs a blocking bridge call on a background thread and marshals
 * progress / log / completion back to the GUI thread via queued signals. */
#ifndef PS4UFS_WORKER_H
#define PS4UFS_WORKER_H

#include <QThread>
#include <QString>
#include <atomic>
#include <functional>

class Worker : public QThread {
    Q_OBJECT
public:
    explicit Worker(QObject *parent = nullptr) : QThread(parent) {}

    /* the job returns an rc and may fill err; it runs on this thread */
    std::function<int(QString & /*err*/)> job;
    std::atomic<bool> cancelFlag{false};

    /* C trampolines for the bridge callbacks (ud == Worker*) */
    static int  progressCb(long long done, long long total, void *ud) {
        Worker *w = static_cast<Worker *>(ud);
        emit w->progress((qint64)done, (qint64)total);
        return w->cancelFlag.load() ? 1 : 0;
    }
    static void logCb(const char *line, void *ud) {
        Worker *w = static_cast<Worker *>(ud);
        emit w->logLine(QString::fromUtf8(line));
    }

signals:
    void progress(qint64 done, qint64 total);
    void logLine(QString line);
    void jobFinished(int rc, QString err);

protected:
    void run() override {
        QString err;
        int rc = job ? job(err) : -1;
        emit jobFinished(rc, err);
    }
};

#endif
