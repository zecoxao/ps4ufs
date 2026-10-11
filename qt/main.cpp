#include "mainwindow.h"
#include <QApplication>

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QApplication::setOrganizationName("zecoxao");
    QApplication::setApplicationName("ps4ufs");
    MainWindow w;
    w.show();
    return app.exec();
}
