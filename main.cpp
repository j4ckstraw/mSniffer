#include "mainwindow.h"
#include <QApplication>

#include "pcap.h"
#include "common.h"

// global vars
pcap_if_t *alldevs;
char errbuf[PCAP_ERRBUF_SIZE];
int interface_selected;
u_char *dataIndex;
QString captureFilterString;
QString displayFilterString;

int main(int argc, char *argv[])
{

    QApplication a(argc, argv);
    MainWindow w;
    interface_selected = 0;  //defalut is the first interface
    w.show();

    // release resources before return;
    int e = a.exec();
    Globe::capPacket.DeleteList();
    // pcap_freealldevs(alldevs);
    return e;
}
