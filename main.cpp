#include "mainwindow.h"
#include <QApplication>

#include "pcap.h"
#include "common.h"

// global vars
pcap_if_t *alldevs;
int interface_selected;
u_char *dataIndex;
QString file_name;
QString captureFilterString;
QString displayFilterString;

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    QApplication a(argc, argv);
    MainWindow w;

    interface_selected = 0;  //defalut is the first interface

//    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
//    {
//        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
//        return 0;
//    }

    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    interfacesDialog *chosedialog = new interfacesDialog();
    w.show();
    chosedialog->show();

    // release resources before return;
    int e = a.exec();
    Globe::capPacket.DeleteList();
    pcap_freealldevs(alldevs);
    return e;
}
