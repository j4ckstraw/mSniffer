#include "mainwindow.h"
#include <QApplication>

#include "pcap.h"

// global vars
pcap_if_t *alldevs;
int interface_selected;

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE+1];
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

    w.show();


    // release resources before return;
    int e = a.exec();
    pcap_freealldevs(alldevs);
    return e;
}
