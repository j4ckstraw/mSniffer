#include "capturethread.h"
#include "filter.h"
#include "common.h"
#include <QString>
#include <QDebug>
#include <QMessageBox>

extern QList<QString> devicesName;
extern int interface_selected;
extern char errbuf[PCAP_ERRBUF_SIZE];
extern QString captureFilterString;

CaptureThread::CaptureThread()
{
    stopped = false;
}

CaptureThread::~CaptureThread(){}

void CaptureThread::stop()
{
    stopped = true;
}

void CaptureThread::run()
{
    pcap_t *adhandle;
    Filter filter;
    int res;
    const char *name = devicesName.at(interface_selected).toStdString().c_str();
    QString Dname = QString(name);

    // Open the adapter
    if ( (adhandle= pcap_open(name,                 // name of the device
                              65536,                // portion of the packet to capture.
                              // 65536 grants that the whole packet will be captured on all the MACs.
                              PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode (nonzero means promiscuous)
                              1000,                 // read timeout
                              NULL,
                              errbuf                // error buffer
                              ) ) == NULL)
        //        if ((adhandle= pcap_open_live(d->name,
        //                                      65536,	// portion of the packet to capture.
        //                                      // 65536 grants that the whole packet will be captured on all the MACs.
        //                                      1,		// promiscuous mode (nonzero means promiscuous)
        //                                      1000,		// read timeout
        //                                      errbuf	// error buffer
        //                                      )) == NULL)
    {
        QMessageBox::warning(0,"Warning!","\nUnable to open the adapter. %s is not supported by WinPcap\n");
        return ;
    }

    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        QMessageBox::warning(0,"Warning!","This program works only on Ethernet networks");
        return;
    }

    // set capture filter
    filter.setFilter(adhandle,captureFilterString);
    if(!Globe::capPacket.Iniflag)
    {
        Globe::capPacket.InitialList();
    }

    // start capture
    while(!stopped)
    {
        struct pcap_pkthdr *header=NULL;
        const u_char *data=NULL;

        res = pcap_next_ex(adhandle, &header,&data);

        if(res>0 && header!=NULL && data!=NULL)
        {
            Globe::capPacket.Countpk++;
            Globe::capPacket.AddPacket();
            Globe::capPacket.Tail->Initial();
            Globe::capPacket.Tail->serialnum=Globe::capPacket.Countpk;
            Globe::capPacket.Tail->copy(header,(u_char *)data);
            Globe::capPacket.Tail->NAname=Dname;
        }
    }// while stopped
    stopped = false;
    emit CaptureStopped();//告知主界面捕获已停止，可以停止分析线程
    qDebug() << "emit CaptureStopped";
    return ;
}
