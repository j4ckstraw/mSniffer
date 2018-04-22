#include "offlinecapturethread.h"
#include "filter.h"
#include "common.h"
#include <QMessageBox>
#include <QStandardItemModel>
#include <QString>
#include <QDebug>

extern QString file_name;

OfflineCaptureThread::OfflineCaptureThread()
{
    stopped = false;
}
OfflineCaptureThread::~OfflineCaptureThread(){}

void OfflineCaptureThread::stop()
{
    stopped = true;
}

void OfflineCaptureThread::run()
{
    int res;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Open the capture file */
    if ((adhandle = pcap_open_offline(file_name.toStdString().c_str(),			// name of the device
                                      errbuf					// error buffer
                                      )) == NULL)
    {
        QMessageBox::warning(0,"Warning","Unable to open the file "+file_name);
        return ;
    }

    if(!Globe::capPacket.Iniflag)
    {
        Globe::capPacket.InitialList();
    }

    qDebug() << "Start capture in offline";
    while(!stopped)
    {
        struct pcap_pkthdr *header=NULL;// header
        const u_char *data=NULL;       // data

        res = pcap_next_ex(adhandle, &header,&data);

        if(res>0 && header!=NULL && data!=NULL)
        {
            // qDebug() << "Valid file";
            Globe::capPacket.Countpk++;
            Globe::capPacket.AddPacket();
            Globe::capPacket.Tail->Initial();
            Globe::capPacket.Tail->serialnum=Globe::capPacket.Countpk;
            Globe::capPacket.Tail->copy(header,(u_char *)data);
            Globe::capPacket.Tail->NAname="FILE";
            qDebug() << QString("offline packet is %1").arg(res);
        }
        else if(res == -1)
        {
            qDebug()<< "A error occur when pcap_next_ex" ;
            stopped = true;
        }
        else if(res == -2){
            qDebug()<< "Read over" ;
            stopped = true;
        }
        else
        {
            qDebug()<< "Unknown error" ;
            stopped = true;
        }
    }

    stopped = false;
    emit OfflineStopped();
    qDebug() << "emit OfflineStopped";
    pcap_close(adhandle);
    return ;
}


