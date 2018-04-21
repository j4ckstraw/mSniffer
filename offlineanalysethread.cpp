#include "offlineanalysethread.h"
#include "filter.h"
#include "common.h"
#include <QMessageBox>
#include <QStandardItemModel>
#include <QString>
#include <QDebug>

extern QString file_name;
extern QStandardItemModel *PacketModel;
void PrintPacket_on_fly(Packet *Pindex);

OfflineAnalyseThread::OfflineAnalyseThread()
{
    stopped = false;
}
OfflineAnalyseThread::~OfflineAnalyseThread(){}

void OfflineAnalyseThread::stop()
{
    stopped = true;
}

void OfflineAnalyseThread::run()
{
    int res;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Open the capture file */
    if ((adhandle = pcap_open_offline(file_name.toStdString().c_str(),			// name of the device
                                      errbuf					// error buffer
                                      )) == NULL)
    {
        // fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
        QMessageBox::warning(0,"Warning","Unable to open the file "+file_name);
        return ;
    }

    /* read and dispatch packets until EOF is reached */
    // pcap_loop(fp, 0, dispatcher_handler, NULL);



    if(!Globe::capPacket.Iniflag)
    {
        Globe::capPacket.InitialList();
    }

    qDebug() << "Start capture in offline";

    while(!stopped)
    {
        struct pcap_pkthdr *header=NULL;//包头
        const u_char *data=NULL;       //包中数据

        res = pcap_next_ex(adhandle, &header,&data);

        if(res>0 && header!=NULL && data!=NULL)//捕获成功增加节点
        {
            // qDebug() << "Valid file";
            Globe::capPacket.Countpk++;
            Globe::capPacket.AddPacket();
            Globe::capPacket.Tail->Initial();
            // Globe::capPacket.Tail = Packet;
            Globe::capPacket.Tail->serialnum=Globe::capPacket.Countpk;
            Globe::capPacket.Tail->copy(header,(u_char *)data);
            Globe::capPacket.Tail->NAname="FILE";
            qDebug() << QString("res is %1").arg(res);
            //printf("%d CaptureTime=%d, len:%d\n",Globe::capPacket.Tail->serialnum,Globe::capPacket.Tail->captime,Globe::capPacket.Tail->header->len);
        }
        else if(res == -1)
        {
            // QMessageBox::warning(0,"Warning","A error occur when pcap_next_ex");
            qDebug()<< "A error occur when pcap_next_ex" ;
            stopped = true;
        }
        else if(res == -2){
            // QMessageBox::information(0,"Success","Read over");
            qDebug()<< "Read over" ;
            stopped = true;
        }
        else
        {
            // QMessageBox::warning(0,"Error","Unknown error");
            qDebug()<< "Unknown error" ;
            stopped = true;
        }
    }

    stopped = false;
    emit OfflineStopped();   //告知主界面捕获已停止，可以停止分析线程
    qDebug() << "emit OfflineStopped";
    pcap_close(adhandle);
    return ;
}


