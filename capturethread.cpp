#include "capturethread.h"
#include "filter.h"
#include "common.h"
#include <QString>
#include <QDebug>
#include <QMessageBox>

extern pcap_if_t *alldevs;
extern int interface_selected;
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

//void CaptureThread::CaptureStopped(){}

void CaptureThread::run()
{
    pcap_t *adhandle;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;
    u_int netmask;

    Filter filter;
    int res;
    clock_t capTime;

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< interface_selected;d=d->next, i++);

    /* Open the adapter */
    if ( (adhandle= pcap_open(d->name,   // 设备名
                              65536,     // 要捕捉的数据包的部分
                                         // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                              1000,      // 读取超时时间
                              NULL,      // 远程机器验证
                              errbuf     // 错误缓冲池
                              ) ) == NULL)
        //        if ((adhandle= pcap_open_live(d->name,	// name of the device
        //                                      65536,	// portion of the packet to capture.
        //                                                // 65536 grants that the whole packet will be captured on all the MACs.
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


    filter.setFilter(adhandle,captureFilterString);

    if(!Globe::capPacket.Iniflag)
    {
        Globe::capPacket.InitialList();
    }

    /* 开始捕捉 */
    while(!stopped)
    {
        struct pcap_pkthdr *header=NULL;//包头
        const u_char *data=NULL;       //包中数据

        res = pcap_next_ex(adhandle, &header,&data);

        if(res>0 && header!=NULL && data!=NULL)//捕获成功增加节点
        {
            Globe::capPacket.Countpk++;
            Globe::capPacket.AddPacket();
            Globe::capPacket.Tail->Initial();
            Globe::capPacket.Tail->serialnum=Globe::capPacket.Countpk;
            Globe::capPacket.Tail->copy(header,(u_char *)data);
            Globe::capPacket.Tail->NAname=d->name;
            //printf("%d CaptureTime=%d, len:%d\n",Globe::capPacket.Tail->serialnum,Globe::capPacket.Tail->captime,Globe::capPacket.Tail->header->len);
        }
        else
        {
            //Globe::capPacket.DeleteNode();
            /*if(res == 0)
                printf("Out of time while capturing the packets: %s\n", pcap_geterr(adhandle));
            else if(res == -1)
                printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
            else if(res == -2)
                printf("EOF was reached reading from an offline capture\n");*/
            continue;
        }

    }
    stopped = false;
    emit CaptureStopped();//告知主界面捕获已停止，可以停止分析线程
    qDebug() << "emit CaptureStopped";
    return ;
}
