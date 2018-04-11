#include "capturethread.h"
#include "filter.h"
#include "common.h"
#include <QString>

extern pcap_if_t *alldevs;
extern int interface_selected;

CaptureThread::CaptureThread()
{
    stopped = false;
}

void CaptureThread::stop()
{
    stopped = true;
}

void CaptureThread::CaptureStopped()
{

}

void CaptureThread::run()
{
    pcap_t *adhandle;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;
    u_int netmask;
    Filter filter;
    // TODO
    // QString inputFilter; /* 捕获过滤器 */
    int res;
    clock_t CapTime;

    /* 跳转到已选设备 */
    for(d=alldevs, i=0; i< interface_selected;d=d->next, i++);

    /* 打开适配器 */
    if ( (adhandle= pcap_open(d->name,  // 设备名
                             65536,     // 要捕捉的数据包的部分
                                        // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                             PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                             1000,      // 读取超时时间
                             NULL,      // 远程机器验证
                             errbuf     // 错误缓冲池
                             ) ) == NULL)
    {
       // fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
        return ;
    }

    /* 检查数据链路层，为了简单，我们只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
       // fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        return ;
    }

    // TODO
    // filter.setFilter(adhandle,inputFilter);

    if(!Globe::capPacket.Iniflag)
    {
        Globe::capPacket.InitialList();
    }


    /* 开始捕捉 */
    while(!stopped)
    {
        struct pcap_pkthdr *header=NULL;//包头
        const u_char *data=NULL;//包中数据

        res = pcap_next_ex( adhandle, &header,&data);

        if(res>0 && header!=NULL && data!=NULL)//捕获成功增加节点
        {
//            Globe::capPacket.Countpk++;
//            Globe::capPacket.AddPacket();
//            Globe::capPacket.Tail->Initial();
//            Globe::capPacket.Tail->serialnum=Globe::capPacket.Countpk;
//            Globe::capPacket.Tail->copy(header,(u_char *)data);
//            Globe::capPacket.Tail->NAname=d->name;
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
    return ;
}
