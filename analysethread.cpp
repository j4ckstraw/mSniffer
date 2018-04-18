#include "analysethread.h"
#include "common.h"
#include <QDebug>

extern pcap_if_t *alldevs;
extern int interface_selected;

AnalyseThread::AnalyseThread()
{
    stopped = false;
}

void AnalyseThread::stop()
{
    stopped = true;
}

void AnalyseThread::run()
{
    Globe::capPacket.Index=Globe::capPacket.Head;
    while(!stopped)
    {
        while(Globe::capPacket.Index && Globe::capPacket.Tail && Globe::capPacket.Index!=Globe::capPacket.Tail)
        {
            if(!Globe::capPacket.Index->Aflag && Globe::capPacket.Index->serialnum>0)//此包没有被分析过且不是初始节点
            {
                AnalyzeEthernet();//调用分析函数
                Globe::capPacket.Index->Aflag=true;
            }
            Globe::capPacket.Index=Globe::capPacket.Index->Next;
        }
        Sleep(1);
    }
    while(Globe::capPacket.Index && Globe::capPacket.Tail && Globe::capPacket.Index!=Globe::capPacket.Tail)//停止信号发送后可能还有数据包未分析
    {
        if(!Globe::capPacket.Index->Aflag && Globe::capPacket.Index->serialnum>0)
        {
            AnalyzeEthernet();
            Globe::capPacket.Index->Aflag=true;
        }
        Globe::capPacket.Index=Globe::capPacket.Index->Next;
    }
    if(Globe::capPacket.Index!=NULL)//分析最后一个数据包
    {
        AnalyzeEthernet();
        Globe::capPacket.Index->Aflag=true;
    }
    stopped = false;
    emit AnalyzeStopped();//告知主界面分析已停止，可以停止打印线程
    qDebug() << "emit AnalyzeStopped";
    return ;
}
