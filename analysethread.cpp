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
            if(!Globe::capPacket.Index->Aflag && Globe::capPacket.Index->serialnum>0)
            {
                AnalyzeEthernet();
                Globe::capPacket.Index->Aflag=true;
            }
            Globe::capPacket.Index=Globe::capPacket.Index->Next;
        }
        Sleep(1);
    }
    while(Globe::capPacket.Index && Globe::capPacket.Tail && Globe::capPacket.Index!=Globe::capPacket.Tail)
    {
        if(!Globe::capPacket.Index->Aflag && Globe::capPacket.Index->serialnum>0)
        {
            AnalyzeEthernet();
            Globe::capPacket.Index->Aflag=true;
        }
        Globe::capPacket.Index=Globe::capPacket.Index->Next;
    }
    if(Globe::capPacket.Index!=NULL)
    {
        AnalyzeEthernet();
        Globe::capPacket.Index->Aflag=true;
    }
    stopped = false;
    emit AnalyzeStopped();
    qDebug() << "emit AnalyzeStopped";
    return ;
}
