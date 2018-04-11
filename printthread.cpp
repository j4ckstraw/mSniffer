#include "printthread.h"
#include "common.h"
#include <QStandardItemModel>
#include <winsock2.h>

extern pcap_if_t *alldevs;
extern int interface_selected;
extern QStandardItemModel *PacketModel;//数据包基本信息

void PrintPacket_online(Packet *Pindex);

PrintThread::PrintThread()
{
    stopped = false;
}

void PrintThread::stop()
{
    stopped = true;
}

void PrintThread::Modelchanged(){}

void PrintThread::run()
{
    while(!stopped)
    {
        Globe::capPacket.Pindex=Globe::capPacket.Head;
        while(Globe::capPacket.Pindex!=Globe::capPacket.Index )
        {
            if(!Globe::capPacket.Pindex->Pflag && Globe::capPacket.Pindex->Aflag)
            {
                while(!MuxFlag)//等待打印完成
                {
                    Sleep(1);
                }
                PrintPacket_online(Globe::capPacket.Pindex);
                emit Modelchanged();
                Globe::capPacket.Pindex->Pflag=true;
            }
            Globe::capPacket.Pindex=Globe::capPacket.Pindex->Next;
        }
        Sleep(1);
    }
    while(Globe::capPacket.Pindex!=Globe::capPacket.Index)//停止信号发送后可能还有未打印的数据包
    {
        if(!Globe::capPacket.Pindex->Pflag && Globe::capPacket.Pindex->Aflag)
        {
            while(!MuxFlag)//等待打印完成
            {
                Sleep(1);
            }
            PrintPacket_online(Globe::capPacket.Pindex);
            emit Modelchanged();
            Globe::capPacket.Pindex->Pflag=true;
        }
        Globe::capPacket.Pindex=Globe::capPacket.Pindex->Next;
    }
    if(Globe::capPacket.Pindex!=NULL)
    {
        if(!Globe::capPacket.Pindex->Pflag && Globe::capPacket.Pindex->Aflag)//打印最后一个数据包
        {
            while(!MuxFlag)//等待打印完成
            {
                Sleep(1);
            }
            PrintPacket_online(Globe::capPacket.Pindex);
            emit Modelchanged();
            Globe::capPacket.Pindex->Pflag=true;
        }
    }
    stopped = false;
}



void PrintPacket_online(Packet *Pindex)
{
    QString s;
    u_short port;
    int row=PacketModel->rowCount();
    PacketModel->insertRow(row,QModelIndex());

    s.setNum(Pindex->serialnum);//序列号
    PacketModel->setData(PacketModel->index(row,0),s);

    s=Pindex->timestamp;//捕获时间
    PacketModel->setData(PacketModel->index(row,1),s);

    u_short k=Pindex->ether_header->ether_type;

    if(k==0x0800)//IPv4
    {
        if(Pindex->IPv4_header==NULL)
        {
            PacketModel->setData(PacketModel->index(row,2),"UNKNOWN");
            PacketModel->setData(PacketModel->index(row,3),"UNKNOWN");
        }
        else
        {
            s=QString("%1.%2.%3.%4").arg(Pindex->IPv4_header->saddr.byte1).arg(Pindex->IPv4_header->saddr.byte2).arg(Pindex->IPv4_header->saddr.byte3).arg(Pindex->IPv4_header->saddr.byte4);//源IP地址
            PacketModel->setData(PacketModel->index(row,2),s);

            s=QString("%1.%2.%3.%4").arg(Pindex->IPv4_header->daddr.byte1).arg(Pindex->IPv4_header->daddr.byte2).arg(Pindex->IPv4_header->daddr.byte3).arg(Pindex->IPv4_header->daddr.byte4);//目的IP地址
            PacketModel->setData(PacketModel->index(row,3),s);
        }

        if(Pindex->IPv4_header->proto==17)//UDP
        {

            s=QString("UDP");
            PacketModel->setData(PacketModel->index(row,4),s);

            if(Pindex->UDP_header==NULL)
            {
                PacketModel->setData(PacketModel->index(row,4),"UNKNOWN");
                PacketModel->setData(PacketModel->index(row,6),"UNKNOWN");
                PacketModel->setData(PacketModel->index(row,7),"UNKNOWN");
            }
            else
            {
            port=ntohs(Pindex->UDP_header->sport);
            s=QString("%1%2").arg(("源端口：")).arg(port);//源端口
            PacketModel->setData(PacketModel->index(row,6),s);

            port=ntohs(Pindex->UDP_header->dport);
            s=QString("%1%2").arg(("目的端口：")).arg(port);//目的端口
            PacketModel->setData(PacketModel->index(row,7),s);
            }
        }
        else if(Pindex->IPv4_header->proto==6)//TCP
        {
            s=QString("TCP");
            PacketModel->setData(PacketModel->index(row,4),s);

            if(Pindex->TCP_header==NULL)
            {
                PacketModel->setData(PacketModel->index(row,4),"UNKNOWN");
                PacketModel->setData(PacketModel->index(row,6),"UNKNOWN");
                PacketModel->setData(PacketModel->index(row,7),"UNKNOWN");
            }
            else
            {
                port=ntohs(Pindex->TCP_header->sport);
                s=QString("%1%2").arg(("源端口：")).arg(port);//源端口
                PacketModel->setData(PacketModel->index(row,6),s);

                port=ntohs(Pindex->TCP_header->dport);
                s=QString("%1%2").arg(("目的端口：")).arg(port);//目的端口
                PacketModel->setData(PacketModel->index(row,7),s);
            }
        }
        else if(Pindex->IPv4_header->proto==1)//ICMP
        {
            s=QString("ICMP");
            PacketModel->setData(PacketModel->index(row,4),s);

            s="UNKNOWN";
            PacketModel->setData(PacketModel->index(row,6),s);
            PacketModel->setData(PacketModel->index(row,7),s);
        }
        else
        {
            PacketModel->setData(PacketModel->index(row,4),Globe::capPacket.Pindex->Netpro);
            s="UNKNOWN";
            PacketModel->setData(PacketModel->index(row,6),s);
            PacketModel->setData(PacketModel->index(row,7),s);
        }

            s.setNum(Pindex->header.len);//包长
            PacketModel->setData(PacketModel->index(row,5),s);
    }
    else if(k==0x86DD)//IPv6
    {
        s=QString("%1.%2.%3.%4.%5.%6.%7.%8.%9.%10.%11.%12.%13.%14.%15.%16").arg(Pindex->IPv6_header->source_ip.byte1).arg(Pindex->IPv6_header->source_ip.byte2).arg(Pindex->IPv6_header->source_ip.byte3).arg(Pindex->IPv6_header->source_ip.byte4).arg(Pindex->IPv6_header->source_ip.byte5).arg(Pindex->IPv6_header->source_ip.byte6).arg(Pindex->IPv6_header->source_ip.byte7).arg(Pindex->IPv6_header->source_ip.byte8).arg(Pindex->IPv6_header->source_ip.byte9).arg(Pindex->IPv6_header->source_ip.byte10).arg(Pindex->IPv6_header->source_ip.byte11).arg(Pindex->IPv6_header->source_ip.byte12).arg(Pindex->IPv6_header->source_ip.byte13).arg(Pindex->IPv6_header->source_ip.byte14).arg(Pindex->IPv6_header->source_ip.byte15).arg(Pindex->IPv6_header->source_ip.byte16);
        PacketModel->setData(PacketModel->index(row,2),s);//源IP

        s=QString("%1.%2.%3.%4.%5.%6.%7.%8.%9.%10.%11.%12.%13.%14.%15.%16").arg(Pindex->IPv6_header->dest_ip.byte1).arg(Pindex->IPv6_header->dest_ip.byte2).arg(Pindex->IPv6_header->dest_ip.byte3).arg(Pindex->IPv6_header->dest_ip.byte4).arg(Pindex->IPv6_header->dest_ip.byte5).arg(Pindex->IPv6_header->dest_ip.byte6).arg(Pindex->IPv6_header->dest_ip.byte7).arg(Pindex->IPv6_header->dest_ip.byte8).arg(Pindex->IPv6_header->dest_ip.byte9).arg(Pindex->IPv6_header->dest_ip.byte10).arg(Pindex->IPv6_header->dest_ip.byte11).arg(Pindex->IPv6_header->dest_ip.byte12).arg(Pindex->IPv6_header->dest_ip.byte13).arg(Pindex->IPv6_header->dest_ip.byte14).arg(Pindex->IPv6_header->dest_ip.byte15).arg(Pindex->IPv6_header->dest_ip.byte16);
        PacketModel->setData(PacketModel->index(row,3),s);//目的IP

        PacketModel->setData(PacketModel->index(row,4),Globe::capPacket.Pindex->Netpro);

        s.setNum(Pindex->header.len);//包长
        PacketModel->setData(PacketModel->index(row,5),s);

        long t=ntohl(Pindex->IPv6_header->load_length);
        s=QString("%1%2").arg(("有效负荷长度:")).arg(t);//报要1


        s=QString("");//报要2
        PacketModel->setData(PacketModel->index(row,7),s);

    }
    else if(k==0x0806)//ARP
    {
        s=QString("%1.%2.%3.%4").arg(Pindex->ARP_header->sip_address.byte1).arg(Pindex->ARP_header->sip_address.byte2).arg(Pindex->ARP_header->sip_address.byte3).arg(Pindex->ARP_header->sip_address.byte4);
        PacketModel->setData(PacketModel->index(row,2),s);//源IP

        s=QString("ARP");
        PacketModel->setData(PacketModel->index(row,4),s);//协议

        s.setNum(Pindex->header.len);//包长
        PacketModel->setData(PacketModel->index(row,5),s);

        if(ntohs(Pindex->ARP_header->option)==0x0001)
        {
            s=QString(("广播"));
            PacketModel->setData(PacketModel->index(row,3),s);//目的IP

            s=QString("%1 %2.%3.%4.%5 %6").arg(("谁有")).arg(Pindex->ARP_header->dip_address.byte1).arg(Pindex->ARP_header->dip_address.byte2).arg(Pindex->ARP_header->dip_address.byte3).arg(Pindex->ARP_header->dip_address.byte4).arg(("的物理地址"));//报要1
            PacketModel->setData(PacketModel->index(row,6),s);

            s=QString("%1 %2.%3.%4.%5").arg(("请告知")).arg(Pindex->ARP_header->sip_address.byte1).arg(Pindex->ARP_header->sip_address.byte2).arg(Pindex->ARP_header->sip_address.byte3).arg(Pindex->ARP_header->sip_address.byte4);//报要2
            PacketModel->setData(PacketModel->index(row,7),s);
        }
        else
        {
            s=QString("%1.%2.%3.%4").arg(Pindex->ARP_header->dip_address.byte1).arg(Pindex->ARP_header->dip_address.byte2).arg(Pindex->ARP_header->dip_address.byte3).arg(Pindex->ARP_header->dip_address.byte4);
            PacketModel->setData(PacketModel->index(row,3),s);//目的IP

            s=QString("%1 %2.%3.%4.%5").arg(("我是")).arg(Pindex->ARP_header->sip_address.byte1).arg(Pindex->ARP_header->sip_address.byte2).arg(Pindex->ARP_header->sip_address.byte3).arg(Pindex->ARP_header->sip_address.byte4);//报要1
           PacketModel->setData(PacketModel->index(row,6),s);

           s=QString("%1 %2：%3：%4：%5：%6：%7").arg(("我的物理地址是")).arg(Pindex->ARP_header->snether_address.byte1,0,16).arg(Pindex->ARP_header->snether_address.byte2,0,16).arg(Pindex->ARP_header->snether_address.byte3,0,16).arg(Pindex->ARP_header->snether_address.byte4,0,16).arg(Pindex->ARP_header->snether_address.byte5,0,16).arg(Pindex->ARP_header->snether_address.byte6,0,16);//报要2
           PacketModel->setData(PacketModel->index(row,7),s);
        }

    }
    else if(k==0x8035)//RARP
    {
        s=QString("%1.%2.%3.%4").arg(Pindex->ARP_header->sip_address.byte1).arg(Pindex->ARP_header->sip_address.byte2).arg(Pindex->ARP_header->sip_address.byte3).arg(Pindex->ARP_header->sip_address.byte4);
        PacketModel->setData(PacketModel->index(row,2),s);//源IP

        s=QString("RARP");
        PacketModel->setData(PacketModel->index(row,4),s);//协议

        s.setNum(Pindex->header.len);//包长
        PacketModel->setData(PacketModel->index(row,5),s);
        if(ntohs(Pindex->ARP_header->option)==0x0003)
        {
            s=QString(("广播"));
            PacketModel->setData(PacketModel->index(row,3),s);//目的IP

            s=QString("%1 %2：%3：%4：%5：%6：%7%8").arg(("谁有")).arg(Pindex->ARP_header->snether_address.byte1,0,16).arg(Pindex->ARP_header->snether_address.byte2,0,16).arg(Pindex->ARP_header->snether_address.byte3,0,16).arg(Pindex->ARP_header->snether_address.byte4,0,16).arg(Pindex->ARP_header->snether_address.byte5,0,16).arg(Pindex->ARP_header->snether_address.byte6,0,16).arg(("的IP地址"));//报要1
            PacketModel->setData(PacketModel->index(row,6),s);

            s=QString("%1 %2：%3：%4：%5：%6：%7").arg(("请告知")).arg(Pindex->ARP_header->snether_address.byte1,0,16).arg(Pindex->ARP_header->snether_address.byte2,0,16).arg(Pindex->ARP_header->snether_address.byte3,0,16).arg(Pindex->ARP_header->snether_address.byte4,0,16).arg(Pindex->ARP_header->snether_address.byte5,0,16).arg(Pindex->ARP_header->snether_address.byte6,0,16);//报要2
            PacketModel->setData(PacketModel->index(row,7),s);
        }
        else
        {
            s=QString("%1.%2.%3.%4").arg(Pindex->ARP_header->dip_address.byte1).arg(Pindex->ARP_header->dip_address.byte2).arg(Pindex->ARP_header->dip_address.byte3).arg(Pindex->ARP_header->dip_address.byte4);
            PacketModel->setData(PacketModel->index(row,3),s);//目的IP

           s=QString("%1 %2：%3：%4：%5：%6：%7%8").arg(("我有")).arg(Pindex->ARP_header->dnether_address.byte1).arg(Pindex->ARP_header->dnether_address.byte2).arg(Pindex->ARP_header->dnether_address.byte3).arg(Pindex->ARP_header->dnether_address.byte4).arg(Pindex->ARP_header->dnether_address.byte5).arg(Pindex->ARP_header->dnether_address.byte6).arg(("的IP地址"));//报要1
           PacketModel->setData(PacketModel->index(row,6),s);

           s=QString("");//报要2
           PacketModel->setData(PacketModel->index(row,7),s);
        }
    }
    else
    {
        s="UNKNOWN";
        PacketModel->setData(PacketModel->index(row,2),s);
        PacketModel->setData(PacketModel->index(row,3),s);
        PacketModel->setData(PacketModel->index(row,4),s);
        PacketModel->setData(PacketModel->index(row,5),s);
        PacketModel->setData(PacketModel->index(row,6),s);
        PacketModel->setData(PacketModel->index(row,7),s);
    }

}
