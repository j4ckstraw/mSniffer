#include "packetprintthread.h"
#include "common.h"
#include "packet.h"
#include <QStandardItemModel>
#include <winsock2.h>
#include <QDebug>

extern pcap_if_t *alldevs;
extern int interface_selected;
extern QStandardItemModel *PacketModel;//数据包基本信息

void PrintPacket_on_fly(Packet *Pindex);

PrintThread::PrintThread()
{
    stopped = false;
}

PrintThread::~PrintThread(){}

void PrintThread::stop()
{
    stopped = true;
}

void PrintThread::run()
{
    while(!stopped)
    {
        Globe::capPacket.Pindex=Globe::capPacket.Head;
        while(Globe::capPacket.Pindex!=Globe::capPacket.Index)
        {
            if(!Globe::capPacket.Pindex->Pflag && Globe::capPacket.Pindex->Aflag)
            {
                while(!MuxFlag)//等待打印完成
                {
                    Sleep(1);
                }
                PrintPacket_on_fly(Globe::capPacket.Pindex);
                emit PacketPrintDone();
                Globe::capPacket.Pindex->Pflag=true;
            }
            Globe::capPacket.Pindex=Globe::capPacket.Pindex->Next;
        }
        Sleep(1);
    }
    while(Globe::capPacket.Pindex && Globe::capPacket.Pindex!=Globe::capPacket.Index)//停止信号发送后可能还有未打印的数据包
    {
        if(!Globe::capPacket.Pindex->Pflag && Globe::capPacket.Pindex->Aflag)
        {
            while(!MuxFlag)//等待打印完成
            {
                Sleep(1);
            }
            PrintPacket_on_fly(Globe::capPacket.Pindex);
            emit PacketPrintDone();
            qDebug() << "emit PacketPrintDone";
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
            PrintPacket_on_fly(Globe::capPacket.Pindex);
            emit PacketPrintDone();
            qDebug() << "emit PacketPrintDone";
            Globe::capPacket.Pindex->Pflag=true;
        }
    }
    stopped = false;
    emit PacketPrintDone();
    qDebug() << "emit PacketPrintDone";
    return ;
}


void PrintPacket_on_fly(Packet *Pindex)
{
    QString s;
    // u_short port;
    u_short src_port;
    u_short dst_port;
    int row=PacketModel->rowCount();
    PacketModel->insertRow(row,QModelIndex());
    s.setNum(Pindex->serialnum);// sequence num
    PacketModel->setData(PacketModel->index(row,0),s);
    s=Pindex->timestamp;//capture time
    PacketModel->setData(PacketModel->index(row,1),s);
    u_short k=Pindex->ether_header->ether_type;
    if (Pindex->Netpro.compare("IPv4")==0)
    {
        if(Pindex->IPv4_header==NULL)
        {
            PacketModel->setData(PacketModel->index(row,2),"UNKNOWN");
            PacketModel->setData(PacketModel->index(row,3),"UNKNOWN");
        }
        else
        {
            s = iptos(Pindex->IPv4_header->saddr);
            PacketModel->setData(PacketModel->index(row,2),s);
            s = iptos(Pindex->IPv4_header->daddr);
            PacketModel->setData(PacketModel->index(row,3),s);
        }
        if(Pindex->Transpro.compare("UDP") == 0)
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
                src_port = ntohs(Pindex->UDP_header->sport);
                dst_port = ntohs(Pindex->UDP_header->dport);
                s = QString("%1 -> %2").arg(src_port).arg(dst_port);
                PacketModel->setData(PacketModel->index(row,6),s);
            }
        }
        else if(Pindex->Transpro.compare("TCP") == 0)
        {
            s=QString("TCP");
            PacketModel->setData(PacketModel->index(row,4),s);

            src_port = ntohs(Pindex->TCP_header->sport);
            dst_port = ntohs(Pindex->TCP_header->dport);

            if(Pindex->TCP_header==NULL)
            {
                PacketModel->setData(PacketModel->index(row,4),"UNKNOWN");
                PacketModel->setData(PacketModel->index(row,6),"UNKNOWN");
                PacketModel->setData(PacketModel->index(row,7),"UNKNOWN");
            }

            if (Pindex->Apppro.compare("HTTP")==0)
            {
                s=QString("HTTP");
                PacketModel->setData(PacketModel->index(row,4),s);

                QString http_txt = analyzeHttpPacket(Pindex);
                HTTP httpInfo = HTTP(http_txt);
                if (src_port == 80) s = httpInfo.httpResponse.split("\r\n")[0];
                else if(dst_port == 80) s = httpInfo.httpMethod.split("\r\n")[0];
                else s = "UNKNOWN";
                PacketModel->setData(PacketModel->index(row,6),s);
            }
            else
            {
                s = QString("%1 -> %2").arg(src_port).arg(dst_port);
                PacketModel->setData(PacketModel->index(row,6),s);
            }
        }
        else if(Pindex->IPv4_header->proto==PROTO_TYPE_ICMP)//ICMP
        {
            s=QString("ICMP");
            PacketModel->setData(PacketModel->index(row,4),s);
            switch(Pindex->ICMP_header->type){
            case ICMP_ECHO:
                s = QString("Echo Request");
                /* XXX ID + Seq + Data */
                break;
            case ICMP_ECHOREPLY:
                s = QString("Echo Reply");
                break;
            case ICMP_DEST_UNREACH:
                switch(Pindex->ICMP_header->code)
                {
                case ICMP_NET_UNREACH:
                    s = QString("Destination Net Unreachable\n");
                    break;
                case ICMP_HOST_UNREACH:
                    s = QString("Destination Host Unreachable\n");
                    break;
                case ICMP_PROT_UNREACH:
                    s = QString("Destination Protocol Unreachable\n");
                    break;
                case ICMP_PORT_UNREACH:
                    s = QString("Destination Port Unreachable\n");
                    break;
                case ICMP_FRAG_NEEDED:
                    // s = QString("Frag needed and DF set (mtu = %u)\n", info);
                    s = QString("Frag needed and DF set ");
                    break;
                case ICMP_SR_FAILED:
                    s = QString("Source Route Failed");
                    break;
                case ICMP_NET_UNKNOWN:
                    s = QString("Destination Net Unknown");
                    break;
                case ICMP_HOST_UNKNOWN:
                    s = QString("Destination Host Unknown");
                    break;
                case ICMP_HOST_ISOLATED:
                    s = QString("Source Host Isolated");
                    break;
                case ICMP_NET_ANO:
                    s = QString("Destination Net Prohibited");
                    break;
                case ICMP_HOST_ANO:
                    s = QString("Destination Host Prohibited");
                    break;
                case ICMP_NET_UNR_TOS:
                    s = QString("Destination Net Unreachable for Type of Service");
                    break;
                case ICMP_HOST_UNR_TOS:
                    s = QString("Destination Host Unreachable for Type of Service");
                    break;
                case ICMP_PKT_FILTERED:
                    s = QString("Packet filtered");
                    break;
                case ICMP_PREC_VIOLATION:
                    s = QString("Precedence Violation");
                    break;
                case ICMP_PREC_CUTOFF:
                    s = QString("Precedence Cutoff");
                    break;
                default:
                    s = QString("Dest Unreachable, Bad Code: %1").arg(Pindex->ICMP_header->code);
                    break;
                }// switch code
            case ICMP_SOURCE_QUENCH:
                s = QString("Source Quench");
                break;
            case ICMP_REDIRECT:
                switch(Pindex->ICMP_header->code) {
                case ICMP_REDIR_NET:
                    s = QString("Redirect Network");
                    break;
                case ICMP_REDIR_HOST:
                    s = QString("Redirect Host");
                    break;
                case ICMP_REDIR_NETTOS:
                    s = QString("Redirect Type of Service and Network");
                    break;
                case ICMP_REDIR_HOSTTOS:
                    s = QString("Redirect Type of Service and Host");
                    break;
                default:
                    s = QString("Redirect, Bad Code: %1").arg(Pindex->ICMP_header->code);
                    break;
                }// switch code
            case ICMP_TIME_EXCEEDED:
                switch(Pindex->ICMP_header->code) {
                case ICMP_EXC_TTL:
                    s = QString("Time to live exceeded");
                    break;
                case ICMP_EXC_FRAGTIME:
                    s = QString("Frag reassembly time exceeded");
                    break;
                default:
                    s = QString("Time exceeded, Bad Code: %1").arg(Pindex->ICMP_header->code);
                    break;
                }
                break;
            case ICMP_PARAMETERPROB:
                // s = QString("Parameter problem: pointer = %1").arg(icp ? (ntohl(icp->un.gateway)>>24) : info);
                s = QString("Parameter problem");
                break;
            case ICMP_TIMESTAMP:
                s = QString("Timestamp");
                /* XXX ID + Seq + 3 timestamps */
                break;
            case ICMP_TIMESTAMPREPLY:
                s = QString("Timestamp Reply");
                /* XXX ID + Seq + 3 timestamps */
                break;
            case ICMP_INFO_REQUEST:
                s = QString("Information Request");
                /* XXX ID + Seq */
                break;
            case ICMP_INFO_REPLY:
                s = QString("Information Reply");
                /* XXX ID + Seq */
                break;
            default:
                    s = QString("Bad ICMP type: %1").arg(Pindex->ICMP_header->type);
            }//switch type
            PacketModel->setData(PacketModel->index(row,6),s);
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
    }// IPv4
    else if(k==ETHER_TYPE_IPv6)//IPv6
    {
        s = ip6tos(Pindex->IPv6_header->source_ip);
        PacketModel->setData(PacketModel->index(row,2),s);//source ip
        s = ip6tos(Pindex->IPv6_header->dest_ip);
        PacketModel->setData(PacketModel->index(row,3),s);//destination ip
        PacketModel->setData(PacketModel->index(row,4),Globe::capPacket.Pindex->Netpro);

        s.setNum(Pindex->header.len);
        PacketModel->setData(PacketModel->index(row,5),s);

        long t=ntohl(Pindex->IPv6_header->load_length);
        s=QString("%1%2").arg(("payload length: ")).arg(t);

    } //IPv6
    else if(k==ETHER_TYPE_ARP)//ARP
    {
        s = iptos(Pindex->ARP_header->sip_address);
        PacketModel->setData(PacketModel->index(row,2),s);//source ip
        s=QString("ARP");
        PacketModel->setData(PacketModel->index(row,4),s);//protocol
        s.setNum(Pindex->header.len);//包长
        PacketModel->setData(PacketModel->index(row,5),s);
        if(ntohs(Pindex->ARP_header->opcode)==ARPOP_REQUEST) // ARP request
        {
            s=QString(("Broadcast"));
            PacketModel->setData(PacketModel->index(row,3),s);//destination ip

            s = QString("Who has ") \
                    + iptos(Pindex->ARP_header->dip_address) \
                    + QString(" Tell ") \
                    + iptos(Pindex->ARP_header->sip_address);

            PacketModel->setData(PacketModel->index(row,6),s);
        }
        else if(ntohs(Pindex->ARP_header->opcode)==ARPOP_REPLY)  // ARP reply
        {
            s = iptos(Pindex->ARP_header->dip_address);
            PacketModel->setData(PacketModel->index(row,3),s); //destination ip

            s = iptos(Pindex->ARP_header->sip_address)\
                    + QString(" is at ")\
                    + mactos(Pindex->ARP_header->snether_address);
            PacketModel->setData(PacketModel->index(row,6),s);
        }
        else
        {
            s = iptos(Pindex->ARP_header->dip_address);
            PacketModel->setData(PacketModel->index(row,3),s);
            s = "UNKNOWN ARP OPCODE";
            PacketModel->setData(PacketModel->index(row,6),s);
        }
    } // ARP
    else if(k==ETHER_TYPE_RARP)//RARP
    {
        s = iptos(Pindex->ARP_header->sip_address);
        PacketModel->setData(PacketModel->index(row,2),s);// source ip
        s=QString("RARP");
        PacketModel->setData(PacketModel->index(row,4),s);// protocol
        s.setNum(Pindex->header.len);//包长
        PacketModel->setData(PacketModel->index(row,5),s);
        if(ntohs(Pindex->ARP_header->opcode)==ARPOP_RREQUEST)       // RARP REQUEST
        {
            s=QString(("Broadcast"));
            PacketModel->setData(PacketModel->index(row,3),s);// destination ip
            s = QString("Who is ") \
                    + mactos(Pindex->ARP_header->dnether_address)\
                    + QString(" Tell ")\
                    + mactos(Pindex->ARP_header->snether_address);
            PacketModel->setData(PacketModel->index(row,6),s);
        }
        else if(ntohs(Pindex->ARP_header->opcode)==ARPOP_RREPLY) // RARP REPLY
        {
           s = iptos(Pindex->ARP_header->dip_address);
           PacketModel->setData(PacketModel->index(row,3),s);
           s = mactos(Pindex->ARP_header->dnether_address) \
                   + QString(" is at ") \
                   + iptos(Pindex->ARP_header->dip_address);
           PacketModel->setData(PacketModel->index(row,6),s);
        }
        else
        {
            s = iptos(Pindex->ARP_header->dip_address);
            PacketModel->setData(PacketModel->index(row,3),s);
            s = "UNKNOWN RARP OPCODE";
            PacketModel->setData(PacketModel->index(row,6),s);
        }
    } //RARP
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
