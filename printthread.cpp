#include "printthread.h"
#include "common.h"
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
    qDebug() << "Print Thread start";
    while(!stopped)
    {
        qDebug() << "In Print thread no stopped";
        Globe::capPacket.Pindex=Globe::capPacket.Head;
        while(Globe::capPacket.Pindex!=Globe::capPacket.Index )
        {
            if(!Globe::capPacket.Pindex->Pflag && Globe::capPacket.Pindex->Aflag)
            {
                while(!MuxFlag)//等待打印完成
                {
                    Sleep(1);
                }
                PrintPacket_on_fly(Globe::capPacket.Pindex);
                emit Modelchanged();
                qDebug() << "emit Modelchanged";
                Globe::capPacket.Pindex->Pflag=true;
            }
            Globe::capPacket.Pindex=Globe::capPacket.Pindex->Next;
        }
        Sleep(1);
    }
    qDebug()<< "Print thread outof while";
    while(Globe::capPacket.Pindex && Globe::capPacket.Pindex!=Globe::capPacket.Index)//停止信号发送后可能还有未打印的数据包
    {
        if(!Globe::capPacket.Pindex->Pflag && Globe::capPacket.Pindex->Aflag)
        {
            qDebug() << "Print thread another while";
            while(!MuxFlag)//等待打印完成
            {
                Sleep(1);
                qDebug() << "Sleep";
            }
            PrintPacket_on_fly(Globe::capPacket.Pindex);
            emit Modelchanged();
            qDebug() << "emit Modelchanged";
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
            emit Modelchanged();
            qDebug() << "emit Modelchanged";
            Globe::capPacket.Pindex->Pflag=true;
        }
    }
    stopped = false;
    emit Modelchanged();
    qDebug() << "emit Modelchanged";
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

    qDebug() << "In PrintPacket_on_fly";
    s.setNum(Pindex->serialnum);//序列号
    qDebug() << "Serianum is : " << Pindex->serialnum;
    PacketModel->setData(PacketModel->index(row,0),s);

    s=Pindex->timestamp;//捕获时间
    PacketModel->setData(PacketModel->index(row,1),s);

    u_short k=Pindex->ether_header->ether_type;

    if(k==ETHER_TYPE_IPv4)//IPv4
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

        if(Pindex->IPv4_header->proto==PROTO_TYPE_UDP)//UDP
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
        else if(Pindex->IPv4_header->proto==PROTO_TYPE_TCP)//TCP
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
            // else if (dst_port == 80 || src_port == 80) // HTTP
            // else if(Pindex->)
            if (Globe::capPacket.Pindex->Netpro.compare("IPv4")==0)
            {
                s=QString("HTTP");
                PacketModel->setData(PacketModel->index(row,4),s);

                QString http_txt = analyzeHttpPacket(Pindex);
                HTTP httpInfo = HTTP(http_txt);
                if (src_port == 80) s = httpInfo.httpResponse;
                else if(dst_port == 80) s = httpInfo.httpMethod;
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

//            s="UNKNOWN";
//            PacketModel->setData(PacketModel->index(row,6),s);
//            PacketModel->setData(PacketModel->index(row,7),s);
            switch(Pindex->ICMP_header->type){
            case ICMP_ECHO:
                s = QString("Echo Request\n");
                /* XXX ID + Seq + Data */
                break;
            case ICMP_ECHOREPLY:
                s = QString("Echo Reply\n");
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
                    s = QString("Source Route Failed\n");
                    break;
                case ICMP_NET_UNKNOWN:
                    s = QString("Destination Net Unknown\n");
                    break;
                case ICMP_HOST_UNKNOWN:
                    s = QString("Destination Host Unknown\n");
                    break;
                case ICMP_HOST_ISOLATED:
                    s = QString("Source Host Isolated\n");
                    break;
                case ICMP_NET_ANO:
                    s = QString("Destination Net Prohibited\n");
                    break;
                case ICMP_HOST_ANO:
                    s = QString("Destination Host Prohibited\n");
                    break;
                case ICMP_NET_UNR_TOS:
                    s = QString("Destination Net Unreachable for Type of Service\n");
                    break;
                case ICMP_HOST_UNR_TOS:
                    s = QString("Destination Host Unreachable for Type of Service\n");
                    break;
                case ICMP_PKT_FILTERED:
                    s = QString("Packet filtered\n");
                    break;
                case ICMP_PREC_VIOLATION:
                    s = QString("Precedence Violation\n");
                    break;
                case ICMP_PREC_CUTOFF:
                    s = QString("Precedence Cutoff\n");
                    break;
                default:
                    s = QString("Dest Unreachable, Bad Code: %1\n").arg(Pindex->ICMP_header->code);
                    break;
                }// switch code
            case ICMP_SOURCE_QUENCH:
                s = QString("Source Quench\n");
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
                    s = QString("Time to live exceeded\n");
                    break;
                case ICMP_EXC_FRAGTIME:
                    s = QString("Frag reassembly time exceeded\n");
                    break;
                default:
                    s = QString("Time exceeded, Bad Code: %1\n").arg(Pindex->ICMP_header->code);
                    break;
                }
                break;
            case ICMP_PARAMETERPROB:
                // s = QString("Parameter problem: pointer = %1\n").arg(icp ? (ntohl(icp->un.gateway)>>24) : info);
                s = QString("Parameter problem\n");
                break;
            case ICMP_TIMESTAMP:
                s = QString("Timestamp\n");
                /* XXX ID + Seq + 3 timestamps */
                break;
            case ICMP_TIMESTAMPREPLY:
                s = QString("Timestamp Reply\n");
                /* XXX ID + Seq + 3 timestamps */
                break;
            case ICMP_INFO_REQUEST:
                s = QString("Information Request\n");
                /* XXX ID + Seq */
                break;
            case ICMP_INFO_REPLY:
                s = QString("Information Reply\n");
                /* XXX ID + Seq */
                break;
            default:
                    s = QString("Bad ICMP type: %1\n").arg(Pindex->ICMP_header->type);
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
        //s=QString("%1.%2.%3.%4.%5.%6.%7.%8.%9.%10.%11.%12.%13.%14.%15.%16").arg(Pindex->IPv6_header->source_ip.byte1).arg(Pindex->IPv6_header->source_ip.byte2).arg(Pindex->IPv6_header->source_ip.byte3).arg(Pindex->IPv6_header->source_ip.byte4).arg(Pindex->IPv6_header->source_ip.byte5).arg(Pindex->IPv6_header->source_ip.byte6).arg(Pindex->IPv6_header->source_ip.byte7).arg(Pindex->IPv6_header->source_ip.byte8).arg(Pindex->IPv6_header->source_ip.byte9).arg(Pindex->IPv6_header->source_ip.byte10).arg(Pindex->IPv6_header->source_ip.byte11).arg(Pindex->IPv6_header->source_ip.byte12).arg(Pindex->IPv6_header->source_ip.byte13).arg(Pindex->IPv6_header->source_ip.byte14).arg(Pindex->IPv6_header->source_ip.byte15).arg(Pindex->IPv6_header->source_ip.byte16);
        PacketModel->setData(PacketModel->index(row,2),s);//源IP

        s = ip6tos(Pindex->IPv6_header->dest_ip);
        // s=QString("%1.%2.%3.%4.%5.%6.%7.%8.%9.%10.%11.%12.%13.%14.%15.%16").arg(Pindex->IPv6_header->dest_ip.byte1).arg(Pindex->IPv6_header->dest_ip.byte2).arg(Pindex->IPv6_header->dest_ip.byte3).arg(Pindex->IPv6_header->dest_ip.byte4).arg(Pindex->IPv6_header->dest_ip.byte5).arg(Pindex->IPv6_header->dest_ip.byte6).arg(Pindex->IPv6_header->dest_ip.byte7).arg(Pindex->IPv6_header->dest_ip.byte8).arg(Pindex->IPv6_header->dest_ip.byte9).arg(Pindex->IPv6_header->dest_ip.byte10).arg(Pindex->IPv6_header->dest_ip.byte11).arg(Pindex->IPv6_header->dest_ip.byte12).arg(Pindex->IPv6_header->dest_ip.byte13).arg(Pindex->IPv6_header->dest_ip.byte14).arg(Pindex->IPv6_header->dest_ip.byte15).arg(Pindex->IPv6_header->dest_ip.byte16);
        PacketModel->setData(PacketModel->index(row,3),s);//目的IP

        PacketModel->setData(PacketModel->index(row,4),Globe::capPacket.Pindex->Netpro);

        s.setNum(Pindex->header.len);//包长
        PacketModel->setData(PacketModel->index(row,5),s);

        long t=ntohl(Pindex->IPv6_header->load_length);
        s=QString("%1%2").arg(("payload length: ")).arg(t);//报要1


//        s=QString("");//报要2
//        PacketModel->setData(PacketModel->index(row,7),s);

    } //IPv6
    else if(k==ETHER_TYPE_ARP)//ARP
    {
        s = iptos(Pindex->ARP_header->sip_address);
        // s=QString("%1.%2.%3.%4").arg(Pindex->ARP_header->sip_address.byte1).arg(Pindex->ARP_header->sip_address.byte2).arg(Pindex->ARP_header->sip_address.byte3).arg(Pindex->ARP_header->sip_address.byte4);
        PacketModel->setData(PacketModel->index(row,2),s);//源IP

        s=QString("ARP");
        PacketModel->setData(PacketModel->index(row,4),s);//协议

        s.setNum(Pindex->header.len);//包长
        PacketModel->setData(PacketModel->index(row,5),s);

        if(ntohs(Pindex->ARP_header->opcode)==ARPOP_REQUEST) // ARP request
        {
            s=QString(("broadcast"));
            PacketModel->setData(PacketModel->index(row,3),s);//目的IP

            s = QString("Who has ") \
                    + iptos(Pindex->ARP_header->dip_address) \
                    + QString(" Tell ") \
                    + iptos(Pindex->ARP_header->sip_address);
//            s=QString("%1 %2.%3.%4.%5? %1 %2.%3.%4.%5").arg("Who has ")\
//                    .arg(Pindex->ARP_header->dip_address.byte1)\
//                    .arg(Pindex->ARP_header->dip_address.byte2)\
//                    .arg(Pindex->ARP_header->dip_address.byte3)\
//                    .arg(Pindex->ARP_header->dip_address.byte4)\
//                    .arg(("Tell "))\
//                    .arg(Pindex->ARP_header->sip_address.byte1)\
//                    .arg(Pindex->ARP_header->sip_address.byte2)\
//                    .arg(Pindex->ARP_header->sip_address.byte3)\
//                    .arg(Pindex->ARP_header->sip_address.byte4); //报要1
            PacketModel->setData(PacketModel->index(row,6),s);
        }
        else if(ntohs(Pindex->ARP_header->opcode)==ARPOP_REPLY)  // ARP reply
        {
            s = iptos(Pindex->ARP_header->dip_address);
//            s=QString("%1.%2.%3.%4")\
//                    .arg(Pindex->ARP_header->dip_address.byte1)\
//                    .arg(Pindex->ARP_header->dip_address.byte2)\
//                    .arg(Pindex->ARP_header->dip_address.byte3)\
//                    .arg(Pindex->ARP_header->dip_address.byte4);
            PacketModel->setData(PacketModel->index(row,3),s);//目的IP

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
        // s=QString("%1.%2.%3.%4").arg(Pindex->ARP_header->sip_address.byte1).arg(Pindex->ARP_header->sip_address.byte2).arg(Pindex->ARP_header->sip_address.byte3).arg(Pindex->ARP_header->sip_address.byte4);
        PacketModel->setData(PacketModel->index(row,2),s);//源IP

        s=QString("RARP");
        PacketModel->setData(PacketModel->index(row,4),s);//协议

        s.setNum(Pindex->header.len);//包长
        PacketModel->setData(PacketModel->index(row,5),s);
        if(ntohs(Pindex->ARP_header->opcode)==ARPOP_RREQUEST)       // RARP REQUEST
        {
            s=QString(("broadcast"));
            PacketModel->setData(PacketModel->index(row,3),s);//目的IP

            s = QString("Who is ") \
                    + mactos(Pindex->ARP_header->dnether_address)\
                    + QString(" Tell ")\
                    + mactos(Pindex->ARP_header->snether_address);
            // s=QString("%1 %2：%3：%4：%5：%6：%7%8").arg(("Who has ")).arg(Pindex->ARP_header->snether_address.byte1,0,16).arg(Pindex->ARP_header->snether_address.byte2,0,16).arg(Pindex->ARP_header->snether_address.byte3,0,16).arg(Pindex->ARP_header->snether_address.byte4,0,16).arg(Pindex->ARP_header->snether_address.byte5,0,16).arg(Pindex->ARP_header->snether_address.byte6,0,16).arg(("的IP地址"));//报要1
            PacketModel->setData(PacketModel->index(row,6),s);

            // s=QString("%1 %2：%3：%4：%5：%6：%7").arg(("Tell")).arg(Pindex->ARP_header->snether_address.byte1,0,16).arg(Pindex->ARP_header->snether_address.byte2,0,16).arg(Pindex->ARP_header->snether_address.byte3,0,16).arg(Pindex->ARP_header->snether_address.byte4,0,16).arg(Pindex->ARP_header->snether_address.byte5,0,16).arg(Pindex->ARP_header->snether_address.byte6,0,16);//报要2
            // PacketModel->setData(PacketModel->index(row,7),s);
        }
        else if(ntohs(Pindex->ARP_header->opcode)==ARPOP_RREPLY) // RARP REPLY
        {
           s = iptos(Pindex->ARP_header->dip_address);
            // s=QString("%1.%2.%3.%4").arg(Pindex->ARP_header->dip_address.byte1).arg(Pindex->ARP_header->dip_address.byte2).arg(Pindex->ARP_header->dip_address.byte3).arg(Pindex->ARP_header->dip_address.byte4);
           PacketModel->setData(PacketModel->index(row,3),s);//目的IP
           s = mactos(Pindex->ARP_header->dnether_address) \
                   + QString(" is at ") \
                   + iptos(Pindex->ARP_header->dip_address);
           // s=QString("%1 %2：%3：%4：%5：%6：%7%8").arg(("我有")).arg(Pindex->ARP_header->dnether_address.byte1).arg(Pindex->ARP_header->dnether_address.byte2).arg(Pindex->ARP_header->dnether_address.byte3).arg(Pindex->ARP_header->dnether_address.byte4).arg(Pindex->ARP_header->dnether_address.byte5).arg(Pindex->ARP_header->dnether_address.byte6).arg(("的IP地址"));//报要1
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
