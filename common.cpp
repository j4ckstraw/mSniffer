#include "common.h"
#include "winsock2.h"
#include "packet.h"

#include <QMessageBox>

PacketList Globe::capPacket;

QString iptos(u_long in)
{
    u_char *p;
    QString output;
    p = (u_char *)&in;
    output=output.number((long)p[0],10)+'.'+output.number((long)p[1],10)+\
            '.'+output.number((long)p[2],10)+'.'+output.number((long)p[3],10);
    return output;
}

QString iptos(struct ip_address address)
{
    QString str = QString("%1.%2.%3.%4")\
            .arg(address.byte1)\
            .arg(address.byte2)\
            .arg(address.byte3)\
            .arg(address.byte4);
    return str;
}

QString mactos(mac_address address)
{
    QString str = QString("(%1:%2:%3:%4:%5:%6)")\
            .arg(address.byte1,0,16)\
            .arg(address.byte2,0,16)\
            .arg(address.byte3,0,16)\
            .arg(address.byte4,0,16)\
            .arg(address.byte5,0,16)\
            .arg(address.byte6,0,16);
    return str;
}

QString ip6tos(ipv6_address address)
{
    QString str = QString("%1%2:%3%4:%5%6:%7%8:%9%10:%11%12:%13%14:%15%16")\
            .arg(address.byte1,0,16)\
            .arg(address.byte2,0,16)\
            .arg(address.byte3,0,16)\
            .arg(address.byte4,0,16)\
            .arg(address.byte5,0,16)\
            .arg(address.byte6,0,16)\
            .arg(address.byte7,0,16)\
            .arg(address.byte8,0,16)\
            .arg(address.byte9,0,16)\
            .arg(address.byte10,0,16)\
            .arg(address.byte11,0,16)\
            .arg(address.byte12,0,16)\
            .arg(address.byte13,0,16)\
            .arg(address.byte14,0,16)\
            .arg(address.byte15,0,16)\
            .arg(address.byte16,0,16);

    return str;
}


#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
QString ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif

    if(getnameinfo(sockaddr,
                   sockaddrlen,
                   address,
                   addrlen,
                   NULL,
                   0,
                   NI_NUMERICHOST) != 0) address = NULL;

    return QString(address);
}
#endif /* __MINGW32__ */



void AnalyzeIP()//分析IP报头
{
    u_char IP_len=0;
    dataIndex=(u_char *)Globe::capPacket.Index->pkt_data+14;
    u_char n=*dataIndex&0xf0;
    n=n/16;
    if (n==4) //IPv4
    {
        Globe::capPacket.IPv4_Countpk++;
        Globe::capPacket.Index->Netpro=QString("IPv4");
        Globe::capPacket.Index->IPv4_header=(struct ip_header *)dataIndex;

        IP_len=(int)Globe::capPacket.Index->IPv4_header->ver_ihl & 0x0f;

        Globe::capPacket.Index->Netlimit=14+IP_len;

        if(Globe::capPacket.Index->IPv4_header->proto==17)//UDP
        {
            Globe::capPacket.UDP_Countpk++;
            Globe::capPacket.Index->Transpro=QString("UDP");
            Globe::capPacket.Index->UDP_header=(udp_header *)(dataIndex+IP_len*4);
            Globe::capPacket.Index->Translimit=Globe::capPacket.Index->Netlimit+8;
        }
        else if(Globe::capPacket.Index->IPv4_header->proto==6)//TCP
        {
            //HTTP
            Globe::capPacket.TCP_Countpk++;
            Globe::capPacket.Index->Transpro=QString("TCP");
            Globe::capPacket.Index->TCP_header=(tcp_header *)(dataIndex+IP_len*4);
            Globe::capPacket.Index->Translimit=Globe::capPacket.Index->Netlimit+20;

            if(Globe::capPacket.Index->TCP_header && \
                    (Globe::capPacket.Index->TCP_header->sport == 80 \
                     ||  Globe::capPacket.Index->TCP_header->dport == 80))
            {
                if (analyzeHttpPacket(Globe::capPacket.Pindex).compare("") != 0)
                    Globe::capPacket.Index->Transpro=QString("HTTP");
            }
        }
        else if(Globe::capPacket.Index->IPv4_header->proto==1)//ICMP
        {
            Globe::capPacket.ICMP_Countpk++;
            Globe::capPacket.Index->Transpro=QString("ICMP");
            Globe::capPacket.Index->ICMP_header=(icmp_header *)(dataIndex+IP_len*4);
            Globe::capPacket.Index->Translimit=Globe::capPacket.Index->Netlimit+10;
        }
        else
        {
            Globe::capPacket.Index->Transpro=QString("UNKNOWN");
            Globe::capPacket.Index->Translimit=Globe::capPacket.Index->Netlimit;
        }
    }
    else if(n==6)//Ipv6
    {
        Globe::capPacket.IPv6_Countpk++;
        Globe::capPacket.Index->Netlimit=14+40;
        Globe::capPacket.Index->Netpro=QString("IPv6");
        Globe::capPacket.Index->IPv6_header=(ipv6_header *)dataIndex;
        if(Globe::capPacket.Index->IPv6_header->next_header==17)//UDP
        {
            Globe::capPacket.UDP_Countpk++;
            Globe::capPacket.Index->Transpro=QString("UDP");
            Globe::capPacket.Index->UDP_header=(udp_header *)(dataIndex+40);
            Globe::capPacket.Index->Translimit=Globe::capPacket.Index->Netlimit+8;
        }
        else if(Globe::capPacket.Index->IPv6_header->next_header==6)//TCP
        {
            Globe::capPacket.TCP_Countpk++;
            Globe::capPacket.Index->Transpro=QString("TCP");
            Globe::capPacket.Index->TCP_header=(tcp_header *)(dataIndex+320);
            Globe::capPacket.Index->Translimit=Globe::capPacket.Index->Netlimit+20;
        }
        else
        {
            Globe::capPacket.Index->Transpro=QString("UNKNOWN");
            Globe::capPacket.Index->Translimit=Globe::capPacket.Index->Netlimit;
        }
    }
}

void AnalyzeARP()//分析ARP和RARP报头
{
    dataIndex=(u_char *)Globe::capPacket.Index->pkt_data+14;
    Globe::capPacket.Index->ARP_header=(arp_header *)dataIndex;
    Globe::capPacket.Index->Netlimit=14+28;
    Globe::capPacket.Index->Translimit=Globe::capPacket.Index->Netlimit;
}

void AnalyzeEthernet()//分析以太网头
{
    //dataIndex=(u_char *)capPacket.Index->pkt_data;
     char timestr[16];
     time_t local_tv_sec;
     struct tm *ltime;

    Globe::capPacket.Index->ether_header=(ethernet_header *)Globe::capPacket.Index->pkt_data;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = Globe::capPacket.Index->header.ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    sprintf(Globe::capPacket.Index->timestamp,"%s%c%d",timestr,'.',Globe::capPacket.Index->header.ts.tv_usec);


    //u_short k
    Globe::capPacket.Index->ether_header->ether_type=ntohs(Globe::capPacket.Index->ether_header->ether_type);
    Globe::capPacket.Index->header.len=Globe::capPacket.Index->header.len;
    if(Globe::capPacket.Index->ether_header->ether_type==0x0800 || Globe::capPacket.Index->ether_header->ether_type==0x86DD)//IP数据报
    {
        AnalyzeIP();
    }
    else if(Globe::capPacket.Index->ether_header->ether_type==0x0806)//ARP数据报
    {
        Globe::capPacket.ARP_Countpk++;
        Globe::capPacket.Index->Netpro=QString("ARP");
        AnalyzeARP();
    }
    else if(Globe::capPacket.Index->ether_header->ether_type==0x8035)//RARP数据报
    {
        Globe::capPacket.RARP_Countpk++;
        Globe::capPacket.Index->Netpro=QString("RARP");
        AnalyzeARP();
    }
    else
    {
        Globe::capPacket.Index->Netpro=QString("UNKNOWN");
        Globe::capPacket.Index->Transpro=QString("UNKNOWN");
    }
}

