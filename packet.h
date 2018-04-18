#ifndef PACKET_H
#define PACKET_H

#include <pcap.h>
#include "common.h"

QString analyzeHttpPacket(struct Packet * Pindex);

class IP
{
public:
    IP();
    ~IP();
    struct ip_header *ip_hdr;
    IP(struct ip_header *ih);

    QString ver;
    QString hdr_len;
    QString tos;
    QString tlen;
    QString flags;
    QString ttl;
    QString proto;
    QString src;
    QString dst;
    QString crc;
    QString ident;
};

class ARP
{
public:
    ARP();
    ~ARP();
    struct arp_header *arp_hdr;
    ARP(struct arp_header *ah);

    QString hd_type;
    u_short proto_type;
    QString proto_type_str;
    QString hd_len;
    QString pro_addr_len;
    u_short opcode;
    QString opcode_str;
    QString src_addr;
    QString dst_addr;
    QString sip_addr;
    QString dip_addr;
};
class TCP
{
public:
    TCP();
    ~TCP();
    struct tcp_header *tcp_hdr;
    TCP(struct tcp_header *th);

    QString src_port;
    QString dst_port;
    QString seq_num;
    QString ack_num;
    QString data_offset;
    u_short flags;
    u_short URG;
    u_short ACK;
    u_short PSH;
    u_short RST;
    u_short SYN;
    u_short FIN;
    QString window_size;
    QString crc;
    QString urgp;
};

class UDP
{
public:
    UDP();
    ~UDP();
    struct udp_header *udp_hdr;
    UDP(struct udp_header *uh);

    QString src_port;
    QString dst_port;
    QString length;
    QString crc;
};

class HTTP
{
public:
    HTTP();
    ~HTTP();
    HTTP(QString text);
    QString text;
    QString httpMethod = "";
    QString httpHost = "";
    QString httpConnection = "";
    QString httpCacheControl = "";
    QString httpUserAgent = "";
    QString httpAccept = "";
    QString httpResponse = "";
};

typedef struct Packet
{
    u_long serialnum;//被捕捉序列号
    //u_long len;//数据包长度
    //int captime;//被捕捉时间
    struct pcap_pkthdr header;//包头
    u_char pkt_data[65535];//包中数据
    Packet *Next;//链表指针
    char timestamp[30];//时戳

    struct ethernet_header *ether_header; //以太网首部
    struct ip_header *IPv4_header;//IPv4首部
    struct ipv6_header *IPv6_header;//IPv6首部
    struct arp_header *ARP_header;//ARP首部

    struct udp_header *UDP_header;//UDP首部
    struct tcp_header *TCP_header;//TCP首部
    struct icmp_header *ICMP_header;//ICMP首部

    QString Netpro;// network layter protocol
    QString Transpro;// transport layer protocol
    QString Apppro; // application layer protocol
    QString SIP;//源IP
    QString DIP;//目的IP
    QString SPort;//源端口
    QString DPort;//目的端口

    QString NAname;//捕获网卡名称

    bool Pflag;//是否已打印标志
    bool Aflag;//是否已分析标志

    u_int Netlimit;//网络层协议末尾
    u_int Translimit;//传输层协议末尾

    void Initial()
    {
        serialnum=0;
        //header=NULL;
        //pkt_data=NULL;
        Next=NULL;
        ether_header=NULL;
        IPv4_header=NULL;
        IPv6_header=NULL;
        ARP_header=NULL;
        UDP_header=NULL;
        TCP_header=NULL;
        ICMP_header=NULL;
        Netpro=QString("None");
        Transpro=QString("None");
        SIP=QString("UNKNOWN");
        DIP=QString("UNKNOWN");
        SPort=QString("UNKNOWN");
        DPort=QString("UNKNOWN");
        Pflag=false;
        Aflag=false;
    }

    void copy(struct pcap_pkthdr *cheader,u_char *data)
    {
        header.len=cheader->len;
        header.caplen=cheader->caplen;
        header.ts.tv_sec=cheader->ts.tv_sec;
        header.ts.tv_usec=cheader->ts.tv_usec;
        memcpy(pkt_data,data,header.len);
    }
}Packet;

typedef struct PacketList
{
    Packet *Head,*Tail,*Index,*Pindex,*Tindex,*OIndex;//头指针、尾指针、分析指针、实时打印指针、倒数第二个指针（删除节点用）、离线打印指针

    bool Iniflag;//是否已初始化标志
    u_long Countpk;//捕获的数据包计数
    u_long UDP_Countpk;//捕获的UDP数据包计数
    u_long TCP_Countpk;//捕获的TCP数据包计数
    u_long ICMP_Countpk;//捕获的ICMP数据包计数
    u_long ARP_Countpk;//捕获的ARP数据包计数
    u_long RARP_Countpk;//捕获的RARP数据包计数
    u_long IPv4_Countpk;//捕获的IPv4数据包计数
    u_long IPv6_Countpk;//捕获的IPv6数据包计数
    //Packetlist capPacket;//捕获的数据包链表

    void AddPacket()
    {
        Packet *p=new Packet;
        p->Initial();
        if(Head==NULL)
        {
            Head=p;
            Tail=p;
            Index=Head;
            Pindex=Head;
            Tindex=Tail;
            OIndex=Head;
        }
        else
        {
            Tindex=Tail;
            Tail->Next=p;
            Tail=Tail->Next;
        }
    }
    void InitialList()
    {
        Countpk=0;
        UDP_Countpk=0;
        TCP_Countpk=0;
        ICMP_Countpk=0;
        ARP_Countpk=0;
        RARP_Countpk=0;
        IPv4_Countpk=0;
        IPv6_Countpk=0;
        Head=NULL;
        Tail=NULL;
        Index=NULL;
        Pindex=NULL;
        Tindex=Head;
        OIndex=Head;
        Iniflag=true;
    }

    void DeleteNode()
    {
        if(Tail!=Tindex)
        {
            if(Tail!=NULL)
            {
                delete Tail;
                Tail=Tindex;
                Tindex=Head;
                if(Tail!=Head)
                {
                    while(Tindex->Next!=Tail)
                    {
                        Tindex=Tindex->Next;
                    }
                }
            }
            else
                Tail=Head;
        }
        else
        {
            if(Tindex!=Head)
            {
                if(Tail!=NULL)
                {
                    Tindex=Head;
                    while(Tindex->Next!=Tail)
                    {
                        Tindex=Tindex->Next;
                    }
                    delete Tail;
                    Tail=Tindex;
                    Tail->Next=NULL;
                    Tindex=Head;
                    while(Tindex->Next!=Tail)
                    {
                        Tindex=Tindex->Next;
                    }
                }
                else
                    Tail=Head;
            }
            else//只剩下一个节点
            {
                if(Head!=NULL)
                    delete Head;
                Head=NULL;
                Tail=NULL;
                Index=NULL;
                Pindex=NULL;
                Tindex=Head;
                OIndex=Head;
            }
        }

    }

    void DeleteList()
    {
//        while(Head!=Tail)
//        {
//            DeleteNode();
//        }
        // refact delete
        while(Head != NULL)
        {
            Tindex = Head;
            Head = Head->Next;
            delete Tindex;
        }

        Tail=NULL;
        Head=NULL;
        Index=NULL;
        Tindex=NULL;
        Countpk=0;
        UDP_Countpk=0;
        TCP_Countpk=0;
        ICMP_Countpk=0;
        ARP_Countpk=0;
        RARP_Countpk=0;
        IPv4_Countpk=0;
        IPv6_Countpk=0;
        Iniflag=false;
    }
}PacketList;


#endif // PACKET_H
