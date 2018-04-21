#include "packet.h"
#include <QRegExp>
#include <QDebug>

QString analyzeHttpPacket(struct Packet *index)
{
    qDebug() << "AnalyzeHttpPacket";
    char* ip_pkt_data = (char*)index->IPv4_header;
    u_short sport = ntohs(index->TCP_header->sport);
    u_short dport = ntohs(index->TCP_header->dport);
    int ip_len = ntohs(index->IPv4_header->tlen);
    bool find_http = false;
    std::string http_txt = "";
    for(int i=0;i<ip_len;++i){
        //check the http request
        if(!find_http && dport == 80
                && ((i+3<ip_len && strncmp(ip_pkt_data+i,"GET ",strlen("GET ")) ==0 )
                || (i+4<ip_len && strncmp(ip_pkt_data+i,"HEAD ",strlen("HEAD ")) == 0 )
                || (i+4<ip_len && strncmp(ip_pkt_data+i,"POST ",strlen("POST ")) == 0 )
                || (i+3<ip_len && strncmp(ip_pkt_data+i,"PUT ",strlen("PUT ")) == 0 )
                || (i+6<ip_len && strncmp(ip_pkt_data+i,"OPTION ",strlen("OPTION ")) == 0 ))
                )
        {
            find_http = true;
        }

        //check the http response
        if(!find_http && sport == 80 && i+8<ip_len && strncmp(ip_pkt_data+i,"HTTP/1.1 ",strlen("HTTP/1.1 "))==0)
        {
            find_http = true;
        }

        //collect the http text
        if(find_http && (isalnum(ip_pkt_data[i]) || ispunct(ip_pkt_data[i]) || \
                         isspace(ip_pkt_data[i]) || isprint(ip_pkt_data[i])))
        {
            http_txt += ip_pkt_data[i];
        }
    }

    qDebug() << "HTTP content:" << QString(http_txt.c_str());

    if (find_http)
    {
        index->Apppro = "HTTP";
        return QString(http_txt.c_str());
    }
    else
    {
        index->Apppro = "";
        return QString("");
    }
}


Ethernet::~Ethernet()
{

}

Ethernet::Ethernet(ethernet_header *eth)
{
    eth_hdr = eth;
    mac_address dhost = eth_hdr->ether_dhost;
    mac_address shost = eth_hdr->ether_shost;
    type = eth_hdr->ether_type;

    switch(type)
    {
    case ETHER_TYPE_IPv4:
        type_str = QString("IPv4");
        break;
    case ETHER_TYPE_IPv6:
        type_str = QString("IPv6");
        break;
    case ETHER_TYPE_ARP:
        type_str = QString("ARP");
        break;
    case ETHER_TYPE_RARP:
        type_str = QString("RARP");
        break;
    default:
        type_str = QString("UNKNOWN");
        break;
    }
    dhost_str = mactos(dhost);
    shost_str = mactos(shost);
//    qDebug() << "Type:" << type;
//    qDebug()<<"Dhost:" <<dhost_str;
//    qDebug() << "Shost:" << shost_str;
}


IP::~IP(){}

IP::IP(ip_header *ih)
{
    ip_hdr = ih;
    ver = (ntohs(ip_hdr->ver_ihl)&0xf000)>>12;
    hdr_len = (ntohs(ip_hdr->ver_ihl)&0x0f00)>>8;
    tos = ntohs(ip_hdr->tos);
    tlen = ntohs(ip_hdr->tlen);
    flags = (ntohs(ip_hdr->flags_fo)&0xe000)>>13;
    flags_str = QString("");
    if(flags&0b100) flags_str += QString("Reserved bit set");
    if(flags&0b010) flags_str += QString("Don't fragment set");
    if(flags&0b001) flags_str += QString("More fragments set");
    ttl = ip_hdr->ttl;
    proto = ip_hdr->proto;
    switch(proto)
    {
    case PROTO_TYPE_ICMP:
        proto_str = QString("ICMP");
        break;
    case PROTO_TYPE_TCP:
        proto_str = QString("TCP");
        break;
    case PROTO_TYPE_UDP:
        proto_str = QString("UDP");
        break;
    case PROTO_TYPE_ICMPv6:
        proto_str = QString("IPv6");
        break;
    default:
        proto_str = QString("UNKNOWN");
        break;
    }
    src_str = QString("%1.%2.%3.%4")\
            .arg(ip_hdr->saddr.byte1)\
            .arg(ip_hdr->saddr.byte2)\
            .arg(ip_hdr->saddr.byte3)\
            .arg(ip_hdr->saddr.byte4);
    dst_str =  QString("%1.%2.%3.%4")\
            .arg(ip_hdr->daddr.byte1)\
            .arg(ip_hdr->daddr.byte2)\
            .arg(ip_hdr->daddr.byte3)\
            .arg(ip_hdr->daddr.byte4);
    crc = ip_hdr->crc;
    ident = ip_hdr->identification;
//    qDebug() << "############# IP INFO #############";
//    qDebug() << "Version: " << ver;
//    qDebug() << "Header len: "<< hdr_len;
//    qDebug() << "Type of service： " << tos;
//    qDebug() << "total len: " << tlen;
//    qDebug() << "flags : "<< flags;
//    qDebug() <<"TTL: "<<ttl;
//    qDebug() <<"Protocol: " << proto;
//    qDebug() <<"Source: "<< src;
//    qDebug() << "Destination: " <<dst;
//    qDebug() << "CRC: " << crc;
//    qDebug() << "Identical: " << ident;
}

TCP::~TCP()
{

}

TCP::TCP(tcp_header *th)
{
    tcp_hdr = th;
    src_port = QString::number(ntohs(tcp_hdr->sport));
    dst_port = QString::number(ntohs(tcp_hdr->dport));
    seq_num = QString::number(ntohs(tcp_hdr->seq));
    ack_num = QString::number(ntohs(tcp_hdr->ack));
    data_offset = QString::number((ntohs(tcp_hdr->tcp_res)&0xf000)>>12);
    flags = ntohs(tcp_hdr->tcp_res)&0x003f;
    URG = flags & 0x0020;
    ACK = flags & 0x0010;
    PSH = flags & 0x0008;
    RST = flags & 0x0004;
    SYN = flags & 0x0002;
    FIN = flags & 0x0001;
    window_size = QString::number(ntohs(tcp_hdr->windsize));
    crc = QString::number(ntohs(tcp_hdr->crc));
    urgp = QString(ntohs(tcp_hdr->urgp));

//    qDebug() << "############# TCP INFO #############";
//    qDebug() << "Src port : "<< src_port;
//    qDebug() << "Dst port: " << dst_port;
//    qDebug() << "seq number : "<< seq_num;
//    qDebug() << "ack number : " << ack_num;
//    qDebug() << "data offset: " << data_offset;
//    qDebug() << "flags : " << flags;
//    qDebug() << QString("URG:%1,ACK:%2,PSH:%3,RST:%4,SYN:%5,FIN:%6;").arg(URG).arg(ACK).arg(PSH).arg(RST).arg(SYN).arg(FIN);
//    qDebug() << "Window size: " << window_size;
//    qDebug() << "Checksum : "<< crc;
//    qDebug() << "Urg pointer: "<< urgp;
}

UDP::~UDP()
{

}

UDP::UDP(udp_header *uh)
{
    udp_hdr = uh;
    src_port = QString::number(ntohs(udp_hdr->sport));
    dst_port = QString::number(ntohs(udp_hdr->dport));
    length = QString::number(ntohs(udp_hdr->len));
    crc = QString::number(ntohs(udp_hdr->crc));

//    qDebug() << "############# UDP INFO #############";
//    qDebug() << "Src port : "<< src_port;
//    qDebug() << "Dst port: " << dst_port;
//    qDebug() << "Length: "<< length;
//    qDebug() << "Checksum: "<< crc;
}

HTTP::HTTP(){}
HTTP::~HTTP(){}
HTTP::HTTP(QString text)
{
    QRegExp httpGetMethodReg("GET .+\r\n");
    httpGetMethodReg.setMinimal(true);
    QRegExp httpHostReg("Host: .+\r\n");
    httpHostReg.setMinimal(true);
    QRegExp httpConnectionReg("Connection: .+\r\n");
    httpConnectionReg.setMinimal(true);
    QRegExp httpCacheControlReg("Cache-Control: .+\r\n");
    httpCacheControlReg.setMinimal(true);
    QRegExp httpUserAgentReg("User-Agent: .+\r\n");
    httpUserAgentReg.setMinimal(true);
    QRegExp httpAcceptReg("Accept: .+\r\n");
    httpAcceptReg.setMinimal(true);
    QRegExp httpResponseReg("HTTP/1.1 .+\r\n");
    httpResponseReg.setMinimal(true);

    if (httpGetMethodReg.indexIn(text) > -1)      httpMethod = httpGetMethodReg.cap(0);
    if (httpHostReg.indexIn(text) > -1)           httpHost = httpHostReg.cap(0);
    if (httpConnectionReg.indexIn(text) > -1)     httpConnection = httpConnectionReg.cap(0);
    if (httpCacheControlReg.indexIn(text) > -1)   httpCacheControl = httpCacheControlReg.cap(0);
    if (httpUserAgentReg.indexIn(text) > -1)      httpUserAgent = httpUserAgentReg.cap(0);
    if (httpAcceptReg.indexIn(text) > -1)         httpAccept = httpAcceptReg.cap(0);
    if (httpResponseReg.indexIn(text) > -1)       httpResponse = httpResponseReg.cap(0);
}

ARP::~ARP()
{

}

ARP::ARP(arp_header *ah)
{
    arp_hdr = ah;

    hd_type = QString::number(ntohs(arp_hdr->hardware_type));
    proto_type = ntohs(arp_hdr->protocal_type);
    switch(proto_type)
    {
    case ETHER_TYPE_IPv4:
        proto_type_str = QString("IPv4");
        break;
    case ETHER_TYPE_IPv6:
        proto_type_str = QString("IPv6");
        break;
    default:
        proto_type_str = QString("UNKNOWN");
        break;
    }
    hd_len = QString::number(arp_hdr->hwadd_len);
    pro_addr_len = QString::number(arp_hdr->proadd_len);
    opcode = ntohs(arp_hdr->opcode);
    switch(opcode)
    {
    case ARPOP_REQUEST:
        opcode_str = QString("ARP Request");
        break;
    case ARPOP_REPLY:
        opcode_str = QString("ARP Reply");
        break;
    case ARPOP_RREQUEST:
        opcode_str = QString("RARP Request.");
        break;
    case ARPOP_RREPLY:
        opcode_str = QString("RARP Reply");
        break;
    default:
        opcode_str = QString("UNKNOWN ARP opcode");
        break;
    }
    src_addr = mactos(arp_hdr->snether_address);
    dst_addr = mactos(arp_hdr->dnether_address);
    sip_addr = iptos(arp_hdr->sip_address);
    dip_addr = iptos(arp_hdr->dip_address);

//    qDebug() << "hd_type:" << hd_type;
//    qDebug() << "proto_type： "<< proto_type;
//    qDebug() << "hd_len" << hd_len;
//    qDebug() << "proto_addr_len" << pro_addr_len;
//    qDebug() << "opcode" << opcode;
//    qDebug() << "opcode_str" << opcode_str;
}
