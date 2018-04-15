#ifndef COMMON_H
#define COMMON_H

#include <QString>
#include "pcap.h"
#include <windows.h>
#include <time.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "packet.h"


extern u_char *dataIndex;
QString iptos(u_long in);
QString iptos(struct ip_address address);
QString ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
QString ip6tos(struct ipv6_address address);
QString mactos(struct mac_address address);

void AnalyzeEthernet();
void AnalyzeARP();
void AnalyzeIP();

/* ARP / RARP structs and definitions */
#define ARPOP_REQUEST  1       /* ARP request.  */
#define ARPOP_REPLY    2       /* ARP reply.  */
/* Some OSes have different names, or don't define these at all */
#define ARPOP_RREQUEST 3       /* RARP request.  */
#define ARPOP_RREPLY   4       /* RARP reply.  */
/*Additional parameters as per http://www.iana.org/assignments/arp-parameters*/
#define ARPOP_DRARPREQUEST 5   /* DRARP request.  */
#define ARPOP_DRARPREPLY 6     /* DRARP reply.  */
#define ARPOP_DRARPERROR 7     /* DRARP error.  */
#define ARPOP_IREQUEST 8       /* Inverse ARP (RFC 1293) request.  */
#define ARPOP_IREPLY   9       /* Inverse ARP reply.  */
#define ATMARPOP_NAK   10      /* ATMARP NAK.  */



#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_IPv6 0x86DD
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_RARP 0x8035

#define PROTO_TYPE_ICMP     1
#define PROTO_TYPE_TCP      6
#define PROTO_TYPE_UDP      17
#define PROTO_TYPE_ICMPv6   58

/* ICMP code type define */
#define ICMP_ECHOREPLY      0   /* Echo Reply           */
#define ICMP_DEST_UNREACH   3   /* Destination Unreachable  */
#define ICMP_SOURCE_QUENCH  4   /* Source Quench        */
#define ICMP_REDIRECT       5   /* Redirect (change route)  */
#define ICMP_ECHO       8   /* Echo Request         */
#define ICMP_TIME_EXCEEDED  11  /* Time Exceeded        */
#define ICMP_PARAMETERPROB  12  /* Parameter Problem        */
#define ICMP_TIMESTAMP      13  /* Timestamp Request        */
#define ICMP_TIMESTAMPREPLY 14  /* Timestamp Reply      */
#define ICMP_INFO_REQUEST   15  /* Information Request      */
#define ICMP_INFO_REPLY     16  /* Information Reply        */
#define ICMP_ADDRESS        17  /* Address Mask Request     */
#define ICMP_ADDRESSREPLY   18  /* Address Mask Reply       */
#define NR_ICMP_TYPES       18

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH    0   /* Network Unreachable      */
#define ICMP_HOST_UNREACH   1   /* Host Unreachable     */
#define ICMP_PROT_UNREACH   2   /* Protocol Unreachable     */
#define ICMP_PORT_UNREACH   3   /* Port Unreachable     */
#define ICMP_FRAG_NEEDED    4   /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED      5   /* Source Route failed      */
#define ICMP_NET_UNKNOWN    6
#define ICMP_HOST_UNKNOWN   7
#define ICMP_HOST_ISOLATED  8
#define ICMP_NET_ANO        9
#define ICMP_HOST_ANO       10
#define ICMP_NET_UNR_TOS    11
#define ICMP_HOST_UNR_TOS   12
#define ICMP_PKT_FILTERED   13  /* Packet filtered */
#define ICMP_PREC_VIOLATION 14  /* Precedence violation */
#define ICMP_PREC_CUTOFF    15  /* Precedence cut off */
#define NR_ICMP_UNREACH     15  /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET      0   /* Redirect Net         */
#define ICMP_REDIR_HOST     1   /* Redirect Host        */
#define ICMP_REDIR_NETTOS   2   /* Redirect Net for TOS     */
#define ICMP_REDIR_HOSTTOS  3   /* Redirect Host for TOS    */

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL        0   /* TTL count exceeded       */
#define ICMP_EXC_FRAGTIME   1   /* Fragment Reass time exceeded */


class Globe
{
public:
    static struct PacketList capPacket;
};

enum class HEADER_T{
    NO,
    TIMESTAMP,
    SOURCE,
    DESTINATION,
    PROTOCOL,
    LENGTH,
    INFO1,
    INFO2
};

/* 4 bytes IP address */
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* 16 bytes IPv6 address */
typedef struct ipv6_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
    u_char byte7;
    u_char byte8;
    u_char byte9;
    u_char byte10;
    u_char byte11;
    u_char byte12;
    u_char byte13;
    u_char byte14;
    u_char byte15;
    u_char byte16;
}ipv6_address;

/* 6字节的MAC地址 */
typedef struct mac_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}mac_address;

/* Ethernet header */
typedef struct ethernet_header{
    mac_address ether_dhost;
    mac_address ether_shost;
    u_short ether_type;
}ethernet_header;

/* IPv4 header */
typedef struct ip_header
{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// Type of service
    u_short tlen;			// Total length
    u_short identification; // Identification
    u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short crc;			// Header checksum
    ip_address	saddr;		// Source address
    ip_address	daddr;		// Destination address
    u_int	op_pad;			// Option + Padding
}ip_header;


/* IPv6 header */
typedef struct ipv6_header{
    u_long  ver_ihl;        // 版本 (4 bits) + 优先级(8 bits)+流标签(20 bits)
    u_short load_length;    // 有效负荷长度
    u_char next_header;     // 下一报头
    u_char jump_limit;      // 跳限制
    ipv6_address source_ip;    //源ip地址
    ipv6_address dest_ip;      //目的ip地址
}ipv6_header;

/*ARP首部*/
typedef struct arp_header{
    u_short hardware_type;              // 硬件类型 (16 bits)
    u_short protocal_type;              //协议类型(16 bits)
    u_char  hwadd_len;                  //硬件地址长度(8 bit)
    u_char  proadd_len;                 //协议地址长度(8 bit)
    u_short opcode;                     //操作类型(16 bits)
    mac_address snether_address;        // 发送端以太网地址(48 bits)
    ip_address  sip_address;              //发送端IP地址(32 bits)
    mac_address dnether_address;       //目的以太网地址(48 bits)
    ip_address  dip_address;             // 目的IP地址（32 bits）
}arp_header;

/* ICMP 首部*/
typedef struct icmp_header{
        u_char  type;          //类型
        u_char  code;          //代码
        u_short ckc;          //校验和
        u_short id;           //识别号
        u_short seq;          //报文序列号
        u_short timestamp;    //时戳

    //    __u8      type;
    //    __u8      code;
    //    __sum16   checksum;
    //    union {
    //        struct {
    //            __be16  id;
    //            __be16  sequence;
    //        } echo;
    //        __be32  gateway;
    //        struct {
    //            __be16  __unused;
    //            __be16  mtu;
    //        } frag;
    //    } un;

//    u_char    type;
//    u_char    code;
//    // u_short   checksum;
//    u_short ckc;
//    union {
//        struct {
//            u_short  id;
//            // u_long   sequence;
//            u_long seq;
//        } echo;
//        u_long  gateway;
//        struct {
//            u_short  __unused;
//            u_short  mtu;
//        } frag;
//    } un;

}icmp_header;

/* TCP header */
typedef struct tcp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_long  seq;            //顺序号
    u_long  ack;            //确认号
    u_short tcp_res;        // TCP头长(4 bits)+保留位(6 bits)+Flags(URG+ACK+PSH+RST+SYN+FIN)
    u_short windsize;       //窗口大小
    u_short crc;            //校验和
    u_short urgp;           //紧急指针
}tcp_header;

/* UDP header*/
typedef struct udp_header
{
    u_short sport;			// Source port
    u_short dport;			// Destination port
    u_short len;			// Datagram length
    u_short crc;			// Checksum
}udp_header;

#endif // COMMON_H
