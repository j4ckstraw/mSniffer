#include <QMessageBox>
#include <QDebug>

#include "devices.h"

Devices::Devices(){}

Devices::~Devices(){}

void Devices::getDevices()
{
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        //fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        QMessageBox::warning(0,"Device Warning", "Error when find all device");
        exit(1);
    }
}

void Devices::freeDevices()
{
    pcap_freealldevs(alldevs);
}

void Devices::printDevices()
{
    for(d=alldevs;d;d=d->next)
    {
        ifPrint(d);
    }
}

void Devices::ifPrint(pcap_if_t *d)
{
    pcap_addr_t *a;
    char ip6str[128];

    /* Name */
    //printf("%s\n",d->name);
    qDebug() << d->name << "\n";

    /* Description */
    if (d->description)
        //printf("\tDescription: %s\n",d->description);
        qDebug() << "\tDescription: " << d->description << "\n";

    /* Loopback Address*/
    // printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");
    //qDebug() << "\tLoopback: " << (d->flags & PCAP_IF_LOOPBACK)?"yes":"no" << "\n";
    QString text = (d->flags & PCAP_IF_LOOPBACK)?"yes":"no";
    qDebug() << "\tLoopback: " << text << "\n";

    /* IP addresses */
    for(a=d->addresses;a;a=a->next) {
        // printf("\tAddress Family: #%d\n",a->addr->sa_family);
        qDebug() << "\tAddress Family: " << a->addr->sa_family << "\n";

        switch(a->addr->sa_family)
        {
        case AF_INET:
            //printf("\tAddress Family Name: AF_INET\n");
            qDebug() << "\tAddress Family Name: AF_INET\n";
            if (a->addr)
                // printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                qDebug() << "\tAddress: " << iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr) << "\n";
            if (a->netmask)
                // printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                qDebug() << "\tNetmask: " << iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr) << "\n";
            if (a->broadaddr)
                // printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                qDebug() << "\tBroadcast Address: " << iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr) <<"\n";
            if (a->dstaddr)
                // printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                qDebug() << "\tDestination Address: " << iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr) << "\n";
            break;

        case AF_INET6:
            // printf("\tAddress Family Name: AF_INET6\n");
            qDebug() << "\tAddress Family Name: AF_INET6\n" ;
#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
            if (a->addr)
                // printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
                qDebug() << "\tAddress: " << ip6tos(a->addr, ip6str, sizeof(ip6str)) << "\n";
#endif
            break;

        default:
            // printf("\tAddress Family Name: Unknown\n");
            qDebug() << "\tAddress Family Name: Unknown\n";
            break;
        }
    }
    //printf("\n");
    qDebug() << "*********************FLAG**************************\n" ;
}


char *Devices::iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

#ifndef __MINGW32__
char *Devices::ip6tos(sockaddr *sockaddr, char *address, int addrlen)
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

    return address;
}
#endif /* __MINGW32__ */
