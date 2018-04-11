#include "filter.h"
#include <QMessageBox>

extern pcap_if_t *alldevs;
extern int interface_selected;

Filter::Filter()
{

}

int Filter::setFilter(pcap_t *inputAdhandle, QString inputFilter)
{
    pcap_if_t *d;
    int i;
    packet_filter = inputFilter;
    adhandle = inputAdhandle;
    if(!inputAdhandle) fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< interface_selected-1 ;d=d->next, i++);

    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;

    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter.toStdString().c_str(), 1, netmask) <0 )
    {
        // fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        // pcap_freealldevs(alldevs);
        QMessageBox::warning(0,"Filter Error","\nUnable to compile the packet filter. Check the syntax.\n");
        return -1;
    }
    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        // pcap_freealldevs(alldevs);
        return -1;
    }
}
