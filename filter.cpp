#include "filter.h"
#include <QMessageBox>

Filter::Filter(QString source_)
{
    source = source_;
}

Filter::Filter(QString source_, QString filter_)
{
    source = source_;
    setFilter(filter_);
}

int Filter::setFilter(QString filter_)
{
    filter = filter_;
    if (source != NULL)
    {
        if ((fp = pcap_open_live(source.toStdString().c_str(),		// name of the device
                                 65536,								// portion of the packet to capture.
                                 // 65536 grants that the whole packet will be captured on all the MACs.
                                 1,									// promiscuous mode (nonzero means promiscuous)
                                 1000,								// read timeout
                                 errbuf								// error buffer
                                 )) == NULL)
        {
            //fprintf(stderr,"\nUnable to open the adapter.\n");
            QMessageBox::warning(0,"Filter error","\nUnable to open the adapter.\n");
            return -2;
        }
    }
    else
        return -1;
    if (filter != NULL)
    {
        // We should loop through the adapters returned by the pcap_findalldevs_ex()
        // in order to locate the correct one.
        //
        // Let's do things simpler: we suppose to be in a C class network ;-)
        bpf_u_int32 NetMask;
        NetMask=0xffffff;

        //compile the filter
        if(pcap_compile(fp, &fcode, filter.toStdString().c_str(), 1, NetMask) < 0)
        {
            // fprintf(stderr,"\nError compiling filter: wrong syntax.\n");
            QMessageBox::warning(0,"Filter error","Error compiling filter: wrong syntax.\n");

            pcap_close(fp);
            return -3;
        }

        //set the filter
        if(pcap_setfilter(fp, &fcode)<0)
        {
            //fprintf(stderr,"\nError setting the filter\n");
            QMessageBox::warning(0,"Filter error","Error setting the filter\n");

            pcap_close(fp);
            return -4;
        }
        return 0;
    }
    return -1;
}

QString Filter::getFilter()
{
    return filter;
}
