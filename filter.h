#ifndef FILTER_H
#define FILTER_H
#include "pcap.h"
#include <QString>

class Filter
{
public:
    explicit Filter();
    int setFilter(pcap_t *inputAdhandle, QString inputFilter);

private:
    pcap_t *adhandle;
    QString packet_filter;
    u_int netmask;
};

#endif // FILTER_H
