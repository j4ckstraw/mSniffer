#ifndef FILTER_H
#define FILTER_H
#include "pcap.h"

class Filter
{
public:
    explicit Filter();
    int setFilter(pcap_t *inputAdhandle, QString inputFilter);

private:
    pcap_t *adhandle;
    QString packet_filter;
    struct bpf_program fcode;
    u_int netmask;
};

#endif // FILTER_H
