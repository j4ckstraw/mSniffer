#ifndef FILTER_H
#define FILTER_H

#include <pcap.h>
#include <QString>

class Filter
{
public:
    Filter();
    Filter(QString filter_);
    int setFilter(QString);
    QString getFilter();

private:
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    QString source = NULL;
    // char *ofilename = NULL;
    // char *filter = NULL;
    QString filter = NULL;
    // int i;
    // pcap_dumper_t *dumpfile;
    struct bpf_program fcode;
    // int res;
    // struct pcap_pkthdr *header;
    // const u_char *pkt_data;
};

#endif // FILTER_H
