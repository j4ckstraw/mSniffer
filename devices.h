#ifndef DEVICES_H
#define DEVICES_H
#include <QtCore>
#include <QObject>

#include <pcap.h>

#ifndef WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock.h>
#endif

#define IPTOSBUFFERS	12

class Devices
{
public:
    explicit Devices();
    ~Devices();

public slots:
    void getDevices();
    void freeDevices();
    void printDevices();

private:
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    void ifPrint(pcap_if_t *d);
    char *iptos(u_long in);
#ifndef __MINGW32__
    char *ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
#endif /* __MINGW32__ */
};

#endif // DEVICES_H
