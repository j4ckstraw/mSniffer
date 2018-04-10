#ifndef COMMON_H
#define COMMON_H

#include <QString>
#include "pcap.h"
#include <windows.h>
#include <time.h>
#include <stdlib.h>


QString iptos(u_long in);
QString ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

#endif // COMMON_H
