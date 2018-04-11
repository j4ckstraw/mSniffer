#include "common.h"

QString iptos(u_long in)
{
    u_char *p;
    QString output;
    p = (u_char *)&in;
    output=output.number((long)p[0],10)+'.'+output.number((long)p[1],10)+\
            '.'+output.number((long)p[2],10)+'.'+output.number((long)p[3],10);
    return output;
}


#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
QString ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
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

    return QString(address);
}
#endif /* __MINGW32__ */
