#include "packet.h"
#include <QRegExp>

HTTP::HTTP(){}
HTTP::~HTTP(){}
HTTP::HTTP(QString text)
{
    QRegExp httpGetMethodReg("GET .+\r\n");
    httpGetMethodReg.setMinimal(true);
    QRegExp httpHostReg("Host: .+\r\n");
    httpHostReg.setMinimal(true);
    QRegExp httpConnectionReg("Connection: .+\r\n");
    httpConnectionReg.setMinimal(true);
    QRegExp httpCacheControlReg("Cache-Control: .+\r\n");
    httpCacheControlReg.setMinimal(true);
    QRegExp httpUserAgentReg("User-Agent: .+\r\n");
    httpUserAgentReg.setMinimal(true);
    QRegExp httpAcceptReg("Accept: .+\r\n");
    httpAcceptReg.setMinimal(true);
    QRegExp httpResponseReg("HTTP/1.1 .+\r\n");
    httpResponseReg.setMinimal(true);

    if (httpGetMethodReg.indexIn(text) > -1)      httpMethod = httpGetMethodReg.cap(0);
    if (httpHostReg.indexIn(text) > -1)           httpHost = httpHostReg.cap(0);
    if (httpConnectionReg.indexIn(text) > -1)     httpConnection = httpConnectionReg.cap(0);
    if (httpCacheControlReg.indexIn(text) > -1)   httpCacheControl = httpCacheControlReg.cap(0);
    if (httpUserAgentReg.indexIn(text) > -1)      httpUserAgent = httpUserAgentReg.cap(0);
    if (httpAcceptReg.indexIn(text) > -1)         httpAccept = httpAcceptReg.cap(0);
    if (httpResponseReg.indexIn(text) > -1)       httpResponse = httpResponseReg.cap(0);
}
