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


QString analyzeHttpPacket(struct Packet *Pindex)
{
    char* ip_pkt_data = (char*)Pindex->IPv4_header;
    int ip_len = ntohs(Pindex->IPv4_header->tlen);
    bool find_http = false;
    std::string http_txt = "";
    for(int i=0;i<ip_len;++i){

        //check the http request
        if(!find_http
                && ((i+3<ip_len && strncmp(ip_pkt_data+i,"GET ",strlen("GET ")) ==0 )
                || (i+4<ip_len && strncmp(ip_pkt_data+i,"HEAD ",strlen("HEAD ")) == 0 )
                || (i+4<ip_len && strncmp(ip_pkt_data+i,"POST ",strlen("POST ")) == 0 )
                || (i+3<ip_len && strncmp(ip_pkt_data+i,"PUT ",strlen("PUT ")) == 0 )
                || (i+6<ip_len && strncmp(ip_pkt_data+i,"OPTION ",strlen("OPTION ")) == 0 ))
                )
        {
            find_http = true;
        }

        //check the http response
        if(!find_http && i+8<ip_len && strncmp(ip_pkt_data+i,"HTTP/1.1 ",strlen("HTTP/1.1 "))==0)
        {
            find_http = true;
        }

        //collect the http text
        if(find_http && (isalnum(ip_pkt_data[i]) || ispunct(ip_pkt_data[i]) || \
                         isspace(ip_pkt_data[i]) || isprint(ip_pkt_data[i])))
        {
            http_txt += ip_pkt_data[i];
        }
    }
    return QString(http_txt.c_str());
}
