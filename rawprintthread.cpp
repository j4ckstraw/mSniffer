#include "rawprintthread.h"
#include "common.h"
#include "packet.h"
#include <QDebug>

extern QString rawText;

RawPrintThread::RawPrintThread()
{
    stopped = false;
}

RawPrintThread::~RawPrintThread()
{

}

void RawPrintThread::stop()
{
    stopped = true;
}

void RawPrintThread::run()
{
    // qDebug() << "RawPrintThread start";
    // rawdataFlag = false;
    unsigned int i,k,l;
    u_char *data=(u_char *)Globe::capPacket.OIndex->pkt_data;
    rawText = QString("");
    unsigned int spliter;
    char *c;
    char buf[4];
    char textbuf[16+2];
    memset(buf,0,4);
    memset(textbuf,0,16+1);
    spliter = 0;

    //handle the hex content
    for(i=0;i<Globe::capPacket.OIndex->header.len;i++)
    {
        if (spliter == 8) rawText += "  ";
        if (spliter == 16)
        {
            rawText += "\t";
            // handle textbuf
            c = (char *)&data[-spliter];
            k=0;
            for(l = 0;l < spliter;l++)
            {
                if (l==8) textbuf[k++] = ' ';
                if(isprint(*c)) textbuf[k++]=*c;
                else textbuf[k++] = '.';
                c++;
            }
            textbuf[16+1]='\0';
            // end handle textbuf
            rawText += QString(textbuf);
            rawText += "\n";
            spliter = 0;
        }
        sprintf(buf,"%02X ",*data);
        rawText += QString(buf);
        spliter++;
        data++;
    } // for
    //fill the gap
    for(i = ((16*3) - spliter*3);i;i--) rawText += " ";

    // append the textbuf
    rawText += "\t";
    // handle textbuf
    c = (char *)&data[-spliter];
    k = 0;
    for(l = 0;l < spliter;l++)
    {
        if (l==8) textbuf[k++] = ' ';
        if(isprint(*c)) textbuf[k++]=*c;
        else textbuf[k++] = '.';
        c++;
    }
    // end handle textbuf
    textbuf[spliter<17?spliter:17]='\0';
    rawText += QString(textbuf);
    rawText += "\n";
    spliter = 0;

    // ui->textEdit_raw->setText(rawText);
    // qDebug()<< text;
    // rawdataFlag = true;
    emit RawPrintDone();
    qDebug() << "emit RawPrintDone";
}
