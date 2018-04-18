#include "detailprintthread.h"
#include "common.h"
#include <QStandardItemModel>
#include <QDebug>
#include <QString>
#include <QMessageBox>

extern QStandardItemModel *DetailModel;

DetailPrintThread::DetailPrintThread()
{
    stopped = false;
}

DetailPrintThread::~DetailPrintThread(){}

void DetailPrintThread::stop()
{
    stopped = true;
}

void DetailPrintThread::run()
{
    QString strText;
    QStandardItem *item;
    QList<QStandardItem *> childItems;
    // qDebug() << QString("serial number:%1").arg(sernum);
    if(!Globe::capPacket.OIndex || !Globe::capPacket.OIndex->Aflag || !Globe::capPacket.OIndex->Pflag)
    {
        QMessageBox::warning(0,"Warning","DetailPrintThread: OIndex is null or not Analysed yet");
        return ;
    }
    u_short sernum = Globe::capPacket.OIndex->serialnum;
    QStandardItem *rootItem = new QStandardItem(QString("No.%1").arg(sernum));
    // clear it before append
    DetailModel->clear();
    DetailModel->appendRow(rootItem);

    /* Frame Info */
    QString arrivedTime = Globe::capPacket.OIndex->timestamp;
    QString devName = Globe::capPacket.OIndex->NAname;
    QString packLen = QString::number(Globe::capPacket.OIndex->header.len);
    QString frameProto = Globe::capPacket.OIndex->Netpro;
    strText = QString("Frame: %1 bytes captured on %2").arg(packLen,devName);
    QStandardItem *frameItem = new QStandardItem(strText);
    item = new QStandardItem(QString("Interface name: %1").arg(devName));
    childItems.push_back(item);
    item = new QStandardItem(QString("Encapsulation type: %1").arg(frameProto));
    childItems.push_back(item);
    item = new QStandardItem(QString("Arrival time: %1").arg(arrivedTime));
    childItems.push_back(item);
    frameItem->appendRows(childItems);
    //rootItem->appendRow(frameItem);
    DetailModel->appendRow(frameItem);

    /* Ethernet Info */
    Ethernet ethInfo = Ethernet(Globe::capPacket.OIndex->ether_header);

//    QString eth_src = mactos(Globe::capPacket.OIndex->ether_header->ether_shost);
//    QString eth_dst = mactos(Globe::capPacket.OIndex->ether_header->ether_dhost);
//    QString type = QString(Globe::capPacket.OIndex->ether_header->ether_type);
//    QString proto = QString(Globe::capPacket.OIndex->Netpro);

    strText = QString("Ethernet II, Src: %1, Dst: %2").arg(ethInfo.shost_str,ethInfo.shost_str);
    QStandardItem *etherItem = new QStandardItem(strText);
    childItems.clear();
    item = new QStandardItem(QString("Destination: %1").arg(ethInfo.dhost_str));
    childItems.push_back(item);
    item = new QStandardItem(QString("Source: %1").arg(ethInfo.shost_str));
    childItems.push_back(item);
    item = new QStandardItem(QString("Type: %1 (0x%2)").arg(ethInfo.type_str).arg(ethInfo.type,4,16,QChar('0')));
    childItems.push_back(item);
    etherItem->appendRows(childItems);
    DetailModel->appendRow(etherItem);

    /* Network Info */

    qDebug() << "Network info:" <<  Globe::capPacket.OIndex->Netpro;

    if(Globe::capPacket.OIndex->Netpro.compare("ARP")==0)
    {
        ARP arpInfo(Globe::capPacket.OIndex->ARP_header);
        strText = QString("Address Resolution Protocol(%1)").arg(arpInfo.opcode_str);
        QStandardItem *networkItem = new QStandardItem(strText);
        childItems.clear();
        item = new QStandardItem(QString("Hardware type: %1").arg(arpInfo.hd_type));
        childItems.push_back(item);
        item = new QStandardItem(QString("Protocol type: %1(0x%2)").arg(arpInfo.proto_type_str).arg(arpInfo.proto_type,4,16,QChar('0')));
        childItems.push_back(item);
        item = new QStandardItem(QString("Hardware size: %1").arg(arpInfo.hd_len));
        childItems.push_back(item);
        item = new QStandardItem(QString("Protocol size: %1").arg(arpInfo.pro_addr_len));
        childItems.push_back(item);
        item = new QStandardItem(QString("Opcode: %1(%2)").arg(arpInfo.opcode_str).arg(arpInfo.opcode));
        childItems.push_back(item);
        item = new QStandardItem(QString("Sender MAC address: %1").arg(arpInfo.src_addr));
        childItems.push_back(item);
        item = new QStandardItem(QString("Sender IP address: %1").arg(arpInfo.sip_addr));
        childItems.push_back(item);
        item = new QStandardItem(QString("Target MAC address: %1").arg(arpInfo.dst_addr));
        childItems.push_back(item);
        item = new QStandardItem(QString("Sender MAC address: %1").arg(arpInfo.dip_addr));
        childItems.push_back(item);
        networkItem->appendRows(childItems);
        DetailModel->appendRow(networkItem);
    }
    else if(Globe::capPacket.OIndex->Netpro.compare("RARP")==0)
    {

    }
    else if(Globe::capPacket.OIndex->Netpro.compare("IPv4")==0)   // IPv4
    {
        IP ipInfo = IP(Globe::capPacket.OIndex->IPv4_header);
        strText = QString("Internet Protocol Version %1, Src: %2, Dst: %3").arg(ipInfo.ver,ipInfo.src,ipInfo.dst);
        QStandardItem *networkItem = new QStandardItem(strText);
        childItems.clear();
        item = new QStandardItem(QString("Version: %1").arg(ipInfo.ver));
        childItems.push_back(item);
        item = new QStandardItem(QString("Header Length: %1").arg(ipInfo.hdr_len));
        childItems.push_back(item);
        item = new QStandardItem(QString("Totol Length: %1").arg(ipInfo.tlen));
        childItems.push_back(item);
        item = new QStandardItem(QString("Identification: %1").arg(ipInfo.ident));
        childItems.push_back(item);
        item = new QStandardItem(QString("Flags: %1").arg(ipInfo.flags));
        childItems.push_back(item);
        item = new QStandardItem(QString("Time to live： %1").arg(ipInfo.ttl));
        childItems.push_back(item);
        item = new QStandardItem(QString("Protocol: %1").arg(ipInfo.proto));
        childItems.push_back(item);
        item = new QStandardItem(QString("Header checksum: %1").arg(ipInfo.crc));
        childItems.push_back(item);
        item = new QStandardItem(QString("Source: %1").arg(ipInfo.src));
        childItems.push_back(item);
        item = new QStandardItem(QString("Destination: %1").arg(ipInfo.dst));
        childItems.push_back(item);
        networkItem->appendRows(childItems);
        // rootItem->appendRow(networkItem);
        DetailModel->appendRow(networkItem);
    }
    else if(Globe::capPacket.OIndex->Netpro.compare("IPv6")==0) // IPv6
    {
        strText = "Internet Protocol Version 6";
        QStandardItem *networkItem = new QStandardItem(strText);
        // rootItem->appendRow(networkItem);
        DetailModel->appendRow(networkItem);
    }
    else
    {
        strText = "Network Info";
        // QStandardItem *networkItem = new QStandardItem(strText);
        // rootItem->appendRow(networkItem);
        // DetailModel->appendRow(networkItem);
    }


    /* Transport Info */
    if(Globe::capPacket.OIndex->Netpro.compare("TCP")==0) // TCP
    {
        TCP tcpInfo = TCP(Globe::capPacket.OIndex->TCP_header);

        strText = QString("Transmission Control Protocol, Src Port: %1, Dst Port: %2, Seq: %3")\
                .arg(tcpInfo.src_port,tcpInfo.dst_port,tcpInfo.seq_num);
        QStandardItem *transItem = new QStandardItem(strText);
        childItems.clear();
        item = new QStandardItem(QString("Source Port: %1").arg(tcpInfo.src_port));
        childItems.push_back(item);
        item = new QStandardItem(QString("Destination Port: %1").arg(tcpInfo.dst_port));
        childItems.push_back(item);
        item = new QStandardItem(QString("Sequence Number: %1").arg(tcpInfo.seq_num));
        childItems.push_back(item);
        item = new QStandardItem(QString("Acknowledgment number: %1").arg(tcpInfo.ack_num));
        childItems.push_back(item);
        item = new QStandardItem(QString("Header length: %1").arg(4*tcpInfo.data_offset.toInt()));
        childItems.push_back(item);
        item = new QStandardItem(QString("Flags: %1").arg(tcpInfo.flags));
        childItems.push_back(item);
        item = new QStandardItem(QString("Window size value: %1").arg(tcpInfo.window_size));
        childItems.push_back(item);
        item = new QStandardItem(QString("Urgent pointer: %1").arg(tcpInfo.urgp));
        childItems.push_back(item);
        transItem->appendRows(childItems);
        // rootItem->appendRow(transItem);
        DetailModel->appendRow(transItem);
    } // end TCP
    else if(Globe::capPacket.OIndex->Netpro.compare("UDP")==0) // UDP
    {
        UDP udpInfo = UDP(Globe::capPacket.OIndex->UDP_header);

        strText = QString("User Datagram Protocol, Src Port: %1, Dst Port: %2")\
                .arg(udpInfo.src_port,udpInfo.dst_port);
        QStandardItem *transItem = new QStandardItem(strText);
        childItems.clear();
        item = new QStandardItem(QString("Source Port: %1").arg(udpInfo.src_port));
        childItems.push_back(item);
        item = new QStandardItem(QString("Destination Port: %1").arg(udpInfo.dst_port));
        childItems.push_back(item);
        item = new QStandardItem(QString("Length: %1").arg(udpInfo.length));
        childItems.push_back(item);
        item = new QStandardItem(QString("Checksum: %1").arg(udpInfo.crc));
        childItems.push_back(item);
        transItem->appendRows(childItems);
        // rootItem->appendRow(transItem);
        DetailModel->appendRow(transItem);
    }// end UDP
    else    // default
    {
        // strText = "UNKNOWN Transport Layer";
        // QStandardItem *transItem = new QStandardItem(strText);
        // rootItem->appendRow(transItem);
        // DetailModel->appendRow(transItem);
    } // end default

    /* Application Layer Info */
    if(Globe::capPacket.OIndex->Apppro.compare("HTTP")==0) // HTTP
    {
        strText = "Hypertext Transfer Protocol";
        QStandardItem *appItem = new QStandardItem(strText);

        QString http_txt = analyzeHttpPacket(Globe::capPacket.Pindex);
        HTTP httpInfo = HTTP(http_txt);
        childItems.clear();
        if (!httpInfo.httpMethod.isEmpty()) childItems.push_back(new QStandardItem(QString(httpInfo.httpMethod)));
        if (!httpInfo.httpResponse.isEmpty()) childItems.push_back(new QStandardItem(QString(httpInfo.httpResponse)));
        if (!httpInfo.httpHost.isEmpty()) childItems.push_back(new QStandardItem(QString(httpInfo.httpHost)));
        if (!httpInfo.httpConnection.isEmpty()) childItems.push_back(new QStandardItem(QString(httpInfo.httpHost)));
        if (!httpInfo.httpUserAgent.isEmpty()) childItems.push_back(new QStandardItem(QString(httpInfo.httpUserAgent)));
        if (!httpInfo.httpAccept.isEmpty()) childItems.push_back(new QStandardItem(QString(httpInfo.httpAccept)));
        appItem->appendRows(childItems);
        //rootItem->appendRow(appItem);
        DetailModel->appendRow(appItem);
    }// end HTTP
    else  // default
    {
        strText = "Application Layer";
        // QStandardItem *appItem = new QStandardItem(strText);
        // rootItem->appendRow(appItem);
        // DetailModel->appendRow(appItem);
    }// end default
    emit DetailPrintDone();
    qDebug() << "Message from DetailPrint: Print done.";
}
