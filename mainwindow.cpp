#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QStandardItemModel>
#include "common.h"
#include <QDebug>
#include "printthread.h"
#include "capturethread.h"
#include "analysethread.h"
#include <QTableView>
#include <QFile>
#include <QFileDialog>

QStandardItemModel *PacketModel = new QStandardItemModel();//数据包基本信息;
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("mSniffer");
    startFlag=false;
    comboindex=0;
    selnum=-1;
    rawdataFlag=false;
    priThread.MuxFlag=true;

    chosedialog = new interfacesDialog();


    /*数据包基本信息联机显示列表*/
#define SIZEOF_HEADER 8
    PacketModel->setColumnCount(SIZEOF_HEADER);
    PacketModel->setHeaderData(0,Qt::Horizontal,QString("No."));
    PacketModel->setHeaderData(1,Qt::Horizontal,QString("Time"));
    PacketModel->setHeaderData(2,Qt::Horizontal,QString("Source"));
    PacketModel->setHeaderData(3,Qt::Horizontal,QString("Destionation"));
    PacketModel->setHeaderData(4,Qt::Horizontal,QString("Protocol"));
    PacketModel->setHeaderData(5,Qt::Horizontal,QString("Length"));
    PacketModel->setHeaderData(6,Qt::Horizontal,QString("Info"));
    PacketModel->setHeaderData(7,Qt::Horizontal,QString("Information2"));
    ui->tableView_packet->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    ui->tableView_packet->setModel(PacketModel);

    // ui->tableView_packet->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tableView_packet->setEditTriggers(QTableView::NoEditTriggers);
    ui->tableView_packet->verticalHeader()->setVisible(false);
    ui->tableView_packet->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    //数据包主要信息显示的样式设置为黄蓝间隔
    ui->tableView_packet->setAlternatingRowColors(true);
    ui->tableView_packet->setStyleSheet("QTableView{background-color: rgb(250, 250, 115);"
                                          "alternate-background-color: rgb(141, 163, 215);}");
    Globe::capPacket.Iniflag=false;

    // toggle buttons state
    ui->actionPause->setEnabled(false);
    ui->actionStop->setEnabled(false);
    ui->actionRestart->setEnabled(false);

    connect(&capThread,SIGNAL(CaptureStopped()),this,SLOT(StopAnalyze()));
    connect(&anaThread,SIGNAL(AnalyzeStopped()),this,SLOT(StopPrint()));
    connect(&priThread,SIGNAL(Modelchanged()),this,SLOT(SetModel()));

}

MainWindow::~MainWindow()
{
    capThread.terminate();
    anaThread.terminate();
    priThread.terminate();
    delete ui;
}

void MainWindow::PrintDetaildata(int sernum)
{
    QString strText;
    QStandardItem *item;
    QList<QStandardItem *> childItems;

    ui->treeView_detail->setHeaderHidden(true);
    QStandardItemModel *DetailModel = new QStandardItemModel();
    // QStandardItem *rootItem = new QStandardItem(QString("No.%1").arg(sernum));
    // DetailModel->appendRow(rootItem);

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
    QString eth_src = mactos(Globe::capPacket.OIndex->ether_header->ether_shost);
    QString eth_dst = mactos(Globe::capPacket.OIndex->ether_header->ether_dhost);
    QString type = QString(Globe::capPacket.OIndex->ether_header->ether_type);
    QString proto = QString(Globe::capPacket.OIndex->Netpro);

    strText = QString("Ethernet II, Src: %1, Dst: %2").arg(eth_src,eth_dst);
    QStandardItem *etherItem = new QStandardItem(strText);
    childItems.clear();
    item = new QStandardItem(QString("Destination: %1").arg(eth_dst));
    childItems.push_back(item);
    item = new QStandardItem(QString("Source: %1").arg(eth_src));
    childItems.push_back(item);
    item = new QStandardItem(QString("Type: %1 (%2)").arg(type).arg(proto));
    childItems.push_back(item);
    etherItem->appendRows(childItems);
    // rootItem->appendRow(etherItem);
    DetailModel->appendRow(etherItem);

    /* Network Info */

    if(Globe::capPacket.OIndex->Netpro.compare("IPv4")==0)   // IPv4
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
        QStandardItem *networkItem = new QStandardItem(strText);
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
        strText = "UNKNOWN Transport Layer";
        QStandardItem *transItem = new QStandardItem(strText);
        // rootItem->appendRow(transItem);
        // DetailModel->appendRow(transItem);
    } // end default

    /* Application Layer Info */
    if(Globe::capPacket.OIndex->Netpro.compare("HTTP")==0) // HTTP
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
        QStandardItem *appItem = new QStandardItem(strText);
        // rootItem->appendRow(appItem);
        // DetailModel->appendRow(appItem);
    }// end default


    ui->treeView_detail->setModel(DetailModel);
}

void MainWindow::PrintRawdata()
{
    rawdataFlag = false;
    int i,k,l;
    u_char *data=(u_char *)Globe::capPacket.OIndex->pkt_data;
    QString text;
    int spliter;
    char *c;
    char buf[4];
    char textbuf[16+2];
    memset(buf,0,4);
    memset(textbuf,0,16+1);
    spliter = 0;

    //handle the hex content
    for(i=0;i<Globe::capPacket.OIndex->header.len;i++)
    {
        if (spliter == 8) text += "  ";
        if (spliter == 16)
        {
            text += "\t";
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
            text += QString(textbuf);
            text += "\n";
            spliter = 0;
        }
        sprintf(buf,"%02X ",*data);
        text += QString(buf);
        spliter++;
        data++;
    } // for
    //fill the gap
    for(i = ((16*3) - spliter*3);i;i--) text += " ";

    // append the textbuf
    text += "\t";
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
    text += QString(textbuf);
    text += "\n";
    spliter = 0;

    ui->textEdit_raw->setText(text);
    // qDebug()<< text;
    rawdataFlag = true;
}

void MainWindow::on_actionQuit_triggered()
{
    capThread.terminate();
    anaThread.terminate();
    priThread.terminate();
    this->close();
}

void MainWindow::on_actionRefresh_Interfaces_triggered()
{
    interfacesDialog *intDia = new interfacesDialog();
    intDia->show();
}

void MainWindow::on_actionStart_triggered()
{
    ui->actionStart->setEnabled(false);
    ui->actionPause->setEnabled(true);
    ui->actionStop->setEnabled(true);
    ui->actionRestart->setEnabled(true);
    if(!capThread.isRunning())
        capThread.start();
    if(!anaThread.isRunning())
        anaThread.start();
    if(!priThread.isRunning())
        priThread.start(QThread::HighPriority);
}

void MainWindow::on_actionStop_triggered()
{
    // toggle buttons state
    ui->actionStart->setEnabled(true);
    ui->actionPause->setEnabled(false);
    ui->actionStop->setEnabled(false);
    ui->actionRestart->setEnabled(true);
    //capThread.wait();
    //capThread.terminate();
    capThread.stop();
}

void MainWindow::on_actionRestart_triggered()
{
    // toggle buttons state
    ui->actionStart->setEnabled(false);
    ui->actionPause->setEnabled(true);
    ui->actionStop->setEnabled(true);
    ui->actionRestart->setEnabled(true);
    capThread.terminate();
    anaThread.terminate();
    priThread.terminate();
    // restart clear captured packets.
    Globe::capPacket.DeleteList();
    PacketModel->clear();
    PacketModel->setColumnCount(SIZEOF_HEADER);
    PacketModel->setHeaderData(0,Qt::Horizontal,QString("No."));
    PacketModel->setHeaderData(1,Qt::Horizontal,QString("Time"));
    PacketModel->setHeaderData(2,Qt::Horizontal,QString("Source"));
    PacketModel->setHeaderData(3,Qt::Horizontal,QString("Destionation"));
    PacketModel->setHeaderData(4,Qt::Horizontal,QString("Protocol"));
    PacketModel->setHeaderData(5,Qt::Horizontal,QString("Length"));
    PacketModel->setHeaderData(6,Qt::Horizontal,QString("Info"));
    PacketModel->setHeaderData(7,Qt::Horizontal,QString("Information2"));
    this->SetModel();
    if(!capThread.isRunning())
        capThread.start();
    if(!anaThread.isRunning())
        anaThread.start();
    if(!priThread.isRunning())
        priThread.start(QThread::HighPriority);
}

void MainWindow::on_actionPause_triggered()
{
    // toggle buttons state
    ui->actionStart->setEnabled(true);
    ui->actionPause->setEnabled(false);
    ui->actionStop->setEnabled(true);
    ui->actionRestart->setEnabled(false);
    // capThread.pause();
    QMessageBox::information(this,"Pause info","this function not implement");
}

void MainWindow::on_actionAbout_mSniffer_triggered()
{
    QMessageBox::about(this,"About mSniffer", "This is mini Sniffer powered by Qt!\n");
}

void MainWindow::SetModel()
{
    // qDebug() << "Now in SetModel";
    priThread.MuxFlag=false;
    if(PacketModel->rowCount()>0)
    {
        ui->tableView_packet->setModel(PacketModel);
    }
//    else
//    {
//        QMessageBox::about(NULL,"", "в");
//    }
    priThread.MuxFlag=true;
}

void MainWindow::StopPrint()
{
    if(priThread.isRunning())
        priThread.stop();
}

void MainWindow::StopAnalyze()
{
    if(anaThread.isRunning())
        anaThread.stop();
}

void MainWindow::on_tableView_packet_clicked(const QModelIndex &index)
{
    if(!priThread.isRunning())//
    {
        QModelIndex index=ui->tableView_packet->currentIndex();
        int row=index.row();//б
        ui->tableView_packet->selectRow(row);
        // int sernum=ui->tableView_packet->index(row,0).data().toInt();
        int sernum = ui->tableView_packet->indexAt(QPoint(row,0)).data().toInt();
        // int sernum = ui->tableView_packet->childAt(row,0)->data().toInt();


        Globe::capPacket.OIndex=Globe::capPacket.Head;//
        while(Globe::capPacket.OIndex->serialnum!=sernum)
        {
            Globe::capPacket.OIndex=Globe::capPacket.OIndex->Next;
        }

        PrintRawdata();//
        PrintDetaildata(sernum);//
    }
}
