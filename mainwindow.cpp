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
    PacketModel->setHeaderData(0,Qt::Horizontal,QString("   No.   "));
    PacketModel->setHeaderData(1,Qt::Horizontal,QString("       Time       "));
    PacketModel->setHeaderData(2,Qt::Horizontal,QString("                   Source                   "));
    PacketModel->setHeaderData(3,Qt::Horizontal,QString("                  Destionation                  "));
    PacketModel->setHeaderData(4,Qt::Horizontal,QString("    Protocol    "));
    PacketModel->setHeaderData(5,Qt::Horizontal,QString("    Length    "));
    PacketModel->setHeaderData(6,Qt::Horizontal,QString("          Information1            "));
    PacketModel->setHeaderData(7,Qt::Horizontal,QString("          Information2            "));
    ui->tableView_packet->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
    ui->tableView_packet->setModel(PacketModel);

    ui->tableView_packet->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
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
    QStandardItem *rootItem = new QStandardItem(QString("No.%1").arg(sernum));
    DetailModel->appendRow(rootItem);

    /* Frame Info */
    QString arrivedTime = Globe::capPacket.PF->timestamp;
    QString devName = Globe::capPacket.PF->NAname;
    QString packLen = QString::number(Globe::capPacket.PF->header.len);
    QString frameProto = Globe::capPacket.PF->Netpro;
    strText = QString("Frame: %1 bytes captured on %2").arg(packLen,devName);
    QStandardItem *frameItem = new QStandardItem(strText);
    item = new QStandardItem(QString("Interface name: %1").arg(devName));
    childItems.push_back(item);
    item = new QStandardItem(QString("Encapsulation type: %1").arg(frameProto));
    childItems.push_back(item);
    item = new QStandardItem(QString("Arrival time: %1").arg(arrivedTime));
    childItems.push_back(item);
    frameItem->appendRows(childItems);
    rootItem->appendRow(frameItem);

    /* Ethernet Info */
    QString eth_src = QString("(%1:%2:%3:%4:%5:%6)")\
            .arg(Globe::capPacket.PF->ether_header->ether_shost.byte1,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_shost.byte2,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_shost.byte3,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_shost.byte4,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_shost.byte5,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_shost.byte6,0,16);
    QString eth_dst = QString("(%1:%2:%3:%4:%5:%6)")\
            .arg(Globe::capPacket.PF->ether_header->ether_dhost.byte1,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_dhost.byte2,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_dhost.byte3,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_dhost.byte4,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_dhost.byte5,0,16)\
            .arg(Globe::capPacket.PF->ether_header->ether_dhost.byte6,0,16);
    QString type = QString(Globe::capPacket.PF->ether_header->ether_type);
    QString proto = QString(Globe::capPacket.PF->Netpro);

    strText = QString("Ethernet II, Src: %1, Dst: %2").arg(eth_src,eth_dst);
    QStandardItem *etherItem = new QStandardItem(strText);
    item = new QStandardItem(QString("Destination: %1").arg(eth_dst));
    childItems.push_back(item);
    item = new QStandardItem(QString("Source: %1").arg(eth_src));
    childItems.push_back(item);
    item = new QStandardItem(QString("Type: %1 (%2)").arg(type).arg(proto));
    childItems.push_back(item);
    etherItem->appendRows(childItems);
    rootItem->appendRow(etherItem);

    /* Network Info */


    strText = "Network Info";
    QStandardItem *networkItem = new QStandardItem(strText);
    rootItem->appendRow(networkItem);

    /* Transport Info */
    strText = "Transport layer";
    QStandardItem *transItem = new QStandardItem(strText);
    rootItem->appendRow(transItem);

    /* Application Layer Info */
    strText = "Application Layer";
    QStandardItem *appItem = new QStandardItem(strText);
    rootItem->appendRow(appItem);

    ui->treeView_detail->setModel(DetailModel);
}

void MainWindow::PrintRawdata()
{
    rawdataFlag = false;
    int i,k,l;
    u_char *data=(u_char *)Globe::capPacket.PF->pkt_data;
    QString text;
    int spliter;
    char *c;
    char buf[4];
    char textbuf[16+2];
    memset(buf,0,4);
    memset(textbuf,0,16+1);
    spliter = 0;

    //handle the hex content
    for(i=0;i<Globe::capPacket.PF->header.len;i++)
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
        qDebug() << buf;
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
    qDebug()<< text;
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
    qDebug() << "Now in SetModel";
    priThread.MuxFlag=false;
    if(PacketModel->rowCount()>0)
    {
        ui->tableView_packet->setModel(PacketModel);
        qDebug() << "setModel";
    }
    else
    {
        QMessageBox::about(NULL,"", "в");
    }
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


        Globe::capPacket.PF=Globe::capPacket.Head;//
        while(Globe::capPacket.PF->serialnum!=sernum)
        {
            Globe::capPacket.PF=Globe::capPacket.PF->Next;
        }

        PrintRawdata();//
        PrintDetaildata(sernum);//
    }
}
