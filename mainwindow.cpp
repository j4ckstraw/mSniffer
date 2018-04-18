#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QStandardItemModel>
#include "common.h"
#include <QDebug>
#include "packetprintthread.h"
#include "capturethread.h"
#include "analysethread.h"
#include "offlineanalysethread.h"
#include <QTableView>
#include <QFile>
#include <QFileDialog>

QString file_name;

QStandardItemModel *PacketModel = new QStandardItemModel(); // packet model
QStandardItemModel *DetailModel = new QStandardItemModel(); // detail model

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
    packetpriThread.MuxFlag=true;

    /*数据包基本信息联机显示列表*/
#define SIZEOF_HEADER 7
    PacketModel->setColumnCount(SIZEOF_HEADER);
    PacketModel->setHeaderData(0,Qt::Horizontal,QString("No."));
    PacketModel->setHeaderData(1,Qt::Horizontal,QString("  Time  "));
    PacketModel->setHeaderData(2,Qt::Horizontal,QString("     Source     "));
    PacketModel->setHeaderData(3,Qt::Horizontal,QString("  Destionation   "));
    PacketModel->setHeaderData(4,Qt::Horizontal,QString("  Protocol  "));
    PacketModel->setHeaderData(5,Qt::Horizontal,QString("  Length  "));
    PacketModel->setHeaderData(6,Qt::Horizontal,QString("                      Info                     "));

    ui->tableView_packet->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->tableView_packet->setModel(PacketModel);

//    ui->tableView_packet->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
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

    chosedialog = new InterfacesDialog();
    chosedialog->setModal(false);
    chosedialog->exec();
    chosedialog->activateWindow();


    connect(&capThread,SIGNAL(CaptureStopped()),this,SLOT(StopAnalyze()));
    connect(&offThread,SIGNAL(OfflineStopped()),this,SLOT(StopAnalyze()));
    connect(&anaThread,SIGNAL(AnalyzeStopped()),this,SLOT(StopPrint()));
    connect(&packetpriThread,SIGNAL(PacketPrintDone()),this,SLOT(UpdatePacketView()));
    connect(&detailpriThread,SIGNAL(DetailPrintDone()),this,SLOT(FlushDetailView()));
}

MainWindow::~MainWindow()
{
    if(!capThread.isFinished())
        capThread.terminate();
    if(!anaThread.isFinished())
        anaThread.terminate();
    if(!packetpriThread.isFinished())
        packetpriThread.terminate();
    if(!offThread.isFinished())
        offThread.terminate();
    delete ui;
}

//void MainWindow::PrintDetaildata(int sernum)
//{
//    ui->treeView_detail->setModel(DetailModel);
//}

void MainWindow::PrintRawdata()
{
    rawdataFlag = false;
    unsigned int i,k,l;
    u_char *data=(u_char *)Globe::capPacket.OIndex->pkt_data;
    QString text;
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
    if(capThread.isRunning())
        capThread.terminate();
    if(anaThread.isRunning())
        anaThread.terminate();
    if(packetpriThread.isRunning())
        packetpriThread.terminate();
    if(offThread.isRunning())
        offThread.terminate();

    chosedialog->close();
    this->close();
}

void MainWindow::on_actionRefresh_Interfaces_triggered()
{
    if(!chosedialog)
    {
        chosedialog = new InterfacesDialog();
        chosedialog->show();
    }
    else
    {
        chosedialog->show();
        chosedialog->activateWindow();
    }
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
    if(!packetpriThread.isRunning())
        packetpriThread.start(QThread::HighPriority);
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
    packetpriThread.terminate();
    // restart clear captured packets.
    Globe::capPacket.DeleteList();
    PacketModel->clear();
    DetailModel->clear();
    PacketModel->setColumnCount(SIZEOF_HEADER);
    PacketModel->setHeaderData(0,Qt::Horizontal,QString("No."));
    PacketModel->setHeaderData(1,Qt::Horizontal,QString("  Time  "));
    PacketModel->setHeaderData(2,Qt::Horizontal,QString("     Source     "));
    PacketModel->setHeaderData(3,Qt::Horizontal,QString("  Destionation   "));
    PacketModel->setHeaderData(4,Qt::Horizontal,QString("  Protocol  "));
    PacketModel->setHeaderData(5,Qt::Horizontal,QString("  Length  "));
    PacketModel->setHeaderData(6,Qt::Horizontal,QString("                      Info                     "));
    // PacketModel->setHeaderData(7,Qt::Horizontal,QString("Information2"));
    this->UpdatePacketView();
    if(!capThread.isRunning())
        capThread.start();
    if(!anaThread.isRunning())
        anaThread.start();
    if(!packetpriThread.isRunning())
        packetpriThread.start(QThread::HighPriority);
}

void MainWindow::on_actionPause_triggered()
{
    // toggle buttons state
//    ui->actionStart->setEnabled(true);
//    ui->actionPause->setEnabled(false);
//    ui->actionStop->setEnabled(true);
//    ui->actionRestart->setEnabled(false);

    QMessageBox::information(this,"Pause info","this function not implement");
}

void MainWindow::on_actionAbout_mSniffer_triggered()
{
    QMessageBox::about(this,"About mSniffer", "This is mini Sniffer powered by Qt!\n");
}


void MainWindow::on_tableView_packet_clicked(const QModelIndex &index)
{
    if(!packetpriThread.isRunning())
    {
        int row=index.row();//б
        ui->tableView_packet->selectRow(row);
        qDebug() << "On packet clicked #####################";
        qDebug() << QString("Row: %1").arg(row);
        qDebug() << QString("QPoint: ") << QPoint(row,0);
        qDebug() << QString("Data: ") << ui->tableView_packet->indexAt(QPoint(row,0)).data();
        qDebug() << QString("Data to INT: %1").arg(ui->tableView_packet->indexAt(QPoint(row,0)).data().toInt());

        unsigned int sernum = ui->tableView_packet->indexAt(QPoint(row,0)).data().toInt();
        qDebug() << QString("Serial number(first Get): %1").arg(sernum);
        if(sernum == 0 )
        {
            QMessageBox::warning(0,"Warning","Sernum is 0");
            return ;
        }
        Globe::capPacket.OIndex=Globe::capPacket.Head;
        while(Globe::capPacket.OIndex->serialnum!=sernum)
        {
            Globe::capPacket.OIndex=Globe::capPacket.OIndex->Next;
        }
        qDebug() << QString("Serial number(before DetailPrintThread): %1").arg(sernum);
        PrintRawdata();
        // PrintDetaildata(sernum);
        if(!detailpriThread.isRunning())
            detailpriThread.start();
    }
}

void MainWindow::on_actionOpen_triggered()
{
    // pcap_t *fp;
    // char errbuf[PCAP_ERRBUF_SIZE];
    QString filter = "All files(*.*);;Wireshark /tcpdump/...-pcap(*.dmp.gz;*.dmp;*.cap.gz;*.cap;*.pcap.gz;*.pcap);;Cinco NetXRay,Sniffer(Windows)(*.caz.gz;*.caz;*.cap.gz;*.cap)";
    file_name = QFileDialog::getOpenFileName(this, "Open a file...","",filter);
    // QMessageBox::information(this,"information","Need to be implement");
    qDebug() << "Open file: " << file_name;
    if(!offThread.isRunning())
        offThread.start();
    if(!anaThread.isRunning())
        anaThread.start();
    if(!packetpriThread.isRunning())
        packetpriThread.start();
}

void MainWindow::UpdatePacketView()
{
    qDebug() << "Now in SetModel";
    packetpriThread.MuxFlag=false;
    if(PacketModel->rowCount()>0)
    {
        ui->tableView_packet->setModel(PacketModel);
    }
    else
    {
        qDebug() << QString("PacketModel count: %1").arg(PacketModel->rowCount());
    }
    packetpriThread.MuxFlag=true;
}

void MainWindow::FlushDetailView()
{
    qDebug() << "Now in DetailModel";
    detailpriThread.MuxFlag=false;
    ui->treeView_detail->setHeaderHidden(true);
    ui->treeView_detail->setEditTriggers(QTableView::NoEditTriggers);
    if(DetailModel->rowCount()>0)
    {
//        while(!detailpriThread.isFinished()) Sleep(1);
        ui->treeView_detail->setModel(DetailModel);
    }
    else
    {
        qDebug() << QString("DetailModel count: %1").arg(DetailModel->rowCount());
    }
    detailpriThread.MuxFlag=true;
}


void MainWindow::StopPrint()
{
    if(packetpriThread.isRunning())
        packetpriThread.stop();
}

void MainWindow::StopAnalyze()
{
    if(anaThread.isRunning())
        anaThread.stop();
}
