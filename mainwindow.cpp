#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QStandardItemModel>
#include "common.h"
#include <QDebug>
#include "packetprintthread.h"
#include "capturethread.h"
#include "analysethread.h"
#include "offlinecapturethread.h"
#include "rawprintthread.h"
#include <QTableView>
#include <QFile>
#include <QFileDialog>

QString file_name;
QStandardItemModel *PacketModel = new QStandardItemModel(); // packet model
QStandardItemModel *DetailModel = new QStandardItemModel(); // detail model
QString rawText;
extern int interface_selected;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("mSniffer");
    setWindowIcon(QIcon(":/icons/favicon.png"));
    startFlag=false;
    comboindex=0;
    selnum=-1;
    rawdataFlag=false;
    packetpriThread.MuxFlag=true;

    // set packet model
    InitPacketModel();

//    ui->tableView_packet->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tableView_packet->setEditTriggers(QTableView::NoEditTriggers);
    ui->tableView_packet->verticalHeader()->setVisible(false);
    ui->tableView_packet->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    //packet view style
    ui->tableView_packet->setAlternatingRowColors(true);
    ui->tableView_packet->setStyleSheet("QTableView{background-color: rgb(250, 250, 115);"
                                        "alternate-background-color: rgb(141, 163, 215);}");
    Globe::capPacket.Iniflag=false;

    // toggle buttons state
    ui->actionPause->setEnabled(false);
    ui->actionStop->setEnabled(false);
    ui->actionRestart->setEnabled(false);


    connect(&capThread,SIGNAL(CaptureStopped()),this,SLOT(StopAnalyze()));
    connect(&offThread,SIGNAL(OfflineStopped()),this,SLOT(StopAnalyze()));
    connect(&anaThread,SIGNAL(AnalyzeStopped()),this,SLOT(StopPrint()));
    connect(&packetpriThread,SIGNAL(PacketPrintDone()),this,SLOT(UpdatePacketView()));
    connect(&detailpriThread,SIGNAL(DetailPrintDone()),this,SLOT(UpdateDetailView()));
    connect(&rawpriThread,SIGNAL(RawPrintDone()),this,SLOT(UpdateRawView()));
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
    if(!detailpriThread.isFinished())
        detailpriThread.terminate();
    if(!rawpriThread.isFinished())
        rawpriThread.terminate();
    delete ui;
}

void MainWindow::InitPacketModel()
{
#define SIZEOF_HEADER 7
    PacketModel->clear();
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
    chosedialog = new InterfacesDialog();
    chosedialog->show();
}

void MainWindow::on_actionStart_triggered()
{
    if (interface_selected == -1)
    {
        QMessageBox::warning(this,"Select a interface","Please select a interface first\n");
        return ;
    }
    ui->actionStart->setEnabled(false);
    ui->actionPause->setEnabled(true);
    ui->actionStop->setEnabled(true);
    ui->actionRestart->setEnabled(true);
    ui->actionOpen->setEnabled(false);
    if(!capThread.isRunning())
        capThread.start();
    if(!anaThread.isRunning())
        anaThread.start();
    if(!packetpriThread.isRunning())
        packetpriThread.start(QThread::HighPriority);
// start these threads when trigger packet detail click
//    if(!detailpriThread.isRunning())
//        detailpriThread.start();
//    if(!rawpriThread.isRunning())
//        rawpriThread.start();
}

void MainWindow::on_actionStop_triggered()
{
    // toggle buttons state
    ui->actionStart->setEnabled(true);
    ui->actionPause->setEnabled(false);
    ui->actionStop->setEnabled(false);
    ui->actionRestart->setEnabled(true);
    ui->actionOpen->setEnabled(true);
    capThread.stop();
}

void MainWindow::on_actionRestart_triggered()
{
    // toggle buttons state
    ui->actionStart->setEnabled(false);
    ui->actionPause->setEnabled(true);
    ui->actionStop->setEnabled(true);
    ui->actionRestart->setEnabled(true);
    ui->actionOpen->setEnabled(false);
    capThread.terminate();
    offThread.terminate();
    anaThread.terminate();
    packetpriThread.terminate();
    detailpriThread.terminate();
    rawpriThread.terminate();
    // restart clear captured packets.
    Globe::capPacket.DeleteList();
    Globe::capPacket.Iniflag = false;
    DetailModel->clear();
    ui->textEdit_raw->clear();
    InitPacketModel();
    // this->UpdatePacketView();
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

    int row=index.row();
    ui->tableView_packet->selectRow(row);
    unsigned int sernum = PacketModel->index(row,0).data().toInt();
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

    if(!rawpriThread.isRunning())
        rawpriThread.start();

    if(!detailpriThread.isRunning())
        detailpriThread.start();

}

void MainWindow::on_actionOpen_triggered()
{
    // pcap_t *fp;
    // char errbuf[PCAP_ERRBUF_SIZE];
    QString filter = "All files(*.*);;Wireshark /tcpdump/...-pcap(*.dmp.gz;*.dmp;*.cap.gz;*.cap;*.pcap.gz;*.pcap);;Cinco NetXRay,Sniffer(Windows)(*.caz.gz;*.caz;*.cap.gz;*.cap)";
    file_name = QFileDialog::getOpenFileName(this, "Open a file...","",filter);
    // QMessageBox::information(this,"information","Need to be implement");
    qDebug() << "Open file: " << file_name;

    // 这个判断有问题。
    if (!file_name.isEmpty())
    {
        ui->actionStart->setEnabled(true);
        ui->actionPause->setEnabled(false);
        ui->actionStop->setEnabled(false);
        ui->actionRestart->setEnabled(false);
        // disable save function
        ui->actionSave->setEnabled(false);
        capThread.terminate();
        anaThread.terminate();
        packetpriThread.terminate();
        detailpriThread.terminate();
        offThread.terminate();
        rawpriThread.terminate();
        // restart clear captured packets.
        Globe::capPacket.DeleteList();
        DetailModel->clear();
        ui->textEdit_raw->clear();
        InitPacketModel();
    }
    else
    {
        return ;
    }
    if(!offThread.isRunning())
        offThread.start();
    if(!anaThread.isRunning())
        anaThread.start();
    if(!packetpriThread.isRunning())
        packetpriThread.start();
}

void MainWindow::on_actionSave_triggered()
{
    QFile file(file_name);
    if(!file.open(QFile::WriteOnly | QFile::Text)){
        QMessageBox::warning(this, "...", "file not open");
        // on_actionSave_as_triggered();
    }
//    QTextStream out(&file);

//    QString text = ui->textEdit->toPlainText();
//    out << text;
    QMessageBox::information(0,"Information","This function needed to be implement");

    file.flush();
    file.close();
}

void MainWindow::UpdatePacketView()
{
    packetpriThread.MuxFlag=false;
    if(PacketModel->rowCount()>0)
    {
        ui->tableView_packet->setModel(PacketModel);
        // qDebug() << "UpdatePacketView";
    }
    else
    {
        qDebug() << QString("PacketModel count: %1").arg(PacketModel->rowCount());
    }
    packetpriThread.MuxFlag=true;
}

void MainWindow::UpdateDetailView()
{
    detailpriThread.MuxFlag=false;
    ui->treeView_detail->setHeaderHidden(true);
    ui->treeView_detail->setEditTriggers(QTableView::NoEditTriggers);
    if(DetailModel->rowCount()>0)
    {
        ui->treeView_detail->setModel(DetailModel);
        qDebug() << "UpdateDetailView";
    }
    else
    {
        qDebug() << QString("DetailModel count: %1").arg(DetailModel->rowCount());
    }
    detailpriThread.MuxFlag=true;
}

void MainWindow::UpdateRawView()
{
    rawpriThread.MuxFlag = false;
    ui->textEdit_raw->setText(rawText);
    qDebug() << "UpdateRawView";
    rawpriThread.MuxFlag = true;
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
