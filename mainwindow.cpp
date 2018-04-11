#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QStandardItemModel>
#include <QTableWidget>
#include "common.h"

QStandardItemModel *PacketModel = new QStandardItemModel();//数据包基本信息;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

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

    connect(&priThread,SIGNAL(Modelchanged()),this,SLOT(SetModel()));
    connect(&capThread,SIGNAL(CaptureStopped()),this,SLOT(StopAnalyze()));
    connect(&anaThread,SIGNAL(AnalyzeStopped()),this,SLOT(StopPrint()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionQuit_triggered()
{
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
    capThread.start();
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
    capThread.start();
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
    priThread.MuxFlag=false;//Print_online_ThreadPacketModel
    if(PacketModel->rowCount()>0)
    {
        ui->tableView_packet->setModel(PacketModel);
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
