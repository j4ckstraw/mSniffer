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
    QString str;
    // pcap_if_t *d;
    QStandardItemModel *DetailModel=new QStandardItemModel();//数据包各层详细信息
    str=QString("%1%2%3").arg(("第")).arg(sernum).arg(("个数据包"));
    QStandardItem *rootitem = new QStandardItem(str);
    DetailModel->appendRow(rootitem);
    DetailModel->setHeaderData(0, Qt::Horizontal, ("数据包详细信息"));

    //QList<QStandardItem *>items;
    str=("网络帧");
    QStandardItem *item = new QStandardItem(str);
    //items.push_back(item);
    rootitem->appendRow(item);
    QList<QStandardItem *> childItems;

    str=QString("%1%2").arg(("选择网卡名称：")).arg(Globe::capPacket.PF->NAname);
    QStandardItem *ditem1 = new QStandardItem(str);
    childItems.push_back(ditem1);

    str=QString("%1%2").arg(("到达时间：")).arg(Globe::capPacket.PF->timestamp);
    QStandardItem *ditem2 = new QStandardItem(str);
    childItems.push_back(ditem2);

    str=QString("%1%2").arg(("帧长：")).arg(Globe::capPacket.PF->header.len);
    QStandardItem *ditem3 = new QStandardItem(str);
    childItems.push_back(ditem3);

    str=QString("%1").arg(("帧中协议："));
    str+="[ eth : "+Globe::capPacket.PF->Netpro+" : "+Globe::capPacket.PF->Transpro+" ]";
    QStandardItem *ditem4 = new QStandardItem(str);
    childItems.push_back(ditem4);

    item->appendRows(childItems);

    str=("链路层");
    QStandardItem *item2 = new QStandardItem(str);
    //items.push_back(item);
    rootitem->appendRow(item2);
    childItems.clear();

    str=QString("%1").arg(("目标物理地址："));
    str+=QString("%1:%2:%3:%4:%5:%6").arg(Globe::capPacket.PF->ether_header->ether_dhost.byte1,0,16).arg(Globe::capPacket.PF->ether_header->ether_dhost.byte2,0,16).arg(Globe::capPacket.PF->ether_header->ether_dhost.byte3,0,16).arg(Globe::capPacket.PF->ether_header->ether_dhost.byte4,0,16).arg(Globe::capPacket.PF->ether_header->ether_dhost.byte5,0,16).arg(Globe::capPacket.PF->ether_header->ether_dhost.byte6,0,16);
    QStandardItem *ditem5 = new QStandardItem(str);
    childItems.push_back(ditem5);

    str=QString("%1").arg(("源物理地址："));
    str+=QString("%1:%2:%3:%4:%5:%6").arg(Globe::capPacket.PF->ether_header->ether_shost.byte1,0,16).arg(Globe::capPacket.PF->ether_header->ether_shost.byte2,0,16).arg(Globe::capPacket.PF->ether_header->ether_shost.byte3,0,16).arg(Globe::capPacket.PF->ether_header->ether_shost.byte4,0,16).arg(Globe::capPacket.PF->ether_header->ether_shost.byte5,0,16).arg(Globe::capPacket.PF->ether_header->ether_shost.byte6,0,16);
    QStandardItem *ditem6 = new QStandardItem(str);
    childItems.push_back(ditem6);

    u_short k=Globe::capPacket.PF->ether_header->ether_type;
    if(k>0x0fff)
    {
        str=QString("%1%2%3)").arg(("协议：")).arg("(0x").arg(k,0,16);
    }
    else if(k>0x00ff)
    {

        str=QString("%1%2%3)").arg(("协议：")).arg("(0x0").arg(k,0,16);
    }
    else if(k>0x000f)
    {

        str=QString("%1%2%3)").arg(("协议：")).arg("(0x00").arg(k,0,16);
    }
    else
    {
        str=QString("%1%2%3)").arg(("协议：")).arg("(0x000").arg(k,0,16);
    }
    //str=QString("%1").arg(("协议："));
    str+=Globe::capPacket.PF->Netpro;
    QStandardItem *ditem7 = new QStandardItem(str);
    childItems.push_back(ditem7);
    item2->appendRows(childItems);


    if(Globe::capPacket.PF->Netpro.compare("ARP")!=0 && Globe::capPacket.PF->Netpro.compare("RARP")!=0)
    {
        str=("网络层");
        QStandardItem *item3 = new QStandardItem(str);
        //items.push_back(item);
        rootitem->appendRow(item3);
        childItems.clear();

        if(Globe::capPacket.PF->Netpro.compare("IPv4")==0)
        {
            str=QString("%1%2").arg(("版本：")).arg((int)(Globe::capPacket.PF->IPv4_header->ver_ihl & 0xf0)/16);
            QStandardItem *ditem8 = new QStandardItem(str);
            childItems.push_back(ditem8);

            str=QString("%1%2%3").arg(("报头长度：")).arg((int)(Globe::capPacket.PF->IPv4_header->ver_ihl & 0x0f)).arg(("字节"));
            QStandardItem *ditem9 = new QStandardItem(str);
            childItems.push_back(ditem9);

            str=QString("%1%2%3").arg(("服务类型：")).arg("0x").arg(Globe::capPacket.PF->IPv4_header->tos,0,16);
            QStandardItem *ditem10 = new QStandardItem(str);
            childItems.push_back(ditem10);

            k=ntohs(Globe::capPacket.PF->IPv4_header->tlen);
            str=QString("%1%2").arg(("总长：")).arg(k);
            QStandardItem *ditem11 = new QStandardItem(str);
            childItems.push_back(ditem11);

            k=ntohs(Globe::capPacket.PF->IPv4_header->identification);
            str=QString("%1%2").arg(("标识：")).arg(k);
            QStandardItem *ditem12 = new QStandardItem(str);
            childItems.push_back(ditem12);

            str=QString("%1%2%3").arg(("标志位：")).arg("0x").arg((Globe::capPacket.PF->IPv4_header->flags_fo & 0xe000)/4096,0,16);
            QStandardItem *ditem13 = new QStandardItem(str);
            childItems.push_back(ditem13);

            str=QString("%1%2").arg(("偏移量：")).arg((int)Globe::capPacket.PF->IPv4_header->flags_fo & 0x1fff);
            QStandardItem *ditem14 = new QStandardItem(str);
            childItems.push_back(ditem14);

            str=QString("%1%2").arg(("存活时间：")).arg((int)Globe::capPacket.PF->IPv4_header->ttl);
            QStandardItem *ditem15 = new QStandardItem(str);
            childItems.push_back(ditem15);

            str=QString("%1%2(%3)").arg(("协议：")).arg(Globe::capPacket.PF->Transpro).arg((int)Globe::capPacket.PF->IPv4_header->proto);
            QStandardItem *ditem16 = new QStandardItem(str);
            childItems.push_back(ditem16);

            k=ntohs(Globe::capPacket.PF->IPv4_header->crc);
            str=QString("%1%2%3").arg(("首部校验和：")).arg("0x").arg(k,0,16);
            QStandardItem *ditem17 = new QStandardItem(str);
            childItems.push_back(ditem17);

            str=QString("%1%2.%3.%4.%5").arg(("源地址：")).arg(Globe::capPacket.PF->IPv4_header->saddr.byte1).arg(Globe::capPacket.PF->IPv4_header->saddr.byte2).arg(Globe::capPacket.PF->IPv4_header->saddr.byte3).arg(Globe::capPacket.PF->IPv4_header->saddr.byte4);//源IP地址
            QStandardItem *ditem18 = new QStandardItem(str);
            childItems.push_back(ditem18);

            str=QString("%1%2.%3.%4.%5").arg(("目的地址：")).arg(Globe::capPacket.PF->IPv4_header->daddr.byte1).arg(Globe::capPacket.PF->IPv4_header->daddr.byte2).arg(Globe::capPacket.PF->IPv4_header->daddr.byte3).arg(Globe::capPacket.PF->IPv4_header->daddr.byte4);//目的IP地址
            QStandardItem *ditem19 = new QStandardItem(str);
            childItems.push_back(ditem19);

            str=QString("%1%2%3").arg(("选项与填充：")).arg("0x").arg(Globe::capPacket.PF->IPv4_header->op_pad,0,16);
            QStandardItem *ditem20 = new QStandardItem(str);
            childItems.push_back(ditem20);
        }
        else if(Globe::capPacket.PF->Netpro.compare("IPv6")==0)
        {
            str=QString("%1%2").arg(("版本：")).arg((int)(Globe::capPacket.PF->IPv6_header->ver_ihl & 0xf0000000)/268435456);
            QStandardItem *ditem8 = new QStandardItem(str);
            childItems.push_back(ditem8);

            str=QString("%1%2").arg(("优先级：")).arg((int)(Globe::capPacket.PF->IPv6_header->ver_ihl & 0x0ff00000)/65536);
            QStandardItem *ditem9 = new QStandardItem(str);
            childItems.push_back(ditem9);

            k=ntohs(Globe::capPacket.PF->IPv6_header->load_length);
            str=QString("%1%2").arg(("有效负荷长度：")).arg(k);
            QStandardItem *ditem10 = new QStandardItem(str);
            childItems.push_back(ditem10);

            str=QString("%1%2(%3)").arg(("下一报头：")).arg(Globe::capPacket.PF->Transpro).arg((int)Globe::capPacket.PF->IPv6_header->next_header);
            QStandardItem *ditem11 = new QStandardItem(str);
            childItems.push_back(ditem11);

            str=QString("%1%2").arg(("跳转限制：")).arg((int)Globe::capPacket.PF->IPv6_header->jump_limit);
            QStandardItem *ditem12 = new QStandardItem(str);
            childItems.push_back(ditem12);

            str=QString(("源地址："));
            str+=QString("%1.%2.%3.%4.%5.%6.%7.%8.%9.%10.%11.%12.%13.%14.%15.%16").arg(Globe::capPacket.PF->IPv6_header->source_ip.byte1).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte2).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte3).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte4).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte5).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte6).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte7).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte8).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte9).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte10).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte11).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte12).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte13).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte14).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte15).arg(Globe::capPacket.PF->IPv6_header->source_ip.byte16);
            QStandardItem *ditem13 = new QStandardItem(str);
            childItems.push_back(ditem13);

            str=QString(("目的地址："));
            str+=QString("%1.%2.%3.%4.%5.%6.%7.%8.%9.%10.%11.%12.%13.%14.%15.%16").arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte1).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte2).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte3).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte4).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte5).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte6).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte7).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte8).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte9).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte10).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte11).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte12).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte13).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte14).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte15).arg(Globe::capPacket.PF->IPv6_header->dest_ip.byte16);
            QStandardItem *ditem14 = new QStandardItem(str);
            childItems.push_back(ditem14);
        }
        if(!childItems.empty())
        {
            item3->appendRows(childItems);
        }
    }
    else
    {

        str=Globe::capPacket.PF->Netpro+("协议");
        QStandardItem *item3 = new QStandardItem(str);
        rootitem->appendRow(item3);
        childItems.clear();

        k=ntohs(Globe::capPacket.PF->ARP_header->hardware_type);
        if(k==1)
        {
            str=QString("%1").arg(("硬件类型：以太网(1)"));
        }
        else
        {
            str=QString("%1(%2)").arg(("硬件类型：未知")).arg(k);
        }
        QStandardItem *ditem4 = new QStandardItem(str);
        childItems.push_back(ditem4);

        k=ntohs(Globe::capPacket.PF->ARP_header->protocal_type);
        if(k==0x0800)
        {
            str=QString("%1").arg(("协议类型：IP(0x0800)"));
        }
        else
        {
            str=QString("%1(%2%3)").arg(("协议类型：未知")).arg("0x").arg(k,0,16);
        }
        QStandardItem *ditem5 = new QStandardItem(str);
        childItems.push_back(ditem5);

        str=QString("%1%2").arg(("硬件地址长度：")).arg((int)Globe::capPacket.PF->ARP_header->hwadd_len);
        QStandardItem *ditem6 = new QStandardItem(str);
        childItems.push_back(ditem6);

        str=QString("%1%2").arg(("协议地址长度：")).arg((int)Globe::capPacket.PF->ARP_header->proadd_len);
        QStandardItem *ditem7 = new QStandardItem(str);
        childItems.push_back(ditem7);

        k=ntohs(Globe::capPacket.PF->ARP_header->option);
        if(k==0x0001 || k==0x0003)
        {
            str=QString("%1").arg(("操作类型：请求(1)"));
        }
        else
        {
            str=QString("%1").arg(("操作类型：应答(2)"));
        }
        QStandardItem *ditem8 = new QStandardItem(str);
        childItems.push_back(ditem8);

        str=QString("%1 %2：%3：%4：%5：%6：%7").arg(("发送端物理地址:")).arg(Globe::capPacket.PF->ARP_header->snether_address.byte1,0,16).arg(Globe::capPacket.PF->ARP_header->snether_address.byte2,0,16).arg(Globe::capPacket.PF->ARP_header->snether_address.byte3,0,16).arg(Globe::capPacket.PF->ARP_header->snether_address.byte4,0,16).arg(Globe::capPacket.PF->ARP_header->snether_address.byte5,0,16).arg(Globe::capPacket.PF->ARP_header->snether_address.byte6,0,16);//报要2
        QStandardItem *ditem11 = new QStandardItem(str);
        childItems.push_back(ditem11);

        str=QString("%1%2.%3.%4.%5").arg(("发送端IP地址：")).arg(Globe::capPacket.PF->ARP_header->sip_address.byte1).arg(Globe::capPacket.PF->ARP_header->sip_address.byte2).arg(Globe::capPacket.PF->ARP_header->sip_address.byte3).arg(Globe::capPacket.PF->ARP_header->sip_address.byte4);
        QStandardItem *ditem10 = new QStandardItem(str);
        childItems.push_back(ditem10);

        str=QString("%1 %2：%3：%4：%5：%6：%7").arg(("目的物理地址:")).arg(Globe::capPacket.PF->ARP_header->dnether_address.byte1,0,16).arg(Globe::capPacket.PF->ARP_header->dnether_address.byte2,0,16).arg(Globe::capPacket.PF->ARP_header->dnether_address.byte3,0,16).arg(Globe::capPacket.PF->ARP_header->dnether_address.byte4,0,16).arg(Globe::capPacket.PF->ARP_header->dnether_address.byte5,0,16).arg(Globe::capPacket.PF->ARP_header->dnether_address.byte6,0,16);//报要2
        QStandardItem *ditem13 = new QStandardItem(str);
        childItems.push_back(ditem13);

        str=QString("%1%2.%3.%4.%5").arg(("目的IP地址：")).arg(Globe::capPacket.PF->ARP_header->dip_address.byte1).arg(Globe::capPacket.PF->ARP_header->dip_address.byte2).arg(Globe::capPacket.PF->ARP_header->dip_address.byte3).arg(Globe::capPacket.PF->ARP_header->dip_address.byte4);
        QStandardItem *ditem12 = new QStandardItem(str);
        childItems.push_back(ditem12);

        if(!childItems.empty())
        {
            item3->appendRows(childItems);
        }
    }

    if(Globe::capPacket.PF->Transpro.compare("UDP")==0)
    {
        str=("传输层(UDP)");
    }
    else if(Globe::capPacket.PF->Transpro.compare("TCP")==0)
    {
        str=("传输层(TCP)");
    }
    else if(Globe::capPacket.PF->Transpro.compare("ICMP")==0)
    {
        str=("传输层(ICMP)");
    }
    else
    {
        str=("传输层");
    }
    QStandardItem *item4 = new QStandardItem(str);
    rootitem->appendRow(item4);
    childItems.clear();

    if(Globe::capPacket.PF->Transpro.compare("UDP")==0)
    {
        k=ntohs(Globe::capPacket.PF->UDP_header->sport);
        str=QString("%1%2").arg(("源端口：")).arg(k);//源端口
        QStandardItem *ditem21 = new QStandardItem(str);
        childItems.push_back(ditem21);

        k=ntohs(Globe::capPacket.PF->UDP_header->dport);
        str=QString("%1%2").arg(("目的端口：")).arg(k);//目的端口
        QStandardItem *ditem22 = new QStandardItem(str);
        childItems.push_back(ditem22);

        k=ntohs(Globe::capPacket.PF->UDP_header->len);
        str=QString("%1%2").arg(("长度：")).arg(k);
        QStandardItem *ditem23 = new QStandardItem(str);
        childItems.push_back(ditem23);

        k=ntohs(Globe::capPacket.PF->UDP_header->crc);
        str=QString("%1%2").arg(("校验和：")).arg(k);
        QStandardItem *ditem24 = new QStandardItem(str);
        childItems.push_back(ditem24);
    }
    else if(Globe::capPacket.PF->Transpro.compare("TCP")==0)
    {
        k=ntohs(Globe::capPacket.PF->TCP_header->sport);
        str=QString("%1%2").arg(("源端口：")).arg(k);//源端口
        QStandardItem *ditem21 = new QStandardItem(str);
        childItems.push_back(ditem21);

        k=ntohs(Globe::capPacket.PF->TCP_header->dport);
        str=QString("%1%2").arg(("目的端口：")).arg(k);//目的端口
        QStandardItem *ditem22 = new QStandardItem(str);
        childItems.push_back(ditem22);

        u_long t=ntohl(Globe::capPacket.PF->TCP_header->seq);
        str=QString("%1%2").arg(("顺序号：")).arg(t);//顺序号
        QStandardItem *ditem23 = new QStandardItem(str);
        childItems.push_back(ditem23);

        t=ntohl(Globe::capPacket.PF->TCP_header->ack);
        str=QString("%1%2").arg(("确认号：")).arg(t);//确认号
        QStandardItem *ditem24 = new QStandardItem(str);
        childItems.push_back(ditem24);

        str=QString("TCP%1%2").arg(("头长：")).arg((int)(Globe::capPacket.PF->TCP_header->tcp_res & 0xf000)/4096);
        str+=QString("  %1%2").arg(("保留位：")).arg((int)(Globe::capPacket.PF->TCP_header->tcp_res & 0x0fc0)/64);
        str+=QString("  URG(%1),ACK(%2),PSH(%3),RST(%4),SYN(%5),FIN(%6)").arg((int)(Globe::capPacket.PF->TCP_header->tcp_res & 0x0020)/32).arg((int)(Globe::capPacket.PF->TCP_header->tcp_res & 0x0010)/16).arg((int)(Globe::capPacket.PF->TCP_header->tcp_res & 0x0008)/8).arg((int)(Globe::capPacket.PF->TCP_header->tcp_res & 0x0004)/4).arg((int)(Globe::capPacket.PF->TCP_header->tcp_res & 0x0002)/2).arg((int)(Globe::capPacket.PF->TCP_header->tcp_res & 0x0001));
        QStandardItem *ditem25 = new QStandardItem(str);
        childItems.push_back(ditem25);

        k=ntohs(Globe::capPacket.PF->TCP_header->windsize);
        str=QString("%1%2").arg(("窗口大小：")).arg(k);
        QStandardItem *ditem26 = new QStandardItem(str);
        childItems.push_back(ditem26);

        k=ntohs(Globe::capPacket.PF->TCP_header->crc);
        str=QString("%1%2").arg(("校验和：")).arg(k);
        QStandardItem *ditem27 = new QStandardItem(str);
        childItems.push_back(ditem27);

        //k=ntohs();
        str=QString("%1%2%3").arg(("紧急指针：")).arg("0x").arg(Globe::capPacket.PF->TCP_header->urgp,0,16);
        QStandardItem *ditem28 = new QStandardItem(str);
        childItems.push_back(ditem28);

    }
    else if(Globe::capPacket.PF->Transpro.compare("ICMP")==0)
    {
        str=QString("%1%2").arg(("类型：")).arg((int)Globe::capPacket.PF->ICMP_header->type);
        QStandardItem *ditem21 = new QStandardItem(str);
        childItems.push_back(ditem21);

        str=QString("%1%2").arg(("代码：")).arg((int)Globe::capPacket.PF->ICMP_header->code);
        QStandardItem *ditem22 = new QStandardItem(str);
        childItems.push_back(ditem22);

        k=ntohs(Globe::capPacket.PF->ICMP_header->ckc);
        str=QString("%1%2").arg(("校验和：")).arg(k);
        QStandardItem *ditem23 = new QStandardItem(str);
        childItems.push_back(ditem23);

        k=ntohs(Globe::capPacket.PF->ICMP_header->id);
        str=QString("%1%2").arg(("识别号：")).arg(k);
        QStandardItem *ditem24 = new QStandardItem(str);
        childItems.push_back(ditem24);

        k=ntohs(Globe::capPacket.PF->ICMP_header->seq);
        str=QString("%1%2").arg(("报文序列号：")).arg(k);
        QStandardItem *ditem25 = new QStandardItem(str);
        childItems.push_back(ditem25);

        k=ntohs(Globe::capPacket.PF->ICMP_header->timestamp);
        str=QString("%1%2").arg(("时戳：")).arg(k);
        QStandardItem *ditem26 = new QStandardItem(str);
        childItems.push_back(ditem26);
    }

    if(!childItems.empty())
    {
        item4->appendRows(childItems);
    }
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
