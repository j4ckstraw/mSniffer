#include "interfacesdialog.h"
#include "ui_interfacesdialog.h"
#include <QtWidgets/QPushButton>
#include <QStandardItemModel>
#include <QList>
#include "common.h"
#include <QDebug>
#include <QModelIndex>
#include "filter.h"
#include <QNetworkInterface>

extern pcap_if_t *alldevs;
extern char errbuf[PCAP_ERRBUF_SIZE];
extern int interface_selected;
extern QString captureFilterString;

QList<QString> devicesName;
static int ready_to_selected;


InterfacesDialog::InterfacesDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::interfacesDialog)
{
    ui->setupUi(this);
}

InterfacesDialog::InterfacesDialog() :
    ui(new Ui::interfacesDialog)
{
    ui->setupUi(this);
    // display filter
    ui->lineEdit_filter->setText(captureFilterString);

    // disble OK button
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    setWindowTitle("Chose Interface");

    interface_selected = -1;

    QStandardItemModel *AdaperInfo = new QStandardItemModel();
    QStandardItem *rootitem = new QStandardItem("Available Adapers");
    AdaperInfo->appendRow(rootitem);
    AdaperInfo->setHeaderData(0,Qt::Horizontal,"Adapers");

    pcap_if_t *d;
    pcap_addr_t *a;
#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
    char ip6str[128];
#endif
    int adaper_count=0;
    QString strText;

//        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
//        {
//            fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
//            return 0;
//        }

    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        // return -1;
    }

    for(d=alldevs; d; d=d->next,adaper_count++)
    {
        /* Name */
        devicesName.push_back(d->name);
        strText = "name: " + QString(d->name);
        QStandardItem *adaper_item = new QStandardItem(strText);
        rootitem->appendRow(adaper_item);

        /* Description */
        if(d->description!=NULL)
        {
            strText="Description: " + QString(d->description);
        }
        else
        {
            strText="Description: null";
        }
        adaper_item->appendRow(new QStandardItem(strText));
        QStandardItem *addresses_item = new QStandardItem("Adresses");
        adaper_item->appendRow(addresses_item);

        /* Addresses */
        for(a=d->addresses;a;a=a->next)
        {
            strText = "Address Family: #" + QString::number(a->addr->sa_family);
            switch(a->addr->sa_family)
            {
            case AF_INET:
                strText +="Address Family Name: AF_INET; ";
                if (a->addr)
                {
                    strText +="Address: ";
                    strText += iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                    strText += "; ";

                }
                if (a->netmask)
                {
                    strText += "Netmask: ";
                    strText += iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
                    strText += "; ";
                }
                if (a->broadaddr)
                {
                    strText += "Broadcast Address: ";
                    strText += iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);
                    strText += "; ";
                }
                if (a->dstaddr)
                {
                    strText += "Destination Address: ";
                    strText += iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr);
                    strText += "; ";
                }
                break;
            case AF_INET6:
                strText +="Address Family Name: AF_INET6";
                strText += "; ";
#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
                if (a->addr)
                {
                    strText += "Address: ";
                    strText += ip6tos(a->addr,ip6str,sizeof(ip6str));
                    strText += "; ";
                }
#endif
                break;
            default:
                strText += "Address Family Name: Unknown";
                strText += "; ";
                break;
            }// end switch
            addresses_item->appendRow(new QStandardItem(strText));
        }// end for(a=d->addresses;a;a=a->next)
    }
    ui->treeView->setModel(AdaperInfo);
    ui->treeView->setEditTriggers(QAbstractItemView::NoEditTriggers);
}// interfacesDialog()

InterfacesDialog::~InterfacesDialog()
{
    pcap_freealldevs(alldevs);
    qDebug() << "Free all devices";
    delete ui;
}

void InterfacesDialog::on_treeView_clicked(const QModelIndex &index)
{
    QString strText;

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
    QString s=index.data().toString();
    if(s.compare("Available Adapers")==0)
    {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        return;
    }
    else
    {
        if (s=index.parent().data().toString(),s.compare("Available Adapers")==0)
            strText=index.data().toString().split(' ')[1];
        else if (s=index.parent().parent().data().toString(),s.compare("Available Adapers")==0)
            strText=index.parent().data().toString().split(' ')[1];
        else if (s=index.parent().parent().parent().data().toString(),s.compare("Available Adapers")==0)
            strText=index.parent().parent().data().toString().split(' ')[1];
        else strText=s;
    }
     ready_to_selected=devicesName.indexOf(strText);
     return;
}

void InterfacesDialog::on_buttonBox_accepted()
{
    interface_selected = ready_to_selected;
    captureFilterString = ui->lineEdit_filter->text();
    qDebug() << "Capture filter: " << captureFilterString;
    qDebug() << "SELECTED INTERFACE: " << interface_selected;
    qDebug() << "SELECTED DEVICE NAME: " << devicesName.at(interface_selected);

//    qDebug() << "See HERE";
//    foreach(QNetworkInterface interf, QNetworkInterface::allInterfaces())
//    {
//        qDebug() << "############ start ###########";
//        qDebug() << interf.humanReadableName();
//        qDebug() << interf.name();
//        qDebug() << interf.hardwareAddress();
//        qDebug() << "############# end ##############";
//    }

//    QNetworkInterface inf = QNetworkInterface::interfaceFromIndex(interface_selected);
//    qDebug() << "interface name: ",
//    qDebug() << inf.humanReadableName();

}
