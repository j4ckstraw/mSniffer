#include "interfacesdialog.h"
#include "ui_interfacesdialog.h"
#include <QtWidgets/QPushButton>
#include <QStandardItemModel>
#include <QList>
#include "common.h"
#include <QDebug>
#include <QModelIndex>

extern pcap_if_t *alldevs;
extern int interface_selected;

static QList<QString> devicesName;
static int ready_to_selected;


interfacesDialog::interfacesDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::interfacesDialog)
{
    ui->setupUi(this);
}

interfacesDialog::interfacesDialog() :
    ui(new Ui::interfacesDialog)
{
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    setWindowTitle("Chose Interface");

    interface_selected = 0;         //defalut is the first interface

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
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    connect(ui->buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(acceptSelect()));

}// interfacesDialog()

interfacesDialog::~interfacesDialog()
{
    delete ui;
}

void interfacesDialog::on_treeView_clicked(const QModelIndex &index)
{
    QString strText;

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
    // QModelIndex index = ui->treeView->currentIndex();
    QString s=index.data().toString();
    qDebug() << s;
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
        qDebug() << strText;
    }
     ready_to_selected=devicesName.indexOf(strText);
     qDebug() << ready_to_selected;
     qDebug() << strText;
     qDebug()<<"OVER";
     return;
}

void interfacesDialog::on_buttonBox_accepted()
{
    interface_selected = ready_to_selected;
    qDebug() << "SELECTED INTERFACE: " << interface_selected;
}
