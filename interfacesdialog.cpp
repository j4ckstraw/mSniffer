#include "interfacesdialog.h"
#include "ui_devicedialog.h"

InterfacesDialog::InterfacesDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeviceDialog)
{
    ui->setupUi(this);
}

InterfacesDialog::~InterfacesDialog()
{
    delete ui;
}
