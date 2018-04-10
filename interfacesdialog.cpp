#include "interfacesdialog.h"
#include "ui_interfacesdialog.h"

interfacesDialog::interfacesDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::interfacesDialog)
{
    ui->setupUi(this);
}

interfacesDialog::~interfacesDialog()
{
    delete ui;
}
