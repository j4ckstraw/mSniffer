#ifndef INTERFACESDIALOG_H
#define INTERFACESDIALOG_H

#include <QDialog>
#include "pcap.h"

namespace Ui {
    class interfacesDialog;
}

class interfacesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit interfacesDialog(QWidget *parent);
    explicit interfacesDialog();
    ~interfacesDialog();

private slots:
    void on_buttonBox_accepted();
    void on_treeView_clicked(const QModelIndex &index);

private:
    Ui::interfacesDialog *ui;
};

#endif // INTERFACESDIALOG_H
