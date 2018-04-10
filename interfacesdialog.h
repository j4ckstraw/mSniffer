#ifndef INTERFACESDIALOG_H
#define INTERFACESDIALOG_H

#include <QDialog>

namespace Ui {
class interfacesDialog;
}

class interfacesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit interfacesDialog(QWidget *parent = 0);
    ~interfacesDialog();

private:
    Ui::interfacesDialog *ui;
};

#endif // INTERFACESDIALOG_H
