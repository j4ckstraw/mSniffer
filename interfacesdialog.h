#ifndef DEVICEDIALOG_H
#define DEVICEDIALOG_H

#include <QDialog>

namespace Ui {
class DeviceDialog;
}

class InterfacesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit InterfacesDialog(QWidget *parent = 0);
    ~InterfacesDialog();

private:
    Ui::DeviceDialog *ui;
};

#endif // DEVICEDIALOG_H
