#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionQuit_triggered()
{
    this->close();
}

void MainWindow::on_startbutton_clicked()
{
    //StartCpature（）；
    //InactivateStart（）；
    //ActivatePause（）；
    //ActivateRestart（）；
}

void MainWindow::on_pausebutton_clicked()
{
    //PauseCapture();
    //InactivatePause(）；
    //ActivateStart();

}

void MainWindow::on_actionAbout_mSniffer_triggered()
{
    QMessageBox::about(this,"About mSniffer", "This is mini Sniffer powered by Qt!");
}
