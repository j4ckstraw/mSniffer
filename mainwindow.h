#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_actionQuit_triggered();

    void on_startbutton_clicked();

    void on_pausebutton_clicked();

    void on_actionAbout_mSniffer_triggered();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
