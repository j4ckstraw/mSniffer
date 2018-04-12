#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "capturethread.h"
#include "analysethread.h"
#include "printthread.h"
#include "interfacesdialog.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void PrintDetaildata(int);
    void PrintRawdata();

private slots:
    void on_actionQuit_triggered();
    void on_actionAbout_mSniffer_triggered();
    void on_actionRefresh_Interfaces_triggered();
    void on_actionStart_triggered();
    void on_actionStop_triggered();
    void on_actionRestart_triggered();
    void on_actionPause_triggered();

    // void StartOrStopThread();
    void SetModel();
    void StopPrint();
    void StopAnalyze();

    void on_tableView_packet_clicked(const QModelIndex &index);

private:
    Ui::MainWindow *ui;

    int selnum;//选中的数据包编号
    volatile bool startFlag;//开始抓包标志
    volatile bool rawdataFlag;//正在输出Rawdata标志
    interfacesDialog *chosedialog;//选择网卡对话框
    CaptureThread capThread;//捕获数据包线程
    AnalyseThread anaThread;//分析数据包线程
    PrintThread priThread;//实时打印数据包信息线程
    int comboindex;//选择过滤方式下拉表框
    // MyGraph *Piegraph;//输出统计饼图窗口
};

#endif // MAINWINDOW_H
