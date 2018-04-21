#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "capturethread.h"
#include "analysethread.h"
#include "packetprintthread.h"
#include "interfacesdialog.h"
#include "offlineanalysethread.h"
#include "detailprintthread.h"
#include "rawprintthread.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    // void PrintDetaildata(int);
    // void PrintRawdata();

private slots:
    void on_actionQuit_triggered();
    void on_actionAbout_mSniffer_triggered();
    void on_actionRefresh_Interfaces_triggered();
    void on_actionStart_triggered();
    void on_actionStop_triggered();
    void on_actionRestart_triggered();
    void on_actionPause_triggered();

    // void StartOrStopThread();
    void UpdatePacketView();
    void FlushDetailView();
    void UpdateRawView();
    void StopPrint();
    void StopAnalyze();

    void on_tableView_packet_clicked(const QModelIndex &index);

    void on_actionOpen_triggered();

private:
    Ui::MainWindow *ui;

    int selnum;//选中的数据包编号
    volatile bool startFlag;//开始抓包标志
    volatile bool rawdataFlag;//正在输出Rawdata标志
    InterfacesDialog *chosedialog;//选择网卡对话框
    CaptureThread capThread;//捕获数据包线程
    AnalyseThread anaThread;//分析数据包线程
    PrintThread packetpriThread;//实时打印数据包信息线程
    OfflineAnalyseThread offThread;
    DetailPrintThread detailpriThread;
    RawPrintThread rawpriThread;
    int comboindex;//选择过滤方式下拉表框
    // MyGraph *Piegraph;//输出统计饼图窗口
};

#endif // MAINWINDOW_H
