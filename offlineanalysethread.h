#ifndef OFFLINEANALYSETHREAD_H
#define OFFLINEANALYSETHREAD_H

#include "pcap.h"
#include <QThread>

class OfflineAnalyseThread : public QThread
{
    Q_OBJECT

public:
    OfflineAnalyseThread();
    ~OfflineAnalyseThread();
    void stop();

signals:
    void OfflineStopped();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // OFFLINEANALYSETHREAD_H
