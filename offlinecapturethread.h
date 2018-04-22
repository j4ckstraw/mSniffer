#ifndef OFFLINEANALYSETHREAD_H
#define OFFLINEANALYSETHREAD_H

#include "pcap.h"
#include <QThread>

class OfflineCaptureThread : public QThread
{
    Q_OBJECT

public:
    OfflineCaptureThread();
    ~OfflineCaptureThread();
    void stop();

signals:
    void OfflineStopped();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // OFFLINEANALYSETHREAD_H
