#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include "pcap.h"
#include <QThread>

class CaptureThread : public QThread
{
    Q_OBJECT

public:
    explicit CaptureThread();
    ~CaptureThread();
    void stop();

signals:
    void CaptureStopped();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // CAPTURETHREAD_H
