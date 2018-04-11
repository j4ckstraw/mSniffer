#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include "pcap.h"

class CaptureThread : public QThread
{
public:
    CaptureThread();
    void stop();

signals:
    void CaptureStopped();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // CAPTURETHREAD_H
