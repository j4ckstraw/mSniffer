#ifndef PRINTTHREAD_H
#define PRINTTHREAD_H

#include "pcap.h"
#include <QThread>

class PrintThread : public QThread
{
public:
    PrintThread();
    void stop();

signals:
    void PrintStopped();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // PRINTTHREAD_H
