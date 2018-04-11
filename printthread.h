#ifndef PRINTTHREAD_H
#define PRINTTHREAD_H

#include "pcap.h"
#include <QThread>

class PrintThread : public QThread
{
public:
    PrintThread();
    void stop();
    bool MuxFlag;

signals:
    void PrintStopped();
signals:
    void Modelchanged();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // PRINTTHREAD_H
