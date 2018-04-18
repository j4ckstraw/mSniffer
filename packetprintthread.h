#ifndef PRINTTHREAD_H
#define PRINTTHREAD_H

#include "pcap.h"
#include <QThread>

class PrintThread : public QThread
{
    Q_OBJECT
public:
    PrintThread();
    ~PrintThread();
    void stop();
    bool MuxFlag;

signals:
    void PacketPrintDone();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // PRINTTHREAD_H
