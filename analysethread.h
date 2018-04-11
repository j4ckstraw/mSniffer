#ifndef ANALYSETHREAD_H
#define ANALYSETHREAD_H

#include "pcap.h"
#include <QThread>

class AnalyseThread : public QThread
{
public:
    AnalyseThread();
    void stop();

signals:
    void AnalyzeStopped();

protected:
     void run();

private:
    volatile bool stopped;
};

#endif // ANALYSETHREAD_H
