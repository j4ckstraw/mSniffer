#ifndef DETAILPRINTTHREAD_H
#define DETAILPRINTTHREAD_H

#include <QThread>

class DetailPrintThread : public QThread
{
    Q_OBJECT
public:
    DetailPrintThread();
    ~DetailPrintThread();
    void stop();
    bool MuxFlag;

signals:
    void DetailPrintDone();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // DETAILPRINTTHREAD_H
