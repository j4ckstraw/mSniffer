#ifndef RAWPRINTTHREAD_H
#define RAWPRINTTHREAD_H

#include <QThread>

class RawPrintThread : public QThread
{
    Q_OBJECT

public:
    RawPrintThread();
    ~RawPrintThread();
    void stop();
    bool MuxFlag;

signals:
    void RawPrintDone();

protected:
    void run();

private:
    volatile bool stopped;
};

#endif // RAWPRINTTHREAD_H
