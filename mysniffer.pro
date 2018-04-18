#-------------------------------------------------
#
# Project created by QtCreator 2018-04-07T21:55:33
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
QT += network

TARGET = mysniffer
TEMPLATE = app

# where my winpacp install
INCLUDEPATH += D:/winpcap-develop-pack/WpdPack/Include
LIBS += -L D:/winpcap-develop-pack/WpdPack/Lib -lwpcap -lPacket -lws2_32

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += WPCAP
DEFINES += HAVE_REMOTE

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    packet.cpp \
    interfacesdialog.cpp \
    common.cpp \
    filter.cpp \
    capturethread.cpp \
    analysethread.cpp \
    offlineanalysethread.cpp \
    packetprintthread.cpp

HEADERS += \
        mainwindow.h \
    packet.h \
    interfacesdialog.h \
    common.h \
    filter.h \
    capturethread.h \
    analysethread.h \
    offlineanalysethread.h \
    packetprintthread.h

FORMS += \
        mainwindow.ui \
    interfacesdialog.ui

RESOURCES += \
    resource.qrc
