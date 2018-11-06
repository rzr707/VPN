TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

win32-g++ {
   QMAKE_CXXFLAGS += -Werror
}
win32-msvc*{
   QMAKE_CXXFLAGS += /WX
}

SOURCES += src/main.cpp \
    src/utils/Logger.cpp \
    src/utils/NetworkHelper.cpp \
    src/utils/ArgumentsParser.cpp \
    src/IPManager.cpp \
    src/TunnelManager.cpp \
    src/Tunnel.cpp \
    src/VPNServer.cpp

HEADERS += \
    src/utils/NetworkHelper.hpp \
    src/utils/Logger.hpp \
    src/utils/ArgumentsParser.hpp \
    src/ClientParameters.hpp \
    src/IPManager.hpp \
    src/Tunnel.hpp \
    src/TunnelManager.hpp \
    src/VPNServer.hpp

LIBS += -lpthread \
        -lwolfssl \

DISTFILES += \
    other.txt
