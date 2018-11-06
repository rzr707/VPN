TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    src/main.cpp \
    src/IpManagerTest.cpp \
    src/NetworkHelperTest.cpp \
    ../VPN_Server/src/VPNServer.cpp \
    ../VPN_Server/src/IPManager.cpp \
    ../VPN_Server/src/TunnelManager.cpp \
    ../VPN_Server/src/Tunnel.cpp \
    ../VPN_Server/src/utils/NetworkHelper.cpp \
    ../VPN_Server/src/utils/Logger.cpp \
    ../VPN_Server/src/utils/ArgumentsParser.cpp \
    src/ArgumentsParserTest.cpp



LIBS += -L/usr/local/lib -lgtest \
        -lpthread \
        -lwolfssl

HEADERS += \
    src/IpManagerTest.hpp \
    ../VPN_Server/src/VPNServer.hpp \
    ../VPN_Server/src/IPManager.hpp \
    ../VPN_Server/src/TunnelManager.hpp \
    ../VPN_Server/src/Tunnel.hpp \
    ../VPN_Server/src/utils/NetworkHelper.hpp \
    ../VPN_Server/src/utils/ArgumentsParser.hpp \
    ../VPN_Server/src/utils/Logger.hpp

