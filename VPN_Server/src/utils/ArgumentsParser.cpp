#include <stdexcept>
#include <string.h>

#include "ArgumentsParser.hpp"
#include "NetworkHelper.hpp"

using namespace utils;

namespace {
    const std::string DEFAULT_SETTINGS[] = {
        "1400",
        "10.0.0.0", "8",
        "8.8.8.8",
        "0.0.0.0", "0",
        "eth0",
        "8888" // port
    };

    const unsigned int DEFAULT_ARG_COUNT = 8;
}


void ArgumentsParser::setDefaultSettings(std::string *&in_param, size_t type) {
    if(!in_param->empty()) {
        return;
    }
    *in_param = DEFAULT_SETTINGS[type];
}

ClientParameters ArgumentsParser::parse(int argc, char** argv)
{
    ClientParameters params;

    params.port = argv[1]; // port to listen

    if (atoi(params.port.c_str()) < 1 || atoi(params.port.c_str()) > 0xFFFF) {
        throw std::invalid_argument(
                    "Error: invalid number of port " + params.port);
    }

    std::string* std_params[DEFAULT_ARG_COUNT];
    std_params[0] = &params.mtu;
    std_params[1] = &params.virtualNetworkIp;
    std_params[2] = &params.networkMask;
    std_params[3] = &params.dnsIp;
    std_params[4] = &params.routeIp;
    std_params[5] = &params.routeMask;
    std_params[6] = &params.physInterface;
    std_params[7] = &params.port;

    for (int i = 2; i < argc; ++i) {
        if (strlen(argv[i]) == 2) {
            switch (argv[i][1]) {
                case 'm':
                    if ((i + 1) < argc) {
                        params.mtu = argv[i + 1];
                    }
                    if (atoi(params.mtu.c_str()) > 2000
                       || atoi(params.mtu.c_str()) < 1000) {
                        throw std::invalid_argument("Invalid mtu");
                    }
                    break;
                case 'a':
                    if ((i + 1) < argc) {
                            params.virtualNetworkIp = argv[i + 1];
                            if(!NetworkHelper::isCorrectIp(params.virtualNetworkIp)) {
                                throw std::invalid_argument("Invalid network ip");
                            }
                    }
                    if ((i + 2) < argc) {
                        params.networkMask = argv[i + 2];
                        if(!NetworkHelper::isCorrectSubmask(params.networkMask)) {
                           throw std::invalid_argument("Invalid mask");
                        }
                    }
                    break;
                case 'd':
                    if ((i + 1) < argc) {
                        params.dnsIp = argv[i + 1];
                    }
                    if (!NetworkHelper::isCorrectIp(params.dnsIp)) {
                        throw std::invalid_argument("Invalid dns IP");
                    }
                    break;
                case 'r':
                    if ((i + 1) < argc) {
                        params.routeIp = argv[i + 1];
                    }
                    if (!NetworkHelper::isCorrectIp(params.routeIp)) {
                        throw std::invalid_argument("Invalid route IP");
                    }
                    if ((i + 2) < argc) {
                        params.routeMask = argv[i + 2];
                        if(!NetworkHelper::isCorrectSubmask(params.routeMask)) {
                            throw std::invalid_argument("Invalid route mask");
                        }
                    }
                    break;
                case 'i':
                    params.physInterface = argv[i + 1];
                    if (!NetworkHelper::isNetIfaceExists(params.physInterface)) {
                        throw std::invalid_argument("No such network interface");
                    }
                    break;
            }
        }
    }

    /* if there was no specific arguments,
     *  default settings will be set up
     */
    for (size_t i = 0; i < DEFAULT_ARG_COUNT; ++i) {
        setDefaultSettings(std_params[i], i);
    }

    return params;
}
