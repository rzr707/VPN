#include "NetworkHelper.hpp"

#include <net/if.h>
#include <linux/if_tun.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>

using namespace utils;

bool NetworkHelper::isCorrectSubmask(const std::string& submaskString) {
    const int SUBMASK = std::atoi(submaskString.c_str());
    return (SUBMASK >= 0) && (SUBMASK <= 32);
}

bool NetworkHelper::isCorrectIp(const std::string& ipAddr) {
    in_addr stub;
    return inet_pton(AF_INET, ipAddr.c_str(), &stub) == 1;
}

bool NetworkHelper::isNetIfaceExists(const std::string& iface) {
    ifaddrs *addrs, *tmp;

    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp) {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
            if(strcmp(iface.c_str(), tmp->ifa_name) == 0)
                return true;

        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);

    return false;
}
