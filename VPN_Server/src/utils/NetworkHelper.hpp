#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>

namespace utils {
    class NetworkHelper {
    public:
        /**
         * @brief isCorrectSubmask checks netmask correctness
         * @param submaskString
         * @return true if submask is correct
         */
        static bool isCorrectSubmask(const std::string& submaskString);

        /**
         * @brief VPNServer::correctIp checks IPv4 address correctness
         * @param ipAddr
         * @return true if IPv4 address is correct
         */
        static bool isCorrectIp(const std::string& ipAddr);

        /**
         * @brief VPNServer::isNetIfaceExists checks existance of network interface
         * @param iface - system network interface name, e.g. 'eth0'
         * @return true if interface 'iface' exists
         */
        static bool isNetIfaceExists(const std::string& iface);
    };
}

#endif // !UTILS_HPP
