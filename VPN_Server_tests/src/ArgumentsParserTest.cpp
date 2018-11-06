#include <gtest/gtest.h>
#include "../VPN_Server/src/utils/ArgumentsParser.hpp"

using namespace utils;


TEST(VpnServerArguments, WrongPortException) {
    int argc = 2;
    char* argv[] = { "", "66666" };

    ASSERT_THROW(ArgumentsParser().parse(argc, argv), std::invalid_argument);
}

TEST(VpnServerPortArgument, StandartArgumentNoExceptionThrown) {
    int argc = 2;
    char* argv[] = { "", "8000" };

    ASSERT_NO_THROW(ArgumentsParser().parse(argc, argv));
}

TEST(VpnServerIpAddrArgument, InvalidIpExceptionThrown) {
    int argc = 5;
    char* argv[] = { "", "8000", "-a", "999.888.777.666", "8" };

    ASSERT_THROW(ArgumentsParser().parse(argc, argv), std::invalid_argument);
}

TEST(VpnServerIpAddrArgument, ValidIpNoExceptionThrown) {
    int argc = 5;
    char* argv[] = { "", "8000", "-a", "192.168.1.0", "8" };

    ASSERT_NO_THROW(ArgumentsParser().parse(argc, argv));
}

TEST(VpnServerIpMaskArgument, InvalidMaskExceptionThrown) {
    int argc = 5;
    char* argv[] = { "", "8000", "-a", "192.168.1.0", "333" };

    ASSERT_THROW(ArgumentsParser().parse(argc, argv), std::invalid_argument);
}

TEST(VpnServerIpMaskArgument, ValidMaskNoExceptionThrown) {
    int argc = 5;
    char* argv[] = { "", "8000", "-a", "192.168.1.0", "16" };

    ASSERT_NO_THROW(ArgumentsParser().parse(argc, argv));
}

TEST(VpnServerNetworkIfaceArgument, NoSuchIfaceException) {
    int argc = 3;
    char* argv[] = { "", "-i", "etj0" };

    ASSERT_THROW(ArgumentsParser().parse(argc, argv), std::invalid_argument);
}
