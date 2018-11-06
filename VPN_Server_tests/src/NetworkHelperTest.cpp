#include <gtest/gtest.h>

#include "../VPN_Server/src/utils/NetworkHelper.hpp"

using namespace utils;

TEST(NetworkHelperTest, CorrectSubmask) {
    ASSERT_TRUE(NetworkHelper::isCorrectSubmask("0"));
    ASSERT_TRUE(NetworkHelper::isCorrectSubmask("5"));
    ASSERT_TRUE(NetworkHelper::isCorrectSubmask("30"));
    ASSERT_TRUE(NetworkHelper::isCorrectSubmask("32"));
    ASSERT_TRUE(NetworkHelper::isCorrectSubmask("32"));
    ASSERT_TRUE(NetworkHelper::isCorrectSubmask("16"));
}

TEST(NetworkHelperTest, IncorrectSubmask) {
    ASSERT_FALSE(NetworkHelper::isCorrectSubmask("-5"));
    ASSERT_FALSE(NetworkHelper::isCorrectSubmask("500"));
    ASSERT_FALSE(NetworkHelper::isCorrectSubmask("100"));
    ASSERT_FALSE(NetworkHelper::isCorrectSubmask("250"));
    ASSERT_FALSE(NetworkHelper::isCorrectSubmask("192.168.100.100"));
}

TEST(NetworkHelperTest, isCorrectIpv4address) {
    ASSERT_TRUE(NetworkHelper::isCorrectIp("192.168.0.0"));
    ASSERT_TRUE(NetworkHelper::isCorrectIp("192.168.255.0"));
    ASSERT_TRUE(NetworkHelper::isCorrectIp("10.0.0.0"));
    ASSERT_TRUE(NetworkHelper::isCorrectIp("11.12.13.14"));
    ASSERT_TRUE(NetworkHelper::isCorrectIp("14.13.12.11"));
    ASSERT_TRUE(NetworkHelper::isCorrectIp("200.13.12.11"));
}

TEST(NetworkHelperTest, InisCorrectIpv4address) {
    ASSERT_FALSE(NetworkHelper::isCorrectIp("1920.168.0.0"));
    ASSERT_FALSE(NetworkHelper::isCorrectIp("192.-1.255.0"));
    ASSERT_FALSE(NetworkHelper::isCorrectIp("wrongip"));
    ASSERT_FALSE(NetworkHelper::isCorrectIp(""));
    ASSERT_FALSE(NetworkHelper::isCorrectIp("14.512.12.11"));
    ASSERT_FALSE(NetworkHelper::isCorrectIp("0.13.12.257"));
}
