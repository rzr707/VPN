#ifndef VPN_SERVER_TEST_HPP
#define VPN_SERVER_TEST_HPP

#include <gtest/gtest.h>
#include <../VPN_Server/src/IPManager.hpp>

class IPManagerTest : public testing::Test {
protected:
    void SetUp() {
        mgr = new IPManager("10.0.0.0/8", 1);
    }
    void TearDown() {
        delete mgr;
    }
    IPManager* mgr;
};


#endif // VPN_SERVER_TEST_HPP
