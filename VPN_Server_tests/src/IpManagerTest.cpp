#include "IpManagerTest.hpp"
#include <arpa/inet.h>

TEST_F(IPManagerTest, TestGetNetworkIpString) {
    ASSERT_EQ("10.0.0.0", mgr->getNetworkString());
    ASSERT_NE("128.0.0.0", mgr->getNetworkString());
    ASSERT_NE("0.0.0.0", mgr->getNetworkString());
    ASSERT_NE("192.168.0.0", mgr->getNetworkString());
}

TEST_F(IPManagerTest, TestGetNextIpAddress) {
    ASSERT_EQ("10.0.0.1", mgr->ipToString());
    mgr->genNextIp();
    ASSERT_EQ("10.0.0.2", mgr->ipToString());

}

TEST_F(IPManagerTest, TestNetworkCapacity) {
    ASSERT_EQ(16777215, mgr->networkCapacity());
}

TEST_F(IPManagerTest, TestIsIpInRange) {
    ASSERT_TRUE(mgr->isInRange(inet_addr("10.10.10.10")));
    ASSERT_TRUE(mgr->isInRange(inet_addr("10.11.12.13")));
    ASSERT_TRUE(mgr->isInRange(inet_addr("10.255.255.254")));
    ASSERT_TRUE(mgr->isInRange(inet_addr("10.255.255.255")));
    ASSERT_FALSE(mgr->isInRange(inet_addr("1.255.255.255")));
    ASSERT_FALSE(mgr->isInRange(inet_addr("192.168.0.1")));
}

TEST_F(IPManagerTest, TestGetMaskString) {
    ASSERT_EQ("255.0.0.0", mgr->maskString());
    ASSERT_NE("255.255.0.0", mgr->maskString());
    ASSERT_NE("255.255.255.0", mgr->maskString());
    ASSERT_NE("255.255.255.255", mgr->maskString());
    ASSERT_NE("255.148.0.0", mgr->maskString());
    ASSERT_NE("0.0.0.0", mgr->maskString());
}

TEST_F(IPManagerTest, TestGetSockaddrIn) {
    ASSERT_EQ(mgr->getSockaddrIn(), inet_addr("10.0.0.1"));
    ASSERT_NE(mgr->getSockaddrIn(), inet_addr("10.0.0.0"));
}

TEST_F(IPManagerTest, TestGetAddrFromPool) {
    ASSERT_EQ(mgr->getAddrFromPool(), inet_addr("10.0.0.1"));
    ASSERT_EQ(mgr->getAddrFromPool(), inet_addr("10.0.0.2"));

}
