#include "VPNServer.hpp"
#include "TunnelManager.hpp"
#include "IPManager.hpp"
#include "utils/Logger.hpp"
#include "utils/NetworkHelper.hpp"
#include "Tunnel.hpp"
#include "utils/ArgumentsParser.hpp"

#include <thread>

#include <net/if.h>
#include <linux/if_tun.h>

#include <string.h>

namespace {
    const char caCertLoc[]   = "certs/ca_cert.crt";
    const char servCertLoc[] = "certs/server-cert.pem";
    const char servKeyLoc[]  = "certs/server-key.pem";
}

using utils::NetworkHelper;

VPNServer::VPNServer(int argc, char** argv)
    : cliParams_(utils::ArgumentsParser().parse(argc, argv))
{
    const size_t IP_POOL_INIT_SIZE = 6;

    manager_.reset(new IPManager(
                                 cliParams_.virtualNetworkIp + '/' + cliParams_.networkMask,
                                 IP_POOL_INIT_SIZE
                                 )
                   );
    tunMgr_.reset(new TunnelManager);

    // Enable IP forwarding
    tunMgr_->execTerminalCommand("echo 1 > /proc/sys/net/ipv4/ip_forward");

    /* In case if program was terminated by error: */
    tunMgr_->cleanupTunnels();

    // Pick a range of private addresses and perform NAT over chosen network interface.
    std::string virtualLanAddress = cliParams_.virtualNetworkIp + '/' + cliParams_.networkMask;
    std::string physInterfaceName = cliParams_.physInterface;

    // Delete previous rule if server crashed:
    std::string delPrevPostrouting
            = "iptables -t nat -D POSTROUTING -s " + virtualLanAddress +
              " -o " + physInterfaceName + " -j MASQUERADE";
    tunMgr_->execTerminalCommand(delPrevPostrouting);

    std::string postrouting
            = "iptables -t nat -A POSTROUTING -s " + virtualLanAddress +
              " -o " + physInterfaceName + " -j MASQUERADE";
    tunMgr_->execTerminalCommand(postrouting);
    initSsl(); // initialize ssl context
}

VPNServer::~VPNServer() {
    // Clean all tunnels with prefix "vpn_"
    tunMgr_->cleanupTunnels();
    // Disable IP Forwarding:
    tunMgr_->execTerminalCommand("echo 0 > /proc/sys/net/ipv4/ip_forward");
    // Remove NAT rule from iptables:
    std::string virtualLanAddress = cliParams_.virtualNetworkIp + '/' + cliParams_.networkMask;
    std::string physInterfaceName = cliParams_.physInterface;
    std::string postrouting
            = "iptables -t nat -D POSTROUTING -s " + virtualLanAddress +
              " -o " + physInterfaceName + " -j MASQUERADE";
    tunMgr_->execTerminalCommand(postrouting);

    wolfSSL_CTX_free(ctxPtr_);
    wolfSSL_Cleanup();
}


void VPNServer::initServer() {
    mutex_.lock();
        std::cout << "\033[4;32mVPN Service is started (DTLS, ver."
                  << __DATE__
                  << ")\033[0m"
                  << std::endl;
    mutex_.unlock();

    std::thread t(&VPNServer::createNewConnection, this);
    t.detach();

    while(true) {
        std::this_thread::sleep_for(std::chrono::seconds(100));
    }
}

void VPNServer::createNewConnection() {
    mutex_.lock();
    // create ssl from sslContext:
    // run commands via unix terminal (needs sudo)
    in_addr_t serTunAddr    = manager_->getAddrFromPool();
    in_addr_t cliTunAddr    = manager_->getAddrFromPool();
    std::string serverIpStr = IPManager::ipToString(serTunAddr);
    std::string clientIpStr = IPManager::ipToString(cliTunAddr);
    size_t tunNumber        = tunMgr_->getTunNumber();
    std::string tunStr      = "vpn_tun" + std::to_string(tunNumber);
    std::string tempTunStr = tunStr;
    int interface = 0; // Tun interface
    int sentParameters = -12345;
    int e = 0;
    // allocate the buffer for a single packet.
    char packet[32767];
    int timer = 0;
    bool isClientConnected = true;
    bool idle = true;
    int length = 0;
    int sentData = 0;
    Tunnel tunnel;

    if(serTunAddr == 0 || cliTunAddr == 0) {
        utils::Logger::log("No free IP addresses. Tunnel will not be created.",
                           std::cerr);
        return;
    }

    tunMgr_->createUnixTunnel(serverIpStr,
                             clientIpStr,
                             tunStr);
    // Get TUN interface.
    interface = getInterface(tunStr.c_str());

    mutex_.unlock();

    // fill array with parameters to send:
    std::unique_ptr<ClientParameters> cliParams(buildParameters(clientIpStr));

    // wait for a tunnel.
    while ((tunnel = getTunnel(cliParams_.port.c_str())).getTunDescriptor() != -1
           &&
           tunnel.getWolfSsl() != nullptr) {

        utils::Logger::log("New client connected to [" + tunStr + "]");

        // send the parameters several times in case of packet loss.
        for (int i = 0; i < 3; ++i) {
            sentParameters =
                wolfSSL_send(tunnel.getWolfSsl(), cliParams->parametersToSend,
                             sizeof(cliParams->parametersToSend),
                             MSG_NOSIGNAL);

            if(sentParameters < 0) {
                utils::Logger::log("Error sending parameters: " +
                                std::to_string(sentParameters));
                e = wolfSSL_get_error(tunnel.getWolfSsl(), 0);
                printf("error = %d, %s\n", e, wolfSSL_ERR_reason_error_string(e));
            }
        }

        // we keep forwarding packets till something goes wrong.
        while (isClientConnected) {
            // assume that we did not make any progress in this iteration.
            idle = true;

            // read the outgoing packet from the input stream.
            length = read(interface, packet, sizeof(packet));
            if (length > 0) {
                // write the outgoing packet to the tunnel.
                sentData = wolfSSL_send(tunnel.getWolfSsl(), packet, length, MSG_NOSIGNAL);
                if(sentData < 0) {
                    utils::Logger::log("sentData < 0");
                    e = wolfSSL_get_error(tunnel.getWolfSsl(), 0);
                    printf("error = %d, %s\n", e, wolfSSL_ERR_reason_error_string(e));
                }

                // there might be more outgoing packets.
                idle = false;

                // if we were receiving, switch to sending.
                if (timer < 1)
                    timer = 1;
            }

            // read the incoming packet from the tunnel.
            length = wolfSSL_recv(tunnel.getWolfSsl(), packet, sizeof(packet), 0);
            if (length == 0) {
                utils::Logger::log(std::string() +
                                   "recv() length == " +
                                   std::to_string(length) +
                                   ". Breaking..",
                                   std::cerr);
                break;
            }
            if (length > 0) {
                // ignore control messages, which start with zero.
                if (packet[0] != 0) {
                    // write the incoming packet to the output stream.
                    sentData = write(interface, packet, length);
                    if(sentData < 0) {
                        utils::Logger::log("write(interface, packet, length) < 0");
                    }
                } else {
                    utils::Logger::log("Recieved empty control msg from client");
                    if(packet[1] == CLIENT_WANT_DISCONNECT && length == 2) {
                        utils::Logger::log("WANT_DISCONNECT from client");
                        isClientConnected = false;
                    }
                }

                // there might be more incoming packets.
                idle = false;

                // if we were sending, switch to receiving.
                if (timer > 0) {
                    timer = 0;
                }
            }

            // if we are idle or waiting for the network, sleep for a
            // fraction of time to avoid busy looping.
            if (idle) {
                std::this_thread::sleep_for(std::chrono::microseconds(100000));

                // increase the timer. This is inaccurate but good enough,
                // since everything is operated in non-blocking mode.
                timer += (timer > 0) ? 100 : -100;

                // we are receiving for a long time but not sending
                if (timer < -10000) {  // -16000
                    // send empty control messages.
                    packet[0] = 0;
                    for (int i = 0; i < 3; ++i) {
                        sentData = wolfSSL_send(tunnel.getWolfSsl(), packet, 1, MSG_NOSIGNAL);
                        if(sentData < 0) {
                            utils::Logger::log("sentData < 0");
                            e = wolfSSL_get_error(tunnel.getWolfSsl(), 0);
                            printf("error = %d, %s\n", e, wolfSSL_ERR_reason_error_string(e));
                        } else {
                            utils::Logger::log("sent empty control packet");
                        }
                    }

                    // switch to sending.
                    timer = 1;
                }

                // we are sending for a long time but not receiving.
                if (timer > TIMEOUT_LIMIT_MS) {
                    utils::Logger::log("[" + tempTunStr + "]" +
                                       "Sending for a long time but"
                                       " not receiving. Breaking...");
                    break;
                }
            }
        }
        utils::Logger::log("Client has been disconnected from tunnel [" +
                           tempTunStr + "]");

        break;
    }
    utils::Logger::log("Tunnel [" + tempTunStr + "] was closed.");
    wolfSSL_shutdown(tunnel.getWolfSsl());
    wolfSSL_free(tunnel.getWolfSsl());
    //
    manager_->returnAddrToPool(serTunAddr);
    manager_->returnAddrToPool(cliTunAddr);
    tunMgr_->closeTunNumber(tunNumber);
}

ClientParameters* VPNServer::buildParameters(const std::string& clientIp) {
    ClientParameters* cliParams = new ClientParameters;
    int size = sizeof(cliParams->parametersToSend);
    // Here is parameters string formed:
    std::string paramStr = std::string() + "m," + this->cliParams_.mtu +
            " a," + clientIp + ",32 d," + this->cliParams_.dnsIp +
            " r," + this->cliParams_.routeIp + "," + this->cliParams_.routeMask;

    // fill parameters array:
    cliParams->parametersToSend[0] = 0; // control messages always start with zero
    memcpy(&cliParams->parametersToSend[1], paramStr.c_str(), paramStr.length());
    memset(&cliParams->parametersToSend[paramStr.length() + 1], ' ', size - (paramStr.length() + 1));

    return cliParams;
}

int VPNServer::getInterface(const char *name) {
    int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

    if (int status = ioctl(interface, TUNSETIFF, &ifr)) {
        throw std::runtime_error("Cannot get TUN interface\nStatus is: " +
                                 status);
    }

    return interface;
}

Tunnel VPNServer::getTunnel(const char *port) {
    // we use an IPv6 socket to cover both IPv4 and IPv6.
    int tunnel = socket(AF_INET6, SOCK_DGRAM, 0);
    int flag = 1;
     // receive packets till the secret matches.
    char packet[1024];
    memset(packet, 0, sizeof(packet[0] * 1024));

    socklen_t addrlen;
    WOLFSSL* ssl;

    /* Create the WOLFSSL Object */
    if ((ssl = wolfSSL_new(ctxPtr_)) == NULL) {
        throw std::runtime_error("wolfSSL_new error.");
    }
    setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

    // accept packets received on any local address.
    sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(atoi(port));

    // call bind(2) in a loop since Linux does not have SO_REUSEPORT.
    while (bind(tunnel, (sockaddr *)&addr, sizeof(addr))) {
        if (errno != EADDRINUSE) {
            return Tunnel(-1, nullptr);
        }
        std::this_thread::sleep_for(std::chrono::microseconds(100000));
    }

    addrlen = sizeof(addr);
    int recievedLen = 0;
    do {
        recievedLen = 0;
        recievedLen = recvfrom(tunnel, packet, sizeof(packet), 0,
                              (sockaddr *)&addr, &addrlen);
        /*
        utils::Logger::log("packet[0] == " +
                           std::to_string(packet[0]) +
                           ", packet[1] == " +
                           std::to_string(packet[1]) +
                           ", receivecLen == " + std::to_string(recievedLen));
        */
        if(recievedLen == 2
           && packet[0] == ZERO_PACKET
           && packet[1] == CLIENT_WANT_CONNECT)
              break;

    } while (true);

    /* if client is connected then run another instance of connection
     * in a new thread: */
    std::thread thr(&VPNServer::createNewConnection, this);
    thr.detach();

    // connect to the client
    connect(tunnel, (sockaddr *)&addr, addrlen);

    // put the tunnel into non-blocking mode.
    fcntl(tunnel, F_SETFL, O_NONBLOCK);

    // set the session ssl to client connection port
    wolfSSL_set_fd(ssl, tunnel);
    wolfSSL_set_using_nonblock(ssl, 1);

    int acceptStatus = SSL_FAILURE;
    int tryCounter   = 1;

    // Try to accept ssl connection for 50 times:
    while( (acceptStatus = wolfSSL_accept(ssl)) != SSL_SUCCESS
          && tryCounter++ <= 50) {
        utils::Logger::log("wolfSSL_accept(ssl) != SSL_SUCCESS. Sleeping..");
        std::this_thread::sleep_for(std::chrono::microseconds(200000));
    }

    if(tryCounter >= 50) {
        wolfSSL_free(ssl);
        return Tunnel(-1, nullptr);
    }

    return Tunnel(tunnel, ssl);
}

void VPNServer::initSsl() {
    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Set ctx to DTLS 1.2 */
    if ((ctxPtr_ = wolfSSL_CTX_new(wolfDTLSv1_2_server_method())) == NULL) {
        throw std::runtime_error("wolfSSL_CTX_new error.");
    }
    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(ctxPtr_, caCertLoc, 0) !=
            SSL_SUCCESS)
        certError(caCertLoc);

    /* Load server certificates */
    if (wolfSSL_CTX_use_certificate_file(ctxPtr_, servCertLoc, SSL_FILETYPE_PEM) !=
                                                                 SSL_SUCCESS)
        certError(servKeyLoc);

    /* Load server Keys */
    if (wolfSSL_CTX_use_PrivateKey_file(ctxPtr_, servKeyLoc,
                SSL_FILETYPE_PEM) != SSL_SUCCESS)
        certError(servKeyLoc);

}

void VPNServer::certError(const char * filename) {
    throw std::runtime_error(std::string() +
                             "Error loading '" +
                             filename +
                             "'. Please check if the file exists");
}
