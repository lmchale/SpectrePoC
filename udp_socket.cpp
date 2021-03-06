/*********************************************************************
*
* Multi-process Spectre PoC
*
* Significant modifications have been made by Luke McHale to demonstrate
*  Spectre across seperate victim and attacker processes.
*
**********************************************************************/

// C++ Includes:
#include <iostream>

// C Includes:
#include <cassert>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

// Local Includes:
#include "udp_socket.h"


SocketUDP::SocketUDP() {
  sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
  assert(sockfd_ >= 0);
}


SocketUDP::~SocketUDP() {
  close(sockfd_);
}


int SocketUDP::open(uint16_t port) {
  memset(&my_addr_, 0, sizeof(my_addr_));
  my_addr_.sin_family = AF_INET;
  my_addr_.sin_addr.s_addr = INADDR_ANY;
  my_addr_.sin_port = htons(port);

  auto status = bind(sockfd_, (sockaddr*)&my_addr_, sizeof(my_addr_));
  assert(status >= 0);
  return status;
}


size_t SocketUDP::recv(uint8_t buf[], size_t buf_size) {
  socklen_t addrLen = sizeof(remote_addr_);
  auto r = ::recvfrom(sockfd_, buf, buf_size, 0,
                      (sockaddr*)&remote_addr_, &addrLen);
  assert(addrLen <= sizeof(remote_addr_));
  return r;
}

size_t SocketUDP::send(void* buf, size_t buf_size) {
  return ::sendto(sockfd_, buf, buf_size, 0,
                  (sockaddr*)&remote_addr_, sizeof(remote_addr_));
}

int SocketUDP::setRemote(const std::string &ipv4_str, uint16_t port) {
  int status;
  in_addr ipv4;
  if ( (status = inet_aton(ipv4_str.c_str(), &ipv4)) != 0) {
    return setRemote(ntohl(ipv4.s_addr), port);
  }
  // else
  std::cerr << "Failed to setRemote to " << ipv4_str << ":" << port << std::endl;
  return status;
}

int SocketUDP::setRemote(uint32_t ipv4, uint16_t port) {
  memset(&remote_addr_, 0, sizeof(remote_addr_));
  remote_addr_.sin_family = AF_INET;
  remote_addr_.sin_addr.s_addr = htonl(ipv4);
  remote_addr_.sin_port = htons(port);
  return 0;
}
