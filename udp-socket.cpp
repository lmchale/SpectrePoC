/*********************************************************************
*
* Multi-process Spectre PoC
*
* This source code is a derivative of the example code provided in the
* "Spectre Attacks: Exploiting Speculative Execution" paper found at
* https://spectreattack.com/spectre.pdf
*
* Modifications have been made by Luke McHale to demonstrate Spectre
* across seperate victim and attacker processes.
*
**********************************************************************/
#include "udp-socket.h"

// C Includes:
#include <cassert>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>


SocketUDP::SocketUDP(uint16_t port) {
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  assert(socket >= 0);

  memset(&srv_addr, 0, sizeof(srv_addr));
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_addr.s_addr = INADDR_ANY;
  srv_addr.sin_port = htons(port);

  auto status = bind(sockfd, (sockaddr*)&srv_addr, sizeof(srv_addr));
  assert(status >= 0);
}

size_t SocketUDP::recv(uint8_t buf[], size_t buf_size) const {
  return ::recv(sockfd, buf, buf_size, 0);
}
