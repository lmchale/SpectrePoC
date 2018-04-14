#ifndef UDP_SOCKET_H
#define UDP_SOCKET_H
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

// C Includes:
#include <cstdlib>
#include <cstdint>
#include <netinet/in.h>

class SocketUDP {
public:
  SocketUDP(uint16_t port);
  size_t recv(uint8_t buf[], size_t buf_size) const;

private:
  sockaddr_in srv_addr;
  int sockfd;
};


#endif // UDP_SOCKET_H
