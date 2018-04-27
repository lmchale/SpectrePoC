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

// C++ Includes:
#include <string>

// C Includes:
#include <cstdlib>
#include <cstdint>
#include <netinet/in.h>


class SocketUDP {
public:
  SocketUDP();
  ~SocketUDP();

  int open(uint16_t port);

  size_t recv(uint8_t buf[], size_t buf_size);
  size_t send(void* buf, size_t buf_size);

  int setRemote(const std::string &ipv4_str, uint16_t port);
  int setRemote(uint32_t ipv4, uint16_t port);

private:
  int sockfd_;
  sockaddr_in my_addr_;
  sockaddr_in remote_addr_;
};


#endif // UDP_SOCKET_H
