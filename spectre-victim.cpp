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
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

// C++ Includes:
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>

// Local Includes:
#include "udp-socket.h"


/********************************************************************
Victim globals.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char secret[4096];       // contiguous, nearby secret in static-globals section
std::string secret_heap; // Contiguous, secret's data exists on heap
//const char *secret = "Replace me with a run-time secret...";


/********************************************************************
Vulnerable victim function.
********************************************************************/
uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x) {
  if (x < array1_size) {
    temp ^= array2[array1[x] * 512];
  }
}


/********************************************************************
Helper/Initialization functions.
********************************************************************/
void update_secret(const std::string& s) {
  if (s.size() < sizeof(secret)) {
    // Update static-global secret:
    std::memcpy(secret, s.c_str(), sizeof(secret));
    printf("secret at VA: 0x%llX\n", (uint64_t)secret);

    int64_t malicious_x = (int64_t)(secret - (char *)array1);
    printf("- byte offset relative to array1[]: %lld\n", malicious_x);
  }

  // Update heap' secret:
  secret_heap = std::move(s); // move constructs, so only exists in one place in heap.
  printf("secret_heap at VA: 0x%llX\n", (uint64_t)secret_heap.c_str());

  int64_t malicious_x = (int64_t)(secret_heap.c_str() - (char *)array1);
  printf("- byte offset relative to array1[]: %lld\n", malicious_x);
}

void init_pages() {
  for (auto i = 0; i < sizeof(array2); i++) {
    array2[i] = 1; /* write to array2 to initialize pages */
  }
}

void print_config() {
  /* Print git commit hash */
  #ifdef GIT_COMMIT_HASH
    std::cout << "Version: commit " GIT_COMMIT_HASH "\n";
  #endif

  /* Print build configuration */
  std::cout << "Build: ";
  #ifndef NORDTSCP
    std::cout << "RDTSCP_SUPPORTED ";
  #else
    std::cout << "RDTSCP_NOT_SUPPORTED ";
  #endif
  #ifndef NOMFENCE
    std::cout << "MFENCE_SUPPORTED ";
  #else
    std::cout << "MFENCE_NOT_SUPPORTED ";
  #endif
  #ifndef NOCLFLUSH
    std::cout << "CLFLUSH_SUPPORTED ";
  #else
    std::cout << "CLFLUSH_NOT_SUPPORTED ";
  #endif
  std::cout << std::endl;
}


/********************************************************************
UDP socket functions.
********************************************************************/
void recv_worker(uint16_t port = 7777) {
  SocketUDP sock(port);
  uint8_t buf[2048];

  std::cout << "["<<port<<"] - Receive worker thread listening." << std::endl;

  for (;;) {
    auto bytes = sock.recv(buf, sizeof(buf));
    if (bytes > 0) {
      std::cout << "["<<port<<"]- Received msg of " << bytes << " bytes.\n";
    }
    else {
      std::cout << "["<<port<<"]- Something went wrong on recv()...\n";
      return;
    }
  }
}


/*
*  Command line arguments:
*  1: Cache hit threshold (int)
*  2: Malicious address start (size_t)
*  3: Malicious address count (int)
*/
int main(int argc, const char *argv[]) {
  // Initialization:
  init_pages();
  print_config();

  /* Parse the listen port from the first command line argument.
     (OPTIONAL) */
  int port = 7777;
  if (argc >= 2) {
    port = atoi(argv[1]);
    if ( !(port > 0 && port < (1<<16)-1) ) {
      std::cerr << "Overriding command line argument for port." << std::endl;
      port = 7777;
    }
//    sscanf(argv[1], "%d", &cache_hit_threshold);
  }

  // Setup receive thread to imitate server:
  std::thread t(recv_worker, port);
  {
    using namespace std::this_thread;
    using namespace std::chrono;
    sleep_for(seconds(1));
  }

  // Loop forever, allowing user to enter new secrets:
  for (;;) {
    std::string buf;
    std::cout << "Please enter secret string:" << std::endl;
    std::getline(std::cin, buf);

    if (buf.length() > 0) {
      update_secret(buf.c_str()); // buf now empty..
    }
  }

  return EXIT_SUCCESS;
}
