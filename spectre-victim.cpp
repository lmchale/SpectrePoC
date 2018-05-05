/*********************************************************************
*
* Multi-process Spectre PoC
*
* This source code is a derivative of the example code provided in the
* "Spectre Attacks: Exploiting Speculative Execution" paper found at
* https://spectreattack.com/spectre.pdf
*
* Significant modifications have been made by Luke McHale to demonstrate
*  Spectre across seperate victim and attacker processes.
*
**********************************************************************/

// C++ Includes:
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <numeric>
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
Victim globals.
********************************************************************/
constexpr size_t PAGE_SIZE = 1<<12; // Assume 4KB page size (minimim)

/* Other global (optional) parameters */
uint16_t udp_port = 7777;


/********************************************************************
Victim private globals.
********************************************************************/
size_t array1_size = 16;  // current valid range (could also be dynamic)
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];

constexpr size_t MAX_BUF_LENGTH = 1<<20;  // 1MB (for many secrets if you so desire)
// Contiguous, nearby secret in static-globals section:
char secret_global[MAX_BUF_LENGTH];
// Contiguous, secret's data exists on heap:
std::vector<char> secret_heap;
// Pointer to contiguous secret in main's stack:
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
Victim gadgets potentially leveraged by attacker.
********************************************************************/
inline void gadget_flush_condition() {
  _mm_clflush( &array1_size );

  /* Delay until flush completes */
#ifndef NOMFENCE
  _mm_mfence();
#else
  for (volatile int z = 0; z < 100; z++) {}
#endif
}


inline bool gadget_touch_va(const size_t va) {
  volatile static uint8_t tmp;

  // Fill TLB with entry correspoding to va:
  // -- side effect: pulls first cache line of page into cache.
  const uint8_t* page = reinterpret_cast<const uint8_t*>(va & ~(PAGE_SIZE-1));
  printf(" -touching page for TLB with 1 byte load at VA: %p\n", page);

  tmp ^= *page;
  return tmp == 0;  // unsued return
}


inline bool gadget_touch_page(const size_t x) {
  volatile static uint8_t tmp;

  // Calculate pointer to first byte in page:
  // - mimics array1-relative addressing for simplicity...
  const uint8_t* page = reinterpret_cast<const uint8_t*>(
        reinterpret_cast<size_t>(&array1[x]) & ~(PAGE_SIZE-1));
  printf("- touching page for TLB with 1 byte load at VA: %p\n", page);

  // Fill TLB with entry correspoding to x:
  // - side effect: pulls first cache line of page into cache
  tmp ^= *page;
  return tmp == 0;  // unsued return
}


inline bool gadget_touch_secrets(size_t i = 0) {
  volatile uint8_t tmp;

  // Fill TLB with entry correspoding to each secret:
  // -- side effect: pulls first cache line of each page into cache.
  const size_t page1 = reinterpret_cast<size_t>(&secret_heap[i])   & ~(PAGE_SIZE-1);
  const size_t page2 = reinterpret_cast<size_t>(&secret_global[i]) & ~(PAGE_SIZE-1);
  const size_t page3 = reinterpret_cast<size_t>(&secret_stack[i])  & ~(PAGE_SIZE-1);

  tmp = gadget_touch_va(page1);
  tmp &= gadget_touch_va(page2);
  tmp &= gadget_touch_va(page3);
  return tmp;
}


/********************************************************************
Helper/Initialization functions.
********************************************************************/
void update_secret(std::string& s) {
  char* cstring_copy = const_cast<char*>(s.c_str());

  // Update stack's secret:
  memcpy(secret_stack, cstring_copy, s.size());
  printf("secret_stack (%ld bytes) at VA: %p\n",
         std::min(s.size(),MAX_BUF_LENGTH) , secret_stack);
  int64_t malicious_x = (int64_t)(secret_stack - (char *)array1);
  std::cout << "- byte offset relative to array1: " << malicious_x << '\n';

  // Update global's secret:
  memcpy(secret_global, cstring_copy, s.size());
  printf("secret_global (%ld bytes) at VA: %p\n",
         std::min(s.size(),MAX_BUF_LENGTH), secret_global);
  malicious_x = (int64_t)(secret_global - (char *)array1);
  std::cout << "- byte offset relative to array1: " << malicious_x << '\n';

  // Update heap's secret:
  for (auto& c : secret_heap) {
    c = 0;  // erase old secret_heap if it exists...
  }
  secret_heap = std::vector<char>(s.size());
  memcpy(secret_heap.data(), cstring_copy, secret_heap.size());
  printf("secret_heap (%ld bytes) at VA: %p\n",
         secret_heap.size(), secret_heap.data());
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
              << SM_HANDLENAME << " with error " << errno << std::endl;
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
  printf("array1 (%ld bytes) at VA: %p\n", sizeof(array1), array1);
  printf("array1_size (%ld bytes) at VA: %p\n", sizeof(array1_size), &array1_size);
  printf("array2 (%ld bytes) at VA: %p\n", sizeof(region::array2), array2);
}


void parse_args(int argc, char* const argv[]) {
  constexpr auto DEFAULT = "These are not the droids you are looking for...";
  std::string init_secret(DEFAULT);
  std::string test_secret(256, char(0));
  std::iota(test_secret.begin(), test_secret.end(), 0);

  // Used if secret loaded from file:
  std::ifstream file;
  std::streamsize fileLength;
  std::vector<char> buffer;

  int c;
  opterr = 0;
  while ( (c = getopt(argc, argv, "hp:s:tf:")) > 0) {
    switch (c) {
    case 'h':
      std::cout << argv[0]
          << " [-p udp_port] [-f filename] [-t]"
          << std::endl;
      exit(EXIT_SUCCESS);
      break;
    case 'p': // Bind to another UDP port (uint16_t)
      udp_port = atol(optarg);
      break;
    case 's': // Initialize secret on startup
      init_secret = std::string(optarg);
      break;
    case 't': // Test secret to cover all 256 byte values
      init_secret = test_secret;
      break;
    case 'f': // File to load into secret at runtime
      file = std::ifstream(optarg, std::ios::binary|std::ios::ate);
      fileLength = file.tellg();
      file.seekg(0, std::ios::beg);
      buffer = std::vector<char>(fileLength);
      if ( file.read(buffer.data(), fileLength) ) {
        init_secret = std::string(buffer.begin(), buffer.end());
      }
      else {
        std::cerr << "Failed to open file: " << optarg << std::endl;
      }
      break;
    case '?':
      std::cerr << "Unknown argument: " << opterr << std::endl;
      exit(EXIT_FAILURE);
    default:
      std::cerr << "Unexpected argument string: " << optarg << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  // Update initialization secret with default or custom parameter:
  update_secret(init_secret);
}



/********************************************************************
UDP socket functions.
********************************************************************/
void victim_worker(uint16_t port) {
  uint8_t pkt_buf[2048];

  SocketUDP s;
  s.open(port);

  std::cout << "["<<port<<"] - Receive worker thread listening." << std::endl;

  for (;;) {
    auto bytes = s.recv(pkt_buf, sizeof(pkt_buf));
    if (bytes == sizeof(msg)) {
      msg& m = reinterpret_cast<msg&>(pkt_buf);
      auto x = m.x;
      Request fn = m.fn;

#ifdef DEBUG
      std::cout << "["<<port<<"]- Received msg of " << bytes << " bytes.\n";
#endif

      switch (fn) {
      case FN_NULL:
      case FN_PROCESS:
#ifdef DEBUG
        std::cout << "Calling helper_simple("<<x<<")" << std::endl;
#endif
        victim_function(x);
        break;
      case FN_EVICT_CONDITION:
#ifdef DEBUG
        std::cout << "Emulating gadget: flush_condition()" << std::endl;
#endif
        gadget_flush_condition();
        break;
      case FN_TOUCH_SECRET:
        std::cout << "Emulating gadget: touch_secret("<<x<<")" << std::endl;
        gadget_touch_secrets(x);
        break;
      case FN_TOUCH_PAGE:
        std::cout << "Emulating gadget: touch_page("<<x<<")" << std::endl;
        gadget_touch_page(x);
        break;
      default:
        std::cerr << "Unexpected operation requested: " << fn << std::endl;
      }

      // Echo back message:
      // - more realistically, helper would return data or condition code...
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
int main(int argc, char* const argv[]) {
  // Allocate space on stack for stack's secret:
  char secet_local[MAX_BUF_LENGTH];
  secret_stack = secet_local;  // set global pointer for helper functions

  // Initialization:
  init_pages();   // Setup shared memory for array2 (side-channel)
  print_config();
  parse_args(argc, argv);

  // Create a cpu_set_t object representing a set of CPUs
  // - Pin worker thread to same cpu as attacker (for now)
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(1, &cpuset);

  // Setup receive thread to imitate server:
  std::thread t(victim_worker, udp_port);
  int rc = pthread_setaffinity_np(t.native_handle(), sizeof(cpuset), &cpuset);
  if (rc != 0) {
    std::cerr << "Error calling pthread_setaffinity_np: " << rc << "\n";
  }

  // Simply sufficient time for threads to start before prompting user:
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Loop forever, allowing user to enter new secrets:
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
