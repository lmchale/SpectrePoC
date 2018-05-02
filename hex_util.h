#ifndef HEX_UTIL_H
#define HEX_UTIL_H

/*********************************************************************
*
* Multi-process Spectre PoC
*
* Significant modifications have been made by Luke McHale to demonstrate
*  Spectre across seperate victim and attacker processes.
*
**********************************************************************/

// C++ Includes:
#include <string>

// C Includes:
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cassert>

// GNU Macros:
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)


// Forward Delcares:
std::string hexdump(const std::string& s);
std::string hexdump(const void* msg, size_t bytes);
bool printable(const std::string &s);
std::string make_printable(const std::string& s);
std::string make_printable(const void* msg, size_t bytes);
std::string hexin(const std::string& s);
size_t hamming(const std::string& lhs, const std::string& rhs);


///////////////////////////////////////////////////////////////////////////////
// Permutation lambda:
auto permute = [](std::string &s, auto n) {
  using byte = uint8_t;

  // Select new random byte to replace:
  byte b = n >> (8 * (sizeof(n)-1));  // select MSB of random word

  // Maximum message pos range is dependant on sizeof(b):
  const size_t pos = n % (s.size() - (sizeof(b)-1));
  byte* ptr = s.c_str() + pos;

  // Permutes (XOR's) a single byte within the mesage:
  *ptr ^= b;
};


// ASCII selection lambda:
auto ascii = [](std::string &s, auto n) {
  using byte = uint8_t;

  // Select new random byte to replace:
  byte b = n >> (8 * (sizeof(n)-1));  // select MSB of random word

  // Maximum message pos range is dependant on sizeof(b):
  const size_t pos = n % (s.size() - (sizeof(b)-1));
  byte* ptr = reinterpret_cast<byte*>(const_cast<char*>(s.c_str() + pos));

  // Fairly pick next ASCII char:
  byte x = b & 0x7F;  // range of 0-127 (attempt 1)
  if ( unlikely(x < 32 || x > 126) ) {
    // outside of common ASCII letters and symbols; retry with inversion:
    bool fold = (b & 0x80) == 0x80;   // true if ms-bit is set
    x = fold ? ~b : b;  // range of 0-127 (attempt 2)
  }
  if ( unlikely(x < 32 || x > 126) ) {
    // still outside of common ASCII letters and symbols; ensure with offset:
    byte shift = x + 32;
    x = (shift & 0x7F) + (shift >> 7);  // range of 0-127 (attempt 3)
  }
  assert(x >= 32 && x <= 126);
  *ptr = x;
};


#endif // HEX_UTIL_H
