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
#include <algorithm>

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
inline bool printable(const char c);
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


// ASCII permutation-selection lambda:
auto permute_ascii = [](std::string &s, auto n) {
  using byte = uint8_t;

  // Select new random byte to replace:
  byte b = n >> (8 * (sizeof(n)-1));  // select MSB of random word

  // Maximum message pos range is dependant on sizeof(b):
  const size_t pos = n % (s.size() - (sizeof(b)-1));
  byte* ptr = reinterpret_cast<byte*>(const_cast<char*>(s.c_str() + pos));

  // Fairly pick next ASCII char:
  byte x = b & 0x7F;  // range of 0-127 (attempt 1)
  if ( unlikely(!printable(x)) ) {
    // outside of common ASCII letters and symbols; retry with inversion:
    bool fold = (b & 0x80) == 0x80;   // true if ms-bit is set
    x = fold ? ~b : b;  // range of 0-127 (attempt 2)
  }
  if ( unlikely(!printable(x)) ) {
    // still outside of common ASCII letters and symbols; ensure with offset:
    byte shift = x + 32;
    x = (shift & 0x7F) + (shift >> 7);  // range of 0-127 (attempt 3)
  }
  assert(printable(x));
  *ptr = x;
};


template <typename T>
T convert_to_int(std::string s) {
  std::stringstream ss;

  // If 0x, remove and treat as hex:
  if (s.substr(0,2) == "0x") {
    s.erase(0,2);
    ss << std::hex << s;
  }
  else {
    ss << s;
  }

  assert(s.size() <= 2*sizeof(T));
  T val;
  ss >> std::hex >> val;
  return val;
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


#endif // HEX_UTIL_H
