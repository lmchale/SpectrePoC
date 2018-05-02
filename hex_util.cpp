/*********************************************************************
*
* Multi-process Spectre PoC
*
* Significant modifications have been made by Luke McHale to demonstrate
*  Spectre across seperate victim and attacker processes.
*
**********************************************************************/

// C++ Includes:
#include <vector>
#include <string>
#include <bitset>
#include <iomanip>
#include <sstream>

// Local Includes:
#include "hex_util.h"

// GNU Macros:
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

using namespace std;


///////////////////////////////////////////////////////////////////////////////
string hexdump(const string& s) {
  auto buf = s.c_str();
  auto len = s.size();
  return hexdump(buf, len);
}


string hexdump(const void* msg, size_t bytes) {
  auto m = static_cast<const unsigned char*>(msg);
  stringstream ss;

  ss << std::hex << std::setfill('0');
  for (decltype(bytes) i = 0; i < bytes; i++) {
    ss << setw(2) << static_cast<unsigned int>(m[i]);
  }
  return ss.str();
}


bool printable(const string &s) {
  for (uint8_t c : s) {
    if (c < 32 || c > 126) { return false; }
  }
  return true;
}


string make_printable(const void* msg, size_t bytes) {
  return make_printable(string(static_cast<const char*>(msg), bytes));
}


string make_printable(const string& s) {
  return printable(s) ? s : string("0x")+hexdump(s);
}


string hexin(const string& s) {
  string buf(s.size()/2, 0);

  for (size_t i = 0; i < buf.size(); i++) {
    stringstream ss;
    ss << s[i*2] << s[i*2 + 1];
    uint16_t byte;
    ss >> hex >> byte;
    buf[i] = byte;
  }

  return buf;
}


size_t hamming(const string& lhs, const string& rhs) {
  using byte = bitset<8>;
  using bitArray = vector<byte>;

  assert(lhs.size() == rhs.size());

  // Calculate Hamming delta by XOR'ing each byte:
  bitArray diff;
  for (bitArray::size_type i = 0; i < lhs.size(); i++) {
    diff.push_back(lhs[i] ^ rhs[i]);
  }

  // Count each bit set in each byte:
  size_t ham = 0;
  for (const byte& b : diff) {
    ham += b.count();
  }
  return ham;
}

