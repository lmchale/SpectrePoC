#ifndef SPECTRE_DEFINES_H
#define SPECTRE_DEFINES_H
/*********************************************************************
*
* Multi-process Spectre PoC
*
* Significant modifications have been made by Luke McHale to demonstrate
*  Spectre across seperate victim and attacker processes.
*
**********************************************************************/

// C Includes:
#include <cstdint>
#include <cstring>


enum Request {
  FN_NULL = 0,
  // 'Safely' calls vulnerable function with x:
  FN_PROCESS = 1,
  // Emulates a gadget which ultimately evicts array1_size from cache:
  FN_EVICT_CONDITION = 2,
  // Emulates a gadget which safely causes secret's page to load into TLB:
  FN_TOUCH_SECRET = 3,
  // Emulates a gadget which safely causes VA's page to load into TLB:
  FN_TOUCH_PAGE = 4
};


#pragma pack(push, 1)
struct msg {
  uint64_t x;
  Request fn;
};
#pragma pack(pop)


#pragma pack(push, 1)
struct region { /* Defines 'structure' of shared memory' */
  uint8_t array2[256 * 512];
};
#pragma pack(pop)


#endif // SPECTRE_DEFINES_H
