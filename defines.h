#ifndef SPECTRE_DEFINES_H
#define SPECTRE_DEFINES_H
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

#pragma pack(push, 1)
struct msg {
  size_t x;
};
#pragma pack(pop)


#endif // SPECTRE_DEFINES_H
