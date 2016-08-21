#pragma once
#include "stdafx.h"
#include "traceConstants.h"
#include "traceStructs.h"

INS_DATA* getDisassembly(unsigned long address, int mutation, HANDLE mutex, map<unsigned long, vector<INS_DATA *>> *disas, bool fuzzy);
INS_DATA* getLastDisassembly(unsigned long address, HANDLE mutex, map<unsigned long, vector<INS_DATA *>> *disas, int *mutation);

int extract_integer(char *char_buf, string marker, int *target);

int caught_stoi(string s, int *result, int base);
int caught_stol(string s, unsigned long *result, int base);

bool obtainMutex(HANDLE mutex, char *errorLocation = 0, int waitTime = MUTEXWAITPERIOD);
void dropMutex(HANDLE mutex, char *location = 0);