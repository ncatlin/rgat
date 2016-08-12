#pragma once
#include "stdafx.h"
#include "traceConstants.h"

int extract_integer(char *char_buf, string marker, int *target);

int caught_stoi(string s, int *result, int base);
int caught_stol(string s, unsigned long *result, int base);

bool obtainMutex(HANDLE mutex, char *errorLocation, int waitTime = MUTEXWAITPERIOD);