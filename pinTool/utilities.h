#pragma once

#include "threadObject.h"

//the pin inttypes.h doesn't work?
#ifdef __LP64__
#define PTR_prefix "%llx"
# else
#define PTR_prefix "%lx"
#endif

void printTagCache(threadObject *thread); 
void DeclareTerribleEventAndExit(std::wstring eventText);
void DeclareTerribleEventAndExit(const wchar_t *eventText);
std::string b64decode(const void* data, const size_t len);