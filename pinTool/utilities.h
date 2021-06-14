#pragma once

#include "threadObject.h"

void printTagCache(threadObject *thread); 
void DeclareTerribleEventAndExit(std::wstring eventText);
void DeclareTerribleEventAndExit(const wchar_t *eventText);
std::string b64decode(const void* data, const size_t len);