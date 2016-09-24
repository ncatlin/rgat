/*
Copyright 2016 Nia Catlin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Misc disassembly and conversion functions
*/
#pragma once
#include "stdafx.h"
#include "traceConstants.h"
#include "traceStructs.h"
#include "thread_graph_data.h"

INS_DATA* getDisassembly(unsigned long address, int mutation, HANDLE mutex, map<unsigned long, INSLIST> *disas, bool fuzzy);
INS_DATA* getLastDisassembly(unsigned long address, unsigned int blockid, HANDLE mutex, map<unsigned long, INSLIST> *disas, int *mutation);

int extract_integer(char *char_buf, string marker, int *target);

int caught_stoi(string s, int *result, int base);
int caught_stoi(string s, unsigned int *result, int base);
int caught_stol(string s, unsigned long *result, int base);

string generate_funcArg_string(string sym, ARGLIST args);