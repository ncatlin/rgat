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
Graph/Process Saving/Loading routines
*/

#pragma once
#include "stdafx.h"
#include "traceStructs.h"
#include "b64.h"
#include "GUIStructs.h"
#include "traceMisc.h"
#include "basicblock_handler.h"

#define tag_START '{'
#define tag_END '}'
#define tag_PROCESSDATA 41
#define tag_PATH 42
#define tag_SYM 43
#define tag_DISAS 44

void writetag(ofstream *file, char tag, int id = 0);
void saveProcessData(PROCESS_DATA *piddata, ofstream *file);
void saveTrace(VISSTATE * clientState);
bool verifyTag(ifstream *file, char tag, int id = 0);

int extractb64path(ifstream *file, unsigned long *modNum, string *modpath, string endTag);

int extractmodsyms(stringstream *blob, int modnum, PROCESS_DATA* piddata);
bool loadProcessData(VISSTATE *clientState, ifstream *file, PROCESS_DATA** piddataPtr, PID_TID PID);
bool loadProcessGraphs(VISSTATE *clientState, ifstream *file, PROCESS_DATA* piddata);

//save every graph in activePid
void saveAll(VISSTATE *clientState);

