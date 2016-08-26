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
int extractb64path(ifstream *file, unsigned long *id, string *modpath, string endTag);
int extractmodsyms(stringstream *blob, int modnum, PROCESS_DATA* piddata);
bool loadProcessData(VISSTATE *clientstate, ifstream *file, PROCESS_DATA* piddata);
bool loadEdgeDict(ifstream *file, thread_graph_data *graph);
bool loadEdgeList(ifstream *file, thread_graph_data *graph);
bool loadExterns(ifstream *file, thread_graph_data *graph);
bool loadNodes(ifstream *file, map<unsigned long, vector<INS_DATA*>> *insdict, thread_graph_data *graph);
bool loadStats(ifstream *file, thread_graph_data *graph);
bool loadProcessGraphs(VISSTATE *clientstate, ifstream *file, PROCESS_DATA* piddata);


