#pragma once
#include "stdafx.h"
#include "shrike_module_handler.h"
#include "shrike_basicblock_handler.h"
#include "rgatState.h"
#include "shrike_structs.h"

void process_new_shrike_connection(rgatState *clientState, vector<SHRIKE_THREADS_STRUCT *> *threadsList, vector <char> *buf);
void shrike_process_coordinator(rgatState *clientState);
void fuzz_spawner_listener(rgatState *clientState, vector<SHRIKE_THREADS_STRUCT *> *threadsList);