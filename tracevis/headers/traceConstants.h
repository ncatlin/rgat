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
Constants used to interpret and plot the trace data
*/

#pragma once
#define BBBUFSIZE 1024*1024
#define MAX_OPCODES 30

#define TAGCACHESIZE 1024*1024
#define TRACE_TAG_MARKER 'j'
#define LOOP_MARKER 'R'
#define LOOP_START_MARKER 'S'
#define LOOP_END_MARKER 'E'

#define MUTEXWAITPERIOD 6000

#define OPUNDEF 0
#define OPJMP 1
#define OPRET 2
#define OPCALL 3

#define NONFLOW 0
#define JUMP 1
#define CALL 2
#define RETURN 3
#define EXTERNAL 4
#define NOSYM 8
#define AFTERRETURN 9
#define FIRST_IN_THREAD 10

#define MOD_UNKNOWN 0 
#define MOD_INSTRUMENTED 1	//plot this
#define MOD_UNINSTRUMENTED 2 //client didn't instrument further - usually windows dlls

//can leave a conditional 2 ways, keep record of what has happened
#define CONDPENDING 1
#define CONDFELLTHROUGH 2
#define CONDTAKEN 4
#define CONDCOMPLETE 8

#define BMULT 2

#define JUMPA -6
#define JUMPB 6
#define JUMPA_CLASH -15
#define CALLB 20
#define CALLA_CLASH -40
#define CALLB_CLASH -30
#define EXTERNA -3
#define EXTERNB 3

//controls placement of the node after a return
#define RETURNA_OFFSET -4
#define RETURNB_OFFSET 3

#define ARG_NOTB64 '0'
#define ARG_BASE64 '1'

typedef pair<unsigned int, unsigned int> NODEPAIR;
typedef vector<NODEPAIR> EDGELIST;
typedef pair<int, string> ARGIDXDATA;
typedef vector<ARGIDXDATA> ARGLIST;
typedef unsigned long MEM_ADDRESS;
typedef DWORD PID_TID;

//random number generated when the block was first seen in cache
typedef unsigned long BLOCK_IDENTIFIER;