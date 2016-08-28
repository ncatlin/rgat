#pragma once
#include "stdafx.h"

typedef std::pair<unsigned int, unsigned int> VERTPAIR;

//extern nodes this node calls. useful for 'call eax' situations
struct CHILDEXTERN {
	int vertid;
	CHILDEXTERN *next;
};

struct INS_DATA {
	void *bb_ptr;
	string mnemonic;
	string op_str;

	/* memory/speed tradeoff 
	1.construct every frame and save memory 
	2.construct at disassemble time and improve render speed
	*/
	string ins_text; 
	char itype;
	bool conditional = false;
	unsigned long address;
	unsigned int numbytes;
	//thread id, vert idx
	map<int, int> threadvertIdx;
	unsigned int modnum;
	//this instruction marks the joining of two BB's
	bool link_instruction = false;
	bool dataEx = false;

	//this was added later, might be worth ditching other stuff in exchange
	string opcodes;
	//for savefile reconstruction
	//string serialize_opstr;
};

struct BB_DATA {
	vector<INS_DATA *> inslist;
	int modnum;
	//list of threads that call this BB
	//inside is list of the threads verts that call it
	//it can exist multiple times on map so caller->this is listed
	//  tid      src   targ
	map <int, vector<VERTPAIR>> thread_callers;
	//this is so bad
	//   tid		caller     argidx, arg 
	map <int, map<long, vector<pair<int, string>>>> pendingcallargs;
	string symbol;
};

struct FUNCARG {
	int argno;
	char *argstr;
	FUNCARG *nextarg;
};

struct PROCESS_DATA {
	bool active = true;
	map <int, string>modpaths;
	int PID = -1;
	map <int, std::map<long, string>>modsyms;
	
	//graph data for each thread in process
	map <int, void *> graphs;
	HANDLE graphsListMutex = CreateMutex(NULL, false, NULL);
	HANDLE disassemblyMutex = CreateMutex(NULL, false, NULL);

	//maps instruction addresses to all data about it
	map <unsigned long, vector<INS_DATA *>> disassembly;

	vector <int> activeMods;
	map <long, BB_DATA *> externdict;
};