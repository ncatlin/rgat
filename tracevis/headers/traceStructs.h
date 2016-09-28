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
Structures used to represent the disassembly
*/
#pragma once
#include "stdafx.h"
#include "edge_data.h"
#include "traceConstants.h"
#include "b64.h"

/*
Pinched from Boost
http://stackoverflow.com/questions/7222143/unordered-map-hash-function-c

get_edge has shown erratic performance with map. experiment further.
*/
template <class T>
inline void hash_combine(std::size_t & seed, const T & v)
{
	std::hash<T> hasher;
	seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

namespace std
{
	template<typename S, typename T> struct hash<pair<S, T>>
	{
		inline size_t operator()(const pair<S, T> & v) const
		{
			size_t seed = 0;
			::hash_combine(seed, v.first);
			::hash_combine(seed, v.second);
			return seed;
		}
	};
}

typedef unordered_map<NODEPAIR, edge_data> EDGEMAP;

//extern nodes this node calls. useful for 'call eax' situations
struct CHILDEXTERN {
	int vertid;
	CHILDEXTERN *next;
};

struct INS_DATA {
	void *bb_ptr;
	string mnemonic;
	string op_str;
	vector<unsigned int> blockIDs;
	/* memory/speed tradeoff 
	1.construct every frame and save memory 
	2.construct at disassemble time and improve render speed
	*/
	string ins_text; 
	char itype;
	bool conditional = false;
	bool dataEx = false;
	MEM_ADDRESS address;
	unsigned int numbytes;
	MEM_ADDRESS condTakenAddress;
	MEM_ADDRESS condDropAddress;
	//thread id, vert idx
	unordered_map<int, int> threadvertIdx;
	unsigned int modnum;
	unsigned int mutationIndex;

	//this was added later, might be worth ditching other stuff in exchange
	string opcodes;
};

typedef vector<INS_DATA *> INSLIST;

struct BB_DATA {
	INSLIST inslist;
	int modnum;
	//list of threads that call this BB
	//inside is list of the threads verts that call it
	//it can exist multiple times on map so caller->this is listed
	//  tid     
	map <int, EDGELIST> thread_callers;

	//   tid	caller    
	map <int, map<MEM_ADDRESS, ARGLIST>> pendingcallargs;
	string symbol;
};

struct FUNCARG {
	int argno;
	char *argstr;
	FUNCARG *nextarg;
};

class PROCESS_DATA 
{
public:
	bool get_sym(unsigned int modNum, MEM_ADDRESS addr, string *sym) 
	{
		if (modsymsPlain[modNum][addr].empty()) 
		{
			if (modsymsb64[modNum][addr].empty())
			{
				*sym = "";
				return false;
			}
			else
			{
				*sym = base64_decode(modsymsb64[modNum][addr]);
				modsymsPlain[modNum][addr] = *sym;
				return true;
			}
		}
		*sym = modsymsPlain[modNum][addr];
		return true;
	}

//private:
	bool active = true;
	map <int, string>modpaths;
	map <int, pair<MEM_ADDRESS, MEM_ADDRESS>> modBounds;
	int PID = -1;
	map <int, std::map<MEM_ADDRESS, string>>modsymsPlain;
	map <int, std::map<MEM_ADDRESS, string>>modsymsb64;

	//graph data for each thread in process
	map <int, void *> graphs;
	HANDLE graphsListMutex = CreateMutex(NULL, false, NULL);
	HANDLE disassemblyMutex = CreateMutex(NULL, false, NULL);
	HANDLE externDictMutex = CreateMutex(NULL, false, NULL);

	//maps instruction addresses to all data about it
	map <MEM_ADDRESS, INSLIST> disassembly;

	//list of basic blocks
	//   address		    blockID			instructionlist
	map <MEM_ADDRESS, map<BLOCK_IDENTIFIER, INSLIST *>> blocklist;

	vector <int> activeMods;
	map <MEM_ADDRESS, BB_DATA *> externdict;
};

struct EXTTEXT {
	NODEPAIR edge;
	int nodeIdx;
	float timeRemaining;
	float yOffset;
	string displayString;
};

