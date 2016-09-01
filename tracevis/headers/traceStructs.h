#pragma once
#include "stdafx.h"
#include "edge_data.h"

typedef std::pair<unsigned int, unsigned int> NODEPAIR;
typedef vector<NODEPAIR> EDGELIST;
typedef pair<int, string> ARGIDXDATA;
typedef vector<ARGIDXDATA> ARGLIST;


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

/*
struct SimpleHash {
	size_t operator()(const NODEPAIR& p) const {
		return p.first ^ p.second;
	}
};
typedef unordered_map<NODEPAIR, edge_data, SimpleHash> EDGEMAP;
*/

//typedef map<NODEPAIR, edge_data> EDGEMAP;
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
	map <int, map<long, ARGLIST>> pendingcallargs;
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
	HANDLE externDictMutex = CreateMutex(NULL, false, NULL);

	//maps instruction addresses to all data about it
	map <unsigned long, INSLIST> disassembly;

	vector <int> activeMods;
	map <long, BB_DATA *> externdict;
};