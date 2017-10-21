/*
Copyright 2016-2017 Nia Catlin

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

#include <boost/filesystem.hpp>
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

typedef void * TRACERECORDPTR;



//extern nodes this node calls. useful for 'call eax' situations
struct CHILDEXTERN 
{
	NODEINDEX vertid;
	CHILDEXTERN *next;
};

struct EXTERNCALLDATA {
	NODEPAIR edgeIdx;
	ARGLIST argList;
};



struct INS_DATA 
{
	void *bb_ptr;
	string mnemonic;
	string op_str;
	//store all the basic blocks this instruction is a member of
	vector<pair<MEM_ADDRESS, BLOCK_IDENTIFIER>> blockIDs;
	/* memory/speed tradeoff 
	1.construct every frame and save memory 
	2.construct at disassemble time and improve render speed
	*/
	string ins_text; 
	eNodeType itype;
	bool conditional = false;
	bool dataEx = false;
	bool hasSymbol = false;

	MEM_ADDRESS address;
	MEM_ADDRESS branchAddress = NULL;
	MEM_ADDRESS condDropAddress;
	unordered_map<PID_TID, NODEINDEX> threadvertIdx;
	unsigned int globalmodnum;
	unsigned int mutationIndex;

	//this was added later, might be worth ditching other stuff in exchange
	uint8_t *opcodes;
	unsigned int numbytes;
};

struct TESTDATA {

};

typedef vector<INS_DATA *> INSLIST;

struct ROUTINE_STRUCT {
	INSLIST inslist;
	unsigned int globalmodnum;
	//list of threads that call this BB
	//inside is list of the threads verts that call it
	//it can exist multiple times on map so caller->this is listed
	//  tid     
	map <PID_TID, EDGELIST> thread_callers;

	bool hasSymbol = false;
	TESTDATA *testdata;
};

struct FUNCARG {
	int argno;  //index
	char *argstr; //content
};

enum eBlockType{ eBlockInternal, eBlockExernal};
struct BLOCK_DESCRIPTOR {
	eBlockType blockType;
	union {
		INSLIST * inslist;
		ROUTINE_STRUCT *externBlock;
	};
};

class PROCESS_DATA 
{
public:
	PROCESS_DATA(int binaryBitWidth) { bitwidth = binaryBitWidth;}
	~PROCESS_DATA() { };

	bool get_sym(unsigned int modNum, MEM_ADDRESS addr, string &sym);
	bool get_modpath(unsigned int modNum, boost::filesystem::path *path); 
	//bool get_modbase(unsigned int modNum, MEM_ADDRESS &moduleBase);


	bool get_extern_at_address(MEM_ADDRESS address, int moduleNum, ROUTINE_STRUCT **BB);
	void save(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
	bool load(const rapidjson::Document& saveJSON);
	INSLIST* getDisassemblyBlock(MEM_ADDRESS blockaddr, BLOCK_IDENTIFIER blockID, bool *dieFlag, ROUTINE_STRUCT **externBlock);
	int find_containing_module(MEM_ADDRESS address);

	vector<boost::filesystem::path> modpaths;
	map <boost::filesystem::path, long> globalModuleIDs;
	map <int, std::map<ADDRESS_OFFSET, string>>modsymsPlain;
	vector <pair<MEM_ADDRESS, MEM_ADDRESS> *> modBounds;

	SRWLOCK disassemblyRWLock = SRWLOCK_INIT;
	SRWLOCK externCallerRWLock = SRWLOCK_INIT;

	//https://msdn.microsoft.com/en-us/library/78t98006.aspx
	inline void getDisassemblyReadLock(){	AcquireSRWLockShared(&disassemblyRWLock);	}
	inline void dropDisassemblyReadLock()	{ReleaseSRWLockShared(&disassemblyRWLock);	}
	inline void getDisassemblyWriteLock()	{AcquireSRWLockExclusive(&disassemblyRWLock); }
	inline void dropDisassemblyWriteLock()	{ReleaseSRWLockExclusive(&disassemblyRWLock);	}

	void getExternDictReadLock();
	void getExternDictWriteLock();
	void dropExternDictReadLock();
	void dropExternDictWriteLock();
	void getExternCallerReadLock();
	void getExternCallerWriteLock();
	void dropExternCallerReadLock();
	void dropExternCallerWriteLock();

	//maps instruction addresses to all data about it
	map <ADDRESS_OFFSET, INSLIST> disassembly;

	//list of basic blocks
	//   address		    blockID			instructionlist
	map <ADDRESS_OFFSET, map<BLOCK_IDENTIFIER, INSLIST *>> addressBlockMap;
	vector <pair<ADDRESS_OFFSET, BLOCK_DESCRIPTOR *>> blockList;


	map <MEM_ADDRESS, ROUTINE_STRUCT *> externdict;
	int bitwidth;


private:
	void saveDisassembly(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
	void saveExternDict(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
	void saveBlockData(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
	void saveMetaData(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
	void saveModules(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
	void saveSymbols(rapidjson::Writer<rapidjson::FileWriteStream>& writer);

	bool loadSymbols(const rapidjson::Value& saveJSON);
	bool loadModules(const rapidjson::Value& processDataJSON);
	bool loadDisassembly(const rapidjson::Value& saveJSON);
	bool loadBasicBlocks(const rapidjson::Value& saveJSON);
	bool loadExterns(const rapidjson::Value& processDataJSON);

	bool unpackModuleSymbolArray(const rapidjson::Value& modSymArray, int globalmodNum);

private:

	SRWLOCK externDictRWLock = SRWLOCK_INIT;

	bool running = true;
	bool killed = false;
	bool dieSlowly = false;
};

struct EXTTEXT {
	unsigned int framesRemaining;
	float yOffset;
	string displayString;
};


size_t disassemble_ins(csh hCapstone, string opcodes, INS_DATA *insdata, MEM_ADDRESS insaddr);
size_t disassemble_ins(csh hCapstone, INS_DATA *insdata, MEM_ADDRESS insaddr);

