#include "stdafx.h"
#include <traceStructs.h>
#include "serialise.h"
#include "basicblock_handler.h"

#include <rapidjson\document.h>
#include <rapidjson\filewritestream.h>
#include <rapidjson\writer.h>
#include <rapidjson\filereadstream.h>
#include <rapidjson\reader.h>
#include <boost\filesystem.hpp>

using namespace rapidjson;





//void PROCESS_DATA::getDisassemblyWriteLockB() { getDisassemblyWriteLock(); };
//void PROCESS_DATA::dropDisassemblyWriteLockB() { dropDisassemblyWriteLock(); };

void PROCESS_DATA::getExternDictReadLock()
{
#ifdef XP_COMPATIBLE
	obtainMutex(externDictMutex, 6396);
#else
	AcquireSRWLockShared(&externDictRWLock);
#endif
}

void PROCESS_DATA::getExternDictWriteLock()
{
#ifdef XP_COMPATIBLE 
	obtainMutex(externDictMutex, 1002);
#else
	AcquireSRWLockExclusive(&externDictRWLock);
#endif
}

void PROCESS_DATA::dropExternDictReadLock()
{
#ifdef XP_COMPATIBLE
	dropMutex(externDictMutex);
#else
	ReleaseSRWLockShared(&externDictRWLock);
#endif
}

void PROCESS_DATA::dropExternDictWriteLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(externDictMutex);
#else
	ReleaseSRWLockExclusive(&externDictRWLock);
#endif
}

void PROCESS_DATA::getExternCallerReadLock()
{
#ifdef XP_COMPATIBLE
	obtainMutex(externCallerMutex, 6366);
#else
	AcquireSRWLockShared(&externCallerRWLock);
#endif
}

void PROCESS_DATA::getExternCallerWriteLock()
{
#ifdef XP_COMPATIBLE 
	obtainMutex(externCallerMutex, 1602);
#else
	AcquireSRWLockExclusive(&externCallerRWLock);
#endif
}

void PROCESS_DATA::dropExternCallerReadLock()
{
#ifdef XP_COMPATIBLE
	dropMutex(externCallerMutex);
#else
	ReleaseSRWLockShared(&externCallerRWLock);
#endif
}

void PROCESS_DATA::dropExternCallerWriteLock()
{
#ifdef XP_COMPATIBLE 
	dropMutex(externCallerMutex);
#else
	ReleaseSRWLockExclusive(&externCallerRWLock);
#endif
}

bool PROCESS_DATA::get_sym(unsigned int modNum, MEM_ADDRESS addr, MEM_ADDRESS &offset, string &sym)
{
	bool found;
	getDisassemblyWriteLock();
	if (modsymsPlain[modNum][addr].empty())
	{
		sym = "";
		found = false;
	}
	else
	{
		sym = modsymsPlain[modNum][addr];
		found = true;
	}
	MEM_ADDRESS base = modBounds[modNum].first;
	dropDisassemblyWriteLock();
	offset = addr - base;

	return found;
}


bool PROCESS_DATA::get_modbase(unsigned int modNum, MEM_ADDRESS &moduleBase)
{
	getDisassemblyReadLock();
	map <int, pair<MEM_ADDRESS, MEM_ADDRESS>>::iterator modBoundsIt = modBounds.find(modNum);
	dropDisassemblyReadLock();	
	
	if (modBoundsIt != modBounds.end())
	{
		moduleBase = modBoundsIt->second.first;
		return true;
	}

	return false;
}

bool PROCESS_DATA::get_modpath(unsigned int modNum, boost::filesystem::path *path)
{

	getDisassemblyReadLock();
	map<int, boost::filesystem::path>::iterator modPathIt = modpaths.find(modNum);
	dropDisassemblyReadLock();

	if (modPathIt != modpaths.end())
	{
		*path = modPathIt->second;
		return true;
	}
	
	return false;
}

bool PROCESS_DATA::get_extern_at_address(MEM_ADDRESS address, BB_DATA **BB, int attempts) {

	getExternDictReadLock();
	map<MEM_ADDRESS, BB_DATA*>::iterator externIt = externdict.find(address);
	while (externIt == externdict.end())
	{
		if (!attempts--) {
			dropExternDictReadLock();
			return false;
		}
		dropExternDictReadLock();
		Sleep(1);
		getExternDictReadLock();
		externIt = externdict.find(address);
	}

	if (BB)
		*BB = externIt->second;
	dropExternDictReadLock();
	return true;
}

bool PROCESS_DATA::is_process(PID_TID testpid, int testID)
{ 
	if (testpid != PID) return false;

	if (testID == randID || !testID)
		return true;

	return false;
}

using namespace rapidjson;

bool unpackExtern(PROCESS_DATA * piddata, const Value& externEntry)
{

	Value::ConstMemberIterator externIt = externEntry.FindMember("A");
	if (externIt == externEntry.MemberEnd())
	{
		cerr << "Error, address not found in extern entry" << endl;
		return false;
	}
	MEM_ADDRESS externAddr = externIt->value.GetUint64();

	BB_DATA *BBEntry = new BB_DATA;

	externIt = externEntry.FindMember("M");
	if (externIt == externEntry.MemberEnd())
	{
		cerr << "[rgat]Error: module ID not found in extern entry" << endl;
		delete BBEntry;
		return false;
	}
	BBEntry->modnum = externIt->value.GetUint();

	externIt = externEntry.FindMember("S");
	if (externIt == externEntry.MemberEnd())
	{
		cerr << "[rgat]Error: symbol presence not recorded in extern entry" << endl;
		delete BBEntry;
		return false;
	}
	BBEntry->hasSymbol = externIt->value.GetBool();

	externIt = externEntry.FindMember("C");
	if (externIt != externEntry.MemberEnd())
	{
		const Value& callerArray = externIt->value;
		Value::ConstValueIterator callerArrayIt = callerArray.Begin();
		for (; callerArrayIt != callerArray.End(); callerArrayIt++)
		{
			EDGELIST threadExternCalls;
			const Value& callingThreadEntry = *callerArrayIt;
			PID_TID threadID = callingThreadEntry[0].GetUint64();
			const Value& callingThreadEdges = callingThreadEntry[1];

			Value::ConstValueIterator callerEdgesIt = callingThreadEdges.Begin();
			for (; callerEdgesIt != callingThreadEdges.End(); callerEdgesIt++)
			{
				const Value& Edge = *callerEdgesIt;
				NODEINDEX source = Edge[0].GetUint64();
				NODEINDEX target = Edge[1].GetUint64();
				threadExternCalls.push_back(make_pair(source, target));
			}
			BBEntry->thread_callers[threadID] = threadExternCalls;
		}
	}

	piddata->externdict[externAddr] = BBEntry;
	return true;
}

//calls to dll functions
bool PROCESS_DATA::loadExterns(const Value& processDataJSON)
{
	Value::ConstMemberIterator procDataIt = processDataJSON.FindMember("Externs");
	if (procDataIt == processDataJSON.MemberEnd())
		return false;
	const Value& externsArray = procDataIt->value;

	stringstream externLoadMsg;
	externLoadMsg << "Loading " << externsArray.Capacity() << " externs";

	cout << "[rgat]" << externLoadMsg.str() << endl;
	//display_only_status_message(externLoadMsg.str(), clientState);

	Value::ConstValueIterator externIt = externsArray.Begin();
	for (; externIt != externsArray.End(); externIt++)
	{
		if (!unpackExtern(this, *externIt))
			return false;
	}
	return true;
}



bool PROCESS_DATA::loadModulePaths(const Value& processDataJSON)
{
	//display_only_status_message("Loading Modules", clientState);
	cout << "[rgat]Loading Module Paths" << endl;

	Value::ConstMemberIterator procDataIt = processDataJSON.FindMember("ModulePaths");
	if (procDataIt == processDataJSON.MemberEnd())
		return false;

	const Value& modPathArray = procDataIt->value;

	stringstream pathLoadMsg;
	pathLoadMsg << "Loading path of " << modPathArray.Capacity() << " modules";

	cout << "[rgat]" << pathLoadMsg.str() << endl;
	//display_only_status_message(pathLoadMsg.str(), clientState);

	Value::ConstValueIterator modPathIt = modPathArray.Begin();
	for (; modPathIt != procDataIt->value.End(); modPathIt++)
	{
		Value::ConstMemberIterator pathDataIt = modPathIt->FindMember("ID");
		if (pathDataIt == modPathIt->MemberEnd())
		{
			cout << "[rgat]ERROR: Module Paths load failed: No module ID" << endl;
			return false;
		}
		int moduleID = pathDataIt->value.GetInt();

		pathDataIt = modPathIt->FindMember("B64");
		if (pathDataIt == modPathIt->MemberEnd())
		{
			cout << "[rgat]ERROR: Module Paths load failed: No path string" << endl;
			return false;
		}

		string b64path = pathDataIt->value.GetString();
		string plainpath = base64_decode(b64path);

		modpaths.emplace(moduleID, plainpath);
	}
	return true;
}

bool unpackModuleSymbolArray(const Value& modSymArray, int moduleID, PROCESS_DATA *piddata)
{
	Value::ConstValueIterator modSymArrIt = modSymArray.Begin();
	for (; modSymArrIt != modSymArray.End(); modSymArrIt++)
	{
		const Value& symbolsArray = *modSymArrIt;
		if ((symbolsArray.Capacity() != 2) ||
			!symbolsArray[0].IsUint64() ||
			!symbolsArray[1].IsString())
		{
			cout << "[rgat]ERROR: Symbols load failed: bad symbol entry in module" << moduleID << endl;
			return false;
		}

		MEM_ADDRESS symAddress = symbolsArray[0].GetUint64();
		string symPlain = symbolsArray[1].GetString();

		piddata->modsymsPlain[moduleID][symAddress] = symPlain;
	}
	return true;
}

bool PROCESS_DATA::loadSymbols(const Value& saveJSON)
{
	Value::ConstMemberIterator symbolsIt = saveJSON.FindMember("ModuleSymbols");
	if (symbolsIt == saveJSON.MemberEnd())
		return false;

	const Value& symbolsArray = symbolsIt->value;

	stringstream symLoadMsg;
	symLoadMsg << "Loading " << symbolsArray.Capacity() << " symbols";

	cout << "[rgat]" << symLoadMsg.str() << endl;
	//display_only_status_message(symLoadMsg.str(), clientState);

	Value::ConstValueIterator modSymsIt = symbolsArray.Begin();
	for (; modSymsIt != symbolsArray.End(); modSymsIt++)
	{
		Value::ConstMemberIterator symDataIt = modSymsIt->FindMember("ModuleID");
		if (symDataIt == modSymsIt->MemberEnd())
		{
			cout << "[rgat]ERROR: Symbols load failed: No module ID" << endl;
			return false;
		}

		int moduleID = symDataIt->value.GetInt();

		symDataIt = modSymsIt->FindMember("Symbols");
		if (symDataIt == modSymsIt->MemberEnd())
		{
			cout << "[rgat]ERROR: Symbols load failed: No symbols array for module " << moduleID << endl;
			return false;
		}
		const Value& modSymArray = symDataIt->value;

		if (!unpackModuleSymbolArray(modSymArray, moduleID, this)) return false;
	}
	return true;
}

struct ADDR_DATA
{
	MEM_ADDRESS address;
	int moduleID;
	bool hasSym;
};

bool unpackOpcodes(PROCESS_DATA *piddata, const Value& opcodesData, ADDR_DATA *addressdata, INSLIST *mutationVector, csh hCapstone)
{

	Value::ConstValueIterator opcodesEntryIt = opcodesData.Begin();
	for (; opcodesEntryIt != opcodesData.End(); opcodesEntryIt++)
	{
		const Value& opcodesEntry = *opcodesEntryIt;
		if (opcodesEntry.Capacity() != 2)
		{
			cerr << "[rgat] Bad mutation entry" << endl;
			return false;
		}

		string opcodesString = opcodesEntry[0].GetString();
		if (opcodesString.empty())
			return false;


		INS_DATA *ins = new INS_DATA;
		ins->modnum = addressdata->moduleID;
		ins->hasSymbol = addressdata->hasSym;

		disassemble_ins(hCapstone, opcodesString, ins, addressdata->address);

		const Value& threadNodes = opcodesEntry[1];
		Value::ConstValueIterator threadNodesIt = threadNodes.Begin();
		for (; threadNodesIt != threadNodes.End(); threadNodesIt++)
		{
			const Value& threadNodesEntry = *threadNodesIt;
			if (threadNodesEntry.Capacity() != 2)
			{
				cerr << "[rgat] Bad thread nodes entry" << endl;
				delete ins;
				return false;
			}

			PID_TID excutingThread = threadNodesEntry[0].GetUint64();
			unsigned int GraphVertID = threadNodesEntry[1].GetInt();
			ins->threadvertIdx.emplace(excutingThread, GraphVertID);
		}

		mutationVector->push_back(ins);
	}
	return true;
}

bool unpackAddress(PROCESS_DATA *piddata, const Value& addressMutations, csh hCapstone)
{
	INSLIST mutationVector;

	if (addressMutations.Capacity() != 3)
	{
		cerr << "[rgat] Bad address entry" << endl;
		return false;
	}

	ADDR_DATA addressStruct;
	addressStruct.address = addressMutations[0].GetUint64();
	addressStruct.moduleID = addressMutations[1].GetInt();
	const Value& mutationData = addressMutations[2];


	if (piddata->modsymsPlain.count(addressStruct.moduleID) && piddata->modsymsPlain.at(addressStruct.moduleID).count(addressStruct.address))
		addressStruct.hasSym = true;
	else
		addressStruct.hasSym = false;

	if (!unpackOpcodes(piddata, mutationData, &addressStruct, &mutationVector, hCapstone))
	{
		cerr << "Failed to unpack opcodes" << endl;
		return false;
	}

	piddata->disassembly.insert(make_pair(addressStruct.address, mutationVector));
	return true;
}

bool PROCESS_DATA::loadDisassembly(const Value& saveJSON)
{
	Value::ConstMemberIterator procDataIt = saveJSON.FindMember("Disassembly");
	if (procDataIt == saveJSON.MemberEnd())
		return false;
	const Value& disassemblyArray = procDataIt->value;

	stringstream disasLoadMsg;
	disasLoadMsg << "Loading disassembly for " << disassemblyArray.Capacity() << " addresses";

	cout << "[rgat]" << disasLoadMsg.str() << endl;
	//display_only_status_message(disasLoadMsg.str(), clientState);


	//display_only_status_message("Loading Disassembly", clientState);

	csh hCapstone;
	cs_mode disasArch;
	if (bitwidth == 32)
		disasArch = CS_MODE_32;
	else if (bitwidth == 64)
		disasArch = CS_MODE_64;
	else
	{
		cerr << "[rgat]ERROR: Bad bitwidth " << bitwidth << endl;
		return false;
	}

	cs_err capOpenResult = cs_open(CS_ARCH_X86, disasArch, &hCapstone);
	if (capOpenResult != CS_ERR_OK)
	{
		cerr << "[rgat]ERROR: Failed to open Capstone instance: " << capOpenResult << endl;
		return false;
	}

	Value::ConstValueIterator disassemblyIt = disassemblyArray.Begin();
	for (; disassemblyIt != disassemblyArray.End(); disassemblyIt++)
	{
		if (!unpackAddress(this, *disassemblyIt, hCapstone))
		{
			cerr << "[rgat]Error: Failed to unpack mutations" << endl;
			cs_close(&hCapstone);
			return false;
		}
	}

	cs_close(&hCapstone);
	return true;
}

bool unpackBasicBlock(PROCESS_DATA * piddata, const Value& blockInstructions)
{
	if (blockInstructions.Capacity() != 2)
	{
		cerr << "[rgat]Error: Failed to unpack basic block instructions (bad entry)" << endl;
		return false;
	}

	MEM_ADDRESS blockaddress = blockInstructions[0].GetUint64();
	const Value& blockVariationsArray = blockInstructions[1];

	Value::ConstValueIterator blockVariationIt = blockVariationsArray.Begin();
	for (; blockVariationIt != blockVariationsArray.End(); blockVariationIt++)
	{
		const Value& blockVariation = *blockVariationIt;

		BLOCK_IDENTIFIER blockID = blockVariation[0].GetUint64();
		INSLIST *blockInsList = new INSLIST;

		piddata->blocklist[blockaddress][blockID] = blockInsList;

		const Value& blockVariationInstructions = blockVariation[1];
		Value::ConstValueIterator instructionsIt = blockVariationInstructions.Begin();
		for (; instructionsIt != blockVariationInstructions.End(); instructionsIt++)
		{
			const Value& instructionEntry = *instructionsIt;
			MEM_ADDRESS instructionAddr = instructionEntry[0].GetUint64();
			unsigned int mutationIdx = instructionEntry[1].GetUint();
			
			auto disasIt = piddata->disassembly.find(instructionAddr);
			if (disasIt == piddata->disassembly.end())
			{
				cerr << "[rgat]Warning: Could not find address " << std::hex << " in disassembly, aborting load" << endl;
				return false;//should maybe be true here to allow partial save to be used
			}
			
			if (mutationIdx >= disasIt->second.size())
			{
				cerr << "[rgat]Warning: Could not find mutation " << std::dec << " in disassembly of address "<<std::hex << instructionAddr << ", aborting load" << endl;
				return false;//should maybe be true here to allow partial save to be used
			}


			INS_DATA* disassembledIns = disasIt->second.at(mutationIdx);
			piddata->blocklist[blockaddress][blockID]->push_back(disassembledIns);
		}
	}
	return true;
}

//tie the disassembled instructions together into basic blocks
bool PROCESS_DATA::loadBasicBlocks(const Value& saveJSON)
{

	Value::ConstMemberIterator procDataIt = saveJSON.FindMember("BasicBlocks");
	if (procDataIt == saveJSON.MemberEnd())
		return false;
	const Value& basicBlockArray = procDataIt->value;

	stringstream BBLoadMsg;
	BBLoadMsg << "Loading " << basicBlockArray.Capacity() << " basic blocks";

	cout << "[rgat]" << BBLoadMsg.str() << endl;
	//display_only_status_message(BBLoadMsg.str(), clientState);


	Value::ConstValueIterator basicBlockIt = basicBlockArray.Begin();
	for (; basicBlockIt != basicBlockArray.End(); basicBlockIt++)
	{
		if (!unpackBasicBlock(this, *basicBlockIt))
			return false;
	}

	return true;
}


bool PROCESS_DATA::load(const rapidjson::Document& saveJSON, TRACERECORDPTR trace)
{
	Value::ConstMemberIterator procDataIt = saveJSON.FindMember("PID");
	if (procDataIt == saveJSON.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find process ID" << endl;
		return false;
	}
	PID = procDataIt->value.GetUint64();

	procDataIt = saveJSON.FindMember("PID_ID");
	if (procDataIt == saveJSON.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find process random ID" << endl;
		return false;
	}
	randID = procDataIt->value.GetInt();

	procDataIt = saveJSON.FindMember("ProcessData");
	if (procDataIt == saveJSON.MemberEnd())
	{
		cout << "[rgat]ERROR: Process data load failed" << endl;
		return false;
	}
	const Value& procDataJSON = procDataIt->value;

	if (!loadModulePaths(procDataJSON))
	{
		cerr << "[rgat]ERROR: Failed to load module paths" << endl;
		return false;
	}

	if (!loadSymbols(procDataJSON))
	{
		cerr << "[rgat]ERROR: Failed to load symbols" << endl;
		return false;
	}

	if (!loadDisassembly(procDataJSON))
	{
		cerr << "[rgat]ERROR: Disassembly reconstruction failed" << endl;
		return false;
	}

	if (!loadBasicBlocks(procDataJSON))
	{
		cerr << "[rgat]ERROR: Basic block reconstruction failed" << endl;
		return false;
	}

	if (!loadExterns(procDataJSON))
	{
		cerr << "[rgat]ERROR: Extern call loading failed" << endl;
		return false;
	}

	tracePtr = trace;

	return true;
}

/*
Find the disassembly for [blockaddr]
If it doesn't exist it will loop for a bit waiting for the disassembly to appear, unless [diegflag] becomes true
If the address is instrumented code, the mutation matching blockID will similarly be looked up and returned
If the address is uninstrumented code, the extern block will be retrieved and its address placed in [*externBlock]
*/
INSLIST* PROCESS_DATA::getDisassemblyBlock(MEM_ADDRESS blockaddr, BLOCK_IDENTIFIER blockID, bool *dieFlag, BB_DATA **externBlock)
{
	int iterations = 0;

	map<MEM_ADDRESS, map<BLOCK_IDENTIFIER, INSLIST *>>::iterator blockIt;
	while (true)
	{
		getDisassemblyReadLock();
		blockIt = blocklist.find(blockaddr);
		dropDisassemblyReadLock();

		if (blockIt != blocklist.end()) break;

		getExternDictReadLock();
		auto externIt = externdict.find(blockaddr);
		dropExternDictReadLock();

		if (externIt != externdict.end()) 
		{ 
			if (externBlock)
				*externBlock = externIt->second;

			return 0; 
		}

		if (iterations++ > 20)
			cerr << "[rgat]Warning: Long wait for disassembly of address 0x" << std::hex << blockaddr << endl;

		Sleep(1);
		if (*dieFlag) return 0;
	}

	INSLIST *resultPtr;
	map<BLOCK_IDENTIFIER, INSLIST *>::iterator mutationIt;

	while (true)
	{
		getDisassemblyReadLock();
		if (blockID == 0 && !blockIt->second.empty())
		{
			resultPtr = blockIt->second.begin()->second;
			dropDisassemblyReadLock();
			break;
		}

		mutationIt = blockIt->second.find(blockID);
		dropDisassemblyReadLock();

		if (mutationIt != blockIt->second.end())
		{
			resultPtr = mutationIt->second;
			break;
		}

		if (iterations++ > 20)
			cerr << "[rgat]Warning... long wait for blockID " << std::hex << blockID << "of address 0x" << blockaddr << endl;
		Sleep(1);
		if (*dieFlag) return 0;
	}

	return resultPtr;
}
