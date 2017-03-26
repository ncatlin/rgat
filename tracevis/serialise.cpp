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
#include "stdafx.h"
#include "serialise.h"
#include "OSspecific.h"
#include "GUIManagement.h"
#include "cylinder_graph.h"

using namespace rapidjson;

#define tag_START '{'
#define tag_END '}'
#define tag_PROCESSDATA 41
#define tag_PATH 42
#define tag_SYM 43
#define tag_DISAS 44
#define tag_EXTERND 45


void saveModulePaths(PROCESS_DATA *piddata, Writer<rapidjson::FileWriteStream>& writer)
{
	writer.Key("ModulePaths");
	writer.StartArray();

	map <int, string>::iterator pathIt = piddata->modpaths.begin();
	for (; pathIt != piddata->modpaths.end(); pathIt++)
	{
		const unsigned char* cus_pathstring = reinterpret_cast<const unsigned char*>(pathIt->second.c_str());
		writer.StartObject();
		writer.Key("ID");
		writer.Int(pathIt->first);
		writer.Key("B64");
		writer.String(base64_encode(cus_pathstring, pathIt->second.size()).c_str());
		writer.EndObject();
	}

	writer.EndArray();
}

//big, but worth doing in case environments differ
void saveModuleSymbols(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("ModuleSymbols");
	writer.StartArray();

	map <int, std::map<MEM_ADDRESS, string>>::iterator modSymIt = piddata->modsymsPlain.begin();
	for (; modSymIt != piddata->modsymsPlain.end(); ++modSymIt)
	{
		writer.StartObject();

		writer.Key("ModuleID");
		writer.Int(modSymIt->first);

		writer.Key("Symbols");
		writer.StartArray();
		map<MEM_ADDRESS, string> ::iterator symIt = modSymIt->second.begin();
		for (; symIt != modSymIt->second.end(); symIt++)
		{
			writer.StartArray();
			writer.Uint64(modSymIt->first); //symbol address
			writer.String(base64_encode((unsigned char*)symIt->second.c_str(), symIt->second.size()).c_str()); //symbol string
			writer.EndArray();
		}
		writer.EndArray();

		writer.EndObject();
	}

	writer.EndArray();
}

void saveDisassembly(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("Disassembly");
	writer.StartArray();

	map <MEM_ADDRESS, INSLIST>::iterator disasIt = piddata->disassembly.begin();
	for (; disasIt != piddata->disassembly.end(); ++disasIt)
	{
		writer.StartArray();

		writer.Int64(disasIt->first); //address

		writer.Int(disasIt->second.front()->modnum); //module
		
		writer.StartArray(); //opcode data for each mutation found at address
		INSLIST::iterator mutationIt = disasIt->second.begin();
		for (; mutationIt != disasIt->second.end(); ++mutationIt)
		{
			INS_DATA *ins = *mutationIt;
			writer.StartArray();

			writer.String(ins->opcodes.c_str());

			//threads containing it
			writer.StartArray();
			unordered_map<PID_TID, NODEINDEX>::iterator threadVertIt = ins->threadvertIdx.begin();
			for (; threadVertIt != ins->threadvertIdx.end(); ++threadVertIt)
			{
				writer.StartArray();

				writer.Int64(threadVertIt->first); //could make file smaller by doing a lookup table.
				writer.Uint(threadVertIt->second);

				writer.EndArray();
			}
			writer.EndArray(); //end array of indexes for this mutation

			writer.EndArray(); //end mutation
		}
		writer.EndArray(); //end array of mutations for this address

		writer.EndArray(); //end address

	}
	writer.EndArray(); // end array of disassembly data for trace
}

void saveExternDict(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("Externs");
	writer.StartArray();

	map <MEM_ADDRESS, BB_DATA *>::iterator externIt = piddata->externdict.begin();
	for (; externIt != piddata->externdict.end(); ++externIt)
	{
		writer.StartObject();

		writer.Key("A");	//address
		writer.Int64(externIt->first); 

		writer.Key("M");	//module number
		writer.Int(externIt->second->modnum);

		writer.Key("S");	//has symbol?
		writer.Bool(externIt->second->hasSymbol);

		//todo: should this object even be written if empty?
		if (!externIt->second->thread_callers.empty())
		{
			writer.Key("C");	//thread callers
			writer.StartArray();
			map<DWORD, EDGELIST>::iterator threadCallIt = externIt->second->thread_callers.begin();
			for (; threadCallIt != externIt->second->thread_callers.end(); ++threadCallIt)
			{
				writer.StartArray();

				//thread id
				writer.Uint64(threadCallIt->first);

				//edges
				writer.StartArray();
				EDGELIST::iterator edgeIt = threadCallIt->second.begin();
				for (; edgeIt != threadCallIt->second.end(); ++edgeIt)
				{
					writer.StartArray();
					//source, target
					writer.Int(edgeIt->first);
					writer.Int(edgeIt->second);

					writer.EndArray();
				}
				writer.EndArray(); //end edge array

				writer.EndArray(); //end thread callers object for this thread
			}
			writer.EndArray(); //end thread callers array for this address
		}
		writer.EndObject(); //end object for this extern entry
	}

	writer.EndArray(); //end externs array
}

void saveBlockData(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("BasicBlocks");
	writer.StartArray();

	map <MEM_ADDRESS, map<BLOCK_IDENTIFIER, INSLIST *>>::iterator blockIt = piddata->blocklist.begin();
	for (; blockIt != piddata->blocklist.end(); ++blockIt)
	{
		writer.StartArray();

		//block address
		writer.Uint64(blockIt->first);

		//instructions 
		writer.StartArray();
		map<BLOCK_IDENTIFIER, INSLIST *>::iterator blockIDIt = blockIt->second.begin();
		for (; blockIDIt != blockIt->second.end(); ++blockIDIt)
		{
			writer.StartArray();

			INSLIST *blockInstructions = blockIDIt->second;

			writer.Uint64(blockIDIt->first); //block ID

			writer.StartArray(); //mutations for each instruction

			INSLIST::iterator blockInsIt = blockInstructions->begin();
			for (; blockInsIt != blockInstructions->end(); ++blockInsIt)
			{
				//write instruction address+mutation loader can look them up in disassembly
				INS_DATA* ins = *blockInsIt;

				writer.StartArray();

				writer.Uint64(ins->address);
				writer.Uint64(ins->mutationIndex);
				
				writer.EndArray();
			}
			
			writer.EndArray(); //end mutations array for this instruction

			writer.EndArray(); //end this instruction
		}

		writer.EndArray();	//end instructions array for this address

		writer.EndArray(); //end basic block object for this address
	}

	writer.EndArray(); //end array of basic blocks
}

void saveMetaData(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("BitWidth");
	if (piddata->bitwidth == CS_MODE_32)
		writer.Uint(32);
	else if (piddata->bitwidth == CS_MODE_64)
		writer.Uint(64);
	else
		cerr << "[rgat] Proto-graph has invalid bitwidth marker " << piddata->bitwidth << endl;

	writer.Key("RGATVersionMaj");
	writer.Uint(RGAT_VERSION_MAJ);
	writer.Key("RGATVersionMin");
	writer.Uint(RGAT_VERSION_MIN);
	writer.Key("RGATVersionFeature");
	writer.Uint(RGAT_VERSION_FEATURE);
}

void saveProcessData(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.StartObject();

	saveMetaData(piddata, writer);
	saveModulePaths(piddata, writer);
	saveModuleSymbols(piddata, writer);
	saveDisassembly(piddata, writer);
	saveBlockData(piddata, writer);
	saveExternDict(piddata, writer);

	writer.EndObject();
}

//if dir doesn't exist in config defined path, create
bool ensureDirExists(string dirname, VISSTATE *clientState)
{
	return true;
}

//saves the process data of activePid and all of its graphs
void saveTrace(VISSTATE * clientState)
{	
	clientState->saving = true;
	string path;
	if (!getSavePath(clientState->config->saveDir, 
		clientState->glob_piddata_map[clientState->activePid->PID]->modpaths.at(0),
		&path, clientState->activePid->PID))
	{
		cout << "[rgat]WARNING: Couldn't save to " << clientState->config->saveDir << endl;
		clientState->config->saveDir = getModulePath()+"\\saves\\";
		cout << "[rgat]Attempting to use " << clientState->config->saveDir << endl;

		if (!getSavePath(clientState->config->saveDir,
			clientState->glob_piddata_map[clientState->activePid->PID]->modpaths.at(0),
			&path, clientState->activePid->PID))
		{
			cerr << "[rgat]ERROR: Failed to save to path " << clientState->config->saveDir << ", giving up." <<endl;
			cerr << "[rgat]Add path of a writable directory to CLIENT_PATH in rgat.cfg" << endl;
			clientState->saving = false;
			return;
		}
		clientState->config->updateSavePath(clientState->config->saveDir);
	}

	cout << "[rgat]Saving process " <<dec<< clientState->activePid->PID <<" to " << path << endl;



	FILE *savefile;
	if ((fopen_s(&savefile, path.c_str(), "wb") != 0))// non-Windows use "w"?
	{
		cerr << "[rgat]Failed to open " << path << "for save" << endl;
		clientState->saving = false;
		return;
	}

	char buffer[65536];
	rapidjson::FileWriteStream outstream(savefile, buffer, sizeof(buffer));
	rapidjson::Writer<rapidjson::FileWriteStream> writer{ outstream };

	writer.StartObject();

	writer.Key("PID");
	writer.Uint64(clientState->activePid->PID);

	writer.Key("ProcessData");
	saveProcessData(clientState->activePid, writer);

	writer.Key("Threads");
	writer.StartArray();

	obtainMutex(clientState->activePid->graphsListMutex, 1012);
	map <PID_TID, void *>::iterator graphit = clientState->activePid->plottedGraphs.begin();
	for (; graphit != clientState->activePid->plottedGraphs.end(); graphit++)
	{
		proto_graph *graph = ((plotted_graph *)graphit->second)->get_protoGraph();
		if (!graph->get_num_nodes()){
			cout << "[rgat]Ignoring empty graph TID "<< graph->get_TID() << endl;
			continue;
		}
		cout << "[rgat]Serialising graph: "<< graphit->first << endl;
		graph->serialise(writer);
	}
	dropMutex(clientState->activePid->graphsListMutex);

	writer.EndArray(); //end threads array

	writer.EndObject();

	fclose(savefile);
	clientState->saving = false;
	cout<<"[rgat]Save complete"<<endl;
}

bool loadModulePaths(VISSTATE *clientState, PROCESS_DATA *piddata, const Value& processData)
{
	display_only_status_message("Loading Modules", clientState);
	cout << "[rgat]Loading Module Paths" << endl;

	Value::ConstMemberIterator procDataIt = processData.FindMember("ModulePaths");
	if (procDataIt == processData.MemberEnd())
		return false;

	const Value& modPathArray = procDataIt->value;

	stringstream pathLoadMsg;
	pathLoadMsg << "Loading path of " << modPathArray.Capacity() << " modules";

	cout << "[rgat]" << pathLoadMsg.str() << endl;
	display_only_status_message(pathLoadMsg.str(), clientState);

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

		piddata->modpaths.emplace(moduleID, plainpath);
	}
	return true;
}

bool unpackModuleSymbolArray(const Value& modSymArray, int moduleID, PROCESS_DATA *piddata)
{
	Value::ConstValueIterator modSymArrIt = modSymArray.Begin();
	for (; modSymArrIt != modSymArray.End(); modSymArrIt++)
	{
		const Value& symbolsArray = *modSymArrIt;
		if (symbolsArray.Capacity() != 2)
		{
			cout << "[rgat]ERROR: Symbols load failed: bad symbol entry in module" << moduleID << endl;
			return false;
		}

		MEM_ADDRESS symAddress = symbolsArray[0].GetUint64();

		string sym64 = symbolsArray[1].GetString();
		string symPlain = base64_decode(sym64);

		piddata->modsymsPlain[moduleID][symAddress] = symPlain;
	}
	return true;
}

bool loadSymbols(VISSTATE *clientState, PROCESS_DATA *piddata, const Value& processData)
{
	Value::ConstMemberIterator symbolsIt = processData.FindMember("ModuleSymbols");
	if (symbolsIt == processData.MemberEnd())
		return false;

	const Value& symbolsArray = symbolsIt->value;

	stringstream symLoadMsg;
	symLoadMsg << "Loading " << symbolsArray.Capacity() << " symbols";

	cout << "[rgat]" << symLoadMsg.str() << endl;
	display_only_status_message(symLoadMsg.str(), clientState);

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

		unpackModuleSymbolArray(modSymArray, moduleID, piddata);
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
		
		INS_DATA *ins = new INS_DATA; //failed load is mem leak
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

bool loadDisassembly(VISSTATE *clientState, PROCESS_DATA *piddata, cs_mode disassemblyMode, const Value& processData)
{
	Value::ConstMemberIterator procDataIt = processData.FindMember("Disassembly");
	if (procDataIt == processData.MemberEnd())
		return false;
	const Value& disassemblyArray = procDataIt->value;

	stringstream disasLoadMsg;
	disasLoadMsg << "Loading disassembly for " << disassemblyArray.Capacity() << " addresses";

	cout << "[rgat]" << disasLoadMsg.str() << endl;
	display_only_status_message(disasLoadMsg.str(), clientState);


	display_only_status_message("Loading Disassembly", clientState);

	csh hCapstone;
	cs_err capOpenResult = cs_open(CS_ARCH_X86, disassemblyMode, &hCapstone);
	if (capOpenResult != CS_ERR_OK) 
	{
		cerr << "[rgat]ERROR: Failed to open Capstone instance: " << capOpenResult << endl;
		return false;
	}

	Value::ConstValueIterator disassemblyIt = disassemblyArray.Begin();
	for (; disassemblyIt != disassemblyArray.End(); disassemblyIt++)
	{
		if (!unpackAddress(piddata, *disassemblyIt, hCapstone))
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

			INS_DATA* disassembledIns = piddata->disassembly.at(instructionAddr).at(mutationIdx);
			piddata->blocklist[blockaddress][blockID]->push_back(disassembledIns);
		}
	}
	return true;
}

//tie the disassembled instructions together into basic blocks
bool loadBasicBlocks(VISSTATE *clientState, PROCESS_DATA *piddata, const Value& processData)
{

	Value::ConstMemberIterator procDataIt = processData.FindMember("BasicBlocks");
	if (procDataIt == processData.MemberEnd())
		return false;
	const Value& basicBlockArray = procDataIt->value;

	stringstream BBLoadMsg;
	BBLoadMsg << "Loading " << basicBlockArray.Capacity() << " basic blocks";

	cout << "[rgat]" << BBLoadMsg.str() << endl;
	display_only_status_message(BBLoadMsg.str(), clientState);


	Value::ConstValueIterator basicBlockIt = basicBlockArray.Begin();
	for (; basicBlockIt != basicBlockArray.End(); basicBlockIt++)
	{
		if (!unpackBasicBlock(piddata, *basicBlockIt))
			return false;
	}

	return true;
}



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
				unsigned int source = Edge[0].GetUint();
				unsigned int target = Edge[1].GetUint();
				threadExternCalls.push_back(make_pair(source, target));
			}
			BBEntry->thread_callers[threadID] = threadExternCalls;
		}	
	}

	piddata->externdict[externAddr] = BBEntry;
	return true;
}

//calls to dll functions
bool loadExterns(VISSTATE *clientState, PROCESS_DATA *piddata, const Value& processData)
{
	Value::ConstMemberIterator procDataIt = processData.FindMember("Externs");
	if (procDataIt == processData.MemberEnd())
		return false;
	const Value& externsArray = procDataIt->value;

	stringstream externLoadMsg;
	externLoadMsg << "Loading " << externsArray.Capacity() << " externs";

	cout << "[rgat]" << externLoadMsg.str() << endl;
	display_only_status_message(externLoadMsg.str(), clientState);

	Value::ConstValueIterator externIt = externsArray.Begin();
	for (; externIt != externsArray.End(); externIt++)
	{
		if (!unpackExtern(piddata, *externIt))
			return false;
	}
	return true;
}

bool getSaveRGATVersion(const Value& procData, unsigned int *versionMaj, unsigned int* versionMin, unsigned int* versionFeature)
{
	Value::ConstMemberIterator memberIt = procData.FindMember("RGATVersionMaj");
	if (memberIt == procData.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find major version of save file" << endl;
		return false;
	}
	*versionMaj = memberIt->value.GetUint();

	memberIt = procData.FindMember("RGATVersionMin");
	if (memberIt == procData.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find minor version of save file" << endl;
		return false;
	}
	*versionMin = memberIt->value.GetUint();

	memberIt = procData.FindMember("RGATVersionFeature");
	if (memberIt == procData.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find feature version of save file" << endl;
		return false;
	}
	*versionFeature = memberIt->value.GetUint();

	if (*versionMaj > RGAT_VERSION_MAJ ||
		(*versionMaj == RGAT_VERSION_MAJ && *versionMin > RGAT_VERSION_MIN) ||
		(*versionMaj == RGAT_VERSION_MAJ && *versionMin == RGAT_VERSION_MIN && *versionFeature == RGAT_VERSION_FEATURE))
		cout << "[rgat]Warning: This file was created by a newer version of rgat" << endl;


	return true;
}

//load process data not specific to threads
bool loadProcessData(VISSTATE *clientState, Document& saveJSON, PROCESS_DATA** piddataPtr, PID_TID PID)
{
	Value::ConstMemberIterator memberIt = saveJSON.FindMember("ProcessData");
	if (memberIt == saveJSON.MemberEnd())
	{
		cout << "[rgat]ERROR: Process data load failed" << endl;
		return false;
	}
	const Value& procData = memberIt->value;

	unsigned int versionMaj, versionMin, versionFeature;
	getSaveRGATVersion(procData, &versionMaj, &versionMin, &versionFeature);
	cout << "[rgat]Loading save by RGAT version " << versionMaj << "." << versionMin << "." << versionFeature << endl;

	Value::ConstMemberIterator procDataIt = procData.FindMember("BitWidth");
	if (procDataIt == procData.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find bitwidth" << endl;
		return false;
	}

	int bitWidth = procDataIt->value.GetInt();
	cout << "[rgat]Executable bitwidth: " << bitWidth << endl;

	cs_mode disassemblyMode;
	switch (bitWidth)
	{
	case 32:
		*piddataPtr = new PROCESS_DATA(32);
		disassemblyMode = CS_MODE_32;
		break;

	case 64:
		*piddataPtr = new PROCESS_DATA(64);
		disassemblyMode = CS_MODE_64;
		break;

	default:
		return false;
	}

	PROCESS_DATA* piddata = *piddataPtr;

	piddata->PID = PID; 

	if(!loadModulePaths(clientState, piddata, procData))
	{
		cerr << "[rgat]ERROR: Failed to load module paths" << endl;
		return false;
	}

	if (!loadSymbols(clientState, piddata, procData))
	{
		cerr << "[rgat]ERROR: Failed to load symbols" << endl;
		return false;
	}

	if (!loadDisassembly(clientState, piddata, disassemblyMode, procData))
	{
		cerr << "[rgat]ERROR: Disassembly reconstruction failed" << endl;
		return false;
	}

	if (!loadBasicBlocks(clientState, piddata, procData))
	{
		cerr << "[rgat]ERROR: Basic block reconstruction failed" << endl;
		return false;
	}

	if (!loadExterns(clientState, piddata, procData))
	{
		cerr << "[rgat]ERROR: Extern call loading failed" << endl;
		return false;
	}

	return true;
}


bool loadGraph(VISSTATE *clientState, PROCESS_DATA* piddata, const Value& graphData)
{
	Value::ConstMemberIterator memberIt = graphData.FindMember("ThreadID");
	if (memberIt == graphData.MemberEnd())
	{
		cerr << "[rgat] Error: Failed to find thread ID for graph" << endl;
		return false;
	}
	PID_TID graphTID = memberIt->value.GetUint64();
	string tidstring = to_string(graphTID);

	display_only_status_message("Loading graph for thread ID: " + tidstring, clientState);

	proto_graph *protograph = new proto_graph(piddata, graphTID);
	cylinder_graph *graph = new cylinder_graph(piddata, graphTID, protograph, &clientState->config->graphColours);
	if (graph->get_protoGraph()->deserialise(graphData, &piddata->disassembly))
		piddata->plottedGraphs.emplace(graphTID, graph);
	else
		return false;

	graph->initialiseDefaultDimensions();
	protograph->active = false;
	protograph->assign_modpath(piddata);
	return true;
}

//load each graph saved for the process
bool loadProcessGraphs(VISSTATE *clientState, Document& saveJSON, PROCESS_DATA* piddata)
{
	Value::ConstMemberIterator procDataIt = saveJSON.FindMember("Threads");
	if (procDataIt == saveJSON.MemberEnd())
		return false;

	const Value& graphArray = procDataIt->value;

	stringstream graphLoadMsg;
	graphLoadMsg << "Loading " << graphArray.Capacity() << " thread graphs";

	cout << "[rgat]" << graphLoadMsg.str() << endl;
	display_only_status_message(graphLoadMsg.str(), clientState);

	Value::ConstValueIterator graphArrayIt = graphArray.Begin();
	for (; graphArrayIt != graphArray.End(); graphArrayIt++)
	{
		if (!loadGraph(clientState, piddata, *graphArrayIt))
		{
			cerr << "[rgat] Failed to load graph" << endl;
			return false;
		}
	}
	
	return true;
}

void saveAll(VISSTATE *clientState)
{
	map<PID_TID, PROCESS_DATA *>::iterator pidIt = clientState->glob_piddata_map.begin();
	for (; pidIt != clientState->glob_piddata_map.end(); pidIt++)
	{
		clientState->activePid = pidIt->second;
		saveTrace(clientState);
	}
}


