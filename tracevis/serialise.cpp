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
#include "sphere_graph.h"

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
			writer.StartObject();
			writer.Key("ID");
			writer.Int(modSymIt->first);

			writer.Key("B64");
			writer.String(base64_encode((unsigned char*)symIt->second.c_str(), symIt->second.size()).c_str());
			writer.EndObject();
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
		writer.StartObject();
		writer.Key("A"); //address
		writer.Int64(disasIt->first);
		
		writer.Key("M");//module number (same for all mutations (i hope))
		writer.Int(disasIt->second.front()->modnum);
		
		writer.Key("D"); //disassembly data for each mutation
		writer.StartArray();
		INSLIST::iterator mutationIt = disasIt->second.begin();
		for (; mutationIt != disasIt->second.end(); ++mutationIt)
		{
			INS_DATA *ins = *mutationIt;
			writer.StartObject();

			writer.Key("O");	//opcodes string
			writer.String(ins->opcodes.c_str());

			writer.Key("T");	//threads containing it
			writer.StartArray();
			unordered_map<PID_TID, NODEINDEX>::iterator threadVertIt = ins->threadvertIdx.begin();
			for (; threadVertIt != ins->threadvertIdx.end(); ++threadVertIt)
			{
				writer.StartObject();

				writer.Key("T");	//thread ID
				writer.Int64(threadVertIt->first); //could make file smaller by doing a lookup table.
	
				writer.Key("I");	//node index of opcode in thread
				writer.Int(threadVertIt->second);

				writer.EndObject();
			}
			writer.EndArray(); //end array of indexes for this mutation

			writer.EndObject(); //end object for this mutation
		}
		writer.EndArray(); //end array of mutations for this address

		writer.EndObject(); //end object for this address

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
				writer.StartObject();

				writer.Key("T");	//thread id
				writer.Uint64(threadCallIt->first);

				writer.Key("E");	//edges
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

				writer.EndObject(); //end thread callers object for this thread
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
		writer.StartObject();

		writer.Key("A");	//block address
		writer.Uint64(blockIt->first);

		writer.Key("I");	//instructions
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

		writer.EndObject(); //end basic block object for this address
	}

	writer.EndArray(); //end array of basic blocks
}

void saveProcessData(PROCESS_DATA *piddata, Writer<FileWriteStream>& writer)
{
	writer.Key("ProcessData");
	writer.StartObject();

	writer.Key("BitWidth");
	if (piddata->bitwidth == CS_MODE_32)
		writer.Uint(32);
	else if (piddata->bitwidth == CS_MODE_64)
		writer.Uint(64);
	else
		cerr << "[rgat] Proto-graph has invalid bitwidth marker " << piddata->bitwidth << endl;

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


	using namespace boost::filesystem;

	char buffer[65536];
	rapidjson::FileWriteStream outstream(savefile, buffer, sizeof(buffer));
	rapidjson::Writer<rapidjson::FileWriteStream> writer{ outstream };

	writer.StartObject();

	writer.Key("PID");
	writer.Uint64(clientState->activePid->PID);

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

int extractb64path(ifstream *file, unsigned int *modNum, string *modpath, string endTag)
{
	string modblob;
	*file >> modblob;
	if (modblob == endTag) {
		file->seekg(1, ios::cur);
		return 0;
	}
	if (modblob.size() > 1024) return -1;

	stringstream ss(modblob);
	string modnum_s, b64path;
	getline(ss, modnum_s, ',');
	getline(ss, b64path, ' ');
	if (!caught_stoi(modnum_s, modNum, 10)) return -1;
	*modpath = base64_decode(b64path);
	return 1;
}

//take a {} enclosed blob of , separated b64 encoded symbols
//insert into respective piddata
int extractmodsyms(stringstream *blob, int modnum, PROCESS_DATA* piddata)
{
	string symAddress_s, b64Sym;
	MEM_ADDRESS symAddress;
	while (true)
	{
		getline(*blob, symAddress_s, ',');
		if (symAddress_s == "}") return 1;
		if (!caught_stoull(symAddress_s, &symAddress, 10))		{
			cerr << "[rgat]extractmodsyms: bad address: " << symAddress_s << endl;
			return -1;
		}

		getline(*blob, b64Sym, '@');
		piddata->modsymsPlain[modnum][symAddress] = base64_decode(b64Sym);
	}
}

//load process data not specific to threads
bool loadProcessData(VISSTATE *clientState, ifstream *file, PROCESS_DATA** piddataPtr, PID_TID PID)
{
	/*
	if (!verifyTag(file, tag_START, tag_PROCESSDATA)) {
		cerr << "[rgat]Corrupt save (process data start)" << endl;
		return false;
	}*/

	char bitWidthChar;
	*file >> bitWidthChar;
	printf("File bitwidth: %c\n", bitWidthChar);

	cs_mode disassemblyMode;
	if (bitWidthChar == '3')
	{
		*piddataPtr = new PROCESS_DATA(32);
		disassemblyMode = CS_MODE_32;
	}
	else if (bitWidthChar == '6')
	{
		*piddataPtr = new PROCESS_DATA(64);
		disassemblyMode = CS_MODE_64;
	}
	else
		return false;

	PROCESS_DATA* piddata = *piddataPtr;

	//paths
	/*
	if (!verifyTag(file, tag_START, tag_PATH)) {
		cerr << "[rgat]Corrupt save (process- path data start)" << endl;
		return false;
	}*/

	display_only_status_message("Loading Modules", clientState);
	cout << "[rgat]Loading Module Paths" << endl;
	string pathstring("");
	string endTagStr;
	endTagStr += tag_END;
	endTagStr += tag_PATH;

	int result, count = 0;
	unsigned int modnum;
	string content;
	while (true)
	{
		result = extractb64path(file, &modnum, &content, endTagStr);
		if (result < 0) 
			return false;
		else 
			if (result == 0) break;
		else 
			piddata->modpaths.emplace(modnum, content);
		if (count++ > 255) 
			return false;
	}
	endTagStr.clear();

	//syms
	display_only_status_message("Loading Symbols", clientState);
	cout << "[rgat]Loading Module Symbols" << endl;
	/*
	if (!verifyTag(file, tag_START, tag_SYM)) {
		cerr<< "[rgat]Corrupt save (process- sym data start)" << endl;
		return false;
	}*/

	endTagStr += tag_END;
	endTagStr += tag_SYM;
	string modSymsBlob_s, modNum_s;
	while (true)
	{
		
		*file >> modSymsBlob_s;
		if (modSymsBlob_s == endTagStr) break;

		stringstream mss(modSymsBlob_s);
		getline(mss, modNum_s, '{');
		if (!caught_stoi(modNum_s, &modnum, 10)) return false;

		result = extractmodsyms(&mss, modnum, piddata);
		if ((result < 0) || (count++ > 255)) return false;
	}
	file->seekg(1, ios::cur);

	//disassembly
	display_only_status_message("Loading Disassembly", clientState);
	cout << "[rgat]Loading instruction disassembly" << endl;
	/*
	if (!verifyTag(file, tag_START, tag_DISAS)) {
		cerr << "[rgat]ERROR: Corrupt save (process- disassembly data start)" << endl;
		return false;
	}
	*/
	csh hCapstone;
	if (cs_open(CS_ARCH_X86, disassemblyMode, &hCapstone) != CS_ERR_OK)	{
		cerr << "[rgat]ERROR: Couldn't open Capstone instance" << endl;
		return false;
	}

	string mutations_s, opcodes, address_s, modnum_s, threadVertSize_s, callerTID_s, calledNode_s;
	int mutations, insmodnum;
	while (true)
	{
		
		MEM_ADDRESS address;
		if (file->peek() == '}') break;

		getline(*file, mutations_s, ',');
		if (!caught_stoi(mutations_s, &mutations, 10)) {
			cerr << "[rgat]ERROR: mutations stoi failed with "<< mutations_s <<endl; return false;
		}

		getline(*file, address_s, ',');
		if (!caught_stoull(address_s, &address, 10)) {
			cerr << "[rgat]ERROR: address stol failed with " << address_s << endl; return false;
		}

		getline(*file, modnum_s, ',');
		if (!caught_stoi(modnum_s, &insmodnum, 10)) {
			cerr << "[rgat]ERROR: modnum stoi failed with " << modnum_s << endl; return false;
		}

		bool hasSym;
		if (piddata->modsymsPlain.count(insmodnum) && piddata->modsymsPlain.at(insmodnum).count(address))
			hasSym = true;
		else 
			hasSym = false;

		INSLIST mutationVector;
		for (int midx = 0; midx < mutations; midx++)
		{
			INS_DATA *ins = new INS_DATA; //failed load is mem leak
			ins->modnum = insmodnum;
			ins->hasSymbol = hasSym;

			getline(*file, opcodes, ',');
			disassemble_ins(hCapstone, opcodes, ins, address);
			mutationVector.push_back(ins);

			int threadVertSize;
			getline(*file, threadVertSize_s, ',');
			if (!caught_stoi(threadVertSize_s, &threadVertSize, 10)) 
				return false;

			for (int tvIdx = 0; tvIdx < threadVertSize; ++tvIdx)
			{
				int callTID, calledNode;
				getline(*file, callerTID_s, ',');
				if (!caught_stoi(callerTID_s, &callTID, 10)) 
					return false;
				getline(*file, calledNode_s, ',');
				if (!caught_stoi(calledNode_s, &calledNode, 10)) 
					return false;
				ins->threadvertIdx.emplace(callTID, calledNode);
			}	
		}
		piddata->disassembly.insert(make_pair(address, mutationVector));
	}
	cs_close(&hCapstone);
	/*
	if (!verifyTag(file, tag_END, tag_DISAS)) {
		cerr << "[rgat]ERROR: Corrupt save (process- disas data end)" << endl;
		return false;
	}*/
	file->seekg(1, ios::cur);

	//basic blocks
	display_only_status_message("Loading Basic Blocks", clientState);
	cout << "[rgat]Loading basic block mapping" << endl;
	/*
	if (!verifyTag(file, tag_START, tag_DISAS)) {
		cerr << "[rgat]ERROR: Corrupt save (process- basic block data start)" << endl;
		return false;
	}*/

	string numblocks_s, blockaddress_s, blockID_s, numinstructions_s, mutationIndex_s, insAddr_s;
	while (true)
	{
		if (file->peek() == '}') break;
		//number of blockIDs recorded for address
		unsigned int numblocks;
		getline(*file, numblocks_s, ',');
		if (!caught_stoi(numblocks_s, &numblocks, 10))
			return false;

		//address of block
		MEM_ADDRESS blockaddress;
		getline(*file, blockaddress_s, ',');
		if (!caught_stoull(blockaddress_s, &blockaddress, 10))
			return false;

		map<MEM_ADDRESS, INSLIST>::iterator disasLookupIt = piddata->disassembly.find(blockaddress);
		if (disasLookupIt == piddata->disassembly.end())
			return false;


		for (unsigned int blocki = 0; blocki < numblocks; ++blocki)
		{
			BLOCK_IDENTIFIER blockID;
			getline(*file, blockID_s, ',');
			if (!caught_stoul(blockID_s, &blockID, 10))
				return false;

			unsigned int numinstructions;
			getline(*file, numinstructions_s, ',');
			if (!caught_stoi(numinstructions_s, &numinstructions, 10))
				return false;

			piddata->blocklist[blockaddress][blockID] = new INSLIST;
			for (unsigned int insi = 0; insi < numinstructions; ++insi)
			{
				MEM_ADDRESS insAddr;
				getline(*file, insAddr_s, ',');
				if (!caught_stoull(insAddr_s, &insAddr, 10))
					return false;

				unsigned int mutationIndex;
				getline(*file, mutationIndex_s, ',');
				if (!caught_stoi(mutationIndex_s, &mutationIndex, 10))
					return false;

				INSLIST *allInsMutations = &disasLookupIt->second;
				if (mutationIndex >= allInsMutations->size())
					return false;

				INS_DATA* disassembledIns = piddata->disassembly.at(insAddr).at(mutationIndex);
				piddata->blocklist[blockaddress][blockID]->push_back(disassembledIns);
			}
		}
	}
	/*
	if (!verifyTag(file, tag_END, tag_DISAS)) {
		cerr << "[rgat]ERROR: Corrupt save (process- basic block data end)" << endl;
		return false;
	}*/
	file->seekg(1, ios::cur);
	/*
	if (!verifyTag(file, tag_START, tag_EXTERND)) {
		cerr << "[rgat]ERROR: Corrupt save (process- extern data start)" << endl;
		return false;
	}*/

	string data_s;
	MEM_ADDRESS externAddr;
	BB_DATA *externEntry;
	
	while (true)
	{
		if (file->peek() == '}') break;
		//number of blockIDs recorded for address
		
		getline(*file, data_s, ',');
		if (!caught_stoull(data_s, &externAddr, 10))
			return false;
		
		if (piddata->externdict.count(externAddr))
			return false;

		externEntry = new BB_DATA;

		getline(*file, data_s, ',');
		if (!caught_stoi(data_s, &externEntry->modnum, 10))
			return false;

		int hasSymI;
		getline(*file, data_s, ',');
		if (!caught_stoi(data_s, &hasSymI, 10))
			return false;
		externEntry->hasSymbol = hasSymI;

		unsigned int threadsCalling;
		getline(*file, data_s, ',');
		if (!caught_stoi(data_s, &threadsCalling, 10))
			return false;

		for (unsigned int tIdx = 0; tIdx < threadsCalling; ++tIdx)
		{
			PID_TID externThreadID;
			getline(*file, data_s, ',');
			if (!caught_stoul(data_s, &externThreadID, 10))
				return false;

			unsigned int numEdges;
			getline(*file, data_s, ',');
			if (!caught_stoi(data_s, &numEdges, 10))
				return false;

			EDGELIST externCalls;
			for (unsigned int eIdx = 0; eIdx < numEdges; ++eIdx)
			{
				NODEINDEX source, targ;
				getline(*file, data_s, ',');
				if (!caught_stoi(data_s, &source, 10))
					return false;
				getline(*file, data_s, ',');
				if (!caught_stoi(data_s, &targ, 10))
					return false;

				externCalls.push_back(make_pair(source, targ));
			}
			externEntry->thread_callers[externThreadID] = externCalls;
		}
		piddata->externdict[externAddr] = externEntry;
	}

	/*
	if (!verifyTag(file, tag_END, tag_EXTERND)) {
		cerr << "[rgat]ERROR: Corrupt save (process- extern data end)" << endl;
		return false;
	}

	if (!verifyTag(file, tag_END, tag_PROCESSDATA)) {
		cerr << "[rgat]ERROR: Corrupt save (process data end)" << endl;
		return false;
	}
	*/
	return true;
}

//load each graph saved for the process
bool loadProcessGraphs(VISSTATE *clientState, ifstream *file, PROCESS_DATA* piddata)
{
	char tagbuf[3]; 
	PID_TID TID; 
	string tidstring;

	cerr << "[rgat]Loading thread graphs..." << endl;
	while (true)
	{
		file->read(tagbuf, 3);
		if (strncmp(tagbuf, "TID", 3)) return false;

		getline(*file, tidstring, '{');
		if (!caught_stoul(tidstring, &TID, 10)) return false;
		proto_graph *protograph = new proto_graph(piddata,TID);
		sphere_graph *graph = new sphere_graph(piddata, TID, protograph, &clientState->config->graphColours);
		graph->initialiseDefaultDimensions();

		protograph->active = false;

		display_only_status_message("Loading Graph "+tidstring, clientState);
		if(graph->get_protoGraph()->unserialise(file, &piddata->disassembly))
			piddata->plottedGraphs.emplace(TID, graph);
		else 
			return false;

		protograph->assign_modpath(piddata);

		cerr << "[rgat]Loaded thread graph "<<TID <<endl;
		if (file->peek() != '}') 
			return false;
		file->seekg(1, ios::cur);

		if (file->peek() != 'T')
			break;

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


