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
#include "traceStructs.h"
#include "b64.h"
#include "GUIStructs.h"
#include "traceMisc.h"
#include "basicblock_handler.h"
#include "OSspecific.h"
#include "GUIManagement.h"
#include "sphere_graph.h"

#define tag_START '{'
#define tag_END '}'
#define tag_PROCESSDATA 41
#define tag_PATH 42
#define tag_SYM 43
#define tag_DISAS 44
#define tag_EXTERND 45


void writetag(ofstream *file, char tag, int id = 0) {
	char tagbuf[2];
	if (!id)
	{
		tagbuf[0] = tag;
		file->write(tagbuf, 1);
	}
	else
	{
		if (tag == tag_START)
		{
			tagbuf[0] = id;
			tagbuf[1] = tag;
		}
		else
		{
			tagbuf[0] = tag;
			tagbuf[1] = id;
		}
		file->write(tagbuf, 2);
	}
}

void saveModulePaths(PROCESS_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_PATH);

	map <int, string>::iterator pathIt = piddata->modpaths.begin();
	for (; pathIt != piddata->modpaths.end(); pathIt++)
	{
		const unsigned char* cus_pathstring = reinterpret_cast<const unsigned char*>(pathIt->second.c_str());
		*file << pathIt->first << "," << base64_encode(cus_pathstring, pathIt->second.size()) << " ";
	}
	writetag(file, tag_END, tag_PATH);
}

//big, but worth doing in case environments differ
void saveModuleSymbols(PROCESS_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_SYM);
	*file << " ";
	map <int, std::map<MEM_ADDRESS, string>>::iterator modSymIt = piddata->modsymsPlain.begin();
	for (; modSymIt != piddata->modsymsPlain.end(); ++modSymIt)
	{
		*file << modSymIt->first;
		writetag(file, tag_START);
		map<MEM_ADDRESS, string> ::iterator symIt = modSymIt->second.begin();
		for (; symIt != modSymIt->second.end(); symIt++)
			*file << symIt->first << "," << base64_encode((unsigned char*)symIt->second.c_str(),symIt->second.size()) << "@";

		writetag(file, tag_END);
		*file << " ";
	}
	writetag(file, tag_END, tag_SYM);
}

void saveDisassembly(PROCESS_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_DISAS);

	map <MEM_ADDRESS, INSLIST>::iterator disasIt = piddata->disassembly.begin();
	for (; disasIt != piddata->disassembly.end(); ++disasIt)
	{
		*file << disasIt->second.size() << ","; //number of mutations at this address
		*file << disasIt->first << ",";  //address
		*file << disasIt->second.front()->modnum << ","; //module number (same for all mutations (i really hope))
		
		INSLIST::iterator mutationIt = disasIt->second.begin();
		for (; mutationIt != disasIt->second.end(); ++mutationIt)
		{
			INS_DATA *ins = *mutationIt;
			//for each mutation write opcodes, number of threads executing it
			*file << ins->opcodes << "," << ins->threadvertIdx.size() << ",";
			unordered_map<PID_TID, NODEINDEX>::iterator threadVertIt = ins->threadvertIdx.begin();
			for (; threadVertIt != ins->threadvertIdx.end(); ++threadVertIt)
			{
				//write thread ID, vert index of node in thread
				*file << threadVertIt->first << "," << threadVertIt->second << ",";
			}
		}
	}
	writetag(file, tag_END, tag_DISAS);
}

void saveExternDict(PROCESS_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_EXTERND);

	map <MEM_ADDRESS, BB_DATA *>::iterator externIt = piddata->externdict.begin();
	for (; externIt != piddata->externdict.end(); ++externIt)
	{
		*file << externIt->first << ","; //extern address
		*file << externIt->second->modnum << ","; 
		*file << externIt->second->hasSymbol << ",";

		*file << externIt->second->thread_callers.size() << ",";
		map<DWORD, EDGELIST>::iterator threadCallIt = externIt->second->thread_callers.begin();
		for (; threadCallIt != externIt->second->thread_callers.end(); ++threadCallIt)
		{
			*file << threadCallIt->first << "," << threadCallIt->second.size() << ",";
			EDGELIST::iterator edgeIt = threadCallIt->second.begin();
			for (; edgeIt != threadCallIt->second.end(); ++edgeIt)
				*file << edgeIt->first << "," << edgeIt->second << ",";
		}
	}
	writetag(file, tag_END, tag_EXTERND);
}

void saveBlockData(PROCESS_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_DISAS);

	map <MEM_ADDRESS, map<BLOCK_IDENTIFIER, INSLIST *>>::iterator blockIt = piddata->blocklist.begin();
	for (; blockIt != piddata->blocklist.end(); ++blockIt)
	{
		*file << blockIt->second.size() << ","; //number of blocks at this address
		*file << blockIt->first << ",";  //block address

		map<BLOCK_IDENTIFIER, INSLIST *>::iterator blockIDIt = blockIt->second.begin();
		for (; blockIDIt != blockIt->second.end(); ++blockIDIt)
		{
			INSLIST *blockInstructions = blockIDIt->second;
			*file << blockIDIt->first << "," << blockInstructions->size() << ",";
			INSLIST::iterator blockInsIt = blockInstructions->begin();
			for (; blockInsIt != blockInstructions->end(); ++blockInsIt)
			{
				//write instruction address+mutation loader can look them up in disassembly
				INS_DATA* ins = *blockInsIt;
				*file << ins->address << "," << ins->mutationIndex << ",";
			}
		}
	}
	writetag(file, tag_END, tag_DISAS);
}

void saveProcessData(PROCESS_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_PROCESSDATA);

	saveModulePaths(piddata, file);
	*file << " ";

	saveModuleSymbols(piddata, file);
	*file << " ";

	saveDisassembly(piddata, file);
	*file << " ";
	
	saveBlockData(piddata, file);
	*file << " ";

	saveExternDict(piddata, file);


	writetag(file, tag_END, tag_PROCESSDATA);
}

//if dir doesn't exist in config defined path, create
bool ensureDirExists(string dirname, VISSTATE *clientState)
{
	return true;
}

//this saves the process data of activePid and all of its graphs
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


	ofstream savefile;
	savefile << std::dec;
	savefile.open(path.c_str(), std::ofstream::binary);
	if (!savefile.is_open())
	{
		cerr << "[rgat]Failed to open " << path << "for save" << endl;
		clientState->saving = false;
		return;
	}

	savefile << "PID " << clientState->activePid->PID << " ";
	saveProcessData(clientState->activePid, &savefile);

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
		graph->serialise(&savefile);
	}
	dropMutex(clientState->activePid->graphsListMutex);

	savefile.close();
	clientState->saving = false;
	cout<<"[rgat]Save complete"<<endl;
}

bool verifyTag(ifstream *file, char tag, int id = 0) {
	char tagbuf[2];
	if (!id)
	{
		file->read(tagbuf, 1);
		return tagbuf[0] == tag;
	}
	else
	{
		file->read(tagbuf, 2);
		if (tag == tag_START)
			return (tagbuf[0] == id && tagbuf[1] == tag);
		else
			return (tagbuf[1] == id && tagbuf[0] == tag);
	}
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
		if (!caught_stoul(symAddress_s, &symAddress, 10))		{
			cerr << "[rgat]extractmodsyms: bad address: " << symAddress_s << endl;
			return -1;
		}

		getline(*blob, b64Sym, '@');
		piddata->modsymsPlain[modnum][symAddress] = base64_decode(b64Sym);
	}
}

//load process data not specific to threads
bool loadProcessData(VISSTATE *clientState, ifstream *file, PROCESS_DATA* piddata)
{
	
	if (!verifyTag(file, tag_START, tag_PROCESSDATA)) {
		cerr << "[rgat]Corrupt save (process data start)" << endl;
		return false;
	}

	//paths
	if (!verifyTag(file, tag_START, tag_PATH)) {
		cerr << "[rgat]Corrupt save (process- path data start)" << endl;
		return false;
	}

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
	if (!verifyTag(file, tag_START, tag_SYM)) {
		cerr<< "[rgat]Corrupt save (process- sym data start)" << endl;
		return false;
	}

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
	if (!verifyTag(file, tag_START, tag_DISAS)) {
		cerr << "[rgat]Corrupt save (process- disassembly data start)" << endl;
		return false;
	}

	csh hCapstone;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &hCapstone) != CS_ERR_OK)	{
		cerr << "[rgat]Couldn't open capstone instance" << endl;
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
			cerr << "[rgat]mutations stoi failed with "<< mutations_s <<endl; return false;
		}

		getline(*file, address_s, ',');
		if (!caught_stoul(address_s, &address, 10)) {
			cerr << "[rgat]address stol failed with " << address_s << endl; return false;
		}

		getline(*file, modnum_s, ',');
		if (!caught_stoi(modnum_s, &insmodnum, 10)) {
			cerr << "[rgat]modnum stoi failed with " << modnum_s << endl; return false;
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

	if (!verifyTag(file, tag_END, tag_DISAS)) {
		cerr << "[rgat]Corrupt save (process- disas data end)" << endl;
		return false;
	}
	file->seekg(1, ios::cur);

	//basic blocks
	display_only_status_message("Loading Basic Blocks", clientState);
	cout << "[rgat]Loading basic block mapping" << endl;
	if (!verifyTag(file, tag_START, tag_DISAS)) {
		cerr << "[rgat]Corrupt save (process- basic block data start)" << endl;
		return false;
	}

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
		if (!caught_stoul(blockaddress_s, &blockaddress, 10))
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
				if (!caught_stoul(insAddr_s, &insAddr, 10))
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

	if (!verifyTag(file, tag_END, tag_DISAS)) {
		cerr << "[rgat]Corrupt save (process- basic block data end)" << endl;
		return false;
	}
	file->seekg(1, ios::cur);

	if (!verifyTag(file, tag_START, tag_EXTERND)) {
		cerr << "[rgat]Corrupt save (process- extern data start)" << endl;
		return false;
	}

	string data_s;
	MEM_ADDRESS externAddr;
	BB_DATA *externEntry;
	
	while (true)
	{
		if (file->peek() == '}') break;
		//number of blockIDs recorded for address
		
		getline(*file, data_s, ',');
		if (!caught_stoul(data_s, &externAddr, 10))
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


	if (!verifyTag(file, tag_END, tag_EXTERND)) {
		cerr << "[rgat]Corrupt save (process- extern data end)" << endl;
		return false;
	}

	if (!verifyTag(file, tag_END, tag_PROCESSDATA)) {
		cerr << "[rgat]Corrupt save (process data end)" << endl;
		return false;
	}

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
		sphere_graph *graph = new sphere_graph(piddata, TID, protograph);
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


