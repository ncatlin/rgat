#include "stdafx.h"
#include "traceStructs.h"
#include "b64.h"
#include "GUIStructs.h"
#include "traceMisc.h"
#include "basicblock_handler.h"
#include "OSspecific.h"

#define tag_START '{'
#define tag_END '}'
#define tag_PROCESSDATA 41
#define tag_PATH 42
#define tag_SYM 43
#define tag_DISAS 44

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
	map <int, std::map<long, string>>::iterator modSymIt = piddata->modsyms.begin();
	for (; modSymIt != piddata->modsyms.end(); modSymIt++)
	{
		*file << modSymIt->first;
		writetag(file, tag_START);
		map<long, string> ::iterator symIt = modSymIt->second.begin();
		for (; symIt != modSymIt->second.end(); symIt++)
		{
			const unsigned char* cus_symstring = reinterpret_cast<const unsigned char*>(symIt->second.c_str());
			*file << symIt->first << "," << base64_encode(cus_symstring, symIt->second.size()) << "@";
		}
		writetag(file, tag_END);
		*file << " ";
	}
	writetag(file, tag_END, tag_SYM);
}

void saveDisassembly(PROCESS_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_DISAS);
	//dump disassembly - could try to be concise and reconstruct on load
	//however we have more diskspace than we have time or RAM and the
	//"small files for sharing" ship has probably sailed, so sod it; be verbose.
	//todo: this is broken by irip change
	map <unsigned long, INSLIST>::iterator disasIt = piddata->disassembly.begin();
	for (; disasIt != piddata->disassembly.end(); disasIt++)
	{
		*file << disasIt->second.size() << ","; //number of mutations at this address
		*file << disasIt->first << ",";  //address

		INSLIST::iterator mutationIt = disasIt->second.begin();
		for (; mutationIt != disasIt->second.end(); mutationIt++)
		{
			INS_DATA *ins = *mutationIt;
			//for each mutation write opcodes, number of threads executing it
			*file << ins->opcodes << "," << ins->threadvertIdx.size() << ",";
			unordered_map<int, int>::iterator threadVertIt = ins->threadvertIdx.begin();
			for (; threadVertIt != ins->threadvertIdx.end(); ++threadVertIt)
			{
				//write thread ID, vert index of node in thread
				*file << threadVertIt->first << "," << threadVertIt->second << ",";
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

	writetag(file, tag_END, tag_PROCESSDATA);
}

//if dir doesn't exist in config defined path, create
bool ensureDirExists(string dirname, VISSTATE *clientState)
{
	return true;

}

void saveTrace(VISSTATE * clientState)
{
	
	clientState->saveInProgress = true;
	ofstream savefile;
	string path;
	if (!getSavePath(clientState, &path, clientState->activePid->PID))
	{
		printf("Failed to get save path\n");
		return;
	}
	printf("Saving to process %d to %s\n", clientState->activePid->PID, path.c_str());
	savefile.open(path.c_str(), std::ofstream::binary);
	if (!savefile.is_open())
	{
		printf("Failed to open %s for save\n", path.c_str());
		return;
	}


	savefile << "PID " << clientState->activePid->PID << " ";
	saveProcessData(clientState->activePid, &savefile);

	obtainMutex(clientState->activePid->graphsListMutex, "Save Trace");
	map <int, void *>::iterator graphit = clientState->activePid->graphs.begin();
	for (; graphit != clientState->activePid->graphs.end(); graphit++)
	{
		thread_graph_data *graph = (thread_graph_data *)graphit->second;
		if (!graph->get_num_nodes()){
			printf("Ignoring empty graph TID %d\n", graph->tid);
			continue;
		}
		printf("Serialising graph: %d\n", graphit->first);
		graph->serialise(&savefile);
	}
	dropMutex(clientState->activePid->graphsListMutex, "Save Trace");

	savefile.close();
	clientState->saveInProgress = false;
	printf("Save complete\n");
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

int extractb64path(ifstream *file, unsigned long *id, string *modpath, string endTag)
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
	if (!caught_stol(modnum_s, id, 10)) return -1;
	*modpath = base64_decode(b64path);
	return 1;
}

//take a {} enclosed blog of , separated b64 encoded symbols
//insert into respective piddata
int extractmodsyms(stringstream *blob, int modnum, PROCESS_DATA* piddata)
{
	string symAddress_s, b64Sym;
	unsigned long symAddress;
	while (true)
	{
		getline(*blob, symAddress_s, ',');
		if (symAddress_s == "}") return 1;
		if (!caught_stol(symAddress_s, &symAddress, 10))		{
			printf("extractmodsyms: bad address: %s", symAddress_s.c_str());
			return -1;
		}

		getline(*blob, b64Sym, '@');
		string sym = base64_decode(b64Sym); //TODO: error checking?
		piddata->modsyms[modnum][symAddress] = sym;
	}
}

bool loadProcessData(VISSTATE *clientstate, ifstream *file, PROCESS_DATA* piddata)
{
	
	if (!verifyTag(file, tag_START, tag_PROCESSDATA)) {
		printf("Corrupt save (process data start)\n");
		return false;
	}

	//paths
	if (!verifyTag(file, tag_START, tag_PATH)) {
		printf("Corrupt save (process- path data start)\n");
		return false;
	}

	printf("Loading Module paths\n");
	string pathstring("");
	string endTagStr;
	endTagStr += tag_END;
	endTagStr += tag_PATH;

	int result, count = 0;
	unsigned long id;
	string content;
	while (true)
	{
		result = extractb64path(file, &id, &content, endTagStr);
		if (result < 0) 
			return false;
		else 
			if (result == 0) break;
		else 
			piddata->modpaths.emplace(id, content);
		if (count++ > 255) 
			return false;
	}
	endTagStr.clear();

	//syms
	printf("Loading Module Symbols\n");
	if (!verifyTag(file, tag_START, tag_SYM)) {
		printf("Corrupt save (process- sym data start)\n");
		return false;
	}

	endTagStr += tag_END;
	endTagStr += tag_SYM;
	while (true)
	{
		int modnum;
		string modSymsBlob_s, modNum_s;
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
	printf("Loading basic block disassembly\n");
	if (!verifyTag(file, tag_START, tag_DISAS)) {
		printf("Corrupt save (process- disas data start)\n");
		return false;
	}

	csh hCapstone;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &hCapstone) != CS_ERR_OK)	{
		printf("Couldn't open capstone instance\n");
		return false;
	}

	string mutations_s;
	int mutations;
	while (true)
	{
		string opcodes, address_s;
		unsigned long address;
		if (file->peek() == '}') break;

		getline(*file, mutations_s, ',');
		if (!caught_stoi(mutations_s, &mutations, 10)) {
			printf("stoi failed with [%s]\n", address_s.c_str()); return false;
		}

		getline(*file, address_s, ',');
		if (!caught_stol(address_s, &address, 10)) {
			printf("stol failed with [%s]\n", address_s.c_str()); return false;
		}

		INSLIST mutationVector;
		for (int midx = 0; midx < mutations; midx++)
		{
			INS_DATA *ins = new INS_DATA;
			
			getline(*file, opcodes, ',');
			disassemble_ins(hCapstone, opcodes, ins, address);
			mutationVector.push_back(ins);

			string threadVertSize_s;
			int threadVertSize;
			getline(*file, threadVertSize_s, ',');
			if (!caught_stoi(threadVertSize_s, &threadVertSize, 10)) return false;

			for (int tvIdx = 0; tvIdx < threadVertSize; ++tvIdx)
			{
				int callTID, calledNode;
				string callerTID_s, calledNode_s;
				getline(*file, callerTID_s, ',');
				if (!caught_stoi(callerTID_s, &callTID, 10)) return false;
				getline(*file, calledNode_s, ',');
				if (!caught_stoi(calledNode_s, &calledNode, 10)) return false;
				ins->threadvertIdx.emplace(callTID, calledNode);
			}	
		}
		piddata->disassembly.insert(make_pair(address, mutationVector));
	}
	cs_close(&hCapstone);

	if (!verifyTag(file, tag_END, tag_DISAS)) {
		printf("Corrupt save (process- disas data start)\n");
		return false;
	}

	if (!verifyTag(file, tag_END, tag_PROCESSDATA)) {
		printf("Corrupt save (process data end)\n");
		return false;
	}

	return true;
}


bool loadProcessGraphs(VISSTATE *clientstate, ifstream *file, PROCESS_DATA* piddata)
{
	char tagbuf[3]; int TID; string tidstring;
	printf("Loading thread graphs...\n");
	while (true)
	{
		file->read(tagbuf, 3);
		if (strncmp(tagbuf, "TID", 3)) return false;

		getline(*file, tidstring, '{');
		if (!caught_stoi(tidstring, &TID, 10)) return false;
		thread_graph_data *graph = new thread_graph_data(&piddata->disassembly, piddata->disassemblyMutex);
		
		graph->tid = TID;
		graph->pid = piddata->PID;
		graph->active = false;

		if(graph->unserialise(file, &piddata->disassembly))
			piddata->graphs.emplace(TID, graph);
		else 
			return false;

		graph->assign_modpath(piddata);

		printf("Loaded thread graph %d\n", TID);
		if (file->peek() != 'T') break;
	}
	return true;
}


