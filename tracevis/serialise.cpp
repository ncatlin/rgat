#include "stdafx.h"
#include "traceStructs.h"
#include "b64.h"
#include "GUIStructs.h"
#include "traceMisc.h"
#include "basicblock_handler.h"

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

void saveModulePaths(PID_DATA *piddata, ofstream *file)
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
void saveModuleSymbols(PID_DATA *piddata, ofstream *file)
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

void saveDisassembly(PID_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_DISAS);
	//dump disassembly - could try to be concise and reconstruct on load
	//however we have more diskspace than we have time or RAM and the
	//"small files for sharing" ship has probably sailed, so sod it; be verbose.
	//todo: this is broken by irip change
	map <unsigned long, vector<INS_DATA*>>::iterator disasIt = piddata->disassembly.begin();
	for (; disasIt != piddata->disassembly.end(); disasIt++)
	{
		*file << disasIt->second.size() << ",";
		*file  << disasIt->first << ",";
		vector<INS_DATA*>::iterator mutationIt = disasIt->second.begin();
		for (; mutationIt != disasIt->second.end(); mutationIt++)
		{
			INS_DATA *ins = *mutationIt;
			*file << ins->opcodes<<",";
		}
	}
	writetag(file, tag_END, tag_DISAS);
}

void saveProcessData(PID_DATA *piddata, ofstream *file)
{
	writetag(file, tag_START, tag_PROCESSDATA);

	saveModulePaths(piddata, file);
	*file << " ";

	saveModuleSymbols(piddata, file);
	*file << " ";

	saveDisassembly(piddata, file);

	writetag(file, tag_END, tag_PROCESSDATA);
}

void saveTrace(VISSTATE * clientState)
{
	clientState->saveInProgress = true;
	ofstream savefile;
	savefile.open("C:\\tracing\\testsave.txt", std::ofstream::binary);

	savefile << "PID " << clientState->activeGraph->pid << " ";
	saveProcessData(clientState->activePid, &savefile);

	obtainMutex(clientState->activePid->graphsListMutex, "Save Trace");
	map <int, void *>::iterator graphit = clientState->activePid->graphs.begin();
	for (; graphit != clientState->activePid->graphs.end(); graphit++)
	{
		thread_graph_data *graph = (thread_graph_data *)graphit->second;
		if (!graph->get_num_verts()){
			printf("Ignoring empty graph %d\n", graph->tid);
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
int extractmodsyms(stringstream *blob, int modnum, PID_DATA* piddata)
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

bool loadProcessData(VISSTATE *clientstate, ifstream *file, PID_DATA* piddata)
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
		vector <INS_DATA *> mutationVector;
		for (int i = 0; i < mutations; i++)
		{
			INS_DATA *ins = new INS_DATA;
			getline(*file, address_s, ',');
			if (!caught_stol(address_s, &address, 10)) {
				printf("stol failed with [%s]\n", address_s.c_str()); return false;
			}
			getline(*file, opcodes, ',');
			disassemble_ins(hCapstone, opcodes, ins, address);
			mutationVector.push_back(ins);
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

bool loadEdgeDict(ifstream *file, thread_graph_data *graph)
{
	string index_s, weight_s, source_s, target_s, edgeclass_s;
	int source, target;
	while (true)
	{
		edge_data *edge = new edge_data;
		getline(*file, weight_s, ',');
		if (!caught_stol(weight_s, (unsigned long *)&edge->weight, 10))
		{
			if (weight_s == string("}D")) 
				return true;
			else
				return false;
		}
		getline(*file, source_s, ',');
		if (!caught_stoi(source_s, (int *)&source, 10)) return false;
		getline(*file, target_s, ',');
		if (!caught_stoi(target_s, (int *)&target, 10)) return false;
		getline(*file, edgeclass_s, '@');
		edge->edgeClass = edgeclass_s.c_str()[0];
		pair<int, int>stpair = make_pair(source, target);
		graph->add_edge(*edge, stpair);
	}
	return false;
}

bool loadExterns(ifstream *file, thread_graph_data *graph)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'E') return false;

	int index;
	unsigned long address;
	string address_s, index_s;

	while (true) {
		getline(*file, index_s, ',');
		if (!caught_stoi(index_s, (int *)&index, 10))
		{
			if (index_s == string("}E")) return true;
			return false;
		}
		getline(*file, address_s, ',');
		if (!caught_stol(address_s, &address, 10)) return false;
		graph->externList.push_back(make_pair(index, address));
	}
}

bool loadNodes(ifstream *file, map <unsigned long, vector<INS_DATA *>> *disassembly, thread_graph_data *graph)
{

	if (!verifyTag(file, tag_START, 'N')) {
		printf("Bad node data\n");
		return false;
	}
	string endtag("}N,D");
	unsigned long address;
	while (true)
	{
		node_data *n = new node_data;
		string nodeid, apos, bpos, bmod, cond, address_s, isExternal, b64func, modfile, mutation_s;
		getline(*file, nodeid, '{');
		if (nodeid == endtag) return true;

		if (!caught_stoi(nodeid, (int *)&n->index, 10))
			return false;
		getline(*file, apos, ',');
		if (!caught_stoi(apos, (int *)&n->vcoord.a, 10)) 
			return false;
		getline(*file, bpos, ',');
		if (!caught_stoi(bpos, (int *)&n->vcoord.b, 10)) 
			return false;
		getline(*file, bmod, ',');
		if (!caught_stoi(bmod, (int *)&n->vcoord.bMod, 10)) 
			return false;
		getline(*file, cond, ',');
		if (!caught_stoi(cond, (int *)&n->conditional, 10)) 
			return false;
		getline(*file, modfile, ',');
		if (!caught_stoi(modfile, &n->nodeMod, 10)) 
			return false;
		getline(*file, address_s, ',');
		if (!caught_stol(address_s, &address, 10)) 
			return false;

		getline(*file, isExternal, ',');
		if (isExternal.at(0) == '0')
		{
			n->external = false;

			getline(*file, mutation_s, '}');
			if (!caught_stoi(mutation_s, (int *)&n->mutation, 10)) 
				return false;
			n->ins = disassembly->at(address).at(n->mutation);
			graph->insert_vert(n->index, *n);
			continue;
		}

		n->external = true;

		string numCalls_s;
		int numCalls;
		string arglist;
		getline(*file, numCalls_s, '{');
		if (!caught_stoi(numCalls_s, &numCalls, 10)) 
			return false;
		printf("\vert load loading %d calls\n", numCalls);
		vector <vector<pair<int, string>>> funcCalls;
		for (int i = 0; i < numCalls; i++)
		{
			string numArgs_s, argidx_s, argb64;
			int argidx, numArgs = 0;
			getline(*file, numArgs_s, ',');
			if (!caught_stoi(numArgs_s, &numArgs, 10)) 
				return false;
			vector<pair<int, string>> callArgs;
			printf("\t\tloading %d args\n", numArgs);
			for (int i = 0; i < numArgs; i++)
			{
				getline(*file, argidx_s, ',');
				if (!caught_stoi(argidx_s, &argidx, 10)) 
					return false;
				getline(*file, argb64, ',');
				string decodedarg = base64_decode(argb64);
				callArgs.push_back(make_pair(argidx, decodedarg));
			}
			if (!callArgs.empty())
				funcCalls.push_back(callArgs);
		}
		if (!funcCalls.empty())
			n->funcargs = funcCalls;
		file->seekg(1, ios::cur); //skip closing brace
		graph->insert_vert(n->index, *n);
	}
}

bool loadStats(ifstream *file, thread_graph_data *graph)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'S') return false;

	string value_s;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, &graph->maxA, 10)) return false;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, &graph->maxB, 10)) return false;
	getline(*file, value_s, ',');
	if (!caught_stol(value_s, (unsigned long*)&graph->maxWeight, 10)) return false;
	getline(*file, value_s, ',');
	if (!caught_stol(value_s, (unsigned long*)&graph->totalInstructions, 10)) return false;

	getline(*file, endtag, '}');
	if (endtag.c_str()[0] != 'S') return false;
	return true;
}

bool loadProcessGraphs(VISSTATE *clientstate, ifstream *file, PID_DATA* piddata)
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
		piddata->graphs.emplace(TID, graph);
		graph->tid = TID;
		graph->pid = piddata->PID;
		graph->active = false;

		if (!loadNodes(file, &piddata->disassembly, graph)) { printf("Node load failed\n");  return false; }
		if (!loadEdgeDict(file, graph))	{ printf("EdgeD load failed\n");  return false; }
		if (!loadExterns(file, graph)) { printf("Externs load failed\n");  return false; }
		if (!loadStats(file, graph)) { printf("Stats load failed\n");  return false; }
		printf("Loaded thread graph %d\n", TID);
		if (file->peek() != 'T') break;
	}
	return true;
}


