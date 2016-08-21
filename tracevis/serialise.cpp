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

void saveProcessData(PID_DATA *piddata, ofstream *file)
{
	return;
	/*
	writetag(file, tag_START, tag_PROCESSDATA);

	//save module paths
	writetag(file, tag_START, tag_PATH);


	map <int, string>::iterator pathIt = piddata->modpaths.begin();
	for (; pathIt != piddata->modpaths.end(); pathIt++)
	{
		const unsigned char* cus_pathstring = reinterpret_cast<const unsigned char*>(pathIt->second.c_str());
		*file << pathIt->first << "," << base64_encode(cus_pathstring, pathIt->second.size()) << " ";
	}
	writetag(file, tag_END, tag_PATH);
	*file << " ";

	//save module symbols (big, but worth doing in case environments differ)
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
	*file << " ";

	writetag(file, tag_START, tag_DISAS);
	//dump disassembly - could try to be concise and reconstruct on load
	//however we have more diskspace than we have time or RAM and the
	//"small files for sharing" ship has probably sailed, so sod it; be verbose.
	todo: this is broken by irip change
	map <unsigned long, vector<INS_DATA*>>::iterator disasIt = piddata->disassembly.begin();
	for (; disasIt != piddata->disassembly.end(); disasIt++)
	{
		*file << disasIt->first << ",";
	}
	writetag(file, tag_END, tag_DISAS);

	writetag(file, tag_END, tag_PROCESSDATA);
	*/
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

int extractmodsyms(stringstream *blob, int modnum, PID_DATA* piddata)
{
	string modnum_s, b64path;
	unsigned long address;
	while (true)
	{
		getline(*blob, modnum_s, ',');
		if (modnum_s == "}") return 1;
		getline(*blob, b64path, '@');
		if (!caught_stol(modnum_s, &address, 10))
		{
			printf("extractmodsyms: bad address: %s", modnum_s.c_str());
			return -1;
		}
		string sym = base64_decode(b64path);
		piddata->modsyms[modnum][address] = sym;
	}
}

bool loadProcessData(VISSTATE *clientstate, ifstream *file, PID_DATA* piddata, map<unsigned long, vector<INS_DATA*>> *insdict)
{
	/*
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
		if (result < 0) return false;
		else if (result == 0) break;
		else piddata->modpaths.emplace(id, content);
		if (count++ > 255) return false;
	}


	//syms
	printf("Loading Module Symbols\n");
	if (!verifyTag(file, tag_START, tag_SYM)) {
		printf("Corrupt save (process- sym data start)\n");
		return false;
	}

	endTagStr.clear();
	endTagStr += tag_END;
	endTagStr += tag_SYM;
	while (true)
	{
		int modnum;
		string modsyms, modnum_s;
		*file >> modsyms;
		if (modsyms == endTagStr) {
			file->seekg(1, ios::cur);
			break;
		}

		stringstream mss(modsyms);
		getline(mss, modnum_s, '{');
		if (!caught_stoi(modnum_s, &modnum, 10)) return false;

		result = extractmodsyms(&mss, modnum, piddata);
		if ((result < 0) || (count++ > 255)) return false;
	}

	//disassembly
	printf("Loading basic block disassembly\n");
	if (!verifyTag(file, tag_START, tag_DISAS)) {
		printf("Corrupt save (process- disas data start)\n");
		return false;
	}

	csh hCapstone;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &hCapstone) != CS_ERR_OK)
	{
		printf("Couldn't open capstone instance\n");
		return false;
	}

	while (true)
	{
		string opcodes, address_s;
		unsigned long address;
		if (file->peek() == '}') break;

		INS_DATA *ins = new INS_DATA;
		getline(*file, address_s, '@');
		if (!caught_stol(address_s, &address, 10)) {
			printf("stol failed with [%s]\n", address_s.c_str()); return false;
		}
		getline(*file, opcodes, ',');
		disassemble_ins(hCapstone, opcodes, ins, address);
		piddata->disassembly.emplace(address, ins);
		insdict->emplace(address, ins);
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
	*/
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
			if (weight_s == string("}D")) return true;
			return false;
		}
		getline(*file, source_s, ',');
		if (!caught_stoi(source_s, (int *)&source, 10)) return false;
		getline(*file, target_s, ',');
		if (!caught_stoi(target_s, (int *)&target, 10)) return false;
		getline(*file, edgeclass_s, '@');
		edge->edgeClass = edgeclass_s.c_str()[0];
		pair<int, int>stpair = make_pair(source, target);
		graph->edgeDict.emplace(stpair, *edge);
	}
}

bool loadEdgeList(ifstream *file, thread_graph_data *graph)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'L') return false;

	string index_s, target_s, source_s;
	int source, target;
	while (true) {
		getline(*file, source_s, ',');
		if (!caught_stoi(source_s, (int *)&source, 10))
		{
			if (source_s == string("}L")) return true;
			return false;
		}
		getline(*file, target_s, ',');
		if (!caught_stoi(target_s, (int *)&target, 10)) return false;
		graph->edgeList.push_back(make_pair(source, target));
	}

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

bool loadNodes(ifstream *file, map<unsigned long, vector<INS_DATA*>> *insdict, thread_graph_data *graph)
{
	return false;
	/*
	if (!verifyTag(file, tag_START, 'N')) {
		printf("Bad node data\n");
		return false;
	}
	string endtag("}N,D");
	while (true)
	{
		node_data *n = new node_data;
		string nodeid, apos, bpos, bmod, cond, address_s, isExternal, b64func, modfile;
		getline(*file, nodeid, '{');
		if (nodeid == endtag) return true;;
		if (!caught_stoi(nodeid, (int *)&n->index, 10))
			return false;
		getline(*file, apos, ',');
		if (!caught_stoi(apos, (int *)&n->vcoord.a, 10)) return false;
		getline(*file, bpos, ',');
		if (!caught_stoi(bpos, (int *)&n->vcoord.b, 10)) return false;
		getline(*file, bmod, ',');
		if (!caught_stoi(bmod, (int *)&n->vcoord.bMod, 10)) return false;
		getline(*file, cond, ',');
		if (!caught_stoi(cond, (int *)&n->conditional, 10)) return false;
		getline(*file, address_s, ',');
		unsigned long address;
		if (!caught_stol(address_s, &address, 10)) return false;
		n->ins = insdict->at(address);
		getline(*file, isExternal, ',');
		if (isExternal.at(0) == '0')
			n->external = false;
		else
			n->external = true;

		getline(*file, modfile, ',');
		if (!caught_stoi(modfile, &n->nodeMod, 10)) return false;

		getline(*file, b64func, '{');
		if (b64func.at(0) != '0')
			n->nodeSym = base64_decode(b64func);
		else
			n->nodeSym = "";

		if (file->peek() != '}')
		{
			string arglist;
			getline(*file, arglist, '}');
			if (arglist.size() == 0) continue;
			stringstream argss(arglist);
			while (true)
			{
				string argidx_s, argb64;
				int argidx;
				getline(argss, argidx_s, ',');
				if (argidx_s.empty()) break;
				if (!caught_stoi(argidx_s, &argidx, 10)) return false;
				getline(argss, argb64, '@');
				string decodedarg = base64_decode(argb64);
				n->funcargs.push_back(make_pair(argidx, decodedarg));
			}
		}
		else
			file->seekg(1, ios::cur);
		//todo graph->vertDict.emplace(n->index, *n);
	}
	*/
}

bool loadStats(ifstream *file, thread_graph_data *graph)
{
	string endtag;
	getline(*file, endtag, '{');
	if (endtag.c_str()[0] != 'S') return false;

	string max;
	getline(*file, max, ',');
	if (!caught_stoi(max, &graph->maxA, 10)) return false;
	getline(*file, max, ',');
	if (!caught_stoi(max, &graph->maxB, 10)) return false;
	getline(*file, max, '}');
	if (!caught_stol(max, (unsigned long*)&graph->maxWeight, 10)) return false;

	getline(*file, endtag, '}');
	if (endtag.c_str()[0] != 'S') return false;
	return true;
}

bool loadProcessGraphs(VISSTATE *clientstate, ifstream *file, PID_DATA* piddata, map<unsigned long, vector<INS_DATA*>> *insdict)
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

		if (!loadNodes(file, insdict, graph))	return false;
		if (!loadEdgeDict(file, graph))	return false;
		if (!loadEdgeList(file, graph))	return false;
		if (!loadExterns(file, graph))	return false;
		if (!loadStats(file, graph))	return false;
		printf("Loaded thread graph %d\n", TID);
		if (file->peek() != 'T') break;
	}
	return true;
}


