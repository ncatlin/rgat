#include "stdafx.h"
#include "traceRecord.h"
#include "graphplots/plotted_graph.h"
#include "serialise.h"
#include "graphplots/cylinder_graph.h"
#include "processLaunching.h"

traceRecord::traceRecord(PID_TID newPID, int randomNo, int bitWidth)
{
	processThreads = new THREAD_POINTERS;
	processdata = new PROCESS_DATA(bitWidth);
	processdata->PID = newPID;
	processdata->randID = randomNo;
	processdata->tracePtr = this;

	//InitializeCriticalSection(&graphsListCritsec);
};

//fill vector ptr with pointers to all trace graphs (which have nodes)
//point is to generate a list of graphs we can interate over in a thread safe way
void traceRecord::getPlottedGraphs(void *graphPtrVecPtr)
{
	if (!graphListLock.trylock())
		return;

	vector<plotted_graph *> *graphlist = (vector<plotted_graph *> *)graphPtrVecPtr;
	for (auto it = plottedGraphs.begin(); it != plottedGraphs.end(); it++)
	{
		plotted_graph *currentGraph = (plotted_graph *)it->second;
		if (currentGraph->get_protoGraph()->get_num_nodes()) //skip threads with no instrumented code
		{
			if (currentGraph->increase_thread_references())
			{
				//cout << "[+1: " << currentGraph->threadReferences << "] trace getplottedgraphs increased references " << endl;
				graphlist->push_back(currentGraph);
			}
		}
	}

	graphListLock.unlock();
}

//fill vector ptr with all trace graphs (which have nodes)
void traceRecord::getProtoGraphs(void *graphPtrVecPtr)
{
	graphListLock.lock();

	vector<proto_graph *> *graphlist = (vector<proto_graph *> *)graphPtrVecPtr;
	for (auto it = protoGraphs.begin(); it != protoGraphs.end(); it++)
	{
		proto_graph *currentGraph = (proto_graph *)it->second;
		graphlist->push_back(currentGraph);
	}

	graphListLock.unlock();
}

void * traceRecord::get_first_graph()
{
	if (plottedGraphs.empty()) return NULL;

	if (graphListLock.trylock())
	{
		void *result = plottedGraphs.begin()->second;
		graphListLock.unlock();
		return result;
	}
	return NULL;
	
}

void traceRecord::serialiseThreads(rapidjson::Writer<rapidjson::FileWriteStream> *writer)
{
	writer->StartArray();
	graphListLock.lock();
	map <PID_TID, PLOTTEDGRAPH_CASTPTR>::iterator graphit = plottedGraphs.begin();
	for (; graphit != plottedGraphs.end(); graphit++)
	{
		proto_graph *graph = ((plotted_graph *)graphit->second)->get_protoGraph();
		if (!graph->get_num_nodes()) {
			cout << "[rgat]Ignoring empty graph TID " << graph->get_TID() << endl;
			continue;
		}
		cout << "[rgat]Serialising graph: " << graphit->first << endl;
		graph->serialise(*writer);
	}
	graphListLock.unlock();
	writer->EndArray();
}

using namespace rapidjson;

bool printRGATVersion(const Value& procData)
{
	unsigned int versionMaj, versionMin, versionFeature;

	Value::ConstMemberIterator memberIt = procData.FindMember("RGATVersionMaj");
	if (memberIt == procData.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find major version of save file" << endl;
		return false;
	}
	versionMaj = memberIt->value.GetUint();

	memberIt = procData.FindMember("RGATVersionMin");
	if (memberIt == procData.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find minor version of save file" << endl;
		return false;
	}
	versionMin = memberIt->value.GetUint();

	memberIt = procData.FindMember("RGATVersionFeature");
	if (memberIt == procData.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find feature version of save file" << endl;
		return false;
	}
	versionFeature = memberIt->value.GetUint();

	cout << "[rgat]Current rgat version is " << RGAT_VERSION_MAJ << "." << RGAT_VERSION_MIN << "." << RGAT_VERSION_FEATURE << endl;
	cout << "[rgat]Loading trace created by rgat version " << versionMaj << "." << versionMin << "." << versionFeature << endl;
	if (versionMaj < RGAT_VERSION_MAJ) return true;
	if (versionMin < RGAT_VERSION_MIN) return true;
	if (versionFeature <= RGAT_VERSION_FEATURE) return true;
	
	cout << "[rgat]Warning: This file was created by a newer version of rgat. Update it if bad things happen." << endl;
	return true;
}


bool traceRecord::loadProcessData(const rapidjson::Document& saveJSON)
{
	Value::ConstMemberIterator memberIt = saveJSON.FindMember("ProcessData");
	if (memberIt == saveJSON.MemberEnd())
	{
		cout << "[rgat]ERROR: Process data load failed" << endl;
		return false;
	}
	const Value& processDataJSON = memberIt->value;

	if (!printRGATVersion(processDataJSON))
		return false;

	Value::ConstMemberIterator procDataIt = processDataJSON.FindMember("BitWidth");
	if (procDataIt == processDataJSON.MemberEnd())
	{
		cout << "[rgat]ERROR: Failed to find bitwidth" << endl;
		return false;
	}

	int bitWidth = procDataIt->value.GetInt();
	if (bitWidth != 32 && bitWidth != 64)
	{
		cout << "[rgat]ERROR: Bad bitwidth: " << bitWidth << endl;
		return false;
	}

	processdata = new PROCESS_DATA(bitWidth);
	if (!processdata->load(saveJSON, this))
	{
		delete processdata;
		return false;
	}

	return true;
}


//load each graph saved for the process
bool traceRecord::loadProcessGraphs(const Document& saveJSON, vector<QColor> *colours)
{
	Value::ConstMemberIterator procDataIt = saveJSON.FindMember("Threads");
	if (procDataIt == saveJSON.MemberEnd())
		return false;

	const Value& graphArray = procDataIt->value;

	stringstream graphLoadMsg;
	graphLoadMsg << "Loading " << graphArray.Capacity() << " thread graphs";

	cout << "[rgat]" << graphLoadMsg.str() << endl;
	//display_only_status_message(graphLoadMsg.str(), clientState);

	Value::ConstValueIterator graphArrayIt = graphArray.Begin();
	for (; graphArrayIt != graphArray.End(); graphArrayIt++)
	{
		if (!loadGraph(*graphArrayIt, colours))
		{
			cerr << "[rgat] Failed to load graph" << endl;
			return false;
		}
	}

	return true;
}

bool traceRecord::loadGraph(const Value& graphData, vector<QColor> *colours)
{
	Value::ConstMemberIterator memberIt = graphData.FindMember("ThreadID");
	if (memberIt == graphData.MemberEnd())
	{
		cerr << "[rgat]Failed to find thread ID for graph" << endl;
		return false;
	}
	PID_TID graphTID = memberIt->value.GetUint64();
	string tidstring = to_string(graphTID);

	//display_only_status_message("Loading graph for thread ID: " + tidstring, clientState);

	proto_graph *protograph = new proto_graph(get_piddata(), graphTID);
	protoGraphs.emplace(make_pair(graphTID, protograph));

	cylinder_graph *graph = new cylinder_graph(get_piddata(), graphTID, protograph, colours);
	if (!graph->get_protoGraph()->deserialise(graphData, &processdata->disassembly))
		return false;

	plottedGraphs.emplace(graphTID, graph);
	graph->initialiseDefaultDimensions();
	graph->setAnimated(false);

	protograph->active = false;
	protograph->assign_modpath(get_piddata());

	return true;
}

bool traceRecord::loadTimeline(const rapidjson::Value& saveJSON)
{
	Value::ConstMemberIterator memberIt = saveJSON.FindMember("Timeline");
	if (memberIt == saveJSON.MemberEnd())
	{
		cerr << "[rgat] Error: Failed to find timeline" << endl;
		return false;
	}

	const Value& timlineObj = memberIt->value;
	runtimeline.unserialise(timlineObj);

	return true;
}

bool traceRecord::load(const rapidjson::Document& saveJSON, vector<QColor> *colours)
{
	if (!loadProcessData(saveJSON))
	{
		cout << "[rgat]ERROR: Process data load failed" << endl;
		return false;
	}

	cout << "[rgat]Loaded process data. Loading graphs..." << endl;

	if (!loadProcessGraphs(saveJSON, colours))//.. &config.graphColours))
	{
		cout << "[rgat]Process Graph load failed" << endl;
		return false;
	}

	if (!loadTimeline(saveJSON))
	{
		cout << "[rgat]Process Graph load failed" << endl;
		return false;
	}
	return true;
}

//recursively gets total number of processes spawned by a process (1 + all descendants)
int traceRecord::countDescendants()
{
	int numProcesses = 1;

	graphListLock.lock();
	for (auto traceIt = children.begin(); traceIt != children.end(); traceIt++)
		numProcesses += (*traceIt)->countDescendants();
	graphListLock.unlock();

	return numProcesses;
}

bool traceRecord::insert_new_thread(PID_TID TID, PLOTTEDGRAPH_CASTPTR graph_plot, PROTOGRAPH_CASTPTR graph_proto)
{
	graphListLock.lock();

	if (protoGraphs.count(TID) > 0)
	{
		cout << "[rgat]: Warning - thread with duplicate ID discarded. This is bad behaviour." << endl;
		graphListLock.unlock();
		return false;
	}

	protoGraphs.insert(make_pair(TID, graph_proto));
	plottedGraphs.insert(make_pair(TID, graph_plot));
	runtimeline.notify_new_thread(getPID(), get_piddata()->randID, TID);

	graphListLock.unlock();
	return true;
}

void traceRecord::killTree()
{
	if (processdata)
		processdata->kill();

	traceRecord *child;
	foreach(child, children)
		child->killTree();
}