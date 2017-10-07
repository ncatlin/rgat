/*
Copyright 2017 Nia Catlin

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
Represents a single trace run. 
Contains all trace data and the rendered graph data
Pointers to child processes (traces) are contained in the processdata
*/

#pragma once
#include "traceStructs.h"
#include "timeline.h"
#include "locks.h"

enum eTracePurpose { eVisualiser, eFuzzer };
typedef void * BINARYTARGETPTR;

class traceRecord
{
public:
	traceRecord(PID_TID newPID, int randomNo, BINARYTARGETPTR binary, time_t timeStarted);
	~traceRecord() {};

	PID_TID getPID() { return PID; }
	wstring getModpathID() { return to_wstring(PID) + to_wstring(randID); }
	BINARYTARGETPTR get_binaryPtr() { return binaryPtr; }
	PROCESS_DATA *get_piddata() { return dynamicDisassemblyData;  }

	void notify_new_pid(PID_TID pid, int PID_ID, PID_TID parentPid) { runtimeline.notify_new_pid(pid, PID_ID, parentPid); running = true; }
	void notify_pid_end(PID_TID pid, int PID_ID) { running = runtimeline.notify_pid_end(pid, PID_ID); }
	void notify_tid_end(PID_TID tid) { runtimeline.notify_thread_end(getPID(), randID, tid); }
	bool insert_new_thread(PID_TID TID, PLOTTEDGRAPH_CASTPTR graph_plot, PROTOGRAPH_CASTPTR graph_proto);
	bool is_process(PID_TID testpid, int testID);

	void *get_first_graph();
	time_t getStartedTime() { return launchedTime; }

	void getPlottedGraphs(void *graphPtrVecPtr);
	void getProtoGraphs(void *graphPtrVecPtr);
	bool isRunning() { return running; }
	int countDescendants();
	
	void save(void *clientConfigPtr);
	bool load(const rapidjson::Document& saveJSON, vector<QColor> *colours);
	void serialiseThreads(rapidjson::Writer<rapidjson::FileWriteStream> *writer);
	void serialiseTimeline(rapidjson::Writer<rapidjson::FileWriteStream> *writer) { runtimeline.serialise(writer); };

	void kill() { if (running) { killed = true; } }
	bool should_die() { return killed; }
	bool is_running() { return running; }
	void set_running(bool r) { running = r; }
	void killTree();
	void setTraceType(eTracePurpose purpose);
	eTracePurpose getTraceType() { return tracetype; }

	rgatlocks::TestableLock graphListLock;

	map <PID_TID, PROTOGRAPH_CASTPTR> protoGraphs;
	map <PID_TID, PLOTTEDGRAPH_CASTPTR> plottedGraphs;

	traceRecord *parentTrace = NULL;
	list<traceRecord *> children;
	bool UIRunningFlag = false;
	void *processThreads;
	void *fuzzRunPtr = NULL;

	PID_TID PID = -1;
	int randID; //to distinguish between processes with identical PIDs

	//index of this vec == client reference to each module. returned value is our static reference to the module
	//needed because each trace drgat can come up with a new ID for each module
	vector<long> modIDTranslationVec;
	map <long, int> activeMods;

	int loadedModuleCount = 0;

private:
	bool loadProcessGraphs(const rapidjson::Document& saveJSON, vector<QColor> *colours);
	bool loadGraph(const rapidjson::Value& graphData, vector<QColor> *colours);
	bool loadTimeline(const rapidjson::Value& saveJSON);

	PROCESS_DATA *dynamicDisassemblyData = NULL; //the first disassembly of each address

	timeline runtimeline;
	time_t launchedTime; //the time the user pressed start, not when the first process was seen

	BINARYTARGETPTR binaryPtr = NULL;
	bool running = false;
	bool killed = false;
	eTracePurpose tracetype;
};