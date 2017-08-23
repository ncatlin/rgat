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

typedef void * BINARYTARGETPTR;

class traceRecord
{
public:
	traceRecord(PID_TID newPID, int randomNo, int bitWidth);
	~traceRecord() { DeleteCriticalSection(&graphsListCritsec); };

	PID_TID getPID() { return processdata->PID; }
	wstring getModpathID() { return to_wstring(processdata->PID) + to_wstring(processdata->randID); }
	PROCESS_DATA * get_piddata() { return processdata; }
	BINARYTARGETPTR get_binaryPtr() { return binaryPtr; }
	void notify_new_pid(PID_TID pid, int PID_ID, PID_TID parentPid) { runtimeline.notify_new_pid(pid, PID_ID, parentPid); running = true; }
	void notify_pid_end(PID_TID pid, int PID_ID) { running = runtimeline.notify_pid_end(pid, PID_ID); }
	void notify_tid_end(PID_TID tid) { runtimeline.notify_thread_end(getPID(), get_piddata()->randID, tid); }
	bool insert_new_thread(PID_TID TID, PLOTTEDGRAPH_CASTPTR graph_plot, PROTOGRAPH_CASTPTR graph_proto);

	void *get_first_graph();
	bool getStartedTime(time_t *result) { return runtimeline.getFirstEventTime(result); }

	void getPlottedGraphs(void *graphPtrVecPtr);
	void getProtoGraphs(void *graphPtrVecPtr);
	bool isRunning() { return running; }
	void setBinaryPtr(BINARYTARGETPTR binptr) { binaryPtr = binptr; }
	int countDescendants();
	
	bool load(const rapidjson::Document& saveJSON, vector<QColor> *colours);
	void serialiseThreads(rapidjson::Writer<rapidjson::FileWriteStream> *writer);
	void serialiseTimeline(rapidjson::Writer<rapidjson::FileWriteStream> *writer) { runtimeline.serialise(writer); };
	void killTree();


	CRITICAL_SECTION graphsListCritsec;
	map <PID_TID, PROTOGRAPH_CASTPTR> protoGraphs;
	map <PID_TID, PLOTTEDGRAPH_CASTPTR> plottedGraphs;

	traceRecord *parentTrace = NULL;
	list<traceRecord *> children;
	bool UIRunningFlag = false;
	void *processThreads;

private:
	bool loadProcessData(const rapidjson::Document& saveJSON);
	bool loadProcessGraphs(const rapidjson::Document& saveJSON, vector<QColor> *colours);
	bool loadGraph(const rapidjson::Value& graphData, vector<QColor> *colours);
	bool loadTimeline(const rapidjson::Value& saveJSON);


	timeline runtimeline;
	BINARYTARGETPTR binaryPtr = NULL;
	bool running = false;
	PROCESS_DATA *processdata;
};