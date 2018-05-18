/*
Copyright 2016-2017 Nia Catlin

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
Class that is notified of and records thread/process stops/starts
Intended to be used to provide a visualisation
*/
#pragma once

#include "traceConstants.h"
#include "locks.h"

#include <rapidjson\document.h>
#include <rapidjson\filewritestream.h>
#include <rapidjson\writer.h>
#include <rapidjson\filereadstream.h>
#include <rapidjson\reader.h>

enum eTimelineEvent { eProcessCreate, eProcessTerminate, eThreadCreate, eThreadTerminate};

struct processEvent {
	eTimelineEvent eventType;
	time_t eventTime;
	PID_TID PID, parentPID;
	int PID_ID;
	PID_TID TID;
};

class timeline
{
public:
	timeline();
	~timeline();
	void notify_new_pid(PID_TID pid, int PID_ID, PID_TID parentPID);
	void notify_new_thread(PID_TID pid, int PID_ID, PID_TID tid);
	bool notify_pid_end(PID_TID pid, int PID_ID);
	void notify_thread_end(PID_TID pid, int PID_ID, PID_TID tid);
	unsigned int numLiveThreads() {return liveThreads;}
	unsigned int numLiveProcesses() { return liveProcesses; }
	bool activeProcessCount() { return liveProcesses; }
	bool getFirstEventTime(time_t *result);
	void serialise(rapidjson::Writer<rapidjson::FileWriteStream> &writer);
	bool unserialise(const rapidjson::Value& timelineJSONData);
	bool unserialiseEvent(const rapidjson::Value& eventData);
	
private:
	unsigned int liveProcesses = 0;
	unsigned int liveThreads = 0;

	vector <pair<PID_TID,int>> pidlist;
	vector<processEvent> eventLog;
	rgatlocks::UntestableLock logLock;
};

