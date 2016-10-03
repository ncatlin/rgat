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
Class that is notified of and records thread/process stops/starts
Intended to be used to provide a visualisation
*/
#pragma once

#include <traceStructs.h>

#define PID_CREATE 1
#define PID_DIE 2
#define TID_CREATE 3
#define TID_DIE 4

struct processEvent {
	int eventType;
	double eventTime;
	PID_TID PID;
	PID_TID TID;
};

class timeline
{
public:
	timeline();
	~timeline();
	void notify_new_pid(PID_TID pid);
	void notify_new_tid(PID_TID pid, PID_TID tid);
	void notify_pid_end(PID_TID pid);
	void notify_tid_end(PID_TID pid, PID_TID tid);
	unsigned int numLiveThreads() {return liveThreads;}
	unsigned int numLiveProcesses() { return liveProcesses; }

private:
	unsigned int liveProcesses = 0;
	unsigned int liveThreads = 0;
	map <int, vector<processEvent *>> pidlist;
	vector<processEvent> creationLog;
	HANDLE accessMutex = CreateMutex(NULL, false, NULL);
};

