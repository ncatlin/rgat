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

#include "stdafx.h"
#include "timeline.h"
#include "traceMisc.h"
#include "OSspecific.h"

timeline::timeline()
{
}


timeline::~timeline()
{
}

void timeline::notify_pid_end(PID_TID pid)
{
	if (!pidlist.count(pid))
	{
		cerr<< "[rgat]ERROR: UNKNOWN PID"<<endl;
		return;
	}
	processEvent ev;
	ev.eventType = PID_DIE;
	ev.eventTime = al_get_time();
	creationLog.push_back(ev);
	--liveProcesses;
}

void timeline::notify_new_pid(PID_TID pid)
{
	if (pidlist.count(pid))
	{
		cerr << "[rgat]ERROR: Duplicate PID. TODO: unique identifiers!"<<endl;
		assert(false);
	}
	processEvent ev;
	ev.eventType = PID_CREATE;
	ev.eventTime = al_get_time();
	obtainMutex(accessMutex, 1033);
	creationLog.push_back(ev);
	dropMutex(accessMutex);
	pidlist[pid];
	++liveProcesses;
}

void timeline::notify_new_tid(PID_TID pid, PID_TID tid)
{
	obtainMutex(accessMutex, 1034);
	processEvent ev;
	ev.eventType = TID_CREATE;
	ev.eventTime = al_get_time();
	ev.PID = pid;
	ev.TID = tid;
	creationLog.push_back(ev);
	pidlist[pid].push_back(&ev);
	dropMutex(accessMutex);
	++liveThreads;
}

void timeline::notify_tid_end(PID_TID pid, PID_TID tid)
{
	obtainMutex(accessMutex, 1035);
	processEvent ev;
	ev.eventType = TID_DIE;
	ev.eventTime = al_get_time();
	ev.PID = pid;
	ev.TID = tid;
	creationLog.push_back(ev);
	dropMutex(accessMutex);
	--liveThreads;
}