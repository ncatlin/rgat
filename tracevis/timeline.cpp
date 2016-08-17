#include "stdafx.h"
#include "timeline.h"
#include "traceMisc.h"

timeline::timeline()
{
}


timeline::~timeline()
{
}

void timeline::notify_pid_end(unsigned int pid)
{
	if (!pidlist.count(pid))
	{
		printf("ERROR: UNKNOWN PID\n");
		return;
	}
	processEvent ev;
	ev.eventType = PID_DIE;
	ev.eventTime = al_get_time();
	creationLog.push_back(ev);
}

void timeline::notify_new_pid(unsigned int pid) 
{
	if (pidlist.count(pid))
	{
		printf("ERROR: DUPLICATE PID. TODO UNIQUE IDENTIFIERS!\n");
		assert(false);
		return;
	}
	processEvent ev;
	ev.eventType = PID_CREATE;
	ev.eventTime = al_get_time();
	creationLog.push_back(ev);
	pidlist[pid];
}

void timeline::notify_new_tid(unsigned int pid, unsigned int tid) 
{
	obtainMutex(accessMutex, "TL TID START", 1000);
	processEvent ev;
	ev.eventType = TID_CREATE;
	ev.eventTime = al_get_time();
	ev.PID = pid;
	ev.TID = tid;
	creationLog.push_back(ev);
	pidlist[pid].push_back(&ev);
	ReleaseMutex(accessMutex);
}

void timeline::notify_tid_end(unsigned int pid, unsigned int tid)
{
	obtainMutex(accessMutex, "TL TID END", 1000);
	processEvent ev;
	ev.eventType = TID_DIE;
	ev.eventTime = al_get_time();
	ev.PID = pid;
	ev.TID = tid;
	creationLog.push_back(ev);
	ReleaseMutex(accessMutex);
}