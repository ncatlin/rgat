#pragma once

#define PID_CREATE 1
#define PID_DIE 2
#define TID_CREATE 3
#define TID_DIE 4

struct processEvent {
	int eventType;
	double eventTime;
	int PID;
	int TID;
};

class timeline
{
public:
	timeline();
	~timeline();
	void notify_new_pid(unsigned int pid);
	void notify_new_tid(unsigned int pid, unsigned int tid);
	void notify_pid_end(unsigned int pid);
	void notify_tid_end(unsigned int pid, unsigned int tid);
	unsigned int numLiveThreads() {return liveThreads;}
	unsigned int numLiveProcesses() { return liveProcesses; }

private:
	unsigned int liveProcesses = 0;
	unsigned int liveThreads = 0;
	map <int, vector<processEvent *>> pidlist;
	vector<processEvent> creationLog;
	HANDLE accessMutex = CreateMutex(NULL, false, NULL);
};

