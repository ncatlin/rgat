#pragma once

class base_thread
{
public:
	base_thread(int thisPID, int thisTID) { PID = thisPID; TID = thisTID; }
	void kill() { die = true; }
	bool is_alive() { return alive; }

	static void __stdcall ThreadEntry(void* pUserData) {
		return ((base_thread*)pUserData)->main_loop();
	}
	virtual void main_loop() {};

protected:
	int PID;
	int TID;
	bool die = false;
	bool alive = false;	
};



