#pragma once
#include <stdafx.h>

string getModulePath();
string get_dr_path();
bool fileExists(string path);
void execute_tracer(string executable, void *clientState);
bool getSavePath(string saveDir, string filename, string *result, int PID);
bool obtainMutex(HANDLE mutex, int waitTime);
void dropMutex(HANDLE mutex);