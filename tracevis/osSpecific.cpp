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
This is intended to be the location for OS abstractions
Need to migrate all Windows API (and soon Linux) routines here
*/
#pragma once 
#include <stdafx.h>
#include "GUIStructs.h"


#ifdef WINDOWS

void renameFile(string originalPath, string targetPath)
{
	MoveFileA(originalPath.c_str(), targetPath.c_str());
}

/*
a lot of the code checks this for success/failure
have changed this to not return until success but leaving this here
in case we want to revert it

prints waitTimeCode in case of failure so use unique time for debugging
*/
bool obtainMutex(HANDLE mutex, int waitTimeCode)
{
	DWORD waitresult;
	do {
		waitresult = WaitForSingleObject(mutex, waitTimeCode);
		if (waitresult != WAIT_TIMEOUT) return true;
		cout << "WARNING! Mutex wait failed after " << std::dec << waitTimeCode << " ms: " << waitresult <<  endl;
	} while (true);
}

bool obtainReadMutex(HANDLE mutex, int waitTimeCode)
{
	DWORD waitresult;
	do {
		waitresult = WaitForSingleObject(mutex, waitTimeCode);
		if (waitresult != WAIT_TIMEOUT) return true;
		cout << "WARNING! Mutex wait failed after " << std::dec << waitTimeCode << " ms: " << waitresult << endl;
	} while (true);
}

void dropMutex(HANDLE mutex) {
	ReleaseMutex(mutex);
}

string time_string()
{
	time_t t = time(0);
	struct tm timenow;
	localtime_s(&timenow, &t);
	stringstream savetime;
	savetime << timenow.tm_mon+1 << timenow.tm_mday << "-" << timenow.tm_hour << timenow.tm_min << timenow.tm_sec;
	return savetime.str();
}

bool fileExists(string path)
{
	wstring wstrpath(path.begin(), path.end());
	return PathFileExists(wstrpath.c_str());
}

//gets path rgat executable is located in
string getModulePath()
{
	CHAR buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	return string(buffer).substr(0, pos);
}

//get filename from path
//http://stackoverflow.com/a/8520815
string basename(string path)
{
	const size_t last_slash_idx = path.find_last_of("\\/");
	if (std::string::npos != last_slash_idx)
		path.erase(0, last_slash_idx + 1);
	return path;
}

//returns path for saving files, tries to create if it doesn't exist
bool getSavePath(string saveDir, string filename, string *result, PID_TID PID)
{
	//if directory doesn't exist, create
	if (!fileExists(saveDir.c_str()))
		if (!CreateDirectoryA(saveDir.c_str(), NULL))
		{
			cerr << "[rgat]Error: Could not create non-existant directory " << saveDir << endl;
			return false;
		}

	stringstream savepath;
	savepath << saveDir << basename(filename) <<"-"<< PID <<"-"<< time_string() << ".rgat";
	*result = savepath.str();
	return true;
}

//get execution string of dr executable + client dll
bool get_dr_path(VISSTATE *clientState, string *path, bool is64Bits)
{
	string DRPathDir = clientState->config->DRDir;
	string DRPathEnd;
	if (is64Bits)
		DRPathEnd.append("bin64\\drrun");
	else
		DRPathEnd.append("bin32\\drrun");

	DRPathEnd.append(".exe");

	string DRPath = DRPathDir + DRPathEnd;
	if (!fileExists(DRPath.c_str()))
	{
		cerr << "[rgat] ERROR: Failed to find DynamoRIO executable at " << DRPath << " listed in config file" << endl;

		string modPathDR = getModulePath() + "\\DynamoRIO\\" + DRPathEnd;
		if ((modPathDR != DRPath) && fileExists(modPathDR))
		{
			DRPath = modPathDR;
			cout << "[rgat] Found DynamoRIO executable at " << DRPath << ", continuing..." << endl;
		}
		else
		{
			cerr << "[rgat]ERROR: Also failed to find DynamoRIO executable at default " << modPathDR << endl;
			return false;
		}
	}

	string DRGATpath;
	if (is64Bits)
		DRGATpath = clientState->config->clientPath + "drgat64";
	else
		DRGATpath = clientState->config->clientPath + "drgat";

	if (clientState->launchopts.debugLogging)
		DRGATpath = DRGATpath + "-debug";
	DRGATpath = DRGATpath + ".dll";


	if (!fileExists(DRGATpath.c_str()))
	{
		cerr << "Unable to find drgat dll at " << DRGATpath << " listed in config file" << endl;
		string drgatPath2 = getModulePath();

		if (is64Bits)
			drgatPath2.append("\\drgat64");
		else
			drgatPath2.append("\\drgat");
		if (clientState->launchopts.debugLogging)
			drgatPath2 = drgatPath2 + "-debug";
		drgatPath2 = drgatPath2 + ".dll";

		if ((drgatPath2 != DRGATpath) && fileExists(drgatPath2))
		{
			DRGATpath = drgatPath2;
			cerr << "[rgat] Succeeded in finding drgat dll at " << drgatPath2 << endl;
		}
		else
		{
			cerr << "[rgat] Failed to find drgat dll in default path " << drgatPath2 << endl;
			return false;
		}
	}

	string drrunArgs = " -thread_private -c ";
	string retstring = DRPath;
	if (clientState->launchopts.pause)
		retstring.append(" -msgbox_mask 15 ");

	retstring.append(drrunArgs);
	retstring.append(DRGATpath);
	*path = retstring;
	return true;
}

string get_options(VISSTATE *clientState)
{
	stringstream optstring;
	if (clientState->launchopts.caffine)
		optstring << " -caffine";

	if (clientState->launchopts.pause)
		optstring << " -sleep";

	if (clientState->launchopts.debugMode)
		optstring << " -blkdebug";

	return optstring.str();
}

eExeCheckResult check_excecutable_type(string executable)
{
	DWORD theType;
	if (!GetBinaryTypeA(executable.c_str(), &theType))
		return eNotExecutable;

	switch (theType)
	{
	case SCS_32BIT_BINARY:
		return eBinary32Bit;
	case SCS_64BIT_BINARY:
		return eBinary64Bit;
	default:
		return eBinaryOther;
	}
}

void execute_tracer(string executable, string args, void *clientState_ptr, bool is64Bits)
{
	if (executable.empty()) return;

	VISSTATE *clientState = (VISSTATE *)clientState_ptr;
	string runpath;
	
	if (!get_dr_path(clientState, &runpath, is64Bits)) return;

	runpath.append(get_options(clientState));
	runpath = runpath + " -- \"" + executable + "\" "+args;

	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	cout << "[rgat]Starting execution using command line [" << runpath << "]" << endl;
	if (CreateProcessA(NULL, (char *)runpath.c_str(), NULL, NULL, false, 0, NULL, NULL, &si, &pi))
		clientState->switchProcess = true;
	else
		cerr << "[rgat]ERROR: Failed to execute target, error: " << GetLastError() << endl;

	CloseHandle(pi.hProcess);

}

void rgat_create_thread(void *threadEntry, void *arg)
{
	DWORD suppressWarningThreadID;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadEntry, (LPVOID)arg, 0, &suppressWarningThreadID);
}


#endif // WIN32

#ifdef LINUX
void renameFile(string originalPath, string targetPath)
{
	cout << "implement me" << endl;
}

/*
a lot of the code checks this for success/failure
have changed this to not return until success but leaving this here
in case we want to revert it

prints waitTimeCode in case of failure so use unique time for debugging
*/
bool obtainMutex(HANDLE mutex, int waitTimeCode)
{
	cout << "implement me" << endl;
	return false;
}

bool obtainReadMutex(HANDLE mutex, int waitTimeCode)
{
	cout << "implement me" << endl;
	return false;
}

void dropMutex(HANDLE mutex) {
	cout << "implement me" << endl;
}

string time_string()
{
	cout << "implement me" << endl;
	return string("");
}

bool fileExists(string path)
{
	cout << "implement me" << endl;
	return false;
}

//gets path rgat executable is located in
string getModulePath()
{
	cout << "implement me" << endl;
	return string("");
}

//get filename from path
//http://stackoverflow.com/a/8520815
string basename(string path)
{
	cout << "implement me" << endl;
	return string("");
}

//returns path for saving files, tries to create if it doesn't exist
bool getSavePath(string saveDir, string filename, string *result, PID_TID PID)
{
	cout << "implement me" << endl;
	return false;
}

//get execution string of dr executable + client dll
bool get_dr_path(VISSTATE *clientState, string *path, bool is64Bits)
{
	cout << "implement me" << endl;
	return false;
}

string get_options(VISSTATE *clientState)
{
	cout << "implement me" << endl;
	return false;
}

char check_excecutable_type(string executable)
{
	cout << "implement me" << endl;
	return 0;
}

void execute_tracer(string executable, string args, void *clientState_ptr, bool is64Bits)
{
	cout << "implement me" << endl;
}

void rgat_create_thread(void *threadEntry, void *arg)
{
	cout << "implement me" << endl;
}


#endif // LINUX