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


#ifdef WIN32
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

	return false;
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
bool getSavePath(string saveDir, string filename, string *result, int PID)
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
bool get_dr_path(VISSTATE *clientState, string *path)
{
	string DRPath = clientState->config->DRDir;
#ifdef X86_32
	DRPath.append("bin32\\drrun.exe");
#elif X86_64
	DRPath.append("bin64\\drrun.exe");
#endif
	if (!fileExists(DRPath.c_str()))
	{
		cerr << "[rgat] ERROR: Failed to find DynamoRIO executable at " << DRPath << " listed in config file" << endl;

		string modPathDR = getModulePath();
		modPathDR.append("\\DynamoRIO\\bin32\\drrun.exe");
		if ((modPathDR != DRPath) && fileExists(modPathDR))
		{
			DRPath = modPathDR;
			cerr << "[rgat] Found DynamoRIO executable at " << DRPath << ", continuing..." << endl;
		}
		else
		{
			cerr << "[rgat]ERROR: Failed to find DynamoRIO executable at " << modPathDR << endl;
			return false;
		}
	}

	string DRGATpath = clientState->config->clientPath + "drgat.dll";
	if (!fileExists(DRGATpath.c_str()))
	{
		cerr << "Unable to find drgat.dll at " << DRGATpath << " listed in config file" << endl;
		string drgatPath2 = getModulePath();
		drgatPath2.append("\\drgat.dll");
		if ((drgatPath2 != DRGATpath) && fileExists(drgatPath2))
		{
			DRGATpath = drgatPath2;
			cerr << "[rgat] Succeeded in finding drgat.dll at " << drgatPath2 << endl;
		}
		else
		{
			cerr << "[rgat] Failed to find drgat.dll " << drgatPath2 << endl;
			return false;
		}
	}

	string drrunArgs = " -c ";
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

void execute_tracer(string executable, string args, void *clientState_ptr) 
{
	if (executable.empty()) return;

	VISSTATE *clientState = (VISSTATE *)clientState_ptr;
	string runpath;
	if (!get_dr_path(clientState, &runpath)) return;
	runpath.append(get_options(clientState));
	runpath = runpath + " -- \"" + executable + "\" "+args;

	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	cout << "[rgat]Starting execution using command line [" << runpath << "]" << endl;
	CreateProcessA(NULL, (char *)runpath.c_str(), NULL, NULL, false, 0, NULL, NULL, &si, &pi);
	clientState->switchProcess = true;
}
#endif // WIN32