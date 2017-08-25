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
This is intended to be the location for OS abstractions
Need to migrate all Windows API (and soon Linux) routines here
*/
#pragma once 
#include <stdafx.h>
#include "OSspecific.h"
#include "binaryTarget.h"

#include <boost\filesystem.hpp>




#ifdef _WINDOWS
#include <Windows.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
//#pragma comment(lib, "shlwapi.lib")

//this is needed for building timelines. it would be good to get drgat to pass the parent PID
//along but I don't think dynamorio can do this so we are stuck with it
//https://gist.github.com/mattn/253013/d47b90159cf8ffa4d92448614b748aa1d235ebe4
PID_TID getParentPID(PID_TID childPid)
{

		HANDLE hSnapshot = INVALID_HANDLE_VALUE;
		PROCESSENTRY32 pe32;
		PID_TID ppid = 0;

		hSnapshot = CreateToolhelp32Snapshot(0x2, 0);// TH32CS_SNAPPROCESS
		__try {
			if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

			ZeroMemory(&pe32, sizeof(pe32));
			pe32.dwSize = sizeof(pe32);
			if (!Process32First(hSnapshot, &pe32)) __leave;

			do {
				if (pe32.th32ProcessID == childPid) {
					ppid = pe32.th32ParentProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &pe32));

		}
		__finally {
			if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
		}
		return ppid;
}

/*
can't use boost::shared_mutex because it performs awfully on linux
https://svn.boost.org/trac10/ticket/11798
*/

//gets path the rgat executable is located in
string getModulePath()
{
	CHAR buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	return string(buffer).substr(0, pos);
}

//get execution string of dr executable + client dll
bool get_dr_path(clientConfig *config, LAUNCHOPTIONS *launchopts, string *path, bool is64Bits)
{
	//get dynamorio exe from path in settings
	//todo: check this works with spaces in the path
	boost::filesystem::path DRPath = config->DRDir;
	boost::filesystem::path DRPathEnd;
	if (is64Bits)
		DRPathEnd.append("bin64\\drrun.exe");
	else
		DRPathEnd.append("bin32\\drrun.exe");

	DRPath += DRPathEnd;

	//not there - try finding it in rgats directory
	if (!boost::filesystem::exists(DRPath))
	{
		cerr << "[rgat] ERROR: Failed to find DynamoRIO executable at " << DRPath << " listed in config file" << endl;

		boost::filesystem::path modPathDR = getModulePath() + "\\DynamoRIO\\";
		modPathDR += DRPathEnd;
		if ((modPathDR != DRPath) && boost::filesystem::exists(modPathDR))
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

	//get the rgat instrumentation client
	boost::filesystem::path drgatPath = config->clientPath;
	if (is64Bits)
		drgatPath += "drgat64";
	else
		drgatPath += "drgat";

	if (launchopts->debugLogging)
		drgatPath += "-debug";
	drgatPath += ".dll";

	if (!boost::filesystem::exists(drgatPath))
	{
		cerr << "Unable to find drgat dll at " << drgatPath << " listed in config file" << endl;
		string drgatPath2 = getModulePath();

		if (is64Bits)
			drgatPath2 += "\\drgat64";
		else
			drgatPath2 += "\\drgat";

		if (launchopts->debugLogging)
			drgatPath2 += "-debug";
		drgatPath2 += ".dll";

		if ((drgatPath2 != drgatPath) && boost::filesystem::exists(drgatPath2))
		{
			drgatPath = drgatPath2;
			cout << "[rgat] Succeeded in finding drgat dll at " << drgatPath2 << endl;
		}
		else
		{
			cerr << "[rgat] Failed to find drgat dll in default path " << drgatPath2 << endl;
			return false;
		}
	}


	stringstream finalCommandline;
	finalCommandline << DRPath.string();

	if (launchopts->pause)
		finalCommandline << " -msgbox_mask 15 ";

	string drrunArgs = " -thread_private "; //todo: allow user to tweak dr options
	//string drrunArgs = " -debug -thread_private "; //todo: allow user to tweak dr options

	finalCommandline << drrunArgs;

	finalCommandline << "-c \"" << drgatPath.string() << "\"";

	*path = finalCommandline.str();
	return true;
}

bool get_bbcount_path(clientConfig *config, LAUNCHOPTIONS *launchopts, string *path, bool is64Bits, string sampleName)
{
	//get dynamorio exe from path in settings
	//todo: check this works with spaces in the path
	boost::filesystem::path DRBase = config->DRDir;
	boost::filesystem::path DRConfigRunPath = DRBase;
	boost::filesystem::path DRPathEnd;
	if (is64Bits)
		DRPathEnd.append("bin64\\drrun.exe");
	else
		DRPathEnd.append("bin32\\drrun.exe");

	DRConfigRunPath += DRPathEnd;

	//not there - try finding it in rgats directory
	if (!boost::filesystem::exists(DRConfigRunPath))
	{
		cerr << "[rgat] ERROR: Failed to find DynamoRIO executable at " << DRConfigRunPath << " listed in config file" << endl;

		DRBase = boost::filesystem::path(getModulePath() + "\\DynamoRIO");
		boost::filesystem::path DRModRunPath(DRBase);
		if (is64Bits)
			DRModRunPath.append("bin64\\drrun.exe");
		else
			DRModRunPath.append("bin32\\drrun.exe");

		if ((DRModRunPath != DRConfigRunPath) && boost::filesystem::exists(DRModRunPath))
		{
			cout << "[rgat] Found DynamoRIO executable at " << DRModRunPath << ", continuing..." << endl;
			DRConfigRunPath = DRModRunPath;
		}
		else
		{
			cerr << "[rgat]ERROR: Also failed to find DynamoRIO executable at default " << DRModRunPath << endl;
			return false;
		}
	}

	//get the rgat instrumentation client
	boost::filesystem::path samplePath = DRBase;
	if (is64Bits)
		samplePath += "samples\\bin64\\" + sampleName + ".dll";
	else
		samplePath += "samples\\bin32\\" + sampleName + ".dll";

	stringstream finalCommandline;
	finalCommandline << DRConfigRunPath.string();

	finalCommandline << " -c \"" << samplePath.string() << "\"";

	*path = finalCommandline.str();
	return true;
}

string get_options(LAUNCHOPTIONS *launchopts)
{
	stringstream optstring;

	//rgat client options
	if (launchopts->removeSleeps)
		optstring << " -caffine";

	if (launchopts->pause)
		optstring << " -sleep";

	//if (launchopts->debugMode)
	//	optstring << " -blkdebug";
	return optstring.str();
}

eExeCheckResult check_excecutable_type(string executable)
{
	DWORD theType;
	if (!GetBinaryTypeA(executable.c_str(), &theType))
		return eNotExecutable;

	//todo: .NET detection

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

//take the target binary path, feed it into dynamorio with all the required options
void execute_tracer(void *binaryTargetPtr, clientConfig *config)
{
	if (!binaryTargetPtr) return;
	binaryTarget *target = (binaryTarget *)binaryTargetPtr;

	LAUNCHOPTIONS *launchopts = &target->launchopts;
	string runpath;
	if (!get_dr_path(config, launchopts, &runpath, (target->getBitWidth() == 64))) 
		return;

	runpath.append(get_options(launchopts));
	runpath = runpath + " -- \"" + target->path().string() + "\" " + launchopts->args;

	STARTUPINFOA startupinfo;
	ZeroMemory(&startupinfo, sizeof(startupinfo));
	startupinfo.cb = sizeof(startupinfo);

	PROCESS_INFORMATION processinfo;
	ZeroMemory(&processinfo, sizeof(processinfo));

	cout << "[rgat]Starting execution using command line [" << runpath << "]" << endl;
	bool success = CreateProcessA(NULL, (char *)runpath.c_str(), NULL, NULL, false, 0, NULL, NULL, &startupinfo, &processinfo);
	if (!success)
		cerr << "[rgat]ERROR: Failed to execute target. Windows error code: " << GetLastError() << endl;

	CloseHandle(processinfo.hProcess);
	CloseHandle(processinfo.hThread);
}

void execute_dynamorio_test(void *binaryTargetPtr, clientConfig *config)
{
	if (!binaryTargetPtr) return;
	binaryTarget *target = (binaryTarget *)binaryTargetPtr;

	LAUNCHOPTIONS *launchopts = &target->launchopts;
	string runpath;
	if (!get_bbcount_path(config, launchopts, &runpath, (target->getBitWidth() == 64), "bbcount"))
		return;

	runpath = runpath + " -- \"" + target->path().string() + "\" " + launchopts->args;

	STARTUPINFOA startupinfo;
	ZeroMemory(&startupinfo, sizeof(startupinfo));
	startupinfo.cb = sizeof(startupinfo);

	PROCESS_INFORMATION processinfo;
	ZeroMemory(&processinfo, sizeof(processinfo));

	cout << "[rgat]Starting test using command line [" << runpath << "]" << endl;
	bool success = CreateProcessA(NULL, (char *)runpath.c_str(), NULL, NULL, false, 0, NULL, NULL, &startupinfo, &processinfo);
	if (!success)
		cerr << "[rgat]ERROR: Failed to execute target. Windows error code: " << GetLastError() << endl;

	CloseHandle(processinfo.hProcess);
	CloseHandle(processinfo.hThread);
}

void rgat_create_thread(void *threadEntry, void *arg)
{
	DWORD suppressWarningThreadID;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadEntry, (LPVOID)arg, 0, &suppressWarningThreadID);
}


#endif // WIN32

#ifdef LINUX

string time_string()
{
	cout << "implement me" << endl;
	return string("");
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
bool getSavePath(boost::filesystem::path saveDir, string filename, string *result, PID_TID PID)
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