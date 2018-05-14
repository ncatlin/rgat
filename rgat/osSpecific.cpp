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


#ifdef _WINDOWS
#include <Windows.h>
#include <Shlwapi.h>
#include <TlHelp32.h>

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

//get command line string of dr executable + client dll + options
bool get_dr_drgat_commandline(clientConfig &config, LAUNCHOPTIONS &launchopts, string &path, bool is64Bits)
{
	//get dynamorio exe from path in settings
	//todo: check this works with spaces in the path
	boost::filesystem::path DRPath = config.DRDir;
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
	boost::filesystem::path drgatPath = config.clientPath;
	if (is64Bits)
		drgatPath += "drgat64";
	else
		drgatPath += "drgat";

	if (launchopts.debugLogging)
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

		if (launchopts.debugLogging)
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

	if (launchopts.pause)
		finalCommandline << " -msgbox_mask 15 ";

	string drrunArgs = " -thread_private "; //todo: allow user to tweak dr options
	//string drrunArgs = " -debug -thread_private "; //todo: allow user to tweak dr options

	finalCommandline << drrunArgs;

	finalCommandline << "-c \"" << drgatPath.string() << "\"";

	path = finalCommandline.str();
	return true;
}

bool get_drdir_path(clientConfig &config, boost::filesystem::path &drpath)
{
	drpath = config.DRDir;
	
	if (boost::filesystem::exists(drpath))
		return true;

	drpath = boost::filesystem::path(getModulePath() + "\\DynamoRIO");
	if (!boost::filesystem::exists(drpath))
		return false;

	config.DRDir = drpath;
	config.saveConfig();
	return true;
}

bool get_pindir_path(clientConfig &config, boost::filesystem::path &pinpath)
{
	pinpath = config.PinDir;

	//if (boost::filesystem::exists(*pinpath))
	//	return true;

	pinpath = boost::filesystem::path(getModulePath() + "\\Pin");
	if (!boost::filesystem::exists(pinpath))
	{
		//leave here until pin in release dir
		//*pinpath = boost::filesystem::path("C:\\devel\\libs\\pin-3.2");
		pinpath = boost::filesystem::path("C:\\devel\\libs\\pin-3.6");
		if (!boost::filesystem::exists(pinpath))
			return false;
	}

	config.PinDir = pinpath;
	config.saveConfig();
	return true;
}


//get command line string of pin executable + client dll + options
bool get_pin_pingat_commandline(clientConfig &config, LAUNCHOPTIONS &launchopts, string &path, bool is64Bits, boost::filesystem::path tmpDir)
{
	//get dynamorio exe from path in settings
	//todo: check this works with spaces in the path
	boost::filesystem::path PINPath = config.PinDir;
	PINPath.append("pin.exe");

	//not there - try finding it in rgats directory
	if (!boost::filesystem::exists(PINPath))
	{
		cerr << "[rgat] ERROR: Failed to find pin executable at " << PINPath << " listed in config file" << endl;

		boost::filesystem::path modPathPin = getModulePath() + "\\pin\\pin.exe";
		if ((modPathPin != PINPath) && boost::filesystem::exists(modPathPin))
		{
			PINPath = modPathPin;
			cout << "[rgat] Found pin executable at " << PINPath << ", continuing..." << endl;
		}
		else
		{
			cerr << "[rgat]ERROR: Also failed to find DynamoRIO executable at default " << modPathPin << endl;
			return false;
		}
	}

	//get the rgat instrumentation client
	boost::filesystem::path pingatPath = config.clientPath;
	if (is64Bits)
		pingatPath += "pingat64";
	else
		pingatPath += "pingat";

	if (launchopts.debugLogging)
		pingatPath += "-debug";
	pingatPath += ".dll";

	if (!boost::filesystem::exists(pingatPath))
	{
		cerr << "Unable to find pingat dll at " << pingatPath << " listed in config file" << endl;
		string pingatPath2 = getModulePath();

		if (is64Bits)
			pingatPath2 += "\\pingat64";
		else
			pingatPath2 += "\\pingat";

		if (launchopts.debugLogging)
			pingatPath2 += "-debug";

		pingatPath2 += ".dll";

		if ((pingatPath2 != pingatPath) && boost::filesystem::exists(pingatPath2))
		{
			pingatPath = pingatPath2;
			cout << "[rgat] Succeeded in finding pingat dll at " << pingatPath2 << endl;
		}
		else
		{
			cerr << "[rgat] Failed to find pingat dll in default path " << pingatPath2 << endl;
			return false;
		}
	}


	stringstream finalCommandline;
	finalCommandline << PINPath.string();	

	if (launchopts.pause)
		finalCommandline << " -pause_tool 25 ";

	string pinArgs = "";// " -thread_private "; //todo: allow user to tweak dr options
						//string drrunArgs = " -debug -thread_private "; //todo: allow user to tweak dr options
	finalCommandline << pinArgs;

	finalCommandline << " -t \"" << pingatPath.string() << "\"";
	finalCommandline << " -D " << tmpDir << " ";

	path = finalCommandline.str();
	return true;
}


bool get_bbcount_path(clientConfig &config, LAUNCHOPTIONS &launchopts, string &path, bool is64Bits, string sampleName)
{
	boost::filesystem::path dynamoRioPath;
	if (!get_drdir_path(config, dynamoRioPath))
	{
		cerr << "[rgat] Failed to find dynamorio directory." << endl;
		return false;
	}

	boost::filesystem::path drrunPath = dynamoRioPath;
	if (is64Bits)
		drrunPath.append("bin64\\drrun.exe");
	else
		drrunPath.append("bin32\\drrun.exe");

	//not there - try finding it in rgats directory
	if (!boost::filesystem::exists(drrunPath))
	{
		cerr << "[rgat] ERROR: Failed to find DynamoRIO drrun.exe executable" << endl;
		return false;
	}

	//get the rgat instrumentation client
	boost::filesystem::path samplePath = dynamoRioPath;
	if (is64Bits)
		samplePath += "samples\\bin64\\" + sampleName + ".dll";
	else
		samplePath += "samples\\bin32\\" + sampleName + ".dll";

	stringstream finalCommandline;
	finalCommandline << drrunPath.string();

	finalCommandline << " -debug -c \"" << samplePath.string() << "\"";

	path = finalCommandline.str();
	return true;
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

bool createHandleInProcess(PID_TID targetpid, HANDLE localhandle, HANDLE &remotehandle)
{
	HANDLE thisprocess = OpenProcess(PROCESS_DUP_HANDLE, false, GetCurrentProcessId());
	HANDLE thatprocess = OpenProcess(PROCESS_DUP_HANDLE, false, targetpid);

	return DuplicateHandle(thisprocess, localhandle, thatprocess, &remotehandle, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
}

bool createInputOutputPipe(PID_TID pid, wstring pipepath, HANDLE &localHandle, HANDLE &remoteHandle)
{
	localHandle = CreateNamedPipe(pipepath.c_str(),
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE,
		255, 65536, 65536, 0, NULL);

	HANDLE pipeOtherEnd = CreateFile(pipepath.c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);

	if (localHandle == INVALID_HANDLE_VALUE || pipeOtherEnd == INVALID_HANDLE_VALUE)
	{
		cerr << "[rgat]createInputPipe failed with error " << GetLastError() << endl;
		return false;
	}

	if (!createHandleInProcess(pid, pipeOtherEnd, remoteHandle))
	{
		cerr << "Failed to create handles in process " << pid << " err: " << GetLastError() << endl;
		return false;
	}

	return true;
}

bool createInputPipe(PID_TID pid, wstring pipepath, HANDLE &localHandle, HANDLE &remoteHandle, DWORD inputsize)
{
	localHandle = CreateNamedPipe(pipepath.c_str(),
		PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE,
		255, inputsize, 1, 0, NULL);

	HANDLE pipeOtherEnd = CreateFile(pipepath.c_str(), GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);

	if (localHandle == INVALID_HANDLE_VALUE || pipeOtherEnd == INVALID_HANDLE_VALUE)
	{
		cerr << "[rgat]createInputPipe failed with error " << GetLastError() << endl;
		return false;
	}

	if (!createHandleInProcess(pid, pipeOtherEnd, remoteHandle))
	{
		cerr << "Failed to create handles in process " << pid << " err: " << GetLastError() << endl;
		return false;
	}

	return true;
}

bool createOutputPipe(PID_TID pid, wstring pipepath, HANDLE &localHandle, HANDLE &remoteHandle)
{
	localHandle = CreateNamedPipe(pipepath.c_str(),
		PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE,
		255, 65536, 65536, 0, NULL);

	HANDLE pipeOtherEnd = CreateFile(pipepath.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);

	if (localHandle == INVALID_HANDLE_VALUE || pipeOtherEnd == INVALID_HANDLE_VALUE)
	{
		cerr << "[rgat]createOutputPipe failed with error " << dec << GetLastError() << endl;
		return false;
	}

	if (!createHandleInProcess(pid, pipeOtherEnd, remoteHandle))
	{
		cerr << "Failed to create handles in process " << dec << pid << " err: " << GetLastError() << endl;
		return false;
	}

	return true;
}

bool createTempDir(boost::filesystem::path &tmpPath)
{
	TCHAR lpTempPathBuffer[MAX_PATH];
	bool success = false;

	int attempts = 4;
	while (attempts--)
	{
		DWORD dwRetVal = GetTempPath(MAX_PATH, lpTempPathBuffer);
		if (dwRetVal > MAX_PATH || (dwRetVal == 0))
		{
			continue;
		}

		tmpPath = boost::filesystem::path(lpTempPathBuffer);
		tmpPath += boost::filesystem::unique_path();

		if (!CreateDirectory(tmpPath.wstring().c_str(), NULL))
		{
			continue;
		}
		
		success = true;
		break;
	}

	if (!success)
		tmpPath = "";

	return success;
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
bool getSavePath(boost::filesystem::path saveDir, string filename, string &result, PID_TID PID)
{
	cout << "implement me" << endl;
	return false;
}

//get execution string of dr executable + client dll
bool get_dr_path(VISSTATE &clientState, string &path, bool is64Bits)
{
	cout << "implement me" << endl;
	return false;
}

string get_options(VISSTATE &clientState)
{
	cout << "implement me" << endl;
	return false;
}

char check_excecutable_type(string executable)
{
	cout << "implement me" << endl;
	return 0;
}

#endif // LINUX