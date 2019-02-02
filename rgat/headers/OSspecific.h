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
Need to migrate all Windows API (and -soon- Linux) routines here
*/
#pragma once
#include <stdafx.h>

#include "clientConfig.h"
#include "locks.h"
#include "traceConstants.h"


enum eExeCheckResult { eNotInitialised, eNotExecutable, eBinary32Bit, eBinary64Bit, eBinaryOther };

string getModulePath();
PID_TID getParentPID(PID_TID childPid);
eExeCheckResult check_excecutable_type(string executable);

bool get_bbcount_path_dynamorio(clientConfig &config, LAUNCHOPTIONS &launchopts, string &path, bool is64Bits, string libName);
bool get_bbcount_path_pin(clientConfig &config, LAUNCHOPTIONS &launchopts, string &path, bool is64Bits);
bool get_drdir_path(clientConfig &config, boost::filesystem::path &drpath);
bool get_pindir_path(clientConfig &config, boost::filesystem::path &pinpath);
bool get_dr_drgat_commandline(clientConfig &config, LAUNCHOPTIONS &launchopts, string &path, bool is64Bits);
bool get_pin_pingat_commandline(clientConfig &config, LAUNCHOPTIONS &launchopts, string &path, bool is64Bits, boost::filesystem::path tmpDir);

bool createHandleInProcess(PID_TID targetpid, HANDLE localhandle, HANDLE &remotehandle);
bool createInputOutputPipe(PID_TID pid, wstring pipepath, HANDLE &localHandle, HANDLE &remoteHandle);
bool createInputPipe(PID_TID pid, wstring pipepath, HANDLE &localHandle, HANDLE &remoteHandle, DWORD inputsize = 65336);
bool createOutputPipe(PID_TID pid, wstring pipepath, HANDLE &localHandle, HANDLE &remoteHandle);

bool createTempDir(boost::filesystem::path &tmpPath);
