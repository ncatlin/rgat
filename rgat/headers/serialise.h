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
Graph/Process Saving/Loading routines
*/

#pragma once
#include "stdafx.h"
#include "traceStructs.h"
#include "traceMisc.h"
#include "rgatState.h"

#include <rapidjson\writer.h>
#include <boost\filesystem.hpp>

void saveTargetData(PROCESS_DATA *piddata, rapidjson::Writer<rapidjson::FileWriteStream>& writer);

FILE * setupSaveFile(clientConfig *config, traceRecord *trace);
wstring time_string(time_t startedTime);
boost::filesystem::path getSaveFilename(boost::filesystem::path binaryFilename, time_t startedTime, PID_TID PID);
bool getSavePath(boost::filesystem::path saveDir, boost::filesystem::path saveFilename, boost::filesystem::path *result);
bool getJSON(boost::filesystem::path traceFilePath, rapidjson::Document *saveJSON);

