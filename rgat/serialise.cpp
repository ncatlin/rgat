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
#include "stdafx.h"
#include "serialise.h"
#include "OSspecific.h"
#include "graphplots/cylinder_graph.h"
#include "traceRecord.h"
#include "binaryTargets.h"

#include "rapidjson/document.h"
using namespace rapidjson;

bool getJSON(boost::filesystem::path traceFilePath, rapidjson::Document *saveJSON)
{
	FILE* pFile;
	fopen_s(&pFile, traceFilePath.string().c_str(), "rb");
	if (!pFile)
	{
		cerr << "[rgat]Warning: Could not open file for reading. Abandoning Load." << endl;
		return false;
	}

	char buffer[65536];
	rapidjson::FileReadStream is(pFile, buffer, sizeof(buffer));

	saveJSON->ParseStream<0, rapidjson::UTF8<>, rapidjson::FileReadStream>(is);
	fclose(pFile);

	if (!saveJSON->IsObject())
	{
		cerr << "[rgat]Warning: Corrupt file. Abandoning Load." << endl;
		if (saveJSON->HasParseError())
		{
			cerr << "\t rapidjson parse error "<< saveJSON->GetParseError() << " at offset " << saveJSON->GetErrorOffset() << endl;
		}
		return false;
	}
	return true;
}




//if dir doesn't exist in config defined path, create
bool ensureDirExists(string dirname, rgatState *clientState)
{
	return true;
}


FILE * setupSaveFile(clientConfig *config, traceRecord *trace)
{
	binaryTarget *target = (binaryTarget *)trace->get_binaryPtr();
	boost::filesystem::path path;
	boost::filesystem::path filename = getSaveFilename(target->path().filename(), trace->getStartedTime(), trace->getPID());

	if (!getSavePath(config->saveDir, filename,  &path))
	{
		cerr << "[rgat]WARNING: Couldn't save to " << config->saveDir << endl;

		config->saveDir = getModulePath() + "\\saves\\";
		cout << "[rgat]Attempting to use " << config->saveDir << endl;

		if (!getSavePath(config->saveDir, filename, &path))
		{
			cerr << "[rgat]ERROR: Failed to save to path " << config->saveDir << ", giving up." << endl;
			cerr << "[rgat]Add path of a writable directory to CLIENT_PATH in rgat.cfg" << endl;
			return NULL;
		}
		config->updateSavePath(config->saveDir);
	}

	cout << "[rgat]Saving trace " << dec << trace->getPID() << " to " << path << endl;

	FILE *savefile;
	if ((fopen_s(&savefile, path.string().c_str(), "wb") != 0))// non-Windows use "w"?
	{
		cerr << "[rgat]Failed to open " << path << "for writing" << endl;
		return NULL;
	}

	return savefile;
}

wstring time_string(time_t startedTime)
{
	struct tm timedata;
	localtime_s(&timedata, &startedTime);
	wstringstream savetime;
	savetime << timedata.tm_mon + 1 << timedata.tm_mday << "-" << timedata.tm_hour << timedata.tm_min << timedata.tm_sec;
	return savetime.str();
}

boost::filesystem::path getSaveFilename(boost::filesystem::path binaryFilename, time_t startedTime, PID_TID PID)
{
	wstringstream filenameSS;
	filenameSS << binaryFilename.wstring() << "-" << PID << "-" << time_string(startedTime) << ".rgat";
	return boost::filesystem::path(filenameSS.str());
}



//returns path for saving files, tries to create if it doesn't exist
bool getSavePath(boost::filesystem::path saveDir, boost::filesystem::path saveFilename, boost::filesystem::path *result)
{
	//if directory doesn't exist, create
	if (!boost::filesystem::is_directory(saveDir))
	{
		if (!boost::filesystem::create_directory(saveDir))
		{
			cerr << "[rgat]Error: Could not create non-existant directory " << saveDir << endl;
			return false;
		}
	}

	boost::filesystem::path savepath(saveDir);
	savepath /= saveFilename;

	*result = savepath;
	return true;
}


