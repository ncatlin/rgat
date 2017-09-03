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
Header for the fuzzing framework
*/
#include "stdafx.h"
#include "fuzzRun.h"
#include "OSspecific.h"
#include "rgat.h"
#include "processLaunching.h"
#include "boost/process.hpp"

//----------
//the ui elements of fuzz updating
void mainTabBox::fuzzUpdateCheck()
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	for each (fuzzRun* session in fuzzruns)
	{
		FUZZUPDATE *entry = session->getUpdate();
		if (!entry) continue;

		QTextCursor text_cursor;
		switch (entry->code)
		{
		case fUpdateCode::eFU_String:
			text_cursor = QTextCursor(ui->fuzzOutput->document());
			text_cursor.movePosition(QTextCursor::End);
			text_cursor.insertText(QString::fromStdString(entry->details) + "\n");
			break;

		case fUpdateCode::eFU_NewThread:
			text_cursor = QTextCursor(ui->fuzzOutput->document());
			text_cursor.movePosition(QTextCursor::End);
			text_cursor.insertText(QString::fromStdString("New thread spawned!") + "\n");
			break;
		}

		delete entry;
	}
}

void mainTabBox::startFuzz()
{
	if (!fuzzThreadLauncherRunning)
	{
		std::thread fuzzThreadLauncher(process_coordinator_thread, clientState, eTracePurpose::eFuzzer);
		fuzzThreadLauncher.detach();
		fuzzThreadLauncherRunning = true;
	}

	binaryTarget *activeTarget = clientState->activeBinary;
	if (!activeTarget)
	{
		cerr << " No target to fuzz... ignoring" << endl;
		return;
	}

	fuzzRun *testingRun = new fuzzRun(activeTarget);
	fuzzruns.push_back(testingRun);

	testingRun->begin();

	if (!fuzzUpdateTimer)
	{
		fuzzUpdateTimer = new QTimer(this);
		connect(fuzzUpdateTimer, &QTimer::timeout, this, &mainTabBox::fuzzUpdateCheck);
		fuzzUpdateTimer->start(250);
	}


}
//-----------------------------


fuzzRun::fuzzRun(binaryTarget *targetptr)
	: base_thread()
{
	binary = targetptr;
}


fuzzRun::~fuzzRun()
{
}


FUZZUPDATE *fuzzRun::getUpdate()
{
	if (updateQ.empty()) return NULL;

	QMutex.lock();

	FUZZUPDATE *result = updateQ.front();
	updateQ.pop();

	QMutex.unlock();

	return result;
}

void fuzzRun::addUpdate(FUZZUPDATE *entry)
{
	QMutex.lock();

	updateQ.push(entry);

	QMutex.unlock();
}

void fuzzRun::launch_target(boost::filesystem::path drrunpath, boost::filesystem::path shrikepath)
{
	runID = rand();
	clientState->addFuzzRun(runID, this);

	stringstream runpath_ss;
	runpath_ss << drrunpath.string();
	runpath_ss << " -debug -thread_private -c ";
	runpath_ss << "\"" << shrikepath.string() << "\" -ID "<< runID;

	//	runpath_ss << " -stage1";

	runpath_ss << "	-- " << binary->path();

	FUZZUPDATE *entry = new FUZZUPDATE;
	entry->code = fUpdateCode::eFU_String;

	boost::process::spawn(runpath_ss.str());
	entry->details = "Started target using command line " + runpath_ss.str();
	addUpdate(entry);
}

void fuzzRun::main_loop()
{
	//gather options
	boost::filesystem::path dynamoRioPath;
	if (!getDRPath(&clientState->config, &dynamoRioPath)) {
		cerr << "[rgat] Failed to find dynamorio directory." << endl;
		return;
	}

	boost::filesystem::path drrunPath = dynamoRioPath;
	if (binary->getBitWidth() == 64)
		drrunPath.append("bin64\\drrun.exe");
	else
		drrunPath.append("bin32\\drrun.exe");

	if (!boost::filesystem::exists(drrunPath))	{
		cerr << "[rgat] ERROR: Failed to find DynamoRIO drrun.exe executable at " << drrunPath.string() << endl;
		return;
	}

	boost::filesystem::path shrikepath("C:\\Users\\nia\\Source\\Repos\\shrike\\x64\\Debug\\shrike.dll");
	if (!boost::filesystem::exists(shrikepath))	{
		cerr << "shrike.dll library at " << shrikepath.string() << " does not exist. Quitting." << endl;
		return;
	}


	launch_target(drrunPath, shrikepath);


	while (true)
	{
		
		while (!targetProcess)
		{
			Sleep(10);
		}
		cout << "got process! " << targetProcess->getPID() << endl;

		bool targetActive = true;
		while (targetActive)
		{//I/O

			Sleep(100);
		}
	}
}

void fuzzRun::begin()
{
	std::thread fuzz_thread(&fuzzRun::ThreadEntry, this);
	fuzz_thread.detach();
}

void fuzzRun::notify_new_thread(PID_TID threadID)
{
	FUZZUPDATE *entry = new FUZZUPDATE;
	entry->code = fUpdateCode::eFU_NewThread;
	entry->details = "newthread";
	addUpdate(entry);


}


void fuzzRun::target_connected(traceRecord* trace)
{
	trace->fuzzRunPtr = this;
	targetProcess = trace;
}