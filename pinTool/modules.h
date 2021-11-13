#pragma once

#include "pin.H"
#include "utilities.h"

bool module_should_be_instrumented(std::string path);

struct moduleData
{
	ADDRINT start, end;
	bool instrumented;
	std::string name;
	INT32 ID;
};

struct regionData
{
	ADDRINT start, end;
	bool instrumented;
};

bool writeEventPipe(char *logText, ...);
void setCommandPipe(NATIVE_FD newpipe);
void setEventPipe(NATIVE_FD newpipe);
OS_RETURN_CODE readCommandPipe(VOID *resultbuf, USIZE *ptrsize);

void getModuleIncludeLists();

extern std::vector <moduleData *> loadedModulesInfo;
extern moduleData *lastBBModule;
extern std::vector<std::string> TraceChoiceDirectoryList;
extern std::vector<std::string> TraceChoiceFileList;
extern bool DefaultIgnoreMode;