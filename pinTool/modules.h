#pragma once
#include "pin.H"

#ifdef HOST_IA32E
#define ADDR_FMT "%llx"
#elif HOST_IA32
#define ADDR_FMT "%lx"
#endif

bool module_should_be_instrumented(std::string path);

struct moduleData
{
	ADDRINT start, end;
	bool instrumented;
	std::string name;
	UINT32 ID;
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