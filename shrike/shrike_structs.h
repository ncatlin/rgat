#pragma once

#include "shrike_module_handler.h"
#include "shrike_basicblock_handler.h"

enum feedbackTags { eCoverageResult = 'C', eExceptionNotification = 'X'};

struct SHRIKE_THREADS_STRUCT {
	//could probably just put them in a map instead
	vector <base_thread *> threads;
	shrike_module_handler *modThread;
	shrike_basicblock_handler *BBthread;
};

enum fUpdateCode { eFU_String, eFU_NewThread };

struct FUZZUPDATE {
	int code;
	string details;
};
