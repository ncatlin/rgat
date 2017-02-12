#pragma once
#include "stdafx.h"
#include "module_handler.h"
#include "basicblock_handler.h"
#include "render_preview_thread.h"
#include "render_conditional_thread.h"
#include "render_heatmap_thread.h"

struct THREAD_POINTERS {
	vector <base_thread *> threads;
	module_handler *modThread;
	basicblock_handler *BBthread;
	preview_renderer *previewThread;
	heatmap_renderer *heatmapThread;
	conditional_renderer *conditionalThread;
};


THREAD_POINTERS *launch_new_process_threads(PID_TID PID, std::map<PID_TID, PROCESS_DATA *> *glob_piddata_map, HANDLE pidmutex, VISSTATE *clientState, cs_mode bitWidth);
void launch_saved_process_threads(PID_TID PID, PROCESS_DATA *piddata, VISSTATE *clientState);
void process_coordinator_thread(VISSTATE *clientState);