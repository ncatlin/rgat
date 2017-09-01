#pragma once
#include "stdafx.h"
#include "module_handler.h"
#include "basicblock_handler.h"
#include "render_preview_thread.h"
#include "render_conditional_thread.h"
#include "render_heatmap_thread.h"
#include "rgatState.h"


struct THREAD_POINTERS {
	//could probably just put them in a map instead
	vector <base_thread *> threads;
	module_handler *modThread;
	basicblock_handler *BBthread;
	preview_renderer *previewThread;
	heatmap_renderer *heatmapThread;
	conditional_renderer *conditionalThread;
};

void launch_new_visualiser_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState);
void launch_saved_process_threads(traceRecord *runRecord, rgatState *clientState);
void process_coordinator_thread(rgatState *clientState, eTracePurpose purpose);