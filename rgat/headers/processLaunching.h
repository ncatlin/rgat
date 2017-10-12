#pragma once
#include "stdafx.h"
#include "gat_module_handler.h"
#include "gat_basicblock_handler.h"
#include "render_preview_thread.h"
#include "render_conditional_thread.h"
#include "render_heatmap_thread.h"
#include "rgatState.h"


struct RGAT_THREADS_STRUCT {
	//could probably just put them in a map instead
	vector <base_thread *> threads;
	gat_module_handler *modThread;
	gat_basicblock_handler *BBthread;
	preview_renderer *previewThread;
	heatmap_renderer *heatmapThread;
	conditional_renderer *conditionalThread;
};

struct PIN_PIPES {
	HANDLE modpipe;
	HANDLE bbpipe;
	HANDLE controlpipe;
};

void execute_tracer(void *binaryTargetPtr, clientConfig *config, bool usePin);
void execute_dynamorio_test(void *binaryTargetPtr, clientConfig *config);

void launch_new_visualiser_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState);
void launch_new_visualiser_threads(binaryTarget *target, traceRecord *runRecord, rgatState *clientState, PIN_PIPES pipes);

void launch_saved_process_threads(traceRecord *runRecord, rgatState *clientState);
void process_coordinator_thread(rgatState *clientState);