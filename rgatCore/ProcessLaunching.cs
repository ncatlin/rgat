using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{

	struct RGAT_THREADS_STRUCT
	{
		//could probably just put them in a map instead
		vector<base_thread*> threads;
		gat_module_handler* modThread = NULL;
		gat_basicblock_handler* BBthread = NULL;
		preview_renderer* previewThread = NULL;
		heatmap_renderer* heatmapThread = NULL;
		conditional_renderer* conditionalThread = NULL;
	};

	//for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
	static void launch_saved_process_threads(TraceRecord runRecord, rgatState clientState)
	{

		RGAT_THREADS_STRUCT* processThreads = new RGAT_THREADS_STRUCT;

		processThreads->previewThread = new preview_renderer(runRecord);
		std::thread previewsthread(&preview_renderer::ThreadEntry, processThreads->previewThread);
		previewsthread.detach();
		processThreads->threads.push_back(processThreads->previewThread);

		processThreads->heatmapThread = new heatmap_renderer(runRecord);
		std::thread heatthread(&heatmap_renderer::ThreadEntry, processThreads->heatmapThread);
		heatthread.detach();
		processThreads->threads.push_back(processThreads->heatmapThread);

		processThreads->conditionalThread = new conditional_renderer(runRecord);
		std::this_thread::sleep_for(200ms);
		std::thread condthread(&conditional_renderer::ThreadEntry, processThreads->conditionalThread);
		condthread.detach();
		processThreads->threads.push_back(processThreads->conditionalThread);

		runRecord->processThreads = processThreads;
	}

	//for each live process we have a thread rendering graph data for previews, heatmaps and conditionals
	//+ module data and disassembly

	static void launch_new_visualiser_threads(binaryTarget* target, traceRecord* runRecord, rgatState* clientState)
	{
		PIN_PIPES localhandles = { NULL, NULL, NULL };
		launch_new_visualiser_threads(target, runRecord, clientState, localhandles);
	}

	static void launch_new_visualiser_threads(binaryTarget* target, traceRecord* runRecord, rgatState* clientState, PIN_PIPES localhandles)
	{
		//spawns trace threads + handles module data for process
		gat_module_handler* tPIDThread = new gat_module_handler(target, runRecord, L"rgatThreadMod", localhandles.modpipe, localhandles.controlpipe);

		RGAT_THREADS_STRUCT* processThreads = new RGAT_THREADS_STRUCT;
		runRecord->processThreads = processThreads;
		std::thread modthread(&gat_module_handler::ThreadEntry, tPIDThread);
		modthread.detach();
		processThreads->modThread = tPIDThread;
		processThreads->threads.push_back(tPIDThread);

		//handles new disassembly data
		gat_basicblock_handler* tBBHandler = new gat_basicblock_handler(target, runRecord, L"rgatThreadBB", localhandles.bbpipe);

		std::thread bbthread(&gat_basicblock_handler::ThreadEntry, tBBHandler);
		bbthread.detach();
		processThreads->BBthread = tBBHandler;
		processThreads->threads.push_back(tBBHandler);

		//non-graphical
		if (!clientState->openGLWorking()) return;

		//graphics rendering threads for each process here	
		preview_renderer* tPrevThread = new preview_renderer(runRecord);
		processThreads->previewThread = tPrevThread;
		std::thread previewthread(&preview_renderer::ThreadEntry, tPrevThread);
		previewthread.detach();

		heatmap_renderer* tHeatThread = new heatmap_renderer(runRecord);
		std::thread heatthread(&heatmap_renderer::ThreadEntry, tHeatThread);
		heatthread.detach();
		processThreads->heatmapThread = tHeatThread;
		processThreads->threads.push_back(tHeatThread);

		conditional_renderer* tCondThread = new conditional_renderer(runRecord);
		std::this_thread::sleep_for(200ms);
		std::thread condthread(&conditional_renderer::ThreadEntry, tCondThread);
		condthread.detach();
		processThreads->conditionalThread = tCondThread;
		processThreads->threads.push_back(tCondThread);
	}
}
