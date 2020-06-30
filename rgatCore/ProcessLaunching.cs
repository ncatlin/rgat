using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;

namespace rgatCore
{

	struct RGAT_THREADS_STRUCT
	{
		//could probably just put them in a map instead
		public List<Thread> threads;
		public ModuleHandlerThread modThread;
		public BlockHandlerThread BBthread;
		public PreviewRendererThread previewThread;
		public HeatmapRendererThread heatmapThread;
		public ConditionalRendererThread conditionalThread;
	};
	class ProcessLaunching
	{
		//for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
		public static void launch_saved_process_threads(TraceRecord runRecord, rgatState clientState)
		{

			RGAT_THREADS_STRUCT processThreads = new RGAT_THREADS_STRUCT();
			processThreads.threads = new List<Thread>();

			processThreads.previewThread = new PreviewRendererThread(runRecord, clientState);
			Thread t1 = new Thread(processThreads.previewThread.ThreadProc);
			processThreads.threads.Add(t1);


			Thread.Sleep(200);
			processThreads.conditionalThread = new ConditionalRendererThread(runRecord, clientState);
			Thread t2 = new Thread(processThreads.conditionalThread.ThreadProc);
			processThreads.threads.Add(t2);

			Thread.Sleep(200);
			processThreads.heatmapThread = new HeatmapRendererThread(runRecord, clientState);
			Thread t3 = new Thread(processThreads.heatmapThread.ThreadProc);
			processThreads.threads.Add(t3);

			runRecord.ProcessThreads = processThreads;
		}

		//for each live process we have a thread rendering graph data for previews, heatmaps and conditionals
		//+ module data and disassembly

		struct PIN_PIPES
		{
			public int modpipe;
			public int bbpipe;
			public int controlpipe;
		};

		static void launch_new_visualiser_threads(BinaryTarget target, TraceRecord runRecord, rgatState clientState)
		{
			PIN_PIPES localhandles;
			localhandles.bbpipe = 0;
			localhandles.controlpipe = 0;
			localhandles.modpipe = 0;
			launch_new_visualiser_threads(target, runRecord, clientState, localhandles);
		}

		static void launch_new_visualiser_threads(BinaryTarget target, TraceRecord runRecord, rgatState clientState, PIN_PIPES localhandles)
		{
			//spawns trace threads + handles module data for process
			/*
			ModuleHandlerThread tPIDThread = new ModuleHandlerThread(target, runRecord, L"rgatThreadMod", localhandles.modpipe, localhandles.controlpipe);

			RGAT_THREADS_STRUCT processThreads = new RGAT_THREADS_STRUCT();
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
			*/
		}
	}
}
