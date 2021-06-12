using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Text;
using System.Threading;

namespace rgatCore
{

	public struct RGAT_THREADS_STRUCT
	{
		//could probably just put them in a map instead
		public List<Thread> threads;
		public ModuleHandlerThread modThread;
		public BlockHandlerThread BBthread;
		public PreviewRendererThread previewThread;
		public HeatRankingThread heatmapThread;
		public ConditionalRendererThread conditionalThread;
	};


	class ProcessLaunching
	{
		public static System.Diagnostics.Process StartTracedProcess(string pintool, string targetBinary, long testID = -1)
		{
			string runargs = $"-t \"{pintool}\" ";
			if (testID > -1)
				runargs += $"-T {testID} ";
			runargs += $"-- \"{targetBinary}\" ";
			return System.Diagnostics.Process.Start(GlobalConfig.PinPath, runargs);
		}



		//for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
		public static void launch_saved_process_threads(TraceRecord runRecord, rgatState clientState)
		{

			RGAT_THREADS_STRUCT processThreads = new RGAT_THREADS_STRUCT();
			processThreads.threads = new List<Thread>();

			processThreads.previewThread = new PreviewRendererThread(runRecord, clientState);
			Thread t1 = new Thread(processThreads.previewThread.ThreadProc);
			t1.Name = "PreviewRendererS";
			processThreads.threads.Add(t1);
			t1.Start();


			//Thread.Sleep(200);
			//processThreads.conditionalThread = new ConditionalRendererThread(runRecord, clientState);
			//Thread t2 = new Thread(processThreads.conditionalThread.ThreadProc);
			//processThreads.threads.Add(t2);

			runRecord.ProcessThreads = processThreads;
		}


		public static void launch_new_visualiser_threads(BinaryTarget target, TraceRecord runRecord, rgatState clientState)
		{
			//non-graphical
			//if (!clientState.openGLWorking()) return;

			RGAT_THREADS_STRUCT processThreads = new RGAT_THREADS_STRUCT();
			processThreads.threads = new List<Thread>();

			processThreads.previewThread = new PreviewRendererThread(runRecord, clientState);
			Thread t1 = new Thread(processThreads.previewThread.ThreadProc);
			t1.Name = "PreviewRendererL";
			processThreads.threads.Add(t1);
			t1.Start();

			Thread.Sleep(200);
			processThreads.conditionalThread = new ConditionalRendererThread(runRecord, clientState);
			Thread t2 = new Thread(processThreads.conditionalThread.ThreadProc);
			processThreads.threads.Add(t2);

			runRecord.ProcessThreads = processThreads;
		}
	}
}
