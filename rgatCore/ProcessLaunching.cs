using rgat.Threads;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace rgat
{

    public class TraceProcessorWorkers
    {
        //could probably just put them in a map instead
        List<TraceProcessorWorker> workers = new List<TraceProcessorWorker>();
        public ModuleHandlerThread modThread;
        public BlockHandlerThread BBthread;
        public PreviewRendererThread previewThread;
        //public HeatRankingThread heatmapThread;
        //public ConditionalRendererThread conditionalThread;
        readonly object _lock = new object();

        public void Register(TraceProcessorWorker worker)
        {
            lock (_lock)
            {
                //https://stackoverflow.com/a/4478490 
                switch (worker)
                {
                    case ModuleHandlerThread t1:
                        modThread = (ModuleHandlerThread)worker;
                        break;
                    case BlockHandlerThread t2:
                        BBthread = (BlockHandlerThread)worker;
                        break;
                    case PreviewRendererThread t3:
                        previewThread = (PreviewRendererThread)worker;
                        break;
                    /*
                case HeatRankingThread t4:
                    heatmapThread = (HeatRankingThread)worker;
                    break;
                case ConditionalRendererThread t5:
                    conditionalThread = (ConditionalRendererThread)worker;
                    break;
                    */
                    default:
                        Debug.Assert(false, $"unknown worker type registered: {worker.GetType()}");
                        break;
                }
                workers.Add(worker);
            }
        }

        public bool Running()
        {
            lock (_lock)
            {
                return workers.Exists(worker => worker.Running);
            }
        }
    };


    class ProcessLaunching
    {
        public static System.Diagnostics.Process StartLocalTrace(string pintool, string targetBinary, long testID = -1)
        {
            string runargs = $"-t \"{pintool}\" ";
            if (testID > -1)
                runargs += $"-T {testID} ";
            runargs += $"-P {rgatState.LocalCoordinatorPipeName} ";
            runargs += $"-- \"{targetBinary}\" ";
            return System.Diagnostics.Process.Start(GlobalConfig.PinPath, runargs);
        }

        public static void StartRemoteTrace(BinaryTarget target, long testID = -1)
        {
            if(!target.RemoteAccessible)
            {
                Logging.RecordLogEvent($"Could not trace {target.FilePath} on non-connected host {target.RemoteHost}", Logging.LogFilterType.TextAlert);
                return;
            }
            string startParams = $"{target.FilePath},{testID}";
            rgatState.NetworkBridge.SendCommand("StartTrace", null, null, startParams);
        }


        //for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
        public static void launch_saved_process_threads(TraceRecord runRecord, rgatState clientState)
        {

            TraceProcessorWorkers processThreads = new TraceProcessorWorkers();

            PreviewRendererThread previewThread = new PreviewRendererThread(runRecord);
            processThreads.Register(previewThread);
            previewThread.Begin();

            //Thread.Sleep(200);
            //processThreads.conditionalThread = new ConditionalRendererThread(runRecord, clientState);
            //Thread t2 = new Thread(processThreads.conditionalThread.ThreadProc);
            //processThreads.threads.Add(t2);

            runRecord.ProcessThreads = processThreads;
        }


        public static void launch_new_visualiser_threads(BinaryTarget target, TraceRecord runRecord, rgatState clientState)
        {
            Logging.RecordLogEvent($"launch_new_visualiser_threads START", Logging.LogFilterType.BulkDebugLogFile);
            //non-graphical
            //if (!clientState.openGLWorking()) return;
            PreviewRendererThread previewThread = new PreviewRendererThread(runRecord);
            runRecord.ProcessThreads.Register(previewThread);
            previewThread.Begin();
            Thread.Sleep(200);
        }
    }
}
