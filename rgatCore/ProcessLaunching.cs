using Newtonsoft.Json.Linq;
using rgat.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace rgat
{
    /// <summary>
    /// Manage the workers for a trace
    /// </summary>
    public class TraceProcessorWorkers
    {
        //could probably just put them in a map instead
        readonly List<TraceProcessorWorker> workers = new List<TraceProcessorWorker>();
        /// <summary>
        /// Module handler worker for this trace
        /// </summary>
        public ModuleHandlerThread? modThread;

        /// <summary>
        /// Basic block disassembler worker for this treace
        /// </summary>
        public BlockHandlerThread? BBthread;

        /// <summary>
        /// Preview renderer worker for this trace
        /// </summary>
        public PreviewRendererThread? previewThread;

        //public HeatRankingThread heatmapThread;
        //public ConditionalRendererThread conditionalThread;
        readonly object _lock = new object();

        /// <summary>
        /// Register a worker for this trace
        /// </summary>
        /// <param name="worker">TraceProcessorWorker worker</param>
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

        /// <summary>
        /// Are any workers running
        /// </summary>
        /// <returns>A running worker was found</returns>
        public bool Running()
        {
            lock (_lock)
            {
                return workers.Exists(worker => worker.Running);
            }
        }
    };

    enum BinaryType { EXE, DLL };
    enum BitWidth { Arch32, Arch64 };

    class ProcessLaunching
    {

        public static System.Diagnostics.Process? StartLocalTrace(string pintool, string targetBinary, PeNet.PeFile? targetPE = null,
            string loaderName = "LoadDLL", int ordinal = 0, long testID = -1)
        {
            if (!File.Exists(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinPath)))
            {
                Logging.RecordError($"Pin.exe path is not correctly configured (Settings->Files->Pin Executable)");
                return null;
            }

            if (!File.Exists(pintool))
            {
                if (pintool == null)
                {
                    Logging.RecordError($"Pintool path was not set");
                }
                else
                {
                    Logging.RecordError($"Pintool {pintool} path was not found");
                }
                return null;
            }

            if (!File.Exists(targetBinary))
            {
                if (pintool == null)
                {
                    Logging.RecordError($"Target binary not found: {targetBinary}");
                }
                return null;
            }

            try
            {
                if (targetPE == null)
                {
                    targetPE = new PeNet.PeFile(targetBinary);
                    if (targetPE == null)
                    {
                        Logging.RecordError($"Unable to parse PE file: {targetBinary}");
                        return null;
                    }
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Unable to parse PE file: {targetBinary} - {e.Message}");
                return null;
            }


            if (targetPE.IsDll)
            {
                BitWidth width = targetPE.Is32Bit ? BitWidth.Arch32 : BitWidth.Arch64;
                return StartLocalDLLTrace(pintool, targetBinary, loaderName, width, ordinal, testID);
            }
            else if (targetPE.IsExe) //'isexe' is true even for DLLs, so isdll has to be first
            {
                return StartLocalEXETrace(pintool, targetBinary, testID);
            }

            Logging.RecordError("Unable to trace non-EXE/DLL file");
            return null;
        }

        static System.Diagnostics.Process? StartLocalDLLTrace(string pintool, string targetBinary, string loadername, BitWidth loaderWidth, int ordinal = 0, long testID = -1)
        {

            System.Diagnostics.Process? result = null;

            string runargs = $"-t \"{pintool}\" ";
            if (testID > -1)
                runargs += $"-T {testID} ";
            runargs += $"-P {rgatState.LocalCoordinatorPipeName!} ";
            runargs += $"-L "; // tracing a library
            runargs += "-- ";



            if (InitLoader(Path.GetDirectoryName(targetBinary), loadername, loaderWidth, out string? loaderPath))
            {
                runargs += $"{loaderPath} {targetBinary},{ordinal}$";
            }

            try
            {
                string pinpath = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinPath);
                Logging.RecordLogEvent($"Launching DLL trace: {pinpath} {runargs}", Logging.LogFilterType.TextDebug);
                result = System.Diagnostics.Process.Start(pinpath, runargs);
                result.Exited += (sender, args) => DeleteLoader(loaderPath);
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to start process: {e.Message}");
            }
            return result;
        }

        static void DeleteLoader(string loader)
        {
            try
            {
                File.Delete(loader);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Unable to delete loader {loader}: {e.Message}");
            }
        }

        static bool InitLoader(string directory, string name, BitWidth loaderWidth, out string? loaderPath)
        {
            loaderPath = Path.Combine(directory, name);

            int attempts = 10;
            while (File.Exists(loaderPath))
            {
                loaderPath = Path.Combine(directory, $"{Path.GetRandomFileName().Substring(0, 4)}_{name}");
                if (attempts-- < 0)
                {
                    Logging.RecordError("Unable to create loader due to prexisting loaders with similar name");
                    return false;
                }
            }

            string loaderName = (loaderWidth == BitWidth.Arch32) ? "DllLoader32" : "DllLoader64";
            byte[]? loaderBytes = rgatState.ReadBinaryResource(loaderName);
            if (loaderBytes == null)
            {
                Logging.RecordError($"Unable to retrieve loader {loaderName} from resources");
                return false;
            }

            try
            {
                File.WriteAllBytes(loaderPath, loaderBytes);
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to write loader to DLL directory: {e}");
                return false;
            }


            return true;
        }


        static System.Diagnostics.Process? StartLocalEXETrace(string pintool, string targetBinary, long testID = -1)
        {
            System.Diagnostics.Process? result = null;

            string runargs = $"-t \"{pintool}\" ";
            if (testID > -1)
                runargs += $"-T {testID} ";
            runargs += $"-P {rgatState.LocalCoordinatorPipeName!} ";
            runargs += $"-- \"{targetBinary}\" ";

            try
            {
                string pinpath = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinPath);
                Logging.RecordLogEvent($"Launching EXE trace: {pinpath} {runargs}", Logging.LogFilterType.TextDebug);
                result = System.Diagnostics.Process.Start(pinpath, runargs);
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to start process: {e.Message}");
            }
            return result;

        }

        public static void StartRemoteTrace(BinaryTarget target, int ordinal = -1, string? loaderName = null, long testID = -1)
        {
            if (!target.RemoteAccessible)
            {
                Logging.RecordLogEvent($"Could not trace {target.FilePath} on non-connected host {target.RemoteHost}", Logging.LogFilterType.TextAlert);
                return;
            }

            JObject startParamObj = new JObject();
            startParamObj.Add("TargetPath", target.FilePath);
            if (testID != -1) startParamObj.Add("TestID", testID);
            if (ordinal != -1) startParamObj.Add("Ordinal", ordinal);
            if (loaderName != null) startParamObj.Add("LoaderName", loaderName);

            rgatState.NetworkBridge.SendCommand("StartTrace", null, null, startParamObj);
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


        public static void launch_new_visualiser_threads(TraceRecord runRecord, rgatState clientState)
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
