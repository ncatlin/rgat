﻿using Newtonsoft.Json.Linq;
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
        private readonly List<TraceProcessorWorker> workers = new List<TraceProcessorWorker>();
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
        private readonly object _lock = new object();

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

    internal enum BinaryType { EXE, DLL };

    public enum BitWidth { Arch32, Arch64 };

    internal class ProcessLaunching
    {
        public static System.Diagnostics.Process? StartLocalTrace(string pintool, ProcessLaunchSettings settings, PeNet.PeFile? targetPE = null, long testID = -1)
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

            if (!File.Exists(settings.BinaryPath))
            {
                Logging.RecordError($"Target binary not available: {settings.BinaryPath}");
                return null;
            }

            try
            {
                if (targetPE == null)
                {
                    targetPE = new PeNet.PeFile(settings.BinaryPath);
                    if (targetPE == null)
                    {
                        Logging.RecordError($"Unable to parse PE file: {settings.BinaryPath}");
                        return null;
                    }
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Unable to parse PE file: {settings.BinaryPath} - {e.Message}");
                return null;
            }


            if (targetPE.IsDll)
            {
                return StartLocalDLLTrace(pintool, settings, testID);
            }
            else if (targetPE.IsExe) //'isexe' is true even for DLLs, so isdll has to be first
            {
                return StartLocalEXETrace(pintool, settings, testID: testID);
            }

            Logging.RecordError("Unable to trace non-EXE/DLL file");
            return null;
        }

        private static System.Diagnostics.Process? StartLocalDLLTrace(string pintool, ProcessLaunchSettings settings, long testID = -1)
        {

            System.Diagnostics.Process? result = null;

            string runargs = $"-t \"{pintool}\" ";
            if (testID > -1)
            {
                runargs += $"-T {testID} ";
            }

            runargs += $"-P {rgatState.LocalCoordinatorPipeName!} ";
            runargs += $"-L "; // tracing a library
            runargs += "-- ";


            string? binaryDir = Path.GetDirectoryName(settings.BinaryPath);
            if (binaryDir is null || Directory.Exists(binaryDir) == false)
            {
                Logging.RecordError("No binary directory");
                return null;
            }

            if (settings.LoaderName is null) settings.LoaderName = "DllLoader";
            if (settings.LoaderWidth is not BitWidth.Arch32 && settings.LoaderWidth is not BitWidth.Arch64)
            {
                Logging.RecordError("No Loader Width Specified");
                return null;
            }

            if (InitLoader(binaryDir, settings.LoaderName, settings.LoaderWidth, out string? loaderPath) && loaderPath is not null)
            {
                runargs += $"{loaderPath} {settings.BinaryPath},{settings.DLLOrdinal}$";
            }
            else
            {
                return null;
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

        private static void DeleteLoader(string loader)
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

        private static bool InitLoader(string directory, string name, BitWidth loaderWidth, out string? loaderPath)
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

        private static System.Diagnostics.Process? StartLocalEXETrace(string pintool, ProcessLaunchSettings settings, long testID = -1)
        {
            System.Diagnostics.Process? result = null;

            string runargs = $"-t \"{pintool}\" ";
            if (testID > -1)
            {
                runargs += $"-T {testID} ";
            }

            runargs += $"-P {rgatState.LocalCoordinatorPipeName!} ";
            runargs += $"-- \"{settings.BinaryPath}\" ";
            if (settings.CommandLineArgs is not null)
                runargs += settings.CommandLineArgs;

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


        public static void StartRemoteTrace(BinaryTarget target, ProcessLaunchSettings settings, long testID = -1)
        {
            if (!target.RemoteAccessible)
            {
                Logging.RecordLogEvent($"Could not trace {target.FilePath} on non-connected host {target.RemoteHost}", Logging.LogFilterType.TextAlert);
                return;
            }

            JObject startParamObj = new JObject();
            if (testID != -1)
            {
                startParamObj.Add("TestID", testID);
            }

            startParamObj.Add("Settings", JObject.FromObject(settings));
            

            rgatState.NetworkBridge.SendCommand("StartTrace", null, null, startParamObj);
        }


        //for each saved process we have a thread rendering graph data for previews, heatmaps and conditonals
        public static void launch_saved_process_threads(TraceRecord runRecord, rgatState clientState)
        {

            TraceProcessorWorkers processThreads = new TraceProcessorWorkers();
            runRecord.ProcessThreads = processThreads;
        }



    }
}
