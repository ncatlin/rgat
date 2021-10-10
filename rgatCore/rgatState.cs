using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;


namespace rgat
{
    /// <summary>
    /// Handles Loading/Saving/Storage of traces and binaries. 
    /// Dumping ground for various utility objects such as signature scanners and video encoder.
    /// 
    /// This is a holdover from the previous iteration of rgat that needs revamping or removing
    /// </summary>
    public class rgatState
    {
        /// <summary>
        /// Initialise the rgat state
        /// </summary>
        public rgatState()
        {
            LocalCoordinatorPipeName = Path.GetRandomFileName().Substring(0, 8).ToUpper();
        }

        /// <summary>
        /// Collection of binary targets that are loaded
        /// </summary>
        public static BinaryTargets targets = new();
        /// <summary>
        /// The currently selected binary target in the UI
        /// </summary>
        public static BinaryTarget? ActiveTarget;
        /// <summary>
        /// The trace currently active in the UI
        /// </summary>
        public static TraceRecord? ActiveTrace;
        /// <summary>
        /// The graph currently active in the UI
        /// </summary>
        public static PlottedGraph? ActiveGraph { get; private set; }
        /// <summary>
        /// A Veldrid GraphicsDevice reference available for general usage
        /// </summary>
        public Veldrid.GraphicsDevice? _GraphicsDevice;
        /// <summary>
        /// The loaded Detect-It-Easy(.Net) engine
        /// </summary>
        public static DetectItEasy? DIELib;
        /// <summary>
        /// The loaded dnYara engine
        /// </summary>
        public static YARAScanner? YARALib;
        /// <summary>
        /// A VideoEncoder object which managed FFMpeg capture
        /// </summary>
        public static VideoEncoder VideoRecorder = new VideoEncoder();
        /// <summary>
        /// A BridgeConnection object which manages the remote tracing connection
        /// </summary>
        public static BridgeConnection NetworkBridge = new BridgeConnection();
        /// <summary>
        /// Is a network connection to another rgat instance active?
        /// </summary>
        public static bool ConnectedToRemote => NetworkBridge != null && NetworkBridge.Connected;
        /// <summary>
        /// The name of the named pipe for locally running pintools to connect to
        /// </summary>
        public static string? LocalCoordinatorPipeName;

        /// <summary>
        /// Set this to cause video recording to start on the next trace connection
        /// </summary>
        public static bool RecordVideoOnNextTrace = false;

        /// <summary>
        /// A thread object which manages local trace connections over a named pipe
        /// </summary>
        public static Threads.ProcessCoordinatorThread? processCoordinatorThreadObj = null;

        /// <summary>
        /// Set the graphics devicefor widgets to use once it has been created 
        /// </summary>
        /// <param name="_gd">A Veldrid GraphicsDevice</param>
        public void InitVeldrid(Veldrid.GraphicsDevice _gd)
        {
            _GraphicsDevice = _gd;
        }

        readonly object _stateLock = new object();

        /// <summary>
        /// The current state of any load or save operation - or null if none
        /// </summary>
        public static SERIALISE_PROGRESS? SerialisationProgress { get; private set; } = null;


        /// <summary>
        /// A task which loads binary signatures such as YARA and DIE
        /// </summary>
        /// <param name="progress">An IProgress object for the UI process bar</param>
        /// <param name="completionCallback">An action to call when the load is complete</param>
        public static void LoadSignatures(IProgress<float>? progress = null, Action? completionCallback = null)
        {
            //todo - inner progress reporting based on signature count
            Logging.RecordLogEvent("Loading DiELib", Logging.LogFilterType.Debug);
            string DiEscriptsDir = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.DiESigsDirectory);
            if (Directory.Exists(DiEscriptsDir) || File.Exists(DiEscriptsDir))
            {
                try
                {
                    DIELib = new DetectItEasy(DiEscriptsDir);
                    Logging.RecordLogEvent("DiELib loaded", Logging.LogFilterType.Debug);
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Failed to load DiELib.NET: {e.Message}");
                }
            }
            else
            {
                Logging.RecordLogEvent($"Not loading DiE scripts: invalid path configured");
            }

            progress?.Report(0.5f);
            Logging.RecordLogEvent("Loading YARA", Logging.LogFilterType.Debug);

            string YARAscriptsDir = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory);
            if (Directory.Exists(YARAscriptsDir))
            {
                try
                {
                    YARALib = new YARAScanner(YARAscriptsDir);
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Unable to load YARA: {e.Message}");
                }
            }
            else
            {
                Logging.RecordLogEvent($"Not loading YARA rules: invalid directory configured");
            }

            if (YARALib != null)
            {
                Logging.RecordLogEvent("YARA loaded", Logging.LogFilterType.Debug);
            }
            progress?.Report(1f);
            completionCallback?.Invoke();
        }


        /// <summary>
        /// Cancellation tokens to be used by all rgat tasks to signal that rgat is shutting down
        /// Nothing should block in a way that will ignore this for more than a few hundred milliseconds
        /// </summary>
        private static readonly CancellationTokenSource _exitTokenSource = new CancellationTokenSource();
        /// <summary>
        /// rgat is shutting down
        /// </summary>
        public static bool rgatIsExiting => _exitTokenSource.IsCancellationRequested;


        /// <summary>
        /// Get a cancellation token which will be cancelled when rgat is exiting
        /// </summary>
        public static CancellationToken ExitToken => _exitTokenSource.Token;

        /// <summary>
        /// The number of traces which have executed in this rgat session
        /// Used by the UI to respond to incoming traces
        /// </summary>
        public static int TotalTraceCount { private set; get; } = 0;

        /// <summary>
        /// Record the connection of a new trace
        /// </summary>
        public static void IncreaseLoadedTraceCount() => TotalTraceCount += 1;




        /// <summary>
        /// Terminate all spawned processes and internal workers, then exit
        /// </summary>
        public static void Shutdown()
        {
            _exitTokenSource.Cancel();

            rgatState.NetworkBridge.Teardown("Exiting");


            DIELib?.CancelAllScans();
            YARALib?.CancelAllScans();
            VideoRecorder?.StopRecording();

            foreach (BinaryTarget targ in targets.GetBinaryTargets())
            {
                foreach (TraceRecord trace in targ.GetTracesList())
                {
                    //give the orders
                    List<ProtoGraph> graphs = trace.ProtoGraphs;
                    for (var i = 0; i < graphs.Count; i++)
                    {
                        graphs[i]?.TraceReader?.Terminate();
                    }
                    trace.ProcessThreads?.modThread?.Terminate();
                    trace.ProcessThreads?.BBthread?.Terminate();

                    //wait for all spawned processes to terminate
                    while (trace.ProtoGraphs.Exists(p => ((p.TraceProcessor != null) && p.TraceProcessor.Running) ||
                    ((p.TraceReader != null) && p.TraceReader.Running)))
                    {
                        Thread.Sleep(10);
                    }

                    //wait for all workers to terminate
                    while (trace.ProcessThreads is not null && trace.ProcessThreads.Running())
                    {
                        Thread.Sleep(10);
                    }
                }
            }
        }


        /// <summary>
        /// Add a new target to the list of loaded target binaries
        /// </summary>
        /// <param name="path">Filesystem path of target</param>
        /// <param name="arch">32 or 64 bits</param>
        /// <param name="isLibrary">The target is a DLL</param>
        /// <param name="makeActive">Set this as active in the UI</param>
        /// <returns>The BinaryTarget object describing the target</returns>
        public static BinaryTarget AddTargetByPath(string path, int arch = 0, bool isLibrary = false, bool makeActive = true)
        {
            BinaryTarget targ = targets.AddTargetByPath(path, isLibrary: isLibrary, arch: arch);
            DIELib?.StartDetectItEasyScan(targ);
            YARALib?.StartYARATargetScan(targ);

            if (makeActive)
            {
                ClearActiveGraph();
                SetActiveTarget(targ);
            }

            return targ;
        }

        /// <summary>
        /// Add a target binary for tracing by a remote rgat instance
        /// </summary>
        /// <param name="path">Filesystem path of target</param>
        /// <param name="hostAddr">Network address of the remote system</param>
        /// <param name="isLibrary">The target is a DLL</param>
        /// <param name="makeActive">Set this as active in the UI</param>
        /// <returns>The BinaryTarget object describing the target</returns>
        public BinaryTarget AddRemoteTargetByPath(string path, string hostAddr, bool isLibrary = false, bool makeActive = true)
        {
            BinaryTarget targ = targets.AddTargetByPath(path, isLibrary: isLibrary);

            if (makeActive)
            {
                ClearActiveGraph();
                SetActiveTarget(targ);
            }
            return targ;
        }

        /// <summary>
        /// Set the binary target active in the UI
        /// </summary>
        /// <param name="path">Path of the target to activate</param>
        public static void SetActiveTarget(string? path)
        {
            if (path == null)
            {
                ActiveTarget = null;
                ActiveTrace = null;
                ClearActiveGraph();
            }
            else
            {
                targets.GetTargetByPath(path, out BinaryTarget? newTarget);
                if (newTarget != null && newTarget != ActiveTarget)
                {
                    ActiveTarget = newTarget;
                    ActiveTrace = null;
                    ClearActiveGraph();
                };
            }
        }


        /// <summary>
        /// Set the binary target active in the UI
        /// </summary>
        /// <param name="newTarget">BinaryTarget object to activate</param>
        public static void SetActiveTarget(BinaryTarget newTarget)
        {
            if (newTarget != null && newTarget != ActiveTarget)
            {
                ActiveTarget = newTarget;
            };
        }

        /// <summary>
        /// Deactivate the currently active graph in the UI
        /// </summary>
        public static void ClearActiveGraph()
        {
            ActiveGraph = null;
        }


        /// <summary>
        /// Set the currently active trace in the UI. If a specific trace is not specified
        /// the trace chosen depends on the 'newest' parameter
        /// </summary>
        /// <param name="trace">An optional TraceRecord to set as active</param>
        /// <param name="newest">If true, get the most recently spawned trace. If false get the first in the list (not guaranteed to be the oldest)</param>
        public static void SelectActiveTrace(TraceRecord? trace = null, bool newest = false)
        {
            ActiveGraph = null;

            if (trace == null && ActiveTarget != null)
            {
                if (newest)
                {
                    trace = ActiveTarget.GetNewestTrace();
                }
                else
                {
                    trace = ActiveTarget.GetFirstTrace();
                }

                if (trace is not null)
                {
                    double secondsSinceLaunch = (DateTime.Now - trace.LaunchedTime).TotalSeconds;
                    if ((trace.ProtoGraphs.Count > 0 || secondsSinceLaunch < 3))
                    {
                        ActiveTrace = trace;
                        SelectGraphInActiveTrace();
                    }
                }
            }

            if (trace is not null && trace.ProtoGraphs.Count > 0)
            {
                ActiveTrace = trace;
                SelectGraphInActiveTrace();
            }

        }





        private static readonly Dictionary<TraceRecord, PlottedGraph> LastGraphs = new Dictionary<TraceRecord, PlottedGraph>();
        private static readonly Dictionary<TraceRecord, uint> LastSelectedTheads = new Dictionary<TraceRecord, uint>();

        /// <summary>
        /// Causes the UI to switch to displaying a different thread graph
        /// </summary>
        /// <param name="plot">The PlottedGraph object of the graph to switch to. Null to clear the active graph.</param>
        public static void SwitchToGraph(PlottedGraph plot)
        {
            //valid target or not, we assume current graph is no longer fashionable
            ClearActiveGraph();

            if (plot == null || plot.BeingDeleted)
            {
                return;
            }

            TraceRecord? trace = ActiveTrace;
            if (trace == null)
            {
                return;
            }

            if (ActiveTrace?.PID != plot.PID)
            {
                return;
            }

            if (SetActiveGraph(plot))
            {
                Debug.Assert(trace.PID == plot.PID);
                LastGraphs[trace] = plot;
                LastSelectedTheads[trace] = plot.TID;
            }
            //setGraphUIControls(graph);
        }

        /// <summary>
        /// Cause the UI to choose an active graph to display, used when no graph is active
        /// </summary>
        /// <returns>If a graph is now active</returns>
        public static bool ChooseActiveGraph()
        {
            if (ActiveGraph != null)
            {
                if (ActiveGraph.BeingDeleted)
                {
                    ActiveGraph = null;
                    return false;
                }

                return true;
            }

            if (ActiveGraph == null)
            {
                if (ActiveTrace == null)
                {
                    SelectActiveTrace();
                }

                SelectGraphInActiveTrace();
            }

            return (ActiveGraph != null);
        }

        /// <summary>
        /// Activate a graph in the active trace
        /// Selects the last one that was active in this trace, or the first seen
        /// </summary>
        private static void SelectGraphInActiveTrace()
        {
            TraceRecord? selectedTrace = ActiveTrace;
            if (selectedTrace == null)
            {
                return;
            }

            if (LastGraphs.TryGetValue(selectedTrace, out PlottedGraph? foundGraph))
            {
                bool found = false;
                List<PlottedGraph> traceGraphs = selectedTrace.GetPlottedGraphs();
                if (traceGraphs.Contains(foundGraph))
                {
                    SwitchToGraph(foundGraph);
                    found = true;
                }
                else
                {
                    uint lastTID = LastSelectedTheads[selectedTrace];
                    PlottedGraph? lastgraph = traceGraphs.Find(pg => pg.TID == lastTID);
                    if (lastgraph != null)
                    {
                        SwitchToGraph(lastgraph);
                        found = true;
                    }
                }

                if (found)
                {
                    return;
                }
            }

            PlottedGraph? firstgraph = selectedTrace.GetFirstGraph();
            if (firstgraph != null)
            {
                Logging.RecordLogEvent("Got first graph " + firstgraph.TID,
                    Logging.LogFilterType.Debug, trace: firstgraph.InternalProtoGraph.TraceData);
                SwitchToGraph(firstgraph);
            }
        }


        /// <summary>
        /// Sets a specific thread graph for the UI to display
        /// </summary>
        /// <param name="plot">A PlottedGraph object of the thread to display</param>
        /// <returns></returns>
        public static bool SetActiveGraph(PlottedGraph plot)
        {
            if (ActiveGraph != null && ActiveGraph.BeingDeleted)
            {
                return false;
            }

            ClearActiveGraph();

            if (ActiveTrace is not null && plot.PID != ActiveTrace.PID)
            {
                ActiveTrace = null;
            }

            Debug.Assert(ActiveGraph == null);

            ActiveGraph = plot;
            return true;
        }

        /// <summary>
        /// Get the currently active thread graph being shown by the UI
        /// </summary>
        /// <returns>The PlottedGraph object of the active thread graph</returns>
        public static PlottedGraph? GetActiveGraph()
        {
            if (ActiveGraph != null && ActiveGraph.BeingDeleted)
            {
                return null;
            }

            if (ActiveGraph == null)
            {
                return null;
            }
            return ActiveGraph;
        }


        /// <summary>
        /// Load a TraceRecord from a serialised trace JObject
        /// </summary>
        /// <param name="metadata">The metadata prelude object of the saved trace</param>
        /// <param name="target">The binarytarget associated with the trace</param>
        /// <param name="traceResult">The output reconstructed TraceRecord</param>
        /// <returns>true if a new trace was created, false if failed or duplicated</returns>
        private static bool LoadTraceRecord(JObject metadata, BinaryTarget target, out TraceRecord? traceResult)
        {
            traceResult = null;

            bool valid = true;
            valid &= metadata.TryGetValue("PID", out JToken? jPID) && jPID is not null;
            valid &= metadata.TryGetValue("PID_ID", out JToken? jID) && jID is not null;
            valid &= metadata.TryGetValue("LaunchedTime", out JToken? jTime) && jTime is not null;

            if (valid is false ||
                jPID!.Type != JTokenType.Integer ||
                jID!.Type != JTokenType.Integer)
            {
                Logging.WriteConsole("Bad trace metadata. Load failed.");
                traceResult = null;
                return false;
            }


            //temporary loading of unix ts in old save files. TODO: move to new format
            DateTime StartTime;
            if (jTime!.Type == JTokenType.Date)
            {
                StartTime = jTime.ToObject<DateTime>();
            }
            else
            {
                Logging.WriteConsole("BAD DATETIME");
                traceResult = null;
                return false;
            }


            bool newTrace = target.CreateNewTrace(StartTime, (uint)jPID, (uint)jID, out traceResult);
            if (!newTrace)
            {
                //updateActivityStatus("Trace already loaded", 15000);
                Logging.RecordError("Trace already loaded");
                return false;
            }

            //updateActivityStatus("Loaded saved process: " + QString::number(tracePID), 15000);
            return true;
        }


        /// <summary>
        /// Serialisation progress information for UI display
        /// </summary>
        public class SERIALISE_PROGRESS
        {
            /// <summary>
            /// Serialisation progress information for UI display
            /// </summary>
            /// <param name="operationName">Title of the operation being performed</param>
            public SERIALISE_PROGRESS(string operationName)
            {
                Operation = operationName;
            }

            /// <summary>
            /// The operation being performed
            /// </summary>
            public string Operation;
            /// <summary>
            /// The number of files being loaded/saved (not used)
            /// </summary>
            public int FileCount;
            /// <summary>
            /// The path of the current file, or null if none
            /// </summary>
            public string? FilePath;
            /// <summary>
            /// Total sections being processed in this stage
            /// </summary>
            public int SectionsTotal;
            /// <summary>
            /// How many of this stages sections are complete
            /// </summary>
            public int SectionsComplete;
            /// <summary>
            /// 0-1 progress in this section
            /// </summary>
            public float SectionProgress;
            /// <summary>
            /// The name of the section being processed
            /// </summary>
            public string? SectionName;
            /// <summary>
            /// Set to cancel processing
            /// </summary>
            public bool Cancelled = false;
        }


        /// <summary>
        /// Load a saved trace
        /// </summary>
        /// <param name="path">The fileystem path of the saved trace</param>
        /// <param name="trace">The loaded TraceRecord object</param>
        /// <returns></returns>
        public bool LoadTraceByPath(string path, out TraceRecord? trace)
        {
            //display_only_status_message("Loading save file...", clientState);
            //updateActivityStatus("Loading " + QString::fromStdString(traceFilePath.string()) + "...", 2000);
            trace = null;
            if (!File.Exists(path))
            {
                return false;
            }

            lock (_stateLock)
            {
                if (SerialisationProgress is null)
                {
                    SerialisationProgress = new SERIALISE_PROGRESS("Loading Trace")
                    {
                        FileCount = 1
                    };
                }
                SerialisationProgress.FilePath = path;
            }

            bool success;
            try
            {
                using (StreamReader streamreader = File.OpenText(path))
                {
                    using (JsonTextReader jsnReader = new JsonTextReader(streamreader))
                    {
                        if (!jsnReader.Read() || jsnReader.TokenType is not JsonToken.StartArray)
                        {
                            Logging.RecordError($"Trace file {path} started with unexpected data");
                            return false;
                        }
                        success = DeserialiseTrace(jsnReader, SerialisationProgress, out trace);
                        if (success is false)
                        {
                            if (SerialisationProgress.Cancelled is false)
                                Logging.RecordError("Failed to load trace file"); //inner function should log why
                            else
                                Logging.RecordLogEvent("Loading cancelled", Logging.LogFilterType.Alert);

                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logging.RecordError("Error loading trace file: " + e.Message);
                success = false;
            }

            lock (_stateLock)
            {
                SerialisationProgress = null;
            }
            if (rgatState.ActiveGraph is null && trace is not null)
            {
                if (ActiveTarget is null)
                {
                    SetActiveTarget(trace.Target);
                }
                rgatState.ChooseActiveGraph();
            }
            return true;
        }


        /// <summary>
        /// Cancel an active load/save operation
        /// </summary>
        public void CancelSerialization()
        {
            lock (_stateLock)
            {
                if (SerialisationProgress is not null) SerialisationProgress.Cancelled = true;
            }
        }


        bool DeserialiseTrace(JsonReader jsnReader, SERIALISE_PROGRESS SerialisationProgress, out TraceRecord? trace)
        {
            trace = null;
            Debug.Assert(SerialisationProgress is not null);

            JsonSerializer serializer = new JsonSerializer();
            BinaryTarget? target;

            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Metadata", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No initial metadata in trace file");
                return false;
            }

            if (!targets.LoadSavedTarget(mdObj, out target) || target is null)
            {
                return false;
            }

            if (!LoadTraceRecord(mdObj, target, out trace) || trace is null)
            {
                if (trace is not null)
                    target.DeleteTrace(trace.LaunchedTime);
                return false;
            }

            Debug.Assert(_GraphicsDevice is not null);

            if (!trace.Load(jsnReader, serializer, SerialisationProgress, _GraphicsDevice))
            {
                target.DeleteTrace(trace.LaunchedTime);
                trace = null;
                return false;
            }

            //updateActivityStatus("Loaded " + QString::fromStdString(traceFilePath.filename().string()), 15000);
            TraceRecord.ExtractChildTraceFilenames(jsnReader, serializer, out List<string>? childrenFiles);

            if (childrenFiles is not null && childrenFiles.Count > 0)
            {
                SerialisationProgress.FileCount = 1 + childrenFiles.Count;
                LoadChildTraces(childrenFiles, trace, SerialisationProgress);
            }
            return true;
        }




        /// <summary>
        /// Loads child traces into a trace record
        /// </summary>
        /// <param name="childrenFiles">A list of relative filesystem paths of traces</param>
        /// <param name="trace">The parent TraceRecord of the child traces</param>
        /// <param name="progress">Serialisation progress object</param>
        private void LoadChildTraces(List<string> childrenFiles, TraceRecord trace, SERIALISE_PROGRESS progress)
        {

            string saveDir = "C:\\";//config.saveDir; //should be same dir as loaded trace?
            foreach (string file in childrenFiles)
            {
                progress.FilePath = file;
                string childFilePath = Path.Combine(saveDir, file);

                if (Path.GetDirectoryName(childFilePath) != saveDir) //or a children subdir?
                {
                    return; //avoid directory traversal
                }

                if (!File.Exists(childFilePath))
                {
                    Logging.WriteConsole("[rgat] Warning: Unable to find child save file " + childFilePath);
                    return;
                }

                if (LoadTraceByPath(childFilePath, out TraceRecord? childTrace) && childTrace is not null)
                {
                    trace.AddChildTrace(childTrace);
                    childTrace.ParentTrace = trace;
                }
            }

        }

        /// <summary>
        /// Cause all the traces of all active targets to be serialised to the trace directory
        /// </summary>
        public static void SaveAllTargets()
        {
            List<BinaryTarget> targslist = targets.GetBinaryTargets();
            int savedCount = 0;
            foreach (BinaryTarget targ in targslist)
            {
                savedCount += SaveTarget(targ);
            }

            Logging.RecordLogEvent($"Finished saving {savedCount} trace{((savedCount is not 1) ? 's' : "")}", Logging.LogFilterType.Alert);
            Logging.WriteConsole($"Finished saving {targslist.Count} targets");
        }




        /// <summary>
        /// Serialise all the traces of the the specified target to the trace directory
        /// </summary>
        /// <param name="targ">A binaryTarget to save traces of</param>
        public static int SaveTarget(BinaryTarget? targ)
        {
            if (targ is null) return 0;

            var traceslist = targ.GetTracesUIList();
            int savedCount = 0;
            SerialisationProgress = new SERIALISE_PROGRESS("Saving Trace")
            {
                FileCount = traceslist.Length
            };

            foreach (TraceRecord trace in traceslist)
            {
                if (!trace.WasLoadedFromSave)
                {
                    try
                    {
                        if (trace.Save(SerialisationProgress, out string? path))
                        {
                            savedCount += 1;
                            Logging.RecordLogEvent($"Saved Process {trace.PID} to {path}", Logging.LogFilterType.Alert);
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.RecordError($"Error saving trace {trace.PID} - {e.Message}");
                    }
                }
            }
            SerialisationProgress = null;
            return savedCount;
        }

        /// <summary>
        /// Export the current trace in the pajek format, a simple graph serialisation format that other graph layout programs accept
        /// </summary>
        public static void ExportTraceAsPajek(TraceRecord trace, uint TID)
        {
            try
            {
                trace.ExportPajek(TID);
            }
            catch (Exception e)
            {
                //Probably will be a thread safety issue
                Logging.RecordError($"Failure exporting Pajek layout ({e.Message})");
            }
        }

        private readonly object _testLock = new object();
        private readonly Dictionary<long, TraceRecord> _testConnections = new Dictionary<long, TraceRecord>();
        /// <summary>
        /// Store a reference to an incoming rgat test trace
        /// </summary>
        /// <param name="testID">The ID of the test</param>
        /// <param name="trace">The TraceRecord associated with the test</param>
        public void RecordTestRunConnection(long testID, TraceRecord trace)
        {
            lock (_testLock)
            {
                Debug.Assert(!_testConnections.ContainsKey(testID));
                Debug.Assert(trace != null);
                _testConnections.Add(testID, trace);
            }
        }

        /// <summary>
        /// Get the TraceRecord for a specific test ID
        /// </summary>
        /// <param name="testID">The test ID to retrieve</param>
        /// <param name="trace">The associated TraceRecord of the test</param>
        /// <returns>true if found, false otherwise</returns>
        public bool GetTestTrace(long testID, out TraceRecord? trace)
        {

            lock (_stateLock)
            {
                if (_testConnections.TryGetValue(testID, out trace))
                {
                    _testConnections.Remove(testID);
                    return true;
                }
                return false;
            }
        }

        /// <summary>
        /// Read a bundled resouce as bytes
        /// </summary>
        /// <param name="name">Resource name</param>
        /// <returns>null or the bytes of the found resource</returns>
        public static byte[]? ReadBinaryResource(string name)
        {
            System.Reflection.Assembly assembly = Assembly.GetExecutingAssembly();
            System.IO.Stream? fs = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames()[0]);
            if (fs is null)
            {
                return null;
            }

            System.Resources.ResourceReader r = new System.Resources.ResourceReader(fs);
            r.GetResourceData(name, out string? rtype, out byte[] resBytes);
            if (resBytes == null || rtype != "ResourceTypeCode.ByteArray")
            {
                return null;
            }

            //https://stackoverflow.com/questions/32891004/why-resourcereader-getresourcedata-return-data-of-type-resourcetypecode-stream
            Stream stream = new MemoryStream(resBytes);
            byte[] result = new byte[stream.Length - 4];
            stream.Seek(4, SeekOrigin.Begin);
            stream.Read(result, 0, result.Length);
            return result;
        }

    }
}
