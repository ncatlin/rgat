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
        /// Collection of binary targets that are loaded
        /// </summary>
        public static BinaryTargets targets = new BinaryTargets();
        /// <summary>
        /// The currently selected binary target in the UI
        /// </summary>
        public BinaryTarget ActiveTarget;
        /// <summary>
        /// The trace currently active in the UI
        /// </summary>
        public TraceRecord ActiveTrace;
        /// <summary>
        /// The graph currently active in the UI
        /// </summary>
        public PlottedGraph ActiveGraph { get; private set; }
        /// <summary>
        /// A Veldrid GraphicsDevice reference available for general usage
        /// </summary>
        public Veldrid.GraphicsDevice _GraphicsDevice;
        /// <summary>
        /// The loaded Detect-It-Easy(.Net) engine
        /// </summary>
        public static DetectItEasy DIELib;
        /// <summary>
        /// The loaded dnYara engine
        /// </summary>
        public static YARAScan YARALib;
        /// <summary>
        /// A VideoEncoder object which managed FFMpeg capture
        /// </summary>
        public static VideoEncoder VideoRecorder = new VideoEncoder();
        /// <summary>
        /// A BridgeConnection object which manages the remote tracing connection
        /// </summary>
        public static BridgeConnection NetworkBridge;
        /// <summary>
        /// Is a network connection to another rgat instance active?
        /// </summary>
        public static bool ConnectedToRemote => NetworkBridge != null && NetworkBridge.Connected;
        /// <summary>
        /// The name of the named pipe for locally running pintools to connect to
        /// </summary>
        public static string LocalCoordinatorPipeName;

        /// <summary>
        /// Set this to cause video recording to start on the next trace connection
        /// </summary>
        public static bool RecordVideoOnNextTrace = false;

        /// <summary>
        /// A thread object which manages local trace connections over a named pipe
        /// </summary>
        public static Threads.ProcessCoordinatorThread processCoordinatorThreadObj = null;


        public rgatState()
        {
            LocalCoordinatorPipeName = Path.GetRandomFileName().Substring(0, 8).ToUpper();
        }

        /// <summary>
        /// Set the graphics devicefor widgets to use once it has been created 
        /// </summary>
        /// <param name="_gd">A Veldrid GraphicsDevice</param>
        public void InitVeldrid(Veldrid.GraphicsDevice _gd)
        {
            _GraphicsDevice = _gd;
            PlottedGraph.clientState = this;
        }

        /// <summary>
        /// A task which loads binary signatures such as YARA and DIE
        /// </summary>
        /// <param name="progress">An IProgress object for the UI process bar</param>
        /// <param name="completionCallback">An action to call when the load is complete</param>
        public static void LoadSignatures(IProgress<float> progress = null, Action completionCallback = null)
        {
            //todo - inner progress reporting based on signature count
            Logging.RecordLogEvent("Loading DiELib", Logging.LogFilterType.TextDebug);
            string DiEscriptsDir = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.DiESigsDirectory);
            if (Directory.Exists(DiEscriptsDir) || File.Exists(DiEscriptsDir))
            {
                try
                {
                    DIELib = new DetectItEasy(DiEscriptsDir);
                    Logging.RecordLogEvent("DiELib loaded", Logging.LogFilterType.TextDebug);
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
            Logging.RecordLogEvent("Loading YARA", Logging.LogFilterType.TextDebug);

            string YARAscriptsDir = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory);
            if (Directory.Exists(YARAscriptsDir))
            {
                try
                {
                    YARALib = new YARAScan(YARAscriptsDir);
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
                Logging.RecordLogEvent("YARA loaded", Logging.LogFilterType.TextDebug);
            }
            progress?.Report(1f);
            if (completionCallback != null) completionCallback();
        }


        /// <summary>
        /// Cancellation tokens to be used by all rgat tasks to signal that rgat is shutting down
        /// Nothing should block in a way that will ignore this for more than a few hundred milliseconds
        /// </summary>
        static CancellationTokenSource _exitTokenSource = new CancellationTokenSource();
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

            if (rgatState.ConnectedToRemote) rgatState.NetworkBridge.Teardown("Exiting");

            DIELib?.CancelAllScans();
            YARALib?.CancelAllScans();
            VideoRecorder?.StopRecording();

            foreach (BinaryTarget targ in targets.GetBinaryTargets())
            {
                foreach (TraceRecord trace in targ.GetTracesList())
                {
                    //give the orders
                    List<ProtoGraph> graphs = trace.GetProtoGraphs();
                    for (var i = 0; i < graphs.Count; i++)
                    {
                        graphs[i]?.TraceReader?.Terminate();
                    }
                    trace.ProcessThreads?.modThread?.Terminate();
                    trace.ProcessThreads?.BBthread?.Terminate();

                    //wait for all spawned processes to terminate
                    while (trace.GetProtoGraphs().Exists(p => ((p.TraceProcessor != null) && p.TraceProcessor.Running) ||
                    ((p.TraceReader != null) && p.TraceReader.Running)))
                    {
                        Thread.Sleep(10);
                    }

                    //wait for all workers to terminate
                    while (trace.ProcessThreads.Running())
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
        public BinaryTarget AddTargetByPath(string path, int arch = 0, bool isLibrary = false, bool makeActive = true)
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
            BinaryTarget targ = targets.AddTargetByPath(path, isLibrary: isLibrary, remoteAddr: hostAddr);

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
        public void SetActiveTarget(string path)
        {
            targets.GetTargetByPath(path, out BinaryTarget newTarget);
            if (newTarget != null && newTarget != ActiveTarget)
            {
                ActiveTarget = newTarget;
                ActiveTrace = null;
                ClearActiveGraph();
            };
        }

        /// <summary>
        /// Set the binary target active in the UI
        /// </summary>
        /// <param name="newTarget">BinaryTarget object to activate</param>
        public void SetActiveTarget(BinaryTarget newTarget)
        {
            if (newTarget != null && newTarget != ActiveTarget)
            {
                ActiveTarget = newTarget;
            };
        }

        /// <summary>
        /// Deactivate the currently active graph in the UI
        /// </summary>
        public void ClearActiveGraph()
        {
            ActiveGraph = null;
        }

        /// <summary>
        /// Set the currently active trace in the UI. If a specific trace is not specified
        /// the trace chosen depends on the 'newest' parameter
        /// </summary>
        /// <param name="trace">An optional TraceRecord to set as active</param>
        /// <param name="newest">If true, get the most recently spawned trace. If false get the first in the list (not guaranteed to be the oldest)</param>
        public void SelectActiveTrace(TraceRecord trace = null, bool newest = false)
        {
            ActiveGraph = null;

            if (trace == null && ActiveTarget != null)
            {
                if (newest)
                    trace = ActiveTarget.GetNewestTrace();
                else
                    trace = ActiveTarget.GetFirstTrace();
            }

            ActiveTrace = trace;
            SelectGraphInActiveTrace();
        }


        /// <summary>
        /// Initialise a loaded target binary from a trace save object
        /// </summary>
        /// <param name="saveJSON">A Newtonsoft JObject for the saved trace</param>
        /// <param name="targetResult">The created BinaryTarget object</param>
        /// <returns></returns>
        static bool InitialiseTarget(Newtonsoft.Json.Linq.JObject saveJSON, out BinaryTarget targetResult)
        {
            BinaryTarget target = null;
            targetResult = null;

            string binaryPath = saveJSON.GetValue("BinaryPath").ToString();
            if (binaryPath == null) return false;

            if (!targets.GetTargetByPath(binaryPath, out target))
            {
                bool isLibrary = false;
                if (saveJSON.TryGetValue("IsLibrary", out JToken isLibTok) && isLibTok.Type == JTokenType.Boolean)
                    isLibrary = isLibTok.ToObject<bool>();
                target = targets.AddTargetByPath(binaryPath, isLibrary: isLibrary);
            }
            //myui.targetListCombo.addTargetToInterface(target, newBinary);

            targetResult = target;
            return true;

        }


        Dictionary<TraceRecord, PlottedGraph> LastGraphs = new Dictionary<TraceRecord, PlottedGraph>();
        Dictionary<TraceRecord, uint> LastSelectedTheads = new Dictionary<TraceRecord, uint>();

        /// <summary>
        /// Causes the UI to switch to displaying a different thread graph
        /// </summary>
        /// <param name="graph">The PlottedGraph object of the graph to switch to. Null to clear the active graph.</param>
        public void SwitchToGraph(PlottedGraph graph)
        {
            //valid target or not, we assume current graph is no longer fashionable
            ClearActiveGraph();

            if (graph == null || graph.beingDeleted) return;

            TraceRecord trace = ActiveTrace;
            if (trace == null) return;
            if (ActiveTrace?.PID != graph.pid) return;

            if (SetActiveGraph(graph))
            {
                Debug.Assert(trace.PID == graph.pid);
                LastGraphs[trace] = graph;
                LastSelectedTheads[trace] = graph.tid;
            }
            //setGraphUIControls(graph);
        }

        /// <summary>
        /// Cause the UI to choose an active graph to display, used when no graph is active
        /// </summary>
        /// <returns>If a graph is now active</returns>
        public bool ChooseActiveGraph()
        {
            if (ActiveGraph != null)
            {
                if (ActiveGraph.beingDeleted)
                {
                    ActiveGraph = null;
                    return false;
                }

                return true;
            }

            if (ActiveGraph == null)
            {
                if (ActiveTrace == null)
                    SelectActiveTrace();

                SelectGraphInActiveTrace();
            }

            return (ActiveGraph != null);
        }

        /// <summary>
        /// Activate a graph in the active trace
        /// Selects the last one that was active in this trace, or the first seen
        /// </summary>
        void SelectGraphInActiveTrace()
        {
            TraceRecord selectedTrace = ActiveTrace;
            if (selectedTrace == null)
            {
                return;
            }

            if (LastGraphs.TryGetValue(selectedTrace, out PlottedGraph foundGraph))
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
                    PlottedGraph lastgraph = traceGraphs.Find(pg => pg.tid == lastTID);
                    if (lastgraph != null)
                    {
                        SwitchToGraph(lastgraph);
                        found = true;
                    }
                }

                if (found) return;
            }

            PlottedGraph firstgraph = selectedTrace.GetFirstGraph();
            if (firstgraph != null)
            {
                Logging.RecordLogEvent("Got first graph " + firstgraph.tid,
                    Logging.LogFilterType.TextDebug, trace: firstgraph.InternalProtoGraph.TraceData);
                SwitchToGraph(firstgraph);
            }
        }


        /// <summary>
        /// Sets a specific thread graph for the UI to display
        /// </summary>
        /// <param name="graph">A PlottedGraph object of the thread to display</param>
        /// <returns></returns>
        public bool SetActiveGraph(PlottedGraph graph)
        {
            if (ActiveGraph != null && ActiveGraph.beingDeleted)
                return false;
            ClearActiveGraph();
            if (graph.pid != ActiveTrace.PID) ActiveTrace = null;

            Debug.Assert(ActiveGraph == null);

            ActiveGraph = graph;
            return true;
        }

        /// <summary>
        /// Get the currently active thread graph being shown by the UI
        /// </summary>
        /// <returns>The PlottedGraph object of the active thread graph</returns>
        public PlottedGraph getActiveGraph()
        {
            if (ActiveGraph != null && ActiveGraph.beingDeleted) return null;

            if (ActiveGraph == null)
            {
                return null;
            }
            return ActiveGraph;
        }


        /// <summary>
        /// Load a TraceRecord from a serialised trace JObject
        /// </summary>
        /// <param name="saveJSON">The Newtonsoft JObject of the saved trace</param>
        /// <param name="target">The binarytarget associated with the trace</param>
        /// <param name="traceResult">The output reconstructed TraceRecord</param>
        /// <returns>true if a new trace was created, false if failed or duplicated</returns>
        static bool LoadTraceRecord(Newtonsoft.Json.Linq.JObject saveJSON, BinaryTarget target, out TraceRecord traceResult)
        {
            bool valid = true;
            valid &= saveJSON.TryGetValue("PID", out JToken jPID);
            valid &= saveJSON.TryGetValue("PID_ID", out JToken jID);
            valid &= saveJSON.TryGetValue("StartTime", out JToken jTime);

            if (valid == false || jPID.Type != JTokenType.Integer ||
                jID.Type != JTokenType.Integer)
            {
                Console.WriteLine("[rgat]Warning: Bad trace metadata. Load failed.");
                traceResult = null;
                return false;
            }


            //temporary loading of unix ts in old save files. TODO: move to new format
            DateTime StartTime;
            if (jTime.Type == JTokenType.Date)
                StartTime = jTime.ToObject<DateTime>();
            else
            {
                Console.WriteLine("BAD DATETIME");
                traceResult = null;
                return false;
            }


            bool newTrace = target.CreateNewTrace(StartTime, (uint)jPID, (uint)jID, out traceResult);
            if (!newTrace)
            {
                //updateActivityStatus("Trace already loaded", 15000);
                Console.WriteLine("[rgat] Trace already loaded");
                return false;
            }

            //updateActivityStatus("Loaded saved process: " + QString::number(tracePID), 15000);
            return true;
        }

        /// <summary>
        /// Load a saved trace
        /// </summary>
        /// <param name="path">The fileystem path of the saved trace</param>
        /// <param name="trace">The loaded TraceRecord object</param>
        /// <returns></returns>
        public bool LoadTraceByPath(string path, out TraceRecord trace)
        {
            //display_only_status_message("Loading save file...", clientState);
            //updateActivityStatus("Loading " + QString::fromStdString(traceFilePath.string()) + "...", 2000);
            trace = null;
            if (!File.Exists(path)) return false;
            Newtonsoft.Json.Linq.JObject saveJSON = null;
            using (StreamReader file = File.OpenText(path))
            {
                string jsnfile = file.ReadToEnd();
                try
                {
                    saveJSON = Newtonsoft.Json.Linq.JObject.Parse(jsnfile);
                }
                catch (Newtonsoft.Json.JsonReaderException e)
                {
                    Console.WriteLine("Failed to parse trace file - invalid JSON.");
                    Console.WriteLine("\t->\t" + e.Message);
                    return false;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to parse trace file: " + e.Message);
                    return false;
                }
            }

            BinaryTarget target;
            if (!InitialiseTarget(saveJSON, out target))
            {
                //updateActivityStatus("Process data load failed - possibly corrupt trace file", 15000);

                return false;
            }

            if (!LoadTraceRecord(saveJSON, target, out trace))
            {
                return false;
            }

            if (!trace.load(saveJSON, _GraphicsDevice))
            {
                target.DeleteTrace(trace.launchedTime);
                trace = null;
                return false;
            }
            //updateActivityStatus("Loaded " + QString::fromStdString(traceFilePath.filename().string()), 15000);
            ExtractChildTraceFilenames(saveJSON, out List<string> childrenFiles);
            if (childrenFiles.Count > 0)
                LoadChildTraces(childrenFiles, trace);

            return true;
        }

        /// <summary>
        /// Get a list of child trace processes from a saved trace
        /// </summary>
        /// <param name="saveJSON">The Newtonsoft JObject of the saved trace</param>
        /// <param name="childrenFiles">A list of relative filesystem paths of child traces</param>
        void ExtractChildTraceFilenames(JObject saveJSON, out List<string> childrenFiles)
        {
            childrenFiles = new List<string>();
            if (saveJSON.TryGetValue("Children", out JToken jChildren) && jChildren.Type == JTokenType.Array)
            {
                JArray ChildrenArray = (JArray)jChildren;
                foreach (JToken fname in ChildrenArray)
                {
                    childrenFiles.Add(fname.ToString());
                }
            }
        }

        /// <summary>
        /// Loads child traces into a trace record
        /// </summary>
        /// <param name="childrenFiles">A list of relative filesystem paths of traces</param>
        /// <param name="trace">The parent TraceRecord of the child traces</param>
        void LoadChildTraces(List<string> childrenFiles, TraceRecord trace)
        {

            string saveDir = "C:\\";//config.saveDir; //should be same dir as loaded trace?
            foreach (string file in childrenFiles)
            {

                string childFilePath = Path.Combine(saveDir, file);

                if (Path.GetDirectoryName(childFilePath) != saveDir) //or a children subdir?
                    return; //avoid directory traversal

                if (!File.Exists(childFilePath))
                {
                    Console.WriteLine("[rgat] Warning: Unable to find child save file " + childFilePath);
                    return;
                }

                LoadTraceByPath(childFilePath, out TraceRecord childTrace);
                trace.children.Add(childTrace);
                childTrace.ParentTrace = trace;
            }

        }

        /// <summary>
        /// Cause all the traces of all active targets to be serialised to the trace directory
        /// </summary>
        public static void SaveAllTargets()
        {
            List<BinaryTarget> targslist = targets.GetBinaryTargets();
            foreach (BinaryTarget targ in targslist)
            {
                SaveTarget(targ);
            }
            Console.WriteLine($"Finished saving {targslist.Count} targets");
        }

        /// <summary>
        /// Serialise all the traces of the the specified target to the trace directory
        /// </summary>
        /// <param name="targ">A binaryTarget to save traces of</param>
        public static void SaveTarget(BinaryTarget targ)
        {
            var traceslist = targ.GetTracesUIList();

            //todo save binary data so it can be loaded without the binary present
            // preview, bitwidth, signature hits, exports, is library
            foreach (Tuple<DateTime, TraceRecord> time_trace in traceslist)
            {
                TraceRecord trace = time_trace.Item2;
                DateTime creationTime = time_trace.Item1;

                if (!trace.WasLoadedFromSave)
                {
                    trace.Save(creationTime);
                }
            }
        }

        /// <summary>
        /// Export the current trace in the pajek format, a simple graph serialisation format that other graph layout programs accept
        /// </summary>
        public void ExportTraceAsPajek(TraceRecord trace, uint TID)
        {
            trace.ExportPajek(TID);
        }


        readonly object _testDictLock = new object();
        Dictionary<long, TraceRecord> _testConnections = new Dictionary<long, TraceRecord>();
        /// <summary>
        /// Store a reference to an incoming rgat test trace
        /// </summary>
        /// <param name="testID">The ID of the test</param>
        /// <param name="trace">The TraceRecord associated with the test</param>
        public void RecordTestRunConnection(long testID, TraceRecord trace)
        {
            lock (_testDictLock)
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
        public bool GetTestTrace(long testID, out TraceRecord trace)
        {

            lock (_testDictLock)
            {
                if (_testConnections.TryGetValue(testID, out trace))
                {
                    _testConnections.Remove(testID);
                    return true;
                }
                return false;
            }
        }

        public static byte[] ReadBinaryResource(string name)
        {
            System.Reflection.Assembly assembly = Assembly.GetExecutingAssembly();
            System.IO.Stream fs = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames()[0]);
            System.Resources.ResourceReader r = new System.Resources.ResourceReader(fs);
            r.GetResourceData(name, out string rtype, out byte[] resBytes);
            if (resBytes == null || rtype != "ResourceTypeCode.ByteArray") return null;

            //https://stackoverflow.com/questions/32891004/why-resourcereader-getresourcedata-return-data-of-type-resourcetypecode-stream
            Stream stream = new MemoryStream(resBytes);
            byte[] result = new byte[stream.Length - 4];
            stream.Seek(4, SeekOrigin.Begin);
            stream.Read(result, 0, result.Length);
            return result;
        }

    }
}
