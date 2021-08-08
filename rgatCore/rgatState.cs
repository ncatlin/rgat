using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

/// <summary>
/// Handles Loading/Saving/Storage of traces and binaries. 
/// Holds various utility objects such as signature scanners and video encoder.
/// </summary>
namespace rgat
{
    public class rgatState
    {
        public BinaryTargets targets = new BinaryTargets();
        public BinaryTarget ActiveTarget;// { get; private set; } = null;
        public TraceRecord ActiveTrace;
        public PlottedGraph ActiveGraph { get; private set; }
        public Veldrid.GraphicsDevice _GraphicsDevice;
        public Veldrid.CommandList _CommandList;
        public DetectItEasy DIELib;
        public YARAScan YARALib;
        public VideoEncoder VideoRecorder = new VideoEncoder();
        public BridgeConnection NetworkBridge = new BridgeConnection(isgui: true);

        public PreviewGraphsWidget PreviewWidget;

        public rgatState()
        {

        }

        public void InitVeldrid(Veldrid.GraphicsDevice _gd, Veldrid.CommandList _cl)
        {
            _GraphicsDevice = _gd;
            _CommandList = _cl;
            PlottedGraph.clientState = this;
        }

        public void LoadSignatures()
        {
            Logging.RecordLogEvent("Loading DiELib", Logging.LogFilterType.TextDebug);
            DIELib = new DetectItEasy(GlobalConfig.DiESigsPath);
            Logging.RecordLogEvent("DiELib loaded. loading YARA", Logging.LogFilterType.TextDebug);

            YARALib = new YARAScan(GlobalConfig.YARARulesDir);
            Logging.RecordLogEvent("YARA loaded", Logging.LogFilterType.TextDebug);
        }


        public bool rgatIsExiting { private set; get; } = false;
        public int InstrumentationCount { private set; get; } = 0;
        public void RecordInstrumentationConnection() => InstrumentationCount += 1;

        public LayoutStyles.Style newGraphLayout = LayoutStyles.Style.ForceDirected3DNodes;

        Dictionary<TraceRecord, PlottedGraph> LastGraphs = new Dictionary<TraceRecord, PlottedGraph>();
        Dictionary<TraceRecord, uint> LastSelectedTheads = new Dictionary<TraceRecord, uint>();

        /// <summary>
        /// Terminate all spawned processes and internal workers, then exit
        /// </summary>
        public void ShutdownRGAT()
        {
            rgatIsExiting = true;
            DIELib?.CancelAllScans();
            YARALib?.CancelAllScans();
            VideoRecorder.Done();

            foreach (BinaryTarget targ in this.targets.GetBinaryTargets())
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

        public BinaryTarget AddTargetByPath(string path, int arch = 0, bool makeActive = true)
        {
            BinaryTarget targ = targets.AddTargetByPath(path, arch);
            DIELib?.StartDetectItEasyScan(targ);
            YARALib?.StartYARATargetScan(targ);

            if (makeActive)
            {
                ClearActiveGraph();
                SetActiveTarget(targ);
            }

            return targ;
        }



        /*

        /// <summary>
        /// Display a message in the visualise log panel, useful for helping the user understand the events unfolding 
        /// </summary>
        /// <param name="message">Message to display</param>
        /// <param name="visibility">
        /// VisThread -  Messages appearing in the graph visualiser if that particular thread is being viewed
        /// VisProcess - Messages appearing in the graph visualiser if any thread from that process is being viewed
        /// VisAll    - Messages that will always appear in the graph visualiser
        /// </param>
        /// <param name="graph">Graph this applies to. If aimed at a trace, just use any graph of the trace</param>
        /// <param name="colour">Optional colour, otherwise default will be used</param>
        public void AddVisualiserMessage(string message, eMessageType visibility, ProtoGraph? graph = null, WritableRgbaFloat? colour = null)
        {
            Debug.Assert(visibility >= eMessageType.eVisThread && visibility <= eMessageType.eVisAll);
            long timenow = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            //Show on visualiser widgets
            LOG_ENTRY msg = new LOG_ENTRY()
            {
                colour = colour?.ToUint(),
                graph = graph,
                text = message,
                visibility = visibility,
                expiryMS = timenow + GlobalConfig.VisMessageMaxLingerTime
            };
            lock (_messagesLock)
            {
                DisplayMessages.Add(msg);
            }
            AddLogMessage(message, eMessageType.eLog, graph, colour);
        }


        public LOG_ENTRY[] GetVisualiserMessages()
        {
            long timenow = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            lock (_messagesLock)
            {
                LOG_ENTRY[] result = DisplayMessages.Where(x => x.expiryMS > timenow).ToArray();
                if (result.Length < DisplayMessages.Count)
                    DisplayMessages = result.ToList();
                return result;
            }
        }
        */


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

        public void SetActiveTarget(BinaryTarget newTarget)
        {
            if (newTarget != null && newTarget != ActiveTarget)
            {
                ActiveTarget = newTarget;
            };
        }

        public void ClearActiveGraph()
        {
            ActiveGraph = null;
        }


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
            selectGraphInActiveTrace();
        }


        static bool initialiseTarget(Newtonsoft.Json.Linq.JObject saveJSON, BinaryTargets targets, out BinaryTarget targetResult)
        {
            BinaryTarget target = null;
            targetResult = null;

            string binaryPath = saveJSON.GetValue("BinaryPath").ToString();
            if (binaryPath == null) return false;

            if (!targets.GetTargetByPath(binaryPath, out target))
            {
                target = targets.AddTargetByPath(binaryPath);
            }
            //myui.targetListCombo.addTargetToInterface(target, newBinary);

            targetResult = target;
            return true;

        }

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

                selectGraphInActiveTrace();
            }


            return (ActiveGraph != null);

        }

        //activate a graph in the active trace
        //selects the last one that was active in this trace, or the first seen
        void selectGraphInActiveTrace()
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



        public bool SetActiveGraph(PlottedGraph graph)
        {

            if (ActiveGraph != null && ActiveGraph.beingDeleted)
                return false;
            ClearActiveGraph();
            if (graph.pid != ActiveTrace.PID) ActiveTrace = null;

            Debug.Assert(ActiveGraph == null);

            //activeGraphLock.lock () ;
            //if (((plotted_graph*)graph)->increase_thread_references(50))
            //{

            ActiveGraph = graph;
            //}
            //activeGraphLock.unlock();
            return true;
        }

        public PlottedGraph getActiveGraph(bool increaseReferences)
        {
            if (ActiveGraph != null && ActiveGraph.beingDeleted) return null;

            //activeGraphLock.lock () ;

            if (ActiveGraph == null)
            {
                //activeGraphLock.unlock();
                return null;
            }

            /*
             * todooooooooooooo
             * 
            if (increaseReferences)
            {
                bool success = activeGraph.increase_thread_references(52);
                if (!success)
                {
                    activeGraphLock.unlock();
                    return NULL;
                }
                //cout << "[+1: "<< ((plotted_graph *)activeGraph).threadReferences << "]increased refs to graph " << activeGraph << endl;
            }
            */
            PlottedGraph tmp = ActiveGraph;
            //activeGraphLock.unlock();

            return tmp;
        }

        public bool CreateNewPlottedGraph(ProtoGraph protoGraph, out PlottedGraph MainGraph)
        {
            switch (newGraphLayout)
            {
                case LayoutStyles.Style.ForceDirected3DNodes:
                    {
                        MainGraph = new PlottedGraph(protoGraph, _GraphicsDevice, GlobalConfig.defaultGraphColours);
                        return true;
                    }
                default:
                    {
                        MainGraph = null;
                        Console.WriteLine("Bad graph layout: " + newGraphLayout);
                        Debug.Assert(false);
                        return false;
                    }
            }
        }

        public static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dtDateTime;
        }

        //return true if a new trace was created, false if failed or duplicate
        //todo should have 3 returns
        static bool initialiseTrace(Newtonsoft.Json.Linq.JObject saveJSON, BinaryTarget target, out TraceRecord traceResult)
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
            if (!initialiseTarget(saveJSON, targets, out target))
            {
                //updateActivityStatus("Process data load failed - possibly corrupt trace file", 15000);

                return false;
            }

            if (!initialiseTrace(saveJSON, target, out trace))
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

        public void SaveAllTargets()
        {
            List<BinaryTarget> targslist = targets.GetBinaryTargets();
            foreach (BinaryTarget targ in targslist)
            {
                SaveTarget(targ);
            }
            Console.WriteLine($"Finished saving {targslist.Count} targets");
        }

        public void SaveTarget(BinaryTarget targ)
        {
            var traceslist = targ.GetTracesUIList();
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

        public void ExportTraceAsPajek(TraceRecord trace, uint TID)
        {
            trace.ExportPajek(TID);
        }


        readonly object _testDictLock = new object();
        Dictionary<long, TraceRecord> _testConnections = new Dictionary<long, TraceRecord>();
        public void RecordTestRunConnection(long testID, TraceRecord trace)
        {
            lock (_testDictLock)
            {
                Debug.Assert(!_testConnections.ContainsKey(testID));
                Debug.Assert(trace != null);
                _testConnections.Add(testID, trace);
            }
        }

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

    }
}
