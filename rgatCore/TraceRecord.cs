using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using rgatCore.Testing;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using static rgatCore.Logging;

namespace rgatCore
{
    public class InstructionData
    {
        public int DebugID;

        //void* bb_ptr;
        public string mnemonic;
        public string op_str;
        //store all the basic blocks this instruction is a member of
        //List<Tuple<ulong, BLOCK_IDENTIFIER>> blockIDs;
        /* memory/speed tradeoff 
		1.construct every frame and save memory 
		2.construct at disassemble time and improve render speed
		*/
        //store all the basic blocks this instruction is a member of
        public List<uint> ContainingBlockIDs;

        public string ins_text;
        public eNodeType itype;
        public bool conditional;
        public bool dataEx;
        public bool hasSymbol;
        public bool PossibleidataThunk;
        public bool IsMPX = false; //https://en.wikipedia.org/wiki/Intel_MPX

        public ulong address;
        public ulong branchAddress;
        public ulong condDropAddress;
        List<Tuple<uint, uint>> threadvertIdx; //was an unordered dictionary in the C++ version
        public int globalmodnum;
        public int mutationIndex;

        public bool BlockBoundary;

        //this was added later, might be worth ditching other stuff in exchange
        public byte[] opcodes;
        public int numbytes;
        public List<Tuple<uint, uint>> ThreadVerts => threadvertIdx.ToList();

        public bool GetThreadVert(uint TID, out uint vert)
        {
            if (threadvertIdx == null)
            {
                vert = uint.MaxValue;
                return false;
            }

            for (var i = 0; i < threadvertIdx.Count; i++)
            {
                if (threadvertIdx[i].Item1 == TID) { vert = threadvertIdx[i].Item2; return true; }
            }
            vert = uint.MaxValue;
            return false;
        }

        public bool InThread(uint TID)
        {
            if (threadvertIdx == null)
            {
                return false;
            }
            for (var i = 0; i < threadvertIdx.Count; i++)
            {
                if (threadvertIdx[i].Item1 == TID) { return true; }
            }
            return false;
        }

        public void AddThreadVert(uint TID, uint vert)
        {
            if (threadvertIdx == null)
            {
                threadvertIdx = new List<Tuple<uint, uint>>();
            }
            threadvertIdx.Add(new Tuple<uint, uint>(TID, vert));
        }
    }

    public class TraceRecord
    {
        public enum eTracePurpose { eVisualiser, eFuzzer };
        public enum eTraceState { eRunning, eSuspended, eTerminated };


        public TraceRecord(uint newPID, long randomNo, BinaryTarget binary, DateTime timeStarted, eTracePurpose purpose = eTracePurpose.eVisualiser, int arch = 0)
        {
            PID = newPID;
            randID = randomNo;
            launchedTime = timeStarted;
            TraceType = purpose;

            //modIDTranslationVec.resize(255, -1);

            binaryTarg = binary;
            if (arch != 0 && binary.BitWidth != arch)
            {
                binary.BitWidth = arch;
            }

            DisassemblyData = new ProcessRecord(binary.BitWidth);
            TraceState = eTraceState.eRunning;

            _tlFilterCounts[Logging.LogFilterType.TimelineProcess] = 0;
            _tlFilterCounts[Logging.LogFilterType.TimelineThread] = 0;
        }

        public long TestRunID { get; private set; }
        public void SetTestRunID(long val) => TestRunID = val;

        bool _loadedFromSave = false;
        public bool WasLoadedFromSave => _loadedFromSave;

        string getModpathID() { return PID.ToString() + randID.ToString(); }
        /*
		void notify_new_pid(uint pid, int PID_ID, uint parentPid) { runtimeline.notify_new_pid(pid, PID_ID, parentPid); running = true; }
		void notify_pid_end(uint pid, int PID_ID) { running = runtimeline.notify_pid_end(pid, PID_ID); }
		void notify_tid_end(uint tid) { runtimeline.notify_thread_end(getPID(), randID, tid); }
		*/

        public void SetTraceState(eTraceState newState)
        {
            Logging.RecordLogEvent($"Set trace state {newState}", Logging.LogFilterType.TextDebug);
            if (TraceState == newState) return;
            Logging.RecordLogEvent("\tactioning it", Logging.LogFilterType.TextDebug);
            if (newState != eTraceState.eSuspended)
            {

                lock (GraphListLock)
                {
                    Logging.RecordLogEvent($"\t\t {ProtoGraphs.Count} graphs", Logging.LogFilterType.TextDebug);
                    foreach (ProtoGraph graph in ProtoGraphs.Values)
                    {
                        Logging.RecordLogEvent("\t\t clearing flag step", Logging.LogFilterType.TextDebug);
                        graph.ClearRecentStep();
                    }
                }
            }
            TraceState = newState;

        }

        public bool InsertNewThread(PlottedGraph mainplot)
        {
            lock (GraphListLock)
            {

                if (ProtoGraphs.ContainsKey(mainplot.tid))
                {
                    Console.WriteLine("Warning - thread with duplicate ID detected. This should never happen. Undefined behaviour ahoy.");
                    return false;
                }

                ProtoGraphs.Add(mainplot.tid, mainplot.InternalProtoGraph);
                PlottedGraphs.Add(mainplot.tid, new Dictionary<eRenderingMode, PlottedGraph>());
                PlottedGraphs[mainplot.tid][eRenderingMode.eStandardControlFlow] = mainplot;

                //runtimeline.notify_new_thread(getPID(), randID, TID);
            }
            Console.WriteLine("Todo implement runtimeline");
            return true;
        }


        //bool is_process(uint testpid, int testID);



        public PlottedGraph GetFirstGraph()
        {
            if (PlottedGraphs.Count == 0) return null;

            //if (graphListLock.trylock())
            var MainPlottedGraphs = GetPlottedGraphs(eRenderingMode.eStandardControlFlow);
            var graphsWithNodes = MainPlottedGraphs.Where(g => g?.InternalProtoGraph.NodeList.Count > 0);
            if (graphsWithNodes.Any())
            {
                return graphsWithNodes.First();
            }

            var graphsWithInstructions = MainPlottedGraphs.Where(g => g.InternalProtoGraph.TotalInstructions > 0);
            if (graphsWithInstructions.Any())
            {
                return graphsWithInstructions.First();
            }

            var graphsWithData = MainPlottedGraphs.Where(g => g.InternalProtoGraph.TraceReader.HasPendingData());
            if (graphsWithData.Any())
            {
                return graphsWithData.First();
            }

            return MainPlottedGraphs.First();
        }

        public PlottedGraph GetLatestGraph()
        {
            if (PlottedGraphs.Count == 0) return null;

            //if (graphListLock.trylock())
            var MainPlottedGraphs = GetPlottedGraphs(eRenderingMode.eStandardControlFlow);
            var graphsWithNodes = MainPlottedGraphs.Where(g => g?.InternalProtoGraph.NodeList.Count > 0);
            if (graphsWithNodes.Any())
            {
                return graphsWithNodes.Last();
            }

            var graphsWithInstructions = MainPlottedGraphs.Where(g => g.InternalProtoGraph.TotalInstructions > 0);
            if (graphsWithInstructions.Any())
            {
                return graphsWithInstructions.Last();
            }

            var graphsWithData = MainPlottedGraphs.Where(g => g.InternalProtoGraph.TraceReader.HasPendingData());
            if (graphsWithData.Any())
            {
                return graphsWithData.Last();
            }

            return MainPlottedGraphs.Last();
        }

        /*

        DateTime getStartedTime() { return launchedTime; }

        /*
		void getPlottedGraphs(void* graphPtrVecPtr);
		void getProtoGraphs(void* graphPtrVecPtr);
		bool isRunning() { return running; }
		int countDescendants();
	
		void save(void* clientConfigPtr);
		*/
        public bool load(Newtonsoft.Json.Linq.JObject saveJSON)//, List<QColor> &colours);
        {
            if (!DisassemblyData.load(saveJSON)) //todo - get the relevant dynamic bit for this trace
            {
                Logging.RecordLogEvent("ERROR: Process data load failed", Logging.LogFilterType.TextError);
                return false;
            }

            Logging.RecordLogEvent("Loaded process data. Loading graphs...", Logging.LogFilterType.TextDebug);


            if (!LoadProcessGraphs(saveJSON))//, colours))//.. &config.graphColours))
            {
                Logging.RecordLogEvent("Process Graph load failed", Logging.LogFilterType.TextError);
                return false;
            }


            if (!LoadTimeline(saveJSON))

            {
                Console.WriteLine("[rgat]Timeline load failed");
                return false;
            }

            _loadedFromSave = true;
            TraceState = eTraceState.eTerminated;
            return true;
        }


        void killTraceProcess() { if (IsRunning) { killed = true; } }
        bool should_die() { return killed; }

        //void killTree();

        // Process start, process end, thread start, thread end
        readonly object _logLock = new object();
        List<Logging.TIMELINE_EVENT> _timeline = new List<Logging.TIMELINE_EVENT>();
        Dictionary<Logging.LogFilterType, int> _tlFilterCounts = new Dictionary<Logging.LogFilterType, int>();
        int runningProcesses = 0;
        int runningThreads = 0;

        public void RecordTimelineEvent(Logging.eTimelineEvent type, TraceRecord trace = null, ProtoGraph graph = null)
        {
            int currentCount;
            switch (type)
            {
                case Logging.eTimelineEvent.ProcessStart:
                    {
                        Debug.Assert(trace != null);

                        lock (_logLock)
                        {
                            _timeline.Add(new Logging.TIMELINE_EVENT(type, trace));
                            runningProcesses += 1;
                            _tlFilterCounts.TryGetValue(Logging.LogFilterType.TimelineProcess, out currentCount);
                            _tlFilterCounts[Logging.LogFilterType.TimelineProcess] = currentCount + 1;
                        }
                    }
                    break;
                case Logging.eTimelineEvent.ProcessEnd:
                    {
                        Debug.Assert(trace != null);
                        //might have been terminated by other means
                        if (trace.TraceState != eTraceState.eTerminated)
                        {
                            runningProcesses -= 1;
                            SetTraceState(eTraceState.eTerminated);

                            if (runningThreads != 0)
                            {
                                Logging.RecordLogEvent("Got process terminate event with running threads. Forcing state to terminated");
                                var graphs = trace.GetProtoGraphs();
                                foreach (ProtoGraph pgraph in graphs)
                                {
                                    if (!pgraph.Terminated)
                                    {

                                        Logging.RecordLogEvent($"Setting state of TID{pgraph.ThreadID}, PID{pgraph.TraceData.PID} to terminated");
                                        pgraph.SetTerminated();
                                    }
                                }

                            }

                            lock (_logLock)
                            {
                                _timeline.Add(new Logging.TIMELINE_EVENT(type, trace));
                                _tlFilterCounts.TryGetValue(Logging.LogFilterType.TimelineProcess, out currentCount);
                                _tlFilterCounts[Logging.LogFilterType.TimelineProcess] = currentCount + 1;
                            }
                        }
                    }
                    break;
                case Logging.eTimelineEvent.ThreadStart:
                    {
                        Debug.Assert(graph != null);
                        lock (_logLock)
                        {
                            _timeline.Add(new Logging.TIMELINE_EVENT(type, graph));
                            runningThreads += 1;
                            _tlFilterCounts.TryGetValue(Logging.LogFilterType.TimelineThread, out currentCount);
                            _tlFilterCounts[Logging.LogFilterType.TimelineThread] = currentCount + 1;
                        }
                    }
                    break;
                case Logging.eTimelineEvent.ThreadEnd:
                    {
                        Debug.Assert(graph != null);
                        Debug.Assert(runningThreads > 0);
                        lock (_logLock)
                        {
                            _timeline.Add(new Logging.TIMELINE_EVENT(type, graph));
                            runningThreads -= 1;
                            if (runningProcesses == 0 && runningThreads == 0) SetTraceState(eTraceState.eTerminated);
                            _tlFilterCounts.TryGetValue(Logging.LogFilterType.TimelineThread, out currentCount);
                            _tlFilterCounts[Logging.LogFilterType.TimelineThread] = currentCount + 1;
                        }
                    }
                    break;
                default:
                    Debug.Assert(false, "Timeline event has no assigned filter");
                    break;
            }

        }

        ulong uniqAPICallIdx = 0;

        public void RecordAPICall(NodeData node, ProtoGraph graph, ulong callIndex, ulong repeats)
        {
            Logging.APICALL call = new Logging.APICALL
            {
                index = callIndex,
                node = node,
                repeats = repeats,
                uniqID = uniqAPICallIdx++,
                graph = graph,
                ApiType = DisassemblyData.GetAPIType(node.GlobalModuleID, node.address)
            };
            lock (_logLock)
            {
                _timeline.Add(new Logging.TIMELINE_EVENT(Logging.eTimelineEvent.APICall, call));
                _tlFilterCounts[call.ApiType] = _tlFilterCounts.GetValueOrDefault(call.ApiType, 0) + 1;
            }
            //Logging.RecordLogEvent("Api call: "+node.Label, trace:this, graph: graph, apicall: call, filter: call.ApiType);

        }

        public int TimelineItemsCount => _timeline.Count;

        /// <summary>
        /// Fetches an array of the newest timeline events for the trace
        /// </summary>
        /// <param name="oldest">The oldest event to return</param>
        /// <param name="max">The most events to return. Default 5.</param>
        /// <returns>And array of TIMELINE_EVENT objects</returns>
        public Logging.TIMELINE_EVENT[] GetTimeLineEntries(long oldest = 0, int max = -1)
        {
            if (max == -1) max = _timeline.Count;
            List<Logging.TIMELINE_EVENT> results = new List<Logging.TIMELINE_EVENT>();
            lock (_logLock)
            {
                var last = _timeline.Count - 1;
                for (; last >= 0 && last >= _timeline.Count - max; last--)
                {
                    if (_timeline[last].EventTimeMS < oldest) break;
                }
                for (var i = last + 1; i < _timeline.Count; i++)
                {
                    results.Add(_timeline[i]);
                }
            }
            return results.ToArray();
        }

        public Dictionary<Logging.LogFilterType, int> GetTimeLineFilterCounts()
        {
            Dictionary<Logging.LogFilterType, int> result = null;
            lock (_logLock)
            {
                result = new Dictionary<Logging.LogFilterType, int>(_tlFilterCounts);
            }
            for (var i = 0; i < (int)Logging.LogFilterType.COUNT; i++)
            {
                if (!result.ContainsKey((Logging.LogFilterType)i))
                {
                    result.Add((Logging.LogFilterType)i, 0);
                }
            }
            return result;
        }


        public eCodeInstrumentation FindContainingModule(ulong address, out int localmodID)
        {
            localmodID = DisassemblyData.FindContainingModule(address);
            if (localmodID == -1)
            {

                Console.WriteLine($"Warning: Unknown module in traceRecord::FindContainingModule for address 0x{address:X}");
                int attempts = 1;
                while (attempts-- != 0)
                {
                    Thread.Sleep(30);
                    localmodID = DisassemblyData.FindContainingModule(address);
                    if (localmodID != -1)
                    {
                        Console.WriteLine("FindContainingModule found!");
                        break;
                    }
                }

                return eCodeInstrumentation.eUninstrumentedCode;
                //assert(localmodID != -1);
            }

            return DisassemblyData.ModuleTraceStates[localmodID];
        }

        private readonly object GraphListLock = new object();
        Dictionary<uint, ProtoGraph> ProtoGraphs = new Dictionary<uint, ProtoGraph>();

        //get a copy of the protographs list
        public List<ProtoGraph> GetProtoGraphs()
        {
            lock (GraphListLock)
            {
                return ProtoGraphs.Values.ToList();
            }
        }
        public int GraphCount => ProtoGraphs.Count;

        public Dictionary<uint, Dictionary<eRenderingMode, PlottedGraph>> PlottedGraphs = new Dictionary<uint, Dictionary<eRenderingMode, PlottedGraph>>();

        public List<PlottedGraph> GetPlottedGraphs(eRenderingMode mode)
        {
            lock (GraphListLock)
            {
                return PlottedGraphs.Values.Select(gDict => gDict.ContainsKey(mode) ? gDict[mode] : null).ToList();
            }
        }

        public eTracePurpose TraceType { get; private set; } = eTracePurpose.eVisualiser;

        public TraceRecord ParentTrace = null;
        public List<TraceRecord> children = new List<TraceRecord>();

        //returns a copy of the child trace list
        public List<TraceRecord> GetChildren()
        {
            lock (GraphListLock)
            {
                return children.ToList();
            }
        }


        public TraceProcessorWorkers ProcessThreads = new TraceProcessorWorkers();
        //void* fuzzRunPtr = null;

        public uint PID { get; private set; }
        public long randID { get; private set; } //to distinguish between processes with identical PIDs


        public int CountDescendantTraces()
        {
            int TraceCount = 1;
            foreach (var child in this.children)
            {
                TraceCount += child.CountDescendantTraces();
            }
            return TraceCount;
        }


        public TraceRecord GetTraceByID(ulong traceID)
        {
            if (PID == traceID) return this;

            lock (GraphListLock)
            {
                foreach (var child in children)
                {
                    TraceRecord rec = child.GetTraceByID(traceID);
                    if (rec != null) return rec;
                }
            }
            return null;
        }


        public ProtoGraph GetProtoGraphByID(ulong graphID)
        {
            lock (GraphListLock)
            {
                foreach (ProtoGraph graph in ProtoGraphs.Values)
                {
                    if (graph.ThreadID == graphID) return graph;
                }
                foreach (var child in children)
                {
                    ProtoGraph graph = child.GetProtoGraphByID(graphID);
                    if (graph != null) return graph;
                }
            }
            return null;
        }

        public ProtoGraph GetProtoGraphByTime(DateTime time)
        {
            lock (GraphListLock)
            {
                foreach (ProtoGraph graph in ProtoGraphs.Values)
                {
                    if (graph.ConstructedTime == time) return graph;
                }
                foreach (var child in children)
                {
                    ProtoGraph graph = child.GetProtoGraphByTime(time);
                    if (graph != null) return graph;
                }
            }
            return null;
        }



        public int CountDescendantGraphs()
        {
            int GraphCount = ProtoGraphs.Count;
            foreach (var child in this.children)
            {
                GraphCount += child.CountDescendantGraphs();
            }
            return GraphCount;
        }


        bool LoadProcessGraphs(JObject processJSON)
        {
            if (!processJSON.TryGetValue("Threads", out JToken jThreads) || jThreads.Type != JTokenType.Array)
            {
                Logging.RecordLogEvent("Failed to find valid Threads in trace", Logging.LogFilterType.TextError);
                return false;
            }

            JArray ThreadsArray = (JArray)jThreads;
            Logging.RecordLogEvent("Loading " + ThreadsArray.Count + " thread graphs", Logging.LogFilterType.TextDebug);
            //display_only_status_message(graphLoadMsg.str(), clientState);

            foreach (JObject threadObj in ThreadsArray)
            {
                if (!LoadGraph(threadObj))
                {
                    Logging.RecordLogEvent("Failed to load graph", Logging.LogFilterType.TextError);
                    return false;
                }
            }

            return true;

        }

        bool LoadGraph(JObject jThreadObj)
        {
            if (!jThreadObj.TryGetValue("ThreadID", out JToken tTID) || tTID.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid ThreadID in thread", Logging.LogFilterType.TextError);
                return false;
            }

            uint GraphThreadID = tTID.ToObject<uint>();
            Logging.RecordLogEvent("Loading thread ID " + GraphThreadID.ToString(), Logging.LogFilterType.TextDebug);
            //display_only_status_message("Loading graph for thread ID: " + tidstring, clientState);

            ProtoGraph protograph = new ProtoGraph(this, GraphThreadID, terminated: true);
            lock (GraphListLock)
            {
                ProtoGraphs.Add(GraphThreadID, protograph);
            }

            try
            {
                if (!protograph.Deserialise(jThreadObj, DisassemblyData.disassembly))
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent("Deserialising trace file failed: " + e.Message, Logging.LogFilterType.TextError);
                return false;
            }

            //CylinderGraph standardRenderedGraph = new CylinderGraph(protograph, GlobalConfig.defaultGraphColours);
            PlottedGraph standardRenderedGraph = new PlottedGraph(protograph, GlobalConfig.defaultGraphColours);
            standardRenderedGraph.SetAnimated(false);


            lock (GraphListLock)
            {
                PlottedGraphs.Add(GraphThreadID, new Dictionary<eRenderingMode, PlottedGraph>());
                PlottedGraphs[GraphThreadID].Add(eRenderingMode.eStandardControlFlow, standardRenderedGraph);
            }

            protograph.AssignModulePath();

            return true;
        }


        /// <summary>
        /// Save all the data needed to reconstruct a process run and all its thread graphs
        /// Recursively saves child processes
        /// </summary>
        /// <param name="traceStartedTime">The time the run was started</param>
        /// <returns>The path the trace was saved to</returns>
        public string Save(DateTime traceStartedTime)
        {
            Logging.RecordLogEvent($"Saving trace {binaryTarg.FilePath} -> PID {PID}");
            if (TraceType != eTracePurpose.eVisualiser)
            {
                Logging.RecordLogEvent("\tSkipping non visualiser trace");
                return "";
            }

            JsonTextWriter wr = CreateSaveFile(traceStartedTime, out string path);
            if (wr == null)
            {
                Logging.RecordLogEvent("\tSaving Failed: Unable to create filestream", Logging.LogFilterType.TextError);
                return "";
            }

            JObject traceSaveObject = new JObject();
            traceSaveObject.Add("PID", PID);
            traceSaveObject.Add("PID_ID", randID);
            traceSaveObject.Add("ProcessData", DisassemblyData.Serialise());
            traceSaveObject.Add("BinaryPath", binaryTarg.FilePath);
            traceSaveObject.Add("StartTime", traceStartedTime);
            traceSaveObject.Add("Threads", SerialiseGraphs());
            traceSaveObject.Add("Timeline", SerialiseTimeline());

            JArray childPathsArray = new JArray();
            foreach (TraceRecord trace in children)
            {
                string childpath = trace.Save(trace.launchedTime);
                if (childpath.Length > 0)
                    childPathsArray.Add(childpath);
            }
            traceSaveObject.Add("Children", childPathsArray);

            traceSaveObject.WriteTo(wr);
            wr.Close();

            Logging.RecordLogEvent("Trace Save Complete");
            if (GlobalConfig.StoreSavedTracesAsRecent)
            {
                GlobalConfig.RecordRecentPath(path, GlobalConfig.eRecentPathType.Trace);
            }
            return wr.Path;
        }

        JArray SerialiseGraphs()
        {
            JArray graphsList = new JArray();

            lock (GraphListLock)
            {
                foreach (var tid__mode_graph in PlottedGraphs)
                {
                    if (tid__mode_graph.Value.Count == 0) continue;
                    ProtoGraph protograph = tid__mode_graph.Value[0].InternalProtoGraph;
                    if (protograph.NodeList.Count == 0) continue;

                    graphsList.Add(protograph.Serialise());
                }
            }

            return graphsList;
        }


        JArray SerialiseTimeline()
        {

            JArray timeline = new JArray();

            for (var i = 0; i < _timeline.Count; i++)
            {
                TIMELINE_EVENT evt = _timeline[i];
                timeline.Add(evt.Serialise());
            }

            return timeline;
        }


        JsonTextWriter CreateSaveFile(DateTime startedTime, out string path)
        {
            string saveFilename = $"{binaryTarg.FileName}-{PID}-{startedTime.ToString("MMM-dd__HH-mm-ss")}.rgat";
            if (!Directory.Exists(GlobalConfig.TraceSaveDirectory))
            {
                Logging.RecordLogEvent("\tWarning: Failed to save - directory " + GlobalConfig.TraceSaveDirectory + " does not exist", Logging.LogFilterType.TextInfo);
                path = null;
                return null;
            }

            path = Path.Join(GlobalConfig.TraceSaveDirectory, saveFilename);
            try
            {
                StreamWriter sw = File.CreateText(path);

                return (new JsonTextWriter(sw));
            }
            catch (UnauthorizedAccessException e)
            {
                Logging.RecordLogEvent($"\tWarning: Unauthorized to open {path} for writing", Logging.LogFilterType.TextInfo);
            }
            catch
            {
                Logging.RecordLogEvent($"\tWarning: Failed to open {path} for writing", Logging.LogFilterType.TextInfo);
            }
            return null;
        }

        private bool LoadTimeline(JObject saveJSON)
        {
            if (!saveJSON.TryGetValue("Timeline", out JToken arrTok) || arrTok.Type != JTokenType.Array)
            {
                Logging.RecordLogEvent($"\tWarning: Missing or bad timeline in trace save", Logging.LogFilterType.TextInfo);
                return false;
            }
            _timeline = new List<TIMELINE_EVENT>();
            JArray arr = arrTok.ToObject<JArray>();
            foreach (JToken tlTok in arr)
            {
                if (tlTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent($"\tWarning: Bad timeline item in trace save", LogFilterType.TextInfo);
                    return false;
                }
                Logging.TIMELINE_EVENT evt = new Logging.TIMELINE_EVENT(tlTok.ToObject<JObject>(), this);
                if (!evt.Inited)
                {
                    Logging.RecordLogEvent($"\tWarning: Invalid timeline item in trace save", Logging.LogFilterType.TextInfo);
                    return false;
                }

                if (evt.LogType == Logging.eLogType.TimeLine)
                {
                    switch (evt.TimelineEventType)
                    {
                        case Logging.eTimelineEvent.ProcessStart:
                        case Logging.eTimelineEvent.ProcessEnd:
                            {
                                _tlFilterCounts.TryGetValue(LogFilterType.TimelineProcess, out int currentCountp);
                                _tlFilterCounts[LogFilterType.TimelineProcess] = currentCountp + 1;
                                _timeline.Add(evt);
                            }
                            break;
                        case Logging.eTimelineEvent.ThreadStart:
                        case Logging.eTimelineEvent.ThreadEnd:
                            {
                                _tlFilterCounts.TryGetValue(LogFilterType.TimelineThread, out int currentCountt);
                                _tlFilterCounts[LogFilterType.TimelineThread] = currentCountt + 1;
                                _timeline.Add(evt);
                            }
                            break;
                        case eTimelineEvent.APICall:
                            APICALL apic = (APICALL)(evt.Item);
                            if (apic.graph.ProcessData.GetSymbol(apic.node.GlobalModuleID, apic.node.address, out string sym))
                            {
                                try
                                {
                                    //resolve the api type again in case the api type list has been updated
                                    string modulePath = apic.graph.ProcessData.GetModulePath(apic.node.GlobalModuleID);
                                    var moduleEnum = WinAPIDetails.ResolveModuleEnum(modulePath);
                                    Logging.LogFilterType ftype = WinAPIDetails.ResolveAPI(moduleEnum, sym);

                                    _tlFilterCounts[ftype] = _tlFilterCounts.GetValueOrDefault(ftype, 0) + 1;
                                    apic.ApiType = ftype;
                                    evt.ReplaceItem(apic);
                                    evt.Filter = ftype;
                                    _timeline.Add(evt);
                                    continue;
                                }
                                catch { }

                            }
                            _tlFilterCounts[apic.ApiType] = _tlFilterCounts.GetValueOrDefault(apic.ApiType, 0) + 1;
                            _timeline.Add(evt);
                            break;
                        default:
                            Debug.Assert(false, "Timeline event has no assigned filter");
                            break;
                    }
                }
                else if (evt.LogType == Logging.eLogType.API)
                {

                    Debug.Assert(false, "Should not have this event type here");
                }
                else
                {
                    Debug.Assert(false, "Should not have this event type here");
                }

            }
            return true;
        }


        public void ExportPajek(uint TID)
        {
            ProtoGraph pgraph = this.ProtoGraphs[TID];
            if (!Directory.Exists(GlobalConfig.TraceSaveDirectory)) return;
            FileStream outfile = File.OpenWrite(Path.Combine(GlobalConfig.TraceSaveDirectory, "pajeksave" + TID.ToString() + ".net"));
            outfile.Write(Encoding.ASCII.GetBytes("%*Colnames \"Disassembly\"\n"));
            outfile.Write(Encoding.ASCII.GetBytes("*Vertices " + pgraph.NodeList.Count + "\n"));

            foreach (NodeData n in pgraph.NodeList)
            {
                outfile.Write(Encoding.ASCII.GetBytes(n.index + " \"" + n.ins.ins_text + "\"\n"));
            }

            outfile.Write(Encoding.ASCII.GetBytes("*edgeslist " + pgraph.NodeList.Count + "\n"));
            foreach (NodeData n in pgraph.NodeList)
            {
                outfile.Write(Encoding.ASCII.GetBytes(n.index + " "));
                foreach (int nodeidx in n.OutgoingNeighboursSet)
                {
                    outfile.Write(Encoding.ASCII.GetBytes(nodeidx.ToString() + " "));
                }
                outfile.Write(Encoding.ASCII.GetBytes("\n"));
            }
            outfile.Close();
        }


        public void SendDebugStepOver(ProtoGraph graph)
        {
            if (!graph.HasRecentStep) return;

            ulong stepAddr = graph.RecentStepAddr;
            List<uint> nodes = DisassemblyData.GetNodesAtAddress(stepAddr, graph.ThreadID);
            if (nodes.Count == 0) return;

            NodeData n = graph.safe_get_node(nodes[^1]);
            if (n.ins.itype != eNodeType.eInsCall)
            {
                SendDebugStep(graph.ThreadID);
                return;
            }
            ulong nextInsAddress = n.ins.address + (ulong)n.ins.numbytes;

            string cmd = $"SOV,{nextInsAddress:X}";
            SendDebugCommand(graph.ThreadID, cmd);
        }

        public void SendDebugStep(uint threadID)
        {
            SendDebugCommand(threadID, "SIN");
        }

        public void SendDebugCommand(uint threadID, string command)
        {
            if (ProcessThreads.modThread == null)
            {
                Logging.RecordLogEvent("Error: DBG command send to trace with no active module thread", Logging.LogFilterType.TextError);
                return;
            }


            byte[] buf = System.Text.Encoding.ASCII.GetBytes(command + '@' + threadID.ToString() + "\n\x00");
            if (ProcessThreads.modThread.SendCommand(buf) == -1)
            {
                Logging.RecordLogEvent("Error sending command to control pipe", Logging.LogFilterType.TextError);
            }
        }


        public ProcessRecord DisassemblyData { private set; get; } = null; //the first disassembly of each address

        //private timeline runtimeline;
        public DateTime launchedTime { private set; get; } //the time the user pressed start, not when the first process was seen

        public BinaryTarget binaryTarg { private set; get; } = null;
        public bool IsRunning => TraceState != eTraceState.eTerminated;
        private bool killed = false;

        public eTraceState TraceState { private set; get; } = eTraceState.eTerminated;

        public bool ProcessingRemaining => ProcessThreads.modThread.Running;


        public TRACE_TEST_RESULTS EvaluateProcessTestRequirement(TraceRequirements ptreq, ref TraceTestResultCommentary resultsobj)
        {
            TRACE_TEST_RESULTS results = new TRACE_TEST_RESULTS();

            resultsobj.traceResultsB = results;
            foreach (TestRequirement req in ptreq.ProcessRequirements)
            {
                Console.WriteLine($"Evaluating process requirement {req.Name} {req.Condition} [val] ");
                bool passed = false;
                string error = "";
                string compareValueString = "";
                switch (req.Name)
                {
                    case "GraphCount":
                        passed = req.Compare(ProtoGraphs.Count, out error);
                        compareValueString = $"{ProtoGraphs.Count}";
                        break;
                    default:
                        Logging.RecordLogEvent("Invalid process test requirement: " + req.Name, Logging.LogFilterType.TextError);
                        break;
                }
                TestResultCommentary comment = new TestResultCommentary()
                {
                    comparedValueString = compareValueString,
                    result = passed ? eTestState.Passed : eTestState.Failed,
                    requirement = req
                };
                if (passed)
                {
                    results.ProcessResults.Passed.Add(comment);
                }
                else
                {
                    if (error != null)
                    {
                        string errmsg = $"Testing Error evaluating Process requirement {req.Name}: {error}";
                        results.ProcessResults.Errors.Add(new Tuple<TestRequirement, string>(req, errmsg));
                        Logging.RecordLogEvent(errmsg, Logging.LogFilterType.TextError);
                    }
                    results.ProcessResults.Failed.Add(comment);
                }
            }


            foreach (REQUIREMENTS_LIST requirementList in ptreq.ThreadRequirements)
            {
                Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS> graphResultsDict = EvaluateThreadTestRequirements(requirementList);
                results.ThreadResults.Add(requirementList, graphResultsDict);
                resultsobj.threadTests.Add(requirementList, graphResultsDict);
            }





            if (ptreq.ChildProcessRequirements.Any())
            {
                foreach (TraceRequirements childRequirements in ptreq.ChildProcessRequirements)
                {
                    Dictionary<TraceRecord, TRACE_TEST_RESULTS> childRequirementResults = new Dictionary<TraceRecord, TRACE_TEST_RESULTS>();
                    foreach (TraceRecord record in children)
                    {
                        //TraceTestResultCommentary childComm = resultsobj.ChildProcessRequirements[0];
                        TraceTestResultCommentary dummy = new TraceTestResultCommentary();
                        childRequirementResults[record] = record.EvaluateProcessTestRequirement(childRequirements, ref dummy);
                    }
                    results.ChildResults[childRequirements] = childRequirementResults;
                }
            }
            return results;
        }



        public Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS> EvaluateThreadTestRequirements(REQUIREMENTS_LIST threadTestReqs)
        {
            Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS> results = new Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS>();
            foreach (ProtoGraph graph in ProtoGraphs.Values)
            {
                results[graph] = graph.MeetsTestRequirements(threadTestReqs);
            }
            return results;
        }


    }
}
