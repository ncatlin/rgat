﻿using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using rgat.Testing;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using static rgat.Logging;

namespace rgat
{
    /// <summary>
    /// An object to describe a disasembled instruction
    /// </summary>
    public class InstructionData
    {
        /// <summary>
        /// Text of the instruction mnemonic
        /// </summary>
        public string Mnemonic = "";
        /// <summary>
        /// Texe of the instruction operands
        /// </summary>
        public string OpStr = "";



        /* 
         * memory/speed tradeoff 
		1.construct every frame and save memory 
		2.construct at disassemble time and improve render speed
		*/
        /// <summary>
        /// All the basic blocks this instruction is a member of
        /// </summary>
        public List<uint>? ContainingBlockIDs;

        /// <summary>
        /// Full text of the disassembled instruction
        /// </summary>
        public string InsText = "";

        /// <summary>
        /// Flow control type of the instruction
        /// </summary>
        public CONSTANTS.eNodeType itype;
        /// <summary>
        /// Is the instruction a conditional jump
        /// </summary>
        public bool conditional;
        /// <summary>
        /// Is the instruction in a non-text area
        /// </summary>
        public bool dataEx;
        /// <summary>
        /// Does the address have a symbol associated with it
        /// </summary>
        public bool hasSymbol;
        /// <summary>
        /// Could the instruction be an APi thunk
        /// </summary>
        public bool PossibleidataThunk;
        /// <summary>
        /// Is the instruction an MPX instruction
        /// </summary>
        public bool IsMPX = false; //https://en.wikipedia.org/wiki/Intel_MPX

        /// <summary>
        /// Memory address of this instruction
        /// </summary>
        public ulong Address;
        /// <summary>
        /// If this instruction is a branch, this is the address the taken branch leads to
        /// </summary>
        public ulong branchAddress;
        /// <summary>
        /// Address of the instruction after this if there is no flow control
        /// </summary>
        public ulong condDropAddress;
        private readonly List<Tuple<uint, uint>> _threadVertIndexes = new List<Tuple<uint, uint>>(); //was an unordered dictionary in the C++ version
        /// <summary>
        /// The module this instruction is located in
        /// </summary>
        public int GlobalModNum;

        /// <summary>
        /// Which version of the instruction at this address is this disassembly for
        /// </summary>
        public int MutationIndex;

        /// <summary>
        /// Is this instruction at the start or end of a basic block
        /// </summary>
        public bool BlockBoundary;

        //this was added later, might be worth ditching other stuff in exchange
        /// <summary>
        /// The raw bytes of the instruction
        /// </summary>
        public byte[]? Opcodes;

        /// <summary>
        /// How many bytes of opcodes the instruction has
        /// </summary>
        public int NumBytes => Opcodes!.Length;

        /// <summary>
        /// The index of the node containing this instruction in each thread [Thread ID/instruction index]
        /// </summary>
        public List<Tuple<uint, uint>> ThreadVerts => _threadVertIndexes.ToList();

        /// <summary>
        /// Get the node index of this instruction in the specified thread
        /// </summary>
        /// <param name="TID">Thread ID</param>
        /// <param name="vert">Ndoe index of the instruction</param>
        /// <returns>If found</returns>
        public bool GetThreadVert(uint TID, out uint vert)
        {
            for (var i = 0; i < _threadVertIndexes.Count; i++)
            {
                if (_threadVertIndexes[i].Item1 == TID) { vert = _threadVertIndexes[i].Item2; return true; }
            }
            vert = uint.MaxValue;
            return false;
        }


        /// <summary>
        /// Test if the instruction was executed by a specific thread
        /// </summary>
        /// <param name="TID">Thread ID</param>
        /// <returns>If executed</returns>
        public bool InThread(uint TID)
        {
            for (var i = 0; i < _threadVertIndexes.Count; i++)
            {
                if (_threadVertIndexes[i].Item1 == TID) { return true; }
            }
            return false;
        }

        /// <summary>
        /// Note that this instruction was executed by a thread
        /// </summary>
        /// <param name="TID">The thread ID</param>
        /// <param name="vert">The node index</param>
        public void AddThreadVert(uint TID, uint vert)
        {
            _threadVertIndexes.Add(new Tuple<uint, uint>(TID, vert));
        }
    }

    /// <summary>
    /// A record of a traced process
    /// </summary>
    public class TraceRecord
    {
        /// <summary>
        /// The type of tracing done
        /// </summary>
        public enum eTracePurpose
        {
            /// <summary>
            /// Gather trace data of the process executing normally to visualise it
            /// </summary>
            eVisualiser,
            /// <summary>
            /// Not implemented
            /// </summary>
            eFuzzer
        };

        /// <summary>
        /// The state of the process being traced
        /// </summary>
        public enum eTraceState
        {
            /// <summary>
            /// The process is running
            /// </summary>
            eRunning,
            /// <summary>
            /// The process is suspended by rgat
            /// </summary>
            eSuspended,
            /// <summary>
            /// The process is terminated
            /// </summary>
            eTerminated
        };


        /// <summary>
        /// Create a trace record
        /// </summary>
        /// <param name="newPID">The OS process ID of the process</param>
        /// <param name="randomNo">A random ID generated by the instrumentation to identify the process</param>
        /// <param name="binary">The associated BinaryTarget of the process</param>
        /// <param name="timeStarted">When the process was recorded starting</param>
        /// <param name="purpose">A purpose value for the trace [only visualiser is supported]</param>
        /// <param name="arch">32 or 64 bits, or 0 if unknown (remote)</param>
        public TraceRecord(uint newPID, long randomNo, BinaryTarget binary, DateTime timeStarted, eTracePurpose purpose = eTracePurpose.eVisualiser, int arch = 0)
        {
            PID = newPID;
            randID = randomNo;
            LaunchedTime = timeStarted;
            TraceType = purpose;

            Target = binary;
            if (arch != 0 && binary.BitWidth != arch)
            {
                binary.BitWidth = arch;
            }

            DisassemblyData = new ProcessRecord(binary.BitWidth);
            TraceState = eTraceState.eRunning;

            //_tlFilterCounts[Logging.LogFilterType.TimelineProcess] = 0;
            //_tlFilterCounts[Logging.LogFilterType.TimelineThread] = 0;
        }

        /// <summary>
        /// The ID of the test for this trace run
        /// </summary>
        public long TestRunID { get; private set; }

        /// <summary>
        /// Set a test run ID
        /// </summary>
        /// <param name="val">The ID</param>
        public void SetTestRunID(long val) => TestRunID = val;

        private bool _loadedFromSave = false;
        /// <summary>
        /// Was this recorded in this session or loaded from a save
        /// </summary>
        public bool WasLoadedFromSave => _loadedFromSave;

        private string getModpathID() { return PID.ToString() + randID.ToString(); }

        /// <summary>
        /// Set the trace state
        /// </summary>
        /// <param name="newState">The new state</param>
        public void SetTraceState(eTraceState newState)
        {
            Logging.RecordLogEvent($"Set trace state {newState}", Logging.LogFilterType.TextDebug);
            if (TraceState == newState)
            {
                return;
            }

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

        /// <summary>
        /// Insert a new thread
        /// </summary>
        /// <param name="graph">The ProtoGraph of the thread</param>
        /// <param name="mainplot">Optional PlottedGraph of the thread</param>
        /// <returns></returns>
        public bool InsertNewThread(ProtoGraph graph, PlottedGraph? mainplot)
        {
            lock (GraphListLock)
            {

                if (mainplot is not null)
                {
                    if (ProtoGraphs.ContainsKey(mainplot.TID))
                    {
                        Console.WriteLine("Warning - thread with duplicate ID detected. This should never happen. Undefined behaviour ahoy.");
                        return false;
                    }

                    PlottedGraphs[graph.ThreadID] = mainplot;
                }

                ProtoGraphs.Add(graph.ThreadID, graph);

                //runtimeline.notify_new_thread(getPID(), randID, TID);
            }
            Console.WriteLine("Todo implement runtimeline");
            return true;
        }


        //bool is_process(uint testpid, int testID);


        /// <summary>
        /// Get any plotted graph with instrumented instructions
        /// </summary>
        /// <returns>A PlottedGraph with nodes or null if none</returns>
        public PlottedGraph? GetFirstGraph()
        {
            if (PlottedGraphs.Count == 0)
            {
                return null;
            }

            //if (graphListLock.trylock())
            var MainPlottedGraphs = GetPlottedGraphs();
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

            var graphsWithData = MainPlottedGraphs.Where(g => g.InternalProtoGraph.TraceReader is not null && g.InternalProtoGraph.TraceReader.HasPendingData);
            if (graphsWithData.Any())
            {
                return graphsWithData.First();
            }

            return MainPlottedGraphs.First();
        }

        /// <summary>
        /// Get the most recently recorded graph with instrumented instructions
        /// </summary>
        /// <returns>The latest PlottedGraph with nodes</returns>
        public PlottedGraph? GetLatestGraph()
        {
            if (PlottedGraphs.Count == 0)
            {
                return null;
            }

            //if (graphListLock.trylock())
            var MainPlottedGraphs = GetPlottedGraphs();
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

            var graphsWithData = MainPlottedGraphs.Where(g => g.InternalProtoGraph.TraceReader is not null && g.InternalProtoGraph.TraceReader.HasPendingData);
            if (graphsWithData.Any())
            {
                return graphsWithData.Last();
            }

            return MainPlottedGraphs.Last();
        }


        /// <summary>
        /// Deserialise a TraceRecord from JSON
        /// </summary>
        /// <param name="saveJSON">The JObject of the trace</param>
        /// <param name="device">A GraphicsDevice to start rendering the graphs with</param>
        /// <returns></returns>
        public bool Load(Newtonsoft.Json.Linq.JObject saveJSON, Veldrid.GraphicsDevice device)
        {
            try
            {
                if (!DisassemblyData.Load(saveJSON)) //todo - get the relevant dynamic bit for this trace
                {
                    Logging.RecordLogEvent("ERROR: Process data load failed", Logging.LogFilterType.TextError);
                    return false;
                }

                Logging.RecordLogEvent("Loaded process data. Loading graphs...", Logging.LogFilterType.TextDebug);


                if (!LoadProcessGraphs(saveJSON, device))//, colours))//.. &config.graphColours))
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
            catch (Exception e)
            {
                Logging.RecordError($"Error loading trace: {e.Message} - {e.StackTrace}");
                return false;
            }
        }

        private void killTraceProcess() { if (IsRunning) { killed = true; } }

        private bool should_die() { return killed; }

        //void killTree();

        // Process start, process end, thread start, thread end
        private readonly object _logLock = new object();
        private List<Logging.TIMELINE_EVENT> _timeline = new List<Logging.TIMELINE_EVENT>();

        //Dictionary<Logging.LogFilterType, int> _tlFilterCounts = new Dictionary<Logging.LogFilterType, int>();

        private int runningProcesses = 0;
        private int runningThreads = 0;

        /// <summary>
        /// Record a process/thread stop/start
        /// </summary>
        /// <param name="type">Event type</param>
        /// <param name="trace">Optional process trace object</param>
        /// <param name="graph">Optional thread graph</param>
        public void RecordTimelineEvent(Logging.eTimelineEvent type, TraceRecord? trace = null, ProtoGraph? graph = null)
        {
            switch (type)
            {
                case Logging.eTimelineEvent.ProcessStart:
                    {
                        Debug.Assert(trace != null);

                        lock (_logLock)
                        {
                            _timeline.Add(new Logging.TIMELINE_EVENT(type, trace));
                            runningProcesses += 1;
                            //  _tlFilterCounts.TryGetValue(Logging.LogFilterType.TimelineProcess, out currentCount);
                            //   _tlFilterCounts[Logging.LogFilterType.TimelineProcess] = currentCount + 1;
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
                                //_tlFilterCounts.TryGetValue(Logging.LogFilterType.TimelineProcess, out currentCount);
                                // _tlFilterCounts[Logging.LogFilterType.TimelineProcess] = currentCount + 1;
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
                            // _tlFilterCounts.TryGetValue(Logging.LogFilterType.TimelineThread, out currentCount);
                            // _tlFilterCounts[Logging.LogFilterType.TimelineThread] = currentCount + 1;
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
                            if (runningProcesses == 0 && runningThreads == 0)
                            {
                                SetTraceState(eTraceState.eTerminated);
                            }
                            //  _tlFilterCounts.TryGetValue(Logging.LogFilterType.TimelineThread, out currentCount);
                            //_tlFilterCounts[Logging.LogFilterType.TimelineThread] = currentCount + 1;
                        }
                    }
                    break;
                default:
                    Debug.Assert(false, "Timeline event has no assigned filter");
                    break;
            }

        }

        private ulong uniqAPICallIdx = 0;

        /// <summary>
        /// Record an APi call
        /// </summary>
        /// <param name="node">The node of the call</param>
        /// <param name="graph">The graph of the node</param>
        /// <param name="callIndex">The index of the call</param>
        /// <param name="repeats">How many repeats were recorded</param>
        public void RecordAPICall(NodeData node, ProtoGraph graph, int callIndex, ulong repeats)
        {
            int ModuleReference = DisassemblyData.GetModuleReference(node.GlobalModuleID);

            APIDetailsWin.API_ENTRY? APIDetails = DisassemblyData.GetAPIEntry(node.GlobalModuleID, ModuleReference, node.address);

            if (APIDetails is null)
            {
                return;
            }

            Logging.APICALL call = new Logging.APICALL(graph)
            {
                Index = callIndex,
                Node = node,
                Repeats = repeats,
                UniqID = uniqAPICallIdx++,
                APIDetails = APIDetails
            };
            lock (_logLock)
            {
                _timeline.Add(new Logging.TIMELINE_EVENT(Logging.eTimelineEvent.APICall, call));

            }
            //Logging.RecordLogEvent("Api call: "+node.Label, trace:this, graph: graph, apicall: call, filter: call.ApiType);

        }

        /// <summary>
        /// How many timeline items are recorded
        /// </summary>
        public int TimelineItemsCount => _timeline.Count;

        /// <summary>
        /// Fetches an array of the newest timeline events for the trace
        /// </summary>
        /// <param name="oldest">The oldest event to return</param>
        /// <param name="max">The most events to return. Default 5.</param>
        /// <returns>And array of TIMELINE_EVENT objects</returns>
        public Logging.TIMELINE_EVENT[] GetTimeLineEntries(long oldest = 0, int max = -1)
        {
            if (max == -1)
            {
                max = _timeline.Count;
            }

            List<Logging.TIMELINE_EVENT> results = new List<Logging.TIMELINE_EVENT>();
            lock (_logLock)
            {
                var last = _timeline.Count - 1;
                for (; last >= 0 && last >= _timeline.Count - max; last--)
                {
                    if (_timeline[last].EventTimeMS < oldest)
                    {
                        break;
                    }
                }
                for (var i = last + 1; i < _timeline.Count; i++)
                {
                    results.Add(_timeline[i]);
                }
            }
            return results.ToArray();
        }

        /*
        public Dictionary<LogFilterType, int> GetTimeLineFilterCounts()
        {
            Dictionary<LogFilterType, int> result = null;
            lock (_logLock)
            {
                result = new Dictionary<LogFilterType, int>(_tlFilterCounts);
            }
            for (var i = 0; i < (int)Logging.LogFilterType.COUNT; i++)
            {
                LogFilterType key = ((LogFilterType)i);
                if (!result.ContainsKey(key))
                {
                    result.Add(key, 0);
                }
            }
            return result;
        }
        */


        /// <summary>
        /// Find the module containing the address
        /// </summary>
        /// <param name="address">The address to find</param>
        /// <param name="localmodID">The module the address was in</param>
        /// <returns>If the address was found in a module</returns>
        public eCodeInstrumentation FindContainingModule(ulong address, out int localmodID)
        {
            bool found = DisassemblyData.FindContainingModule(address, out int? outID);
            if (found)
            {
                localmodID = outID!.Value;
                return DisassemblyData.ModuleTraceStates[localmodID];
            }

            // Todo: the issue here is either code that hasn't been disasembled (full trace buffers?) or code executing in a buffer 

            localmodID = -1;
            Console.WriteLine($"Warning: Unknown module in traceRecord::FindContainingModule for address 0x{address:X}");
            int attempts = 1;
            while (attempts-- != 0)
            {
                Thread.Sleep(30);
                found = DisassemblyData.FindContainingModule(address, out outID);
                if (found)
                {
                    localmodID = outID!.Value;
                    Console.WriteLine("FindContainingModule found!");
                    break;
                }
            }

            Debug.Assert(found);
            return DisassemblyData.ModuleTraceStates[localmodID!];
        }

        private readonly object GraphListLock = new object();
        private readonly Dictionary<uint, ProtoGraph> ProtoGraphs = new Dictionary<uint, ProtoGraph>();

        /// <summary>
        /// get a copy of the protographs list
        /// </summary>
        /// <returns></returns>
        public List<ProtoGraph> GetProtoGraphs()
        {
            lock (GraphListLock)
            {
                return ProtoGraphs.Values.ToList();
            }
        }

        /// <summary>
        /// The number of graphs in the trace
        /// </summary>
        public int GraphCount => ProtoGraphs.Count;


        //todo: thread IDs are not unique!
        /// <summary>
        /// Dictionary of plotted graphs by thread ID
        /// </summary>
        public Dictionary<uint, PlottedGraph> PlottedGraphs = new Dictionary<uint, PlottedGraph>();


        /// <summary>
        /// Get a thread safe copy of the list of plotted graphs
        /// </summary>
        /// <returns>List of plotted graphs</returns>
        public List<PlottedGraph> GetPlottedGraphs()
        {
            lock (GraphListLock)
            {
                return PlottedGraphs.Values.ToList();
            }
        }

        /// <summary>
        /// The type of trace. Currently visualiser is the only supported type
        /// </summary>
        public eTracePurpose TraceType { get; private set; } = eTracePurpose.eVisualiser;

        /// <summary>
        /// The trace of the process which spawn this process, if this process is a child
        /// </summary>
        public TraceRecord? ParentTrace = null;

        /// <summary>
        /// Child processes spawned by this process
        /// </summary>
        public List<TraceRecord> children = new List<TraceRecord>();


        /// <summary>
        /// returns a copy of the child trace list
        /// </summary>
        /// <returns>Child tracerecords</returns>
        public List<TraceRecord> GetChildren()
        {
            lock (GraphListLock)
            {
                return children.ToList();
            }
        }

        /// <summary>
        /// Trace data handling workers
        /// </summary>
        public TraceProcessorWorkers ProcessThreads = new TraceProcessorWorkers();
        //void* fuzzRunPtr = null;

        /// <summary>
        /// Process ID of the process being traced
        /// </summary>
        public uint PID { get; private set; }

        /// <summary>
        /// Unique ID to distinguish between processes with identical PIDs
        /// </summary>
        public long randID { get; private set; }

        /// <summary>
        /// Count how many processes are desecended from this process. Count includes this one.
        /// </summary>
        /// <returns>1 + number of child processes</returns>
        public int CountDescendantTraces()
        {
            int TraceCount = 1;
            foreach (var child in this.children)
            {
                TraceCount += child.CountDescendantTraces();
            }
            return TraceCount;
        }


        /// <summary>
        /// Get a trace by unique ID
        /// </summary>
        /// <param name="traceID">ID of the trace</param>
        /// <returns>TraceRecord or null if not found</returns>
        public TraceRecord? GetTraceByID(ulong traceID)
        {
            if (PID == traceID)
            {
                return this;
            }

            lock (GraphListLock)
            {
                foreach (var child in children)
                {
                    TraceRecord? rec = child.GetTraceByID(traceID);
                    if (rec != null)
                    {
                        return rec;
                    }
                }
            }
            return null;
        }


        /// <summary>
        /// Get a thread associated with a thread ID. todo this is bad due to non uniqueness
        /// </summary>
        /// <param name="graphID">Thread ID of the graph</param>
        /// <returns>ProtoGraph if found, or null</returns>
        public ProtoGraph? GetProtoGraphByTID(ulong graphID)
        {
            lock (GraphListLock)
            {
                foreach (ProtoGraph graph in ProtoGraphs.Values)
                {
                    if (graph.ThreadID == graphID)
                    {
                        return graph;
                    }
                }
                foreach (var child in children)
                {
                    ProtoGraph? graph = child.GetProtoGraphByTID(graphID);
                    if (graph != null)
                    {
                        return graph;
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Get a thread graph by time of creation
        /// </summary>
        /// <param name="time">Time the graph was created</param>
        /// <returns>Graph or null if not found</returns>
        public ProtoGraph? GetProtoGraphByTime(DateTime time)
        {
            lock (GraphListLock)
            {
                foreach (ProtoGraph graph in ProtoGraphs.Values)
                {
                    if (graph.ConstructedTime == time)
                    {
                        return graph;
                    }
                }
                foreach (var child in children)
                {
                    ProtoGraph? graph = child.GetProtoGraphByTime(time);
                    if (graph != null)
                    {
                        return graph;
                    }
                }
            }
            return null;
        }


        /// <summary>
        /// How many thread graphs this trace has spawned, including those of any child processes
        /// </summary>
        /// <returns>Threads in this and child processes</returns>
        public int CountDescendantGraphs()
        {
            int GraphCount = ProtoGraphs.Count;
            foreach (var child in this.children)
            {
                GraphCount += child.CountDescendantGraphs();
            }
            return GraphCount;
        }

        private bool LoadProcessGraphs(JObject processJSON, Veldrid.GraphicsDevice device)
        {
            if (!processJSON.TryGetValue("Threads", out JToken? jThreads) || jThreads.Type != JTokenType.Array)
            {
                Logging.RecordLogEvent("Failed to find valid Threads in trace", Logging.LogFilterType.TextError);
                return false;
            }

            JArray ThreadsArray = (JArray)jThreads;
            Logging.RecordLogEvent("Loading " + ThreadsArray.Count + " thread graphs", Logging.LogFilterType.TextDebug);
            //display_only_status_message(graphLoadMsg.str(), clientState);

            foreach (JObject threadObj in ThreadsArray)
            {
                if (!LoadGraph(threadObj, device))
                {
                    Logging.RecordLogEvent("Failed to load graph", Logging.LogFilterType.TextError);
                    return false;
                }
            }

            return true;

        }

        private bool LoadGraph(JObject jThreadObj, Veldrid.GraphicsDevice device)
        {
            if (!jThreadObj.TryGetValue("ThreadID", out JToken? tTID) || tTID.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid ThreadID in thread", Logging.LogFilterType.TextError);
                return false;
            }
            uint GraphThreadID = tTID.ToObject<uint>();

            if (!jThreadObj.TryGetValue("StartAddress", out JToken? tAddr) || tAddr.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid StartAddress in thread", Logging.LogFilterType.TextError);
                return false;
            }
            ulong startAddr = tAddr.ToObject<ulong>();

            Logging.RecordLogEvent("Loading thread ID " + GraphThreadID.ToString(), Logging.LogFilterType.TextDebug);
            //display_only_status_message("Loading graph for thread ID: " + tidstring, clientState);

            ProtoGraph protograph = new ProtoGraph(this, GraphThreadID, startAddr, terminated: true);

            try
            {
                if (!protograph.Deserialise(jThreadObj, DisassemblyData))
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Deserialising trace file failed: {e.Message} - {e.StackTrace}");
                return false;
            }

            lock (GraphListLock)
            {
                ProtoGraphs.Add(GraphThreadID, protograph);
            }

            //CylinderGraph standardRenderedGraph = new CylinderGraph(protograph, GlobalConfig.defaultGraphColours);
            PlottedGraph standardRenderedGraph = new PlottedGraph(protograph, device);
            standardRenderedGraph.SetAnimated(false);


            lock (GraphListLock)
            {
                PlottedGraphs.Add(GraphThreadID, standardRenderedGraph);
            }

            return true;
        }


        /// <summary>
        /// Save all the data needed to reconstruct a process run and all its thread graphs
        /// Recursively saves child processes
        /// </summary>
        /// <param name="traceStartedTime">The time the run was started</param>
        /// <param name="savePath">The filesystem path the trace was saved to</param>
        /// <returns>The path the trace was saved to</returns>
        public bool Save(DateTime traceStartedTime, out string? savePath)
        {
            savePath = null;
            Logging.RecordLogEvent($"Saving trace {Target.FilePath} -> PID {PID}");
            if (TraceType != eTracePurpose.eVisualiser)
            {
                Logging.RecordLogEvent("\tSkipping non visualiser trace");
                return false;
            }

            JsonTextWriter? wr = CreateSaveFile(traceStartedTime, out savePath);
            if (wr == null || savePath is null)
            {
                Logging.RecordLogEvent("\tSaving Failed: Unable to create filestream", Logging.LogFilterType.TextError);
                return false;
            }

            JObject traceSaveObject = new JObject();
            traceSaveObject.Add("PID", PID);
            traceSaveObject.Add("PID_ID", randID);
            traceSaveObject.Add("IsLibrary", Target.IsLibrary);
            traceSaveObject.Add("ProcessData", DisassemblyData.Serialise());
            traceSaveObject.Add("BinaryPath", Target.FilePath);
            traceSaveObject.Add("StartTime", traceStartedTime);
            traceSaveObject.Add("Threads", SerialiseGraphs());
            traceSaveObject.Add("Timeline", SerialiseTimeline());

            JArray childPathsArray = new JArray();
            int saveCount = 0;
            foreach (TraceRecord trace in children)
            {
                if (trace.Save(trace.LaunchedTime, out string? childpath) && childpath is not null)
                {
                    if (childpath.Length > 0)
                    {
                        childPathsArray.Add(childpath);
                    }

                    saveCount += 1;
                }
            }
            traceSaveObject.Add("Children", childPathsArray);

            traceSaveObject.WriteTo(wr);
            wr.Close();

            if (GlobalConfig.Settings.Logs.StoreSavedTracesAsRecent)
            {
                GlobalConfig.Settings.RecentPaths.RecordRecentPath(Config.rgatSettings.PathType.Trace, savePath);
            }
            return true;
        }

        private JArray SerialiseGraphs()
        {
            JArray graphsList = new JArray();

            lock (GraphListLock)
            {
                foreach (var tid_graph in PlottedGraphs)
                {
                    ProtoGraph protograph = tid_graph.Value.InternalProtoGraph;
                    graphsList.Add(protograph.Serialise());
                }
            }

            return graphsList;
        }

        private JArray SerialiseTimeline()
        {

            JArray timeline = new JArray();

            for (var i = 0; i < _timeline.Count; i++)
            {
                TIMELINE_EVENT evt = _timeline[i];
                timeline.Add(evt.Serialise());
            }

            return timeline;
        }

        private JsonTextWriter? CreateSaveFile(DateTime startedTime, out string? path)
        {
            string saveFilename = $"{Target.FileName}-{PID}-{startedTime.ToString("MMM-dd__HH-mm-ss")}.rgat";
            string saveDir = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.TraceSaveDirectory);
            if (!Directory.Exists(saveDir))
            {
                Logging.RecordLogEvent($"\tWarning: Failed to save - directory {saveDir} does not exist", Logging.LogFilterType.TextInfo);
                path = null;
                return null;
            }

            path = Path.Join(saveDir, saveFilename);
            try
            {
                StreamWriter sw = File.CreateText(path);

                return (new JsonTextWriter(sw));
            }
            catch (UnauthorizedAccessException)
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
            if (!saveJSON.TryGetValue("Timeline", out JToken? arrTok) || arrTok.Type != JTokenType.Array)
            {
                Logging.RecordLogEvent($"\tWarning: Missing or bad timeline in trace save", Logging.LogFilterType.TextInfo);
                return false;
            }
            _timeline = new List<TIMELINE_EVENT>();
            JArray? arr = arrTok.ToObject<JArray>();
            if (arr is null)
            {
                return false;
            }

            foreach (JToken tlTok in arr)
            {
                if (tlTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent($"\tWarning: Bad timeline item in trace save", Logging.LogFilterType.TextInfo);
                    return false;
                }
                JObject? tlObj = tlTok.ToObject<JObject>();
                if (tlObj is null)
                {
                    Logging.RecordLogEvent($"\tWarning: Invalid timeline object in trace save", Logging.LogFilterType.TextInfo);
                    return false;
                }
                Logging.TIMELINE_EVENT evt = new Logging.TIMELINE_EVENT(tlObj, this);
                if (!evt.Inited)
                {
                    Logging.RecordLogEvent($"\tWarning: Invalid timeline object data in trace save", Logging.LogFilterType.TextInfo);
                    return false;
                }

                if (evt.LogType == Logging.eLogFilterBaseType.TimeLine)
                {
                    switch (evt.TimelineEventType)
                    {
                        case Logging.eTimelineEvent.ProcessStart:
                        case Logging.eTimelineEvent.ProcessEnd:
                            {
                                // _tlFilterCounts.TryGetValue(LogFilterType.TimelineProcess , out int currentCountp);
                                // _tlFilterCounts[LogFilterType.TimelineProcess] = currentCountp + 1;
                                _timeline.Add(evt);
                            }
                            break;
                        case Logging.eTimelineEvent.ThreadStart:
                        case Logging.eTimelineEvent.ThreadEnd:
                            {
                                //_tlFilterCounts.TryGetValue(LogFilterType.TimelineThread, out int currentCountt);
                                //_tlFilterCounts[LogFilterType.TimelineThread] = currentCountt + 1;
                                _timeline.Add(evt);
                            }
                            break;

                        case Logging.eTimelineEvent.APICall:
                            _timeline.Add(evt);
                            break;//not in logs window
                        /*
                        case eTimelineEvent.APICall:
                        APICALL apic = (APICALL)(evt.Item);
                        if (apic.graph.ProcessData.GetSymbol(apic.node.GlobalModuleID, apic.node.address, out string? sym))
                        {
                            try
                            {
                                //resolve the api type again in case the api type list has been updated
                                string modulePath = apic.graph.ProcessData.GetModulePath(apic.node.GlobalModuleID);
                                var moduleEnum = WinAPIDetails.ResolveModuleEnum(modulePath);
                                string ftype = WinAPIDetails.ResolveAPIFilterType(moduleEnum, sym);

                                //_tlFilterCounts[LogFilterType.] = _tlFilterCounts.GetValueOrDefault(ftype, 0) + 1;
                                apic.ApiType = ftype;
                                evt.ReplaceItem(apic);
                                evt.Filter = LogFilterType;
                                _timeline.Add(evt);
                                continue;
                            }
                            catch { }

                        }
                        _tlFilterCounts[apic.ApiType] = _tlFilterCounts.GetValueOrDefault(apic.ApiType, 0) + 1;
                        _timeline.Add(evt);
                        break;
                        */
                        default:
                            Debug.Assert(false, "Timeline event has no assigned filter");
                            break;
                    }
                }
                else
                {
                    Debug.Assert(false, "Should not have this event type here");
                }

            }
            return true;
        }


        /// <summary>
        /// Export the current trace in the pajek format, a simple graph serialisation format that other graph layout programs accept
        /// </summary>
        /// <param name="TID">Thread ID of the graph to serialise</param>
        public void ExportPajek(uint TID)
        {
            ProtoGraph pgraph = this.ProtoGraphs[TID];
            string saveDir = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.TraceSaveDirectory);
            if (!Directory.Exists(saveDir))
            {
                return;
            }

            FileStream outfile = File.OpenWrite(Path.Combine(saveDir, "pajeksave" + TID.ToString() + ".net"));
            outfile.Write(Encoding.ASCII.GetBytes("%*Colnames \"Disassembly\"\n"));
            outfile.Write(Encoding.ASCII.GetBytes("*Vertices " + pgraph.NodeList.Count + "\n"));

            foreach (NodeData n in pgraph.NodeList)
            {
                outfile.Write(Encoding.ASCII.GetBytes(n.Index + " \"" + n.ins!.InsText + "\"\n"));
            }

            outfile.Write(Encoding.ASCII.GetBytes("*edgeslist " + pgraph.NodeList.Count + "\n"));
            foreach (NodeData n in pgraph.NodeList)
            {
                outfile.Write(Encoding.ASCII.GetBytes(n.Index + " "));
                foreach (int nodeidx in n.OutgoingNeighboursSet)
                {
                    outfile.Write(Encoding.ASCII.GetBytes(nodeidx.ToString() + " "));
                }
                outfile.Write(Encoding.ASCII.GetBytes("\n"));
            }
            outfile.Close();
        }

        /// <summary>
        /// Send a step command to execute a single instruction in a paused trace. Will step over function calls
        /// </summary>
        /// <param name="graph">The graph of the thread to step over</param>
        public void SendDebugStepOver(ProtoGraph graph)
        {
            if (!graph.HasRecentStep)
            {
                return;
            }

            ulong stepAddr = graph.RecentStepAddr;
            List<uint> nodes = DisassemblyData.GetNodesAtAddress(stepAddr, graph.ThreadID);
            if (nodes.Count == 0)
            {
                return;
            }

            NodeData? n = graph.GetNode(nodes[^1]);
            Debug.Assert(n is not null);
            if (n.ins!.itype != CONSTANTS.eNodeType.eInsCall)
            {
                SendDebugStep(graph);
                return;
            }
            ulong nextInsAddress = n.ins.Address + (ulong)n.ins.NumBytes;

            string cmd = $"SOV,{nextInsAddress:X}";
            SendDebugCommand(graph.ThreadID, cmd);
        }

        /// <summary>
        /// Send a step command to execute a single instruction in a paused trace. Will step into function calls
        /// </summary>
        /// <param name="graph">The graph of the thread to step over</param>
        public void SendDebugStep(ProtoGraph graph)
        {
            SendDebugCommand(graph.ThreadID, "SIN");
        }

        /// <summary>
        /// Send a debug command to a traced thread
        /// </summary>
        /// <param name="threadID">The thread ID</param>
        /// <param name="command">A command</param>
        public void SendDebugCommand(uint threadID, string command)
        {
            if (ProcessThreads.modThread == null)
            {
                Logging.RecordLogEvent("Error: DBG command send to trace with no active module thread", Logging.LogFilterType.TextError);
                return;
            }


            byte[] buf = System.Text.Encoding.ASCII.GetBytes(command + '@' + threadID.ToString() + "\n\x00");
            if (!ProcessThreads.modThread.SendCommand(buf))
            {
                Logging.RecordLogEvent("Error sending command to control pipe", Logging.LogFilterType.TextError);
            }
        }

        /// <summary>
        /// The disassembly associated with each address
        /// </summary>
        public ProcessRecord DisassemblyData { private set; get; }

        /// <summary>
        /// the time the user pressed start, not when the first process was seen
        /// </summary>
        public DateTime LaunchedTime { private set; get; }

        /// <summary>
        /// The BinaryTarget associated with this trace object
        /// </summary>
        public BinaryTarget Target { private set; get; }

        /// <summary>
        /// false if the process is no longer being traced
        /// </summary>
        public bool IsRunning => TraceState != eTraceState.eTerminated;
        private bool killed = false;

        /// <summary>
        /// The state of the trace process
        /// </summary>
        public eTraceState TraceState { private set; get; } = eTraceState.eTerminated;

        /// <summary>
        /// Are there any edges left to render, or might more trace data arrive?
        /// </summary>
        public bool ProcessingRemaining => ProcessThreads.modThread is not null && (ProcessThreads.modThread.Running || this.PlottedGraphs.Values.Any(g => !g.RenderingComplete));

        /// <summary>
        /// See if the success requirements of a complete trace run are met 
        /// </summary>
        /// <param name="ptreq">Trace requirements object for the test</param>
        /// <param name="resultsobj">A Test results commentary object which describes how the test executed</param>
        /// <returns>The results of the test</returns>
        public TRACE_TEST_RESULTS EvaluateProcessTestRequirement(TraceRequirements ptreq, ref TraceTestResultCommentary resultsobj)
        {
            TRACE_TEST_RESULTS results = new TRACE_TEST_RESULTS();

            resultsobj.traceResults = results;
            foreach (TestRequirement req in ptreq.ProcessRequirements)
            {
                Console.WriteLine($"Evaluating process requirement {req.Name} {req.Condition} [val] ");
                bool passed = false;
                string? error = "";
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
                TestResultCommentary comment = new TestResultCommentary(req)
                {
                    comparedValueString = compareValueString,
                    result = passed ? eTestState.Passed : eTestState.Failed,
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


        /// <summary>
        /// Determine if the thread meets a set of test requirements
        /// </summary>
        /// <param name="threadTestReqs">REQUIREMENTS_LIST</param>
        /// <returns>A dictionary of REQUIREMENT_TEST_RESULTS for each thread</returns>
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
