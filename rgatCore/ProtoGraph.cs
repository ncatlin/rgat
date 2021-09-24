using Newtonsoft.Json.Linq;
using rgat.Testing;
using rgat.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using static rgat.CONSTANTS;

namespace rgat
{
    /// <summary>
    /// Record of an API call for UI display
    /// </summary>
    public struct APICALLDATA
    {
        /// <summary>
        /// Caller -> Target node pair
        /// </summary>
        public Tuple<uint, uint> edgeIdx;

        /// <summary>
        /// a list of (index, value) tuples
        /// where 
        ///     index: the position of the argument in the function prototype
        ///     value: a string representation of the argument value
        /// </summary>
        public List<Tuple<int, string>> argList;
    };

    /// <summary>
    /// The instrumentation state for a module/instruction
    /// </summary>
    public enum eCodeInstrumentation
    {
        /// <summary>
        /// Instructions are instrumented
        /// </summary>
        eInstrumentedCode = 0,
        /// <summary>
        /// Instructions are not instrumented, will be marked as an API call
        /// </summary>
        eUninstrumentedCode = 1
    };

    /// <summary>
    /// Description of entries into uninstrumented code, usually APi calls
    /// </summary>
    public struct ROUTINE_STRUCT
    {
        /// <summary>
        /// The module ID of the code
        /// </summary>
        public int Module;

        /// <summary>
        /// list of threads that call this routine (ThreadID, (caller, target))
        /// ProcessData.ExternCallerLock should be held to access this, which is terrible
        /// </summary>
        public Dictionary<uint, List<Tuple<uint, uint>>> ThreadCallers;

        /// <summary>
        /// Does the routine have a symbol associated with it
        /// </summary>
        public bool HasSymbol;
    };

    /// <summary>
    /// The Tag associated with an executed basic block
    /// </summary>
    public struct TAG
    {
        /// <summary>
        /// Address of the block
        /// </summary>
        public ulong blockaddr;
        /// <summary>
        /// ID of the block
        /// </summary>
        public uint blockID;
        /// <summary>
        /// How many instructions are in the block
        /// </summary>
        public ulong insCount;
        //used internally
        /// <summary>
        /// Did the block lead to instrumented code
        /// </summary>
        public eCodeInstrumentation InstrumentationState;
        /// <summary>
        /// A known API associated with this tag
        /// </summary>
        public ROUTINE_STRUCT? foundExtern;
    };

    /// <summary>
    /// A recorded thread trace event
    /// </summary>
    public enum eTraceUpdateType
    {
        /// <summary>
        /// A basic block was executed
        /// </summary>
        eAnimExecTag,
        /// <summary>
        /// A basic block was executed so much it went into 
        /// a low-overhead light instrumentation mode
        /// </summary>
        eAnimUnchained,
        /// <summary>
        /// A region of light instrumentation was exited, the details
        /// of what happened are enclosed
        /// </summary>
        eAnimUnchainedResults,
        /// <summary>
        /// Execution is resuming in full-instrumentation mode
        /// </summary>
        eAnimReinstrument,
        /// <summary>
        /// A REP prefixed instruction executed
        /// </summary>
        eAnimRepExec,
        /// <summary>
        /// An exception happened
        /// </summary>
        eAnimExecException
    };


    /// <summary>
    /// A trace event that can be replayed
    /// The interpretation of all the values depends on the entry type
    /// </summary>
    public struct ANIMATIONENTRY
    {
        /// <summary>
        /// The type of action that caused this entry
        /// </summary>
        public eTraceUpdateType entryType;
        /// <summary>
        /// The address of the basic block this happened in
        /// </summary>
        public ulong blockAddr;
        /// <summary>
        /// The ID of the basic block
        /// </summary>
        public uint blockID;
        /// <summary>
        /// Which edges were involved, how many times
        /// </summary>
        public List<Tuple<uint, ulong>>? edgeCounts;
        /// <summary>
        /// A count for this event
        /// </summary>
        public ulong count;
        /// <summary>
        /// The target address of the event
        /// </summary>
        public ulong targetAddr;
        /// <summary>
        /// The block ID of the target
        /// </summary>
        public uint targetID;
    };


    /// <summary>
    /// The data structure representing a recorded process thread
    /// </summary>
    public class ProtoGraph
    {

        /// <summary>
        /// The data structure representing a recorded process thread
        /// </summary>
        /// <param name="runrecord">A TraceRecord for the process containing this thread</param>
        /// <param name="threadID">A Thread ID for the thread</param>
        /// <param name="startAddr">The first program counter address of the thread</param>
        /// <param name="terminated">Set to true if loading a saved trace</param>
        public ProtoGraph(TraceRecord runrecord, uint threadID, ulong startAddr, bool terminated = false)
        {
            TraceData = runrecord;
            ProcessData = runrecord.DisassemblyData;
            ThreadID = threadID;
            Terminated = terminated;
            StartAddress = startAddr;
            AssignModulePath();
        }

        /// <summary>
        /// The threads operating system assigned thread ID
        /// </summary>
        public uint ThreadID = 0;

        /// <summary>
        /// The address of the first instruction executed by the thread. May not be instrumented.
        /// </summary>
        public ulong StartAddress = 0;

        /// <summary>
        /// The worker which is reading trace data from the instrumented thread
        /// </summary>
        public TraceIngestWorker? TraceReader { set; get; } = null;
        /// <summary>
        /// The worker which is processing trace data from the instrumented thread
        /// </summary>
        public ThreadTraceProcessingThread? TraceProcessor { set; get; } = null;

        /// <summary>
        /// Process data shared by all threads (instruction disassembly, API metadata, etc)
        /// </summary>
        public ProcessRecord ProcessData { private set; get; }

        /// <summary>
        /// Describes the lifetime of the process, parent storage class for threads
        /// </summary>
        public TraceRecord TraceData { private set; get; }

        /// <summary>
        /// When the thread was recorded, used as a unique identifier for threads
        /// </summary>
        public DateTime ConstructedTime { private set; get; } = DateTime.Now;

        /// <summary>
        /// The order of most busy instructions has been calculated since the graph was last updated
        /// </summary>
        public bool HeatSolvingComplete = false; //todo set this once processing is done?

        /*
        public List<InteractionTarget> SystemInteractions = new List<InteractionTarget>();
        public Dictionary<ulong, InteractionTarget> Interacted_FileHandles = new Dictionary<ulong, InteractionTarget>();
        public Dictionary<string, InteractionTarget> Interacted_FilePaths = new Dictionary<string, InteractionTarget>();
        public Dictionary<string, InteractionTarget> Interacted_RegistryPaths = new Dictionary<string, InteractionTarget>();
        public Dictionary<string, InteractionTarget> Interacted_NetworkPaths = new Dictionary<string, InteractionTarget>();
        public Dictionary<string, InteractionTarget> Interacted_Mutexes = new Dictionary<string, InteractionTarget>();
 */

        /// <summary>
        /// Mark this thread as having completed execution
        /// </summary>
        public void SetTerminated()
        {
            lock (AnimDataLock)
            {
                if (!Terminated)
                {
                    TraceData.RecordTimelineEvent(Logging.eTimelineEvent.ThreadEnd, graph: this);
                    Terminated = true;
                }
            }
        }


        private bool LoadNodes(JArray NodesArray, ProcessRecord processinfo)
        {
            foreach (JArray nodeItem in NodesArray)
            {
                NodeData n = new NodeData();//can't this be done at start?
                if (!n.Deserialise(nodeItem, processinfo))
                {
                    Console.WriteLine("Failed to deserialise node");
                    return false;
                }

                InsertNode(n.Index, n);
            }

            return true;
        }


        private bool LoadExceptions(JArray exceptionsArray)
        {
            foreach (JToken entry in exceptionsArray)
            {
                if (entry.Type != JTokenType.Integer)
                {
                    return false;
                }

                ExceptionNodeIndexes.Add(entry.ToObject<uint>());
            }
            return true;
        }


        private bool LoadStats(JObject graphData)
        {
            if (!graphData.TryGetValue("Module", out JToken? jModID) || jModID.Type != JTokenType.Integer)
            {
                return false;
            }
            exeModuleID = jModID.ToObject<int>();

            if (exeModuleID < 0 || exeModuleID >= TraceData.DisassemblyData.LoadedModuleBounds.Count)
            {
                return false;
            }

            if (!graphData.TryGetValue("TotalInstructions", out JToken? jTotal) || jTotal.Type != JTokenType.Integer)
            {
                return false;
            }
            TotalInstructions = jTotal.ToObject<ulong>();

            if (!graphData.TryGetValue("ConstructedTime", out JToken? timeTok) || timeTok.Type != JTokenType.Date)
            {
                return false;
            }
            ConstructedTime = timeTok.ToObject<DateTime>();

            return true;
        }

        private bool LoadAnimationData(JArray animationArray)
        {
            Logging.RecordLogEvent($"LoadAnimationData Loading {animationArray.Count} trace entries for graph {ThreadID}");
            foreach (JArray animFields in animationArray)
            {
                if (animFields.Count != 7)
                {
                    return false;
                }

                ANIMATIONENTRY entry = new ANIMATIONENTRY();
                entry.entryType = (eTraceUpdateType)animFields[0].ToObject<uint>();
                entry.blockAddr = animFields[1].ToObject<ulong>();
                entry.blockID = animFields[2].ToObject<uint>();
                entry.count = animFields[3].ToObject<ulong>();
                entry.targetAddr = animFields[4].ToObject<ulong>();
                entry.targetID = animFields[5].ToObject<uint>();
                JArray edgecounts = (JArray)animFields[6];
                if (edgecounts.Count > 0)
                {
                    entry.edgeCounts = new List<Tuple<uint, ulong>>();
                    for (int i = 0; i < edgecounts.Count; i += 2)
                    {
                        entry.edgeCounts.Add(new Tuple<uint, ulong>(edgecounts[i].ToObject<uint>(), edgecounts[i + 1].ToObject<ulong>()));
                    }
                }
                else
                {
                    entry.edgeCounts = null;
                }
                SavedAnimationData.Add(entry);
            }

            return true;
        }

        private bool LoadCallData(JArray callarray)
        {
            foreach (JArray entry in callarray)
            {
                if (entry.Count != 3 || entry[0].Type != JTokenType.Integer ||
                    entry[1].Type != JTokenType.Integer || entry[2].Type != JTokenType.Array)
                {
                    Console.WriteLine("Error: Bad entry in LoadCallData");
                    return false;
                }

                Tuple<uint, uint> edge = new Tuple<uint, uint>(entry[0].ToObject<uint>(), entry[1].ToObject<uint>());
                List<Tuple<int, string>> CallArgList = new List<Tuple<int, string>>();

                foreach (JArray argEntry in (JArray)entry[2])
                {
                    if (argEntry.Count != 2 || argEntry[0].Type != JTokenType.Integer || argEntry[1].Type != JTokenType.String)
                    {
                        return false;
                    }

                    Tuple<int, string> argData = new Tuple<int, string>(argEntry[0].ToObject<int>(), argEntry[1].ToString());
                    CallArgList.Add(argData);
                }

                APICALLDATA callDat = new APICALLDATA();
                callDat.argList = CallArgList;
                callDat.edgeIdx = edge;
                SymbolCallRecords.Add(callDat);
            }
            return true;
        }

        private bool set_target_instruction(InstructionData instruction)
        {
            //ReadLock(piddata->disassemblyRWLock);
            lock (TraceData.DisassemblyData.InstructionsLock) //todo this can be a read lock
            {
                //Console.WriteLine($"Checking if instruction 0x{instruction.address:X}, dbgid {instruction.DebugID} mut {instruction.mutationIndex} executed");
                if (instruction.GetThreadVert(ThreadID, out uint targetID))
                {
                    targVertID = targetID;
                    return true;
                }
                return false;
            }
        }



        ///todo is this needed
        ///yes. yes it is.
        private void AddEdge_LastToTargetVert(bool alreadyExecuted, int instructionIndex, ulong repeats)
        {
            Tuple<uint, uint> edgeIDPair = new Tuple<uint, uint>(ProtoLastVertID, targVertID);

            //Console.WriteLine($"\tAddEdge_LastToTargetVert {ProtoLastVertID} -> {targVertID} repeats {repeats}");

            if (EdgeExists(edgeIDPair, out EdgeData? edgeObj))
            {
                edgeObj!.IncreaseExecutionCount(repeats);
                //cout << "repeated internal edge from " << lastVertID << "->" << targVertID << endl;
                return;
            }

            if (lastNodeType == eEdgeNodeType.eFIRST_IN_THREAD)
            {
                return;
            }

            NodeData? sourcenode = GetNode(ProtoLastVertID);
            Debug.Assert(sourcenode is not null);
            if (sourcenode.ThunkCaller)
            {
                return;
            }

            //make API calls leaf nodes, rather than part of the chain
            //if (sourcenode.IsExternal)
            //    sourcenode = safe_get_node(ProtoLastLastVertID);

            if (!EdgeExists(new Tuple<uint, uint>(sourcenode.Index, targVertID)))
            {
                EdgeData newEdge = new EdgeData(index: EdgeList.Count, sourceType: lastNodeType, execCount: repeats);

                if (instructionIndex > 0)
                {
                    newEdge.edgeClass = alreadyExecuted ? eEdgeNodeType.eEdgeOld : eEdgeNodeType.eEdgeNew;
                }
                else
                {
                    if (alreadyExecuted)
                    {
                        newEdge.edgeClass = eEdgeNodeType.eEdgeOld;
                    }
                    else
                    {
                        switch (lastNodeType)
                        {
                            case eEdgeNodeType.eNodeReturn:
                                newEdge.edgeClass = eEdgeNodeType.eEdgeReturn;
                                break;
                            case eEdgeNodeType.eNodeException:
                                newEdge.edgeClass = eEdgeNodeType.eEdgeException;
                                break;
                            case eEdgeNodeType.eNodeCall:
                                newEdge.edgeClass = eEdgeNodeType.eEdgeCall;
                                break;
                            default:
                                newEdge.edgeClass = eEdgeNodeType.eEdgeNew;
                                break;
                        }
                    }
                }

                //Console.WriteLine($"Creating edge src{sourcenode.index} -> targvid{targVertID}");
                NodeData? targNode = GetNode(targVertID);
                Debug.Assert(targNode is not null);
                AddEdge(newEdge, sourcenode, targNode);
            }


        }

        /// <summary>
        /// A step command was just issued
        /// </summary>
        public bool HasRecentStep { private set; get; } = false;
        /// <summary>
        /// The last address stepped from
        /// </summary>
        public ulong RecentStepAddr { private set; get; }
        /// <summary>
        /// The address being stepped to
        /// </summary>
        public ulong NextStepAddr { private set; get; }
        /// <summary>
        /// Stepping is done
        /// </summary>
        public void ClearRecentStep() => HasRecentStep = false;

        /// <summary>
        /// Setup a step operation
        /// </summary>
        /// <param name="blockID">The block stepped to</param>
        /// <param name="address">The address stepped from</param>
        /// <param name="nextAddr">The address stepped to</param>
        /// <returns></returns>
        public bool SetRecentStep(uint blockID, ulong address, ulong nextAddr)
        {
            HasRecentStep = true;
            RecentStepAddr = address;
            NextStepAddr = nextAddr;

            if (BlocksFirstLastNodeList.Count <= blockID)
            {
                addBlockToGraph(blockID, 1);
                return false;
            }

            return true;
        }


        private void run_faulting_BB(TAG tag)
        {
            Logging.RecordLogEvent($"Faulting Block recorded: block:{tag.blockID} 0x{tag.blockaddr:X} lastvid:{ProtoLastVertID}, lastlastvid:{ProtoLastLastVertID}",
                Logging.LogFilterType.TextError);


            ROUTINE_STRUCT? foundExtern = null;
            List<InstructionData>? block = ProcessData.GetDisassemblyBlock(tag.blockID, ref foundExtern, tag.blockaddr);
            if (block == null)
            {
                Logging.RecordLogEvent($"Faulting Block {tag.blockID} 0x{tag.blockaddr:X} not recorded in disassembly");
                Debug.Assert(false);
                if (foundExtern != null)
                {
                    Console.WriteLine($"[rgat]Warning - faulting block was in uninstrumented code at 0x{tag.blockaddr}");
                }
                else
                {
                    Console.WriteLine($"[rgat]Warning - failed to get disassembly for faulting block at 0x{tag.blockaddr}");
                }

                return;
            }

            for (int instructionIndex = 0; (ulong)instructionIndex <= tag.insCount; ++instructionIndex)
            {
                InstructionData instruction = block[instructionIndex];

                if (lastNodeType != eEdgeNodeType.eFIRST_IN_THREAD && !node_exists(ProtoLastVertID))
                {
                    Console.WriteLine("\t\t[rgat]ERROR: RunBB- Last vert {lastVertID} not found");
                    Debug.Assert(false);
                }

                //target vert already on this threads graph?
                bool alreadyExecuted = set_target_instruction(instruction);
                if (!alreadyExecuted)
                {
                    targVertID = handle_new_instruction(instruction, tag.blockID, 1);
                }
                else
                {
                    GetNode(targVertID)?.IncreaseExecutionCount(1);
                }

                AddEdge_LastToTargetVert(alreadyExecuted, instructionIndex, 1);

                //BB_addExceptionEdge(alreadyExecuted, instructionIndex, 1);

                //setup conditions for next instruction
                if ((ulong)instructionIndex < tag.insCount)
                {
                    lastNodeType = eEdgeNodeType.eNodeNonFlow;
                }
                else
                {
                    lastNodeType = eEdgeNodeType.eNodeException;
                    lock (highlightsLock)
                    {
                        if (!exceptionSet.Contains(targVertID))
                        {
                            exceptionSet.Add(targVertID);
                        }
                    }
                }

                ProtoLastLastVertID = ProtoLastVertID;
                ProtoLastVertID = targVertID;
            }
        }

        private bool RunExternal(ulong targaddr, ulong repeats, out Tuple<uint, uint>? resultPair)
        {
            if (GlobalConfig.Settings.Logs.BulkLogging)
            {
                Logging.RecordLogEvent($"RunExternal: targaddr:0x{targaddr:X} repeats:{repeats}, lastvid:{ProtoLastVertID}, lastlast:{ProtoLastLastVertID}", Logging.LogFilterType.BulkDebugLogFile);
            }

            //start by examining our caller
            NodeData? lastNode = GetNode(ProtoLastVertID);
            if (lastNode is null || lastNode.IsExternal) { resultPair = null; return false; }
            Debug.Assert(lastNode.ins!.NumBytes > 0);

            //if caller is also external then we are not interested in this (does this happen?)
            if (ProcessData.ModuleTraceStates[lastNode.GlobalModuleID] == eCodeInstrumentation.eUninstrumentedCode) { resultPair = null; return false; }


            bool found = ProcessData.FindContainingModule(targaddr, out int? moduleNo);
            if (!found)
            {
                //this happens in test binary: -mems-
                Console.WriteLine("Warning: Code executed which is not in image or an external module. Possibly a buffer.");
                resultPair = null;
                return false;
            }
            int modnum = moduleNo!.Value;

            ProcessData.get_extern_at_address(targaddr, modnum, out ROUTINE_STRUCT thisbb);


            //see if caller already called this
            //if so, get the destination node so we can just increase edge weight
            if (thisbb.ThreadCallers.TryGetValue(ThreadID, out List<Tuple<uint, uint>>? callers))
            {
                //piddata->getExternCallerReadLock();
                foreach (var caller in callers)
                {
                    if (caller.Item1 != ProtoLastVertID)
                    {
                        continue;
                    }

                    //piddata->dropExternCallerReadLock();

                    //this instruction in this thread has already called it
                    //cout << "repeated external edge from " << lastVertID << "->" << targVertID << endl;

                    targVertID = caller.Item2;

                    EdgeData? e = GetEdge(caller.Item1, caller.Item2);
                    if (e is not null)
                    {
                        e.IncreaseExecutionCount(repeats);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Bad edge in RunExternal: {caller.Item1},{caller.Item2} in thread {this.ThreadID}, module {this.ProcessData.GetModulePath(modnum)}");
                    }

                    NodeData? targNode = GetNode(targVertID);
                    Debug.Assert(targNode is not null);
                    targNode.IncreaseExecutionCount(repeats);

                    TraceData.RecordAPICall(targNode, this, targNode.currentCallIndex, repeats); //todo this should be done in a BG thread

                    targNode.currentCallIndex = (int)Math.Min(int.MaxValue, (ulong)targNode.currentCallIndex + repeats);
                    ProtoLastLastVertID = ProtoLastVertID;
                    ProtoLastVertID = targVertID;
                    resultPair = caller;

                    return true;
                }
                //not found: thread has already called it, but from a different place

            }//else: thread hasn't called this function before


            //piddata->dropExternCallerReadLock();

            lastNode.childexterns += 1;
            targVertID = (uint)NodeCount;
            resultPair = new Tuple<uint, uint>(ProtoLastVertID, targVertID);

            lock (ProcessData.ExternCallerLock)
            {
                //has this thread executed this basic block before?
                if (callers == null)
                {
                    List<Tuple<uint, uint>> callervec = new List<Tuple<uint, uint>>();
                    //cout << "add extern addr " << std::hex<<  targaddr << " mod " << std::dec << modnum << endl;
                    callervec.Add(resultPair);
                    thisbb.ThreadCallers.Add(ThreadID, callervec);
                }
                else
                {
                    callers.Add(resultPair);
                }
            }

            int module = thisbb.Module;

            //make new external/library call node
            NodeData newTargNode = new NodeData();
            newTargNode.GlobalModuleID = module;
            newTargNode.IsExternal = true;
            newTargNode.address = targaddr;
            newTargNode.Index = targVertID;
            newTargNode.parentIdx = ProtoLastVertID;
            newTargNode.SetExecutionCount(repeats);
            newTargNode.BlockID = uint.MaxValue;
            newTargNode.HasSymbol = true;


            InsertNode(targVertID, newTargNode);

            TraceData.RecordAPICall(newTargNode, this, 0, repeats);


            NodeData? sourceNode = GetNode(ProtoLastVertID);
            Debug.Assert(sourceNode is not null);
            NodeData? targetNode = GetNode(targVertID);
            Debug.Assert(targetNode is not null);

            EdgeData newEdge = new EdgeData(index: EdgeList.Count, sourceType: sourceNode.VertType(), execCount: repeats);
            newEdge.edgeClass = eEdgeNodeType.eEdgeLib;
            AddEdge(newEdge, sourceNode, targetNode);
            //cout << "added external edge from " << lastVertID << "->" << targVertID << endl;
            lastNodeType = eEdgeNodeType.eNodeExternal;
            ProtoLastLastVertID = ProtoLastVertID;
            ProtoLastVertID = newTargNode.Index;
            // ProtoLastLastVertID = ProtoLastVertID;
            //ProtoLastVertID = targVertID;
            return true;
        }

        private readonly object argsLock = new object();

        //call arguments are recieved out-of-order from trace tags due to tag caching. they are stored here until they can be associated with the correct node
        private readonly List<INCOMING_CALL_ARGUMENT> _unprocessedCallArguments = new List<INCOMING_CALL_ARGUMENT>();

        private struct INCOMING_CALL_ARGUMENT
        {
            public ulong sourceBlock;
            public ulong callerAddress;
            public ulong calledAddress;
            public int argIndex;
            public bool finalEntry;
            public string argstring;
            public bool isReturnVal;
        }

        private void RemoveProcessedArgsFromCache(uint completeCount)
        {
            lock (argsLock)
            {
                _unprocessedCallArguments.RemoveRange(0, (int)completeCount);
            }
        }


        /// <summary>
        /// Runs through the cached API call arguments and attempts to match complete
        /// sets up to corresponding nodes on the graph once they have been inserted
        /// </summary>
        public void ProcessIncomingCallArguments()
        {
            if (_unprocessedCallArguments.Count == 0)
            {
                return;
            }

            ulong currentSourceBlock = _unprocessedCallArguments[0].sourceBlock;
            if ((int)currentSourceBlock == -1)
            {
                return; //API called before instrumented code was reached
            }

            ulong currentTarget = _unprocessedCallArguments[0].calledAddress;

            uint completecount = 0;
            int currentIndex = -1;
            int maxCacheI = _unprocessedCallArguments.Count;

            for (var cacheI = 0; cacheI < maxCacheI; cacheI++)
            {
                INCOMING_CALL_ARGUMENT arg = _unprocessedCallArguments[cacheI];
                if (arg.calledAddress != currentTarget)
                {
                    Logging.RecordLogEvent($"Breakdown of API argument processing between {_unprocessedCallArguments[cacheI - 1].argstring} and {_unprocessedCallArguments[cacheI].argstring}Check the 'M' and 'E' fields of any recently added API wrapper in the instrumentation tool", Logging.LogFilterType.TextError);

                    _unprocessedCallArguments.RemoveRange(0, cacheI);
                    return;
                }

                Debug.Assert(arg.sourceBlock == currentSourceBlock, "ProcessIncomingCallArguments() unexpected change of source");
                Debug.Assert(arg.argIndex > currentIndex || arg.isReturnVal, "ProcessIncomingCallArguments() unexpected change of source");
                if (BlocksFirstLastNodeList.Count <= (int)currentSourceBlock)
                {
                    break;
                }

                Tuple<uint, uint>? blockIndexes = BlocksFirstLastNodeList[(int)currentSourceBlock];
                if (blockIndexes == null)
                {
                    break;
                }

                uint callerNodeIdx = blockIndexes.Item2;
                currentIndex = arg.argIndex; //uh
                if (!arg.finalEntry)
                {
                    continue;
                }


                //each API call target can have multiple nodes in a thread, so we have to get the list of 
                //every edge that has this extern as a target
                if (!lookup_extern_func_calls(arg.calledAddress, out List<Tuple<uint, uint>>? threadCalls) || threadCalls is null)
                {
                    Console.WriteLine($"\tProcessIncomingCallArguments - Failed to find *any* callers of 0x{arg.calledAddress:X} in current thread. Leaving until it appears.");
                    RemoveProcessedArgsFromCache(completecount);
                    return;
                }

                //run through each edge, trying to match args to the right caller-callee pair
                //running backwards should be more efficient as the lastest node is likely to hit the latest arguments
                bool sequenceProcessed = false;
                for (var i = threadCalls.Count - 1; i >= 0; i--)
                {
                    //ulong callerAddress = callerNode.ins.address;

                    if (threadCalls[i].Item1 != callerNodeIdx)
                    {
                        continue;
                    }

                    NodeData? functionNode = GetNode(threadCalls[i].Item2);
                    Debug.Assert(functionNode is not null);

                    //each node can only have a certain number of arguments to prevent simple denial of service
                    if (functionNode.callRecordsIndexs.Count >= GlobalConfig.Settings.Tracing.ArgStorageMax)
                    {
                        //todo: blacklist this callee from future processing
                        Console.WriteLine($"Warning, dropping args to extern 0x{currentTarget:X} because the storage limit is {GlobalConfig.Settings.Tracing.ArgStorageMax}");
                    }
                    else
                    {
                        List<Tuple<int, string>> argStringsList = new List<Tuple<int, string>>();
                        for (var aI = 0; aI <= cacheI; aI++)
                        {
                            argStringsList.Add(new Tuple<int, string>(_unprocessedCallArguments[aI].argIndex, _unprocessedCallArguments[aI].argstring));
                            completecount++;
                        }

                        APICALLDATA callRecord;
                        callRecord.edgeIdx = threadCalls[i];
                        callRecord.argList = argStringsList;

                        functionNode.callRecordsIndexs.Add((ulong)SymbolCallRecords.Count);
                        SymbolCallRecords.Add(callRecord);
                        RecordSystemInteraction(functionNode, callRecord);

                        // this toggle isn't thread safe so slight chance for renderer to not notice the final arg
                        // not worth faffing around with locks though - maybe just re-read at tracereader thread termination
                        functionNode.Dirty = true;
                    }
                    sequenceProcessed = true;
                    break;
                }

                if (!sequenceProcessed)
                {
                    NodeData? targnode = GetNode(threadCalls[0].Item2);
                    Debug.Assert(targnode is not null);
                    ProcessData.GetSymbol(targnode.GlobalModuleID, arg.calledAddress, out string? sym);
                    Console.WriteLine($"\tProcessIncomingCallArguments - Failed to find *specific* caller of 0x{arg.calledAddress:X} [{sym}] in current thread. Leaving until it appears.");
                    break;
                }

                //setup for next sequence of args
                if (_unprocessedCallArguments.Count <= (cacheI + 1))
                {
                    break;
                }

                currentTarget = _unprocessedCallArguments[cacheI + 1].calledAddress;
                currentSourceBlock = _unprocessedCallArguments[cacheI + 1].sourceBlock;
                currentIndex = -1;

            }

            RemoveProcessedArgsFromCache(completecount);
        }

        private void RecordSystemInteraction(NodeData node, APICALLDATA APIcall)
        {
            Debug.Assert(node.IsExternal && node.HasSymbol);
            //int  moduleEnum = ProcessData.ModuleAPIReferences[node.GlobalModuleID];

            ProcessData.GetSymbol(node.GlobalModuleID, node.address, out string? symbol);
            Console.WriteLine($"Node {node.Index} is system interaction {node.IsExternal}");

        }


        //future optimisation - try to insert complete complete sequences immediately
        /// <summary>
        /// Inserts API call argument data from the trace into the cache
        /// Attempts to add it to the graph if a full set of arguments is collected
        /// </summary>
        /// <param name="funcpc">Address of the function the argument is for</param>
        /// <param name="sourceBlockID">The block that called the function</param>
        /// <param name="argpos">The position of the argument in the parameter list</param>
        /// <param name="contents">A string representation of the argument</param>
        /// <param name="isLastArgInCall">Is this the last argument being recorded for this call?</param>
        public void CacheIncomingCallArgument(ulong funcpc, ulong sourceBlockID, int argpos, string contents, bool isLastArgInCall)
        {

            INCOMING_CALL_ARGUMENT argstruc = new INCOMING_CALL_ARGUMENT()
            {
                argIndex = argpos,
                calledAddress = funcpc,
                callerAddress = ulong.MaxValue,
                argstring = contents,
                finalEntry = isLastArgInCall,
                sourceBlock = sourceBlockID,
                isReturnVal = argpos == -1
            };
            lock (argsLock)
            {
                _unprocessedCallArguments.Add(argstruc);
            }

            if (isLastArgInCall)
            {
                ProcessIncomingCallArguments();
            }
        }


        private bool lookup_extern_func_calls(ulong called_function_address, out List<Tuple<uint, uint>>? callEdges)
        {
            Console.WriteLine($"lookup_extern_func_calls looking for 0x{called_function_address:x}");
            lock (ProcessData.ExternCallerLock)
            {
                if (TraceData.DisassemblyData.externdict.TryGetValue(called_function_address, out ROUTINE_STRUCT rtn))
                {
                    return rtn.ThreadCallers.TryGetValue(ThreadID, out callEdges);
                }
            }

            callEdges = null;
            return false;
        }

        private void InsertNode(uint targVertID, NodeData node)
        {
            lock (nodeLock)
            {
                Debug.Assert((NodeList.Count == 0) || (targVertID == NodeList[^1].Index + 1));

                if (node.IsExternal)
                {
                    externalNodeList.Add(node.Index);
                }
                else if (node.ins!.hasSymbol)
                {
                    internalNodeList.Add(node.Index);
                }

                NodeList.Add(node);
            }
        }

        /// <summary>
        /// Are two nodes linked by an edge? (ie: does one instruction lead to another)
        /// </summary>
        /// <param name="edge">The node pair</param>
        /// <returns>An edge was found</returns>
        public bool EdgeExists(Tuple<uint, uint> edge)
        {
            lock (edgeLock)
            {
                return _edgeDict.ContainsKey(edge);
            }
        }


        /// <summary>
        /// Are two nodes linked by an edge? (ie: does one instruction lead to another)
        /// Also returns the edge
        /// </summary>
        /// <param name="edge">The node pair</param>
        /// <param name="edged">The edge, if found</param>
        /// <returns>An edge was found</returns>
        public bool EdgeExists(Tuple<uint, uint> edge, out EdgeData? edged)
        {
            lock (edgeLock)
            {
                return _edgeDict.TryGetValue(edge, out edged) && edged is not null;
            }
        }

        /// <summary>
        /// Get a thread-safe copy of the nodepair edge list
        /// </summary>
        /// <returns>The list of nodepairs</returns>
        public List<Tuple<uint, uint>> GetEdgelistCopy()
        {

            lock (edgeLock)
            {
                return EdgeList.ToList();
            }
        }

        /// <summary>
        /// Get a thread-safe copy of the EdgeData edge list
        /// </summary>
        /// <returns>The list of EdgeData</returns>
        public List<EdgeData> GetEdgeObjListCopy()
        {
            lock (edgeLock)
            {
                return edgeObjList.ToList();
            }
        }

        /// <summary>
        /// Get a thread-safe copy of the nodedata list
        /// </summary>
        /// <returns>The list of NodeData</returns>
        public List<NodeData> GetNodeObjlistCopy()
        {
            lock (nodeLock)
            {
                return NodeList.ToList();
            }
        }


        /// <summary>
        /// Get an edge data object by source and target node
        /// </summary>
        /// <param name="src">Source node index</param>
        /// <param name="targ">Target node index</param>
        /// <returns>The edge if found, or null</returns>
        public EdgeData? GetEdge(uint src, uint targ)
        {
            lock (edgeLock)
            {
                if (_edgeDict.TryGetValue(new Tuple<uint, uint>(src, targ), out EdgeData? result))
                {
                    return result;
                }
                return null;
            }
        }


        /// <summary>
        /// Get an edge data object by source and target node tuple
        /// The edge must already be known to exist
        /// </summary>
        /// <param name="srcTarg">Source/Target node tuple</param>
        /// <returns>The edge</returns>
        public EdgeData GetEdge(Tuple<uint, uint> srcTarg)
        {
            lock (edgeLock)
            {
                return _edgeDict[srcTarg];
            }
        }

        /// <summary>
        /// Get the node objects associated with an edge index
        /// </summary>
        /// <param name="EdgeIndex">index of the edge in the edgelist</param>
        /// <param name="source">NodeData source</param>
        /// <param name="targ">NodeData target</param>
        /// <returns>The edge nodes</returns>
        public void GetEdgeNodes(int EdgeIndex, out NodeData source, out NodeData targ)
        {
            lock (edgeLock)
            {
                Tuple<uint, uint> nodes = EdgeList[EdgeIndex];
                source = NodeList[(int)nodes.Item1];
                targ = NodeList[(int)nodes.Item2];
            }
        }

        /// <summary>
        /// Retrieve an nodepair and an edgedata object for a given edge index
        /// </summary>
        /// <param name="index">The index of the edge</param>
        /// <param name="srcTarg">Output nodepaid</param>
        /// <param name="e">Output edge data</param>
        public void GetEdgeNodes(int index, out Tuple<uint, uint> srcTarg, out EdgeData e)
        {
            Debug.Assert(index < EdgeList.Count);
            lock (edgeLock)
            {
                srcTarg = EdgeList[index];
                e = _edgeDict[srcTarg];
            }
        }

        /// <summary>
        /// Add an edge by source,target index pair
        /// </summary>
        /// <param name="SrcNodeIdx">Source index</param>
        /// <param name="TargNodeIdx">Target index</param>
        /// <param name="execCount">Execution count</param>
        public void AddEdge(uint SrcNodeIdx, uint TargNodeIdx, ulong execCount)
        {
            NodeData? sourceNode = GetNode(SrcNodeIdx);
            NodeData? targNode = GetNode(TargNodeIdx);

            Debug.Assert(sourceNode is not null && targNode is not null);

            EdgeData newEdge = new EdgeData(index: EdgeList.Count, sourceType: sourceNode.VertType(), execCount: execCount);

            if (targNode.IsExternal)
            {
                newEdge.edgeClass = eEdgeNodeType.eEdgeLib;
            }
            else if (sourceNode.ins!.itype == eNodeType.eInsCall)
            {
                newEdge.edgeClass = eEdgeNodeType.eEdgeCall;
            }
            else if (sourceNode.ins.itype == eNodeType.eInsReturn)
            {
                newEdge.edgeClass = eEdgeNodeType.eEdgeReturn;
            }
            else
            {
                newEdge.edgeClass = eEdgeNodeType.eEdgeOld;
            }

            AddEdge(newEdge, sourceNode, targNode);
        }


        /// <summary>
        /// Add an existing edge, given pre-existing edge and node data
        /// </summary>
        /// <param name="e">Edgedata</param>
        /// <param name="source">Source NodeData</param>
        /// <param name="target">Target NodeData</param>
        public void AddEdge(EdgeData e, NodeData source, NodeData target)
        {
            Tuple<uint, uint> edgePair = new Tuple<uint, uint>(source.Index, target.Index);
            //Console.WriteLine($"\t\tAddEdge {source.index} -> {target.index}");


            if (!source.OutgoingNeighboursSet.Contains(edgePair.Item2))
            {
                source.OutgoingNeighboursSet.Add(edgePair.Item2);
            }


            if (source.IsConditional && source.conditional != ConditionalType.CONDCOMPLETE)
            {
                if (source.ins!.condDropAddress == target.address)
                {
                    if (source.ins.branchAddress == target.address)
                    {
                        source.conditional = ConditionalType.CONDCOMPLETE; //opaque predicate
                    }
                    else
                    {
                        source.conditional |= ConditionalType.CONDFELLTHROUGH;
                    }
                }
                else if (source.ins.branchAddress == target.address)
                {
                    source.conditional |= ConditionalType.CONDTAKEN;
                }
            }

            lock (nodeLock)
            {
                if (!target.IncomingNeighboursSet.Contains(edgePair.Item1))
                {
                    target.IncomingNeighboursSet.Add(edgePair.Item1);
                }
            }

            lock (edgeLock)
            {
                _edgeDict.Add(edgePair, e);
                EdgeList.Add(edgePair);
                edgeObjList.Add(e);
            }

        }

        /// <summary>
        /// Record an exception in the instruented process
        /// </summary>
        /// <param name="thistag">The exception tag</param>
        public void handle_exception_tag(TAG thistag)
        {
            if (thistag.InstrumentationState == eCodeInstrumentation.eInstrumentedCode)
            {
                run_faulting_BB(thistag);

                TotalInstructions += thistag.insCount;
            }

            else if (thistag.InstrumentationState == eCodeInstrumentation.eUninstrumentedCode) //call to (uninstrumented) external library
            {
                if (ProtoLastVertID == 0)
                {
                    return;
                }

                //find caller,external vertids if old + add node to graph if new
                Console.WriteLine("[rgat]WARNING: Exception handler in uninstrumented module reached\n." +
                    "I have no idea if this code will handle it; Let me know when you reach the other side...");
                if (!RunExternal(thistag.blockaddr, 1, out Tuple<uint, uint>? resultPair))
                {
                    Console.WriteLine($"\tSecondary error - couldn't deal with extern address 0x{thistag.blockaddr:X}");
                }
            }
            else
            {
                Console.WriteLine("[rgat]Error: Bad jump tag while handling exception");
                Debug.Assert(false);
            }
        }


        /// <summary>
        /// Handle an event in the traced graph
        /// </summary>
        /// <param name="thistag">The event tag</param>
        /// <param name="skipFirstEdge">If we are expecting this and have already recorded the edge that leads to this</param> //messy
        public void handle_tag(TAG thistag, bool skipFirstEdge = false)
        {
            if (thistag.InstrumentationState == eCodeInstrumentation.eInstrumentedCode)
            {
                //Console.WriteLine($"Processing instrumented tag blockaddr 0x{thistag.blockaddr:X} [BLOCKID: {thistag.blockID}] inscount {thistag.insCount}");

                addBlockToGraph(thistag.blockID, 1, !skipFirstEdge);
            }

            else if (thistag.InstrumentationState == eCodeInstrumentation.eUninstrumentedCode)
            {
                //if (ProtoLastVertID == 0) return;

                //find caller,external vertids if old + add node to graph if new
                if (RunExternal(thistag.blockaddr, 1, out Tuple<uint, uint>? resultPair)) //todo skipfirstedge
                {
                    ProcessIncomingCallArguments(); //todo - does this ever achieve anything here?
                }
            }
            else
            {
                Console.WriteLine($"[rgat]WARNING: Handle_tag dead code assert at block 0x{thistag.blockaddr:X}");
                Debug.Assert(false);
            }


        }

        /// <summary>
        /// Arguments have been recorded for an API call which we haven't consolidated yet
        /// </summary>
        public bool HasPendingArguments => _unprocessedCallArguments.Any();

        private readonly object edgeLock = new object();

        //node id pairs to edge data
        private readonly Dictionary<Tuple<uint, uint>, EdgeData> _edgeDict = new Dictionary<Tuple<uint, uint>, EdgeData>();

        /// <summary>
        /// Ordered list of executing edges
        /// </summary>
        private readonly List<Tuple<uint, uint>> EdgeList = new List<Tuple<uint, uint>>();
        /// <summary>
        /// How many edges have been recorded
        /// </summary>
        public int EdgeCount => EdgeList.Count;

        /// <summary>
        /// Store of edge data
        /// </summary>

        public List<EdgeData> edgeObjList = new List<EdgeData>();

        /// <summary>
        /// light-touch list of blocks for filling in edges without locking disassembly data
        /// </summary>
        public List<Tuple<uint, uint>?> BlocksFirstLastNodeList = new List<Tuple<uint, uint>?>();


        private readonly object highlightsLock = new object();
        private readonly object nodeLock = new object();

        /// <summary>
        /// List of all graph nodes. The node Index is an index into this
        /// </summary>
        public List<NodeData> NodeList = new List<NodeData>();

        /// <summary>
        /// Does a node index exist
        /// </summary>
        /// <param name="idx">index</param>
        /// <returns>it exists</returns>
        public bool node_exists(uint idx) => NodeList.Count > idx;

        /// <summary>
        /// how many nodes exist
        /// </summary>
        public int NodeCount => NodeList.Count;


        /// <summary>
        /// Record the execution of an instruction on the graph
        /// </summary>
        /// <param name="instruction">The instruction to record</param>
        /// <param name="blockID">The basic block the instruction is in</param>
        /// <param name="repeats">How many times this instruction was executed this time</param>
        /// <returns>A node index for the created node</returns>
        public uint handle_new_instruction(InstructionData instruction, uint blockID, ulong repeats)
        {

            NodeData thisnode = new NodeData();
            uint targVertID = (uint)NodeCount;
            thisnode.Index = targVertID;
            thisnode.ins = instruction;
            thisnode.conditional = thisnode.ins.conditional ? ConditionalType.ISCONDITIONAL : ConditionalType.NOTCONDITIONAL;
            thisnode.address = instruction.Address;
            thisnode.BlockID = blockID;
            thisnode.parentIdx = ProtoLastVertID;
            thisnode.SetExecutionCount(repeats);
            thisnode.GlobalModuleID = instruction.GlobalModNum;
            thisnode.HasSymbol = instruction.hasSymbol;

            Debug.Assert(!node_exists(targVertID));
            InsertNode(targVertID, thisnode);

            lock (TraceData.DisassemblyData.InstructionsLock)
            {
                instruction.AddThreadVert(ThreadID, targVertID);
            }

            //lastVertID = targVertID;
            return targVertID;
        }


        /// <summary>
        /// Record execution of an instrution that is already on the graph
        /// </summary>
        /// <param name="targVertID">Instruction node ID</param>
        /// <param name="repeats">How many times it executed</param>
        public void handle_previous_instruction(uint targVertID, ulong repeats)
        {
            NodeData? prevInstruction = GetNode(targVertID);

            Debug.Assert(prevInstruction is not null);
            prevInstruction.IncreaseExecutionCount(repeats);
        }


        /// <summary>
        /// Add a new basic block to the graph
        /// </summary>
        /// <param name="blockID">Block ID</param>
        /// <param name="repeats">How many times it executed</param>
        /// <param name="recordEdge">Does the edge need recording</param>
        /// <param name="setLastID">Should the tail be set as the last executed node</param>
        /// <param name="customPreviousVert">Add a custom node to set as the last executed node</param>
        public void addBlockToGraph(uint blockID, ulong repeats, bool recordEdge = true, bool setLastID = true, uint? customPreviousVert = null)
        {
            List<InstructionData>? block = TraceData.DisassemblyData.getDisassemblyBlock(blockID);
            Debug.Assert(block is not null);
            int numInstructions = block.Count;

            if (GlobalConfig.Settings.Logs.BulkLogging)
            {
                Logging.RecordLogEvent(
                    $"Adding block {blockID}:0x{block[0].Address:X} to graph with {numInstructions} ins. LastVID:{ProtoLastVertID}, lastlastvid:{ProtoLastLastVertID}",
                    trace: this.TraceData,
                    graph: this,
                    filter: Logging.LogFilterType.BulkDebugLogFile);
            }

            TotalInstructions += ((ulong)numInstructions * repeats);

            uint firstVert = 0;
            //Console.WriteLine($"addBlockLineToGraph adding block addr 0x{block[0].address:X} with {block.Count} instructions");
            for (int instructionIndex = 0; instructionIndex < numInstructions; ++instructionIndex)
            {
                InstructionData instruction = block[instructionIndex];
                //Console.WriteLine($"\t{blockID}:InsIdx{instructionIndex} -> '{instruction.ins_text}'");
                //start possible #ifdef DEBUG  candidate
                if (lastNodeType != eEdgeNodeType.eFIRST_IN_THREAD)
                {
                    if (!node_exists(ProtoLastVertID))
                    {
                        //had an odd error here where it returned false with idx 0 and node list size 1. can only assume race condition?
                        Console.WriteLine($"\t\t[rgat]ERROR: RunBB- Last vert {ProtoLastVertID} not found. Node list size is: {NodeList.Count}");
                        Debug.Assert(false);
                    }
                }
                //end possible  #ifdef DEBUG candidate


                //target vert already on this threads graph?
                bool alreadyExecuted = set_target_instruction(instruction);
                if (!alreadyExecuted)
                {
                    targVertID = handle_new_instruction(instruction, blockID, repeats);
                    // Console.WriteLine($"\t\tins addr 0x{instruction.address:X} {instruction.ins_text} is new, handled as new. targid => {targVertID}");
                }
                else
                {
                    // Console.WriteLine($"\t\tins addr 0x{instruction.address:X} {instruction.ins_text} exists [targVID => {targVertID}], handling as existing");
                    handle_previous_instruction(targVertID, repeats);
                }

                if (instructionIndex == 0)
                {
                    firstVert = targVertID;
                }

                AddEdge_LastToTargetVert(alreadyExecuted, instructionIndex, (recordEdge || instructionIndex > 0) ? repeats : 0);

                //setup conditions for next instruction
                switch (instruction.itype)
                {
                    case eNodeType.eInsCall:
                        lastNodeType = eEdgeNodeType.eNodeCall;
                        break;

                    case eNodeType.eInsJump:
                        lastNodeType = eEdgeNodeType.eNodeJump;
                        break;

                    case eNodeType.eInsReturn:
                        lastNodeType = eEdgeNodeType.eNodeReturn;
                        break;

                    default:
                        lastNodeType = eEdgeNodeType.eNodeNonFlow;
                        break;
                }

                if (setLastID)
                {
                    ProtoLastLastVertID = ProtoLastVertID;
                    ProtoLastVertID = targVertID;
                    // Console.WriteLine($"\t\t\t New LastVID:{ProtoLastVertID}, lastlastvid:{ProtoLastLastVertID}");
                }
            }


            lock (edgeLock)
            {
                while (BlocksFirstLastNodeList.Count <= (int)blockID)
                {
                    BlocksFirstLastNodeList.Add(null);
                }
                if (BlocksFirstLastNodeList[(int)blockID] == null)
                {
                    BlocksFirstLastNodeList[(int)blockID] = new Tuple<uint, uint>(firstVert, ProtoLastVertID);

                }
            }

            //Console.WriteLine($"Thread {ThreadID} draw block from nidx {firstVert} -to- {lastVertID}");
        }

        /*
        void handle_loop_contents();

		int getAnimDataSize() { return savedAnimationData.Count; }
		List<ANIMATIONENTRY>* getSavedAnimData() { return &savedAnimationData; }
		
		*/

        //list of all external nodes
        private readonly List<uint> externalNodeList = new List<uint>();
        /// <summary>
        /// Number of external nodes
        /// </summary>
        public int ExternalNodesCount => externalNodeList.Count;
        /// <summary>
        /// Thread safe list of external node indexes
        /// </summary>
        /// <returns>Array of external node indexes</returns>
        public uint[] copyExternalNodeList()
        {
            lock (nodeLock)
            {
                return externalNodeList.ToArray();
            }
        }

        //list of all internal nodes with symbols. Unused.
        private readonly List<uint> internalNodeList = new List<uint>();

        /// <summary>
        /// Get a NodeData object by index
        /// </summary>
        /// <param name="index">Index of the node</param>
        /// <returns>The node data or null if a bad index</returns>
        public NodeData? GetNode(uint index)
        {
            if (index >= NodeList.Count)
            {
                return null;
            }

            NodeData n = NodeList[(int)index];
            return n;

        }

        private bool LoadEdges(JArray EdgeArray)
        {
            foreach (JArray entry in EdgeArray.Children())
            {
                uint source = entry[0].ToObject<uint>();
                uint target = entry[1].ToObject<uint>();
                NodeData? srcNode = GetNode(source);
                NodeData? targNode = GetNode(target);

                if (srcNode is null || targNode is null)
                {
                    return false;
                }

                EdgeData edge = new EdgeData(serialised: entry, index: EdgeList.Count, sourceType: srcNode.VertType());
                //todo: edge count?
                AddEdge(edge, srcNode, targNode);
            }
            return true;
        }


        /// <summary>
        /// Store a processed trace data entry from instrumentation for replay
        /// </summary>
        /// <param name="entry">The ANIMATIONENTRY value</param>
        public void PushAnimUpdate(ANIMATIONENTRY entry)
        {
            //Console.WriteLine($"Pushed anim update with block addr {entry.blockAddr} id {entry.blockID}");
            lock (AnimDataLock)
            {
                SavedAnimationData.Add(entry);
            }
            LastUpdated = DateTime.Now;
        }

        /// <summary>
        /// When an animation entry was last added
        /// </summary>
        public DateTime LastUpdated { get; private set; } = DateTime.Now;
        private readonly object AnimDataLock = new object();

        /// <summary>
        /// A list of trace entries which can be replayed
        /// </summary>
        public List<ANIMATIONENTRY> SavedAnimationData = new List<ANIMATIONENTRY>();
        private readonly List<uint> ExceptionNodeIndexes = new List<uint>();

        /// <summary>
        /// The module the thread was located in, usually the argument passed to CreateThread (or the linux equivalent)
        /// </summary>
        public string StartModuleName { get; private set; } = "";

        private void AssignModulePath()
        {
            bool found = ProcessData.FindContainingModule(StartAddress, out int? exeModuleID);
            if (!found || exeModuleID >= ProcessData.LoadedModulePaths.Count)
            {
                return;
            }

            StartModuleName = System.IO.Path.GetFileName(ProcessData.LoadedModulePaths[exeModuleID!.Value]);

            if (StartModuleName.Length > UI.MAX_MODULE_PATH_LENGTH)
            {
                StartModuleName = ".." + StartModuleName.Substring(StartModuleName.Length - UI.MAX_MODULE_PATH_LENGTH, UI.MAX_MODULE_PATH_LENGTH);
            }
        }


        /// <summary>
        /// Serialise this thread to JSON for writing to disk
        /// </summary>
        /// <returns>The JObject of the thread</returns>
        public JObject Serialise()
        {
            JObject result = new JObject();
            result.Add("ThreadID", ThreadID);
            result.Add("StartAddress", StartAddress);

            lock (nodeLock)
            {
                JArray nodesArray = new JArray();
                NodeList.ForEach(node => nodesArray.Add(node.Serialise()));
                result.Add("Nodes", nodesArray);
            }

            lock (edgeLock)
            {
                JArray edgeArray = new JArray();
                EdgeList.ForEach(edgetuple => edgeArray.Add(_edgeDict[edgetuple].Serialise(edgetuple.Item1, edgetuple.Item2)));
                result.Add("Edges", edgeArray);

                JArray blockBounds = new JArray();
                for (var i = 0; i < BlocksFirstLastNodeList.Count; i++)
                {
                    var blocktuple = BlocksFirstLastNodeList[i];
                    if (blocktuple == null)
                    {
                        var block = ProcessData.BasicBlocksList[i];
                        Debug.Assert(block is not null);
                        block.Item2[0].GetThreadVert(ThreadID, out uint startVert);
                        block.Item2[^1].GetThreadVert(ThreadID, out uint endVert);
                        blockBounds.Add(startVert);
                        blockBounds.Add(endVert);
                    }
                    else
                    {
                        blockBounds.Add(blocktuple.Item1);
                        blockBounds.Add(blocktuple.Item2);
                    }
                }
                result.Add("BlockBounds", blockBounds);
            }

            lock (highlightsLock)
            {
                JArray exceptNodeArray = new JArray();
                exceptionSet.ForEach(exc_node_idx => exceptNodeArray.Add(exc_node_idx));
                result.Add("Exceptions", exceptNodeArray);
            }

            result.Add("Module", exeModuleID);

            //todo - lock?
            JArray externCalls = new JArray();
            foreach (APICALLDATA ecd in SymbolCallRecords)
            {
                JArray callArgsEntry = new JArray();
                callArgsEntry.Add(ecd.edgeIdx.Item1);
                callArgsEntry.Add(ecd.edgeIdx.Item2);

                JArray argsArray = new JArray();
                foreach (var arg in ecd.argList)
                {
                    JArray ecdEntryArgs = new JArray();
                    ecdEntryArgs.Add(arg.Item1);
                    ecdEntryArgs.Add(arg.Item2);
                    argsArray.Add(ecdEntryArgs);
                }
                callArgsEntry.Add(argsArray);
                externCalls.Add(callArgsEntry);
            }
            result.Add("ExternCalls", externCalls);

            result.Add("TotalInstructions", TotalInstructions);
            result.Add("ConstructedTime", ConstructedTime);

            JArray replayDataArr = new JArray();
            lock (AnimDataLock)
            {
                foreach (ANIMATIONENTRY repentry in SavedAnimationData)
                {
                    JArray replayItem = new JArray();
                    replayItem.Add(repentry.entryType);
                    replayItem.Add(repentry.blockAddr);
                    replayItem.Add(repentry.blockID);
                    replayItem.Add(repentry.count);
                    replayItem.Add(repentry.targetAddr);
                    replayItem.Add(repentry.targetID);

                    JArray edgeCounts = new JArray();
                    if (repentry.edgeCounts != null)
                    {
                        foreach (var targCount in repentry.edgeCounts) //todo actually use blockID
                        {
                            edgeCounts.Add(targCount.Item1);
                            edgeCounts.Add(targCount.Item2);
                        }
                    }
                    replayItem.Add(edgeCounts);

                    replayDataArr.Add(replayItem);
                }
            }
            result.Add("ReplayData", replayDataArr);


            return result;
        }


        /// <summary>
        /// Restore a thread ProtoGraph from a JObject
        /// </summary>
        /// <param name="graphData">The serialised ProtoGraph JObject</param>
        /// <param name="processinfo">The processdata associated with the thread</param>
        /// <returns>The deserialised ProtoGraph</returns>
        public bool Deserialise(JObject graphData, ProcessRecord processinfo)
        {
            if (!graphData.TryGetValue("Nodes", out JToken? jNodes) || jNodes.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid Nodes in trace");
                return false;
            }
            JArray NodesArray = (JArray)jNodes;
            if (!LoadNodes(NodesArray, processinfo))
            {
                Console.WriteLine("[rgat]ERROR: Failed to load nodes");
                return false;
            }

            if (!graphData.TryGetValue("Edges", out JToken? jEdges) || jEdges.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid Edges in trace");
                return false;
            }

            JArray EdgeArray = (JArray)jEdges;
            if (!LoadEdges(EdgeArray))
            {
                Console.WriteLine("[rgat]ERROR: Failed to load edges");
                return false;
            }

            if (!graphData.TryGetValue("BlockBounds", out JToken? blockbounds) || blockbounds.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid BlockBounds array in trace");
                return false;
            }

            BlocksFirstLastNodeList = new List<Tuple<uint, uint>?>();
            JArray blockBoundsArray = (JArray)blockbounds;
            for (int i = 0; i < blockBoundsArray.Count; i += 2)
            {
                Tuple<uint, uint> blockFirstLast = new Tuple<uint, uint>(blockBoundsArray[i].ToObject<uint>(), blockBoundsArray[i + 1].ToObject<uint>());
                BlocksFirstLastNodeList.Add(blockFirstLast);
                //Debug.Assert((int)blockFirstLast.Item1 <= (int)blockFirstLast.Item2); //todo this may be needed still
            }


            if (!graphData.TryGetValue("Exceptions", out JToken? jExcepts) || jEdges.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid Exceptions in trace");
                return false;
            }
            JArray ExceptionArray = (JArray)jExcepts;
            if (!LoadExceptions(ExceptionArray))
            {
                Console.WriteLine("[rgat]ERROR: Failed to load Exceptions");
                return false;
            }

            if (!graphData.TryGetValue("ExternCalls", out JToken? jExternCalls) || jExternCalls.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid ExternCalls in trace");
                return false;
            }
            JArray ExternCallsArray = (JArray)jExternCalls;
            if (!LoadCallData(ExternCallsArray))
            {
                Console.WriteLine("[rgat]ERROR: Failed to load ExternCalls");
                return false;
            }

            if (!graphData.TryGetValue("ReplayData", out JToken? jReplayData) || jExternCalls.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid ReplayData in trace");
                return false;
            }
            JArray ReplayDataArray = (JArray)jReplayData;
            if (!LoadAnimationData(ReplayDataArray))
            {
                Console.WriteLine("[rgat]ERROR: Failed to load ReplayData");
                return false;
            }

            if (!LoadStats(graphData))
            {
                Logging.RecordLogEvent("ERROR: Failed to load graph stats", Logging.LogFilterType.TextError);
                return false;
            }
            return true;
        }


        /*
         todo - pointless copying these, can access directly
        gets latest count entries in order of most recent first
        */
        /// <summary>
        /// Get recent animation entries for rendering by the visualiser bar
        /// </summary>
        /// <param name="count"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public int GetRecentAnimationEntries(int count, out List<ANIMATIONENTRY> result)
        {
            result = new List<ANIMATIONENTRY>();
            int sz = Math.Min(count, SavedAnimationData.Count - 1);
            int index = SavedAnimationData.Count - 1;
            for (var i = 0; i < sz; i++)
            {
                result.Add(SavedAnimationData[index - i]);
            }
            return index;
        }


        /// <summary>
        /// Get the list of thread animation entries
        /// </summary>
        /// <returns>The original list of entries</returns>
        public List<ANIMATIONENTRY> GetSavedAnimationData() => SavedAnimationData;

        /// <summary>
        /// The API calls made by the thread
        /// </summary>
        public List<APICALLDATA> SymbolCallRecords = new List<APICALLDATA>();

        /// <summary>
        /// A count of the total number of instrumented instructions (including repeats) executed in the thread
        /// </summary>
        public ulong TotalInstructions { get; set; } = 0;

        /// <summary>
        /// The module ID of the thread
        /// </summary>
        public int exeModuleID = -1;


        //important state variables!
        private uint targVertID = 0; //new vert we are creating

        //temp debug setup for breakpointing
        /*
        uint _internalTargVertID = 0;
        public uint targVertID
        {
            get { return _internalTargVertID; }
            set
            {
                _internalTargVertID = value;
            }
        }*/

        private uint _pplvid = 0;

        /// <summary>
        /// The index of the last added node
        /// </summary>
        public uint ProtoLastVertID
        {
            get { return _pplvid; }
            set
            {
                _pplvid = value;
            }
        }

        /// <summary>
        /// The index of the node before the last added node
        /// </summary>
        public uint ProtoLastLastVertID = 0;
        private eEdgeNodeType lastNodeType = eEdgeNodeType.eFIRST_IN_THREAD;

        /// <summary>
        /// Exec count of the busiest block in the graph
        /// </summary>
        public ulong BusiestBlockExecCount = 0;
        private readonly List<string> loggedCalls = new List<string>();

        /// <summary>
        /// number of times an external function has been called. used to Dictionary arguments to calls
        /// </summary>
        public Dictionary<uint, ulong> externFuncCallCounter = new Dictionary<uint, ulong>();
        private readonly List<uint> exceptionSet = new List<uint>();

        /// <summary>
        /// Get all exception event nodes
        /// </summary>
        /// <returns>List of node indexes</returns>
        public uint[] GetExceptionNodes()
        {
            lock (highlightsLock)
            {
                return exceptionSet.ToArray();
            }
        }

        /// <summary>
        /// Is this thread terminated
        /// </summary>
        public bool Terminated { get; private set; } = false;

        /// <summary>
        /// Is this thread in a low-instrumentation busy area
        /// </summary>
        public bool PerformingUnchainedExecution = false;


        /// <summary>
        /// Check if this thread meets the thread requirements of a test
        /// </summary>
        /// <param name="requirements">REQUIREMENTS_LIST</param>
        /// <returns>REQUIREMENT_TEST_RESULTS</returns>
        public Testing.REQUIREMENT_TEST_RESULTS MeetsTestRequirements(REQUIREMENTS_LIST requirements)
        {
            REQUIREMENT_TEST_RESULTS results = new REQUIREMENT_TEST_RESULTS();

            foreach (Testing.TestRequirement req in requirements.value)
            {
                string? error = null;
                bool passed = false;
                string? compareValueString = "";
                switch (req.Name)
                {
                    case "EdgeCount":
                        passed = req.Compare(EdgeList.Count, out error);
                        compareValueString = $"{EdgeList.Count}";
                        break;
                    case "UniqueExceptionCount":
                        passed = req.Compare(exceptionSet.Count, out error);
                        compareValueString = $"{exceptionSet.Count}";
                        break;
                    case "NodeCount":
                        passed = req.Compare(NodeList.Count, out error);
                        compareValueString = $"{NodeList.Count}";
                        break;
                    case "ExternalNodeCount":
                        passed = req.Compare(externalNodeList.Count, out error);
                        compareValueString = $"{externalNodeList.Count}";
                        break;
                    case "InstructionExecs":
                        passed = req.Compare(TotalInstructions, out error);
                        compareValueString = $"{TotalInstructions}";
                        break;
                    case "Edges":
                        JArray? expectedEdgeArr = req.ExpectedValue?.ToObject<JArray>();
                        passed = expectedEdgeArr != null && ValidateEdgeTestList(expectedEdgeArr, out compareValueString);
                        break;
                    default:
                        compareValueString = "[?]";
                        error = "Bad Thread Test Condition: " + req.Name;
                        break;
                }

                TestResultCommentary comment = new TestResultCommentary(req)
                {
                    comparedValueString = compareValueString,
                    result = passed ? eTestState.Passed : eTestState.Failed
                };

                if (passed)
                {
                    results.Passed.Add(comment);
                }
                else
                {
                    results.Failed.Add(comment);
                    if (error != null)
                    {
                        results.Errors.Add(new Tuple<TestRequirement, string>(req, error));
                        Logging.RecordLogEvent(error, Logging.LogFilterType.TextError);
                    }
                }
            }
            return results;
        }

        private bool ValidateEdgeTestList(JArray testedges, out string failedComparison)
        {
            foreach (JToken testedge in testedges)
            {
                if (testedge.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent($"Bad object in 'Edges' list of test case: {testedge}", Logging.LogFilterType.TextError);
                    failedComparison = "Bad edge test object";
                    return false;
                }
                JObject? edgeTestObj = testedge.ToObject<JObject>();

                if (edgeTestObj is null)
                {
                    failedComparison = "Bad edge test object";
                    return false;
                }

                if (!edgeTestObj.TryGetValue("Source", out JToken? srcTok) || srcTok.Type != JTokenType.Integer ||
                    !edgeTestObj.TryGetValue("Target", out JToken? targTok) || targTok.Type != JTokenType.Integer)
                {
                    Logging.RecordLogEvent($"'Edges' test values require int Source and Target values: {testedge}", Logging.LogFilterType.TextError);
                    failedComparison = "Bad Test";
                    return false;
                }

                uint src = srcTok.ToObject<uint>();
                uint targ = targTok.ToObject<uint>();
                Tuple<uint, uint> edgeTuple = new Tuple<uint, uint>(src, targ);
                if (!EdgeExists(edgeTuple))
                {
                    //pass a 0 count to assert the edge does not exist
                    if (!GetTestEdgeCount(edgeTestObj, out ulong count) || count != 0)
                    {
                        failedComparison = $"Edge {src},{targ} exists";
                        return false;
                    }
                }

                //listing the edge without the count => just assert the edge exists
                if (GetTestEdgeCount(edgeTestObj, out ulong requiredExecCount))
                {
                    EdgeData edge = GetEdge(edgeTuple);

                    //just assume we want equals. could do a condition if anyone cares.
                    if (edge.ExecutionCount != requiredExecCount)
                    {
                        failedComparison = $"Edge {src},{targ} executed {edge.ExecutionCount} times (!= {requiredExecCount}) ";
                        return false;
                    }
                }
            }

            failedComparison = "";
            return true;
        }

        private bool GetTestEdgeCount(JObject edgeObj, out ulong count)
        {
            if (edgeObj.TryGetValue("Count", out JToken? countTok))
            {
                if (countTok.Type != JTokenType.Integer)
                {
                    count = 0;
                    Logging.RecordLogEvent($"EdgeTestObject Count must be integer, not {countTok.Type}", Logging.LogFilterType.TextError);
                    return false;
                }
                count = countTok.ToObject<ulong>();
                return true;
            }
            count = 0;
            return false;
        }


    }
}
