using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using rgat.Testing;
using rgat.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
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
        eUninstrumentedCode = 1,
        /// <summary>
        /// The instruction couldn't be looked up
        /// </summary>
        eInvalid = 2
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
        public bool HeatSolvingComplete { get; private set; } = false;

        /// <summary>
        /// Used by the heat solver to mark heat ranking as complete
        /// </summary>
        public void MarkHeatSolvingComplete() => HeatSolvingComplete = true;

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






        private bool SetTargetInstruction(InstructionData instruction)
        {
            //ReadLock(piddata->disassemblyRWLock);
            lock (TraceData.DisassemblyData.InstructionsLock) //todo this can be a read lock
            {
                //Logging.WriteConsole($"Checking if instruction 0x{instruction.address:X}, dbgid {instruction.DebugID} mut {instruction.mutationIndex} executed");
                if (instruction.GetThreadVert(ThreadID, out uint targetID))
                {
                    targVertID = targetID;
                    return true;
                }
                return false;
            }
        }


        private void AddEdge_LastToTargetVert(bool alreadyExecuted, int instructionIndex, ulong repeats)
        {
            Tuple<uint, uint> edgeIDPair = new Tuple<uint, uint>(ProtoLastVertID, targVertID);

            //Logging.WriteConsole($"\tAddEdge_LastToTargetVert {ProtoLastVertID} -> {targVertID} repeats {repeats}");

            if (EdgeExists(edgeIDPair, out EdgeData? edgeObj))
            {
                edgeObj!.IncreaseExecutionCount(repeats);
                //cout << "repeated internal edge from " << lastVertID << "->" << targVertID << endl;
                return;
            }

            if (lastNodeType == EdgeNodeType.eFIRST_IN_THREAD)
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
                    newEdge.edgeClass = alreadyExecuted ? EdgeNodeType.eEdgeOld : EdgeNodeType.eEdgeNew;
                }
                else
                {
                    if (alreadyExecuted)
                    {
                        newEdge.edgeClass = EdgeNodeType.eEdgeOld;
                    }
                    else
                    {
                        switch (lastNodeType)
                        {
                            case EdgeNodeType.eNodeReturn:
                                newEdge.edgeClass = EdgeNodeType.eEdgeReturn;
                                break;
                            case EdgeNodeType.eNodeException:
                                newEdge.edgeClass = EdgeNodeType.eEdgeException;
                                break;
                            case EdgeNodeType.eNodeCall:
                                newEdge.edgeClass = EdgeNodeType.eEdgeCall;
                                break;
                            default:
                                newEdge.edgeClass = EdgeNodeType.eEdgeNew;
                                break;
                        }
                    }
                }

                //Logging.WriteConsole($"Creating edge src{sourcenode.index} -> targvid{targVertID}");
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
                Logging.LogFilterType.Alert);


            ROUTINE_STRUCT? foundExtern = null;
            List<InstructionData>? block = ProcessData.GetDisassemblyBlock(tag.blockID, ref foundExtern, tag.blockaddr);
            if (block == null)
            {
                Logging.RecordLogEvent($"Faulting Block {tag.blockID} 0x{tag.blockaddr:X} not recorded in disassembly");
                Debug.Assert(false);
                if (foundExtern != null)
                {
                    Logging.WriteConsole($"[rgat]Warning - faulting block was in uninstrumented code at 0x{tag.blockaddr}");
                }
                else
                {
                    Logging.WriteConsole($"[rgat]Warning - failed to get disassembly for faulting block at 0x{tag.blockaddr}");
                }

                return;
            }

            for (int instructionIndex = 0; (ulong)instructionIndex <= tag.insCount; ++instructionIndex)
            {
                InstructionData instruction = block[instructionIndex];

                if (lastNodeType != EdgeNodeType.eFIRST_IN_THREAD && !NodeExists(ProtoLastVertID))
                {
                    Logging.WriteConsole("\t\t[rgat]ERROR: RunBB- Last vert {lastVertID} not found");
                    Debug.Assert(false);
                }

                //target vert already on this threads graph?
                bool alreadyExecuted = SetTargetInstruction(instruction);
                if (!alreadyExecuted)
                {
                    targVertID = HandleNewInstruction(instruction, tag.blockID, 1);
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
                    lastNodeType = EdgeNodeType.eNodeNonFlow;
                }
                else
                {
                    lastNodeType = EdgeNodeType.eNodeException;
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
                Logging.WriteConsole("Warning: Code executed which is not in image or an external module. Possibly a buffer.");
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
                    List<Tuple<uint, uint>> callervec = new List<Tuple<uint, uint>>
                    {
                        //cout << "add extern addr " << std::hex<<  targaddr << " mod " << std::dec << modnum << endl;
                        resultPair
                    };
                    thisbb.ThreadCallers.Add(ThreadID, callervec);
                }
                else
                {
                    callers.Add(resultPair);
                }
            }

            int module = thisbb.Module;

            //make new external/library call node
            NodeData newTargNode = new NodeData
            {
                GlobalModuleID = module,
                IsExternal = true,
                address = targaddr,
                Index = targVertID,
                parentIdx = ProtoLastVertID
            };
            newTargNode.SetExecutionCount(repeats);
            newTargNode.BlockID = uint.MaxValue;
            newTargNode.HasSymbol = true;


            InsertNode(newTargNode);

            TraceData.RecordAPICall(newTargNode, this, 0, repeats);


            NodeData? sourceNode = GetNode(ProtoLastVertID);
            Debug.Assert(sourceNode is not null);
            NodeData? targetNode = GetNode(targVertID);
            Debug.Assert(targetNode is not null);

            EdgeData newEdge = new EdgeData(index: EdgeList.Count, sourceType: sourceNode.VertType(), execCount: repeats)
            {
                edgeClass = EdgeNodeType.eEdgeLib
            };
            AddEdge(newEdge, sourceNode, targetNode);
            //cout << "added external edge from " << lastVertID << "->" << targVertID << endl;
            lastNodeType = EdgeNodeType.eNodeExternal;
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
                    Logging.RecordLogEvent($"Breakdown of API argument processing between {_unprocessedCallArguments[cacheI - 1].argstring} and {_unprocessedCallArguments[cacheI].argstring}Check the 'M' and 'E' fields of any recently added API wrapper in the instrumentation tool", Logging.LogFilterType.Error);

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
                    //Logging.WriteConsole($"\n---\tProcessIncomingCallArguments - Failed to find *any* callers of 0x{arg.calledAddress:X} in current thread. Leaving until it appears.\n---");
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
                    if (functionNode.callRecordsIndexs.Count < GlobalConfig.Settings.Tracing.ArgStorageMax)
                    {
                        if (functionNode.callRecordsIndexs.Count >= (GlobalConfig.Settings.Tracing.ArgStorageMax - 1))
                            Logging.RecordLogEvent($"Warning, dropping future args to extern 0x{currentTarget:X} because the storage limit is {GlobalConfig.Settings.Tracing.ArgStorageMax}");

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
                        //RecordSystemInteraction(functionNode, callRecord);

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
                    //This happens a lot
                    //Logging.WriteConsole($"\tProcessIncomingCallArguments - Failed to find *specific* caller of 0x{arg.calledAddress:X} [{sym}] in current thread. Leaving until it appears.");
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
            //return; //todo restore this 
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
            if (GlobalConfig.BulkLog) Logging.RecordLogEvent($"lookup_extern_func_calls looking for 0x{called_function_address:x}", Logging.LogFilterType.BulkDebugLogFile);
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

        private void InsertNode(NodeData node)
        {
            lock (nodeLock)
            {
                Debug.Assert((NodeList.Count == 0) || (node.Index == NodeList[^1].Index + 1));

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
        public bool EdgeExists(Tuple<uint, uint> edge, out EdgeData? edged) //todo this is a bottleneck
        {
            lock (edgeLock)
            {
                return _edgeDict.TryGetValue(edge, out edged) && edged is not null;
            }
        }



        /// <summary>
        /// Get readonly references to the nodepair edge list and full edgelist
        /// </summary>
        /// <returns>The list of nodepairs</returns>
        public void GetEdgelistSpans(out Span<Tuple<uint, uint>> nodesList, out Span<EdgeData> edgesList)
        {
            Stopwatch st = new Stopwatch();
            st.Start();
            lock (edgeLock)
            {
                st.Stop();
                if (st.ElapsedMilliseconds > 60)
                    Console.WriteLine($"GetEdgelistSpans edgelog was contended for {st.ElapsedMilliseconds}ms ");
                st.Restart();
                nodesList = CollectionsMarshal.AsSpan(EdgeList);
                edgesList = CollectionsMarshal.AsSpan(edgeObjList);
            }
            st.Stop();
            if (st.ElapsedMilliseconds > 60)
                Console.WriteLine($"GetEdgelistSpans marshalling took {st.ElapsedMilliseconds}ms ");
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
        /// Get a readonly span of the nodedata list
        /// </summary>
        /// <returns>The list of NodeData</returns>
        public ReadOnlySpan<NodeData> GetNodeObjlistSpan()
        {
            lock (nodeLock)
            {
                return CollectionsMarshal.AsSpan<NodeData>(NodeList);
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
                newEdge.edgeClass = EdgeNodeType.eEdgeLib;
            }
            else if (sourceNode.ins!.itype == NodeType.eInsCall)
            {
                newEdge.edgeClass = EdgeNodeType.eEdgeCall;
            }
            else if (sourceNode.ins.itype == NodeType.eInsReturn)
            {
                newEdge.edgeClass = EdgeNodeType.eEdgeReturn;
            }
            else
            {
                newEdge.edgeClass = EdgeNodeType.eEdgeOld;
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
            //Logging.WriteConsole($"\t\tAddEdge {source.index} -> {target.index}");

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

            lock (edgeLock)
            {
                lock (nodeLock)
                {
                    if (!target.IncomingNeighboursSet.Contains(edgePair.Item1))
                    {
                        target.IncomingNeighboursSet.Add(edgePair.Item1);
                    }
                    if (!source.OutgoingNeighboursSet.Contains(edgePair.Item2))
                    {
                        source.OutgoingNeighboursSet.Add(edgePair.Item2);
                    }
                }

                _edgeDict.Add(edgePair, e);
                EdgeList.Add(edgePair);
                edgeObjList.Add(e);
            }

        }

        /// <summary>
        /// Record an exception in the instruented process
        /// </summary>
        /// <param name="thistag">The exception tag</param>
        public void HandleExceptionTag(TAG thistag)
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
                Logging.WriteConsole("[rgat]WARNING: Exception handler in uninstrumented module reached\n." +
                    "I have no idea if this code will handle it; Let me know when you reach the other side...");
                if (!RunExternal(thistag.blockaddr, 1, out Tuple<uint, uint>? resultPair))
                {
                    Logging.WriteConsole($"\tSecondary error - couldn't deal with extern address 0x{thistag.blockaddr:X}");
                }
            }
            else
            {
                Logging.WriteConsole("[rgat]Error: Bad jump tag while handling exception");
                Debug.Assert(false);
            }
        }


        /// <summary>
        /// Handle an event in the traced graph
        /// </summary>
        /// <param name="thistag">The event tag</param>
        /// <param name="skipFirstEdge">If we are expecting this and have already recorded the edge that leads to this</param> //messy
        public void HandleTag(TAG thistag, bool skipFirstEdge = false)
        {
            Stopwatch sw = new();
            if (thistag.InstrumentationState == eCodeInstrumentation.eInstrumentedCode)
            {
                //Logging.WriteConsole($"Processing instrumented tag blockaddr 0x{thistag.blockaddr:X} [BLOCKID: {thistag.blockID}] inscount {thistag.insCount}");
                sw.Start();
                addBlockToGraph(thistag.blockID, 1, !skipFirstEdge);
                sw.Stop();
                if (sw.ElapsedMilliseconds > 70)
                    Console.WriteLine($"HandleTag::addblock to graph took {sw.ElapsedMilliseconds} ms");
            }

            else if (thistag.InstrumentationState == eCodeInstrumentation.eUninstrumentedCode)
            {
                //if (ProtoLastVertID == 0) return;

                //find caller,external vertids if old + add node to graph if new
                sw.Start();
                if (RunExternal(thistag.blockaddr, 1, out Tuple<uint, uint>? resultPair)) //todo skipfirstedge
                {
                    sw.Stop();
                    if (sw.ElapsedMilliseconds > 60)
                        Console.WriteLine($"HandleTag::RunExternal (ret true) took {sw.ElapsedMilliseconds} ms");
                    ProcessIncomingCallArguments();
                }
                else
                {

                    sw.Stop();
                    if (sw.ElapsedMilliseconds > 40)
                        Console.WriteLine($"RunExternal (ret false) took {sw.ElapsedMilliseconds} ms");
                }
            }
            else
            {
                Logging.WriteConsole($"[rgat]WARNING: Handle_tag dead code assert at block 0x{thistag.blockaddr:X}");
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
        public bool NodeExists(uint idx) => NodeList.Count > idx;

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
        public uint HandleNewInstruction(InstructionData instruction, uint blockID, ulong repeats)
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

            Debug.Assert(!NodeExists(targVertID));

            Stopwatch st = new Stopwatch();
            st.Start();
            InsertNode(thisnode);
            st.Stop(); if (st.ElapsedMilliseconds > 100)
            {
                Console.WriteLine($"!!!!!!InsertNode nodelock is contended for {st.ElapsedMilliseconds}");
            }

            st.Restart();
            lock (TraceData.DisassemblyData.InstructionsLock)
            {
                instruction.AddThreadVert(ThreadID, targVertID);
            }
            st.Stop(); if (st.ElapsedMilliseconds > 100)
            {
                Console.WriteLine($"!!!!!!AddThreadVert InstructionsLock is contended for {st.ElapsedMilliseconds}");
            }

            //lastVertID = targVertID;
            return targVertID;
        }


        /// <summary>
        /// Record execution of an instrution that is already on the graph
        /// </summary>
        /// <param name="targVertID">Instruction node ID</param>
        /// <param name="repeats">How many times it executed</param>
        public void HandlePreviousInstruction(uint targVertID, ulong repeats)
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
            Stopwatch st = new();
            st.Start();
            List<InstructionData>? block = TraceData.DisassemblyData.getDisassemblyBlock(blockID);
            if (block is null)
            {
                if (rgatState.rgatIsExiting is false)
                {
                    Logging.RecordError($"Failed to fetch block {blockID}");
                }
                return;
            }
            Debug.Assert(block is not null);
            int numInstructions = block.Count;
            st.Stop();
            if (st.ElapsedMilliseconds > 100)
                Console.WriteLine($"abg getDisassemblyBlock took {st.ElapsedMilliseconds}");

            if (GlobalConfig.Settings.Logs.BulkLogging)
            {
                Logging.RecordLogEvent(
                    $"Adding block {blockID}:0x{block[0].Address:X} to graph with {numInstructions} ins. LastVID:{ProtoLastVertID}, lastlastvid:{ProtoLastLastVertID}",
                    trace: this.TraceData,
                    graph: this,
                    filter: Logging.LogFilterType.BulkDebugLogFile);
            }

            TotalInstructions += ((ulong)numInstructions * repeats);

            st.Start();
            uint firstVert = 0;
            //Logging.WriteConsole($"addBlockLineToGraph adding block addr 0x{block[0].address:X} with {block.Count} instructions");
            for (int instructionIndex = 0; instructionIndex < numInstructions; ++instructionIndex)
            {
                InstructionData instruction = block[instructionIndex];
                //Logging.WriteConsole($"\t{blockID}:InsIdx{instructionIndex} -> '{instruction.ins_text}'");
                //start possible #ifdef DEBUG  candidate
                if (lastNodeType != EdgeNodeType.eFIRST_IN_THREAD)
                {
                    if (!NodeExists(ProtoLastVertID))
                    {
                        //had an odd error here where it returned false with idx 0 and node list size 1. can only assume race condition?
                        Logging.WriteConsole($"\t\t[rgat]ERROR: RunBB- Last vert {ProtoLastVertID} not found. Node list size is: {NodeList.Count}");
                        Debug.Assert(false);
                    }
                }
                //end possible  #ifdef DEBUG candidate


                //target vert already on this threads graph?
                bool alreadyExecuted = SetTargetInstruction(instruction);
                if (!alreadyExecuted)
                {
                    targVertID = HandleNewInstruction(instruction, blockID, repeats);
                    // Logging.WriteConsole($"\t\tins addr 0x{instruction.address:X} {instruction.ins_text} is new, handled as new. targid => {targVertID}");
                }
                else
                {
                    // Logging.WriteConsole($"\t\tins addr 0x{instruction.address:X} {instruction.ins_text} exists [targVID => {targVertID}], handling as existing");
                    HandlePreviousInstruction(targVertID, repeats);
                }

                if (instructionIndex == 0)
                {
                    firstVert = targVertID;
                }

                AddEdge_LastToTargetVert(alreadyExecuted, instructionIndex, (recordEdge || instructionIndex > 0) ? repeats : 0);

                //setup conditions for next instruction
                switch (instruction.itype)
                {
                    case NodeType.eInsCall:
                        lastNodeType = EdgeNodeType.eNodeCall;
                        break;

                    case NodeType.eInsJump:
                        lastNodeType = EdgeNodeType.eNodeJump;
                        break;

                    case NodeType.eInsReturn:
                        lastNodeType = EdgeNodeType.eNodeReturn;
                        break;

                    default:
                        lastNodeType = EdgeNodeType.eNodeNonFlow;
                        break;
                }

                if (setLastID)
                {
                    ProtoLastLastVertID = ProtoLastVertID;
                    ProtoLastVertID = targVertID;
                    // Logging.WriteConsole($"\t\t\t New LastVID:{ProtoLastVertID}, lastlastvid:{ProtoLastLastVertID}");
                }
            }


            st.Stop();
            if (st.ElapsedMilliseconds > 100)
                Console.WriteLine($"abg loop took {st.ElapsedMilliseconds} over {numInstructions} instructions");


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

            //Logging.WriteConsole($"Thread {ThreadID} draw block from nidx {firstVert} -to- {lastVertID}");
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
        public ReadOnlySpan<uint> copyExternalNodeList()
        {
            lock (nodeLock)
            {
                return CollectionsMarshal.AsSpan<uint>(externalNodeList);
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



        /// <summary>
        /// Store a processed trace data entry from instrumentation for replay
        /// </summary>
        /// <param name="entry">The ANIMATIONENTRY value</param>
        public void PushAnimUpdate(ANIMATIONENTRY entry)
        {
            //Logging.WriteConsole($"Pushed anim update with block addr {entry.blockAddr} id {entry.blockID}");
            lock (AnimDataLock)
            {
                SavedAnimationData.Add(entry);
                UpdateCount += 1;
            }
            LastUpdated = DateTime.Now;
        }

        /// <summary>
        /// Delete animation entries
        /// This only activates on a live trace if a certain number are stored
        /// </summary>
        /// <param name="maxIndex">index to delete up to</param>
        /// <returns>New adjusted index</returns>
        public int PurgeAnimationEntries(int maxIndex)
        {
            if (this.Terminated is false && SavedAnimationData.Count < 500) return maxIndex;
            lock (AnimDataLock)
            {
                if (animDataRefs == 0)
                {
                    SavedAnimationData.RemoveRange(0, maxIndex);
                    return 0;
                }
                return maxIndex;
            }
        }


        /// <summary>
        /// When an animation entry was last added
        /// </summary>
        public DateTime LastUpdated { get; private set; } = DateTime.Now;
        private readonly object AnimDataLock = new object();

        /// <summary>
        /// Store how many updates have been recorded (even if animation data is being discarded)
        /// </summary>
        public ulong UpdateCount { get; private set; } = 0;

        /// <summary>
        /// Store how many updates have been recorded (even if animation data is being discarded)
        /// </summary>
        public int StoredUpdateCount => SavedAnimationData.Count;

        /// <summary>
        /// A list of trace entries which can be replayed
        /// </summary>
        private List<ANIMATIONENTRY> SavedAnimationData = new List<ANIMATIONENTRY>();
        private readonly List<uint> ExceptionNodeIndexes = new List<uint>();

        /// <summary>
        /// Reported as the thread start by PIn
        /// </summary>
        public string StartModuleName { get; private set; } = "";

        /// <summary>
        /// The first instrumented module, or if failing that the start module
        /// </summary>
        public string FirstInstrumentedModuleName
        {
            get
            {
                if (_firstInstrumentedModuleName.Length > 0) return _firstInstrumentedModuleName;
                if (NodeCount > 0)
                {
                    try
                    {
                        int firstNodeModule = NodeList[0].GlobalModuleID;
                        if (ProcessData.LoadedModulePaths.Count > firstNodeModule)
                        {
                            string modulePath = ProcessData.LoadedModulePaths[firstNodeModule];
                            _firstInstrumentedModuleName = System.IO.Path.GetFileName(modulePath);
                            return _firstInstrumentedModuleName;
                        }
                    }
                    catch { }
                }
                return StartModuleName;
            }
        }


        private string _firstInstrumentedModuleName = "";



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
        public void Serialise(JsonWriter writer, rgatState.SERIALISE_PROGRESS progress)
        {
            JObject metadata = new JObject {
                { "Field", "Thread"},
                { "ThreadID", ThreadID },
                { "StartAddress", StartAddress },
                { "TotalInstructions", this.TotalInstructions },
                { "ConstructedTime", ConstructedTime },
                { "UpdateCount", UpdateCount}
            };

            metadata.WriteTo(writer);

            progress.SectionsTotal = 6;
            progress.SectionsComplete = 0;

            //Section 1: nodes
            progress.SectionName = $"Thread {ThreadID} nodes";
            progress.SectionProgress = 0;
            lock (nodeLock)
            {
                JObject nodesMeta = new JObject();
                nodesMeta.Add("Field", "Nodes");
                nodesMeta.Add("Count", NodeList.Count);
                nodesMeta.WriteTo(writer);
                for (var i = 0; i < NodeList.Count; i++)
                {
                    NodeList[i].Serialise(writer);
                    progress.SectionProgress = (float)i / (float)NodeList.Count;
                    if (progress.Cancelled) return;
                }
            }
            progress.SectionsComplete += 1;

            //Section 2: edges
            progress.SectionName = $"Thread {ThreadID} edges";
            progress.SectionProgress = 0;
            lock (edgeLock)
            {

                JObject edgesMeta = new JObject();
                edgesMeta.Add("Field", "Edges");
                edgesMeta.Add("Count", EdgeList.Count);
                edgesMeta.Add("ItemSize", 4);
                edgesMeta.WriteTo(writer);

                writer.WriteStartArray();
                for (var ei = 0; ei < EdgeList.Count; ei++)
                {
                    edgeObjList[ei].Serialise(EdgeList[ei], writer);
                    progress.SectionProgress = (float)ei / (float)EdgeList.Count;
                    if (progress.Cancelled) return;
                }
                writer.WriteEndArray();

                progress.SectionsComplete += 1;


                //Section 3: blocks
                progress.SectionName = $"Thread {ThreadID} blocks";
                progress.SectionProgress = 0;
                JObject blocksMeta = new JObject();
                blocksMeta.Add("Field", "Blocks");
                blocksMeta.Add("Count", BlocksFirstLastNodeList.Count);
                blocksMeta.WriteTo(writer);

                writer.WriteStartArray();
                for (var i = 0; i < BlocksFirstLastNodeList.Count; i++)
                {
                    var blocktuple = BlocksFirstLastNodeList[i];
                    if (blocktuple == null)
                    {
                        var block = ProcessData.BasicBlocksList[i];
                        Debug.Assert(block is not null);
                        block.Item2[0].GetThreadVert(ThreadID, out uint startVert);
                        block.Item2[^1].GetThreadVert(ThreadID, out uint endVert);
                        writer.WriteValue(startVert);
                        writer.WriteValue(endVert);
                    }
                    else
                    {
                        writer.WriteValue(blocktuple.Item1);
                        writer.WriteValue(blocktuple.Item2);
                    }
                    progress.SectionProgress = (float)i / (float)BlocksFirstLastNodeList.Count;
                    if (progress.Cancelled) return;
                }
                writer.WriteEndArray();

            }

            progress.SectionsComplete += 1;

            //Section 4: exceptions
            progress.SectionName = $"Thread {ThreadID} exceptions";
            progress.SectionProgress = 0;
            lock (highlightsLock)
            {
                JObject exceptionsMeta = new JObject();
                exceptionsMeta.Add("Field", "Exceptions");
                exceptionsMeta.Add("Count", exceptionSet.Count);
                exceptionsMeta.WriteTo(writer);
                JArray exceptNodeArray;
                exceptNodeArray = JArray.FromObject(exceptionSet);
                exceptNodeArray.WriteTo(writer);
            }

            progress.SectionsComplete += 1;


            //Section 5: externs
            progress.SectionName = $"Thread {ThreadID} API calls";
            progress.SectionProgress = 0;

            JObject symCallsMeta = new JObject();
            symCallsMeta.Add("Field", "SymbolCalls");
            symCallsMeta.Add("Count", SymbolCallRecords.Count);
            symCallsMeta.WriteTo(writer);

            writer.WriteStartArray();
            for (var i = 0; i < SymbolCallRecords.Count; i++)
            {
                APICALLDATA ecd = SymbolCallRecords[i];

                writer.WriteValue(ecd.edgeIdx.Item1); // caller idx
                writer.WriteValue(ecd.edgeIdx.Item2); // api node idx
                writer.WriteValue(ecd.argList.Count); // arg count

                foreach (var arg in ecd.argList)
                {
                    writer.WriteValue(arg.Item1); // arg idx
                    writer.WriteValue(arg.Item2); // arg
                }
                progress.SectionProgress = (float)i / (float)SymbolCallRecords.Count;
                if (progress.Cancelled) return;
            }
            writer.WriteEndArray();

            progress.SectionsComplete += 1;


            //Section 6: replay
            progress.SectionName = $"Thread {ThreadID} repaly data";
            lock (AnimDataLock)
            {
                JObject replayMeta = new JObject();
                replayMeta.Add("Field", "ReplayData");
                replayMeta.Add("Disabled", this.TraceData.DiscardTraceData);

                int eventsToSave = this.TraceData.DiscardTraceData ? 0 : SavedAnimationData.Count;
                if (eventsToSave > 0 && GlobalConfig.Settings.Tracing.ReplayStorageMax is not null)
                {
                    eventsToSave = Math.Min(SavedAnimationData.Count, GlobalConfig.Settings.Tracing.ReplayStorageMax.Value);
                }
                replayMeta.Add("Count", eventsToSave);
                replayMeta.WriteTo(writer);

                writer.WriteStartArray();
                for (int i = 0; i < eventsToSave; i++)
                {
                    ANIMATIONENTRY repentry = SavedAnimationData[i];

                    writer.WriteValue(repentry.entryType);
                    writer.WriteValue(repentry.blockAddr);
                    writer.WriteValue(repentry.blockID);
                    writer.WriteValue(repentry.count);
                    writer.WriteValue(repentry.targetAddr);
                    writer.WriteValue(repentry.targetID);

                    if (repentry.edgeCounts is null)
                    {
                        writer.WriteValue(0);
                    }
                    else
                    {
                        writer.WriteValue(repentry.edgeCounts.Count);
                        foreach (var targCount in repentry.edgeCounts) //todo actually use blockID
                        {
                            writer.WriteValue(targCount.Item1);
                            writer.WriteValue(targCount.Item2);
                        }
                    }
                    progress.SectionProgress = (float)i / (float)SavedAnimationData.Count;
                    if (progress.Cancelled) return;
                }
                writer.WriteEndArray();
            }
            progress.SectionsComplete += 1;
        }


        /// <summary>
        /// Restore a thread ProtoGraph from a JObject
        /// </summary>
        /// <param name="metadata">Section metadata prelude JSON</param>
        /// <param name="jsnReader">A JsonReader for the trace file</param>
        /// <param name="serializer">A JsonSerializer</param>
        /// <param name="processinfo">The processdata associated with the thread</param>
        /// <param name="progress">Serialisation progress object</param>
        /// <returns>The deserialised ProtoGraph</returns>
        public bool Deserialise(JObject metadata, JsonReader jsnReader, JsonSerializer serializer, ProcessRecord processinfo, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionsTotal = 7;
            progress.SectionsComplete = 0;
            progress.SectionName = $"Thread {this.ThreadID} Stats";
            if (LoadStats(metadata) is false)
            {
                Logging.RecordLogEvent("Failed to load graph stats");
                return false;
            }

            progress.SectionsComplete += 1;
            if (LoadNodes(jsnReader, serializer, progress) is false)
            {
                Logging.WriteConsole("Failed to find valid Nodes in trace");
                return false;
            }

            progress.SectionsComplete += 1;
            if (LoadEdges(jsnReader, serializer, progress) is false)
            {
                Logging.WriteConsole("Failed to find valid Nodes in trace");
                return false;
            }

            progress.SectionsComplete += 1;
            if (LoadBlocks(jsnReader, serializer, progress) is false)
            {
                Logging.WriteConsole("Failed to load block bounds");
                return false;
            }

            progress.SectionsComplete += 1;
            if (LoadExceptions(jsnReader, serializer, progress) is false)
            {
                Logging.WriteConsole("Failed to load Exceptions");
                return false;
            }

            progress.SectionsComplete += 1;
            if (LoadCallData(jsnReader, serializer, progress) is false)
            {
                Logging.WriteConsole("Failed to load ExternCalls");
                return false;
            }


            progress.SectionsComplete += 1;
            progress.SectionName = $"Thread {this.ThreadID} Replay Data";
            if (LoadReplayData(jsnReader, serializer, progress) is false)
            {
                Logging.WriteConsole("Failed to load ReplayData");
                return false;
            }

            progress.SectionsComplete += 1;
            return true;
        }



        private bool LoadStats(JObject graphData)
        {

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

            if (!graphData.TryGetValue("UpdateCount", out JToken? updateCountTok) || updateCountTok.Type != JTokenType.Integer)
            {
                return false;
            }
            UpdateCount = updateCountTok.ToObject<ulong>();

            return true;
        }


        bool LoadNodes(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = $"Thread {this.ThreadID} Nodes";
            progress.SectionProgress = 0;

            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Nodes", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No node metadata in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("Count", out JToken? countTok) || countTok.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid node count in graph");
                return false;
            }
            int nodeCount = countTok.ToObject<int>();

            NodeList.Capacity = nodeCount;
            for (var i = 0; i < nodeCount; i++)
            {
                if (jsnReader.Read() is false || jsnReader.TokenType is not JsonToken.StartArray)
                {
                    Logging.RecordLogEvent("Bad node entry");
                    return false;
                }
                JArray? nodeitem = serializer.Deserialize<JArray>(jsnReader);
                if (nodeitem is null)
                {
                    Logging.RecordLogEvent("Bad node entry");
                    return false;
                }

                NodeData n = new NodeData();
                n.Deserialise(nodeitem, processinfo: this.ProcessData);
                InsertNode(n);
                progress.SectionProgress = (float)i / (float)nodeCount;
                if (progress.Cancelled) return false;
            }


            return true;
        }


        private bool LoadEdges(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = $"Thread {this.ThreadID} Edges";
            progress.SectionProgress = 0;

            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Edges", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No edge metadata in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("Count", out JToken? countTok) || countTok.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid edge count in graph");
                return false;
            }

            int edgeCount = countTok.ToObject<int>();
            EdgeList.Capacity = edgeCount;


            if (!mdObj.TryGetValue("ItemSize", out JToken? sizetok) || sizetok.Type != JTokenType.Integer || sizetok.ToObject<int>() is not 4)
            {
                Logging.RecordLogEvent("Edge array didn't have an item size of 4");
                return false;
            }

            jsnReader.Read();
            if (jsnReader.TokenType is not JsonToken.StartArray) return false;
            jsnReader.Read();

            for (var i = 0; i < edgeCount; i++)
            {
                uint source = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                uint target = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                NodeData? srcNode = GetNode(source);
                NodeData? targNode = GetNode(target);

                if (srcNode is null || targNode is null)
                {
                    return false;
                }

                EdgeNodeType edgeType = serializer.Deserialize<EdgeNodeType>(jsnReader); jsnReader.Read();
                ulong execCount = serializer.Deserialize<ulong>(jsnReader); jsnReader.Read();

                EdgeData edge = new EdgeData(edgeType, execCount, index: EdgeList.Count, sourceType: srcNode.VertType());
                AddEdge(edge, srcNode, targNode);
                progress.SectionProgress = (float)i / (float)edgeCount;
                if (progress.Cancelled) return false;
            }

            return jsnReader.TokenType is JsonToken.EndArray;
        }


        private bool LoadBlocks(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = $"Thread {this.ThreadID} Blocks";
            progress.SectionProgress = 0;
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Blocks", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No Blocks metadata in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("Count", out JToken? countTok) || countTok.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid Blocks count in graph");
                return false;
            }

            int blockCount = countTok.ToObject<int>();
            BlocksFirstLastNodeList.Capacity = blockCount;

            jsnReader.Read();
            if (jsnReader.TokenType is not JsonToken.StartArray) return false;
            jsnReader.Read();

            for (var i = 0; i < blockCount; i++)
            {
                uint firstNode = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                uint lastNode = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                BlocksFirstLastNodeList.Add(new Tuple<uint, uint>(firstNode, lastNode));
                progress.SectionProgress = (float)i / (float)blockCount;
                if (progress.Cancelled) return false;
            }

            return jsnReader.TokenType is JsonToken.EndArray;
        }


        private bool LoadExceptions(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = $"Thread {this.ThreadID} Exceptions";
            progress.SectionProgress = 0;
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Exceptions", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No Exceptions data in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("Count", out JToken? countTok) || countTok.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid node count in graph");
                return false;
            }

            int excCount = countTok.ToObject<int>();
            exceptionSet.Capacity = excCount;

            jsnReader.Read();
            if (jsnReader.TokenType is not JsonToken.StartArray) return false;
            jsnReader.Read();

            for (var i = 0; i < excCount; i++)
            {
                uint nodeIdx = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                exceptionSet.Add(nodeIdx);
                progress.SectionProgress = (float)i / (float)excCount;
                if (progress.Cancelled) return false;
            }

            return jsnReader.TokenType is JsonToken.EndArray;
        }


        private bool LoadCallData(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = $"Thread {this.ThreadID} API Calls";
            progress.SectionProgress = 0;
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "SymbolCalls", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No SymbolCalls metadata in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("Count", out JToken? countTok) || countTok.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid node count in graph");
                return false;
            }
            int count = countTok.ToObject<int>();

            jsnReader.Read();
            if (jsnReader.TokenType is not JsonToken.StartArray) return false;
            jsnReader.Read();

            SymbolCallRecords.Capacity = count;
            for (var calli = 0; calli < count; calli++)
            {

                uint callerIdx = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                uint targetIdx = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                uint argCount = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();

                APICALLDATA symcall = new APICALLDATA()
                {
                    edgeIdx = new Tuple<uint, uint>(callerIdx, targetIdx),
                    argList = new()
                };

                for (var argi = 0; argi < argCount; argi++)
                {
                    int argIdx = serializer.Deserialize<int>(jsnReader); jsnReader.Read();
                    string? arg = serializer.Deserialize<string>(jsnReader); jsnReader.Read();
                    if (arg is not null)
                        symcall.argList.Add(new Tuple<int, string>(argIdx, arg));
                }
                SymbolCallRecords.Add(symcall);
                progress.SectionProgress = (float)calli / (float)count;
                if (progress.Cancelled) return false;
            }

            return jsnReader.TokenType is JsonToken.EndArray;
        }


        private bool LoadReplayData(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = $"Thread {this.ThreadID} Replay Data";
            progress.SectionProgress = 0;
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "ReplayData", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No ReplayData metadata in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("Count", out JToken? countTok) || countTok.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid node count in graph");
                return false;
            }
            int entryCount = countTok.ToObject<int>();


            jsnReader.Read();
            if (jsnReader.TokenType is not JsonToken.StartArray) return false;
            jsnReader.Read();

            bool skipPastSkipped = false;
            if (GlobalConfig.Settings.Tracing.ReplayStorageMax is not null)
            {
                skipPastSkipped = true;
                if (GlobalConfig.Settings.Tracing.ReplayStorageMax.Value < entryCount)
                {
                    entryCount = GlobalConfig.Settings.Tracing.ReplayStorageMax.Value;
                    skipPastSkipped = true;
                }
            }
            SavedAnimationData.Capacity = entryCount;

            for (var entryi = 0; entryi < entryCount; entryi++)
            {
                ANIMATIONENTRY entry = new ANIMATIONENTRY();
                entry.entryType = serializer.Deserialize<eTraceUpdateType>(jsnReader); jsnReader.Read();
                entry.blockAddr = serializer.Deserialize<ulong>(jsnReader); jsnReader.Read();
                entry.blockID = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                entry.count = serializer.Deserialize<ulong>(jsnReader); jsnReader.Read();
                entry.targetAddr = serializer.Deserialize<ulong>(jsnReader); jsnReader.Read();
                entry.targetID = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();

                int edgeRepCount = serializer.Deserialize<int>(jsnReader); jsnReader.Read();
                if (edgeRepCount is 0)
                {
                    entry.edgeCounts = null;
                }
                else
                {
                    entry.edgeCounts = new();
                    for (var repi = 0; repi < edgeRepCount; repi++)
                    {
                        uint blockID = serializer.Deserialize<uint>(jsnReader); jsnReader.Read();
                        ulong repeatCount = serializer.Deserialize<ulong>(jsnReader); jsnReader.Read();
                        entry.edgeCounts.Add(new Tuple<uint, ulong>(blockID, repeatCount));
                    }
                }
                SavedAnimationData.Add(entry);
                progress.SectionProgress = (float)entryi / (float)entryCount;
                if (progress.Cancelled) return false;
            }

            if (skipPastSkipped is true)
            {
                progress.SectionName = $"Thread {this.ThreadID} Skipping Excess Replay Data";
                while (jsnReader.TokenType is not JsonToken.EndArray && jsnReader.Read()) { }
            }

            return jsnReader.TokenType is JsonToken.EndArray;
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
            lock (AnimDataLock)
            {
                int sz = Math.Min(count, SavedAnimationData.Count - 1);
                int index = SavedAnimationData.Count - 1;
                for (var i = 0; i < sz; i++)
                {
                    result.Add(SavedAnimationData[index - i]);
                }
                return index;
            }
        }


        /// <summary>
        /// Get the list of thread animation entries
        /// ReleaseSavedAnimationDataReference() must be called after being finished with the list
        /// </summary>
        /// <returns>The original list of entries</returns>
        public List<ANIMATIONENTRY> GetSavedAnimationDataReference()
        {
            lock (AnimDataLock)
            {
                animDataRefs += 1;
                return SavedAnimationData;
            }
        }


        /// <summary>
        /// Release a reference to the saved animation data
        /// At 0 it will be eligible for deletion operations
        /// </summary>
        public void ReleaseSavedAnimationDataReference()
        {
            lock (AnimDataLock)
            {
                animDataRefs -= 1;
                if (_requireAnimationDataPurge && animDataRefs == 0)
                {
                    SavedAnimationData.Clear();
                    _requireAnimationDataPurge = false;
                }
            }
        }
        private int animDataRefs = 0;
        private bool _requireAnimationDataPurge = false;

        /// <summary>
        /// Clear the trace replay data, or mark it for clearing when the locks are released
        /// </summary>
        public void PurgeSavedAnimationData()
        {
            lock (AnimDataLock)
            {
                if (animDataRefs == 0)
                {
                    SavedAnimationData.Clear();
                }
                else
                {
                    _requireAnimationDataPurge = true;
                }
            }
        }

        /// <summary>
        /// The API calls made by the thread
        /// </summary>
        public List<APICALLDATA> SymbolCallRecords = new List<APICALLDATA>();

        /// <summary>
        /// A count of the total number of instrumented instructions (including repeats) executed in the thread
        /// </summary>
        public ulong TotalInstructions { get; set; } = 0;


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
        private EdgeNodeType lastNodeType = EdgeNodeType.eFIRST_IN_THREAD;

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
        /// Number of exceptions in this thread
        /// </summary>
        public int ExceptionCount => exceptionSet.Count;

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
                        Logging.RecordLogEvent(error, Logging.LogFilterType.Error);
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
                    Logging.RecordLogEvent($"Bad object in 'Edges' list of test case: {testedge}", Logging.LogFilterType.Error);
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
                    Logging.RecordLogEvent($"'Edges' test values require int Source and Target values: {testedge}", Logging.LogFilterType.Error);
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

        private static bool GetTestEdgeCount(JObject edgeObj, out ulong count)
        {
            if (edgeObj.TryGetValue("Count", out JToken? countTok))
            {
                if (countTok.Type != JTokenType.Integer)
                {
                    count = 0;
                    Logging.RecordLogEvent($"EdgeTestObject Count must be integer, not {countTok.Type}", Logging.LogFilterType.Error);
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
