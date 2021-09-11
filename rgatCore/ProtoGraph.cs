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
    public struct APICALLDATA
    {
        public Tuple<uint, uint> edgeIdx;
        /// <summary>
        /// a list of (index, value) tuples
        /// where 
        ///     index: the position of the argument in the function prototype
        ///     value: a string representation of the argument value
        /// </summary>
        public List<Tuple<int, string>> argList;
    };

    public struct ROUTINE_STRUCT
    {
        public List<InstructionData> inslist;
        public int globalmodnum;
        //list of threads that call this BB
        //inside is list of the threads verts that call it
        //it can exist multiple times on map so caller.this is listed
        //  tid     
        public Dictionary<uint, List<Tuple<uint, uint>>> thread_callers;
        public bool hasSymbol;
    };

    public struct TAG
    {
        //come from trace
        public ulong blockaddr;
        public uint blockID;
        public ulong insCount;
        //used internally
        public eCodeInstrumentation jumpModifier;
        public ROUTINE_STRUCT? foundExtern;
    };
    public enum eTraceUpdateType { eAnimExecTag, eAnimUnchained, eAnimUnchainedResults, eAnimReinstrument, eAnimRepExec, eAnimExecException };
    public enum eLoopState { eNoLoop, eBuildingLoop, eLoopProgress };
    public enum eCodeInstrumentation { eInstrumentedCode = 0, eUninstrumentedCode = 1 };

    public struct ANIMATIONENTRY
    {
        public eTraceUpdateType entryType;
        public ulong blockAddr;
        public uint blockID;
        public List<Tuple<uint, ulong>> edgeCounts;
        public ulong count;
        public ulong targetAddr;
        public uint targetID;
    };


    public class ProtoGraph
    {

        public ProtoGraph(TraceRecord runrecord, uint threadID, bool terminated = false)
        {
            TraceData = runrecord;
            ProcessData = runrecord.DisassemblyData;
            ThreadID = threadID;
            Terminated = terminated;
        }

        public uint ThreadID = 0;

        public TraceIngestWorker TraceReader { set; get; } = null;
        public ThreadTraceProcessingThread TraceProcessor { set; get; } = null;
        public ProcessRecord ProcessData { private set; get; } = null;
        public TraceRecord TraceData { private set; get; } = null;
        public DateTime ConstructedTime { private set; get; } = DateTime.Now;

        public bool HeatSolvingComplete = false;

        public List<InteractionTarget> SystemInteractions = new List<InteractionTarget>();
        public Dictionary<ulong, InteractionTarget> Interacted_FileHandles = new Dictionary<ulong, InteractionTarget>();
        public Dictionary<string, InteractionTarget> Interacted_FilePaths = new Dictionary<string, InteractionTarget>();
        public Dictionary<string, InteractionTarget> Interacted_RegistryPaths = new Dictionary<string, InteractionTarget>();
        public Dictionary<string, InteractionTarget> Interacted_NetworkPaths = new Dictionary<string, InteractionTarget>();
        public Dictionary<string, InteractionTarget> Interacted_Mutexes = new Dictionary<string, InteractionTarget>();
 


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

                InsertNode(n.index, n);
            }

            return true;
        }


        private bool LoadExceptions(JArray exceptionsArray)
        {
            foreach (JToken entry in exceptionsArray)
            {
                if (entry.Type != JTokenType.Integer) return false;
                ExceptionNodeIndexes.Add(entry.ToObject<uint>());
            }
            return true;
        }

        private bool LoadStats(JObject graphData)
        {
            if (!graphData.TryGetValue("Module", out JToken jModID) || jModID.Type != JTokenType.Integer)
            {
                return false;
            }
            exeModuleID = jModID.ToObject<int>();

            if (exeModuleID >= TraceData.DisassemblyData.LoadedModuleBounds.Count) return false;
            moduleBase = TraceData.DisassemblyData.LoadedModuleBounds[exeModuleID].Item1;

            if (!graphData.TryGetValue("TotalInstructions", out JToken jTotal) || jTotal.Type != JTokenType.Integer)
            {
                return false;
            }
            TotalInstructions = jTotal.ToObject<ulong>();

            if (!graphData.TryGetValue("ConstructedTime", out JToken timeTok) || timeTok.Type != JTokenType.Date)
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
                if (animFields.Count != 7) return false;
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
                        return false;

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

            if (EdgeExists(edgeIDPair, out EdgeData edgeObj))
            {
                edgeObj.IncreaseExecutionCount(repeats);
                //cout << "repeated internal edge from " << lastVertID << "->" << targVertID << endl;
                return;
            }

            if (lastNodeType == eEdgeNodeType.eFIRST_IN_THREAD) return;



            NodeData sourcenode = safe_get_node(ProtoLastVertID);
            if (sourcenode.ThunkCaller) return;

            //make API calls leaf nodes, rather than part of the chain
            //if (sourcenode.IsExternal)
            //    sourcenode = safe_get_node(ProtoLastLastVertID);

            if (!EdgeExists(new Tuple<uint, uint>(sourcenode.index, targVertID)))
            {
                EdgeData newEdge = new EdgeData(index: EdgeList.Count, sourceType: lastNodeType, execCount: repeats);

                if (instructionIndex > 0)
                    newEdge.edgeClass = alreadyExecuted ? eEdgeNodeType.eEdgeOld : eEdgeNodeType.eEdgeNew;
                else
                {
                    if (alreadyExecuted)
                        newEdge.edgeClass = eEdgeNodeType.eEdgeOld;
                    else
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

                //Console.WriteLine($"Creating edge src{sourcenode.index} -> targvid{targVertID}");
                AddEdge(newEdge, sourcenode, safe_get_node(targVertID));
            }


        }

        public bool HasRecentStep { private set; get; } = false;
        public ulong RecentStepAddr { private set; get; }
        public ulong NextStepAddr { private set; get; }
        public void ClearRecentStep() => HasRecentStep = false;
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
            List<InstructionData> block = ProcessData.getDisassemblyBlock(tag.blockID, ref foundExtern, tag.blockaddr);
            if (block == null)
            {
                Logging.RecordLogEvent($"Faulting Block {tag.blockID} 0x{tag.blockaddr:X} not recorded in disassembly");
                Debug.Assert(false);
                if (foundExtern != null)
                    Console.WriteLine($"[rgat]Warning - faulting block was in uninstrumented code at 0x{tag.blockaddr}");
                else
                    Console.WriteLine($"[rgat]Warning - failed to get disassembly for faulting block at 0x{tag.blockaddr}");

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
                    targVertID = handle_new_instruction(instruction, tag.blockID, 1);
                else
                    safe_get_node(targVertID).IncreaseExecutionCount(1);
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
                        if (!exceptionSet.Contains(targVertID)) exceptionSet.Add(targVertID);
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
            NodeData lastNode = safe_get_node(ProtoLastVertID);
            if (lastNode.IsExternal) { resultPair = null; return false; }
            Debug.Assert(lastNode.ins.numbytes > 0);

            //if caller is also external then we are not interested in this (does this happen?)
            if (ProcessData.ModuleTraceStates[lastNode.GlobalModuleID] == eCodeInstrumentation.eUninstrumentedCode) { resultPair = null; return false; }


            int modnum = ProcessData.FindContainingModule(targaddr);
            if (modnum == -1)
            {
                //this happens in test binary: -mems-
                Console.WriteLine("Warning: Code executed which is not in image or an external module. Possibly a buffer.");
                resultPair = null;
                return false;
            }

            ProcessData.get_extern_at_address(targaddr, modnum, out ROUTINE_STRUCT thisbb);


            //see if caller already called this
            //if so, get the destination node so we can just increase edge weight
            if (thisbb.thread_callers.TryGetValue(ThreadID, out List<Tuple<uint, uint>> callers))
            {
                //piddata->getExternCallerReadLock();
                foreach (var caller in callers)
                {
                    if (caller.Item1 != ProtoLastVertID) continue;

                    //piddata->dropExternCallerReadLock();

                    //this instruction in this thread has already called it
                    //cout << "repeated external edge from " << lastVertID << "->" << targVertID << endl;

                    targVertID = caller.Item2;

                    EdgeData e = GetEdge(caller.Item1, caller.Item2);
                    if (e != null)
                    {
                        e.IncreaseExecutionCount(repeats);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Bad edge in RunExternal: {caller.Item1},{caller.Item2} in thread {this.ThreadID}, module {this.ProcessData.GetModulePath(modnum)}");
                    }

                    NodeData targNode = safe_get_node(targVertID);
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
            targVertID = get_num_nodes();
            resultPair = new Tuple<uint, uint>(ProtoLastVertID, targVertID);

            lock (ProcessData.ExternCallerLock)
            {
                //has this thread executed this basic block before?
                if (callers == null)
                {
                    List<Tuple<uint, uint>> callervec = new List<Tuple<uint, uint>>();
                    //cout << "add extern addr " << std::hex<<  targaddr << " mod " << std::dec << modnum << endl;
                    callervec.Add(resultPair);
                    thisbb.thread_callers.Add(ThreadID, callervec);
                }
                else
                    callers.Add(resultPair);
            }

            int module = thisbb.globalmodnum;

            //make new external/library call node
            NodeData newTargNode = new NodeData();
            newTargNode.GlobalModuleID = module;
            newTargNode.IsExternal = true;
            newTargNode.address = targaddr;
            newTargNode.index = targVertID;
            newTargNode.parentIdx = ProtoLastVertID;
            newTargNode.SetExecutionCount(repeats);
            newTargNode.BlockID = uint.MaxValue;
            newTargNode.HasSymbol = true;


            InsertNode(targVertID, newTargNode);

            TraceData.RecordAPICall(newTargNode, this, 0, repeats);


            NodeData sourceNode = safe_get_node(ProtoLastVertID);
            EdgeData newEdge = new EdgeData(index: EdgeList.Count, sourceType: sourceNode.VertType(), execCount: repeats);
            newEdge.edgeClass = eEdgeNodeType.eEdgeLib;
            AddEdge(newEdge, sourceNode, safe_get_node(targVertID));
            //cout << "added external edge from " << lastVertID << "->" << targVertID << endl;
            lastNodeType = eEdgeNodeType.eNodeExternal;
            ProtoLastLastVertID = ProtoLastVertID;
            ProtoLastVertID = newTargNode.index;
            // ProtoLastLastVertID = ProtoLastVertID;
            //ProtoLastVertID = targVertID;
            return true;
        }



        public readonly object argsLock = new object();

        //call arguments are recieved out-of-order from trace tags due to tag caching. they are stored here until they can be associated with the correct node
        private List<INCOMING_CALL_ARGUMENT> _unprocessedCallArguments = new List<INCOMING_CALL_ARGUMENT>();
        struct INCOMING_CALL_ARGUMENT
        {
            public ulong sourceBlock;
            public ulong callerAddress;
            public ulong calledAddress;
            public int argIndex;
            public bool finalEntry;
            public string argstring;
            public bool isReturnVal;
        }


        void RemoveProcessedArgsFromCache(uint completeCount)
        {
            lock (argsLock)
            {
                _unprocessedCallArguments.RemoveRange(0, (int)completeCount);
            }
        }


        /*
         * Runs through the cached API call arguments and attempts to match complete
         * sets up to corresponding nodes on the graph once they have been inserted
         */
        public void ProcessIncomingCallArguments()
        {
            if (_unprocessedCallArguments.Count == 0) return;

            ulong currentSourceBlock = _unprocessedCallArguments[0].sourceBlock;
            if ((int)currentSourceBlock == -1) 
                return; //API called before instrumented code was reached
            ulong currentTarget = _unprocessedCallArguments[0].calledAddress;

            uint completecount = 0;
            int currentIndex = -1;
            int maxCacheI = _unprocessedCallArguments.Count;

            for (var cacheI = 0; cacheI < maxCacheI; cacheI++)
            {
                INCOMING_CALL_ARGUMENT arg = _unprocessedCallArguments[cacheI];
                if (arg.calledAddress != currentTarget)
                {
                    Logging.RecordLogEvent($"Breakdown of API argument processing between {_unprocessedCallArguments[cacheI-1].argstring} and {_unprocessedCallArguments[cacheI].argstring}Check the 'M' and 'E' fields of any recently added API wrapper in the instrumentation tool", Logging.LogFilterType.TextError);
                    
                    _unprocessedCallArguments.RemoveRange(0, cacheI);
                    return;
                }

                Debug.Assert(arg.sourceBlock == currentSourceBlock, "ProcessIncomingCallArguments() unexpected change of source");
                Debug.Assert(arg.argIndex > currentIndex || arg.isReturnVal, "ProcessIncomingCallArguments() unexpected change of source");
                if (BlocksFirstLastNodeList.Count <= (int)currentSourceBlock)
                    break;


                Tuple<uint, uint> blockIndexes = BlocksFirstLastNodeList[(int)currentSourceBlock];
                if (blockIndexes == null) break;

                uint callerNodeIdx = blockIndexes.Item2;
                currentIndex = arg.argIndex; //uh
                if (!arg.finalEntry) continue;


                //each API call target can have multiple nodes in a thread, so we have to get the list of 
                //every edge that has this extern as a target
                if (!lookup_extern_func_calls(arg.calledAddress, out List<Tuple<uint, uint>> threadCalls))
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

                    if (threadCalls[i].Item1 != callerNodeIdx) continue;
                    NodeData functionNode = safe_get_node(threadCalls[i].Item2);

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
                        functionNode.newArgsRecorded = true;
                    }
                    sequenceProcessed = true;
                    break;
                }

                if (!sequenceProcessed)
                {
                    NodeData targnode = safe_get_node(threadCalls[0].Item2);
                    ProcessData.GetSymbol(targnode.GlobalModuleID, arg.calledAddress, out string sym);
                    Console.WriteLine($"\tProcessIncomingCallArguments - Failed to find *specific* caller of 0x{arg.calledAddress:X} [{sym}] in current thread. Leaving until it appears.");
                    break;
                }

                //setup for next sequence of args
                if (_unprocessedCallArguments.Count <= (cacheI + 1)) break;

                currentTarget = _unprocessedCallArguments[cacheI + 1].calledAddress;
                currentSourceBlock = _unprocessedCallArguments[cacheI + 1].sourceBlock;
                currentIndex = -1;

            }

            RemoveProcessedArgsFromCache(completecount);
        }

        void RecordSystemInteraction(NodeData node, APICALLDATA APIcall)
        {
            Debug.Assert(node.IsExternal && node.HasSymbol);
            //int  moduleEnum = ProcessData.ModuleAPIReferences[node.GlobalModuleID];

            ProcessData.GetSymbol(node.GlobalModuleID, node.address, out string symbol);
            Console.WriteLine($"Node {node.index} is system interaction {node.IsExternal}");
        
        }

        /*
         * Inserts API call argument data from the trace into the cache
         * Attempts to add it to the graph if a full set of arguments is collected
         */
        //future optimisation - try to insert complete complete sequences immediately
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
                ProcessIncomingCallArguments();
        }


        private bool lookup_extern_func_calls(ulong called_function_address, out List<Tuple<uint, uint>>? callEdges)
        {
            Console.WriteLine($"lookup_extern_func_calls looking for 0x{called_function_address:x}");
            lock (ProcessData.ExternCallerLock)
            {
                if (TraceData.DisassemblyData.externdict.TryGetValue(called_function_address, out ROUTINE_STRUCT rtn))
                {
                    return rtn.thread_callers.TryGetValue(ThreadID, out callEdges);
                }
            }

            callEdges = null;
            return false;
        }




        //public void LinkBasicBlocks(List<InstructionData> source, List<InstructionData> target);

        void InsertNode(uint targVertID, NodeData node)
        {
            lock (nodeLock)
            {
                Debug.Assert((NodeList.Count == 0) || (targVertID == NodeList[^1].index + 1));

                if (node.IsExternal)
                {
                    //highlightsLock.lock () ;
                    externalNodeList.Add(node.index);
                    //highlightsLock.unlock();
                }
                else if (node.ins.hasSymbol)
                {
                    //highlightsLock.lock () ;
                    internalNodeList.Add(node.index);
                    //highlightsLock.unlock();
                }

                NodeList.Add(node);
            }
        }


        public bool EdgeExists(Tuple<uint, uint> edge)
        {
            lock (edgeLock)
            {
                return _edgeDict.ContainsKey(edge);
            }
        }

        public bool EdgeExists(Tuple<uint, uint> edge, out EdgeData? edged)
        {
            lock (edgeLock)
            {
                return _edgeDict.TryGetValue(edge, out edged);
            }
        }

        public List<Tuple<uint, uint>> GetEdgelistCopy()
        {

            lock (edgeLock)
            {
                return EdgeList.ToList();
            }
        }

        public List<EdgeData> GetEdgeObjListCopy()
        {
            lock (edgeLock)
            {
                return edgeObjList.ToList();
            }
        }

        public List<NodeData> GetNodeObjlistCopy()
        {
            lock (nodeLock)
            {
                return NodeList.ToList();
            }
        }

        public EdgeData GetEdge(uint src, uint targ)
        {
            lock (edgeLock)
            {
                if (_edgeDict.TryGetValue(new Tuple<uint, uint>(src, targ), out EdgeData result))
                {
                    return result;
                }
                return null;
            }
        }

        public EdgeData GetEdge(Tuple<uint, uint> srcTarg)
        {

            lock (edgeLock)
            {
                return _edgeDict[srcTarg];
            }
        }

        public void GetEdgeNodes(int index, out Tuple<uint, uint> srcTarg, out EdgeData e)
        {
            lock (edgeLock)
            {
                if (index < EdgeList.Count)
                {
                    srcTarg = EdgeList[index];
                    _edgeDict.TryGetValue(srcTarg, out e);
                }
                else
                {
                    srcTarg = null;
                    e = null;
                }
            }
        }

        public void AddEdge(uint SrcNodeIdx, uint TargNodeIdx, ulong execCount)
        {
            NodeData sourceNode = safe_get_node(SrcNodeIdx);
            NodeData targNode = safe_get_node(TargNodeIdx);

            EdgeData newEdge = new EdgeData(index: EdgeList.Count, sourceType: sourceNode.VertType(), execCount: execCount);

            if (targNode.IsExternal)
            {
                newEdge.edgeClass = eEdgeNodeType.eEdgeLib;
            }
            else if (sourceNode.ins.itype == eNodeType.eInsCall)
                newEdge.edgeClass = eEdgeNodeType.eEdgeCall;
            else if (sourceNode.ins.itype == eNodeType.eInsReturn)
                newEdge.edgeClass = eEdgeNodeType.eEdgeReturn;
            else
                newEdge.edgeClass = eEdgeNodeType.eEdgeOld;

            AddEdge(newEdge, sourceNode, targNode);

        }


        public void AddEdge(EdgeData e, NodeData source, NodeData target)
        {
            Tuple<uint, uint> edgePair = new Tuple<uint, uint>(source.index, target.index);
            //Console.WriteLine($"\t\tAddEdge {source.index} -> {target.index}");


            if (!source.OutgoingNeighboursSet.Contains(edgePair.Item2))
            {
                source.OutgoingNeighboursSet.Add(edgePair.Item2);
            }


            if (source.conditional != eConditionalType.NOTCONDITIONAL &&
                source.conditional != eConditionalType.CONDCOMPLETE)
            {
                if (source.ins.condDropAddress == target.address)
                {
                    if (source.ins.branchAddress == target.address)
                    {
                        source.conditional = eConditionalType.CONDCOMPLETE; //opaque predicate
                    }
                    else
                    {
                        source.conditional |= eConditionalType.CONDFELLTHROUGH;
                    }
                }
                else if (source.ins.branchAddress == target.address)
                {
                    source.conditional |= eConditionalType.CONDTAKEN;
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


        public void handle_exception_tag(TAG thistag)
        {
            if (thistag.jumpModifier == eCodeInstrumentation.eInstrumentedCode)
            {
                run_faulting_BB(thistag);

                TotalInstructions += thistag.insCount;
            }

            else if (thistag.jumpModifier == eCodeInstrumentation.eUninstrumentedCode) //call to (uninstrumented) external library
            {
                if (ProtoLastVertID == 0) return;

                //find caller,external vertids if old + add node to graph if new
                Console.WriteLine("[rgat]WARNING: Exception handler in uninstrumented module reached\n." +
                    "I have no idea if this code will handle it; Let me know when you reach the other side...");
                if (!RunExternal(thistag.blockaddr, 1, out Tuple<uint, uint> resultPair))
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


        public void handle_tag(TAG thistag, bool skipFirstEdge = false)
        {

            if (thistag.jumpModifier == eCodeInstrumentation.eInstrumentedCode)
            {
                //Console.WriteLine($"Processing instrumented tag blockaddr 0x{thistag.blockaddr:X} [BLOCKID: {thistag.blockID}] inscount {thistag.insCount}");

                addBlockToGraph(thistag.blockID, 1, !skipFirstEdge);
            }

            else if (thistag.jumpModifier == eCodeInstrumentation.eUninstrumentedCode)
            {
                //if (ProtoLastVertID == 0) return;

                //find caller,external vertids if old + add node to graph if new
                if (RunExternal(thistag.blockaddr, 1, out Tuple<uint, uint> resultPair)) //todo skipfirstedge
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

        public bool hasPendingArguments() { return _unprocessedCallArguments.Count != 0; }

        private readonly object edgeLock = new object();
        //node id pairs to edge data
        Dictionary<Tuple<uint, uint>, EdgeData> _edgeDict = new Dictionary<Tuple<uint, uint>, EdgeData>();
        //order of edge execution
        //todo - make this private, hide from view for thread safety
        public List<Tuple<uint, uint>> EdgeList = new List<Tuple<uint, uint>>();
        public List<EdgeData> edgeObjList = new List<EdgeData>();
        //light-touch list of blocks for filling in edges without locking disassembly data
        public List<Tuple<uint, uint>> BlocksFirstLastNodeList = new List<Tuple<uint, uint>>();


        private readonly object highlightsLock = new object();


        public readonly object nodeLock = new object();
        public List<NodeData> NodeList = new List<NodeData>(); //node id to node data

        public bool node_exists(uint idx) { return (NodeList.Count > idx); }
        public uint get_num_nodes() { return (uint)NodeList.Count; }
        public uint get_num_edges() { return (uint)EdgeList.Count; }
        /*
		public void acquireNodeReadLock() { getNodeReadLock(); }
		public void releaseNodeReadLock() { dropNodeReadLock(); }
                */

        public uint handle_new_instruction(InstructionData instruction, uint blockID, ulong repeats)
        {

            NodeData thisnode = new NodeData();
            uint targVertID = get_num_nodes();
            thisnode.index = targVertID;
            thisnode.ins = instruction;
            thisnode.conditional = thisnode.ins.conditional ? eConditionalType.ISCONDITIONAL : eConditionalType.NOTCONDITIONAL;
            thisnode.address = instruction.address;
            thisnode.BlockID = blockID;
            thisnode.parentIdx = ProtoLastVertID;
            thisnode.SetExecutionCount(repeats);
            thisnode.GlobalModuleID = instruction.globalmodnum;
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


        public void handle_previous_instruction(uint targVertID, ulong repeats)
        {
            safe_get_node(targVertID).IncreaseExecutionCount(repeats);
        }


        public void addBlockToGraph(uint blockID, ulong repeats, bool recordEdge = true, bool setLastID = true, uint? customPreviousVert = null)
        {
            List<InstructionData> block = TraceData.DisassemblyData.getDisassemblyBlock(blockID);
            int numInstructions = block.Count;

            if (GlobalConfig.Settings.Logs.BulkLogging)
            {
                Logging.RecordLogEvent(
                    $"Adding block {blockID}:0x{block[0].address:X} to graph with {numInstructions} ins. LastVID:{ProtoLastVertID}, lastlastvid:{ProtoLastLastVertID}",
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

                if (instructionIndex == 0) firstVert = targVertID;

                AddEdge_LastToTargetVert(alreadyExecuted, instructionIndex, (ulong)((recordEdge || instructionIndex > 0) ? repeats : 0));

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
        List<uint> externalNodeList = new List<uint>();
        public int ExternalNodesCount => externalNodeList.Count;
        public uint[] copyExternalNodeList()
        {
            return externalNodeList.ToArray();
        }

        //list of all internal nodes with symbols
        List<uint> internalNodeList = new List<uint>();
        //List<uint> copyInternalNodeList();
        /*
		//these are called a lot. make sure as efficient as possible
		EdgeData get_edge(Tuple<uint,uint> edge)
        {
			if (edgeindex >= edgeList.size()) return 0;

			getEdgeReadLock();
			EDGEMAP::iterator edgeIt = edgeDict.find(edgeList.at(edgeindex));
			dropEdgeReadLock();

			if (edgeIt != edgeDict.end())
				return &edgeIt.second;
			else
				return null;
		}
		inline edge_data * unsafe_get_edge(Tuple<uint, uint> edgePair);

		edge_data* get_edge(uint edgeindex);

		//edge_data *get_or_create_edge(node_data *source, node_data *target);

		node_data* unsafe_get_node(uint index);
		*/

        public NodeData safe_get_node(uint index)
        {
            if (index >= NodeList.Count)
                return null;

            //getNodeReadLock();
            NodeData n = NodeList[(int)index];
            //dropNodeReadLock();
            return n;

        }

        bool LoadEdges(JArray EdgeArray)
        {
            foreach (JArray entry in EdgeArray.Children())
            {
                uint source = entry[0].ToObject<uint>();
                uint target = entry[1].ToObject<uint>();
                EdgeData edge = new EdgeData(serialised: entry, index: EdgeList.Count, sourceType: safe_get_node(source).VertType());
                //todo: edge count?
                AddEdge(edge, safe_get_node(source), safe_get_node(target));
            }
            return true;
        }



        public void PushAnimUpdate(ANIMATIONENTRY entry)
        {
            //Console.WriteLine($"Pushed anim update with block addr {entry.blockAddr} id {entry.blockID}");
            lock (AnimDataLock)
            {
                SavedAnimationData.Add(entry);
            }
            LastUpdated = DateTime.Now;
        }

        public DateTime LastUpdated { get; private set; } = DateTime.Now;
        private readonly object AnimDataLock = new object();
        //animation data received from target
        public List<ANIMATIONENTRY> SavedAnimationData = new List<ANIMATIONENTRY>();

        List<uint> ExceptionNodeIndexes = new List<uint>();

        public void AssignModulePath()
        {
            exeModuleID = safe_get_node(0).GlobalModuleID;
            if (exeModuleID >= ProcessData.LoadedModulePaths.Count) return;

            string ModulePath = ProcessData.LoadedModulePaths[exeModuleID];
            moduleBase = TraceData.DisassemblyData.LoadedModuleBounds[exeModuleID].Item1;


            if (ModulePath.Length > UI.MAX_DIFF_PATH_LENGTH)
                ModulePath = ".." + ModulePath.Substring(ModulePath.Length - UI.MAX_DIFF_PATH_LENGTH, UI.MAX_DIFF_PATH_LENGTH);
        }
        /*
		public ulong BacklogOutgoing = 0;
		public ulong BacklogIncoming = 0;

		ulong get_backlog_total();
        */

        public void RecordAPIEvent()
        {

        }


        public JObject Serialise()
        {
            JObject result = new JObject();
            result.Add("ThreadID", ThreadID);

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
                        ProcessData.BasicBlocksList[i].Item2[0].GetThreadVert(ThreadID, out uint startVert);
                        ProcessData.BasicBlocksList[i].Item2[^1].GetThreadVert(ThreadID, out uint endVert);
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

        public bool Deserialise(JObject graphData, ProcessRecord processinfo)
        {
            if (!graphData.TryGetValue("Nodes", out JToken jNodes) || jNodes.Type != JTokenType.Array)
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

            if (!graphData.TryGetValue("Edges", out JToken jEdges) || jEdges.Type != JTokenType.Array)
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

            if (!graphData.TryGetValue("BlockBounds", out JToken blockbounds) || blockbounds.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid BlockBounds array in trace");
                return false;
            }

            BlocksFirstLastNodeList = new List<Tuple<uint, uint>>();
            JArray blockBoundsArray = (JArray)blockbounds;
            for (int i = 0; i < blockBoundsArray.Count; i += 2)
            {
                Tuple<uint, uint> blockFirstLast = new Tuple<uint, uint>(blockBoundsArray[i].ToObject<uint>(), blockBoundsArray[i + 1].ToObject<uint>());
                BlocksFirstLastNodeList.Add(blockFirstLast);
                Debug.Assert((int)blockFirstLast.Item1 <= (int)blockFirstLast.Item2);
            }


            if (!graphData.TryGetValue("Exceptions", out JToken jExcepts) || jEdges.Type != JTokenType.Array)
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

            if (!graphData.TryGetValue("ExternCalls", out JToken jExternCalls) || jExternCalls.Type != JTokenType.Array)
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

            if (!graphData.TryGetValue("ReplayData", out JToken jReplayData) || jExternCalls.Type != JTokenType.Array)
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


        //todo - pointless copying these, can access directly
        //gets latest count entries in order of most recent first
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

        public List<ANIMATIONENTRY> GetSavedAnimationData() => SavedAnimationData;

        /*
		bool instructions_to_nodepair(InstructionData sourceIns, InstructionData targIns, NODEPAIR &result);
		*/
        public List<APICALLDATA> SymbolCallRecords = new List<APICALLDATA>();
        public ulong TotalInstructions { get; set; } = 0;
        public int exeModuleID = -1;
        public ulong moduleBase = 0;
        public string modulePath;
        public Dictionary<ulong, uint> InternalPlaceholderFuncNames = new Dictionary<ulong, uint>();

        //public uint lastNode = 0;
        //used by heatDictionary solver
        uint finalNodeID = 0;

        //important state variables!
        public uint targVertID = 0; //new vert we are creating

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

        uint _pplvid = 0;

        public uint ProtoLastVertID
        {
            get { return _pplvid; }
            set
            {
                _pplvid = value;
            }
        }

        //public uint ProtoLastVertID = 0; //the vert that led to new instruction
        public uint ProtoLastLastVertID = 0; //the vert that led to the previous instruction

        eEdgeNodeType lastNodeType = eEdgeNodeType.eFIRST_IN_THREAD;

        public List<ulong> _edgeHeatThresholds = Enumerable.Repeat((ulong)0, 9).ToList();
        public List<ulong> _nodeHeatThresholds = Enumerable.Repeat((ulong)0, 9).ToList();

        public ulong BusiestBlockExecCount = 0;
        public eLoopState loopState = eLoopState.eNoLoop;

        List<string> loggedCalls = new List<string>();

        //number of times an external function has been called. used to Dictionary arguments to calls
        public Dictionary<uint, ulong> externFuncCallCounter = new Dictionary<uint, ulong>();

        List<uint> exceptionSet = new List<uint>();

        public uint[] GetExceptionNodes()
        {
            lock (highlightsLock)
            {
                return exceptionSet.ToArray();
            }
        }

        //void start_edgeL_iteration(EDGELIST::iterator* edgeIt, EDGELIST::iterator* edgeEnd);
        //void stop_edgeL_iteration();

        public bool Terminated { get; private set; } = false;
        public bool PerformingUnchainedExecution = false;


        public Testing.REQUIREMENT_TEST_RESULTS MeetsTestRequirements(REQUIREMENTS_LIST requirements)
        {
            REQUIREMENT_TEST_RESULTS results = new REQUIREMENT_TEST_RESULTS();

            foreach (Testing.TestRequirement req in requirements.value)
            {
                string error = null;
                bool passed = false;
                string compareValueString = "";
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
                        passed = ValidateEdgeTestList(req.ExpectedValue.ToObject<JArray>(), out compareValueString);
                        break;
                    default:
                        compareValueString = "[?]";
                        error = "Bad Thread Test Condition: " + req.Name;
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

        bool ValidateEdgeTestList(JArray testedges, out string failedComparison)
        {
            foreach (JToken testedge in testedges)
            {
                if (testedge.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent($"Bad object in 'Edges' list of test case: {testedge}", Logging.LogFilterType.TextError);
                    failedComparison = "Bad Test";
                    return false;
                }
                JObject edgeTestObj = testedge.ToObject<JObject>();
                if (!edgeTestObj.TryGetValue("Source", out JToken srcTok) || srcTok.Type != JTokenType.Integer ||
                    !edgeTestObj.TryGetValue("Target", out JToken targTok) || targTok.Type != JTokenType.Integer)
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
                    if (edge.executionCount != requiredExecCount)
                    {
                        failedComparison = $"Edge {src},{targ} executed {edge.executionCount} times (!= {requiredExecCount}) ";
                        return false;
                    }
                }
            }

            failedComparison = "";
            return true;
        }

        bool GetTestEdgeCount(JObject edgeObj, out ulong count)
        {
            if (edgeObj.TryGetValue("Count", out JToken countTok))
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


        public class APITHUNK
        {
            public Dictionary<int, int> callerNodes = new Dictionary<int, int>();
        }

        public Dictionary<int, APITHUNK> ApiThunks = new Dictionary<int, APITHUNK>();

    }
}
