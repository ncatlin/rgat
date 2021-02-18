﻿using Newtonsoft.Json.Linq;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgatCore
{
    struct EXTERNCALLDATA
    {
        public Tuple<uint, uint> edgeIdx;
        public List<Tuple<int, string>> argList;
    };

    struct ROUTINE_STRUCT
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

    struct TAG
    {
        //come from trace
        public ulong blockaddr;
        public uint blockID;
        public ulong insCount;
        //used internally
        public eCodeInstrumentation jumpModifier;
        public ROUTINE_STRUCT? foundExtern;
    };
    enum eTraceUpdateType { eAnimExecTag, eAnimLoop, eAnimLoopLast, eAnimUnchained, eAnimUnchainedResults, eAnimUnchainedDone, eAnimExecException };
    enum eLoopState { eNoLoop, eBuildingLoop, eLoopProgress };
    enum eCodeInstrumentation { eInstrumentedCode = 0, eUninstrumentedCode = 1 };

    struct ANIMATIONENTRY
    {
        public eTraceUpdateType entryType;
        public ulong blockAddr;
        public uint blockID;
        public ulong count;
        public ulong targetAddr;
        public uint targetID;
        public ulong callCount;
    };


    class ProtoGraph
    {

        public ProtoGraph(TraceRecord runrecord, uint threadID)
        {
            TraceData = runrecord;
            ProcessData = runrecord.DisassemblyData;
            ThreadID = threadID;
        }

        public uint ThreadID = 0;

        public ThreadTraceIngestThread TraceReader { set; get; } = null;
        public ProcessRecord ProcessData { private set; get; } = null;
        public TraceRecord TraceData { private set; get; } = null;

        //used to keep a blocking extern highlighted - may not be useful with new method TODO
        private uint latest_active_node_idx = 0;
        public DateTime ConstructedTime { private set; get; } = DateTime.Now;

        private bool LoadNodes(JArray NodesArray, Dictionary<ulong, List<InstructionData>> disassembly)
        {
            foreach (JArray nodeItem in NodesArray)
            {
                NodeData n = new NodeData();//can't this be done at start?
                if (!n.Deserialise(nodeItem, disassembly))
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
            return true;
        }

        private bool LoadAnimationData(JArray animationArray)
        {
            Console.WriteLine($"Loading {animationArray.Count} items");
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
                entry.callCount = animFields[6].ToObject<ulong>();

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

                EXTERNCALLDATA callDat = new EXTERNCALLDATA();
                callDat.argList = CallArgList;
                callDat.edgeIdx = edge;
                ExternCallRecords.Add(callDat);
            }
            return true;
        }

        private bool set_target_instruction(InstructionData instruction)
        {
            //ReadLock(piddata->disassemblyRWLock);
            lock (TraceData.DisassemblyData.InstructionsLock) //todo this can be a read lock
            {
                //Console.WriteLine($"Checking if instruction 0x{instruction.address:X}, dbgid {instruction.DebugID} mut {instruction.mutationIndex} executed");
                return (instruction.threadvertIdx.TryGetValue(ThreadID, out targVertID));
            }
        }


        private void AddEdge_LastToTargetVert(bool alreadyExecuted, int instructionIndex, ulong repeats)
        {
            Tuple<uint, uint> edgeIDPair = new Tuple<uint, uint>(ProtoLastVertID, targVertID);

            //Console.WriteLine($"\AddEdge_LastToTargetVert {lastVertID} -> {targVertID}");
            if (EdgeExists(edgeIDPair))
            {
                //cout << "repeated internal edge from " << lastVertID << "->" << targVertID << endl;
                return;
            }

            if (lastNodeType == eEdgeNodeType.eFIRST_IN_THREAD) return;

            EdgeData newEdge = new EdgeData(edgeList.Count);
            newEdge.chainedWeight = 0;

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


            NodeData sourcenode = safe_get_node(ProtoLastVertID);
            //make API calls leaf nodes, rather than part of the chain
            if (sourcenode.IsExternal)
                sourcenode = safe_get_node(ProtoLastLastVertID);

            if (!EdgeExists(new Tuple<uint, uint>(sourcenode.index, targVertID)))
            {
                AddEdge(newEdge, sourcenode, safe_get_node(targVertID));
            }


        }

        private void run_faulting_BB(TAG tag)
        {
            ROUTINE_STRUCT? foundExtern = null;
            List<InstructionData> block = ProcessData.getDisassemblyBlock(tag.blockID, ref foundExtern, tag.blockaddr);
            if (block == null)
            {
                if (foundExtern != null)
                    Console.WriteLine($"[rgat]Warning - faulting block was in uninstrumented code at 0x{tag.blockaddr}");
                else
                    Console.WriteLine($"[rgat]Warning - failed to ged disassebly for faulting block at 0x{tag.blockaddr}");

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
                    safe_get_node(targVertID).executionCount += 1;
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
            //start by examining our caller
            NodeData lastNode = safe_get_node(ProtoLastVertID);
            if (lastNode.IsExternal) { resultPair = null; return false; }
            Debug.Assert(lastNode.ins.numbytes > 0);

            //if caller is also external then we are not interested in this
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

                    NodeData targNode = safe_get_node(targVertID);
                    targNode.executionCount += repeats;
                    targNode.currentCallIndex += repeats;
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
            newTargNode.executionCount = 1;


            InsertNode(targVertID, newTargNode); //this invalidates all node_data* pointers
            lastNode = newTargNode;


            EdgeData newEdge = new EdgeData(edgeList.Count);
            newEdge.chainedWeight = 0;
            newEdge.edgeClass = eEdgeNodeType.eEdgeLib;
            AddEdge(newEdge, safe_get_node(ProtoLastVertID), safe_get_node(targVertID));
            //cout << "added external edge from " << lastVertID << "->" << targVertID << endl;
            lastNodeType = eEdgeNodeType.eNodeExternal;
            ProtoLastLastVertID = ProtoLastVertID;
            ProtoLastVertID = targVertID;
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
            if ((int)currentSourceBlock == -1) return; //API called before instrumented code was reached
            ulong currentTarget = _unprocessedCallArguments[0].calledAddress;

            uint completecount = 0;
            int currentIndex = -1;
            int maxCacheI = _unprocessedCallArguments.Count;

            for (var cacheI = 0; cacheI < maxCacheI; cacheI++)
            {
                INCOMING_CALL_ARGUMENT arg = _unprocessedCallArguments[cacheI];
                Debug.Assert(arg.calledAddress == currentTarget, "ProcessIncomingCallArguments() unexpected change of target");
                Debug.Assert(arg.sourceBlock == currentSourceBlock, "ProcessIncomingCallArguments() unexpected change of source");
                Debug.Assert(arg.argIndex > currentIndex, "ProcessIncomingCallArguments() unexpected change of source");
                if (BlocksFirstLastNodeList.Count <= (int)currentSourceBlock) 
                    break;
                uint callerNodeIdx = BlocksFirstLastNodeList[(int)currentSourceBlock].Item2;
                currentIndex = arg.argIndex;

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
                    if (functionNode.callRecordsIndexs.Count >= GlobalConfig.ArgStorageMax)
                    {
                        //todo: blacklist this callee from future processing
                        Console.WriteLine($"Warning, dropping args to extern 0x{currentTarget:X} because the storage limit is {GlobalConfig.ArgStorageMax}");
                    }
                    else
                    {
                        List<Tuple<int, string>> argStringsList = new List<Tuple<int, string>>();
                        for (var aI = 0; aI <= cacheI; aI++)
                        {
                            argStringsList.Add(new Tuple<int, string>(_unprocessedCallArguments[aI].argIndex, _unprocessedCallArguments[aI].argstring));
                        }

                        EXTERNCALLDATA callRecord;
                        callRecord.edgeIdx = threadCalls[i];
                        callRecord.argList = argStringsList;

                        ExternCallRecords.Add(callRecord);
                        functionNode.callRecordsIndexs.Add((ulong)ExternCallRecords.Count - 1);

                        // this toggle isn't thread safe so slight chance for renderer to not notice the final arg
                        // not worth faffing around with locks though - maybe just re-read at tracereader thread termination
                        functionNode.newArgsRecorded = true;
                    }
                    completecount++;
                    sequenceProcessed = true;
                    break;
                }

                if (!sequenceProcessed)
                {
                    Console.WriteLine($"\tProcessIncomingCallArguments - Failed to find *specific* caller of 0x{arg.calledAddress:X} in current thread. Leaving until it appears.");
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
                sourceBlock = sourceBlockID
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
                if (NodeList.Count > 0)
                    Debug.Assert(targVertID == NodeList[NodeList.Count - 1].index + 1);

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
                return edgeDict.ContainsKey(edge);
            }
        }

        public bool EdgeExists(Tuple<uint, uint> edge, out EdgeData? edged)
        {
            lock (edgeLock)
            {
                return edgeDict.TryGetValue(edge, out edged);
            }
        }
        public List<Tuple<uint, uint>> GetEdgelistCopy()
        {

            lock (edgeLock)
            {
                return edgeList.ToList();
            }
        }

        public void AddEdge(uint SrcNodeIdx, uint TargNodeIdx)
        {
            NodeData sourceNode = safe_get_node(SrcNodeIdx);
            NodeData targNode = safe_get_node(TargNodeIdx);

            EdgeData newEdge = new EdgeData(edgeList.Count);

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

            if (source.IsExternal)
                Console.WriteLine("f");

            //todo needs nodelock?
            if (!source.OutgoingNeighboursSet.Contains(edgePair.Item2))
            {
                source.OutgoingNeighboursSet.Add(edgePair.Item2);
                source.UpdateDegree();
            }

            if (source.conditional != eConditionalType.NOTCONDITIONAL &&
                source.conditional != eConditionalType.CONDCOMPLETE)
            {
                if (source.ins.condDropAddress == target.address)
                    source.conditional |= eConditionalType.CONDFELLTHROUGH;
                else if (source.ins.branchAddress == target.address)
                    source.conditional |= eConditionalType.CONDTAKEN;
            }

            lock (nodeLock)
            {
                target.IncomingNeighboursSet.Add(edgePair.Item1);
                target.UpdateDegree();
            }

            lock (edgeLock)
            {
                edgeDict.Add(edgePair, e); 
                edgeList.Add(edgePair);
            }

        }


        public void handle_exception_tag(TAG thistag)
        {
            if (thistag.jumpModifier == eCodeInstrumentation.eInstrumentedCode)
            {
                run_faulting_BB(thistag);

                TotalInstructions += thistag.insCount;

                set_active_node(ProtoLastVertID);
            }

            else if (thistag.jumpModifier == eCodeInstrumentation.eUninstrumentedCode) //call to (uninstrumented) external library
            {
                if (ProtoLastVertID == 0) return;

                //find caller,external vertids if old + add node to graph if new
                Console.WriteLine("[rgat]WARNING: Exception handler in uninstrumented module reached\n." +
                    "I have no idea if this code will handle it; Let me know when you reach the other side...");
                if (RunExternal(thistag.blockaddr, 1, out Tuple<uint, uint> resultPair))
                {
                    set_active_node(resultPair.Item2);
                }
                else
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


        public void handle_tag(TAG thistag, ulong repeats = 1)
        {

            if (thistag.jumpModifier == eCodeInstrumentation.eInstrumentedCode)
            {
                //Console.WriteLine($"Processing instrumented tag blockaddr 0x{thistag.blockaddr:X} inscount {thistag.insCount}");

                addBlockToGraph(thistag, repeats);
                set_active_node(ProtoLastVertID);
            }

            else if (thistag.jumpModifier == eCodeInstrumentation.eUninstrumentedCode)
            {
                if (ProtoLastVertID == 0) return;

                //find caller,external vertids if old + add node to graph if new
                if (RunExternal(thistag.blockaddr, repeats, out Tuple<uint, uint> resultPair))
                {
                    ProcessIncomingCallArguments(); //todo - does this ever achieve anything here?
                    set_active_node(resultPair.Item2);
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
        public Dictionary<Tuple<uint, uint>, EdgeData> edgeDict = new Dictionary<Tuple<uint, uint>, EdgeData>();
        //order of edge execution
        //todo - make this private, hide from view for thread safety
        public List<Tuple<uint, uint>> edgeList = new List<Tuple<uint, uint>>();
        //light-touch list of blocks for filling in edges without locking disassembly data
        public List<Tuple<uint, uint>> BlocksFirstLastNodeList = new List<Tuple<uint, uint>>();


        private readonly object highlightsLock = new object();


        public readonly object nodeLock = new object();
        public List<NodeData> NodeList = new List<NodeData>(); //node id to node data

        public bool node_exists(uint idx) { return (NodeList.Count > idx); }
        public uint get_num_nodes() { return (uint)NodeList.Count; }
        public uint get_num_edges() { return (uint)edgeList.Count; }
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
            thisnode.executionCount = repeats;
            thisnode.GlobalModuleID = instruction.globalmodnum;

            Debug.Assert(!node_exists(targVertID));
            InsertNode(targVertID, thisnode);

            lock (TraceData.DisassemblyData.InstructionsLock)
            {
                instruction.threadvertIdx.Add(ThreadID, targVertID);
            }

            //lastVertID = targVertID;
            return targVertID;
        }


        public void handle_previous_instruction(uint targVertID, ulong repeats)
        {

            safe_get_node(targVertID).executionCount += repeats;
            //lastVertID = targVertID;
        }


        public void addBlockToGraph(TAG tag, ulong repeats)
        {
            List<InstructionData> block = TraceData.DisassemblyData.getDisassemblyBlock(tag.blockID);
            int numInstructions = block.Count;
            TotalInstructions += ((ulong)numInstructions * repeats);

            uint firstVert = 0;
            //Console.WriteLine($"addBlockLineToGraph adding block addr 0x{block[0].address:X} with {block.Count} instructions");
            for (int instructionIndex = 0; instructionIndex < numInstructions; ++instructionIndex)
            {
                InstructionData instruction = block[instructionIndex];

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
                    //Console.WriteLine($"\tins addr 0x{instruction.address:X} is new, handling as new");
                    targVertID = handle_new_instruction(instruction, tag.blockID, repeats);
                }
                else
                {
                    //Console.WriteLine($"\tins addr 0x{instruction.address:X} exists, handling as existing");
                    handle_previous_instruction(targVertID, repeats);
                }

                if (instructionIndex == 0) firstVert = targVertID;

                if (loopState == eLoopState.eBuildingLoop)
                {
                    firstLoopVert = targVertID;
                    loopState = eLoopState.eLoopProgress;
                }


                AddEdge_LastToTargetVert(alreadyExecuted, instructionIndex, repeats);

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
                ProtoLastLastVertID = ProtoLastVertID;
                ProtoLastVertID = targVertID;
            }


            lock (edgeLock)
            {
                while (BlocksFirstLastNodeList.Count <= tag.blockID) BlocksFirstLastNodeList.Add(null);
                if (BlocksFirstLastNodeList[(int)tag.blockID] == null)
                {
                    BlocksFirstLastNodeList[(int)tag.blockID] = new Tuple<uint, uint>(firstVert, ProtoLastVertID);
                }
            }

            //Console.WriteLine($"Thread {ThreadID} draw block from nidx {firstVert} -to- {lastVertID}");
        }

        public void set_active_node(uint idx)
        {
            if (idx > NodeList.Count) return;
            //getNodeWriteLock();
            latest_active_node_idx = idx;
            //dropNodeWriteLock();
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
                uint edgeClass = entry[2].ToObject<uint>();

                EdgeData edge = new EdgeData(edgeList.Count)
                {
                    edgeClass = (eEdgeNodeType)edgeClass
                };

                Tuple<uint, uint> stpair = new Tuple<uint, uint>(source, target);
                AddEdge(edge, safe_get_node(source), safe_get_node(target));
            }
            return true;
        }



        public void PushAnimUpdate(ANIMATIONENTRY entry)
        {
            lock (AnimDataLock)
            {
                SavedAnimationData.Add(entry);
            }
        }

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


            if (ModulePath.Length > UI_Constants.MAX_DIFF_PATH_LENGTH)
                ModulePath = ".." + ModulePath.Substring(ModulePath.Length - UI_Constants.MAX_DIFF_PATH_LENGTH, UI_Constants.MAX_DIFF_PATH_LENGTH);
        }
        /*
		public ulong BacklogOutgoing = 0;
		public ulong BacklogIncoming = 0;

		ulong get_backlog_total();
        */
        public void SetLoopState(eLoopState loopState_, ulong loopIterations_)
        {

            loopState = loopState_;
            loopIterations = loopIterations_;

        }

        public void DumpLoop()
        {
            Debug.Assert(loopState == eLoopState.eBuildingLoop);

            if (loopCache.Count == 0)
            {
                loopState = eLoopState.eNoLoop;
                return;
            }

            //put the verts/edges on the graph
            for (int cacheIdx = 0; cacheIdx < loopCache.Count; ++cacheIdx)
            {
                TAG thistag = loopCache[cacheIdx];
                handle_tag(thistag, loopIterations);

                ANIMATIONENTRY animUpdate = new ANIMATIONENTRY();
                animUpdate.blockAddr = thistag.blockaddr;
                animUpdate.blockID = thistag.blockID;
                animUpdate.count = loopIterations;
                animUpdate.entryType = eTraceUpdateType.eAnimLoop;

                if (TraceData.FindContainingModule(animUpdate.blockAddr, out int containingmodule) == eCodeInstrumentation.eUninstrumentedCode)
                {
                    Tuple<ulong, uint> uniqueExternID = new Tuple<ulong, uint>(thistag.blockaddr, thistag.blockID);
                    animUpdate.callCount = externFuncCallCounter[uniqueExternID]++;
                }

                PushAnimUpdate(animUpdate);
            }

            ANIMATIONENTRY lastanimUpdate = new ANIMATIONENTRY();
            lastanimUpdate.entryType = eTraceUpdateType.eAnimLoopLast;
            PushAnimUpdate(lastanimUpdate);

            loopCache.Clear();
            loopIterations = 0;
            loopState = eLoopState.eNoLoop;

        }



        public JObject Serialise()
        {
            JObject result = new JObject();
            result.Add("ThreadID", ThreadID);

            lock (nodeLock)
            {
                JArray nodesArray = new JArray();
                foreach (NodeData node in NodeList)
                {
                    nodesArray.Add(node.Serialise());
                }

                result.Add("Nodes", nodesArray);
            }

            lock (edgeLock)
            {
                JArray edgeArray = new JArray();
                foreach (var edgetuple in edgeList)
                {
                    edgeArray.Add(edgeDict[edgetuple].Serialise(edgetuple.Item1, edgetuple.Item2));
                }

                result.Add("Edges", edgeArray);
            }

            lock (highlightsLock)
            {
                JArray exceptNodeArray = new JArray();
                foreach (var exc_node_idx in exceptionSet)
                {
                    exceptNodeArray.Add(exc_node_idx);
                }

                result.Add("Exceptions", exceptNodeArray);
            }

            result.Add("Module", exeModuleID);

            //todo - lock?
            JArray externCalls = new JArray();
            foreach (EXTERNCALLDATA ecd in ExternCallRecords)
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
                    replayItem.Add(repentry.callCount);
                    replayDataArr.Add(replayItem);
                }
            }
            result.Add("ReplayData", replayDataArr);



            return result;
        }

        public bool Deserialise(JObject graphData, Dictionary<ulong, List<InstructionData>> disassembly)
        {
            if (!graphData.TryGetValue("Nodes", out JToken jNodes) || jNodes.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid Nodes in trace");
                return false;
            }
            JArray NodesArray = (JArray)jNodes;
            if (!LoadNodes(NodesArray, disassembly))
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
                Console.WriteLine("[rgat]ERROR: Failed to load graph stats");
                return false;
            }
            return true;
        }
        /*
		bool instructions_to_nodepair(InstructionData sourceIns, InstructionData targIns, NODEPAIR &result);
		*/
        public List<EXTERNCALLDATA> ExternCallRecords = new List<EXTERNCALLDATA>();
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
        public uint ProtoLastVertID = 0; //the vert that led to new instruction
        public uint ProtoLastLastVertID = 0; //the vert that led to the previous instruction

        eEdgeNodeType lastNodeType = eEdgeNodeType.eFIRST_IN_THREAD;

        ulong loopIterations = 0;
        uint firstLoopVert = 0;
        public eLoopState loopState = eLoopState.eNoLoop;
        //tag address, mod type
        public List<TAG> loopCache = new List<TAG>();
        Tuple<uint, uint> repeatStart;
        Tuple<uint, uint> repeatEnd;

        List<string> loggedCalls = new List<string>();

        //number of times an external function has been called. used to Dictionary arguments to calls
        public Dictionary<Tuple<ulong, uint>, ulong> externFuncCallCounter = new Dictionary<Tuple<ulong, uint>, ulong>();

        bool updated = true;

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

        public bool Terminated = false;
        public bool PerformingUnchainedExecution = false;
    }
}
