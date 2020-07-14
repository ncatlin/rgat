using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        public ROUTINE_STRUCT foundExtern;
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
        public ulong targetID;
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

        private int nlockholder = 0;

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
            foreach (JArray animFields in animationArray)
            {
                if (animFields.Count != 7) return false;
                ANIMATIONENTRY entry = new ANIMATIONENTRY();
                entry.entryType = (eTraceUpdateType)animFields[0].ToObject<uint>();
                entry.blockAddr = animFields[1].ToObject<ulong>();
                entry.blockID = animFields[2].ToObject<uint>();
                entry.count = animFields[3].ToObject<ulong>();
                entry.targetAddr = animFields[4].ToObject<ulong>();
                entry.targetID = animFields[5].ToObject<ulong>();
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
                return (instruction.threadvertIdx.TryGetValue(ThreadID, out targVertID));
            }
        }

        /*

		private void BB_addNewEdge(bool alreadyExecuted, int instructionIndex, ulong repeats);
		private void run_faulting_BB(TAG &tag);
        */
        private bool RunExternal(ulong targaddr, ulong repeats, out Tuple<int,int>? resultPair)
        {
            //start by examining our caller
            NodeData lastNode = safe_get_node(lastVertID);
            if (lastNode.IsExternal) { resultPair = null; return false; }
            Debug.Assert(lastNode.ins.numbytes > 0);

            //if caller is also external then we are not interested in this
            if (!ProcessData.ActiveModules[lastNode.GlobalModuleID]) { resultPair = null; return false; }


            ROUTINE_STRUCT? thisbb = null;
            int modnum = ProcessData.FindContainingModule(targaddr);
            Debug.Assert(modnum != -1);

            ProcessData.get_extern_at_address(targaddr, modnum, ref thisbb);
            Debug.Assert(thisbb != null);

            //see if caller already called this
            //if so, get the destination node so we can just increase edge weight
            auto x = thisbb->thread_callers.find(tid);
            piddata->getExternCallerReadLock();
            if (x != thisbb->thread_callers.end())
            {
                EDGELIST::iterator vecit = x->second.begin();
                for (; vecit != x->second.end(); ++vecit)
                {
                    if (vecit->first != lastVertID) continue;

                    piddata->dropExternCallerReadLock();

                    //this instruction in this thread has already called it
                    //cout << "repeated external edge from " << lastVertID << "->" << targVertID << endl;

                    targVertID = vecit->second;

                    node_data* targNode = safe_get_node(targVertID);
                    targNode->executionCount += repeats;
                    targNode->currentCallIndex += repeats;
                    lastVertID = targVertID;

                    return true;
                }
                //else: thread has already called it, but from a different place
            }
            //else: thread hasn't called this function before

            piddata->dropExternCallerReadLock();

            lastNode->childexterns += 1;
            targVertID = (NODEINDEX)get_num_nodes();

            piddata->getExternCallerWriteLock();

            //has this thread executed this basic block before?
            auto callersIt = thisbb->thread_callers.find(tid);
            if (callersIt == thisbb->thread_callers.end())
            {
                EDGELIST callervec;
                //cout << "add extern addr " << std::hex<<  targaddr << " mod " << std::dec << modnum << endl;
                callervec.push_back(make_pair(lastVertID, targVertID));
                thisbb->thread_callers.emplace(tid, callervec);
            }
            else
                callersIt->second.push_back(make_pair(lastVertID, targVertID));

            piddata->dropExternCallerWriteLock();

            int module = thisbb->globalmodnum;

            //make new external/library call node
            node_data newTargNode;
            newTargNode.globalModID = module;
            newTargNode.external = true;
            newTargNode.address = targaddr;
            newTargNode.index = targVertID;
            newTargNode.parentIdx = lastVertID;
            newTargNode.executionCount = 1;

            insert_node(targVertID, newTargNode); //this invalidates all node_data* pointers
            lastNode = &newTargNode;

            *resultPair = std::make_pair(lastVertID, targVertID);

            piddata->getExternDictWriteLock();
            piddata->externdict.insert(make_pair(targaddr, thisbb));
            piddata->dropExternDictWriteLock();

            edge_data newEdge;
            newEdge.chainedWeight = 0;
            newEdge.edgeClass = eEdgeLib;
            add_edge(newEdge, *safe_get_node(lastVertID), *safe_get_node(targVertID));
            //cout << "added external edge from " << lastVertID << "->" << targVertID << endl;
            lastNodeType = eNodeExternal;
            lastVertID = targVertID;
            return true;
        }
		private void ProcessNewArgs()
        {
            //target function		caller  		args
            Dictionary<ulong, Dictionary<ulong, vector<ARGLIST>>>::iterator pendingCallArgIt = pendingcallargs.begin();
            while (pendingCallArgIt != pendingcallargs.end())
            {

                EDGELIST threadCalls;
                //each function can have multiple nodes in a thread, so we have to get the list of 
                //every edge that has this extern as a target
                if (!lookup_extern_func_calls(pendingCallArgIt->first, threadCalls))
                {
                    ++pendingCallArgIt;
                    continue;
                }

                //run through each edge, trying to match args to the right caller-callee pair
                //running backwards should be more efficient as the lastest node is likely to hit the latest arguments
                EDGELIST::reverse_iterator callEdgeIt = threadCalls.rbegin();
                while (callEdgeIt != threadCalls.rend())
                {
                    node_data* callerNode = safe_get_node(callEdgeIt->first);
                    MEM_ADDRESS callerAddress = callerNode->ins->address; //this breaks if call not used?
                    node_data* functionNode = safe_get_node(callEdgeIt->second);

                    externCallsLock.lock () ;
                    map<MEM_ADDRESS, vector<ARGLIST>>::iterator caller_args_vec_IT = pendingCallArgIt->second.begin();

                    while (caller_args_vec_IT != pendingCallArgIt->second.end())
                    {
                        //check if we have found the source of the call that used these arguments
                        if (caller_args_vec_IT->first != callerAddress)
                        {
                            ++caller_args_vec_IT;
                            continue;
                        }

                        vector<ARGLIST> & calls_arguments_list = caller_args_vec_IT->second;

                        ARGLIST args;
                        foreach (args, calls_arguments_list)
				{
                            //each node can only have a certain number of arguments to prevent simple DoS
                            //todo: should be a launch option though
                            if (functionNode->callRecordsIndexs.size() < arg_storage_capacity)
                            {
                                EXTERNCALLDATA callRecord;
                                callRecord.edgeIdx = *callEdgeIt;
                                callRecord.argList = args;

                                externCallRecords.push_back(callRecord);
                                functionNode->callRecordsIndexs.push_back((unsigned long)externCallRecords.size() - 1);
                            }
                            else
                                break;
                        }
                        calls_arguments_list.clear();

                        if (caller_args_vec_IT->second.empty())
                            caller_args_vec_IT = pendingCallArgIt->second.erase(caller_args_vec_IT);
                        else
                            ++caller_args_vec_IT;
                    }
                    externCallsLock.unlock();

                    ++callEdgeIt;
                }
                if (pendingCallArgIt->second.empty())
                    pendingCallArgIt = pendingcallargs.erase(pendingCallArgIt);
                else
                    ++pendingCallArgIt;
            }
        }
        /*
		private bool lookup_extern_func_calls(ulong called_function_address, EDGELIST &callEdges);
		private void build_functioncall_from_args();
		

		//   function 	      caller		
		Dictionary<ulong, Dictionary<ulong, List<List<Tuple<int, string>>>>> pendingcallargs;

		private uint arg_storage_capacity = 100;
		private ulong pendingCalledFunc = 0;
		private ulong pendingFuncCaller = 0;

		private List<Tuple<int,string>> pendingArgs;
		

		
		public void LinkBasicBlocks(List<InstructionData> source, List<InstructionData> target);
		*/
        void InsertNode(uint targVertID, NodeData node)
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

            //getNodeWriteLock();
            NodeList.Add(node);
            //dropNodeWriteLock();
        }

        //public bool edge_exists(NODEPAIR edge, edge_data** edged);
        public void AddEdge(EdgeData e, NodeData source, NodeData target)
        {
            Tuple<uint, uint> edgePair = new Tuple<uint, uint>(source.index, target.index);

            //getNodeWriteLock();

            source.OutgoingNeighboursSet.Add(edgePair.Item2);
            if (source.conditional != eConditionalType.NOTCONDITIONAL &&
                source.conditional != eConditionalType.CONDCOMPLETE)
            {
                if (source.ins.condDropAddress == target.address)
                    source.conditional |= eConditionalType.CONDFELLTHROUGH;
                else if (source.ins.branchAddress == target.address)
                    source.conditional |= eConditionalType.CONDTAKEN;
            }

            target.IncomingNeighboursSet.Add(edgePair.Item1);
            //dropNodeWriteLock();

            //getEdgeWriteLock();
            edgeDict.Add(edgePair, e);
            edgeList.Add(edgePair);
            //dropEdgeWriteLock();
        }


        //public void add_pending_arguments(int argpos, string contents, bool callDone);

        //public void handle_exception_tag(TAG &thistag);
        
        public void handle_tag(TAG thistag, ulong repeats = 1)
        {

            if (thistag.jumpModifier == eCodeInstrumentation.eInstrumentedCode)
            {
                //addBlockNodesToGraph(thistag, repeats);
                addBlockLineToGraph(thistag, repeats);

                TotalInstructions += thistag.insCount * repeats;
                set_active_node(lastVertID);
            }

            else if (thistag.jumpModifier == eCodeInstrumentation.eUninstrumentedCode)
            {
                if (lastVertID == 0) return;

                //find caller,external vertids if old + add node to graph if new
                RunExternal(thistag.blockaddr, repeats, out Tuple<int, int> resultPair);
                process_new_args();
                set_active_node(resultPair.Item2);
            }
            else
            {
                Console.WriteLine($"[rgat]WARNING: Handle_tag dead code assert at block 0x{thistag.blockaddr:X}");
                Debug.Assert(false);
            }


        }

        //public bool notify_pending_func(ulong funcpc, ulong returnpc);
        //public bool hasPendingCalledFunc() { return pendingCalledFunc != null; }

        //node id pairs to edge data
        public Dictionary<Tuple<uint, uint>, EdgeData> edgeDict = new Dictionary<Tuple<uint, uint>, EdgeData>();
        //order of edge execution
        public List<Tuple<uint, uint>> edgeList = new List<Tuple<uint, uint>>();

        public List<NodeData> NodeList = new List<NodeData>(); //node id to node data
        public List<BlockData> BlockList = new List<BlockData>(); //node id to node data

        public bool node_exists(uint idx) { return (NodeList.Count > idx); }
        public int get_num_nodes() { return NodeList.Count; }
        public int get_num_edges() { return edgeList.Count; }
        /*
		public void acquireNodeReadLock() { getNodeReadLock(); }
		public void releaseNodeReadLock() { dropNodeReadLock(); }

		public uint handle_new_instruction(InstructionData instruction, ulong blockID, ulong repeats);
		public void handle_previous_instruction(uint targVertID, ulong repeats);
        */
        public void addBlockLineToGraph(TAG tag, ulong repeats)
        {
            List<InstructionData> block = TraceData.DisassemblyData.getDisassemblyBlock(tag.blockaddr, tag.blockID, null);
            int numInstructions = block.Count;

            Tuple<int,int> firstVert;
            Tuple<int, int> lastVert;

            for (int instructionIndex = 0; instructionIndex < numInstructions; ++instructionIndex)
            {
                InstructionData instruction = block[instructionIndex];

                //start possible #ifdef DEBUG  candidate
                if (lastNodeType != eEdgeNodeType.eFIRST_IN_THREAD)
                {
                    if (!node_exists(lastVertID))
                    {
                        //had an odd error here where it returned false with idx 0 and node list size 1. can only assume race condition?
                        Console.WriteLine($"\t\t[rgat]ERROR: RunBB- Last vert {lastVertID} not found. Node list size is: {NodeList.Count}");
                        Debug.Assert(false);
                    }
                }
                //end possible  #ifdef DEBUG candidate

                //target vert already on this threads graph?
                bool alreadyExecuted = SetTR(instruction);
                if (!alreadyExecuted)
                {
                    targVertID = handle_new_instruction(*instruction, tag->blockID, repeats);
                }
                else
                {
                    handle_previous_instruction(targVertID, repeats);
                }

                if (instructionIndex == 0) firstVert = targVertID;

                if (loopState == eLoopState.eBuildingLoop)
                {
                    firstLoopVert = targVertID;
                    loopState = eLoopState.eLoopProgress;
                }

                BB_addNewEdge(alreadyExecuted, instructionIndex, repeats);

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
                lastVertID = targVertID;
            }

            block_data newblock(firstVert, lastVertID);
            getEdgeWriteLock();
            blockList.push_back(newblock);
            dropEdgeWriteLock();
            std::cout << "draw block from nidx " << firstVert << " -to- " << lastVertID << std::endl;
        }

        public void addBlockNodesToGraph(TAG tag, int repeats)
        {
            INSLIST* block = piddata->getDisassemblyBlock(tag->blockaddr, tag->blockID, 0);
            size_t numInstructions = (int)block->size();

            for (size_t instructionIndex = 0; instructionIndex < numInstructions; ++instructionIndex)
            {
                InstructionData instruction = block[instructionIndex];

                //start possible #ifdef DEBUG  candidate
                if (lastNodeType != eEdgeNodeType.eFIRST_IN_THREAD)
                {
                    if (!node_exists(lastVertID))
                    {
                        //had an odd error here where it returned false with idx 0 and node list size 1. can only assume race condition?
                        cerr << "\t\t[rgat]ERROR: RunBB- Last vert " << lastVertID << " not found. Node list size is: " << nodeList.size() << endl;
                        assert(0);
                    }
                }
                //end possible  #ifdef DEBUG candidate

                //target vert already on this threads graph?
                bool alreadyExecuted = set_target_instruction(instruction);
                if (!alreadyExecuted)
                {
                    targVertID = handle_new_instruction(instruction, tag.blockID, repeats);
                }
                else
                {
                    handle_previous_instruction(targVertID, repeats);
                }

                if (loopState == eLoopState.eBuildingLoop)
                {
                    firstLoopVert = targVertID;
                    loopState = eLoopState.eLoopProgress;
                }

                BB_addNewEdge(alreadyExecuted, instructionIndex, repeats);

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
                lastVertID = targVertID;
            }
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

		void set_max_arg_storage(uint maxargs) { arg_storage_capacity = maxargs; }
		string get_node_sym(uint idx);

		int getAnimDataSize() { return savedAnimationData.Count; }
		List<ANIMATIONENTRY>* getSavedAnimData() { return &savedAnimationData; }
		
		*/
        //list of all external nodes
        List<uint> externalNodeList = new List<uint>();
        //List<uint> copyExternalNodeList();

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

                EdgeData edge = new EdgeData
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
            //animationListsRWLOCK_.lock () ;
            SavedAnimationData.Add(entry);
            //animationListsRWLOCK_.unlock();
        }

        
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
                ModulePath = ".." + ModulePath.Substring(ModulePath.Length - UI_Constants.MAX_DIFF_PATH_LENGTH, ModulePath.Length);
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

                push_anim_update(animUpdate);
            }

            ANIMATIONENTRY lastanimUpdate;
            lastanimUpdate.entryType = eTraceUpdateType.eAnimLoopLast;
            push_anim_update(lastanimUpdate);

            loopCache.Clear();
            loopIterations = 0;
            loopState = eLoopState.eNoLoop;

        }



        //bool serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer);

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
        List<EXTERNCALLDATA> ExternCallRecords = new List<EXTERNCALLDATA>();
        public ulong TotalInstructions { get; private set; } = 0;
        int exeModuleID = -1;
        public ulong moduleBase = 0;
        public string modulePath;
        public Dictionary<ulong, uint> InternalPlaceholderFuncNames = new Dictionary<ulong, uint>();

        public uint lastNode = 0;
        //used by heatDictionary solver
        uint finalNodeID = 0;

        //important state variables!
        uint lastVertID = 0; //the vert that led to new instruction
        uint targVertID = 0; //new vert we are creating
        eEdgeNodeType lastNodeType = eEdgeNodeType.eFIRST_IN_THREAD;

        ulong loopIterations = 0;
        uint firstLoopVert = 0;
        public eLoopState loopState = eLoopState.eNoLoop;
        //tag address, mod type
        public List<TAG> loopCache = new List<TAG>();
        Tuple<uint, uint> repeatStart;
        Tuple<uint, uint> repeatEnd;

        List<string> loggedCalls;

        //number of times an external function has been called. used to Dictionary arguments to calls
        public Dictionary<Tuple<ulong, uint>, ulong> externFuncCallCounter;

        bool updated = true;

        void set_terminated()
        {
            terminated = true;
            updated = true; //aka needvboreloadpreview
            IsActive = false;
            finalNodeID = lastVertID;
        }

        //void start_edgeL_iteration(EDGELIST::iterator* edgeIt, EDGELIST::iterator* edgeEnd);
        //void stop_edgeL_iteration();

        public bool IsActive = true;
        public bool terminated = false;
    }
}
