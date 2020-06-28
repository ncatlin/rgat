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
        public uint globalmodnum;
        //list of threads that call this BB
        //inside is list of the threads verts that call it
        //it can exist multiple times on map so caller->this is listed
        //  tid     
        public Dictionary<uint, List<Tuple<uint, uint>>> thread_callers;
        public bool hasSymbol;
    };

    struct TAG
    {
        //come from trace
        ulong blockaddr;
        ulong blockID;
        ulong insCount;
        //used internally
        int jumpModifier;
        ROUTINE_STRUCT foundExtern;
    };

    class ProtoGraph
    {
        enum eLoopState { eNoLoop, eBuildingLoop, eLoopProgress };

        public ProtoGraph(TraceRecord runrecord, uint threadID)
        {
            TraceData = runrecord;
            ProcessData = runrecord.DisassemblyData;
            ThreadID = threadID;
        }


        public uint ThreadID = 0;

        private int nlockholder = 0;

        public TraceIngestThread TraceReader { set; get; } = null;
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
        //private bool loadStats(const rapidjson::Value& graphData);
        //private bool loadAnimationData(const rapidjson::Value& replayArray);
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
                externCallRecords.Add(callDat);
            }
            return true;
        }

        /*

	private bool set_target_instruction(InstructionData instruction);
		private void BB_addNewEdge(bool alreadyExecuted, int instructionIndex, ulong repeats);
		private void run_faulting_BB(TAG &tag);
		private bool run_external(ulong targaddr, ulong repeats, NODEPAIR* resultPair);

		private void process_new_args();
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

        }

        /*
		public void add_pending_arguments(int argpos, string contents, bool callDone);

		public void handle_exception_tag(TAG &thistag);
		public void process_trace_tag(char* entry);
		public void handle_tag(TAG* thistag, ulong repeats = 1);
		public bool notify_pending_func(ulong funcpc, ulong returnpc);
		public bool hasPendingCalledFunc() { return pendingCalledFunc != null; }
		public EDGEDictionary edgeDict; //node id pairs to edge data
		public EDGELIST edgeList; //order of edge execution

		//i feel like this misses the point, idea is to iterate safely
		public EDGELIST* edgeLptr() { return &edgeList; }
		*/
        public List<NodeData> NodeList = new List<NodeData>(); //node id to node data
        public List<BlockData> BlockList = new List<BlockData>(); //node id to node data
        /*
		public bool node_exists(uint idx) { return (nodeList.Count > idx); }
		public int get_num_nodes() { return nodeList.Count; }
		public int get_num_edges() { return edgeDict.Count; }

		public void acquireNodeReadLock() { getNodeReadLock(); }
		public void releaseNodeReadLock() { dropNodeReadLock(); }

		public uint handle_new_instruction(InstructionData instruction, ulong blockID, ulong repeats);
		public void handle_previous_instruction(uint targVertID, ulong repeats);
		public void addBlockLineToGraph(TAG* tag, int repeats);
		public void addBlockNodesToGraph(TAG* tag, int repeats);


		void set_active_node(uint idx);
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
				return &edgeIt->second;
			else
				return null;
		}
		inline edge_data * unsafe_get_edge(Tuple<uint, uint> edgePair);

		edge_data* get_edge(uint edgeindex);

		//edge_data *get_or_create_edge(node_data *source, node_data *target);

		node_data* unsafe_get_node(uint index);
		*/

        NodeData safe_get_node(uint index)
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

                EdgeData edge = new EdgeData();
                edge.edgeClass = (eEdgeNodeType)edgeClass;

                Tuple<uint, uint> stpair = new Tuple<uint, uint>(source, target);
                AddEdge(edge, safe_get_node(source), safe_get_node(target));
            }
            return true;
        }


        /*
		void push_anim_update(ANIMATIONENTRY);
		//animation data received from target
		List<ANIMATIONENTRY> savedAnimationData;
		
		*/
        //todo rename
        List<uint> ExceptionNodeIndexes;

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

		void set_loop_state(int loopState_, ulong loopIterations_);
		void dump_loop();

		*/

        bool terminationFlag = false;
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
            if (!LoadExceptions(EdgeArray))
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

            /*

			graphDataIt = graphData.FindMember("ReplayData");
			if (graphDataIt == graphData.MemberEnd())
			{
				cerr << "[rgat] Error: Failed to find replay data" << endl;
				return false;
			}
			if (!loadAnimationData(graphDataIt->value)) { cerr << "[rgat]ERROR: Failed to load trace replay data" << endl; return false; }

			if (!loadStats(graphData)) { cerr << "[rgat]ERROR: Failed to load graph stats" << endl; return false; }
			*/

            return true;

        }
        /*
		bool instructions_to_nodepair(InstructionData sourceIns, InstructionData targIns, NODEPAIR &result);
		*/
        List<EXTERNCALLDATA> externCallRecords;
        ulong totalInstructions = 0;
        int exeModuleID = -1;
        ulong moduleBase = 0;
        string modulePath;
        Dictionary<ulong, uint> internalPlaceholderFuncNames;

        uint lastNode = 0;
        //used by heatDictionary solver
        uint finalNodeID = 0;

        //important state variables!
        uint lastVertID = 0; //the vert that led to new instruction
        uint targVertID = 0; //new vert we are creating
        eEdgeNodeType lastNodeType = eEdgeNodeType.eFIRST_IN_THREAD;

        ulong loopIterations = 0;
        uint firstLoopVert = 0;
        eLoopState loopState = eLoopState.eNoLoop;
        //tag address, mod type
        List<TAG> loopCache;
        Tuple<uint, uint> repeatStart;
        Tuple<uint, uint> repeatEnd;

        List<string> loggedCalls;

        //number of times an external function has been called. used to Dictionary arguments to calls
        Dictionary<Tuple<ulong, ulong>, ulong> externFuncCallCounter;

        bool terminated = false;
        bool updated = true;

        void set_terminated()
        {
            terminated = true;
            updated = true; //aka needvboreloadpreview
            terminationFlag = true;
            IsActive = false;
            finalNodeID = lastVertID;
        }

        //void start_edgeL_iteration(EDGELIST::iterator* edgeIt, EDGELIST::iterator* edgeEnd);
        //void stop_edgeL_iteration();

        public bool IsActive = true;
    }
}
