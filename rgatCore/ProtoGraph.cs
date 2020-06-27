using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace rgatCore
{
	struct EXTERNCALLDATA
	{
		public Tuple<uint,uint> edgeIdx;
		public List<Tuple<int, string>> argList;
	};

	struct ROUTINE_STRUCT
	{
		List<InstructionData> inslist;
		uint globalmodnum;
		//list of threads that call this BB
		//inside is list of the threads verts that call it
		//it can exist multiple times on map so caller->this is listed
		//  tid     
		Dictionary<uint, List<Tuple<uint,uint>>> thread_callers;
		bool hasSymbol;
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
		enum eLoopState { eNoLoop, eBuildingLoop, eLoopProgress};

		public ProtoGraph(TraceRecord runrecord, uint threadID)
		{
			TraceData = runrecord;
			ProcessData = runrecord.DisassemblyData;
			ThreadID = threadID;
		}


		private uint ThreadID = 0;

		private int nlockholder = 0;

		public TraceIngestThread TraceReader { set; get; } = null;
		public ProcessRecord ProcessData { private set; get; } = null;
		public TraceRecord TraceData { private set; get; } = null;

		//used to keep a blocking extern highlighted - may not be useful with new method TODO
		private uint latest_active_node_idx = 0;
		public DateTime ConstructedTime { private set; get; } = DateTime.Now;

		//private bool loadNodes(const rapidjson::Value& nodesArray, Dictionary<ulong, List<InstructionData>> disassembly);
		

		/*
		private bool loadExceptions(const rapidjson::Value& exceptionsArray);
	private bool loadStats(const rapidjson::Value& graphData);
	private bool loadAnimationData(const rapidjson::Value& replayArray);
	private bool loadCallData(const rapidjson::Value& graphData);


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
		public void insert_node(uint targVertID, node_data node);
		public bool edge_exists(NODEPAIR edge, edge_data** edged);
		public void add_edge(edge_data e, node_data &source, node_data &target);

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

		public List<node_data> nodeList; //node id to node data
		public List<block_data> blockList; //node id to node data

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

		//list of all external nodes
		List<uint> externalNodeList;
		List<uint> copyExternalNodeList();

		//list of all internal nodes with symbols
		List<uint> internalNodeList;
		List<uint> copyInternalNodeList();
		*/
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
		node_data* safe_get_node(uint index);

		bool loadEdgeDict(const rapidjson::Value& edgeArray);
	

		void push_anim_update(ANIMATIONENTRY);
		//animation data received from target
		List<ANIMATIONENTRY> savedAnimationData;

		//todo rename
		List<uint> exceptionSet;

		void assign_modpath();

		public ulong BacklogOutgoing = 0;
		public ulong BacklogIncoming = 0;

		ulong get_backlog_total();

		void set_loop_state(int loopState_, ulong loopIterations_);
		void dump_loop();

		*/

		bool terminationFlag = false;
		//bool serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		//bool deserialise(const rapidjson::Value& graphData, Dictionary<ulong, List<InstructionData>> disassembly);
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
			active = false;
			finalNodeID = lastVertID;
		}

		//void start_edgeL_iteration(EDGELIST::iterator* edgeIt, EDGELIST::iterator* edgeEnd);
		//void stop_edgeL_iteration();

		bool active = true;
	}
}
