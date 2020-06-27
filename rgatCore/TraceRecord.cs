using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
	struct InstructionData
    {
		/*
		void* bb_ptr;
		string mnemonic;
		string op_str;
		//store all the basic blocks this instruction is a member of
		List<Tuple<ulong, BLOCK_IDENTIFIER>> blockIDs;
		/* memory/speed tradeoff 
		1.construct every frame and save memory 
		2.construct at disassemble time and improve render speed
		*/

		/*
		string ins_text;
		eNodeType itype;
		bool conditional = false;
		bool dataEx = false;
		bool hasSymbol = false;

		ulong address;
		ulong branchAddress = NULL;
		ulong condDropAddress;
		unordered_Dictionary<PID_TID, uint> threadvertIdx;
		uint globalmodnum;
		uint mutationIndex;

		//this was added later, might be worth ditching other stuff in exchange
		std::unique_ptr<uint8_t[]> opcodes;
		uint numbytes;
		*/
	}


	class TraceRecord
    {
		enum eTracePurpose { eVisualiser, eFuzzer };
		public TraceRecord(uint newPID, int randomNo, BinaryTarget binary, DateTime timeStarted)
        {
			PID = newPID;
			randID = randomNo;
			launchedTime = timeStarted;

			//modIDTranslationVec.resize(255, -1);

			binaryPtr = binary;
			DisassemblyData = new ProcessRecord(binary.BitWidth);
			//DisassemblyData->modBounds.resize(255, null);
		}

		uint getPID() { return PID; }
		string getModpathID() { return PID.ToString() + randID.ToString(); }
		BinaryTarget get_binaryPtr() { return binaryPtr; }

		/*
		void notify_new_pid(uint pid, int PID_ID, uint parentPid) { runtimeline.notify_new_pid(pid, PID_ID, parentPid); running = true; }
		void notify_pid_end(uint pid, int PID_ID) { running = runtimeline.notify_pid_end(pid, PID_ID); }
		void notify_tid_end(uint tid) { runtimeline.notify_thread_end(getPID(), randID, tid); }
		
		bool insert_new_thread(uint TID, PlottedGraph graph_plot, PROTOGRAPH_CASTPTR graph_proto);
		bool is_process(uint testpid, int testID);
		
		
		PlottedGraph get_first_graph()
        {
			if (PlottedGraphs.empty()) return null;

			if (graphListLock.trylock())
			{
				void* result = NULL;
				for (auto it = plottedGraphs.begin(); it != plottedGraphs.end(); it++)
				{
					PlottedGraph graph = (PlottedGraph)it->second;
					if (!graph->get_protoGraph()->nodeList.empty())
					{
						result = graph;
						graph->increase_thread_references(33);
						std::cout << graph->main_scalefactors->stretchA << std::endl;
						break;
					}
				}

				graphListLock.unlock();

				return result;
			}
			return NULL;
		}
		*/

		DateTime getStartedTime() { return launchedTime; }

		/*
		void getPlottedGraphs(void* graphPtrVecPtr);
		void getProtoGraphs(void* graphPtrVecPtr);
		bool isRunning() { return running; }
		int countDescendants();
	
		void save(void* clientConfigPtr);
		*/
		//bool load(const rapidjson::Document& saveJSON, List<QColor> &colours);
		/*
		void serialiseThreads(rapidjson::Writer<rapidjson::FileWriteStream> &writer);
		void serialiseTimeline(rapidjson::Writer<rapidjson::FileWriteStream> &writer) { runtimeline.serialise(writer); };
		*/
		void killTraceProcess() { if (running) { killed = true; } }
		bool should_die() { return killed; }
		bool is_running() { return running; }
		void set_running(bool r) { running = r; }
		/*
		void killTree();
		void setTraceType(eTracePurpose purpose);
		eTracePurpose getTraceType() { return tracetype; }
		int find_containing_module(ulong address, int &localmodID);
		*/
		Dictionary<uint, ProtoGraph> ProtoGraphs;
		Dictionary<uint, PlottedGraph> PlottedGraphs;

		TraceRecord ParentTrace = null;
		List<TraceRecord> children;
		bool UIRunningFlag = false;
		//void* processThreads = null;
		//void* fuzzRunPtr = null;

		uint PID;
		int randID; //to distinguish between processes with identical PIDs

		//index of this vec == client reference to each module. returned value is our static reference to the module
		//needed because each trace drgat can come up with a new ID for each module
		List<long> modIDTranslationVec;
		Dictionary<long, bool> activeMods;

		int loadedModuleCount = 0;

		/*
		private bool loadProcessGraphs(const rapidjson::Document& saveJSON, List<QColor> &colours);
		private bool loadGraph(const rapidjson::Value& graphData, List<QColor> &colours);
		private bool loadTimeline(const rapidjson::Value& saveJSON);
		*/
		public ProcessRecord DisassemblyData { private set; get; } = null; //the first disassembly of each address

		//private timeline runtimeline;
		private DateTime launchedTime; //the time the user pressed start, not when the first process was seen

		private BinaryTarget binaryPtr = null;
		private bool running = false;
		private bool killed = false;
		private eTracePurpose tracetype;
	}
}
