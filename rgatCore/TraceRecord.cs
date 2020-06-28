using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace rgatCore
{
    struct InstructionData
    {

        //void* bb_ptr;
        public string mnemonic;
        public string op_str;
        //store all the basic blocks this instruction is a member of
        //List<Tuple<ulong, BLOCK_IDENTIFIER>> blockIDs;
        /* memory/speed tradeoff 
		1.construct every frame and save memory 
		2.construct at disassemble time and improve render speed
		*/


        public string ins_text;
        public eNodeType itype;
        public bool conditional;
        bool dataEx;
        public bool hasSymbol;

        public ulong address;
        public ulong branchAddress;
        public ulong condDropAddress;
        public Dictionary<uint, uint> threadvertIdx; //was an unordered dictionary in the C++ version
        public int globalmodnum;
        uint mutationIndex;

        //this was added later, might be worth ditching other stuff in exchange
        public byte[] opcodes;
        public int numbytes;

    }

    class TraceRecord
    {
        public enum eTracePurpose { eVisualiser, eFuzzer };
        public TraceRecord(uint newPID, uint randomNo, BinaryTarget binary, DateTime timeStarted, eTracePurpose purpose = eTracePurpose.eVisualiser)
        {
            PID = newPID;
            randID = randomNo;
            launchedTime = timeStarted;
            TraceType = purpose;

            //modIDTranslationVec.resize(255, -1);

            binaryPtr = binary;
            DisassemblyData = new ProcessRecord(binary.BitWidth);
            //DisassemblyData->modBounds.resize(255, null);
        }

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
        public bool load(Newtonsoft.Json.Linq.JObject saveJSON)//, List<QColor> &colours);
        {
            if (!DisassemblyData.load(saveJSON)) //todo - get the relevant dynamic bit for this trace
            {
                Console.WriteLine("[rgat]ERROR: Process data load failed");
                return false;
            }

            Console.WriteLine("[rgat]Loaded process data. Loading graphs...");


            if (!LoadProcessGraphs(saveJSON))//, colours))//.. &config.graphColours))
            {
                Console.WriteLine("[rgat]Process Graph load failed");
                return false;
            }
            /*
			if (!loadTimeline(saveJSON))
			{
				Console.WriteLine("[rgat]Timeline load failed");
				return false;
			}
			*/
            return true;
        }



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
		int find_containing_module(ulong address, int &localmodID);
		*/
        Dictionary<uint, ProtoGraph> ProtoGraphs = new Dictionary<uint, ProtoGraph>();
        Dictionary<uint, PlottedGraph> PlottedGraphs = new Dictionary<uint, PlottedGraph>();

        public eTracePurpose TraceType { get; private set; } = eTracePurpose.eVisualiser;

        TraceRecord ParentTrace = null;
        List<TraceRecord> children;
        bool UIRunningFlag = false;
        //void* processThreads = null;
        //void* fuzzRunPtr = null;

        public uint PID { get; private set; }
        uint randID; //to distinguish between processes with identical PIDs

        //index of this vec == client reference to each module. returned value is our static reference to the module
        //needed because each trace drgat can come up with a new ID for each module
        List<long> modIDTranslationVec;
        Dictionary<long, bool> activeMods;

        int loadedModuleCount = 0;


        bool LoadProcessGraphs(JObject processJSON)
        {
            if (!processJSON.TryGetValue("Threads", out JToken jThreads) || jThreads.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid Threads in trace");
                return false;
            }

            JArray ThreadsArray = (JArray)jThreads;
            Console.WriteLine("Loading " + ThreadsArray.Count + " thread graphs");
            //display_only_status_message(graphLoadMsg.str(), clientState);

            foreach (JObject threadObj in ThreadsArray)
            {
                if (!LoadGraph(threadObj))
                {
                    Console.WriteLine("[rgat] Failed to load graph");
                    return false;
                }
            }

            return true;

        }

        bool LoadGraph(JObject jThreadObj)
        {
            if (!jThreadObj.TryGetValue("ThreadID", out JToken tTID) || tTID.Type != JTokenType.Integer)
            {
                Console.WriteLine("[rgat] Failed to find valid ThreadID in thread");
                return false;
            }

            uint GraphThreadID = tTID.ToObject<uint>();
            Console.WriteLine("Loading thread ID " + GraphThreadID.ToString());
            //display_only_status_message("Loading graph for thread ID: " + tidstring, clientState);

            ProtoGraph protograph = new ProtoGraph(this, GraphThreadID);
            ProtoGraphs.Add(GraphThreadID, protograph);
            if (!protograph.Deserialise(jThreadObj, DisassemblyData.disassembly))
                return false;

            CylinderGraph renderedgraph = new CylinderGraph(protograph);//, &colours);

            PlottedGraphs.Add(GraphThreadID, renderedgraph);
            //renderedgraph.initialiseDefaultDimensions();
            //renderedgraph.setAnimated(false);


            protograph.IsActive = false;
            protograph.AssignModulePath();

            return true;
        }




        //private bool loadTimeline(const rapidjson::Value& saveJSON);

        public ProcessRecord DisassemblyData { private set; get; } = null; //the first disassembly of each address

        //private timeline runtimeline;
        private DateTime launchedTime; //the time the user pressed start, not when the first process was seen

        private BinaryTarget binaryPtr = null;
        private bool running = false;
        private bool killed = false;
    }
}
