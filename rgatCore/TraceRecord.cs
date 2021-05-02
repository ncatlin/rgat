using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace rgatCore
{
    struct InstructionData
    {
        public int DebugID;

        //void* bb_ptr;
        public string mnemonic;
        public string op_str;
        //store all the basic blocks this instruction is a member of
        //List<Tuple<ulong, BLOCK_IDENTIFIER>> blockIDs;
        /* memory/speed tradeoff 
		1.construct every frame and save memory 
		2.construct at disassemble time and improve render speed
		*/
        //store all the basic blocks this instruction is a member of
        public List<uint> ContainingBlockIDs;

        public string ins_text;
        public eNodeType itype;
        public bool conditional;
        public bool dataEx;
        public bool hasSymbol;

        public ulong address;
        public ulong branchAddress;
        public ulong condDropAddress;
        public Dictionary<uint, uint> threadvertIdx; //was an unordered dictionary in the C++ version
        public int globalmodnum;
        public int mutationIndex;

        public bool BlockBoundary;

        //this was added later, might be worth ditching other stuff in exchange
        public byte[] opcodes;
        public int numbytes;

    }

    class TraceRecord
    {
        public enum eTracePurpose { eVisualiser, eFuzzer };
        public enum eTraceState { eRunning, eSuspended, eTerminated };


        public TraceRecord(uint newPID, long randomNo, BinaryTarget binary, DateTime timeStarted, eTracePurpose purpose = eTracePurpose.eVisualiser, int arch = 0)
        {
            PID = newPID;
            randID = randomNo;
            launchedTime = timeStarted;
            TraceType = purpose;

            //modIDTranslationVec.resize(255, -1);

            binaryTarg = binary;
            if (arch != 0 && binary.BitWidth != arch)
            {
                binary.BitWidth = arch;
            }

            DisassemblyData = new ProcessRecord(binary.BitWidth);
            TraceState = eTraceState.eRunning;
        }

        bool _loadedFromSave = false;
        public bool WasLoadedFromSave => _loadedFromSave;

        string getModpathID() { return PID.ToString() + randID.ToString(); }
        /*
		void notify_new_pid(uint pid, int PID_ID, uint parentPid) { runtimeline.notify_new_pid(pid, PID_ID, parentPid); running = true; }
		void notify_pid_end(uint pid, int PID_ID) { running = runtimeline.notify_pid_end(pid, PID_ID); }
		void notify_tid_end(uint tid) { runtimeline.notify_thread_end(getPID(), randID, tid); }
		*/

        public void SetTraceState(eTraceState newState)
        {
            if (TraceState == newState) return;
            if (newState != eTraceState.eSuspended)
            {

                lock (GraphListLock)
                {
                    foreach (ProtoGraph graph in ProtoGraphs.Values)
                    {
                        graph.ClearRecentStep();
                    }
                }
            }
            TraceState = newState;
            
        }

        public bool InsertNewThread(PlottedGraph mainplot)
        {
            lock (GraphListLock)
            {

                if (ProtoGraphs.ContainsKey(mainplot.tid))
                {
                    Console.WriteLine("Warning - thread with duplicate ID detected. This should never happen. Undefined behaviour ahoy.");
                    return false;
                }

                ProtoGraphs.Add(mainplot.tid, mainplot.internalProtoGraph);
                PlottedGraphs.Add(mainplot.tid, new Dictionary<eRenderingMode, PlottedGraph>());
                PlottedGraphs[mainplot.tid][eRenderingMode.eStandardControlFlow] = mainplot;

                //runtimeline.notify_new_thread(getPID(), randID, TID);
            }
            Console.WriteLine("Todo implement runtimeline");
            return true;
        }


        //bool is_process(uint testpid, int testID);



        public PlottedGraph GetFirstGraph()
        {
            if (PlottedGraphs.Count == 0) return null;

            //if (graphListLock.trylock())
            var MainPlottedGraphs = GetPlottedGraphsList(eRenderingMode.eStandardControlFlow);
            var graphsWithNodes = MainPlottedGraphs.Where(g => g?.internalProtoGraph.NodeList.Count > 0);
            if (graphsWithNodes.Any())
            {
                return graphsWithNodes.First();
            }

            var graphsWithInstructions = MainPlottedGraphs.Where(g => g.internalProtoGraph.TotalInstructions > 0);
            if (graphsWithInstructions.Any())
            {
                return graphsWithInstructions.First();
            }

            var graphsWithData = MainPlottedGraphs.Where(g => g.internalProtoGraph.TraceReader.HasPendingData());
            if (graphsWithData.Any())
            {
                return graphsWithData.First();
            }

            return MainPlottedGraphs.First();

        }
        /*

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
            _loadedFromSave = true;
            TraceState = eTraceState.eTerminated;
            return true;
        }



        /*
		void serialiseThreads(rapidjson::Writer<rapidjson::FileWriteStream> &writer);
		void serialiseTimeline(rapidjson::Writer<rapidjson::FileWriteStream> &writer) { runtimeline.serialise(writer); };
		*/
        void killTraceProcess() { if (IsRunning) { killed = true; } }
        bool should_die() { return killed; }

        //void killTree();

        public eCodeInstrumentation FindContainingModule(ulong address, out int localmodID)
        {
            localmodID = DisassemblyData.FindContainingModule(address);
            if (localmodID == -1)
            {

                Console.WriteLine($"Warning: Unknown module in traceRecord::FindContainingModule for address 0x{address:X}");
                int attempts = 1;
                while (attempts-- != 0)
                {
                    Thread.Sleep(30);
                    localmodID = DisassemblyData.FindContainingModule(address);
                    if (localmodID != -1)
                    {
                        Console.WriteLine("found!");

                        break;
                    }
                }

                return eCodeInstrumentation.eUninstrumentedCode;
                //assert(localmodID != -1);
            }

            return DisassemblyData.ModuleTraceStates[localmodID];
        }

        private readonly object GraphListLock = new object();
        Dictionary<uint, ProtoGraph> ProtoGraphs = new Dictionary<uint, ProtoGraph>();

        public Dictionary<uint, Dictionary<eRenderingMode, PlottedGraph>> PlottedGraphs = new Dictionary<uint, Dictionary<eRenderingMode, PlottedGraph>>();

        public List<PlottedGraph> GetPlottedGraphsList(eRenderingMode mode)
        {
            lock (GraphListLock)
            {
                return PlottedGraphs.Values.Select(gDict => gDict.ContainsKey(mode) ? gDict[mode] : null).ToList();
            }
        }

        public eTracePurpose TraceType { get; private set; } = eTracePurpose.eVisualiser;

        public TraceRecord ParentTrace = null;
        public List<TraceRecord> children = new List<TraceRecord>();

        public RGAT_THREADS_STRUCT ProcessThreads;
        //void* fuzzRunPtr = null;

        public uint PID { get; private set; }
        public long randID { get; private set; } //to distinguish between processes with identical PIDs

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
            lock (GraphListLock)
            {
                ProtoGraphs.Add(GraphThreadID, protograph);
            }

            try
            {
                if (!protograph.Deserialise(jThreadObj, DisassemblyData.disassembly))
                    return false;
            }
            catch (Exception e)
            {
                Console.WriteLine("Deserialising trace file failed: "+e.Message);
                return false;
            }

            //CylinderGraph standardRenderedGraph = new CylinderGraph(protograph, GlobalConfig.defaultGraphColours);
            PlottedGraph standardRenderedGraph = new PlottedGraph(protograph, GlobalConfig.defaultGraphColours);
            standardRenderedGraph.SetAnimated(false);


            lock (GraphListLock)
            {
                PlottedGraphs.Add(GraphThreadID, new Dictionary<eRenderingMode, PlottedGraph>());
                PlottedGraphs[GraphThreadID].Add(eRenderingMode.eStandardControlFlow, standardRenderedGraph);
            }
            protograph.Terminated = true;
            protograph.AssignModulePath();

            return true;
        }


        /// <summary>
        /// Save all the data needed to reconstruct a process run and all its thread graphs
        /// Recursively saves child processes
        /// </summary>
        /// <param name="traceStartedTime">The time the run was started</param>
        /// <returns>The path the trace was saved to</returns>
        public string Save(DateTime traceStartedTime)
        {
            Console.WriteLine($"Saving trace {binaryTarg.FilePath} -> PID {PID}");
            if (TraceType != eTracePurpose.eVisualiser)
            {
                Console.WriteLine("\tSkipping non visualiser trace");
                return "";
            }

            JsonTextWriter wr = CreateSaveFile(traceStartedTime);
            if (wr == null)
            {
                Console.WriteLine("\tSaving Failed: Unable to create filestream");
                return "";
            }

            JObject traceSaveObject = new JObject();
            traceSaveObject.Add("PID", PID);
            traceSaveObject.Add("PID_ID", randID);
            traceSaveObject.Add("ProcessData", DisassemblyData.Serialise());
            traceSaveObject.Add("BinaryPath", binaryTarg.FilePath);
            traceSaveObject.Add("StartTime", traceStartedTime);
            traceSaveObject.Add("Threads", SerialiseGraphs());
            traceSaveObject.Add("Timeline", SerialiseTimeline() );

            JArray childPathsArray = new JArray();
            foreach (TraceRecord trace in children)
            {
                string childpath = trace.Save(trace.launchedTime);
                if (childpath.Length > 0)
                    childPathsArray.Add(childpath);
            }
            traceSaveObject.Add("Children", childPathsArray);

            traceSaveObject.WriteTo(wr);
            wr.Close();

            Console.WriteLine("Trace Save Complete");
            return wr.Path;
        }

        JArray SerialiseGraphs()
        {
            JArray graphsList = new JArray();

            lock(GraphListLock)
            {
                foreach (var tid__mode_graph in PlottedGraphs)
                {
                    if (tid__mode_graph.Value.Count == 0) continue;
                    ProtoGraph protograph = tid__mode_graph.Value[0].internalProtoGraph;
                    if (protograph.NodeList.Count == 0) continue;

                    graphsList.Add(protograph.Serialise());
                }
            }

            return graphsList;
        }


        JObject SerialiseTimeline()
        {

            JObject timeline = new JObject();
            return timeline;
        }


        JsonTextWriter CreateSaveFile(DateTime startedTime)
        {
            string saveFilename = $"{binaryTarg.FileName}-{PID}-{startedTime.ToString("MMM-dd__HH-mm-ss")}.rgat";
            if (!Directory.Exists(GlobalConfig.SaveDirectory))
            {
                GlobalConfig.SaveDirectory = Path.Join(Directory.GetCurrentDirectory(), "saves");
            }
            if (!Directory.Exists(GlobalConfig.SaveDirectory))
            {
                Console.WriteLine("\tWarning: Failed to save - directory " + GlobalConfig.SaveDirectory + " does not exist");
                return null;
            }

            string path = Path.Join(GlobalConfig.SaveDirectory, saveFilename);
            try
            {
                StreamWriter sw = File.CreateText(path);

                return (new JsonTextWriter(sw));
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine($"\tWarning: Unauthorized to open {path} for writing");
                return null;
            }
            catch
            {
                Console.WriteLine($"\tWarning: Failed to open {path} for writing");
                return null;
            }

            return null;
        }

        //private bool loadTimeline(const rapidjson::Value& saveJSON);


        public  void ExportPajek(uint TID)
        {
            ProtoGraph pgraph = this.ProtoGraphs[TID];

            FileStream outfile = File.OpenWrite(Path.Combine(GlobalConfig.SaveDirectory, "pajeksave" + TID.ToString() + ".net"));
            outfile.Write(Encoding.ASCII.GetBytes("%*Colnames \"Disassembly\"\n"));
            outfile.Write(Encoding.ASCII.GetBytes("*Vertices "+pgraph.NodeList.Count+"\n"));

            foreach (NodeData n in pgraph.NodeList)
            {
                outfile.Write(Encoding.ASCII.GetBytes(n.index+" \""+n.ins.ins_text+"\"\n"));
            }

            outfile.Write(Encoding.ASCII.GetBytes("*edgeslist " + pgraph.NodeList.Count + "\n"));
            foreach (NodeData n in pgraph.NodeList)
            {
                outfile.Write(Encoding.ASCII.GetBytes(n.index + " "));
                foreach (int nodeidx in n.OutgoingNeighboursSet)
                {
                    outfile.Write(Encoding.ASCII.GetBytes(nodeidx.ToString() + " "));
                }
                outfile.Write(Encoding.ASCII.GetBytes("\n"));
            }
            outfile.Close();
        }

        public void SendDebugCommand(ulong threadID, string command)
        {
            if (_moduleThread == null)
            {
                Console.WriteLine("Error: DBG command send to trace with no active module thread");
                return;
            }

            byte[] buf = System.Text.Encoding.ASCII.GetBytes(command+'@'+threadID.ToString()+"\n\x00");
            if(_moduleThread.SendCommand(buf) == -1)
            {
                Console.WriteLine("Error sending command to control pipe");
            }
        }


        public ProcessRecord DisassemblyData { private set; get; } = null; //the first disassembly of each address

        //private timeline runtimeline;
        public DateTime launchedTime { private set; get; } //the time the user pressed start, not when the first process was seen

        public BinaryTarget binaryTarg { private set; get; } = null;
        public bool IsRunning => TraceState != eTraceState.eTerminated;
        private bool killed = false;

        public eTraceState TraceState { private set; get; } = eTraceState.eTerminated;

        ModuleHandlerThread _moduleThread;
        BlockHandlerThread _blockThread;
        public void SetModuleHandlerThread(ModuleHandlerThread moduleHandlerObj) => _moduleThread = moduleHandlerObj;
        public void SetBlockHandlerThread(BlockHandlerThread blockHandlerObj) => _blockThread = blockHandlerObj;
    }
}
