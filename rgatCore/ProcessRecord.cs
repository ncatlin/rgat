using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class ProcessRecord
    {

        public ProcessRecord(int binaryBitWidth) { bitwidth = binaryBitWidth; }

        /*
		public bool get_sym(uint modNum, ulong mem_addr, string &sym);
		public bool get_modpath(uint modNum, boost::filesystem::path* path);
		//bool get_modbase(uint modNum, ulong &moduleBase);


		public bool get_extern_at_address(ulong address, int moduleNum, ROUTINE_STRUCT** BB);
		public void save(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		*/
        public bool load(JObject tracejson)
        {

            var processDataJSON = tracejson.GetValue("ProcessData");

            if (processDataJSON == null)
            {
                Console.WriteLine("[rgat]ERROR: Process data load failed");
                return false;
            }

            if (!loadModules((JObject)processDataJSON))
            {
                Console.WriteLine("[rgat]ERROR: Failed to load module paths");
                return false;
            }
            
			if (!loadSymbols((JObject)processDataJSON))
			{
                Console.WriteLine("[rgat]ERROR: Failed to load symbols");
				return false;
			}

            /*
			if (!loadDisassembly(processDataJSON))
			{
				cerr << "[rgat]ERROR: Disassembly reconstruction failed" << endl;
				return false;
			}
			if (!loadBlockData(processDataJSON))
			{
				cerr << "[rgat]ERROR: Basic block reconstruction failed" << endl;
				return false;
			}

			if (!loadExterns(processDataJSON))
			{
				cerr << "[rgat]ERROR: Extern call loading failed" << endl;
				return false;
			}
			*/
            return true;

        }
        
		//public INSLIST* getDisassemblyBlock(ulong blockaddr, BLOCK_IDENTIFIER blockID, ROUTINE_STRUCT** externBlock);
		//public int find_containing_module(ulong address);

		public List<string> LoadedModulePaths = new List<string>();
        public List<Tuple<ulong, ulong>> LoadedModuleBounds = new List<Tuple<ulong, ulong>>();
        public Dictionary<string, long> globalModuleIDs = new Dictionary<string, long>();
		public Dictionary<int, Dictionary<ulong, string>> modsymsPlain = new Dictionary<int, Dictionary<ulong, string>>();
        /* 
            public ulong instruction_before(ulong addr);

            public Tuple<ulong, BLOCK_DESCRIPTOR*> blockDetails(BLOCK_IDENTIFIER blockid);
            public ulong numBlocksSeen() { return blockList.size(); }
            //must already have disassembly write lock
            public void addBlock_HaveLock(ulong addr, BLOCK_DESCRIPTOR* blk) { blockList.push_back(make_pair(addr, blk)); }
            */
        //maps instruction addresses to all data about it
        public Dictionary<ulong, List<InstructionData>> disassembly;
        //useful for mapping return addresses to callers without a locking search
        public Dictionary<ulong, ulong> previousInstructionsCache;

        //list of basic blocks
        //   address		    blockID			instructionlist
        //map <ulong, Dictionary<BLOCK_IDENTIFIER, INSLIST *>> addressBlockMap;
        public List<Tuple<ulong, List<InstructionData>>> blockList;


        public Dictionary<ulong, ROUTINE_STRUCT> externdict;
        public int bitwidth;

        /*
	private void saveDisassembly(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveExternDict(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveBlockData(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveMetaData(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveModules(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
		private void saveSymbols(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
        */

		private bool loadSymbols(JObject processJSON)
         {
            Console.WriteLine("[rgat]Loading Module Symbols");
            //display_only_status_message(symLoadMsg.str(), clientState);

            if (!processJSON.TryGetValue("ModuleSymbols", out JToken symbolslist) || symbolslist.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid ModuleSymbols in trace");
                return false;
            }

            ulong totalSyms = 0;
            foreach (JObject item in symbolslist.Children())
            {
               if(!item.TryGetValue("ModuleID", out JToken modID) || modID.Type != JTokenType.Integer)
                {
                    Console.WriteLine("[rgat]ERROR: Symbols load failed: No valid module ID");
                    return false;
                }
                modsymsPlain.Add(modID.ToObject<int>(), new Dictionary<ulong, string>());

                if (!item.TryGetValue("Symbols", out JToken syms) || syms.Type != JTokenType.Array)
                {
                    Console.WriteLine("[rgat]ERROR: Symbols load failed: No valid symbols list");
                    return false;
                }
                foreach (JArray sym in syms.Children())
                {
                    if (sym.Count != 2 || sym[0].Type != JTokenType.Integer || sym[1].Type != JTokenType.String)
                    {
                        Console.WriteLine("[rgat]ERROR: Symbols load failed: Bad symbol in list");
                        return false;
                    }
                    ulong SymAddress = sym[0].ToObject<ulong>();
                    string SymName = sym[1].ToObject<string>();

                    modsymsPlain[modID.ToObject<int>()][SymAddress] = SymName;
                    totalSyms += 1;
                }
            }
            Console.WriteLine("[rgat]Finished loading " + totalSyms + " symbols");
            return true;
        }
		
        private bool loadModules(JObject processJSON)
        {
            //display_only_status_message("Loading Modules", clientState);
            Console.WriteLine("[rgat]Loading Module Paths");
            if (!processJSON.TryGetValue("ModulePaths", out JToken moduleslist))
            {
                Console.WriteLine("[rgat] Failed to find ModulePaths in trace");
                return false;
            }



            //display_only_status_message(pathLoadMsg.str(), clientState);
            var modulesArray = moduleslist.ToObject<List<Dictionary<string, string>>>();

            Console.WriteLine("Loading " + modulesArray.Count + " modules");
            foreach (Dictionary<string, string> entry in modulesArray)
            {
                if(!entry.TryGetValue("B64", out string b64Value))
                {
                    Console.WriteLine("[rgat]ERROR: Module Paths load failed: No path string");
                    return false;
                }

                string plainpath = System.Convert.FromBase64String(b64Value).ToString();
                LoadedModulePaths.Add(plainpath);
            }




            if (!processJSON.TryGetValue("ModuleBounds", out Newtonsoft.Json.Linq.JToken modulebounds))
            {
                Console.WriteLine("[rgat] Failed to find ModuleBounds in trace");
                return false;
            }
            var modsBoundArray = modulebounds.ToObject<List<List<ulong>>>();
            LoadedModuleBounds.Clear();

            foreach (List<ulong> entry in modsBoundArray)
            {
                LoadedModuleBounds.Add(new Tuple<ulong, ulong>(entry[0], entry[1]));
            }
            return true;
        }

        /*
        private bool loadDisassembly(const rapidjson::Value& saveJSON);
        private bool loadBlockData(const rapidjson::Value& saveJSON);
        private bool loadExterns(const rapidjson::Value& processDataJSON);

        private bool unpackModuleSymbolArray(const rapidjson::Value& modSymArray, int globalmodNum);
            */


        private bool running = true;
        private bool killed = false;
        public bool dieFlag = false;
    }
}
