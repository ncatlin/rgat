using Gee.External.Capstone;
using Gee.External.Capstone.X86;
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

            if (!LoadModules((JObject)processDataJSON))
            {
                Console.WriteLine("[rgat]ERROR: Failed to load module paths");
                return false;
            }

            if (!LoadSymbols((JObject)processDataJSON))
            {
                Console.WriteLine("[rgat]ERROR: Failed to load symbols");
                return false;
            }

            if (!LoadDisassembly((JObject)processDataJSON))
            {
                Console.WriteLine("[rgat]ERROR: Disassembly reconstruction failed");
                return false;
            }
            /*
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
        public Dictionary<ulong, List<InstructionData>> disassembly = new Dictionary<ulong, List<InstructionData>>();
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

        private bool LoadSymbols(JObject processJSON)
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
                if (!item.TryGetValue("ModuleID", out JToken modID) || modID.Type != JTokenType.Integer)
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

        private bool LoadModules(JObject processJSON)
        {
            //display_only_status_message("Loading Modules", clientState);
            Console.WriteLine("[rgat]Loading Module Paths");
            if (!processJSON.TryGetValue("ModulePaths", out JToken moduleslist))
            {
                Console.WriteLine("[rgat] Failed to find ModulePaths in trace");
                return false;
            }

            var modulesArray = moduleslist.ToObject<List<Dictionary<string, string>>>();

            Console.WriteLine("Loading " + modulesArray.Count + " modules");
            foreach (Dictionary<string, string> entry in modulesArray)
            {
                if (!entry.TryGetValue("B64", out string b64Value))
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

        struct ADDRESS_DATA
        {
            public ulong address;
            public int moduleID;
            public bool hasSym;
        };


        //for disassembling saved instructions
        //takes a capstone context, opcode string, target instruction data struct and the address of the instruction
        int DisassembleIns(CapstoneX86Disassembler disassembler, ref InstructionData insdata)
        {
            X86Instruction[] instructions = disassembler.Disassemble(insdata.opcodes);
            //todo: catch some kind of exception, since i cant see any way of getting error codes
            if (instructions.Length != 1)
            {
                Console.WriteLine("[rgat]ERROR: Failed disassembly for opcodes: " + insdata.opcodes);// << " error: " << cs_errno(hCapstone) << endl;
                return 0;
            }

            X86Instruction insn = instructions[0];

            insdata.mnemonic = insn.Mnemonic;
            insdata.op_str = insn.Operand;
            insdata.ins_text = insdata.mnemonic + " " + insdata.op_str;

            if (insdata.mnemonic == "call")
            {
                try
                {
                    insdata.branchAddress = ulong.Parse(insdata.op_str);
                    //insdata->branchAddress = std::stoull(insdata->op_str, 0, 16);
                }
                catch
                {
                    insdata.branchAddress = 0;
                }
                insdata.itype = eNodeType.eInsCall;
            }

            else if (insdata.mnemonic == "ret") //todo: iret
            {
                insdata.itype = eNodeType.eInsReturn;
            }
            else if (insdata.mnemonic == "jmp")
            {
                try { insdata.branchAddress = ulong.Parse(insdata.op_str); } //todo: not a great idea actually... just point to the outgoing neighbours for labels
                catch { insdata.branchAddress = 0; }
                insdata.itype = eNodeType.eInsJump;
            }
            else
            {
                insdata.itype = eNodeType.eInsUndefined;
                //assume all j+ instructions aside from jmp are conditional (todo: bother to check)
                if (insdata.mnemonic[0] == 'j')
                {
                    insdata.conditional = true;
                    try { insdata.branchAddress = ulong.Parse(insdata.op_str); } //todo: not a great idea actually... just point to the outgoing neighbours for labels
                    catch { insdata.branchAddress = 0; }
                    insdata.condDropAddress = insdata.address + (ulong)insdata.numbytes;
                }

            }
            return instructions.Length;
        }

        private bool UnpackOpcodes(JArray mutationData, CapstoneX86Disassembler disassembler, ADDRESS_DATA addressData, out List<InstructionData> opcodeVariants)
        {
            opcodeVariants = new List<InstructionData>();
            foreach (JArray mutation in mutationData)
            {
                if (mutation.Count != 2 || mutation[0].Type != JTokenType.String || mutation[1].Type != JTokenType.Array)
                {
                    Console.WriteLine("[rgat]Load Error: Bad mutation entry");
                    opcodeVariants = null;
                    return false;
                }

                InstructionData ins = new InstructionData();
                ins.globalmodnum = addressData.moduleID;
                ins.hasSymbol = addressData.hasSym;
                ins.opcodes = System.Convert.FromBase64String(mutation[0].ToObject<string>());
                ins.numbytes = ins.opcodes.Length;
                ins.address = addressData.address;

                if (ins.numbytes == 0)
                {
                    Console.WriteLine("[rgat]Load Error: Empty opcode string");
                    opcodeVariants = null;
                    return false;
                }

                DisassembleIns(disassembler, ref ins);

                JArray threadNodes = (JArray)mutation[1];

                ins.threadvertIdx = new Dictionary<uint, uint>();
                foreach (JArray entry in threadNodes.Children())
                {
                    if (entry.Count != 2 || entry[0].Type != JTokenType.Integer || entry[1].Type != JTokenType.Integer)
                    {
                        Console.WriteLine("[rgat] Load Error: Bad thread nodes entry");
                        return false;
                    }

                    uint excutingThread = entry[0].ToObject<uint>();
                    uint GraphVertID = entry[1].ToObject<uint>();
                    ins.threadvertIdx.Add(excutingThread, GraphVertID);
                }
                
                opcodeVariants.Add(ins);

            }
            return true;
        }

        bool UnpackAddress(JArray entry, CapstoneX86Disassembler disassembler)
        {
            if (entry.Type != JTokenType.Array || entry.Count != 3 ||
                       entry[0].Type != JTokenType.Integer ||
                       entry[1].Type != JTokenType.Integer ||
                       entry[2].Type != JTokenType.Array
                       )
            {
                Console.WriteLine("[rgat] Invalid disassembly entry in trace");
                return false;
            }

            ADDRESS_DATA addrData = new ADDRESS_DATA();
            addrData.address = entry[0].ToObject<ulong>();
            addrData.moduleID = entry[1].ToObject<int>();

            addrData.hasSym = (modsymsPlain.ContainsKey(addrData.moduleID) &&
                                modsymsPlain[addrData.moduleID].ContainsKey(addrData.address));

            JArray mutationData = (JArray)entry[2];

            if (!UnpackOpcodes(mutationData, disassembler, addrData, out List<InstructionData> opcodeVariants))
            {
                Console.WriteLine("[rgat] Invalid disassembly for opcodes");
                return false;
            }
            disassembly.Add(addrData.address, opcodeVariants);
            return true;
        }

        bool LoadDisassembly(JObject processJSON)
        {
            if (!processJSON.TryGetValue("BitWidth", out JToken tBitWidth) || tBitWidth.Type != JTokenType.Integer)
            {
                Console.WriteLine("[rgat] Failed to find valid BitWidth in trace");
                return false;
            }
            bitwidth = tBitWidth.ToObject<int>();
            if (bitwidth != 32 && bitwidth != 64)
            {
                Console.WriteLine("[rgat] Invalid BitWidth " + bitwidth);
                return false;
            }

            if (!processJSON.TryGetValue("Disassembly", out JToken disassemblyList) || disassemblyList.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid Disassembly in trace");
                return false;
            }
            JArray DisassemblyArray = (JArray)disassemblyList;

            Console.WriteLine("[rgat]Loading Disassembly for " + DisassemblyArray.Count + " addresses");
            //display_only_status_message("", clientState);

            X86DisassembleMode disasMode = (bitwidth == 32) ? X86DisassembleMode.Bit32 : X86DisassembleMode.Bit64;
            using (CapstoneX86Disassembler disassembler = CapstoneDisassembler.CreateX86Disassembler(disasMode))
            {
                foreach (JArray entry in DisassemblyArray)
                {
                    if (!UnpackAddress(entry, disassembler)) return false;
                }
            }

            return true;
        }


        /*
        private bool loadBlockData(JObject processJSON);
        private bool loadExterns(JObject processJSON);

        */


        private bool running = true;
        private bool killed = false;
        public bool dieFlag = false;
    }
}
