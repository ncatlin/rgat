﻿using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace rgatCore
{
    class ProcessRecord
    {

        public ProcessRecord(int binaryBitWidth) {
            BitWidth = binaryBitWidth; 
            for (int i = 0; i < 150; i++)
            {
                modIDTranslationVec.Add(-1);
            }
        }

    		//public bool get_modpath(uint modNum, boost::filesystem::path* path);
		//bool get_modbase(uint modNum, ulong &moduleBase);
        

		public void get_extern_at_address(ulong address, int moduleNum, out ROUTINE_STRUCT BB)
        {
            lock (ExternCallerLock)
            {
                if (!externdict.TryGetValue(address, out BB))
                {
                    BB = new ROUTINE_STRUCT();
                    BB.globalmodnum = moduleNum;
                    BB.thread_callers = new Dictionary<uint, List<Tuple<uint, uint>>>();
 
                    externdict.Add(address, BB);
                    
                }
            }
        }
        //public void save(rapidjson::Writer<rapidjson::FileWriteStream>& writer);

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
            
			if (!LoadBlockData((JObject)processDataJSON))
			{
                Console.WriteLine("[rgat]ERROR: Basic block reconstruction failed");
				return false;
			}
            
			if (!loadExterns((JObject)processDataJSON))
			{
				Console.WriteLine("[rgat]ERROR: Extern call loading failed");
				return false;
			}
			
            return true;

        }



        //returns address once it does
        public ulong EnsureBlockExistsGetAddress(uint blockID)
        {
            int timewaited = 0;
            while (true)
            {

                lock (InstructionsLock)
                {
                    if (blockList.Count > blockID && blockList[(int)blockID] != null)
                    {
                        return blockList[(int)blockID].Item1;
                    }
                }
                if (dieFlag) return 0;
                Thread.Sleep(2);
                timewaited += 2;
                if (timewaited > 2500 && (timewaited % 1000)  == 0)
                {
                    Console.WriteLine($"Warning, long wait for block {blockID}. Currently {timewaited/1000}s");
                }

            }
        }

        //is there a better way of doing this?
        public List<InstructionData> getDisassemblyBlock(uint blockID)
        {
            ROUTINE_STRUCT? stub = null;
            return getDisassemblyBlock(blockID, ref stub);
        }
        public List<InstructionData> getDisassemblyBlock(uint blockID, ref ROUTINE_STRUCT? externBlock, ulong externBlockaddr = 0)
        {
            int iterations = 0;

            while (true)
            {
                if (externBlockaddr != 0 || blockID == uint.MaxValue)
                {
                    int moduleNo = FindContainingModule(externBlockaddr);
                    if (ModuleTraceStates[moduleNo] == eCodeInstrumentation.eUninstrumentedCode)
                    {
                        ROUTINE_STRUCT tmpexternBlock;
                        get_extern_at_address(externBlockaddr, moduleNo, out tmpexternBlock);
                        externBlock = tmpexternBlock;
                        return null;
                    }
                }


                if (blockID < blockList.Count)
                {
                    var result = blockList[(int)blockID];
                    if (result != null)
                    {
                        externBlock = null;
                        return result.Item2;
                    }
                }


                if (iterations > 3)
                    Thread.Sleep(1);

                if (iterations++ > 20 && (iterations % 20 == 0))
                    Console.WriteLine($"[rgat]Warning: Long wait for disassembly of block ID {blockID}");

                if (iterations++ > 200)
                { 
                    Console.WriteLine($"[rgat]Warning: Giving up waiting for disassembly of block ID {blockID}");
                    return null;
                }

                if (dieFlag) return null;
            }
        }
        
        public int FindContainingModule(ulong address)
        {
            int numModules = LoadedModuleBounds.Count;
            for (int modNo = 0; modNo < numModules; ++modNo)
            {
                Tuple<ulong, ulong> moduleBounds = LoadedModuleBounds[modNo];
                if (moduleBounds == null) continue;
                if (address >= moduleBounds.Item1 && address <= moduleBounds.Item2)
                {
                    return modNo;
                }
            }

            return -1;
        }




        public void AddModule(int localmodID, string path, ulong start, ulong end, char isInstrumented)
        {
            if (localmodID > 1000)
            {
                Console.WriteLine($"Ignoring strangely huge module id {localmodID} {path}");
                return;
            }


            lock (ModulesLock)
            {
                int globalModID = LoadedModuleCount; //index into our module lists

                LoadedModulePaths.Add(path);
                //globalModuleIDs.Add(path, globalModID); //sharing violation here???

                if (localmodID >= modIDTranslationVec.Count) { for (int i = 0; i < localmodID + 20; i++) modIDTranslationVec.Add(-1); }
                modIDTranslationVec[localmodID] = globalModID; 

                ModuleTraceStates.Add(isInstrumented == '1' ? eCodeInstrumentation.eInstrumentedCode : eCodeInstrumentation.eUninstrumentedCode);
                LoadedModuleBounds.Add(new Tuple<ulong, ulong>(start, end));
                
                LoadedModuleCount += 1;
            }
        }








        public void AddSymbol(int localModnum, ulong offset, string name)
        {
            lock (SymbolsLock)
            {
                int modnum = modIDTranslationVec[localModnum];

                if (!modsymsPlain.ContainsKey(modnum))
                {
                    modsymsPlain.Add(modnum, new Dictionary<ulong, string>());
                }

                if (modsymsPlain[modnum].ContainsKey(offset)){
                    modsymsPlain[modnum][offset] += "/" + name;
                }
                else
                    modsymsPlain[modnum].Add(offset, name);

            }
        }

        public bool SymbolExists(int GlobalModuleNumber, ulong address)
        {
            return modsymsPlain.ContainsKey(GlobalModuleNumber) && modsymsPlain[GlobalModuleNumber].ContainsKey(address);

        }

        public bool GetSymbol(int GlobalModuleNumber, ulong address, out string symbol)
        {
            lock (ModulesLock)
            {
                if (modsymsPlain.ContainsKey(GlobalModuleNumber))
                {
                    ulong offset = address - LoadedModuleBounds[GlobalModuleNumber].Item1;
                    return modsymsPlain[GlobalModuleNumber].TryGetValue(offset, out symbol);
                }
            }
            symbol = "";
            return false;

        }

        public string GetModulePath(int GlobalModuleID)
        {
            lock (ModulesLock)
            {
                return LoadedModulePaths[GlobalModuleID];
            }
        }


        public void AddDisassembledBlock(uint blockID, ulong address, List<InstructionData> instructions)
        {
            //these arrive out of order so have to add some dummy entries
            lock (InstructionsLock)
            {
                if (blockList.Count > blockID)
                { 
                    blockList[(int)blockID] = new Tuple<ulong, List<InstructionData>>(address, instructions);
                    return;
                }

                while (blockList.Count < blockID)
                {
                    blockList.Add(null);
                }
                blockList.Add(new Tuple<ulong, List<InstructionData>>(address, instructions));
            }
        }

        public List<string> LoadedModulePaths = new List<string>();
        public List<int> modIDTranslationVec = new List<int>();
        public List<Tuple<ulong, ulong>> LoadedModuleBounds = new List<Tuple<ulong, ulong>>();
        public List<eCodeInstrumentation> ModuleTraceStates = new List<eCodeInstrumentation>();

        public Dictionary<string, long> globalModuleIDs = new Dictionary<string, long>();
        public int LoadedModuleCount = 0;
        
        //todo review these
        private readonly object ModulesLock = new object();
        public readonly object ExternCallerLock = new object(); //todo stop this being public

        private readonly object SymbolsLock = new object();
        private Dictionary<int, Dictionary<ulong, string>> modsymsPlain = new Dictionary<int, Dictionary<ulong, string>>();
        
            public bool instruction_before(ulong addr, out ulong result)
        {
            const int LARGEST_X86_INSTRUCTION = 15;
{
                //first lookup in cache
                if (previousInstructionsCache.TryGetValue(addr, out result))
                {
                    return true;
                }

                if (disassembly.Count == 0) return false;

                //x86 has variable length instructions so we have to 
                //search backwards, byte by byte
                lock (InstructionsLock)
                {
                    ulong testaddr = 0, addrMinus;
                    for (addrMinus = 1; addrMinus < (LARGEST_X86_INSTRUCTION + 1); addrMinus++)
                    {
                        testaddr = addr - addrMinus;
                        if (disassembly.ContainsKey(testaddr))
                        {
                            break;
                        }
                    }

                    if (addrMinus > LARGEST_X86_INSTRUCTION)
                    {
                        //cerr << "[rgat]Error: Unable to find instruction before 0x" << hex << addr << endl;
                        return false;
                    }

                    previousInstructionsCache.Add(addr, testaddr);
                    result = testaddr;
                    return true;
                }

            }
        }


        /*
            public Tuple<ulong, BLOCK_DESCRIPTOR*> blockDetails(BLOCK_IDENTIFIER blockid);
            public ulong numBlocksSeen() { return blockList.size(); }
            //must already have disassembly write lock
            public void addBlock_HaveLock(ulong addr, BLOCK_DESCRIPTOR* blk) { blockList.push_back(make_pair(addr, blk)); }
            */



        public readonly object InstructionsLock = new object();

        //maps instruction addresses to list of different instructions that resided at that address
        public Dictionary<ulong, List<InstructionData>> disassembly = new Dictionary<ulong, List<InstructionData>>();

        //useful for mapping return addresses to callers without a locking search
        public Dictionary<ulong, ulong> previousInstructionsCache = new Dictionary<ulong, ulong>();

        //list of basic blocks - guarded by instructionslock
        //              address
        public List<Tuple<ulong, List<InstructionData>>> blockList = new List<Tuple<ulong, List<InstructionData>>>();
        //private Dictionary<uint, List<InstructionData>> blockDict = new Dictionary<uint, List<InstructionData>>();

        public Dictionary<ulong, ROUTINE_STRUCT> externdict = new Dictionary<ulong, ROUTINE_STRUCT>();
        public int BitWidth;

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
        public static int DisassembleIns(CapstoneX86Disassembler disassembler, ulong address, ref InstructionData insdata)
        {
            X86Instruction[] instructions = disassembler.Disassemble(insdata.opcodes, (long)address);
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

                    insdata.branchAddress = Convert.ToUInt64(insn.Operand, 16);
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
                insdata.itype = eNodeType.eInsJump;
                try { insdata.branchAddress = Convert.ToUInt64(insdata.op_str, 16); } //todo: not a great idea actually... just point to the outgoing neighbours for labels
                catch { insdata.branchAddress = 0; }

                if (insdata.branchAddress == (address + (ulong)insdata.numbytes))
                {
                    insdata.itype = eNodeType.eInsUndefined; //junp to next address is nop
                }
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

                DisassembleIns(disassembler, addressData.address, ref ins);

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

            ADDRESS_DATA addrData = new ADDRESS_DATA
            {
                address = entry[0].ToObject<ulong>(),
                moduleID = entry[1].ToObject<int>()
            };

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
            BitWidth = tBitWidth.ToObject<int>();
            if (BitWidth != 32 && BitWidth != 64)
            {
                Console.WriteLine("[rgat] Invalid BitWidth " + BitWidth);
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

            X86DisassembleMode disasMode = (BitWidth == 32) ? X86DisassembleMode.Bit32 : X86DisassembleMode.Bit64;
            using (CapstoneX86Disassembler disassembler = CapstoneDisassembler.CreateX86Disassembler(disasMode))
            {
                foreach (JArray entry in DisassemblyArray)
                {
                    if (!UnpackAddress(entry, disassembler)) return false;
                }
            }

            return true;
        }


        
        private bool LoadBlockData(JObject processJSON)
        {
            if (!processJSON.TryGetValue("BasicBlocks", out JToken tBBLocks) || tBBLocks.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid BasicBlocks in trace");
                return false;
            }
            JArray BBlocksArray = (JArray)tBBLocks;

            Console.WriteLine("Loading "+ BBlocksArray.Count + " basic blocks");
            //display_only_status_message(BBLoadMsg.str(), clientState);

            foreach (JArray blockEntry in BBlocksArray)
            {
                if (blockEntry.Count != 2 || blockEntry[0].Type != JTokenType.Integer || blockEntry[1].Type != JTokenType.Array)
                {
                    Console.WriteLine("Error: Bad basic block descriptor");
                    return false;
                }
                JArray insAddresses = (JArray)blockEntry[1];
                if (insAddresses.Count % 2 != 0)
                {
                    Console.WriteLine("Error: Bad basic block descriptor");
                    return false;
                }


                List<InstructionData> blkInstructions = new List<InstructionData>();
                ulong blockaddress = blockEntry[0].ToObject<ulong>();
                blockList.Add(new Tuple<ulong, List<InstructionData>>(blockaddress, blkInstructions));

                for (var i = 0; i < insAddresses.Count; i+=2)
                {
                    ulong insAddress = insAddresses[i].ToObject<ulong>();
                    int mutationIndex = insAddresses[i+1].ToObject<int>();
                    blkInstructions.Add(disassembly[insAddress][mutationIndex]);
                }
            }

            return true;
        }
        
        
        bool UnpackExtern(JObject externEntry)
        {
            if (!externEntry.TryGetValue("A", out JToken Addr) || Addr.Type != JTokenType.Integer)
            {
                Console.WriteLine("[rgat]Error, address not found in extern entry");
                return false;
            }
            ulong externAddr = Addr.ToObject<ulong>();

            ROUTINE_STRUCT BBEntry = new ROUTINE_STRUCT();


            if (!externEntry.TryGetValue("M", out JToken ModID) || ModID.Type != JTokenType.Integer)
            {
                Console.WriteLine("[rgat]Error: module ID not found in extern entry");
                return false;
            }
            BBEntry.globalmodnum = ModID.ToObject<int>();

            if (!externEntry.TryGetValue("S", out JToken hasSym) || hasSym.Type != JTokenType.Boolean)
            {
                Console.WriteLine("[rgat]Error: Symbol presence not found in extern entry");
                return false;
            }
            BBEntry.hasSymbol = ModID.ToObject<bool>();


            if (externEntry.TryGetValue("C", out JToken callers) && callers.Type != JTokenType.Array)
            {
                BBEntry.thread_callers = new Dictionary<uint, List<Tuple<uint, uint>>>();
                JArray CallersArray = (JArray)callers;
                foreach (JArray caller in CallersArray)
                {

                    List<Tuple<uint, uint>> ThreadExternCalls = new List<Tuple<uint, uint>>();
                    uint threadID = caller[0].ToObject<uint>();
                    JArray edges = (JArray) caller[1];

                    foreach (JArray edge in edges)
                    {
                            uint source = edge[0].ToObject<uint>();
                            uint target = edge[0].ToObject<uint>();
                            ThreadExternCalls.Add(new Tuple<uint, uint>(source, target));
                    }
                    BBEntry.thread_callers.Add(threadID, ThreadExternCalls);
                  
                }
            }

            externdict.Add(externAddr,BBEntry);
            return true;
        }


        bool loadExterns(JObject processJSON)
        {
            if (!processJSON.TryGetValue("Externs", out JToken jExterns) || jExterns.Type != JTokenType.Array)
            {
                Console.WriteLine("[rgat] Failed to find valid Externs in trace");
                return false;
            }
            JArray ExternsArray = (JArray)jExterns;


            Console.WriteLine("Loading " + ExternsArray.Count + " externs");
            //display_only_status_message(externLoadMsg.str(), clientState);

            foreach (JObject externObj in ExternsArray.Children())
            {
                if (!UnpackExtern(externObj))
                    return false;
            }
            return true;
        }

       
        public bool dieFlag = false;
    }
}
