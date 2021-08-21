using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgat
{
    public class ProcessRecord
    {

        public ProcessRecord(int binaryBitWidth)
        {
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
        //todo - failure on limit excess
        public bool EnsureBlockExistsGetAddress(uint blockID, out ulong address)
        {
            int timewaited = 0;
            while (true)
            {

                lock (InstructionsLock)
                {
                    if (BasicBlocksList.Count > blockID && BasicBlocksList[(int)blockID] != null)
                    {
                        address = BasicBlocksList[(int)blockID].Item1;
                        return true;
                    }
                }
                if (dieFlag) {
                    address = 0;
                    return false; 
                }
                Thread.Sleep(2);
                timewaited += 2;
                if (timewaited > 2500 && (timewaited % 1000) == 0)
                {
                    Console.WriteLine($"Warning, long wait for block {blockID}. Currently {timewaited / 1000}s");
                    if (timewaited > 5000)
                    {
                        address = 0;
                        return false;
                    }
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
                    if (ModuleTraceStates.Count <= moduleNo || moduleNo == -1)
                    {
                        Console.WriteLine($"Error: Unable to find extern module {moduleNo} in ModuleTraceStates dict");
                        externBlock = null;
                        return null;
                    }
                    if (ModuleTraceStates[moduleNo] == eCodeInstrumentation.eUninstrumentedCode)
                    {
                        get_extern_at_address(externBlockaddr, moduleNo, out ROUTINE_STRUCT tmpexternBlock);
                        externBlock = tmpexternBlock;
                        return null;
                    }
                }


                if (blockID < BasicBlocksList.Count)
                {
                    var result = BasicBlocksList[(int)blockID];
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

        //todo broke on replay with extern modules
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
                ModuleAPIReferences.Add(WinAPIDetails.ResolveModuleEnum(path));
                APITypes.Add(globalModID, new Dictionary<ulong, Logging.LogFilterType>());
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
            int attempts = 10;
            lock (SymbolsLock)
            {
                int modnum = modIDTranslationVec[localModnum];
                while (modnum == -1 && modnum <= APITypes.Count)
                {
                    Thread.Sleep(3);
                    modnum = modIDTranslationVec[localModnum];
                    attempts -= 1;
                    if (attempts == 0)
                    {
                        Logging.RecordLogEvent($"Failed to translate module ID {localModnum}", filter:  Logging.LogFilterType.TextError);
                        return;
                    }
                }
                Debug.Assert(modnum != -1);

                if (!modsymsPlain.ContainsKey(modnum))
                {
                    modsymsPlain.Add(modnum, new Dictionary<ulong, string>());
                }

                if (modsymsPlain[modnum].ContainsKey(offset))
                {
                    modsymsPlain[modnum][offset] += "/" + name; //some addresses have multiple symbols
                }
                else
                {
                    modsymsPlain[modnum].Add(offset, name);
                    int moduleref = ModuleAPIReferences[modnum];
                   // APITypes[modnum].Add(offset, WinAPIDetails.ResolveAPIFilterType(moduleref, name));
                    
                }

            }
        }

        public bool SymbolExists(int GlobalModuleNumber, ulong address)
        {
            return modsymsPlain.ContainsKey(GlobalModuleNumber) && modsymsPlain[GlobalModuleNumber].ContainsKey(address - LoadedModuleBounds[GlobalModuleNumber].Item1);
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


        /// <summary>
        /// Takes an address in target process and looks up the path of the module and symbol at that address
        /// </summary>
        /// <param name="address">Address of potential symbol in loaded modules of target program</param>
        /// <param name="moduleID">rgat ID of module output here, if found.</param>
        /// <param name="module">Path of module is output here, if found</param>
        /// <param name="symbol">Name of symbol is output here, if found</param>
        /// <returns>True if both module and symbol string resolved. False otherwise.</returns>
        public bool ResolveSymbolAtAddress(ulong address, out int moduleID, out string module, out string symbol)
        {
            moduleID = FindContainingModule(address);
            if (moduleID == -1)
            {
                module = "";
                symbol = "";
                return false;
            }

            lock (ModulesLock)
            {
                module = LoadedModulePaths[moduleID];

                if (modsymsPlain.ContainsKey(moduleID))
                {
                    ulong offset = address - LoadedModuleBounds[moduleID].Item1;
                    if (modsymsPlain[moduleID].TryGetValue(offset, out symbol)) return true;
                }
            }
            symbol = "";
            return false;
        }

        /// <summary>
        /// Lookup the path of a module (ie DLL/library/binary) from the module ID
        /// </summary>
        /// <param name="GlobalModuleID">rgat internal ID for module in target process</param>
        /// <returns>string containing the module path</returns>
        public string GetModulePath(int GlobalModuleID)
        {
            lock (ModulesLock)
            {
                return LoadedModulePaths[GlobalModuleID];
            }
        }


        public ulong GetBlockAtAddress(ulong address)
        {
            bool hasBlock = false;
            while (!hasBlock)
            {
                lock (InstructionsLock)
                {
                    hasBlock = blockIDDict.ContainsKey(address);
                }
                if (hasBlock) break;
                int moduleNo = FindContainingModule(address);
                if (ModuleTraceStates.Count <= moduleNo)
                {
                    Console.WriteLine($"Warning: Unable to find extern module {moduleNo} in ModuleTraceStates dict");
                    Thread.Sleep(15);
                    continue;
                }
                if (ModuleTraceStates[moduleNo] == eCodeInstrumentation.eUninstrumentedCode)
                {
                    return ulong.MaxValue;
                }
                Console.WriteLine($"Waiting for block at 0x{address:x}");
                Thread.Sleep(15);

            }
            return blockIDDict[address][^1];
        }

        public ulong GetAddressOfBlock(int blockID)
        {
            Debug.Assert(blockID != -1 && blockID < BasicBlocksList.Count);
            return BasicBlocksList[blockID].Item1;
        }


        public void AddDisassembledBlock(uint blockID, ulong address, List<InstructionData> instructions)
        {
            //these arrive out of order so have to add some dummy entries
            lock (InstructionsLock)
            {
                if (BasicBlocksList.Count > blockID)
                {
                    BasicBlocksList[(int)blockID] = new Tuple<ulong, List<InstructionData>>(address, instructions);
                }
                else
                {
                    while (BasicBlocksList.Count < blockID)
                    {
                        BasicBlocksList.Add(null);
                    }
                    BasicBlocksList.Add(new Tuple<ulong, List<InstructionData>>(address, instructions));
                }
                if (blockIDDict.ContainsKey(address))
                {
                    blockIDDict[address].Add(blockID);
                }
                else
                {
                    blockIDDict[address] = new List<ulong>() { blockID };
                }
            }
        }



        public List<string> LoadedModulePaths = new List<string>();
        public List<int> modIDTranslationVec = new List<int>();
        public List<int> ModuleAPIReferences = new List<int>();
        public List<Tuple<ulong, ulong>> LoadedModuleBounds = new List<Tuple<ulong, ulong>>();
        public List<eCodeInstrumentation> ModuleTraceStates = new List<eCodeInstrumentation>();

        public Dictionary<string, long> globalModuleIDs = new Dictionary<string, long>();
        public int LoadedModuleCount = 0;

        //todo review these
        private readonly object ModulesLock = new object();
        public readonly object ExternCallerLock = new object(); //todo stop this being public

        private readonly object SymbolsLock = new object();
        private Dictionary<int, Dictionary<ulong, string>> modsymsPlain = new Dictionary<int, Dictionary<ulong, string>>();

        private Dictionary<int, Dictionary<ulong, Logging.LogFilterType>> APITypes = new Dictionary<int, Dictionary<ulong, Logging.LogFilterType>>();

        public int GetModuleReference(int GlobalModuleID)
        {
            if (GlobalModuleID >= modsymsPlain.Count) return -1; //todo race condition here where it could stay as -1 if requested too early?
            return  ModuleAPIReferences[GlobalModuleID];
        }

        
        public WinAPIDetails.API_ENTRY? GetAPIEntry(int globalModuleID, int moduleAPIRef, ulong address)
        {
            if (moduleAPIRef == -1) return null;

            ulong symbolOffset = address - LoadedModuleBounds[globalModuleID].Item1;
            if(modsymsPlain[globalModuleID].TryGetValue(symbolOffset, out string symname))
            {
                return WinAPIDetails.GetAPIInfo(moduleAPIRef, symname);
            }

            return null;
        }



        public bool GetInstructionBefore(ulong addr, out ulong result)
        {
            const int LARGEST_X86_INSTRUCTION = 15;
            {
                //first lookup in cache
                if (previousInstructionsCache.TryGetValue(addr, out result))
                {
                    return true;
                }

                //the code that is executing has not been disassembled yet
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

        public List<uint> GetNodesAtAddress(ulong addr, uint TID)
        {
            lock (InstructionsLock)
            {
                if (!disassembly.TryGetValue(addr, out List<InstructionData> inslist)) return new List<uint>();
                var result = new List<uint>();
                foreach (var ins in inslist)
                {
                    if (ins.GetThreadVert(TID, out uint vert))
                    {
                        result.Add(vert);
                    }
                }
                return result;
            }
        }

        public readonly object InstructionsLock = new object();

        //maps instruction addresses to list of different instructions that resided at that address
        public Dictionary<ulong, List<InstructionData>> disassembly = new Dictionary<ulong, List<InstructionData>>();

        //useful for mapping return addresses to callers without a locking search
        public Dictionary<ulong, ulong> previousInstructionsCache = new Dictionary<ulong, ulong>();

        //list of basic blocks - guarded by instructionslock
        //              address
        public List<Tuple<ulong, List<InstructionData>>> BasicBlocksList = new List<Tuple<ulong, List<InstructionData>>>();
        private Dictionary<ulong, List<ulong>> blockIDDict = new Dictionary<ulong, List<ulong>>();

        public Dictionary<ulong, ROUTINE_STRUCT> externdict = new Dictionary<ulong, ROUTINE_STRUCT>();
        public int BitWidth;



        private bool LoadSymbols(JObject processJSON)
        {
            Logging.RecordLogEvent("Loading Module Symbols", Logging.LogFilterType.TextDebug);
            //display_only_status_message(symLoadMsg.str(), clientState);

            if (!processJSON.TryGetValue("ModuleSymbols", out JToken symbolslist) || symbolslist.Type != JTokenType.Array)
            {
                Logging.RecordLogEvent("Failed to find valid ModuleSymbols in trace", Logging.LogFilterType.TextError);
                return false;
            }

            ulong totalSyms = 0;
            foreach (JObject item in symbolslist.Children())
            {
                if (!item.TryGetValue("ModuleID", out JToken modID) || modID.Type != JTokenType.Integer)
                {
                    Logging.RecordLogEvent("ERROR: Symbols load failed: No valid module ID", Logging.LogFilterType.TextError);
                    return false;
                }
                modsymsPlain.Add(modID.ToObject<int>(), new Dictionary<ulong, string>());

                if (!item.TryGetValue("Symbols", out JToken syms) || syms.Type != JTokenType.Array)
                {
                    Logging.RecordLogEvent("[rgat]ERROR: Symbols load failed: No valid symbols list", Logging.LogFilterType.TextError);
                    return false;
                }
                foreach (JArray sym in syms.Children())
                {
                    if (sym.Count != 2 || sym[0].Type != JTokenType.Integer || sym[1].Type != JTokenType.String)
                    {
                        Logging.RecordLogEvent("[rgat]ERROR: Symbols load failed: Bad symbol in list", Logging.LogFilterType.TextError);
                        return false;
                    }
                    ulong SymAddress = sym[0].ToObject<ulong>();
                    string SymName = sym[1].ToObject<string>();

                    modsymsPlain[modID.ToObject<int>()][SymAddress] = SymName;
                    totalSyms += 1;
                }
            }

            Logging.RecordLogEvent("Finished loading " + totalSyms + " symbols", Logging.LogFilterType.TextDebug);
            return true;
        }

        private bool LoadModules(JObject processJSON)
        {
            //display_only_status_message("Loading Modules", clientState);

            Logging.RecordLogEvent("LoadModules() Loading Module Paths");
            if (!processJSON.TryGetValue("ModulePaths", out JToken moduleslist))
            {
                Logging.RecordLogEvent("LoadModules() Failed to find ModulePaths in trace", Logging.LogFilterType.TextError);
                return false;
            }

            var modulesArray = moduleslist.ToObject<List<string>>();

            Logging.RecordLogEvent("Loading " + modulesArray.Count + " modules", Logging.LogFilterType.TextDebug);
            foreach (string b64entry in modulesArray)
            {
                string plainpath = Encoding.Unicode.GetString(Convert.FromBase64String(b64entry));
                LoadedModulePaths.Add(plainpath);
            }

            if (!processJSON.TryGetValue("ModuleBounds", out Newtonsoft.Json.Linq.JToken modulebounds))
            {
                Logging.RecordLogEvent("Failed to find ModuleBounds in trace", Logging.LogFilterType.TextError);
                return false;
            }
            var modsBoundArray = modulebounds.ToObject<List<List<ulong>>>();
            LoadedModuleBounds.Clear();

            foreach (List<ulong> entry in modsBoundArray)
            {
                LoadedModuleBounds.Add(new Tuple<ulong, ulong>(entry[0], entry[1]));
            }


            if (!processJSON.TryGetValue("ModuleTraceStates", out Newtonsoft.Json.Linq.JToken modtracestatesTkn))
            {
                Logging.RecordLogEvent("Failed to find ModuleTraceStates in trace", Logging.LogFilterType.TextError);
                return false;
            }

            ModuleTraceStates.Clear();
            int[] intstates = modtracestatesTkn.ToObject<List<int>>().ToArray();
            ModuleTraceStates = Array.ConvertAll(intstates, value => (eCodeInstrumentation)value).ToList();
            return true;
        }

        struct ADDRESS_DATA
        {
            public ulong address;
            public int moduleID;
            public bool hasSym;
            public bool blockBoundary;
        };


        //for disassembling saved instructions
        //takes a capstone context, opcode string, target instruction data struct and the address of the instruction
        public static int DisassembleIns(CapstoneX86Disassembler disassembler, ulong address, ref InstructionData insdata)
        {
            X86Instruction[] instructions = disassembler.Disassemble(insdata.opcodes, (long)address);
            //todo: catch some kind of exception, since i cant see any way of getting error codes
            if (instructions.Length != 1)
            {
                Logging.RecordLogEvent("ERROR: Failed disassembly for opcodes: " + insdata.opcodes, Logging.LogFilterType.TextError);// << " error: " << cs_errno(hCapstone) << endl;
                return 0;
            }

            X86Instruction insn = instructions[0];

            insdata.mnemonic = insn.Mnemonic;
            insdata.op_str = insn.Operand;
            insdata.ins_text = insdata.mnemonic + " " + insdata.op_str;
            if (insn.Bytes[0] == 0xf2 && insdata.mnemonic.StartsWith("bnd"))
            {
                insdata.mnemonic = insn.Mnemonic.Substring(4);
                insdata.IsMPX = true;
            }
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
                insdata.itype = RGAT_CONSTANTS.eNodeType.eInsCall;
            }

            else if (insdata.mnemonic == "ret") //todo: iret
            {
                insdata.itype = RGAT_CONSTANTS.eNodeType.eInsReturn;
            }
            else if (insdata.mnemonic == "jmp")
            {

                insdata.itype = RGAT_CONSTANTS.eNodeType.eInsJump;

                if (insn.Operand.Contains("["))
                {

                    try
                    {
                        int idxAddrStart = insn.Operand.IndexOf('[') + 1;
                        int addrSize = (insn.Operand.IndexOf(']') - idxAddrStart);
                        string targMemAddr = insn.Operand.Substring(idxAddrStart, addrSize);
                        insdata.branchAddress = Convert.ToUInt64(targMemAddr, 16);
                        insdata.PossibleidataThunk = true;
                    } //todo: not a great idea actually... just point to the outgoing neighbours for labels
                    catch { insdata.branchAddress = 0; }

                }
                else
                {
                    try { insdata.branchAddress = Convert.ToUInt64(insdata.op_str, 16); } //todo: not a great idea actually... just point to the outgoing neighbours for labels
                    catch { insdata.branchAddress = 0; }
                }

                if (insdata.branchAddress == (address + (ulong)insdata.numbytes))
                {
                    insdata.itype = RGAT_CONSTANTS.eNodeType.eInsUndefined; //junp to next address is nop
                }
            }
            else
            {
                insdata.itype = RGAT_CONSTANTS.eNodeType.eInsUndefined;
                //assume all j+ instructions aside from jmp are conditional (todo: bother to check)
                if (insdata.mnemonic[0] == 'j')
                {
                    insdata.conditional = true;
                    try
                    {
                        insdata.branchAddress = Convert.ToUInt64(insdata.op_str, 16);
                    } //todo: not a great idea actually... just point to the outgoing neighbours for labels
                    catch { insdata.branchAddress = 0; }
                    insdata.condDropAddress = insdata.address + (ulong)insdata.numbytes;
                }

            }
            return instructions.Length;
        }

        private static bool UnpackOpcodes(JArray mutationData, CapstoneX86Disassembler disassembler, ADDRESS_DATA addressData, out List<InstructionData> opcodeVariants)
        {
            opcodeVariants = new List<InstructionData>();
            foreach (JArray mutation in mutationData)
            {
                if (mutation.Count != 2 || mutation[0].Type != JTokenType.String || mutation[1].Type != JTokenType.Array)
                {
                    Logging.RecordLogEvent("Load Error: Bad mutation entry", Logging.LogFilterType.TextError);
                    opcodeVariants = null;
                    return false;
                }

                InstructionData ins = new InstructionData();
                ins.globalmodnum = addressData.moduleID;
                ins.hasSymbol = addressData.hasSym;
                ins.opcodes = System.Convert.FromBase64String(mutation[0].ToObject<string>());
                ins.numbytes = ins.opcodes.Length;
                ins.address = addressData.address;
                ins.BlockBoundary = addressData.blockBoundary;

                if (ins.numbytes == 0)
                {
                    Logging.RecordLogEvent("Load Error: Empty opcode string", Logging.LogFilterType.TextError);
                    opcodeVariants = null;
                    return false;
                }

                DisassembleIns(disassembler, addressData.address, ref ins);

                JArray threadNodes = (JArray)mutation[1];

                foreach (JArray entry in threadNodes.Children())
                {
                    if (entry.Count != 2 || entry[0].Type != JTokenType.Integer || entry[1].Type != JTokenType.Integer)
                    {
                        Logging.RecordLogEvent("Load Error: Bad thread nodes entry", Logging.LogFilterType.TextError);
                        return false;
                    }

                    uint excutingThread = entry[0].ToObject<uint>();
                    uint GraphVertID = entry[1].ToObject<uint>();
                    ins.AddThreadVert(excutingThread, GraphVertID);
                }

                opcodeVariants.Add(ins);
            }
            return true;
        }

        bool UnpackAddress(JArray entry, CapstoneX86Disassembler disassembler)
        {
            if (entry.Type != JTokenType.Array || entry.Count != 4 ||
                       entry[0].Type != JTokenType.Integer ||
                       entry[1].Type != JTokenType.Integer ||
                       entry[2].Type != JTokenType.Integer ||
                       entry[3].Type != JTokenType.Array
                       )
            {
                Logging.RecordLogEvent("Invalid disassembly entry in saved trace", Logging.LogFilterType.TextError);
                return false;
            }

            ADDRESS_DATA addrData = new ADDRESS_DATA
            {
                address = entry[0].ToObject<ulong>(),
                moduleID = entry[1].ToObject<int>(),
                blockBoundary = entry[2].ToObject<int>() == 1 ? true : false
            };

            addrData.hasSym = (modsymsPlain.ContainsKey(addrData.moduleID) &&
                                modsymsPlain[addrData.moduleID].ContainsKey(addrData.address));


            JArray mutationData = (JArray)entry[3];

            if (!UnpackOpcodes(mutationData, disassembler, addrData, out List<InstructionData> opcodeVariants))
            {
                Logging.RecordLogEvent("Invalid disassembly for opcodes in trace", Logging.LogFilterType.TextError);
                return false;
            }
            disassembly.Add(addrData.address, opcodeVariants);
            return true;
        }

        bool LoadDisassembly(JObject processJSON)
        {
            if (!processJSON.TryGetValue("BitWidth", out JToken tBitWidth) || tBitWidth.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid BitWidth in trace", Logging.LogFilterType.TextError);
                return false;
            }
            BitWidth = tBitWidth.ToObject<int>();
            if (BitWidth != 32 && BitWidth != 64)
            {
                Logging.RecordLogEvent("Invalid BitWidth " + BitWidth, Logging.LogFilterType.TextError);
                return false;
            }

            if (!processJSON.TryGetValue("Disassembly", out JToken disassemblyList) || disassemblyList.Type != JTokenType.Array)
            {
                Logging.RecordLogEvent("Failed to find valid Disassembly in trace", Logging.LogFilterType.TextError);
                return false;
            }
            JArray DisassemblyArray = (JArray)disassemblyList;

            Logging.RecordLogEvent("Loading Disassembly for " + DisassemblyArray.Count + " addresses", Logging.LogFilterType.TextDebug);
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
                Logging.RecordLogEvent("Failed to find valid BasicBlocks in trace", Logging.LogFilterType.TextError);
                return false;
            }
            JArray BBlocksArray = (JArray)tBBLocks;

            Logging.RecordLogEvent("Loading " + BBlocksArray.Count + " basic blocks", Logging.LogFilterType.TextDebug);
            //display_only_status_message(BBLoadMsg.str(), clientState);
            uint blockID = 0;
            foreach (JArray blockEntry in BBlocksArray)
            {
                if (blockEntry.Count != 2 || blockEntry[0].Type != JTokenType.Integer || blockEntry[1].Type != JTokenType.Array)
                {
                    Logging.RecordLogEvent("Error in saved trace: Bad basic block descriptor", Logging.LogFilterType.TextError);
                    return false;
                }
                JArray insAddresses = (JArray)blockEntry[1];
                List<InstructionData> blkInstructions = new List<InstructionData>();
                ulong blockaddress = blockEntry[0].ToObject<ulong>();

                for (var i = 0; i < insAddresses.Count; i++)
                {
                    ulong insAddress = insAddresses[i][0].ToObject<ulong>();
                    int mutationIndex = insAddresses[i][1].ToObject<int>();
                    InstructionData ins = disassembly[insAddress][mutationIndex];
                    blkInstructions.Add(ins);
                    if (ins.ContainingBlockIDs == null) ins.ContainingBlockIDs = new List<uint>();
                    ins.ContainingBlockIDs.Add(blockID);
                    disassembly[insAddress][mutationIndex] = ins;

                }
                blockID += 1;


                BasicBlocksList.Add(new Tuple<ulong, List<InstructionData>>(blockaddress, blkInstructions));
            }

            return true;
        }


        bool UnpackExtern(JObject externEntry)
        {
            if (!externEntry.TryGetValue("A", out JToken Addr) || Addr.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Error, address not found in extern entry", Logging.LogFilterType.TextError);
                return false;
            }
            ulong externAddr = Addr.ToObject<ulong>();

            ROUTINE_STRUCT BBEntry = new ROUTINE_STRUCT();


            if (!externEntry.TryGetValue("M", out JToken ModID) || ModID.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("[rgat]Error: module ID not found in extern entry", Logging.LogFilterType.TextError);
                return false;
            }
            BBEntry.globalmodnum = ModID.ToObject<int>();

            if (!externEntry.TryGetValue("S", out JToken hasSym) || hasSym.Type != JTokenType.Boolean)
            {
                Logging.RecordLogEvent("[rgat]Error: Symbol presence not found in extern entry", Logging.LogFilterType.TextError);
                return false;
            }
            BBEntry.hasSymbol = ModID.ToObject<bool>();


            if (externEntry.TryGetValue("C", out JToken callers) && callers.Type == JTokenType.Array)
            {
                BBEntry.thread_callers = new Dictionary<uint, List<Tuple<uint, uint>>>();
                JArray CallersArray = (JArray)callers;

                foreach (JArray caller in CallersArray)
                {
                    List<Tuple<uint, uint>> ThreadExternCalls = new List<Tuple<uint, uint>>();

                    uint threadID = caller[0].ToObject<uint>();
                    JArray edges = (JArray)caller[1];

                    foreach (JArray edge in edges)
                    {
                        uint source = edge[0].ToObject<uint>();
                        uint target = edge[1].ToObject<uint>();
                        ThreadExternCalls.Add(new Tuple<uint, uint>(source, target));
                    }

                    BBEntry.thread_callers.Add(threadID, ThreadExternCalls);

                }
            }

            externdict.Add(externAddr, BBEntry);
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


            Logging.RecordLogEvent("Loading " + ExternsArray.Count + " externs", Logging.LogFilterType.TextDebug);
            //display_only_status_message(externLoadMsg.str(), clientState);

            foreach (JObject externObj in ExternsArray.Children())
            {
                if (!UnpackExtern(externObj))
                    return false;
            }
            return true;
        }

        public JObject Serialise()
        {
            JObject result = new JObject();
            SerialiseMetaData(ref result);
            lock (InstructionsLock)
            {
                SerialiseDisassembly(ref result);
                SerialiseBlockData(ref result);
            }
            SerialiseModules(ref result);
            SerialiseSymbols(ref result);
            SerialiseExternDict(ref result);

            return result;
        }


        private void SerialiseMetaData(ref JObject saveObject)
        {
            if (BitWidth == 32 || BitWidth == 64)
            {
                saveObject.Add("BitWidth", BitWidth);
            }
            else
            {
                Logging.RecordLogEvent($"Error: Serialise() - Invalid bitwidth {BitWidth}", Logging.LogFilterType.TextError);
                return;
            }

            saveObject.Add("RGATVersionMaj", RGAT_CONSTANTS.VERSION.MAJOR);
            saveObject.Add("RGATVersionMin", RGAT_CONSTANTS.VERSION.MINOR);
            saveObject.Add("RGATVersionFeature", RGAT_CONSTANTS.VERSION.FEATURE);
        }

        private void SerialiseDisassembly(ref JObject saveObject)
        {
            JArray disasarray = new JArray();
            foreach (KeyValuePair<ulong, List<InstructionData>> addr_inslist in disassembly)
            {
                JArray insentry = new JArray();
                insentry.Add(addr_inslist.Key);
                insentry.Add(addr_inslist.Value[0].globalmodnum);
                insentry.Add(addr_inslist.Value[0].BlockBoundary ? 1 : 0);

                JArray opcodesMutationsList = new JArray();
                foreach (var mutation in addr_inslist.Value)
                {
                    JArray mutationData = new JArray();
                    string opcodestring = System.Convert.ToBase64String(mutation.opcodes);
                    mutationData.Add(opcodestring);

                    JArray threadsUsingInstruction = new JArray();
                    List<Tuple<uint, uint>> threadVerts = mutation.ThreadVerts;
                    if (threadVerts != null)
                    {
                        foreach (Tuple<uint, uint> thread_node in threadVerts)
                        {
                            JArray threadNodeMappings = new JArray();
                            threadNodeMappings.Add(thread_node.Item1);
                            threadNodeMappings.Add(thread_node.Item2);
                            threadsUsingInstruction.Add(threadNodeMappings);
                        }
                    }
                    mutationData.Add(threadsUsingInstruction);
                    opcodesMutationsList.Add(mutationData);
                }
                insentry.Add(opcodesMutationsList);
                disasarray.Add(insentry);
            }
            saveObject.Add("Disassembly", disasarray);
        }


        private void SerialiseModules(ref JObject saveObject)
        {
            JArray ModulePaths = new JArray();
            foreach (string path in LoadedModulePaths)
            {
                ModulePaths.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(path)));
            }
            saveObject.Add("ModulePaths", ModulePaths);

            JArray ModuleBounds = new JArray();
            foreach (Tuple<ulong, ulong> start_end in LoadedModuleBounds)
            {
                JArray BoundsTuple = new JArray();
                BoundsTuple.Add(start_end.Item1);
                BoundsTuple.Add(start_end.Item2);
                ModuleBounds.Add(BoundsTuple);
            }
            saveObject.Add("ModuleBounds", ModuleBounds);

            JArray ModuleTraceStatesArr = new JArray();
            foreach (eCodeInstrumentation tState in ModuleTraceStates)
            {
                ModuleTraceStatesArr.Add(tState);
            }
            saveObject.Add("ModuleTraceStates", ModuleTraceStatesArr);
        }


        private void SerialiseSymbols(ref JObject saveObject)
        {
            JArray ModuleSymbols = new JArray();

            foreach (var modID_symsdict in modsymsPlain)
            {
                JObject modSymsObj = new JObject();
                modSymsObj.Add("ModuleID", modID_symsdict.Key);

                JArray modSymsArr = new JArray();
                foreach (var address_symstring in modID_symsdict.Value)
                {
                    JArray modSymEntry = new JArray();
                    modSymEntry.Add(address_symstring.Key);
                    modSymEntry.Add(address_symstring.Value);
                    modSymsArr.Add(modSymEntry);
                }
                modSymsObj.Add("Symbols", modSymsArr);
                ModuleSymbols.Add(modSymsObj);
            }

            saveObject.Add("ModuleSymbols", ModuleSymbols);
        }


        private void SerialiseBlockData(ref JObject saveObject)
        {
            JArray BasicBlocksArray = new JArray();

            foreach (var addr_inslist in BasicBlocksList)
            {
                JArray blockArray = new JArray();
                blockArray.Add(addr_inslist.Item1);

                JArray inslist = new JArray();
                foreach (InstructionData i in addr_inslist.Item2)
                {
                    JArray insentry = new JArray();
                    insentry.Add(i.address);
                    insentry.Add(i.mutationIndex);
                    inslist.Add(insentry);
                }
                blockArray.Add(inslist);
                BasicBlocksArray.Add(blockArray);
            }
            saveObject.Add("BasicBlocks", BasicBlocksArray);
        }


        private void SerialiseExternDict(ref JObject saveObject)
        {
            JArray externsArray = new JArray();

            foreach (var addr_rtnstruct in externdict)
            {
                JObject externObj = new JObject();
                externObj.Add("A", addr_rtnstruct.Key);

                ROUTINE_STRUCT externStruc = addr_rtnstruct.Value;
                externObj.Add("M", externStruc.globalmodnum);
                externObj.Add("S", externStruc.hasSymbol);

                if (externStruc.thread_callers.Count > 0)
                {
                    JArray callersArr = new JArray();

                    foreach (var thread_edgelist in externStruc.thread_callers)
                    {
                        JArray callerCalls = new JArray();
                        callerCalls.Add(thread_edgelist.Key);

                        JArray edgeList = new JArray();
                        foreach (var edge in thread_edgelist.Value)
                        {
                            JArray threadEdge = new JArray();
                            threadEdge.Add(edge.Item1);
                            threadEdge.Add(edge.Item2);
                            edgeList.Add(threadEdge);
                        }

                        callerCalls.Add(edgeList);
                        callersArr.Add(callerCalls);
                    }

                    externObj.Add("C", callersArr);
                }
                externsArray.Add(externObj);
            }
            saveObject.Add("Externs", externsArray);
        }


        public bool dieFlag = false;
    }
}
