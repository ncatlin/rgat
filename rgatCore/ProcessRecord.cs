using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgat
{
    /// <summary>
    /// Records process data which is shared between threads
    /// </summary>
    public class ProcessRecord
    {
        /// <summary>
        /// Create a ProcessRecord
        /// </summary>
        /// <param name="binaryBitWidth">32 or 64 bits</param>
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

        /// <summary>
        /// Get information about the entry to uninstrumented code at the given address
        /// </summary>
        /// <param name="address">Address of uninstrumented code</param>
        /// <param name="moduleNum">Module the address is in </param>
        /// <param name="RTN">ROUTINE_STRUCT output</param>
        public void get_extern_at_address(ulong address, int moduleNum, out ROUTINE_STRUCT RTN)
        {
            lock (ExternCallerLock)
            {
                if (!externdict.TryGetValue(address, out RTN))
                {
                    RTN = new ROUTINE_STRUCT
                    {
                        Module = moduleNum,
                        ThreadCallers = new Dictionary<uint, List<Tuple<uint, uint>>>()
                    };
                    externdict.Add(address, RTN);
                }
            }
        }



        //is there a better way of doing this?
        /// <summary>
        /// Get lsit of instructions for a block
        /// </summary>
        /// <param name="blockID">IF of the block</param>
        /// <returns></returns>
        public List<InstructionData>? getDisassemblyBlock(uint blockID)
        {
            ROUTINE_STRUCT? stub = null;
            return GetDisassemblyBlock(blockID, ref stub);
        }


        /// <summary>
        /// Get the list of instructions for a block
        /// This blocks until the data is disassembled and is generally some of the oldest and worst code in the codebase
        /// </summary>
        /// <param name="blockID">Block ID</param>
        /// <param name="externBlock">If external, the associated object</param>
        /// <param name="externBlockaddr">An optional external address</param>
        /// <returns></returns>
        public List<InstructionData>? GetDisassemblyBlock(uint blockID, ref ROUTINE_STRUCT? externBlock, ulong externBlockaddr = 0)
        {
            int iterations = 0;

            while (!rgatState.rgatIsExiting)
            {
                if (externBlockaddr != 0 || blockID == uint.MaxValue)
                {
                    bool found = FindContainingModule(externBlockaddr, out int? moduleNo);
                    if (!found || ModuleTraceStates.Count <= moduleNo)
                    {
                        Logging.WriteConsole($"Error: Unable to find extern module {moduleNo} in ModuleTraceStates dict");
                        externBlock = null;
                        return null;
                    }
                    if (ModuleTraceStates[moduleNo!.Value] == eCodeInstrumentation.eUninstrumentedCode)
                    {
                        get_extern_at_address(externBlockaddr, moduleNo!.Value, out ROUTINE_STRUCT tmpexternBlock);
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
                {
                    Thread.Sleep(1);
                }

                if (iterations++ > 20 && (iterations % 20 == 0))
                {
                    Logging.WriteConsole($"[rgat]Warning: Long wait for disassembly of block ID {blockID}");
                }

                if (iterations++ > 200)
                {
                    Logging.WriteConsole($"[rgat]Warning: Giving up waiting for disassembly of block ID {blockID}");
                    break;
                }
            }
            return null;
        }

        //todo broke on replay with extern modules
        /// <summary>
        /// Find the module containing this address
        /// </summary>
        /// <param name="address">Address to find</param>
        /// <param name="moduleID">Module containing this address</param>
        /// <returns>If the address was found</returns>
        public bool FindContainingModule(ulong address, out int? moduleID)
        {
            int numModules = LoadedModuleBounds.Count;
            for (int modNo = 0; modNo < numModules; ++modNo)
            {
                Tuple<ulong, ulong> moduleBounds = LoadedModuleBounds[modNo];
                if (moduleBounds == null)
                {
                    continue;
                }

                if (address >= moduleBounds.Item1 && address <= moduleBounds.Item2)
                {
                    moduleID = modNo;
                    return true;
                }
            }
            moduleID = null;
            return false;
        }


        /// <summary>
        /// Record a module for this process
        /// </summary>
        /// <param name="localmodID">Internal module number returned by the instrumentation tool</param>
        /// <param name="path">Filesystem path of the module</param>
        /// <param name="start">Module start address</param>
        /// <param name="end">Module end address</param>
        /// <param name="isInstrumented">If the instrumentation tool is instrumenting this module</param>
        public void AddModule(int localmodID, string path, ulong start, ulong end, char isInstrumented)
        {
            if (localmodID > 1000)
            {
                Logging.WriteConsole($"Ignoring strangely huge module id {localmodID} {path}");
                return;
            }


            lock (ModulesLock)
            {
                int globalModID = LoadedModuleCount; //index into our module lists

                LoadedModulePaths.Add(path);
                ModuleAPIReferences.Add(APIDetailsWin.ResolveModuleEnum(path));
                APITypes.Add(globalModID, new Dictionary<ulong, Logging.LogFilterType>());
                //globalModuleIDs.Add(path, globalModID); //sharing violation here???

                if (localmodID >= modIDTranslationVec.Count)
                {
                    for (int i = 0; i < localmodID + 20; i++)
                    {
                        modIDTranslationVec.Add(-1);
                    }
                }
                modIDTranslationVec[localmodID] = globalModID;

                ModuleTraceStates.Add(isInstrumented == '1' ? eCodeInstrumentation.eInstrumentedCode : eCodeInstrumentation.eUninstrumentedCode);
                LoadedModuleBounds.Add(new Tuple<ulong, ulong>(start, end));

                LoadedModuleCount += 1;
            }
        }



        /// <summary>
        /// Add a recorded symbol to an address
        /// </summary>
        /// <param name="localModnum">Internal module number returned by the instrumentation tool</param>
        /// <param name="offset">Offset of the symbol in the module</param>
        /// <param name="name">Name of the symbol</param>
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
                        Logging.RecordLogEvent($"Failed to translate module ID {localModnum}", filter: Logging.LogFilterType.Error);
                        return;
                    }
                }
                Debug.Assert(modnum != -1);

                if (!modsymsPlain.ContainsKey(modnum))
                {
                    modsymsPlain.Add(modnum, new Dictionary<ulong, string?>());
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

        /// <summary>
        /// Does a symbol exist at this address
        /// </summary>
        /// <param name="GlobalModuleNumber">The module containing the address</param>
        /// <param name="address">The address</param>
        /// <returns>true if a symbol exists here</returns>
        public bool SymbolExists(int GlobalModuleNumber, ulong address)
        {
            return modsymsPlain.TryGetValue(GlobalModuleNumber, out Dictionary<ulong, string?>? syms) && syms.ContainsKey(address - LoadedModuleBounds[GlobalModuleNumber].Item1);
        }


        /// <summary>
        /// Get the symbol at an address
        /// </summary>
        /// <param name="GlobalModuleNumber">The module containing the address</param>
        /// <param name="address">The address</param>
        /// <param name="symbol">Output symbol retrieved</param>
        /// <returns>If found</returns>
        public bool GetSymbol(int GlobalModuleNumber, ulong address, out string? symbol)
        {
            lock (ModulesLock)
            {
                if (modsymsPlain.ContainsKey(GlobalModuleNumber))
                {
                    ulong offset = address - LoadedModuleBounds[GlobalModuleNumber].Item1;
                    return modsymsPlain[GlobalModuleNumber].TryGetValue(offset, out symbol);
                }
            }
            symbol = null;
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
            if (!FindContainingModule(address, out int? modNum))
            {
                moduleID = -1;
                module = "";
                symbol = "";
                return false;
            }
            moduleID = modNum!.Value;

            lock (ModulesLock)
            {
                module = LoadedModulePaths[moduleID];

                if (modsymsPlain.ContainsKey(moduleID))
                {
                    string? foundSym;
                    ulong offset = address - LoadedModuleBounds[moduleID].Item1;
                    if (modsymsPlain[moduleID].TryGetValue(offset, out foundSym))
                    {
                        symbol = foundSym!;
                        return symbol is not null;
                    }
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


        /// <summary>
        /// Get the ID of the block at the specified address
        /// This is a blocking operation which waits for the block to appear in 
        /// disassembly if it was not present at the time of the call
        /// </summary>
        /// <param name="address">Address of the block</param>
        /// <returns>The ID of the block</returns>
        public ulong WaitForBlockAtAddress(ulong address)
        {
            bool hasBlock = false;
            while (!hasBlock && !rgatState.rgatIsExiting)
            {
                lock (InstructionsLock)
                {
                    hasBlock = blockIDDict.ContainsKey(address);
                }
                if (hasBlock)
                {
                    break;
                }

                bool found = FindContainingModule(address, out int? moduleNo);
                if (!found || ModuleTraceStates.Count <= moduleNo)
                {
                    Logging.WriteConsole($"Warning: Unable to find extern module {moduleNo} in ModuleTraceStates dict");
                    Thread.Sleep(15);
                    continue;
                }
                if (ModuleTraceStates[moduleNo!.Value] == eCodeInstrumentation.eUninstrumentedCode)
                {
                    return ulong.MaxValue;
                }
                Logging.WriteConsole($"Waiting for block at 0x{address:x}");
                Thread.Sleep(15);

            }
            return blockIDDict[address][^1];
        }


        /// <summary>
        /// Given a block ID, wait until it is dissembled and return the address
        /// </summary>
        /// <param name="blockID">Block ID to find</param>
        /// <param name="address">output address when it exists</param>
        /// <returns>if the block was found. will only return false if cancelled by rgat exit</returns>
        public bool WaitForAddressOfBlock(uint blockID, out ulong address)
        {
            int timewaited = 0;
            while (true)
            {

                lock (InstructionsLock)
                {
                    if (BasicBlocksList.Count > blockID)
                    {
                        var item = BasicBlocksList[(int)blockID];
                        if (item is not null)
                        {
                            address = item.Item1;
                            return true;
                        }
                    }
                }
                if (rgatState.rgatIsExiting)
                {
                    address = 0;
                    return false;
                }
                Thread.Sleep(2);
                timewaited += 2;
                if (timewaited > 2500 && (timewaited % 1000) == 0)
                {
                    Logging.WriteConsole($"Warning, long wait for block {blockID}. Currently {timewaited / 1000}s");
                    if (timewaited > 5000)
                    {
                        address = 0;
                        return false;
                    }
                }

            }
        }


        /// <summary>
        /// Get the address of a block
        /// </summary>
        /// <param name="blockID">The ID of the block</param>
        /// <returns>The address of the block</returns>
        public ulong GetAddressOfBlock(int blockID)
        {
            Debug.Assert(blockID != -1 && blockID < BasicBlocksList.Count);
            var item = BasicBlocksList[blockID];
            Debug.Assert(item is not null);
            return item.Item1;
        }


        /// <summary>
        /// Record a disassembled block from the blockreader worker
        /// </summary>
        /// <param name="blockID">ID of the block</param>
        /// <param name="address">Address of the block</param>
        /// <param name="instructions">The blocks disassembled instructions</param>
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


        /// <summary>
        /// Filesystem paths of loaded modules
        /// </summary>
        public List<string> LoadedModulePaths = new List<string>();
        /// <summary>
        /// Translation list of local module IDs (known to the instrumentation engine) to global module IDs (known to rgat)
        /// </summary>
        public List<int> modIDTranslationVec = new List<int>();
        /// <summary>
        /// API references of modules for API metadata operations
        /// </summary>
        public List<int> ModuleAPIReferences = new List<int>();
        /// <summary>
        /// Start and end memory addresses of each module
        /// </summary>
        public List<Tuple<ulong, ulong>> LoadedModuleBounds = new List<Tuple<ulong, ulong>>();
        /// <summary>
        /// Whether each modules is instrumented or not
        /// </summary>
        public List<eCodeInstrumentation> ModuleTraceStates = new List<eCodeInstrumentation>();

        /// <summary>
        /// Number of loaded modules
        /// </summary>
        public int LoadedModuleCount = 0;

        //todo review these
        private readonly object ModulesLock = new object();

        /// <summary>
        /// Guards access to API call data
        /// This is accessed from plottedgraph, protograph and process record but shouldnt be
        /// May need to give each ROUTINE_STRUCT threadcallers item its own lock
        /// </summary>
        public readonly object ExternCallerLock = new object(); //todo stop this being public

        private readonly object SymbolsLock = new object();
        private readonly Dictionary<int, Dictionary<ulong, string?>> modsymsPlain = new Dictionary<int, Dictionary<ulong, string?>>();

        private readonly Dictionary<int, Dictionary<ulong, Logging.LogFilterType>> APITypes = new Dictionary<int, Dictionary<ulong, Logging.LogFilterType>>();

        /// <summary>
        /// Get the unique API reference value for the specified module
        /// </summary>
        /// <param name="GlobalModuleID">Global module ID</param>
        /// <returns>An API reference value which can be used in API metadata lookup operations</returns>
        public int GetModuleReference(int GlobalModuleID)
        {
            if (GlobalModuleID >= modsymsPlain.Count)
            {
                return -1; //todo race condition here where it could stay as -1 if requested too early?
            }

            return ModuleAPIReferences[GlobalModuleID];
        }


        /// <summary>
        /// Get API details for a module/address
        /// </summary>
        /// <param name="globalModuleID">Module</param>
        /// <param name="moduleAPIRef">API data reference</param>
        /// <param name="address">Address of the symbol</param>
        /// <returns>API details for that entry or null if not found</returns>
        public APIDetailsWin.API_ENTRY? GetAPIEntry(int globalModuleID, int moduleAPIRef, ulong address)
        {
            if (moduleAPIRef == -1)
            {
                return null;
            }

            ulong symbolOffset = address - LoadedModuleBounds[globalModuleID].Item1;
            if (modsymsPlain[globalModuleID].TryGetValue(symbolOffset, out string? symname) && symname is not null)
            {
                return APIDetailsWin.GetAPIInfo(moduleAPIRef, symname);
            }

            return null;
        }


        /// <summary>
        /// Get all the nodes found at an address in a thread
        /// </summary>
        /// <param name="addr">Memory address</param>
        /// <param name="TID">The thread with the instructions in it</param>
        /// <returns></returns>
        public List<uint> GetNodesAtAddress(ulong addr, uint TID)
        {
            lock (InstructionsLock)
            {
                if (!disassembly.TryGetValue(addr, out List<InstructionData>? inslist))
                {
                    lock (ExternCallerLock)
                    {
                        if (externdict.TryGetValue(addr, out ROUTINE_STRUCT val))
                        {
                            if (val.ThreadCallers.TryGetValue(TID, out List<Tuple<uint, uint>>? callers))
                            {
                                return callers.Select(x => x.Item2).ToList();
                            }
                        }
                    }
                    return new List<uint>();
                }
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


        /// <summary>
        /// Guard disassembly data structures
        /// TODO: This needs to not be public and should be a RW lock
        /// </summary>
        public readonly object InstructionsLock = new object();


        /// <summary>
        /// maps instruction addresses to list of different instructions that resided at that address
        /// </summary>
        public Dictionary<ulong, List<InstructionData>> disassembly = new Dictionary<ulong, List<InstructionData>>();


        /// <summary>
        /// list of address, basic blocks - guarded by instructionslock
        /// </summary>
        public List<Tuple<ulong, List<InstructionData>>?> BasicBlocksList = new();

        private readonly Dictionary<ulong, List<ulong>> blockIDDict = new Dictionary<ulong, List<ulong>>();

        /// <summary>
        /// The entries into uninstrumented code
        /// </summary>
        public Dictionary<ulong, ROUTINE_STRUCT> externdict = new Dictionary<ulong, ROUTINE_STRUCT>();

        /// <summary>
        /// This process is 32 or 64 bit
        /// </summary>
        public int BitWidth;




        private struct ADDRESS_DATA
        {
            public ulong address;
            public int moduleID;
            public bool hasSym;
            public bool blockBoundary;
        };


        /// <summary>
        /// for disassembling saved instructions
        /// takes a capstone context, opcode string, target instruction data struct and the address of the instruction
        /// </summary>
        /// <param name="disassembler">capstone disassembler instance</param>
        /// <param name="address">instruction address</param>
        /// <param name="insdata">partially initialsed instruction data with the bytes</param>
        /// <returns>Number of bytes disassembled</returns>
        public static int DisassembleIns(CapstoneX86Disassembler disassembler, ulong address, InstructionData insdata)
        {
            X86Instruction[] instructions = disassembler.Disassemble(insdata.Opcodes, (long)address);
            //todo: catch some kind of exception, since i cant see any way of getting error codes
            if (instructions.Length != 1)
            {
                Logging.RecordLogEvent("Failed disassembly for opcodes: " + insdata.Opcodes);
                return 0;
            }

            X86Instruction insn = instructions[0];

            insdata.Mnemonic = insn.Mnemonic;
            insdata.OpStr = insn.Operand;
            insdata.InsText = insdata.Mnemonic + " " + insdata.OpStr;
            if (insn.Bytes[0] == 0xf2 && insdata.Mnemonic.StartsWith("bnd"))
            {
                insdata.Mnemonic = insn.Mnemonic.Substring(4);
                insdata.IsMPX = true;
            }
            if (insdata.Mnemonic == "call")
            {
                try
                {

                    insdata.branchAddress = Convert.ToUInt64(insn.Operand, 16);
                }
                catch
                {
                    insdata.branchAddress = 0;
                }
                insdata.itype = CONSTANTS.NodeType.eInsCall;
            }

            else if (insdata.Mnemonic == "ret") //todo: iret
            {
                insdata.itype = CONSTANTS.NodeType.eInsReturn;
            }
            else if (insdata.Mnemonic == "jmp")
            {

                insdata.itype = CONSTANTS.NodeType.eInsJump;

                if (insn.Operand.Contains("["))
                {

                    try
                    {
                        int idxAddrStart = insn.Operand.IndexOf('[') + 1;
                        int addrSize = (insn.Operand.IndexOf(']') - idxAddrStart);
                        string targMemAddr = insn.Operand.Substring(idxAddrStart, addrSize);
                        insdata.PossibleidataThunk = true;
                        insdata.branchAddress = Convert.ToUInt64(targMemAddr, 16);
                    } //todo: not a great idea actually... just point to the outgoing neighbours for labels
                    catch { insdata.branchAddress = 0; }

                }
                else
                {
                    try { insdata.branchAddress = Convert.ToUInt64(insdata.OpStr, 16); } //todo: not a great idea actually... just point to the outgoing neighbours for labels
                    catch { insdata.branchAddress = 0; }
                }

                if (insdata.branchAddress == (address + (ulong)insdata.NumBytes))
                {
                    insdata.itype = CONSTANTS.NodeType.eInsUndefined; //junp to next address is nop
                }
            }
            else
            {
                insdata.itype = CONSTANTS.NodeType.eInsUndefined;
                //assume all j+ instructions aside from jmp are conditional (are they?)
                if (insdata.Mnemonic[0] == 'j')
                {
                    insdata.conditional = true;
                    try
                    {
                        insdata.branchAddress = Convert.ToUInt64(insdata.OpStr, 16);
                    } 
                    catch {
                        insdata.branchAddress = 0;
                    }
                    insdata.condDropAddress = insdata.Address + (ulong)insdata.NumBytes;
                }

            }
            return instructions.Length;
        }





        /// <summary>
        /// Serialise this process data to JSON
        /// </summary>
        /// <returns>JObject of the process data</returns>
        public bool Serialise(JsonWriter writer, rgatState.SERIALISE_PROGRESS progress)
        {
            JObject result = new JObject();

            progress.SectionsTotal = 6;
            progress.SectionsComplete = 0;

            JObject? metadata = SerialiseMetaData();
            if (metadata is null) return false;

            metadata.WriteTo(writer);

            progress.SectionsComplete += 1;
            SerialiseModules(writer, progress);
            progress.SectionsComplete += 1;
            SerialiseSymbols(writer, progress);
            progress.SectionsComplete += 1;

            lock (InstructionsLock)
            {
                SerialiseDisassembly(writer, progress);
                progress.SectionsComplete += 1;
                SerialiseBlockData(writer, progress);
                progress.SectionsComplete += 1;
            }
            lock (ExternCallerLock)
            {
                SerialiseExternDict(writer, progress);
                progress.SectionsComplete += 1;
            }
            return true;
        }


        //public void save(rapidjson::Writer<rapidjson::FileWriteStream>& writer);
        /// <summary>
        /// Deserialise the process record from JSON
        /// </summary>
        /// <param name="jsnReader">JSON processrecord</param>
        /// <param name="serializer">JSON processrecord</param>
        /// <param name="progress">JSON processrecord</param>
        /// <returns>If successful</returns>
        public bool Load(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionsTotal = 6;
            progress.SectionsComplete = 0;
            progress.SectionName = "Process Metadata";

            if (DeserialiseMetaData(jsnReader, serializer) is false)
            {
                Logging.RecordLogEvent("Failed to load process metadata");
                return false;
            }

            progress.SectionsComplete += 1;
            progress.SectionName = "Modules";
            if (LoadModules(jsnReader, serializer, progress) is false)
            {
                Logging.RecordLogEvent("ERROR: Failed to load module paths");
                return false;
            }

            progress.SectionsComplete += 1;
            progress.SectionName = "Symbols";
            if (LoadSymbols(jsnReader, serializer, progress) is false)
            {
                Logging.RecordLogEvent("ERROR: Failed to load symbols");
                return false;
            }

            progress.SectionsComplete += 1;
            if (LoadDisassembly(jsnReader, serializer, progress) is false)
            {
                Logging.RecordLogEvent("Disassembly reconstruction failed");
                return false;
            }

            progress.SectionsComplete += 1;
            if (LoadBlockData(jsnReader, serializer, progress) is false)
            {
                Logging.RecordLogEvent("Basic block reconstruction failed");
                return false;
            }

            progress.SectionsComplete += 1;
            if (LoadExterns(jsnReader, serializer, progress) is false)
            {
                Logging.RecordLogEvent("Extern call loading failed");
                return false;
            }
            progress.SectionsComplete += 1;

            return true;

        }


        private JObject? SerialiseMetaData()
        {
            JObject metadata = new JObject();
            metadata.Add("Field", "ProcessRecord");

            if (BitWidth == 32 || BitWidth == 64)
            {
                metadata.Add("BitWidth", BitWidth);
            }
            else
            {
                Logging.RecordLogEvent($"Error: Serialise() - Invalid bitwidth {BitWidth}", Logging.LogFilterType.Error);
                return null;
            }

            return metadata;
        }



        private bool DeserialiseMetaData(JsonReader jsnReader, JsonSerializer serializer)
        {
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "ProcessRecord", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No process data metadata in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("BitWidth", out JToken? tBitWidth) || tBitWidth.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid BitWidth in trace", Logging.LogFilterType.Error);
                return false;
            }

            BitWidth = tBitWidth.ToObject<int>();
            if (BitWidth != 32 && BitWidth != 64)
            {
                Logging.RecordLogEvent("Invalid BitWidth " + BitWidth, Logging.LogFilterType.Error);
                return false;
            }
            return true;
        }



        private void SerialiseModules(JsonWriter writer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionProgress = 0;
            progress.SectionName = "Modules";

            JObject meta = new JObject();
            meta.Add("Field", "Modules");
            meta.WriteTo(writer);

            JArray ModulePaths = new JArray();
            foreach (string path in LoadedModulePaths)
            {
                ModulePaths.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(path)));
            }
            ModulePaths.WriteTo(writer);

            progress.SectionProgress = 0.3f;

            writer.WriteStartArray();
            foreach (Tuple<ulong, ulong> start_end in LoadedModuleBounds)
            {
                writer.WriteValue(start_end.Item1);
                writer.WriteValue(start_end.Item2);
            }
            writer.WriteEndArray();

            progress.SectionProgress = 0.6f;


            JArray ModuleTraceStatesArr = new JArray();
            foreach (eCodeInstrumentation tState in ModuleTraceStates)
            {
                ModuleTraceStatesArr.Add(tState);
            }
            ModuleTraceStatesArr.WriteTo(writer);
            progress.SectionProgress = 1f;

        }


        private bool LoadModules(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Modules", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No module metadata in trace file");
                return false;
            }

            jsnReader.Read();
            var modulesArray = serializer.Deserialize<List<string>>(jsnReader);
            if (modulesArray is null)
            {
                Logging.RecordLogEvent("No module path list in trace file");
                return false;
            }

            progress.SectionProgress = 0.3f;
            if (progress.Cancelled) return false;

            foreach (string b64entry in modulesArray)
            {
                string plainpath = Encoding.Unicode.GetString(Convert.FromBase64String(b64entry));
                LoadedModulePaths.Add(plainpath);
            }

            if (jsnReader.Read() is false || jsnReader.TokenType is not JsonToken.StartArray)
            {
                Logging.RecordLogEvent("Failed to find ModuleBounds array ", Logging.LogFilterType.Error);
                return false;
            }

            LoadedModuleBounds.Clear();

            while (jsnReader.Read() && jsnReader.TokenType == JsonToken.Integer && jsnReader.Value is not null)
            {
                ulong startBound = (ulong)((long)jsnReader.Value);
                if (jsnReader.Read() && jsnReader.TokenType == JsonToken.Integer && jsnReader.Value is not null)
                {
                    ulong endBound = (ulong)((long)jsnReader.Value);
                    LoadedModuleBounds.Add(new Tuple<ulong, ulong>(startBound, endBound));
                }
                else
                {
                    Logging.RecordLogEvent("Bad module bounds entry");
                    return false;
                }
            }
            if (jsnReader.TokenType is not JsonToken.EndArray)
            {
                Logging.RecordLogEvent("Expected ModuleBounds array termination");
                return false;
            }

            progress.SectionProgress = 0.6f;
            if (progress.Cancelled) return false;

            jsnReader.Read();
            List<eCodeInstrumentation>? ilist = serializer.Deserialize<List<eCodeInstrumentation>>(jsnReader);
            if (ilist is not null && ilist.Count == LoadedModulePaths.Count)
            {
                ModuleTraceStates = ilist;
                LoadedModuleCount = LoadedModulePaths.Count;
            }
            else
            {
                Logging.RecordLogEvent("Failed to load ModuleTraceStates");
                return false;
            }

            progress.SectionProgress = 1f;
            return true;
        }



        private void SerialiseSymbols(JsonWriter writer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionProgress = 0;
            progress.SectionName = "Symbols";

            JObject meta = new JObject();
            meta.Add("Field", "Symbols");
            meta.Add("ModuleCount", modsymsPlain.Count);
            meta.Add("TotalSymbols", modsymsPlain.Values.Sum(x => x.Count));
            meta.WriteTo(writer);

            int doneCount = 0;
            foreach (var modID_symsdict in modsymsPlain)
            {
                writer.WriteStartArray();
                writer.WriteValue(modID_symsdict.Key); //module ID
                writer.WriteValue(modID_symsdict.Value.Count); //symbol count

                foreach (var address_symstring in modID_symsdict.Value)
                {
                    writer.WriteValue(address_symstring.Key); //address
                    writer.WriteValue(address_symstring.Value); //name
                }
                writer.WriteEndArray();
                doneCount += 1;
                progress.SectionProgress = doneCount / (float)modsymsPlain.Count;
                if (progress.Cancelled) return;
            }
        }



        private bool LoadSymbols(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Symbols", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No module metadata in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("ModuleCount", out JToken? countTok) || countTok.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid ModuleCount in trace symbols list");
                return false;
            }
            progress.SectionProgress = 0;

            int modulesToLoad = countTok.ToObject<int>();
            int loaded = 0;
            while (loaded < modulesToLoad && jsnReader.Read() && jsnReader.TokenType == JsonToken.StartArray)
            {
                if (jsnReader.Read() is false || jsnReader.TokenType is not JsonToken.Integer || jsnReader.Value is null) return false;
                int modID = (int)((long)jsnReader.Value);

                modsymsPlain.Add(modID, new Dictionary<ulong, string?>());

                if (jsnReader.Read() is false || jsnReader.TokenType is not JsonToken.Integer) return false;
                int symCount = (int)((long)jsnReader.Value);
                jsnReader.Read();

                for (var symI = 0; symI < symCount; symI++)
                {
                    ulong SymAddress = serializer.Deserialize<ulong>(jsnReader); jsnReader.Read();
                    string? SymName = serializer.Deserialize<string>(jsnReader); jsnReader.Read();

                    modsymsPlain[modID][SymAddress] = SymName;
                }

                if (jsnReader.TokenType is not JsonToken.EndArray)
                {
                    Logging.RecordLogEvent("Bad symbol entry");
                    return false;
                }
                loaded += 1;

                progress.SectionProgress = loaded / (float)modulesToLoad;
                if (progress.Cancelled) return false;
            }
            return true;
        }



        private void SerialiseDisassembly(JsonWriter writer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionProgress = 0;
            progress.SectionName = "Code";

            JObject meta = new JObject();
            meta.Add("Field", "Disassembly");
            meta.Add("Count", disassembly.Count);
            meta.WriteTo(writer);

            int doneCount = 0;
            foreach (KeyValuePair<ulong, List<InstructionData>> addr_inslist in disassembly)
            {
                JArray insentry = new JArray
                {
                    addr_inslist.Key,
                    addr_inslist.Value[0].GlobalModNum,
                    addr_inslist.Value[0].BlockBoundary ? 1 : 0
                };

                List<InstructionData> addrinstructions = addr_inslist.Value;
                insentry.Add(addrinstructions.Count); //how many different instructions were seen at that address

                foreach (var mutation in addr_inslist.Value)
                {
                    string opcodestring;
                    if (mutation.Opcodes is null)
                    {
                        Debug.Assert(mutation.InsText.Contains("INVALID"));
                        opcodestring = "";
                    }
                    else
                    {
                        opcodestring = System.Convert.ToBase64String(mutation.Opcodes!);
                    }
                    insentry.Add(opcodestring);

                    List<Tuple<uint, uint>> threadVerts = mutation.ThreadVerts;

                    insentry.Add(threadVerts.Count);
                    foreach (Tuple<uint, uint> thread_node in threadVerts)
                    {
                        insentry.Add(thread_node.Item1); // thread ID
                        insentry.Add(thread_node.Item2); // node index of instruction on thread graph
                    }

                }
                insentry.WriteTo(writer);
                doneCount += 1;
                progress.SectionProgress = doneCount / (float)disassembly.Count;
                if (progress.Cancelled) return;
            }
        }




        private bool LoadDisassembly(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = "Disassembly";
            progress.SectionProgress = 0;

            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Disassembly", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No Disassembly metadata in trace file");
                return false;
            }

            if (!mdObj.TryGetValue("Count", out JToken? countTok) || countTok.Type != JTokenType.Integer)
            {
                Logging.RecordLogEvent("Failed to find valid Count in LoadDisassembly");
                return false;
            }

            X86DisassembleMode disasMode = (BitWidth == 32) ? X86DisassembleMode.Bit32 : X86DisassembleMode.Bit64;
            using CapstoneX86Disassembler disassembler = CapstoneDisassembler.CreateX86Disassembler(disasMode);
            
            int insCount = countTok.ToObject<int>();
            for (int i = 0; i < insCount; i++)
            {
                if (jsnReader.Read() is false || jsnReader.TokenType is not JsonToken.StartArray)
                {
                    Logging.RecordLogEvent("Bad disassembly array");
                    return false;
                }

                JArray? entry = serializer.Deserialize<JArray>(jsnReader);
                if (entry is null || entry.Count is 0)
                {
                    Logging.RecordLogEvent("No instructions in LoadDisassembly");
                    return false;
                }
                if (!UnpackAddress(entry, disassembler))
                {
                    return false;
                }
                progress.SectionProgress = i / (float)insCount;
                if (progress.Cancelled) return false;
            }

            return true;
        }


        private bool UnpackAddress(JArray entry, CapstoneX86Disassembler disassembler)
        {
            if (entry.Type != JTokenType.Array || entry.Count < 4 ||
                       entry[0].Type != JTokenType.Integer ||
                       entry[1].Type != JTokenType.Integer ||
                       entry[2].Type != JTokenType.Integer ||
                       entry[3].Type != JTokenType.Integer
                       )
            {
                Logging.RecordLogEvent("Invalid disassembly entry in saved trace", Logging.LogFilterType.Error);
                return false;
            }

            ADDRESS_DATA addressData = new ADDRESS_DATA
            {
                address = entry[0].ToObject<ulong>(),
                moduleID = entry[1].ToObject<int>(),
                blockBoundary = entry[2].ToObject<int>() == 1
            };

            addressData.hasSym = (modsymsPlain.ContainsKey(addressData.moduleID) &&
                                modsymsPlain[addressData.moduleID].ContainsKey(addressData.address));


            int mutationCount = (int)entry[3];
            int entryIndex = 4;

            List<InstructionData> opcodeVariants = new List<InstructionData>();
            for (var mi = 0; mi < mutationCount; mi++)
            {
                string opcodeB64 = entry[entryIndex + mi].ToString();
                entryIndex += 1;

                InstructionData ins = new InstructionData
                {
                    GlobalModNum = addressData.moduleID,
                    hasSymbol = addressData.hasSym,
                    Address = addressData.address,
                    BlockBoundary = addressData.blockBoundary
                };

                if (opcodeB64.Length > 0)
                {
                    ins.Opcodes = System.Convert.FromBase64String(opcodeB64);
                    if (DisassembleIns(disassembler, addressData.address, ins) is 0)
                        return false;
                }
                else
                {
                    ins.InsText = "INVALID INSTRUCTION";
                }

                int threadvertCount = (int)entry[entryIndex + mi];
                entryIndex += 1;

                for (var vertI = 0; vertI < threadvertCount; vertI++)
                {
                    uint thread = (uint)entry[entryIndex + mi];
                    entryIndex += 1;
                    uint vertIndex = (uint)entry[entryIndex + mi];
                    entryIndex += 1;

                    ins.ThreadVerts.Add(new Tuple<uint, uint>(thread, vertIndex));
                }
                opcodeVariants.Add(ins);
            }

            disassembly.Add(addressData.address, opcodeVariants);
            return true;
        }



        private void SerialiseBlockData(JsonWriter writer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionProgress = 0;
            progress.SectionName = "Blocks";

            JObject meta = new JObject();
            meta.Add("Field", "BasicBlocks");
            meta.Add("Count", BasicBlocksList.Count);
            meta.WriteTo(writer);

            int doneCount = 0;
            foreach (var addr_inslist in BasicBlocksList)
            {
                if (addr_inslist is null)
                {
                    writer.WriteNull();
                    continue;
                }

                JArray blockArray = new JArray
                {
                    addr_inslist.Item1,
                    addr_inslist.Item2.Count
                };
                foreach (InstructionData i in addr_inslist.Item2)
                {
                    blockArray.Add(i.Address);
                    blockArray.Add(i.MutationIndex);
                }

                blockArray.WriteTo(writer);
                doneCount += 1;
                progress.SectionProgress = doneCount / (float)BasicBlocksList.Count;
                if (progress.Cancelled) return;
            }
        }


        private bool LoadBlockData(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = "Blocks";
            progress.SectionProgress = 0;
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "BasicBlocks", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No BasicBlocks metadata in trace file");
                return false;
            }

            if (mdObj.TryGetValue("Count", out JToken? countTok) is false || countTok is null)
            {
                Logging.RecordLogEvent("No BasicBlocks count in LoadBlockData");
                return false;
            }
            int blockCount = countTok.ToObject<int>();


            BasicBlocksList.Capacity = blockCount; //kindof want to sanity check this but Int.MaxValue is not unrealistic for genuine data

            for (int blockID = 0; blockID < blockCount; blockID++)
            {
                if (!jsnReader.Read()) return false;
                if (jsnReader.TokenType == JsonToken.Null)
                {
                    jsnReader.Read();
                    BasicBlocksList[blockID] = null;
                    continue;
                }
                if (jsnReader.TokenType == JsonToken.StartArray)
                {
                    jsnReader.Read();
                    ulong blockAddress = serializer.Deserialize<ulong>(jsnReader); jsnReader.Read();
                    List<InstructionData> blkInstructions = new List<InstructionData>();
                    int insCount = serializer.Deserialize<int>(jsnReader); jsnReader.Read();
                    for (var insI = 0; insI < insCount; insI++)
                    {
                        ulong insAddress = serializer.Deserialize<ulong>(jsnReader); jsnReader.Read();
                        int mutationIndex = serializer.Deserialize<int>(jsnReader); jsnReader.Read();
                        if (insAddress is 5850545)
                        {
                            Console.WriteLine("s");
                        }
                        InstructionData ins = disassembly[insAddress][mutationIndex];
                        blkInstructions.Add(ins);
                        if (ins.ContainingBlockIDs == null)
                        {
                            ins.ContainingBlockIDs = new List<uint>();
                        }

                        ins.ContainingBlockIDs.Add((uint)blockID);
                    }
                    BasicBlocksList.Add(new Tuple<ulong, List<InstructionData>>(blockAddress, blkInstructions));
                }
                progress.SectionProgress = blockID / (float)blockCount;
                if (progress.Cancelled) return false;
            }

            return true;
        }


        private void SerialiseExternDict(JsonWriter writer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = "Externals";
            progress.SectionProgress = 0;

            JObject meta = new JObject();
            meta.Add("Field", "Externs");
            meta.Add("Count", externdict.Count);
            meta.WriteTo(writer);

            int doneCount = 0;
            foreach (var addr_rtnstruct in externdict)
            {
                ROUTINE_STRUCT externStruc = addr_rtnstruct.Value;
                JArray externArr = new JArray
                {
                     addr_rtnstruct.Key, //address
                     externStruc.Module,
                     externStruc.HasSymbol
                };

                externArr.Add(externStruc.ThreadCallers.Count);

                if (externStruc.ThreadCallers.Count > 0)
                {
                    foreach (var thread_edgelist in externStruc.ThreadCallers)
                    {
                        externArr.Add(thread_edgelist.Key);
                        externArr.Add(thread_edgelist.Value.Count);

                        foreach (var edge in thread_edgelist.Value)
                        {
                            externArr.Add(edge.Item1);
                            externArr.Add(edge.Item2);
                        }
                    }
                }
                externArr.WriteTo(writer);
                doneCount += 1;
                progress.SectionProgress = doneCount / (float)externdict.Count;
                if (progress.Cancelled) return;
            }
        }



        private bool LoadExterns(JsonReader jsnReader, JsonSerializer serializer, rgatState.SERIALISE_PROGRESS progress)
        {
            progress.SectionName = "Externals";
            progress.SectionProgress = 0;
            if (BinaryTargets.ValidateSavedMetadata(jsnReader, serializer, "Externs", out JObject? mdObj) is false || mdObj is null)
            {
                Logging.RecordLogEvent("No Externs metadata in trace file");
                return false;
            }

            if (mdObj.TryGetValue("Count", out JToken? countTok) is false || countTok is null)
            {
                Logging.RecordLogEvent("No Externs count in LoadExterns");
                return false;
            }
            int count = countTok.ToObject<int>(); 

            for (var externI = 0; externI < count; externI++)
            {
                jsnReader.Read();
                JArray? extArr = serializer.Deserialize<JArray>(jsnReader);
                if (extArr is null || extArr.Count < 4)
                {
                    Logging.RecordLogEvent("Bad extern item");
                    return false;
                }

                ulong externAddr = (ulong)extArr[0];
                ROUTINE_STRUCT externStruc = new ROUTINE_STRUCT()
                {
                    Module = (int)extArr[1],
                    HasSymbol = (bool)extArr[2],
                };

                int threadCount = (int)extArr[3];
                if (threadCount > 0)
                {
                    int arrayIndex = 4;
                    externStruc.ThreadCallers = new();
                    for (var threadI = 0; threadI < threadCount; threadI++)
                    {
                        uint thread = (uint)extArr[arrayIndex]; arrayIndex++;
                        uint callerCount = (uint)extArr[arrayIndex]; arrayIndex++;

                        List<Tuple<uint, uint>> threadCallers = new();
                        for (var callerI = 0; callerI < callerCount; callerI++)
                        {
                            uint src = (uint)extArr[arrayIndex]; arrayIndex++;
                            uint targ = (uint)extArr[arrayIndex]; arrayIndex++;
                            threadCallers.Add(new Tuple<uint, uint>(src, targ));
                        }
                        externStruc.ThreadCallers.Add(thread, threadCallers);
                    }
                }
                externdict[externAddr] = externStruc;
                progress.SectionProgress = externI / (float)count;
                if (progress.Cancelled) return false;
            }
            return true;
        }
    }
}
