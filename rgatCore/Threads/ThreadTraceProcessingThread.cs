using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgatCore.Threads
{
    class ThreadTraceProcessingThread
    {
        ProtoGraph protograph;
        Thread runningThread;
        bool IrregularTimerFired = false;
        System.Timers.Timer IrregularActionTimer = null;



        struct BLOCKREPEAT
        {
            //public ulong blockaddr;
            public uint blockID;
            //public uint insCount;
            public List<uint> targBlocks;
            public ulong totalExecs;
            public List<InstructionData> blockInslist;
        };

        List<BLOCKREPEAT> blockRepeatQueue = new List<BLOCKREPEAT>();

        struct NEW_EDGE_BLOCKDATA
        {
            public ulong sourceAddr;
            public uint sourceID;
            public ulong targAddr;
            public uint targID;
        };

        List<NEW_EDGE_BLOCKDATA> PendingEdges = new List<NEW_EDGE_BLOCKDATA>();

        public ThreadTraceProcessingThread(ProtoGraph newProtoGraph)
        {
            protograph = newProtoGraph;

            runningThread = new Thread(Processor);
            runningThread.Name = "TraceProcessor" + this.protograph.ThreadID;
            runningThread.Start();

            IrregularActionTimer = new System.Timers.Timer(800);
            IrregularActionTimer.Elapsed += (sender, args) => IrregularTimerFired = true;
            IrregularActionTimer.AutoReset = false;
            IrregularActionTimer.Start();
        }


        void PerformIrregularActions()
        {
            if (PendingEdges.Count > 0)     SatisfyPendingEdges();
            if (blockRepeatQueue.Count > 0) AssignBlockRepeats();
            IrregularActionTimer.Start();
        }

        //peforms non-sequence critical graph updates
        //update nodes with cached execution counts and new edges from unchained runs
        //also updates graph with delayed edge notifications
        bool AssignBlockRepeats()
        {

            int RecordedBlocksQty = protograph.BlocksFirstLastNodeList.Count;
            List<BLOCKREPEAT> doneRepeats = new List<BLOCKREPEAT>();
            for (var i = 0; i < blockRepeatQueue.Count; i++)
            {
                BLOCKREPEAT brep = blockRepeatQueue[i];
                //first find the blocks instruction list
                if (brep.blockID >= RecordedBlocksQty) continue;
                NodeData n = null;

                if (brep.blockInslist == null)
                {
                    if (brep.blockID >= protograph.BlocksFirstLastNodeList.Count ||
                        protograph.BlocksFirstLastNodeList[(int)brep.blockID] == null)
                    {
                        continue;
                    }

                    brep.blockInslist = protograph.ProcessData.BasicBlocksList[(int)brep.blockID].Item2;
                }

                //first record execution of each instruction
                foreach (InstructionData ins in brep.blockInslist)
                {

                    n = protograph.safe_get_node(ins.threadvertIdx[protograph.ThreadID]);
                    n.executionCount += brep.totalExecs;
                    protograph.TotalInstructions += brep.totalExecs;
                }


                //create any new edges between unchained nodes
                List<uint> donelist = new List<uint>();
                foreach (uint targetblockidx in brep.targBlocks)
                {

                    if (targetblockidx < RecordedBlocksQty)
                    {
                        //external libraries will not be found by find_block_disassembly, but will be handled by run_external
                        //this notices it has been handled and drops it from pending list
                        bool alreadyHandled = false;
                        foreach (uint targnidx in n.OutgoingNeighboursSet)
                        {
                            if (protograph.safe_get_node(targnidx).BlockID == targetblockidx)
                            {
                                donelist.Add(targetblockidx);
                                alreadyHandled = true;
                                break;
                            }
                        }
                        if (alreadyHandled) 
                            continue;
                    }

                    List<InstructionData> targetBlock = protograph.ProcessData.BasicBlocksList[(int)targetblockidx].Item2;
                    InstructionData firstIns = targetBlock[0];
                    if (firstIns.threadvertIdx.ContainsKey(protograph.ThreadID))
                    {

                        uint srcNode = protograph.BlocksFirstLastNodeList[(int)brep.blockID].Item2;
                        uint targNode = firstIns.threadvertIdx[protograph.ThreadID];
                        if (!protograph.edgeDict.ContainsKey(new Tuple<uint, uint>(srcNode, targNode)))
                        {
                            Console.WriteLine($"Assigned new edge from node {srcNode} to {targNode}");
                            protograph.AddEdge(srcNode, targNode);
                        }

                        //cout << "assign block repeats. block id " <<dec << blockid << " / addr 0x" << hex << 
                        //	firstIns->address << " not on graph in thread " << dec << TID << endl;

                        donelist.Add(targetblockidx);
                        continue;
                    }
                    
                }

                brep.targBlocks = brep.targBlocks.Except(donelist).ToList();
                if (brep.targBlocks.Count == 0)
                {
                    doneRepeats.Add(brep);
                }
            }

            blockRepeatQueue = blockRepeatQueue.Except(doneRepeats).ToList();
            return blockRepeatQueue.Count == 0;
        }



        void SatisfyPendingEdges()
        {
            int blockQty = protograph.BlocksFirstLastNodeList.Count;
            List<NEW_EDGE_BLOCKDATA> doneList = new List<NEW_EDGE_BLOCKDATA>();
            foreach( NEW_EDGE_BLOCKDATA pnd in PendingEdges )
            {
                if (pnd.sourceID > blockQty || pnd.targID > blockQty) continue;
                Console.WriteLine($"Satisfying an edge request! {pnd.sourceID}:0x{pnd.sourceAddr:X}->{pnd.targID}:0x{pnd.targAddr:X}");

                uint SrcNodeIdx = protograph.BlocksFirstLastNodeList[(int)pnd.sourceID].Item2;
                uint TargNodeIdx = protograph.BlocksFirstLastNodeList[(int)pnd.targID].Item1;
                protograph.AddEdge(SrcNodeIdx, TargNodeIdx);
                doneList.Add(pnd);
            }

            PendingEdges = PendingEdges.Except(doneList).ToList();
        }


        void ProcessLoopMarker(byte[] entry)
        {
            if (entry[1] == 'S')//LOOP START MARKER
            {
                ulong loopIterations = BitConverter.ToUInt32(entry, 2);
                Console.WriteLine($"Processing loop started marker {loopIterations} iterations");
                protograph.SetLoopState(eLoopState.eBuildingLoop, loopIterations);
            }
            else if (entry[1] == 'E')//LOOP END MARKER
            {
                Console.WriteLine($"Processing loop ended marker");
                protograph.DumpLoop();
            }
        }

        public void ProcessTraceTag(byte[] entry)
        {
            TAG thistag;
            ulong nextBlockAddress;
            int tokenpos = 0;
            for (; tokenpos < entry.Length; tokenpos++) if (entry[tokenpos] == ',') break;

            thistag.blockID = uint.Parse(Encoding.ASCII.GetString(entry, 1, tokenpos - 1), NumberStyles.HexNumber);
            thistag.blockaddr = protograph.ProcessData.EnsureBlockExistsGetAddress(thistag.blockID);
            Debug.Assert(thistag.blockID < protograph.ProcessData.BasicBlocksList.Count, "ProcessTraceTag tried to process block that hasn't been disassembled");

            int addrstart = ++tokenpos;
            nextBlockAddress = ulong.Parse(Encoding.ASCII.GetString(entry, addrstart, entry.Length - addrstart), NumberStyles.HexNumber);

            thistag.jumpModifier = eCodeInstrumentation.eInstrumentedCode;
            thistag.foundExtern = null;
            thistag.insCount = 0; //meaningless here


            if (protograph.loopState == eLoopState.eBuildingLoop)
            {
                protograph.loopCache.Add(thistag);
            }
            else
            {
                protograph.handle_tag(thistag);

                ANIMATIONENTRY animUpdate = new ANIMATIONENTRY();
                animUpdate.entryType = eTraceUpdateType.eAnimExecTag;
                animUpdate.blockAddr = thistag.blockaddr;
                animUpdate.blockID = thistag.blockID;
                protograph.PushAnimUpdate(animUpdate);
            }

            //fallen through/failed conditional jump
            if (nextBlockAddress == 0) return;

            eCodeInstrumentation modType = protograph.TraceData.FindContainingModule(nextBlockAddress, out int modnum);
            if (modType == eCodeInstrumentation.eInstrumentedCode) return;

            //modType could be known unknown here
            //in case of unknown, this waits until we know. hopefully rare.
            int attempts = 1;

            TAG externTag = new TAG();
            externTag.jumpModifier = eCodeInstrumentation.eUninstrumentedCode;
            externTag.blockaddr = nextBlockAddress;

            if (protograph.loopState == eLoopState.eBuildingLoop)
                protograph.loopCache.Add(externTag);
            else
            {
                protograph.handle_tag(externTag);

                ANIMATIONENTRY animUpdate = new ANIMATIONENTRY();
                animUpdate.blockAddr = nextBlockAddress;
                animUpdate.entryType = eTraceUpdateType.eAnimExecTag;
                animUpdate.blockID = uint.MaxValue;
                Tuple<ulong, uint> callkey = new Tuple<ulong, uint>(thistag.blockaddr, thistag.blockID);
                if (protograph.externFuncCallCounter.TryGetValue(callkey, out ulong prevCount))
                {
                    protograph.externFuncCallCounter[callkey] = prevCount + 1;
                    animUpdate.callCount = prevCount + 1;
                }
                else
                {
                    protograph.externFuncCallCounter.Add(callkey, 1);
                    animUpdate.callCount = 1;
                }
                protograph.PushAnimUpdate(animUpdate);
            }
        }



        //decodes argument and places in processing queue, processes if all decoded for that call
        void HandleArg(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 6);

            int argIdx = int.Parse(entries[1], NumberStyles.Integer);
            ulong funcpc = ulong.Parse(entries[2], NumberStyles.HexNumber);
            ulong returnpc = ulong.Parse(entries[3], NumberStyles.HexNumber);
            char moreArgsFlag = entries[4][0];

            bool callDone = moreArgsFlag == 'E' ? true : false;
            string argstring = entries[5];


            if (!protograph.hasPendingCalledFunc())
            {
                bool hasPendingFuncCaller = protograph.notify_pending_func(funcpc, returnpc);
                if (!hasPendingFuncCaller)
                    return;
            }

            //contents = string("<NULLARG>");


            protograph.add_pending_arguments(argIdx, argstring, callDone);

        }

        /*
         Adds a link between previously unlinked instructions that are within an unchained area
         */
        bool UnchainedLinkingUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 8);

            ulong sourceAddr = ulong.Parse(entries[1], NumberStyles.HexNumber);
            uint src_blockID = (uint)ulong.Parse(entries[2], NumberStyles.HexNumber);
            uint src_numins = (uint)ulong.Parse(entries[3], NumberStyles.HexNumber);




            ulong targetAddr = ulong.Parse(entries[7], NumberStyles.HexNumber);



            protograph.PerformingUnchainedExecution = false;

            List<InstructionData> lastBB = protograph.ProcessData.getDisassemblyBlock(src_blockID);
            InstructionData lastIns = lastBB[^1];
            bool found = lastIns.threadvertIdx.TryGetValue(protograph.ThreadID, out uint srcidx);
            if (!found)
            {
                Console.WriteLine($"AddUnlinkingUpdate Error: Unable to find node for instruction 0x{lastIns.address:X}: {lastIns.ins_text} in thread {protograph.ThreadID}");
                return false;
            }

            protograph.ProtoLastVertID = srcidx;


            TAG thistag;
            thistag.blockaddr = ulong.Parse(entries[4], NumberStyles.HexNumber);
            thistag.blockID = (uint)ulong.Parse(entries[5], NumberStyles.HexNumber);
            thistag.insCount = (uint)ulong.Parse(entries[6], NumberStyles.HexNumber);
            thistag.jumpModifier = eCodeInstrumentation.eInstrumentedCode;
            thistag.foundExtern = null;
            protograph.handle_tag(thistag);


            Debug.Assert(protograph.BlocksFirstLastNodeList.Count > src_blockID, "Bad src block id in unlinking update");


            Console.WriteLine($"Processing UnchainedLinkingUpdate source 0x{sourceAddr:X} inscount {src_numins} currentaddr 0x{thistag.blockaddr:X}");



            if (protograph.TraceData.FindContainingModule(targetAddr, out int modnum) == eCodeInstrumentation.eUninstrumentedCode)
            {
                protograph.ProcessData.get_extern_at_address(targetAddr, modnum, out ROUTINE_STRUCT foundExtern);

                bool targetFound = false;
                lock (protograph.ProcessData.ExternCallerLock)
                {
                    if (foundExtern.thread_callers.TryGetValue(protograph.ThreadID, out List<Tuple<uint, uint>> callList))
                    {
                        foreach (Tuple<uint, uint> edge in callList)
                        {
                            if (edge.Item1 == protograph.targVertID)
                            {
                                targetFound = true;
                                protograph.ProtoLastVertID = foundExtern.thread_callers[protograph.ThreadID][0].Item2;
                                NodeData lastnode = protograph.safe_get_node(protograph.ProtoLastVertID);
                                ++lastnode.executionCount;
                                break;
                            }
                        }
                        if (!targetFound)
                        {
                            Console.WriteLine($"[rgat]Warning: 0x{targetAddr:X} in {protograph.ProcessData.LoadedModulePaths[foundExtern.globalmodnum]} not found. Heatmap accuracy may suffer.");
                        }
                    }
                    else
                    {
                        /*
                        i've only seen this fail when unlinking happens at the end of a program. eg:
                            int main()
                            {
                                for (many iterations){ do a thing; }
                                return 0;  <- targ2 points to address outside program... can't draw an edge to it
                            }
                        which is not a problem. this happens in the nestedloops tests

                        Could come up with a way to only warn if the thread continues (eg: if anything at all comes after this from the trace pipe).
                        For now as it hasn't been a problem i've improvised by checking if we return to code after the BaseThreadInitThunk symbol,
                            but this is not reliable outside of my runtime environment
                        */


                        bool foundsym = false;
                        string sym = "";
                        ulong offset;

                        if (foundExtern.globalmodnum != -1)
                        {
                            offset = targetAddr - protograph.ProcessData.LoadedModuleBounds[foundExtern.globalmodnum].Item1;

                            //i haven't added a good way of looking up the nearest symbol. this requirement should be rare, but if not it's a todo

                            for (int i = 0; i < 4096; i++)
                            {
                                if (protograph.ProcessData.GetSymbol(foundExtern.globalmodnum, offset - (ulong)i, out sym))
                                {
                                    foundsym = true;
                                    break;
                                }
                            }
                            if (!foundsym) sym = "Unknown Symbol";

                            if (sym != "BaseThreadInitThunk")
                            {
                                string modulepath = protograph.ProcessData.LoadedModulePaths[foundExtern.globalmodnum];
                                Console.WriteLine($"[rgat]Warning,  unseen code executed after a busy block. (Module:{modulepath}+0x{offset:X}): '{sym}'");
                                Console.WriteLine("\t If this happened at a thread exit it is not a problem and can be ignored");
                            }
                        }
                        else
                        {

                            Console.WriteLine($"[rgat]Warning, unknown module with addr 0x{targetAddr:X}");
                        }
                    }
                }

            }
            
            ANIMATIONENTRY animUpdate;
            animUpdate.blockAddr = thistag.blockaddr;
            animUpdate.blockID = thistag.blockID;
            animUpdate.entryType = eTraceUpdateType.eAnimUnchainedDone;
            animUpdate.callCount = 0;
            animUpdate.count = 0;
            animUpdate.targetAddr = 0;
            animUpdate.targetID = 0;
            protograph.PushAnimUpdate(animUpdate);
            return true;
        }


        void AddUnchainedUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 5);

            ANIMATIONENTRY animUpdate;
            animUpdate.entryType = eTraceUpdateType.eAnimUnchained;
            animUpdate.blockAddr = ulong.Parse(entries[1], NumberStyles.HexNumber);
            animUpdate.blockID = uint.Parse(entries[2], NumberStyles.HexNumber);
            animUpdate.targetAddr = ulong.Parse(entries[3], NumberStyles.HexNumber);
            animUpdate.targetID = uint.Parse(entries[4], NumberStyles.HexNumber);
            animUpdate.count = 0;
            animUpdate.callCount = 0;
            protograph.PushAnimUpdate(animUpdate);


            Console.WriteLine($"Processing AddUnchainedUpdate source 0x{animUpdate.blockAddr:X} targaddr 0x{animUpdate.targetAddr:X}");
            protograph.PerformingUnchainedExecution = true;
        }



        void AddExecCountUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 4);


            BLOCKREPEAT newRepeat;
            newRepeat.blockID = uint.Parse(entries[1], NumberStyles.HexNumber);
            newRepeat.totalExecs = ulong.Parse(entries[2], NumberStyles.HexNumber);
            newRepeat.targBlocks = new List<uint>();

            Console.WriteLine($"Processing AddExecCountUpdate block {newRepeat.blockID } ");

            string[] rptblocks = entries[3].Split(',');
            
            foreach (string bid_s in rptblocks)
            {
                uint targblockID = uint.Parse(bid_s, NumberStyles.HexNumber);
                newRepeat.targBlocks.Add(targblockID);

                Console.WriteLine($"\t +targ {targblockID} ");
            }

            newRepeat.blockInslist = null;
            //newRepeat.insCount = 0;
            //newRepeat.blockaddr = 0;
            blockRepeatQueue.Add(newRepeat);

            ANIMATIONENTRY animUpdate;
            animUpdate.entryType = eTraceUpdateType.eAnimUnchainedResults;
            animUpdate.blockAddr = 0;
            animUpdate.blockID = newRepeat.blockID;
            animUpdate.count = newRepeat.totalExecs;
            animUpdate.callCount = 0;
            animUpdate.targetAddr = 0;
            animUpdate.targetID = 0;
            protograph.PushAnimUpdate(animUpdate);
        }




        void AddSatisfyUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 5);
            NEW_EDGE_BLOCKDATA edgeNotification;
            edgeNotification.sourceAddr = ulong.Parse(entries[1], NumberStyles.HexNumber);
            edgeNotification.sourceID = uint.Parse(entries[2], NumberStyles.HexNumber);
            edgeNotification.targAddr = ulong.Parse(entries[3], NumberStyles.HexNumber);
            edgeNotification.targID = uint.Parse(entries[4], NumberStyles.HexNumber);

            PendingEdges.Add(edgeNotification);
        }



        void AddExceptionUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 4);

            ulong address = ulong.Parse(entries[1], NumberStyles.HexNumber);
            ulong code = ulong.Parse(entries[2], NumberStyles.HexNumber);
            ulong flags = ulong.Parse(entries[3], NumberStyles.HexNumber);


            Console.WriteLine($"[rgat]Exception detected in PID{protograph.TraceData.PID} TID: {protograph.ThreadID} [code 0x{code:X} flags: 0x{flags:X}] at address 0x{address:X}");
            List<InstructionData> faultingBlock;
            bool gotDisas = false;
            lock (protograph.ProcessData.InstructionsLock) //read lock
            {
                gotDisas = protograph.ProcessData.disassembly.TryGetValue(address, out  faultingBlock);
            }


            //problem here: no way of knowing which mutation of the faulting instruction was executed
            //going to have to assume it's the most recent mutation
            if (!gotDisas)
            {
                Thread.Sleep(50);
                lock (protograph.ProcessData.InstructionsLock) //read lock
                {
                    if (!protograph.ProcessData.disassembly.TryGetValue(address, out faultingBlock))
                    {
                        Console.WriteLine($"[rgat]Exception address 0x{address:X} not found in disassembly");
                        return;
                    }
                }
            }

            //problem here: no way of knowing which mutation of the faulting block was executed
            //going to have to assume it's the most recent mutation
            InstructionData exceptingins = faultingBlock[^1];
            var faultingBBAddrID = exceptingins.ContainingBlockIDs[^1];
            List<InstructionData> faultingBB = protograph.ProcessData.getDisassemblyBlock(faultingBBAddrID.Item2);

            //todo: Lock, linq
            int instructionsUntilFault = 0;
            for (;  instructionsUntilFault < faultingBB.Count; ++instructionsUntilFault)
            {
                if (faultingBB[instructionsUntilFault].address == address) break;
        
            }

            TAG interruptedBlockTag;
            interruptedBlockTag.blockaddr = faultingBBAddrID.Item1;
            interruptedBlockTag.insCount = (ulong)instructionsUntilFault;
            interruptedBlockTag.blockID = faultingBBAddrID.Item2;
            interruptedBlockTag.jumpModifier = eCodeInstrumentation.eInstrumentedCode;
            interruptedBlockTag.foundExtern = null;
            interruptedBlockTag.insCount = 0;
            protograph.handle_exception_tag(interruptedBlockTag);

            ANIMATIONENTRY animUpdate;
            animUpdate.entryType =  eTraceUpdateType.eAnimExecException;
            animUpdate.blockAddr = interruptedBlockTag.blockaddr;
            animUpdate.blockID = interruptedBlockTag.blockID;
            animUpdate.count = (ulong)instructionsUntilFault;
            animUpdate.callCount = 0;
            animUpdate.targetAddr = 0;
            animUpdate.targetID = 0;
            protograph.PushAnimUpdate(animUpdate);
        }


        private readonly Object debug_tag_lock = new Object();
        void Processor()
        {
            while (!protograph.TraceReader.StopFlag || protograph.TraceReader.HasPendingData())
            {
                byte[] msg = protograph.TraceReader.DeQueueData();
                if (msg == null)
                {
                    AssignBlockRepeats();
                    protograph.TraceReader.RequestWakeupOnData();
                    protograph.TraceReader.TagDataReadyEvent.WaitOne();
                    continue;
                }

                //Console.WriteLine("IngestedMsg: " + Encoding.ASCII.GetString(msg, 0, msg.Length));
                lock (debug_tag_lock)
                {
                    switch (msg[0])
                    {
                        case (byte)'j':
                            ProcessTraceTag(msg);
                            break;
                        case (byte)'R':
                            ProcessLoopMarker(msg);
                            break;
                        case (byte)'A':
                            HandleArg(msg);
                            break;
                        case (byte)'U':
                            UnchainedLinkingUpdate(msg);
                            break;
                        case (byte)'u':
                            AddUnchainedUpdate(msg);
                            break;
                        case (byte)'B':
                            AddExecCountUpdate(msg);
                            break;
                        case (byte)'s':
                            AddSatisfyUpdate(msg);
                            break;
                        case (byte)'X':
                            AddExceptionUpdate(msg);
                            break;
                        default:
                            Console.WriteLine($"Handle unknown tag {(char)msg[0]}");
                            Console.WriteLine("IngestedMsg: " + Encoding.ASCII.GetString(msg, 0, msg.Length));
                            break;
                    }
                }

                if (IrregularTimerFired)
                {
                    PerformIrregularActions();
                }
            }


            Console.WriteLine($"{runningThread.Name} finished with {PendingEdges.Count} pending edges and {blockRepeatQueue.Count} blockrepeats outstanding");
        }

    }
}
