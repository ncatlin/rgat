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
            public ulong repeatCount;
            public List<Tuple<ulong, ulong>> targEdges; //BlockID_Count
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
            //if (PendingEdges.Count > 0)     SatisfyPendingEdges();
            if (blockRepeatQueue.Count > 0) AssignBlockRepeats();
            if (protograph.hasPendingArguments()) protograph.ProcessIncomingCallArguments();
            IrregularActionTimer.Start();
        }

        //peforms non-sequence-critical graph updates
        //update nodes with cached execution counts and new edges from unchained runs
        //also updates graph with delayed edge notifications
        void AssignBlockRepeats()
        {
            int RecordedBlocksQty = protograph.BlocksFirstLastNodeList.Count;
            //List<BLOCKREPEAT> remainingRepeats = new List<BLOCKREPEAT>();
            for (var i = blockRepeatQueue.Count - 1; i >= 0; i--)
            {
                BLOCKREPEAT brep = blockRepeatQueue[i];
                //first find the blocks instruction list
                //if (brep.blockID >= RecordedBlocksQty) { remainingRepeats.Add(brep); continue; }
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
                InstructionData lastIns = brep.blockInslist[^1];
                foreach (InstructionData ins in brep.blockInslist)
                {
                    n = protograph.safe_get_node(ins.threadvertIdx[protograph.ThreadID]);
                    n.IncreaseExecutionCount(brep.repeatCount);
                    protograph.TotalInstructions += brep.repeatCount;

                    if (ins.address != lastIns.address)
                    {
                        uint targID = n.OutgoingNeighboursSet[0];
                        EdgeData targEdge = protograph.GetEdge(n.index, targID);
                        targEdge.IncreaseExecutionCount(brep.repeatCount);
                    }
                }

                NodeData lastNode = n;
                //create any new edges between unchained nodes
                foreach (var targblockID_Count in brep.targEdges)
                {
                    int targetBlockID = (int)targblockID_Count.Item1;
                    ulong execCount = targblockID_Count.Item2;
                    if (targetBlockID >= protograph.BlocksFirstLastNodeList.Count || protograph.BlocksFirstLastNodeList[targetBlockID] == null)
                    {
                        protograph.addBlockToGraph((uint)targetBlockID, execCount);
                    }
                    else
                    {
                        uint targNodeID = protograph.BlocksFirstLastNodeList[targetBlockID].Item1;
                        if (!n.OutgoingNeighboursSet.Contains(targNodeID))
                        {
                            protograph.AddEdge(n.index, targNodeID, execCount);
                        }
                        else
                        {
                            protograph.GetEdge(n.index, targNodeID).IncreaseExecutionCount(execCount);
                        }
                    }
                }
                blockRepeatQueue.RemoveAt(i);
            }
        }


        /*
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
        */

        /*
        void ProcessLoopMarker(byte[] entry)
        {
            if (entry[1] == 'S')//LOOP START MARKER
            {
                ulong loopIterations = BitConverter.ToUInt32(entry, 2);
                //Console.WriteLine($"Processing loop started marker {loopIterations} iterations");
                protograph.SetLoopState(eLoopState.eBuildingLoop, loopIterations);
            }
            else if (entry[1] == 'E')//LOOP END MARKER
            {
                //Console.WriteLine($"Processing loop ended marker");
                protograph.DumpLoop();
            }
        }*/

        bool _ignore_next_tag = false;
        uint _ignored_tag_blockID = 0;

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

            if (_ignore_next_tag)
            {
                Debug.Assert(thistag.blockID == _ignored_tag_blockID);
                _ignore_next_tag = false;
            }
            else
            {
                protograph.handle_tag(thistag);
            }
            ANIMATIONENTRY animUpdate = new ANIMATIONENTRY();
            animUpdate.entryType = eTraceUpdateType.eAnimExecTag;
            animUpdate.blockAddr = thistag.blockaddr;
            animUpdate.blockID = thistag.blockID;
            protograph.PushAnimUpdate(animUpdate);

            //fallen through/failed conditional jump
            if (nextBlockAddress == 0) return;

            eCodeInstrumentation modType = protograph.TraceData.FindContainingModule(nextBlockAddress, out int modnum);
            if (modType == eCodeInstrumentation.eInstrumentedCode)
            {
                if (protograph.exeModuleID == -1 && protograph.NodeList.Count != 0)
                    protograph.AssignModulePath();

                return;
            }

            ProcessExtern(nextBlockAddress, thistag.blockID);
        }

        void AddSingleStepUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 1, entry.Length - 1);
            string[] entries = msg.Split(',', 3);
            if (entries.Length == 3)
            {
                uint blockID = uint.Parse(entries[0], NumberStyles.HexNumber);
                ulong stepAddr = ulong.Parse(entries[1], NumberStyles.HexNumber);
                ulong nextAddr = uint.Parse(entries[2], NumberStyles.HexNumber);
                if(!protograph.SetRecentStep(blockID, stepAddr, nextAddr))
                {
                    _ignore_next_tag = true;
                    _ignored_tag_blockID = blockID;
                }
            }
            else
            {
                Console.WriteLine($"AddSingleStepUpdate Error: Entries had length {entries.Length}: {entry}");
            }
        }


        void ProcessExtern(ulong externAddr, uint callerBlock)
        {
            //modType could be known unknown here
            //in case of unknown, this waits until we know. hopefully rare.
            int attempts = 1;

            TAG externTag = new TAG();
            externTag.jumpModifier = eCodeInstrumentation.eUninstrumentedCode;
            externTag.blockaddr = externAddr;

            protograph.handle_tag(externTag);

            ANIMATIONENTRY animUpdate = new ANIMATIONENTRY();
            animUpdate.blockAddr = externAddr;
            animUpdate.entryType = eTraceUpdateType.eAnimExecTag;
            animUpdate.blockID = uint.MaxValue;
            if (protograph.externFuncCallCounter.TryGetValue(callerBlock, out ulong prevCount))
            {
                protograph.externFuncCallCounter[callerBlock] = prevCount + 1;
                animUpdate.count = prevCount + 1;
            }
            else
            {
                protograph.externFuncCallCounter.Add(callerBlock, 1);
                animUpdate.count = 1;
            }
            protograph.PushAnimUpdate(animUpdate);

        }


        //decodes argument and places in processing queue, processes if all decoded for that call
        void HandleArg(byte[] entry)
        {
            //todo also - crashes if proto handler disabled, why
            //todo
            //Console.WriteLine("todo reenable incoming areguments after crashes stop");
            return;


            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 6);

            int argIdx = int.Parse(entries[1], NumberStyles.Integer);
            ulong funcpc = ulong.Parse(entries[2], NumberStyles.HexNumber);
            ulong sourceBlockID = ulong.Parse(entries[3], NumberStyles.HexNumber);

            char moreArgsFlag = entries[4][0];

            bool callDone = moreArgsFlag == 'E';
            string argstring = entries[5];

            Console.WriteLine($"Handling arg index {argIdx} of symbol address 0x{funcpc:x} from source block {sourceBlockID} :'{argstring}'");

            protograph.CacheIncomingCallArgument(funcpc, sourceBlockID, argIdx, argstring, callDone);

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

            protograph.ProtoLastLastVertID = protograph.ProtoLastVertID;
            protograph.ProtoLastVertID = srcidx;


            TAG thistag;
            thistag.blockaddr = ulong.Parse(entries[4], NumberStyles.HexNumber);
            thistag.blockID = (uint)ulong.Parse(entries[5], NumberStyles.HexNumber);
            thistag.insCount = (uint)ulong.Parse(entries[6], NumberStyles.HexNumber);
            thistag.jumpModifier = eCodeInstrumentation.eInstrumentedCode;
            thistag.foundExtern = null;
            protograph.handle_tag(thistag);


            Debug.Assert(protograph.BlocksFirstLastNodeList.Count > src_blockID, "Bad src block id in unlinking update");


            //Console.WriteLine($"Processing UnchainedLinkingUpdate source 0x{sourceAddr:X} inscount {src_numins} currentaddr 0x{thistag.blockaddr:X}");



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
                                lastnode.IncreaseExecutionCount(1);
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
            animUpdate.count = 0;
            animUpdate.targetAddr = 0;
            animUpdate.targetID = 0;
            animUpdate.edgeCounts = null;
            protograph.PushAnimUpdate(animUpdate);
            return true;
        }


        void AddUnchainedUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 2);

            ANIMATIONENTRY animUpdate;
            animUpdate.entryType = eTraceUpdateType.eAnimUnchained;
            animUpdate.blockID = uint.Parse(entries[1], NumberStyles.HexNumber);
            animUpdate.targetAddr = 0;
            animUpdate.targetID = 0;
            animUpdate.count = 0;
            animUpdate.edgeCounts = null;
            animUpdate.blockAddr = 0;
            protograph.PushAnimUpdate(animUpdate);


            //Console.WriteLine($"Processing AddUnchainedUpdate source 0x{animUpdate.blockAddr:X} targaddr 0x{animUpdate.targetAddr:X}");
            protograph.PerformingUnchainedExecution = true;
        }



        void AddExecCountUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 3);


            BLOCKREPEAT newRepeat;
            newRepeat.blockID = uint.Parse(entries[1], NumberStyles.HexNumber);
            newRepeat.targEdges = new List<Tuple<ulong, ulong>>();

            //Console.WriteLine($"Processing AddExecCountUpdate block {newRepeat.blockID }");

            string[] edgeCounts = entries[2].Split(',');

            ulong blockExecs = 0;
            for (int i = 0; i < edgeCounts.Count(); i += 2)
            {
                ulong targAddr = ulong.Parse(edgeCounts[i], NumberStyles.HexNumber);

                ulong targBlock = protograph.ProcessData.GetBlockAtAddress(targAddr);
                ulong edgeExecCount = ulong.Parse(edgeCounts[i + 1], NumberStyles.HexNumber);

                if (targBlock == ulong.MaxValue)
                {

                    ProcessExtern(targAddr, newRepeat.blockID);

                }
                else
                {
                    newRepeat.targEdges.Add(new Tuple<ulong, ulong>(targBlock, edgeExecCount));
                }
                blockExecs += edgeExecCount;
                //Console.WriteLine($"\t +targ {targblockID} ");
            }
            newRepeat.repeatCount = blockExecs;
            newRepeat.blockInslist = null;
            //newRepeat.insCount = 0;
            //newRepeat.blockaddr = 0;
            blockRepeatQueue.Add(newRepeat);

            ANIMATIONENTRY animUpdate;
            animUpdate.entryType = eTraceUpdateType.eAnimUnchainedResults;
            animUpdate.blockAddr = 0;
            animUpdate.blockID = newRepeat.blockID;
            animUpdate.edgeCounts = newRepeat.targEdges;
            animUpdate.count = blockExecs;
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
                gotDisas = protograph.ProcessData.disassembly.TryGetValue(address, out faultingBlock);
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
            uint faultingBasicBlock_ID = exceptingins.ContainingBlockIDs[^1];
            List<InstructionData> faultingBB = protograph.ProcessData.getDisassemblyBlock(faultingBasicBlock_ID);

            //todo: Lock, linq
            int instructionsUntilFault = 0;
            for (; instructionsUntilFault < faultingBB.Count; ++instructionsUntilFault)
            {
                if (faultingBB[instructionsUntilFault].address == address) break;

            }

            TAG interruptedBlockTag;
            interruptedBlockTag.blockaddr = protograph.ProcessData.BasicBlocksList[(int)faultingBasicBlock_ID].Item2[0].address;
            interruptedBlockTag.insCount = (ulong)instructionsUntilFault;
            interruptedBlockTag.blockID = faultingBasicBlock_ID;
            interruptedBlockTag.jumpModifier = eCodeInstrumentation.eInstrumentedCode;
            interruptedBlockTag.foundExtern = null;
            interruptedBlockTag.insCount = 0;
            protograph.handle_exception_tag(interruptedBlockTag);

            ANIMATIONENTRY animUpdate;
            animUpdate.entryType = eTraceUpdateType.eAnimExecException;
            animUpdate.blockAddr = interruptedBlockTag.blockaddr;
            animUpdate.blockID = interruptedBlockTag.blockID;
            animUpdate.count = (ulong)instructionsUntilFault;
            animUpdate.targetAddr = 0;
            animUpdate.targetID = 0;
            animUpdate.edgeCounts = null;
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
                        case (byte)'S':
                            AddSingleStepUpdate(msg);
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

            IrregularActionTimer.Stop();
            PerformIrregularActions();

            Console.WriteLine($"{runningThread.Name} finished with {PendingEdges.Count} pending edges and {blockRepeatQueue.Count} blockrepeats outstanding");
        }

    }
}
