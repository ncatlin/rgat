using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgatCore.Threads
{
    class ThreadTraceProcessingThread
    {
        ProtoGraph protograph;
        Thread runningThread;

        public ThreadTraceProcessingThread(ProtoGraph newProtoGraph)
        {
            protograph = newProtoGraph;

            runningThread = new Thread(Processor);
            runningThread.Name = "TraceProcessor" + this.protograph.ThreadID;
            runningThread.Start();
        }



        void ProcessLoopMarker(byte[] entry)
        {
            if (entry[1] == 'S')//LOOP START MARKER
            {
                ulong loopIterations = BitConverter.ToUInt32(entry, 2);
                protograph.SetLoopState(eLoopState.eBuildingLoop, loopIterations);
            }
            else if (entry[1] == 'E')//LOOP END MARKER
            {
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
            Debug.Assert(thistag.blockID < protograph.ProcessData.blockList.Count, "ProcessTraceTag tried to process block that hasn't been disassembled");

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


        void add_unlinking_update(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 6);

            ulong sourceAddr = ulong.Parse(entries[1], NumberStyles.HexNumber);
            ulong blockID_numins = ulong.Parse(entries[2], NumberStyles.HexNumber);
            uint srcblockID = (uint)blockID_numins >> 32;
            uint srcinscount = (uint)blockID_numins & 0xff;

            List<InstructionData> lastBB = protograph.ProcessData.getDisassemblyBlock(0, srcblockID);
            InstructionData lastIns = lastBB[^1];
            bool found = lastIns.threadvertIdx.TryGetValue(protograph.ThreadID, out uint srcidx);
            Debug.Assert(found);

            protograph.lastVertID = srcidx;

            ulong currentAddr = ulong.Parse(entries[3], NumberStyles.HexNumber);
            ulong currentblockID_numins = ulong.Parse(entries[4], NumberStyles.HexNumber);

            Debug.Assert(protograph.BlockList.Count > srcblockID, "Bad src block id in unlinking update");


            TAG thistag;
            thistag.insCount = (uint)currentblockID_numins & 0xff;
            thistag.blockID = (uint)currentblockID_numins >> 32;
            thistag.jumpModifier = eCodeInstrumentation.eInstrumentedCode;
            thistag.foundExtern = null;
            thistag.blockaddr = 0;
            protograph.handle_tag(thistag);



            ulong targetAddr = ulong.Parse(entries[5], NumberStyles.HexNumber);

            if (protograph.TraceData.FindContainingModule(targetAddr, out int modnum) == eCodeInstrumentation.eUninstrumentedCode)
            {
                ROUTINE_STRUCT? foundExtern = null;
                protograph.ProcessData.get_extern_at_address(targetAddr, modnum, ref foundExtern);

                bool targetFound = false;

                if (foundExtern.Value.thread_callers.TryGetValue(protograph.ThreadID, out List<Tuple<uint, uint>> callList))
                {
                    foreach (Tuple<uint, uint> edge in callList)
                    {
                        if (edge.Item1 == protograph.targVertID)
                        {
                            targetFound = true;
                            protograph.lastVertID = foundExtern.Value.thread_callers[protograph.ThreadID][0].Item2;
                            NodeData lastnode = protograph.safe_get_node(protograph.lastVertID);
                            ++lastnode.executionCount;
                            break;
                        }
                    }
                    if (!targetFound)
                    {
                        Console.WriteLine($"[rgat]Warning: 0x{targetAddr:X} in {protograph.ProcessData.LoadedModulePaths[foundExtern.Value.globalmodnum]} not found. Heatmap accuracy may suffer.");
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

                    if (foundExtern.Value.globalmodnum != -1)
                    {
                        offset = targetAddr - protograph.ProcessData.LoadedModuleBounds[foundExtern.Value.globalmodnum].Item1;

                        //i haven't added a good way of looking up the nearest symbol. this requirement should be rare, but if not it's a todo

                        for (int i = 0; i < 4096; i++)
                        {
                            if (protograph.ProcessData.get_sym(foundExtern.Value.globalmodnum, offset - (ulong)i, out sym))
                            {
                                foundsym = true;
                                break;
                            }
                        }
                        if (!foundsym) sym = "Unknown Symbol";

                        if (sym != "BaseThreadInitThunk")
                        {
                            string modulepath = protograph.ProcessData.LoadedModulePaths[foundExtern.Value.globalmodnum];
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
            ANIMATIONENTRY animUpdate;
            animUpdate.blockAddr = thistag.blockaddr;
            animUpdate.blockID = thistag.blockID;
            animUpdate.entryType = eTraceUpdateType.eAnimUnchainedDone;
            animUpdate.callCount = 0;
            animUpdate.count = 0;
            animUpdate.targetAddr = 0;
            animUpdate.targetID = 0;
            protograph.PushAnimUpdate(animUpdate);

        }


        void Processor()
        {
            while (!protograph.TraceReader.StopFlag || protograph.TraceReader.HasPendingData())
            {
                byte[] msg = protograph.TraceReader.DeQueueData();
                if (msg == null)
                {
                    protograph.TraceReader.RequestWakeupOnData();
                    protograph.TraceReader.dataReadyEvent.WaitOne();
                    continue;
                }

                bool todoprint = false;
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
                        add_unlinking_update(msg);
                        break;
                    case (byte)'u':
                        todoprint = true;
                        Console.WriteLine("Handle UNCHAIN_MARKER");
                        break;
                    case (byte)'B':
                        todoprint = true;
                        Console.WriteLine("Handle EXECUTECOUNT_MARKER");
                        break;
                    case (byte)'s':
                        todoprint = true;
                        Console.WriteLine("Handle SATISFY_MARKER");
                        break;
                    case (byte)'X':
                        todoprint = true;
                        Console.WriteLine("Handle EXCEPTION_MARKER");
                        break;
                    case (byte)'Z':
                        todoprint = true;
                        Console.WriteLine("Handle Thread Terminated");
                        break;
                    default:
                        todoprint = true;
                        Console.WriteLine($"Handle unknown tag {(char)msg[0]}");
                        break;
                }
                if (todoprint)
                    Console.WriteLine("IngestedMsg: " + Encoding.ASCII.GetString(msg, 0, msg.Length));

            }
            Console.WriteLine(runningThread.Name + " finished");
        }

    }
}
