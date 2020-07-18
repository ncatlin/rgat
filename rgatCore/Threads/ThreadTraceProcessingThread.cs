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
        ThreadTraceIngestThread ingestThread;
        Thread runningThread;

        public ThreadTraceProcessingThread(ProtoGraph newProtoGraph, ThreadTraceIngestThread _ingestionthread)
        {
            protograph = newProtoGraph;
            ingestThread = _ingestionthread;

            runningThread = new Thread(Processor);
            runningThread.Name = "TraceProcessor"+this.protograph.ThreadID;
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
            nextBlockAddress = ulong.Parse(Encoding.ASCII.GetString(entry, addrstart, entry.Length-addrstart), NumberStyles.HexNumber);

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


        void Processor()
        {
            while (!ingestThread.StopFlag || ingestThread.HasPendingData())
            {
                byte[] msg = ingestThread.DeQueueData();
                if (msg == null)
                {
                    ingestThread.RequestWakeupOnData();
                    ingestThread.dataReadyEvent.WaitOne();
                    continue;
                }

                Console.WriteLine("IngestedMsg: "+Encoding.ASCII.GetString(msg, 0, msg.Length));
                switch (msg[0])
                {
                    case (byte)'j':
                        ProcessTraceTag(msg);
                        break;
                    case (byte)'R':
                        ProcessLoopMarker(msg);
                        Console.WriteLine("Handle LOOP_MARKER");
                        break;
                    case (byte)'A':
                        Console.WriteLine("Handle ARG_MARKER");
                        break;
                    case (byte)'U':
                        Console.WriteLine("Handle UNLINK_MARKER");
                        break;
                    case (byte)'u':
                        Console.WriteLine("Handle UNCHAIN_MARKER");
                        break;
                    case (byte)'B':
                        Console.WriteLine("Handle EXECUTECOUNT_MARKER");
                        break;
                    case (byte)'s':
                        Console.WriteLine("Handle SATISFY_MARKER");
                        break;
                    case (byte)'X':
                        Console.WriteLine("Handle EXCEPTION_MARKER");
                        break;
                    case (byte)'Z':
                        Console.WriteLine("Handle Thread Terminated");
                        break;
                    default:
                        Console.WriteLine($"Handle unknown tag {(char)msg[0]}");
                        break;
                }

            }
            Console.WriteLine(runningThread.Name + " finished");
        }

    }
}
