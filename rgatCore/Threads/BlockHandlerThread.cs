using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using rgat.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Threading;

namespace rgat
{
    public class BlockHandlerThread : TraceProcessorWorker
    {
        enum eBlkInstrumentation { eUninstrumentedCode = 0, eInstrumentedCode = 1, eCodeInDataArea = 2 };

        readonly BinaryTarget target;
        readonly TraceRecord trace;
        NamedPipeServerStream blockPipe = null;
        readonly int bitWidth;
        readonly CapstoneX86Disassembler disassembler;
        readonly uint? _remotePipeID;

        public delegate void ProcessPipeMessageAction(byte[] buf, int bytesRead);
        public BlockHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord, uint? remotePipeID = null)
        {
            target = binaryTarg;
            trace = runrecord;
            bitWidth = target.BitWidth;
            _remotePipeID = remotePipeID;

            //todo don't create in headless mode
            X86DisassembleMode disasMode = (bitWidth == 32) ? X86DisassembleMode.Bit32 : X86DisassembleMode.Bit64;
            disassembler = CapstoneDisassembler.CreateX86Disassembler(disasMode);
        }

        public static string GetBlockPipeName(uint PID, long instanceID)
        {
            return "BB" + PID.ToString() + instanceID.ToString();
        }

        public override void Begin()
        {

            ProcessPipeMessageAction param;
            if (_remotePipeID != null)
            {
                if (rgatState.ConnectedToRemote)
                {
                    if (rgatState.NetworkBridge.HeadlessMode)
                    {
                        WorkerThread = new Thread(LocalListener);
                        param = MirrorMessageToUI;
                    }
                    else
                    {
                        WorkerThread = new Thread(RemoteListener);
                        param = IngestBlockLocal;
                    }
                    WorkerThread.Name = $"TraceModuleHandler_Remote_{_remotePipeID}";
                }
                else
                {
                    Logging.RecordLogEvent("Refusing to start block handler with remote pipe without being connected", filter: Logging.LogFilterType.TextError);
                    return;
                }
            }
            else
            {
                param = IngestBlockLocal;
                WorkerThread = new Thread(LocalListener);
                WorkerThread.Name = $"TraceModuleHandler_{trace.PID}_{trace.randID}";
            }

            base.Begin();
            WorkerThread.Start(param);
        }

        void ConnectCallback(IAsyncResult ar)
        {
            try
            {
                blockPipe.EndWaitForConnection(ar);
                Console.WriteLine("Block pipe connected for PID " + trace.PID);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception while trying to connect block pipe for PID {trace.PID}: {e.Message}");
            }
        }


        void MirrorMessageToUI(byte[] buf, int bytesRead)
        {
            //Console.WriteLine($"Mirrormsg len {bytesRead}/{buf.Length} to ui: " + System.Text.ASCIIEncoding.ASCII.GetString(buf, 0, bytesRead));
            rgatState.NetworkBridge.SendRawTraceData(_remotePipeID.Value, buf, bytesRead);
        }


        void IngestBlockLocal(byte[] buf, int bytesRead)
        {
            //buf[bytesRead] = 0;
            if (buf[0] != 'B')
            {
                throw new ArgumentException($"IngestBlockLocal: BlockHandler pipe read unhandled entry from PID {trace.PID}");
            }

            int pointerSize = (bitWidth / 8);
            int bufPos = 1;
            ulong BlockAddress = (bitWidth == 32) ? BitConverter.ToUInt32(buf, 1) : BitConverter.ToUInt64(buf, 1);


            bufPos += pointerSize;

            Debug.Assert(buf[bufPos] == '@'); bufPos++;

            uint localmodnum = BitConverter.ToUInt32(buf, bufPos); bufPos += 4;
            Debug.Assert(buf[bufPos] == '@'); bufPos++;

            int globalModNum = trace.DisassemblyData.modIDTranslationVec[(int)localmodnum];
            if (globalModNum < 0 || globalModNum >= trace.DisassemblyData.LoadedModuleBounds.Count)
            {
                throw new IndexOutOfRangeException($"Bad module ID {globalModNum} not recorded");
            }
            ulong moduleStart = trace.DisassemblyData.LoadedModuleBounds[globalModNum].Item1;
            ulong modoffset = BlockAddress - moduleStart;

            eBlkInstrumentation instrumentedStatusByte = (eBlkInstrumentation)buf[bufPos++];
            Debug.Assert(instrumentedStatusByte >= 0 && (int)instrumentedStatusByte <= 2);

            bool instrumented, dataExecution = false;
            if (instrumentedStatusByte == eBlkInstrumentation.eUninstrumentedCode)
                instrumented = false;
            else
            {
                instrumented = true;
                if (instrumentedStatusByte == eBlkInstrumentation.eCodeInDataArea)
                    dataExecution = true;
            }
            Debug.Assert(instrumented);

            uint blockID = BitConverter.ToUInt32(buf, bufPos); bufPos += 4;

            //Console.WriteLine($"Processing block {blockID} address 0x{BlockAddress:X} module {globalModNum}");

            if (!instrumented) //should no longer happen
            {
                Console.WriteLine($"[rgat] Error: Uninstrumented block at address 0x{BlockAddress:X} module {trace.DisassemblyData.LoadedModulePaths[globalModNum]} has been... instrumented?");
                return;
            }

            List<InstructionData> blockInstructions = new List<InstructionData>();
            ulong insaddr = BlockAddress;

            //Console.WriteLine($"Ingesting block ID {blockID} address 0x{insaddr:X}");

            int dbginscount = -1;
            while (bufPos < buf.Length && buf[bufPos] == '@') //er here
            {
                bufPos++;
                byte insByteCount = buf[bufPos];
                bufPos++;
                Debug.Assert(insByteCount > 0 && insByteCount < 16);

                byte[] opcodes = new ReadOnlySpan<byte>(buf, bufPos, insByteCount).ToArray(); bufPos += insByteCount;
                List<InstructionData>? foundList = null;

                lock (trace.DisassemblyData.InstructionsLock)
                {
                    dbginscount++;


                    if (trace.DisassemblyData.disassembly.TryGetValue(insaddr, out foundList))
                    {

                        //Console.WriteLine($"\t Block {blockID} existing ins {dbginscount}-0x{insaddr:X}: {foundList[0].ins_text}");

                        InstructionData possibleInstruction = foundList[^1];
                        //if address has been seen but opcodes are not same as most recent, disassemble again
                        //might be a better to check all mutations instead of most recent
                        bool mutation = possibleInstruction.numbytes != insByteCount || !possibleInstruction.opcodes.SequenceEqual<byte>(opcodes);
                        if (!mutation)
                        {
                            blockInstructions.Add(possibleInstruction);
                            insaddr += (ulong)possibleInstruction.numbytes;
                            continue;
                        }
                    }
                    //Console.WriteLine($"Blockaddrhandler, Ins 0x{insaddr:X} not previously disassembled");

                    InstructionData instruction = new InstructionData();
                    instruction.Address = insaddr;
                    instruction.numbytes = insByteCount;
                    instruction.opcodes = opcodes;
                    instruction.globalmodnum = globalModNum;
                    instruction.dataEx = dataExecution;
                    instruction.ContainingBlockIDs = new List<uint>();
                    instruction.ContainingBlockIDs.Add(blockID);
                    instruction.hasSymbol = trace.DisassemblyData.SymbolExists(globalModNum, insaddr);

                    if (dbginscount == 0)// || buf[bufPos] != '@')
                    {
                        instruction.BlockBoundary = true;
                    }
                    else
                        instruction.BlockBoundary = false;


                    //need to move this out of the lock
                    if (ProcessRecord.DisassembleIns(disassembler, insaddr, ref instruction) < 1)
                    {
                        Logging.RecordLogEvent($"[rgat]ERROR: Bad dissasembly in PID {trace.PID}. Corrupt trace?", Logging.LogFilterType.TextError);
                        return;
                    }

                    // Console.WriteLine($"[rgatBlkHandler]\t Block {blockID} new      ins {dbginscount}-0x{insaddr:X}: {instruction.ins_text}");

                    if (foundList == null)
                    {
                        trace.DisassemblyData.disassembly[insaddr] = new List<InstructionData>();
                    }
                    instruction.mutationIndex = trace.DisassemblyData.disassembly[insaddr].Count;

                    instruction.DebugID = trace.DisassemblyData.disassembly.Count;

                    trace.DisassemblyData.disassembly[insaddr].Add(instruction);


                    blockInstructions.Add(instruction);

                    insaddr += (ulong)instruction.numbytes;
                }
            }
            Debug.Assert(blockInstructions.Count != 0);
            //Console.WriteLine($"Block ID {blockID} ({BlockAddress:X}) had {blockInstructions.Count} instructions");
            trace.DisassemblyData.AddDisassembledBlock(blockID, BlockAddress, blockInstructions);
        }

        readonly CancellationTokenSource cancelTokens = new CancellationTokenSource();

        public void Terminate()
        {
            try
            {
                cancelTokens.Cancel();
                if (blockPipe != null && blockPipe.IsConnected)
                    blockPipe.Disconnect();
            }
            catch { return; }
        }

        public void AddRemoteBlockData(byte[] data, int startIndex)
        {
            lock (_lock)
            {
                _incomingRemoteBlockData.Enqueue(data);
                NewDataEvent.Set();
            }
        }

        readonly Queue<byte[]> _incomingRemoteBlockData = new Queue<byte[]>();
        readonly ManualResetEventSlim NewDataEvent = new ManualResetEventSlim(false);
        readonly object _lock = new object();


        void RemoteListener(object ProcessMessageobj)
        {
            byte[][] newItems;
            while (!rgatState.rgatIsExiting)
            {
                try
                {
                    NewDataEvent.Wait(rgatState.NetworkBridge.CancelToken);
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"BlockThread::RemoteListener exception {e.Message}");
                    break;
                }
                lock (_lock)
                {
                    newItems = _incomingRemoteBlockData.ToArray();
                    _incomingRemoteBlockData.Clear();
                    NewDataEvent.Reset();
                }
                foreach (byte[] item in newItems)
                {
                    //try
                    {
                        IngestBlockLocal(item, item.Length);
                    }
                    /*
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Remote Block processing exception: {e.Message}", Logging.LogFilterType.TextError);
                        rgatState.NetworkBridge.Teardown("Block Ingest Exception");
                        base.Finished();
                        return;
                    }*/
                }

                //todo: remote trace termination -> loop exit condition
            }


            base.Finished();
        }


        async void LocalListener(object ProcessMessageobj)
        {
            string name = GetBlockPipeName(trace.PID, trace.randID);
            ProcessPipeMessageAction ProcessMessage = (ProcessPipeMessageAction)ProcessMessageobj;
            blockPipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
            IAsyncResult res1 = blockPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Block");


            int totalWaited = 0;
            while (!rgatState.rgatIsExiting && !blockPipe.IsConnected)
            {
                Thread.Sleep(1000);
                totalWaited += 1000;
                Console.WriteLine($"BlockPipeThread Waiting BlockPipeConnected:{blockPipe.IsConnected} TotalTime:{totalWaited}");
                if (totalWaited > 8000)
                {
                    Console.WriteLine($"Timeout waiting for rgat client sub-connections. BlockPipeConnected:{blockPipe.IsConnected} ");
                    break;
                }
            }


            byte[]? pendingBuf = null;
            const int BufMax = 4096; //todo experiment for perfomance
            int bytesRead = 0;
            while (!rgatState.rgatIsExiting && blockPipe.IsConnected)
            {
                byte[] buf = new byte[BufMax];
                try
                {
                    bytesRead = await blockPipe.ReadAsync(buf, 0, BufMax, cancelTokens.Token);
                }
                catch
                {
                    continue;
                }

                if (bytesRead < 1024)
                {
                    if (pendingBuf != null)
                    {
                        //this is multipart, tack it onto the next fragment
                        bytesRead = pendingBuf.Length + bytesRead;
                        buf = pendingBuf.Concat(buf).ToArray();
                        pendingBuf = null;
                    }
                    //Logging.RecordLogEvent("IncomingMessageCallback: " + Encoding.ASCII.GetString(buf, 0, bytesread), filter: Logging.LogFilterType.BulkDebugLogFile);
                    if (bytesRead > 0)
                    {
                        try
                        {
                            ProcessMessage(buf, bytesRead);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordError($"Local Block processing exception: {e}");
                            rgatState.NetworkBridge.Teardown();
                            base.Finished();
                            return;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    //multi-part message, queue this for reassembly
                    pendingBuf = (pendingBuf == null) ? buf : pendingBuf.Concat(buf).ToArray();
                }
            }



            blockPipe.Dispose();
            Finished();
            Console.WriteLine($"BlockHandler Listener thread exited for PID {trace.PID}");
        }

    }
}
