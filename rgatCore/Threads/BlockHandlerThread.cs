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
    /// <summary>
    /// A worker for disassembling the instructions sent by an instrumented trace
    /// </summary>
    public class BlockHandlerThread : TraceProcessorWorker
    {
        private enum eBlkInstrumentation { eUninstrumentedCode = 0, eInstrumentedCode = 1, eCodeInDataArea = 2 };

        private readonly BinaryTarget target;
        private readonly TraceRecord trace;
        private NamedPipeServerStream? blockPipe = null;
        private readonly int bitWidth;
        private readonly CapstoneX86Disassembler disassembler;
        private readonly uint? _remotePipeID;

        private delegate void ProcessPipeMessageAction(byte[] buf, int bytesRead);

        Thread? NonRemoteIngestThread;

        /// <summary>
        /// Create a basic block processing worker
        /// </summary>
        /// <param name="binaryTarg">Binary target associated with the trace</param>
        /// <param name="runrecord">TraceRecord associated with the trace</param>
        /// <param name="remotePipeID">ID of the pipe receiving basic block data</param>
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


        /// <summary>
        /// Get the name of the pipe to listen on
        /// </summary>
        /// <param name="PID">Process ID of the traced process</param>
        /// <param name="instanceID">Unique trace ID of the process</param>
        /// <returns>A named pipe name</returns>
        public static string GetBlockPipeName(uint PID, long instanceID)
        {
            return "BB" + PID.ToString() + instanceID.ToString();
        }

        /// <summary>
        /// Start the worker
        /// </summary>
        public override void Begin()
        {

            ProcessPipeMessageAction param;
            if (_remotePipeID != null)
            {
                if (rgatState.ConnectedToRemote)
                {
                    if (rgatState.NetworkBridge.HeadlessMode)
                    {
                        //Spawn a thread to receive (and cache) blocks from the trace and send them over the network
                        WorkerThread = new Thread(LocalListener);
                        param = MirrorMessageToUI;
                    }
                    else
                    {
                        //Spawn a thread to process blocks from the network
                        WorkerThread = new Thread(BlockProcessor);
                        param = DissasembleBlock;
                    }
                    WorkerThread.Name = $"TraceModuleHandler_Remote_{_remotePipeID}";
                }
                else
                {
                    Logging.RecordLogEvent("Refusing to start block handler with remote pipe without being connected", filter: Logging.LogFilterType.Error);
                    return;
                }


                base.Begin();
                WorkerThread.Start(param);

            }
            else
            {

                //Spawn a thread to receive blocks from the trace and add them to the queue
                NonRemoteIngestThread = new Thread(LocalListener);
                NonRemoteIngestThread.Name = $"TraceBlockHandlerListen_{trace.PID}_{trace.randID}";

                //Spawn a thread to process blocks from the queue
                WorkerThread = new Thread(BlockProcessor);
                WorkerThread.Name = $"TraceBlockHandlerProcess_{trace.PID}_{trace.randID}";

                base.Begin();
                NonRemoteIngestThread.Start((ProcessPipeMessageAction)EnqueueBlockDataLocally);
                WorkerThread.Start((ProcessPipeMessageAction)DissasembleBlock);

            }

        }

        private void ConnectCallback(IAsyncResult ar)
        {
            try
            {
                blockPipe!.EndWaitForConnection(ar);
                Logging.RecordLogEvent("Block pipe connected for PID " + trace.PID);
            }
            catch (Exception e)
            {
                Logging.RecordException($"Exception while trying to connect block pipe for PID {trace.PID}: {e.Message}", e);
            }
        }

        private void MirrorMessageToUI(byte[] buf, int bytesRead)
        {
            //Logging.WriteConsole($"Mirrormsg len {bytesRead}/{buf.Length} to ui: " + System.Text.ASCIIEncoding.ASCII.GetString(buf, 0, bytesRead));
            Debug.Assert(_remotePipeID is not null);
            rgatState.NetworkBridge.SendRawTraceData(_remotePipeID.Value, buf, bytesRead);
        }        
        

        private void EnqueueBlockDataLocally(byte[] buf, int bytesRead)
        {
            lock (_lock)
            {
                _incomingRemoteBlockData.Enqueue(buf);
                NewDataEvent.Set();
            }
        }


        private void DissasembleBlock(byte[] buf, int bytesRead)
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

            int localmodnum = BitConverter.ToInt32(buf, bufPos); bufPos += 4;
            Debug.Assert(buf[bufPos] == '@'); bufPos++;

            int globalModNum = localmodnum >= 0 ? trace.DisassemblyData.modIDTranslationVec[localmodnum] : 0; //for now just mark non-image code as being part of the target
            if (localmodnum >= 0 && (globalModNum < 0 || globalModNum >= trace.DisassemblyData.LoadedModuleBounds.Count))
            {
                if (globalModNum == -1)
                    Logging.RecordError("Known IngestBlockLocal module translation error condition -1");
                //todo this can be -1 with super laggy remote tracing. deal with remote trace lag first.
                throw new IndexOutOfRangeException($"IngestBlockLocal: Bad module ID {globalModNum} not recorded"); 
            }

            //ulong moduleStart = trace.DisassemblyData.LoadedModuleBounds[globalModNum].Item1;
            //ulong modoffset = BlockAddress - moduleStart;

            eBlkInstrumentation instrumentedStatusByte = (eBlkInstrumentation)buf[bufPos++];
            Debug.Assert(instrumentedStatusByte >= 0 && (int)instrumentedStatusByte <= 2);

            bool instrumented, dataExecution = false;
            if (instrumentedStatusByte == eBlkInstrumentation.eUninstrumentedCode)
            {
                instrumented = false;
            }
            else
            {
                instrumented = true;
                if (instrumentedStatusByte == eBlkInstrumentation.eCodeInDataArea)
                {
                    dataExecution = true;
                }
            }
            Debug.Assert(instrumented);

            uint blockID = BitConverter.ToUInt32(buf, bufPos); bufPos += 4;

            //Logging.WriteConsole($"Processing block {blockID} address 0x{BlockAddress:X} module {globalModNum}");

            if (!instrumented) //should no longer happen
            {
                Logging.RecordError($"[rgat] Error: Uninstrumented block at address 0x{BlockAddress:X} module {trace.DisassemblyData.LoadedModulePaths[globalModNum]} has been... instrumented?");
                return;
            }

            List<InstructionData> blockInstructions = new List<InstructionData>();
            ulong insaddr = BlockAddress;
            //Logging.WriteConsole($"Ingesting block ID {blockID} address 0x{insaddr:X} modnum {globalModNum} data: {System.Text.Encoding.ASCII.GetString(buf, 0, bytesRead)}");

            int dbginscount = -1;
            while (bufPos < buf.Length && buf[bufPos] == '@') //er here
            {
                bufPos++;
                byte insByteCount = buf[bufPos];
                bufPos++;
                Debug.Assert(insByteCount > 0 && insByteCount < 16);

                byte[] opcodes = new ReadOnlySpan<byte>(buf, bufPos, insByteCount).ToArray(); bufPos += insByteCount;
                List<InstructionData>? foundList = null;

                lock (trace.DisassemblyData._instructionsLock)
                {
                    dbginscount++;


                    if (trace.DisassemblyData.disassembly.TryGetValue(insaddr, out foundList))
                    {

                        //Logging.WriteConsole($"\t Block {blockID} existing ins {dbginscount}-0x{insaddr:X}: {foundList[0].ins_text}");

                        InstructionData possibleInstruction = foundList[^1];
                        //if address has been seen but opcodes are not same as most recent, disassemble again
                        //might be a better to check all mutations instead of most recent
                        bool mutation = possibleInstruction.NumBytes != insByteCount || !possibleInstruction.Opcodes!.SequenceEqual<byte>(opcodes);
                        if (!mutation)
                        {
                            blockInstructions.Add(possibleInstruction);
                            insaddr += (ulong)possibleInstruction.NumBytes;
                            continue;
                        }
                    }


                    //Logging.WriteConsole($"Blockaddrhandler, Ins 0x{insaddr:X} not previously disassembled");

                    InstructionData instruction = new InstructionData();
                    instruction.Address = insaddr;
                    instruction.Opcodes = opcodes;
                    instruction.GlobalModNum = globalModNum;
                    instruction.dataEx = dataExecution;
                    instruction.ContainingBlockIDs = new List<uint>();
                    instruction.ContainingBlockIDs.Add(blockID);
                    instruction.hasSymbol = trace.DisassemblyData.SymbolExists(globalModNum, insaddr);

                    if (dbginscount == 0)// || buf[bufPos] != '@')
                    {
                        instruction.BlockBoundary = true;
                    }
                    else
                    {
                        instruction.BlockBoundary = false;
                    }


                    if (localmodnum is -1)
                    {
                        trace.DisassemblyData.AddNonImageAddress(insaddr);
                    }
                    //need to move this out of the lock
                    if (ProcessRecord.DisassembleIns(disassembler, insaddr, instruction) < 1)
                    {
                        Logging.RecordLogEvent($"[rgat]ERROR: Bad dissasembly in PID {trace.PID}. Corrupt trace?", Logging.LogFilterType.Error);
                        return;
                    }

                    // Logging.WriteConsole($"[rgatBlkHandler]\t Block {blockID} new      ins {dbginscount}-0x{insaddr:X}: {instruction.ins_text}");

                    if (foundList == null)
                    {
                        trace.DisassemblyData.disassembly[insaddr] = new List<InstructionData>();
                    }
                    instruction.MutationIndex = trace.DisassemblyData.disassembly[insaddr].Count;

                    trace.DisassemblyData.disassembly[insaddr].Add(instruction);


                    blockInstructions.Add(instruction);

                    insaddr += (ulong)instruction.NumBytes;
                }
            }
            Debug.Assert(blockInstructions.Count != 0);
            //Logging.WriteConsole($"Block ID {blockID} ({BlockAddress:X}) had {blockInstructions.Count} instructions");
            trace.DisassemblyData.AddDisassembledBlock(blockID, BlockAddress, blockInstructions);
        }

        private readonly CancellationTokenSource cancelTokens = new CancellationTokenSource();

        /// <summary>
        /// Cause the worker to stop and disconnect its pipe
        /// </summary>
        public override void Terminate()
        { 
            try
            {
                cancelTokens.Cancel();
                if (blockPipe != null && blockPipe.IsConnected)
                {
                    blockPipe.Disconnect();
                }
            }
            catch { return; }
        }

        /// <summary>
        /// Add some raw basic block data to the worker queue
        /// </summary>
        /// <param name="data">Basic block data from the instrumentation</param>
        public void AddRemoteBlockData(byte[] data)
        {
            lock (_lock)
            {
                _incomingRemoteBlockData.Enqueue(data);
                NewDataEvent.Set();
            }
        }

        private readonly Queue<byte[]> _incomingRemoteBlockData = new Queue<byte[]>();
        private readonly ManualResetEventSlim NewDataEvent = new ManualResetEventSlim(false);
        private readonly object _lock = new object();

        /// <summary>
        /// How many items of basic block data are waiting for disassembly
        /// </summary>
        public int QueueSize => _incomingRemoteBlockData.Count + _processingItems;
        int _processingItems = 0;

        private void BlockProcessor(object? ProcessMessageobj)
        {
            byte[][] newItems;
            while (!rgatState.rgatIsExiting)
            {
                try
                {
                    _processingItems = 0;
                    NewDataEvent.Wait(1000, rgatState.NetworkBridge.CancelToken);
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"BlockThread::BlockProcessor wait exception {e.Message}. Usually just user cancellation."); 
                    break;
                }
                lock (_lock)
                {
                    newItems = _incomingRemoteBlockData.ToArray();
                    _incomingRemoteBlockData.Clear();
                    NewDataEvent.Reset();
                    _processingItems = newItems.Length;
                }
                foreach (byte[] item in newItems)
                {
                    try
                    {
                        DissasembleBlock(item, item.Length);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordException($"Block processing exception: {e.Message}", e);
                        rgatState.NetworkBridge.Teardown("Block Ingest Exception");
                        base.Finished();
                        return;
                    }
                }
            }

            base.Finished();
        }

        private async void LocalListener(object? ProcessMessageobj)
        {
            if (ProcessMessageobj is null)
            {
                return;
            }

            string name = GetBlockPipeName(trace.PID, trace.randID);
            ProcessPipeMessageAction ProcessMessage = (ProcessPipeMessageAction)ProcessMessageobj;
            blockPipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
            IAsyncResult res1 = blockPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Block");


            int totalWaited = 0;
            while (!rgatState.rgatIsExiting && !blockPipe.IsConnected)
            {
                Thread.Sleep(1000);
                totalWaited += 1000;
                if (totalWaited > 4000)
                {
                    Logging.WriteConsole($"BlockPipeThread Waiting BlockPipeConnected:{blockPipe.IsConnected} TotalTime:{totalWaited}");
                }
                if (totalWaited > 8000)
                {
                    Logging.RecordError($"Timeout waiting for rgat client sub-connections. BlockPipeConnected:{blockPipe.IsConnected} ");
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
                            Logging.RecordException($"Local Block processing exception: {e.Message}", e);
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
            Logging.RecordLogEvent($"BlockHandler Listener thread exited for PID {trace.PID}", filter: Logging.LogFilterType.Debug);
        }

    }
}
