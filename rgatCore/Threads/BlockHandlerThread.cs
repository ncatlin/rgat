using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgatCore
{
    public class BlockHandlerThread : TraceProcessorWorker
    {
        enum eBlkInstrumentation { eUninstrumentedCode = 0, eInstrumentedCode = 1, eCodeInDataArea = 2 };

        BinaryTarget target;
        TraceRecord trace;
        NamedPipeServerStream blockPipe = null;
        int bitWidth;
        CapstoneX86Disassembler disassembler;
        string _controlPipeName;

        public BlockHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord, string pipename)
        {
            target = binaryTarg;
            trace = runrecord;
            bitWidth = target.BitWidth;
            _controlPipeName = pipename;

            X86DisassembleMode disasMode = (bitWidth == 32) ? X86DisassembleMode.Bit32 : X86DisassembleMode.Bit64;
            disassembler = CapstoneDisassembler.CreateX86Disassembler(disasMode);
        }

        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(new ParameterizedThreadStart(Listener));
            WorkerThread.Name = "Block" + trace.PID;
            WorkerThread.Start(_controlPipeName);
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



        void IngestBlock(byte[] buf, int bytesRead)
        {
            buf[bytesRead] = 0;
            if (buf[0] != 'B')
            {
                Console.WriteLine("BlockHandler pipe read unhandled entry from PID {trace.PID}");
                Console.WriteLine("\t" + System.Text.ASCIIEncoding.ASCII.GetString(buf));
                return;
            }

            int pointerSize = (bitWidth / 8);
            int bufPos = 1;
            ulong BlockAddress = (bitWidth == 32) ? BitConverter.ToUInt32(buf, 1) : BitConverter.ToUInt64(buf, 1);


            bufPos += pointerSize;

            Debug.Assert(buf[bufPos] == '@'); bufPos++;

            uint localmodnum = BitConverter.ToUInt32(buf, bufPos); bufPos += 4;
            Debug.Assert(buf[bufPos] == '@'); bufPos++;

            int globalModNum = trace.DisassemblyData.modIDTranslationVec[(int)localmodnum];
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

            Console.WriteLine($"Processing block {blockID} address 0x{BlockAddress:X} module {globalModNum}");

            if (!instrumented) //should no longer happen
            {
                Console.WriteLine($"[rgat] Error: Uninstrumented block at address 0x{BlockAddress:X} module {trace.DisassemblyData.LoadedModulePaths[globalModNum]} has been... instrumented?");
                return;
            }

            List<InstructionData> blockInstructions = new List<InstructionData>();
            ulong insaddr = BlockAddress;

            //Console.WriteLine($"Ingesting block ID {blockID} address 0x{insaddr:X}");

            int dbginscount = -1;
            while (buf[bufPos] == '@')
            {
                bufPos++;
                byte insByteCount = buf[bufPos];
                bufPos++;
                Debug.Assert(insByteCount > 0 && insByteCount < 16);

                byte[] opcodes = new ReadOnlySpan<byte>(buf, bufPos, insByteCount).ToArray(); bufPos += insByteCount;
                List<InstructionData> foundList = null;

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
                    instruction.address = insaddr;
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
                        Console.WriteLine($"[rgat]ERROR: Bad dissasembly in PID {trace.PID}. Corrupt trace?");
                        return;
                    }

                    //Console.WriteLine($"[rgatBlkHandler]\t Block {blockID} new      ins {dbginscount}-0x{insaddr:X}: {instruction.ins_text}");

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

        CancellationTokenSource cancelTokens = new CancellationTokenSource();

        public void Terminate()
        {
            cancelTokens.Cancel();
            if (blockPipe != null && blockPipe.IsConnected)
                blockPipe.Disconnect();
        }

        async void Listener(Object pipenameO)
        {
            string name = (string)pipenameO;
            blockPipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
            IAsyncResult res1 = blockPipe.BeginWaitForConnection(new AsyncCallback(ConnectCallback), "Block");


            int totalWaited = 0;
            while (!_clientState.rgatIsExiting)
            {
                if (blockPipe.IsConnected) break;
                Thread.Sleep(1000);
                totalWaited += 1000;
                Console.WriteLine($"ModuleHandlerThread Waiting BlockPipeConnected:{blockPipe.IsConnected} TotalTime:{totalWaited}");
                if (totalWaited > 8000)
                {
                    Console.WriteLine($"Timeout waiting for rgat client sub-connections. BlockPipeConnected:{blockPipe.IsConnected} ");
                    break;
                }
            }


            byte[] pendingBuf = null;
            const int BufMax = 4096; //todo experiment for perfomance
            int bytesRead = 0;
            while (!_clientState.rgatIsExiting && blockPipe.IsConnected)
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
                        IngestBlock(buf, bytesRead);
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
