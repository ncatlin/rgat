﻿using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgatCore
{
    class BlockHandlerThread
    {
        enum eBlkInstrumentation { eUninstrumentedCode = 0, eInstrumentedCode = 1, eCodeInDataArea = 2 };


        BinaryTarget target;
        TraceRecord trace;
        rgatState _clientState;
        int threadsCount = 0;
        NamedPipeServerStream blockPipe = null;
        Thread listenerThread = null;
        int bitWidth;
        CapstoneX86Disassembler disassembler;

        public BlockHandlerThread(BinaryTarget binaryTarg, TraceRecord runrecord, rgatState clientState)
        {
            target = binaryTarg;
            trace = runrecord;
            bitWidth = target.BitWidth;
            _clientState = clientState;

            X86DisassembleMode disasMode = (bitWidth == 32) ? X86DisassembleMode.Bit32 : X86DisassembleMode.Bit64;
            disassembler = CapstoneDisassembler.CreateX86Disassembler(disasMode);
        }

        public void Begin(string controlPipeName)
        {

            listenerThread = new Thread(new ParameterizedThreadStart(Listener));
            listenerThread.Name = "Block" + trace.PID;
            listenerThread.Start(controlPipeName);
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


        void ReadCallback(IAsyncResult ar)
        {
            int pointerSize = (bitWidth / 8);
            int bytesread = 0;
            byte[] buf = (byte[])ar.AsyncState;
            try
            {
                bytesread = blockPipe.EndRead(ar);
            }
            catch (Exception e)
            {
                Console.WriteLine("BlockHandler Read callback exception " + e.Message);
                return;
            }

            if (bytesread == 0)
            {
                Console.WriteLine($"WARNING: BlockHandler pipe read 0 bytes from PID {trace.PID}");
                return;
            }


            buf[bytesread] = 0;
            int bufPos = 0;
            if (buf[bufPos++] != 'B')
            {
                Console.WriteLine("BlockHandler pipe read unhandled entry from PID {trace.PID}");
                Console.WriteLine("\t" + System.Text.ASCIIEncoding.ASCII.GetString(buf));
                return;
            }


            ulong BlockAddress = (bitWidth == 32) ? BitConverter.ToUInt32(buf, 1) : BitConverter.ToUInt64(buf, 1);
            bufPos += pointerSize;

            Debug.Assert(buf[bufPos] == '@'); bufPos++;
            Console.WriteLine($"Got {bitWidth}bit block addr {BlockAddress:X}");

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

            uint blockID = BitConverter.ToUInt32(buf, bufPos); bufPos += 4;
            Console.WriteLine("Processing block id " + blockID);

            if (!instrumented) //should no longer happen
            {
                Console.WriteLine($"[rgat] Error: Uninstrumented block at address {BlockAddress} module {trace.DisassemblyData.LoadedModulePaths[globalModNum]} has been... instrumented?");
                return;
            }

            List<InstructionData> blockInstructions = new List<InstructionData>();
            ulong insaddr = BlockAddress;

            while (buf[bufPos++] == '@')
            {
                byte insByteCount = buf[bufPos++];
                Debug.Assert(insByteCount < 16);

                byte[] opcodes = new ReadOnlySpan<byte>(buf, bufPos, insByteCount).ToArray(); bufPos += insByteCount;
                List<InstructionData> foundList = null;
                lock (trace.DisassemblyData.InstructionsLock)
                {

                    if (trace.DisassemblyData.disassembly.TryGetValue(insaddr, out foundList))
                    {
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
                }



                InstructionData instruction = new InstructionData();
                instruction.numbytes = insByteCount;
                instruction.opcodes = opcodes;
                instruction.globalmodnum = globalModNum;
                instruction.dataEx = dataExecution;
                instruction.ContainingBlockIDs = new List<Tuple<ulong, uint>>();
                instruction.ContainingBlockIDs.Add(new Tuple<ulong, uint>(insaddr, blockID));
                instruction.hasSymbol = trace.DisassemblyData.SymbolExists(globalModNum, insaddr);

                if (ProcessRecord.DisassembleIns(disassembler, ref instruction) < 1)
                {
                    Console.WriteLine($"[rgat]ERROR: Bad dissasembly in PID {trace.PID}. Corrupt trace?");
                    return;
                }

                lock (trace.DisassemblyData.InstructionsLock)
                {
                    if (foundList == null)
                    { 
                        trace.DisassemblyData.disassembly[insaddr] = new List<InstructionData>();
                    }
                    instruction.mutationIndex = trace.DisassemblyData.disassembly[insaddr].Count;
                    trace.DisassemblyData.disassembly[insaddr].Add(instruction);
                }

                insaddr += (ulong)instruction.numbytes;
            }

            trace.DisassemblyData.AddDisassembledBlock(blockID, BlockAddress, blockInstructions);
        }

 

        void Listener(Object pipenameO)
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


            while (!_clientState.rgatIsExiting && blockPipe.IsConnected)
            {
                byte[] buf = new byte[14096 * 4];
                IAsyncResult res = blockPipe.BeginRead(buf, 0, 2000, new AsyncCallback(ReadCallback), buf);
                WaitHandle.WaitAny(new WaitHandle[] { res.AsyncWaitHandle }, 2000);
                if (!res.IsCompleted)
                {
                    try { blockPipe.EndRead(res); }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception on blockreader read : " + e.Message);
                    };
                }
            }


            /*
            while (!_clientState.rgatIsExiting && blockPipe.IsConnected)
            {
                

                
                Thread.Sleep(1000);
                try
                {
                    blockPipe.Write(System.Text.Encoding.Unicode.GetBytes("@HB@\x00\x00"));
                } catch (Exception e)
                {
                    if (e.Message != "Pipe is broken.") {
                        Console.WriteLine($"Blockhandler heartbeat stopped: {e.Message}");
                   }
                    else
                    {
                        Console.WriteLine("Blockhandler pipe broke");
                        break;
                    }
                }
            }
            */

            blockPipe.Dispose();
            Console.WriteLine($"BlockHandler Listener thread exited for PID {trace.PID}");
        }

    }
}
