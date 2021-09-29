using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgat.Threads
{
    /// <summary>
    /// Worker for processing trace data
    /// </summary>
    public class ThreadTraceProcessingThread : TraceProcessorWorker
    {
        private readonly ProtoGraph protograph;
        private bool IrregularTimerFired = false;
        private System.Timers.Timer? IrregularActionTimer = null;

        private struct BLOCKREPEAT
        {
            //public ulong blockaddr;
            public uint blockID;
            public ulong repeatCount;
            public List<Tuple<uint, ulong>> targEdges; //BlockID_Count
            public List<Tuple<ulong, ulong>>? targExternEdges; //Addr_Count
            public List<InstructionData>? blockInslist;
        };

        private readonly List<BLOCKREPEAT> blockRepeatQueue = new List<BLOCKREPEAT>();
        /// <summary>
        /// How many blockrepeats are waiting go be assigned
        /// </summary>
        public int PendingBlockRepeats => blockRepeatQueue.Count;
        /// <summary>
        /// How long it took to assign the last blockrepeats
        /// </summary>
        public double LastBlockRepeatsTime = 0;

        private struct NEW_EDGE_BLOCKDATA
        {
            public ulong sourceAddr;
            public uint sourceID;
            public ulong targAddr;
            public uint targID;
        };

        private readonly List<NEW_EDGE_BLOCKDATA> PendingEdges = new List<NEW_EDGE_BLOCKDATA>();

        private class APITHUNK
        {
            public Dictionary<int, int> callerNodes = new Dictionary<int, int>();
        }

        private readonly Dictionary<int, APITHUNK> ApiThunks = new Dictionary<int, APITHUNK>();

        /// <summary>
        /// Worker for processing trace data
        /// </summary>
        /// <param name="newProtoGraph">Thread graph being processed</param>
        public ThreadTraceProcessingThread(ProtoGraph newProtoGraph)
        {
            protograph = newProtoGraph;

            if (rgatState.ConnectedToRemote && rgatState.NetworkBridge.HeadlessMode)
            {
                Logging.RecordLogEvent("Error: Trace processor created in headless mode", Logging.LogFilterType.TextError);
                rgatState.NetworkBridge.Teardown("TraceProcessor created in wrong mode");
            }
        }

        /// <summary>
        /// Begin processing
        /// </summary>
        public override void Begin()
        {
            base.Begin();

            WorkerThread = new Thread(Processor)
            {
                Name = "TraceProcessor" + this.protograph.ThreadID
            };
            WorkerThread.Start();

            IrregularActionTimer = new System.Timers.Timer(800);
            IrregularActionTimer.Elapsed += (sender, args) => IrregularTimerFired = true;
            IrregularActionTimer.AutoReset = false;
            IrregularActionTimer.Start();
        }

        private void PerformIrregularActions()
        {
            if (rgatState.rgatIsExiting)
            {
                return;
            }

            if (blockRepeatQueue.Count > 0)
            {
                AssignBlockRepeats();
            }

            if (protograph.HasPendingArguments)
            {
                protograph.ProcessIncomingCallArguments();
            }

            IrregularActionTimer?.Start();
        }

        //peforms non-sequence-critical graph updates
        //update nodes with cached execution counts and new edges from unchained runs
        //also updates graph with delayed edge notifications
        private void AssignBlockRepeats()
        {
            Stopwatch ABRtime = new System.Diagnostics.Stopwatch();
            ABRtime.Start();

            int RecordedBlocksQty = protograph.BlocksFirstLastNodeList.Count;
            for (var i = blockRepeatQueue.Count - 1; i >= 0; i--)
            {
                BLOCKREPEAT brep = blockRepeatQueue[i];
                NodeData? n = null;

                if (brep.blockInslist == null)
                {
                    if (brep.blockID >= protograph.ProcessData.BasicBlocksList.Count)
                    {
                        continue;
                    }
                    var block = protograph.ProcessData.BasicBlocksList[(int)brep.blockID];
                    if (block is null)
                    {
                        continue;
                    }

                    brep.blockInslist = block.Item2;
                }

                bool needWait = false;
                foreach (var targblockID_Count in brep.targEdges)
                {
                    int edgeblock = (int)targblockID_Count.Item1;
                    if (edgeblock >= protograph.ProcessData.BasicBlocksList.Count)
                    {
                        //block has not been processed yet
                        needWait = true;
                        break;
                    }
                    if (edgeblock >= protograph.BlocksFirstLastNodeList.Count ||
                        (protograph.BlocksFirstLastNodeList[edgeblock] == null &&
                        !ApiThunks.ContainsKey(edgeblock)))
                    {
                        var block = protograph.ProcessData.BasicBlocksList[edgeblock];
                        if (block is null)
                        {
                            continue;
                        }

                        if (block.Item2[0].PossibleidataThunk)
                        {
                            //block has not been processed (and its probably (...) not a thunk)
                            needWait = true;
                            break;
                        }
                    }

                    var blockB = protograph.ProcessData.BasicBlocksList[edgeblock];
                    if (blockB is null || !blockB.Item2[0].InThread(protograph.ThreadID))
                    {
                        //block has not been placed on graph
                        needWait = true;
                        break;
                    }
                }

                if (needWait)
                {
                    continue;
                }

                //store pending changes, only apply them if all the data is available
                List<Tuple<NodeData, ulong>> increaseNodes = new List<Tuple<NodeData, ulong>>();
                List<Tuple<EdgeData, ulong>> increaseEdges = new List<Tuple<EdgeData, ulong>>();

                InstructionData lastIns = brep.blockInslist[^1];

                if (brep.targExternEdges != null)
                {
                    if (!lastIns.PossibleidataThunk || brep.blockInslist.Count != 1)
                    {
                        lastIns.GetThreadVert(protograph.ThreadID, out uint lastNodeIdx);
                        NodeData? lastNode = protograph.GetNode(lastNodeIdx);
                        if (lastNode is null)
                        {
                            continue;
                        }

                        foreach (var addr_Count in brep.targExternEdges)
                        {
                            ulong targetAddr = addr_Count.Item1;
                            ulong execCount = addr_Count.Item2;

                            bool found = false;
                            foreach (var x in lastNode.OutgoingNeighboursSet)
                            {
                                NodeData? outn = protograph.GetNode(x);
                                if (outn == null)
                                {
                                    continue;
                                }

                                if (outn.IsExternal && outn.address == targetAddr)
                                {
                                    EdgeData? e = protograph.GetEdge(lastNodeIdx, outn.Index);
                                    if (e == null)
                                    {
                                        continue;
                                    }

                                    increaseNodes.Add(new Tuple<NodeData, ulong>(outn, execCount));
                                    increaseEdges.Add(new Tuple<EdgeData, ulong>(e, execCount));
                                    found = true;
                                    break;
                                }
                            }
                            if (!found)
                            {
                                needWait = true;
                                break;

                            };
                        }
                    }
                }
                if (needWait)
                {
                    continue;
                }


                //first record execution of each instruction
                foreach (InstructionData ins in brep.blockInslist)
                {
                    if (!ins.GetThreadVert(protograph.ThreadID, out uint vert))
                    {
                        needWait = true;
                        break;
                    }
                    n = protograph.GetNode(vert);
                    if (n == null)
                    {
                        needWait = true;
                        break;
                    }
                    increaseNodes.Add(new Tuple<NodeData, ulong>(n, brep.repeatCount));

                    if (ins.Address != lastIns.Address)
                    {
                        uint targID = n.OutgoingNeighboursSet[0];
                        EdgeData? targEdge = protograph.GetEdge(n.Index, targID);
                        if (targEdge == null)
                        {
                            needWait = true;
                            break;
                        }

                        //if (n.OutgoingNeighboursSet.Count == 1)
                        increaseEdges.Add(new Tuple<EdgeData, ulong>(targEdge, brep.repeatCount));
                        /*
                        Logging.RecordLogEvent($"Blockrepeat increasing internal edge {n.index},{targID} from {targEdge.executionCount} to {targEdge.executionCount + brep.repeatCount} execs",
                            graph: protograph,
                            trace: protograph.TraceData,
                            filter: Logging.LogFilterType.BulkDebugLogFile);
                        */

                    }
                }
                if (needWait)
                {
                    continue;
                }

                List<ExtraEdge> newEdges = new List<ExtraEdge>();

                //create any new edges between unchained nodes
                foreach (var targblockID_Count in brep.targEdges)
                {
                    int targetBlockID = (int)targblockID_Count.Item1;
                    ulong execCount = targblockID_Count.Item2;
                    uint targNodeID = 0;
                    if (targetBlockID >= protograph.BlocksFirstLastNodeList.Count || protograph.BlocksFirstLastNodeList[targetBlockID] == null)
                    {
                        if (ApiThunks.TryGetValue(targetBlockID, out APITHUNK? thunkData))
                        {
                            if (thunkData.callerNodes.TryGetValue((int)n!.Index, out int targNd))
                            {
                                targNodeID = (uint)targNd;
                                //protograph.NodeList[targNd].IncreaseExecutionCount(brep.repeatCount);
                            }
                            else
                            {
                                Logging.WriteConsole($"No callers for node 0x{n.address:X}");
                                needWait = true;
                                break;
                            }
                        }
                        else
                        {
                            //sometimes blocks get a new id
                            InstructionData? altIns = protograph.ProcessData.BasicBlocksList[targetBlockID]?.Item2[0];
                            if (altIns is not null && altIns.GetThreadVert(protograph.ThreadID, out uint altFirstNodeIdx))
                            {
                                targNodeID = altFirstNodeIdx;
                            }
                            else
                            {
                                Logging.WriteConsole($"No callers for node 0x{altIns?.Address:X}");
                                needWait = true;
                                break;
                            }
                        }
                        //var il = protograph.ProcessData.getDisassemblyBlock((uint)targetBlockID);
                        //targNodeID = il[0].threadvertIdx[protograph.ThreadID];
                    }
                    else
                    {
                        targNodeID = protograph.BlocksFirstLastNodeList[targetBlockID]!.Item1;
                    }


                    if (n!.OutgoingNeighboursSet.Contains(targNodeID) is false)
                    {
                        //again let new tag execution handle it
                        newEdges.Add(new ExtraEdge() { count = execCount, source = n.Index, target = targNodeID });

                        Logging.RecordLogEvent($"Blockrepeat adding edge {n.Index},{targNodeID} with {execCount} execs",
                           Logging.LogFilterType.BulkDebugLogFile);

                    }
                    else
                    {
                        EdgeData? edge = protograph.GetEdge(n.Index, targNodeID);
                        Debug.Assert(edge is not null);
                        Logging.RecordLogEvent($"Blockrepeat increasing execs of edge {n.Index},{targNodeID} from {edge.ExecutionCount} to {edge.ExecutionCount + execCount}",
                           Logging.LogFilterType.BulkDebugLogFile);
                        increaseEdges.Add(new Tuple<EdgeData, ulong>(edge, execCount));
                    }
                }

                if (needWait)
                {
                    continue;
                }

                //Now everything is validated, apply to the graph
                foreach (ExtraEdge newEdge in newEdges)
                {
                    protograph.AddEdge(newEdge.source, newEdge.target, newEdge.count);
                }
                foreach (var nodeInc in increaseNodes)
                {
                    nodeInc.Item1.IncreaseExecutionCount(nodeInc.Item2);
                    protograph.TotalInstructions += nodeInc.Item2;
                }
                foreach (var edgeInc in increaseEdges)
                {
                    edgeInc.Item1.IncreaseExecutionCount(edgeInc.Item2);
                }


                blockRepeatQueue.RemoveAt(i);
            }
            ABRtime.Stop();
            LastBlockRepeatsTime = ABRtime.Elapsed.TotalMilliseconds;
        }

        private struct ExtraEdge
        {
            public uint source;
            public uint target;
            public ulong count;
        };

        private bool _ignore_next_tag = false;
        private uint _ignored_tag_blockID = 0;

        /// <summary>
        /// Handle execution of a basic block
        /// </summary>
        /// <param name="entry">A trace tag entry from instrumentation</param>
        public void ProcessTraceTag(byte[] entry)
        {
            TAG thistag;
            ulong nextBlockAddress;
            int tokenpos = 0;
            for (; tokenpos < entry.Length; tokenpos++)
            {
                if (entry[tokenpos] == ',')
                {
                    break;
                }
            }

            thistag.blockID = uint.Parse(Encoding.ASCII.GetString(entry, 1, tokenpos - 1), NumberStyles.HexNumber);
            //this may be a bad idea, could just be running faster than the dissassembler thread
            int waits = 0;
            while (thistag.blockID >= protograph.ProcessData.BasicBlocksList.Count)
            {
                Thread.Sleep(50);
                waits += 1;
                if (waits > 5)
                {
                    Logging.WriteConsole($"Waiting for block {thistag.blockID} to appear ({protograph.ProcessData.BasicBlocksList.Count} available)");
                }
            }
            Debug.Assert(thistag.blockID < protograph.ProcessData.BasicBlocksList.Count, "ProcessTraceTag tried to process block that hasn't been disassembled");

            if (!protograph.ProcessData.WaitForAddressOfBlock(thistag.blockID, out thistag.blockaddr))
            {
                Logging.RecordError($"Error - EnsureBlockExistsGetAddress failed for {protograph.TraceData.Target.FileName} block {thistag.blockID}. Discarding trace.");
                protograph.TraceReader!.Terminate();
                return;
            }

            ANIMATIONENTRY animUpdate = new ANIMATIONENTRY
            {
                entryType = eTraceUpdateType.eAnimExecTag,
                blockAddr = thistag.blockaddr,
                blockID = thistag.blockID
            };
            protograph.PushAnimUpdate(animUpdate);

            int addrstart = ++tokenpos;
            string result = ASCIIEncoding.ASCII.GetString(entry);
            nextBlockAddress = ulong.Parse(Encoding.ASCII.GetString(entry, addrstart, entry.Length - addrstart), NumberStyles.HexNumber);

            thistag.InstrumentationState = eCodeInstrumentation.eInstrumentedCode;
            thistag.foundExtern = null;
            thistag.insCount = 0; //meaningless here


            //fallen through/failed conditional jump
            if (_ignore_next_tag)
            {
                if (_ignore_next_tag)
                {
                    Debug.Assert(thistag.blockID == _ignored_tag_blockID); //todo - happens singlestepping past call then continuing in functions test
                    _ignore_next_tag = false;
                }
                return;
            }


            //this messy bit of code deals with unistrumented APi code that has been called from a "jmp ptr [addr]" instruction
            eCodeInstrumentation modType = protograph.TraceData.FindContainingModule(nextBlockAddress, out int modnum);
            if (modType == eCodeInstrumentation.eUninstrumentedCode)
            {
                List<InstructionData>? preExternBlock = protograph.TraceData.DisassemblyData.getDisassemblyBlock(thistag.blockID);
                if (preExternBlock is not null &&
                    preExternBlock.Count == 1 &&
                    preExternBlock[0].PossibleidataThunk)
                {
                    InstructionData thunkInstruction = preExternBlock[0];
                    ProcessExtern(nextBlockAddress, thistag.blockID);

                    bool firstCallByThisNode = false;
                    if (ApiThunks.TryGetValue((int)thistag.blockID, out APITHUNK? thunkinfo))
                    {
                        if (!thunkinfo.callerNodes.ContainsKey((int)protograph.ProtoLastLastVertID))
                        {
                            firstCallByThisNode = true;
                            thunkinfo.callerNodes.Add((int)protograph.ProtoLastLastVertID, (int)protograph.ProtoLastVertID);
                        }
                    }
                    else
                    {
                        firstCallByThisNode = true;
                        APITHUNK thunkData = new APITHUNK();
                        thunkData.callerNodes.Add((int)protograph.ProtoLastLastVertID, (int)protograph.ProtoLastVertID);
                        ApiThunks.Add((int)thistag.blockID, thunkData);
                    }

                    if (firstCallByThisNode)
                    {

                        thunkInstruction.AddThreadVert(protograph.ThreadID, protograph.ProtoLastVertID);
                        //todo this can be bad idx
                        if (protograph.ProtoLastLastVertID < protograph.NodeList.Count)
                        {
                            protograph.NodeList[(int)protograph.ProtoLastLastVertID].ThunkCaller = true;
                        }
                        else
                        {
                            Logging.RecordLogEvent($"Error - thunk caller index {protograph.ProtoLastLastVertID} not available", Logging.LogFilterType.TextError);
                        }
                    }

                    uint calleridx = protograph.ProtoLastLastVertID;
                    NodeData apinode = protograph.NodeList[(int)protograph.ProtoLastVertID];
                    if (!apinode.IncomingNeighboursSet.Contains(calleridx))
                    {
                        apinode.IncomingNeighboursSet.Add(calleridx);
                    }

                    if (thistag.blockID == protograph.BlocksFirstLastNodeList.Count)
                    {
                        protograph.BlocksFirstLastNodeList.Add(null);
                    }
                    else if (thistag.blockID < protograph.BlocksFirstLastNodeList.Count && protograph.BlocksFirstLastNodeList[(int)thistag.blockID] != null)
                    {
                        Debug.Assert(false, "Panik"); //todo: exceptions
                    }

                    return;
                }
            }

            protograph.HandleTag(thistag, dontcountnextedge);
            if (dontcountnextedge)
            {
                dontcountnextedge = false;
            }


            if (modType is eCodeInstrumentation.eUninstrumentedCode)
            {
                ProcessExtern(nextBlockAddress, thistag.blockID);
            }
        }

        private void AddSingleStepUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 1, entry.Length - 1);
            string[] entries = msg.Split(',', 3);
            if (entries.Length == 3)
            {
                uint blockID = uint.Parse(entries[0], NumberStyles.HexNumber);
                ulong stepAddr = ulong.Parse(entries[1], NumberStyles.HexNumber);
                ulong nextAddr = uint.Parse(entries[2], NumberStyles.HexNumber);
                if (!protograph.SetRecentStep(blockID, stepAddr, nextAddr))
                {
                    _ignore_next_tag = true;
                    _ignored_tag_blockID = blockID;
                }
            }
            else
            {
                Logging.WriteConsole($"AddSingleStepUpdate Error: Entries had length {entries.Length}: {entry}");
            }
        }


        //show a REP prefixed instruction has executed at least once (ie: with ecx > 0)
        private void AddRepExecUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 2);

            ANIMATIONENTRY animUpdate = new ANIMATIONENTRY
            {
                entryType = eTraceUpdateType.eAnimRepExec,
                blockID = uint.Parse(entries[1], NumberStyles.HexNumber)
            };
            protograph.PushAnimUpdate(animUpdate);
            Logging.RecordLogEvent($"A REP instruction (blkid {animUpdate.blockID}) has executed at least once. Need to action this as per trello 160");
        }

        private void ProcessExtern(ulong externAddr, uint callerBlock)
        {
            //modType could be known unknown here
            //in case of unknown, this waits until we know. hopefully rare.

            TAG externTag = new TAG
            {
                InstrumentationState = eCodeInstrumentation.eUninstrumentedCode,
                blockaddr = externAddr
            };

            protograph.HandleTag(externTag);

            ANIMATIONENTRY animUpdate = new ANIMATIONENTRY
            {
                blockAddr = externAddr,
                entryType = eTraceUpdateType.eAnimExecTag,
                blockID = uint.MaxValue
            };
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
        private void HandleArg(byte[] entry)
        {

            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 6);

            int argIdx = int.Parse(entries[1], NumberStyles.Integer);
            ulong funcpc = ulong.Parse(entries[2], NumberStyles.HexNumber);
            ulong sourceBlockID = ulong.Parse(entries[3], NumberStyles.HexNumber);

            char moreArgsFlag = entries[4][0];
            string argstring = entries[5];

            Logging.WriteConsole($"Handling arg index {argIdx} of symbol address 0x{funcpc:x} from source block {sourceBlockID} :'{argstring}'");

            protograph.CacheIncomingCallArgument(funcpc, sourceBlockID, argpos: argIdx, contents: argstring, isLastArgInCall: moreArgsFlag == 'E');

        }

        private void HandleRetVal(byte[] entry)
        {

            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 4);

            ulong funcpc = ulong.Parse(entries[1], NumberStyles.HexNumber);
            ulong sourceBlockID = ulong.Parse(entries[2], NumberStyles.HexNumber);

            protograph.CacheIncomingCallArgument(funcpc, sourceBlockID, -1, entries[3], true); //todo look at this causing a dupe arg list to be created

        }

        private void AddReinstrumentedUpdate(byte[] entry)
        {
            dontcountnextedge = true; // the edge from deinstrumented -> instrumented is already recorded
            protograph.PerformingUnchainedExecution = false;

            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 2);

            ANIMATIONENTRY animUpdate;
            animUpdate.entryType = eTraceUpdateType.eAnimReinstrument;
            animUpdate.blockID = uint.Parse(entries[1], NumberStyles.HexNumber);
            animUpdate.targetAddr = 0;
            animUpdate.targetID = 0;
            animUpdate.count = 0;
            animUpdate.edgeCounts = null;
            animUpdate.blockAddr = 0;
            protograph.PushAnimUpdate(animUpdate);

            protograph.ProtoLastLastVertID = protograph.ProtoLastVertID;
            var blockNodes = protograph.BlocksFirstLastNodeList[(int)animUpdate.blockID];

            if (blockNodes != null)
            { protograph.ProtoLastVertID = blockNodes.Item2; }
            else
            {
                //protograph.ProtoLastVertID = prto
                //don't bother setting the last vert id?
                /*
                if (protograph.ApiThunks.TryGetValue((int)animUpdate.blockID, out ProtoGraph.APITHUNK thunkInfo))
                {

                    
                    if (thunkInfo.callerNodes.TryGetValue((int)protograph.ProtoLastVertID, out int callervert))
                    {

                        Logging.WriteConsole("dxde");
                    }

                    Logging.WriteConsole("xde");
                    return;
                }*/
                //Debug.Assert(false, $"Block {animUpdate.blockID} has null entry but is not a thunk");
            }
            currentUnchainedBlocks.Clear(); //todo dont need this
        }

        private readonly List<uint> currentUnchainedBlocks = new List<uint>();

        private void AddUnchainedUpdate(byte[] entry)
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

            currentUnchainedBlocks.Add(animUpdate.blockID);

            protograph.ProtoLastLastVertID = protograph.ProtoLastVertID;
            var blockNodes = protograph.BlocksFirstLastNodeList[(int)animUpdate.blockID];

            if (blockNodes == null)
            {
                if (ApiThunks.TryGetValue((int)animUpdate.blockID, out APITHUNK? thunkInfo))
                {
                    if (thunkInfo.callerNodes.TryGetValue((int)protograph.ProtoLastVertID, out int thunkTargetAPINodeIdx))
                    {
                        if (protograph.PerformingUnchainedExecution == false)
                        {
                            protograph.GetEdge(protograph.ProtoLastVertID, (uint)thunkTargetAPINodeIdx)?.IncreaseExecutionCount(1);
                            protograph.PerformingUnchainedExecution = true;
                        }
                        return;
                    }
                    Debug.Assert(false, $"Bad thunk state, node {protograph.ProtoLastVertID} does not call this thunk");
                }
                Debug.Assert(false, $"Bad thunk state, block {animUpdate.blockID} has null listing but is not a thunk");
            }

            if (!protograph.NodeList[(int)protograph.ProtoLastLastVertID].ThunkCaller)
            {
                if (protograph.PerformingUnchainedExecution == false)
                {
                    EdgeData? e = protograph.GetEdge(protograph.ProtoLastLastVertID, blockNodes.Item1);
                    if (e != null)
                    {
                        e.IncreaseExecutionCount(1);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Error: AddUnchainedUpdate for missing edge {protograph.ProtoLastLastVertID},{blockNodes.Item1}",
                            filter: Logging.LogFilterType.TextError);
                    }
                    protograph.PerformingUnchainedExecution = true;
                }
            }

            protograph.ProtoLastVertID = blockNodes.Item2;

            //Logging.WriteConsole($"Processing AddUnchainedUpdate source 0x{animUpdate.blockAddr:X} targaddr 0x{animUpdate.targetAddr:X}");
        }

        private void AddExecCountUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 3);


            BLOCKREPEAT newRepeat;
            newRepeat.blockID = uint.Parse(entries[1], NumberStyles.HexNumber);
            newRepeat.targEdges = new List<Tuple<uint, ulong>>();
            newRepeat.targExternEdges = null;

            if (GlobalConfig.Settings.Logs.BulkLogging)
            {
                Logging.RecordLogEvent($"Processing AddExecCountUpdate block {newRepeat.blockID}",
                    trace: protograph.TraceData,
                    graph: protograph,
                    filter: Logging.LogFilterType.BulkDebugLogFile);
            }

            string[] edgeCounts = entries[2].Split(',');

            ulong blockExecs = 0;
            for (int i = 0; i < edgeCounts.Length; i += 2)
            {
                ulong targAddr = ulong.Parse(edgeCounts[i], NumberStyles.HexNumber);

                ulong targBlock = protograph.ProcessData.WaitForBlockAtAddress(targAddr);
                ulong edgeExecCount = ulong.Parse(edgeCounts[i + 1], NumberStyles.HexNumber);

                if (targBlock == ulong.MaxValue)
                {
                    if (newRepeat.targExternEdges == null)
                    {
                        newRepeat.targExternEdges = new List<Tuple<ulong, ulong>>();
                    }
                    newRepeat.targExternEdges.Add(new Tuple<ulong, ulong>(targAddr, edgeExecCount));
                }
                else
                {
                    newRepeat.targEdges.Add(new Tuple<uint, ulong>((uint)targBlock, edgeExecCount));
                }
                blockExecs += edgeExecCount;

                if (GlobalConfig.Settings.Logs.BulkLogging)
                {
                    Logging.RecordLogEvent($"\t +targ {targBlock}x{edgeExecCount}",
                        trace: protograph.TraceData,
                        graph: protograph,
                        filter: Logging.LogFilterType.BulkDebugLogFile);
                }
            }
            newRepeat.repeatCount = blockExecs;
            newRepeat.blockInslist = null;
            blockRepeatQueue.Add(newRepeat);

            ANIMATIONENTRY animUpdate;
            animUpdate.entryType = eTraceUpdateType.eAnimUnchainedResults;
            animUpdate.blockAddr = ulong.MaxValue;
            animUpdate.blockID = newRepeat.blockID;
            animUpdate.edgeCounts = newRepeat.targEdges;
            animUpdate.count = blockExecs;
            animUpdate.targetAddr = ulong.MaxValue;
            animUpdate.targetID = 0;
            protograph.PushAnimUpdate(animUpdate);

            if (blockExecs > protograph.BusiestBlockExecCount)
            {
                protograph.BusiestBlockExecCount = blockExecs;
            }
        }

        private void AddSatisfyUpdate(byte[] entry)
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

        private void AddExceptionUpdate(byte[] entry)
        {
            string msg = Encoding.ASCII.GetString(entry, 0, entry.Length);
            string[] entries = msg.Split(',', 4);

            ulong address = ulong.Parse(entries[1], NumberStyles.HexNumber);
            ulong code = ulong.Parse(entries[2], NumberStyles.HexNumber);
            ulong flags = ulong.Parse(entries[3], NumberStyles.HexNumber);


            Logging.WriteConsole($"[rgat]Exception detected in PID{protograph.TraceData.PID} TID: {protograph.ThreadID} [code 0x{code:X} flags: 0x{flags:X}] at address 0x{address:X}");
            List<InstructionData>? faultingBlock;
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
                        Logging.WriteConsole($"[rgat]Exception address 0x{address:X} not found in disassembly");
                        return;
                    }
                }
            }

            //problem here: no way of knowing which mutation of the faulting block was executed
            //going to have to assume it's the most recent mutation
            InstructionData exceptingins = faultingBlock![^1];
            Debug.Assert(exceptingins.ContainingBlockIDs is not null);
            uint faultingBasicBlock_ID = exceptingins.ContainingBlockIDs[^1];
            List<InstructionData>? faultingBB = protograph.ProcessData.getDisassemblyBlock(faultingBasicBlock_ID);
            Debug.Assert(faultingBB is not null);

            //todo: Lock, linq
            int instructionsUntilFault = 0;
            for (; instructionsUntilFault < faultingBB.Count; ++instructionsUntilFault)
            {
                if (faultingBB[instructionsUntilFault].Address == address)
                {
                    break;
                }
            }

            var faultblock = protograph.ProcessData.BasicBlocksList[(int)faultingBasicBlock_ID];
            Debug.Assert(faultblock is not null);
            TAG interruptedBlockTag;
            interruptedBlockTag.blockaddr = faultblock.Item2[0].Address;
            interruptedBlockTag.insCount = (ulong)instructionsUntilFault;
            interruptedBlockTag.blockID = faultingBasicBlock_ID;
            interruptedBlockTag.InstrumentationState = eCodeInstrumentation.eInstrumentedCode;
            interruptedBlockTag.foundExtern = null;
            protograph.HandleExceptionTag(interruptedBlockTag);

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

        private bool dontcountnextedge = false;


        private readonly object debug_tag_lock = new object();

        private void Processor()
        {
            if (protograph.TraceReader is null)
            {
                Logging.RecordError("Trace processor has no trace reader associated");
                return;
            }

            //process traces until program exits or the trace ingest stops + the queues are empty
            while (!rgatState.rgatIsExiting && (!protograph.TraceReader.StopFlag || protograph.TraceReader.HasPendingData))
            {
                byte[]? msg = protograph.TraceReader.DeQueueData();
                if (msg == null)
                {
                    AssignBlockRepeats();
                    protograph.TraceReader.RequestWakeupOnData();
                    if (rgatState.rgatIsExiting || protograph.TraceReader.StopFlag) { continue; }
                    try
                    {
                        protograph.TraceReader.TagDataReadyEvent.Wait(-1, cancellationToken: protograph.TraceReader.CancelToken);
                    }
                    catch
                    {
                        continue;
                    }

                    continue;
                }



                //if (msg[0] != 'A') Logging.WriteConsole("IngestedMsg: " + Encoding.ASCII.GetString(msg, 0, msg.Length));
                //Logging.RecordLogEvent("IngestedMsg: " + Encoding.ASCII.GetString(msg, 0, msg.Length), filter: Logging.LogFilterType.BulkDebugLogFile);

                lock (debug_tag_lock) //todo dont forget to remove this
                {
                    switch (msg[0])
                    {
                        case (byte)'j':
                            ProcessTraceTag(msg);
                            break;
                        case (byte)'A':
                            HandleArg(msg);
                            break;
                        case (byte)'a':
                            HandleRetVal(msg);
                            break;
                        case (byte)'R':
                            AddReinstrumentedUpdate(msg);
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
                        case (byte)'r':
                            AddRepExecUpdate(msg);
                            break;
                        default:
                            Logging.RecordLogEvent($"Bad trace tag {(char)msg[0]}", filter: Logging.LogFilterType.BulkDebugLogFile);

                            Logging.RecordLogEvent($"Bad trace tag: {msg[0]} - likely a corrupt trace", Logging.LogFilterType.TextError);
                            Logging.WriteConsole($"Handle unknown tag {(char)msg[0]}");
                            Logging.WriteConsole("IngestedMsg: " + Encoding.ASCII.GetString(msg, 0, msg.Length));
                            protograph.TraceReader.Terminate();
                            break;
                    }
                }

                if (IrregularTimerFired)
                {
                    PerformIrregularActions();
                }
            }

            IrregularActionTimer?.Stop();

            //final pass
            PerformIrregularActions();


            Logging.WriteConsole($"{WorkerThread?.Name} finished with {PendingEdges.Count} pending edges and {blockRepeatQueue.Count} blockrepeats outstanding");
            Debug.Assert(blockRepeatQueue.Count == 0 || rgatState.rgatIsExiting || protograph.TraceReader.StopFlag);

            Finished();
        }
    }
}
