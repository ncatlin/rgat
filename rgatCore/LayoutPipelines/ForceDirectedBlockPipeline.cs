﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Veldrid;

namespace rgat.Layouts
{
    class ForceDirectedBlockPipeline : LayoutPipelines.LayoutPipeline
    {

        public ForceDirectedBlockPipeline(GraphicsDevice gdev) : base(gdev, "ForceDirectedBlock")
        {
            SetupComputeResources();
        }

        bool _disposed = false;
        public override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _velocityShader?.Dispose();
                    _velocityShaderRsrcLayout?.Dispose();
                    _velocityComputePipeline?.Dispose();
                    _positionShader?.Dispose();
                    _positionShaderRsrcLayout?.Dispose();
                    _positionComputePipeline?.Dispose();
                }
                _disposed = true;
            }
            base.Dispose(disposing);
        }

        private unsafe void SetupComputeResources()
        {
            Debug.Assert(_gd is not null, "Init not called");
            ResourceFactory factory = _gd.ResourceFactory;

            if (_gd.Features.ComputeShader is false) { Logging.RecordError("Error: Compute shaders are unavailable"); return; }

            _velocityParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<VelocityShaderParams>(), BufferUsage.UniformBuffer, name: "VelocityShaderParams");


            byte[]? velocityBlockShaderBytes = ImGuiNET.ImGuiController.LoadEmbeddedShaderCode(factory, "sim-blockVelocity", ShaderStages.Fragment);
            _velocityShader = factory.CreateShader(new ShaderDescription(ShaderStages.Compute, velocityBlockShaderBytes, "FS"));

            _velocityShaderRsrcLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeStrengths", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockMiddles", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));

            ComputePipelineDescription VelocityBlockCPD = new ComputePipelineDescription(_velocityShader, _velocityShaderRsrcLayout, 16, 16, 1);

            _velocityComputePipeline = factory.CreateComputePipeline(VelocityBlockCPD);

            _positionShaderRsrcLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)
            ));


            byte[]? positionShaderBytes = ImGuiNET.ImGuiController.LoadEmbeddedShaderCode(factory, "sim-blockPosition", ShaderStages.Vertex);
            _positionShader = factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, positionShaderBytes, "FS")); //todo ... not fragment

            ComputePipelineDescription PositionCPD = new ComputePipelineDescription(_positionShader, _positionShaderRsrcLayout, 16, 16, 1);
            _positionComputePipeline = factory.CreateComputePipeline(PositionCPD);
            _positionParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<PositionShaderParams>(), BufferUsage.UniformBuffer, name: "PositionShaderParams");
        }


        public override void Compute(PlottedGraph plot, CommandList cl, bool flip, float delta)
        {
            GraphLayoutState layout = plot.LayoutState;
            ResourceSetDescription velocity_rsrc_desc, pos_rsrc_desc;
            if (flip)
            {
                velocity_rsrc_desc = new ResourceSetDescription(_velocityShaderRsrcLayout,
                    _velocityParamsBuffer, layout.PositionsVRAM1, layout.VelocitiesVRAM1, layout.EdgeConnectionIndexes,
                    layout.EdgeConnections, layout.EdgeStrengths, layout.BlockMetadata, layout.BlockMiddles,
                layout.VelocitiesVRAM2
                );

                pos_rsrc_desc = new ResourceSetDescription(_positionShaderRsrcLayout,
                    _positionParamsBuffer, layout.PositionsVRAM1, layout.VelocitiesVRAM2, layout.BlockMetadata,
                   layout.PositionsVRAM2);
            }
            else
            {
                velocity_rsrc_desc = new ResourceSetDescription(_velocityShaderRsrcLayout,
                _velocityParamsBuffer, layout.PositionsVRAM2, layout.VelocitiesVRAM2, layout.EdgeConnectionIndexes,
                layout.EdgeConnections, layout.EdgeStrengths, layout.BlockMetadata, layout.BlockMiddles,
                layout.VelocitiesVRAM1
                );

                pos_rsrc_desc = new ResourceSetDescription(_positionShaderRsrcLayout,
                    _positionParamsBuffer, layout.PositionsVRAM2, layout.VelocitiesVRAM1, layout.BlockMetadata,
                    layout.PositionsVRAM1);
            }

            RenderVelocity(velocity_rsrc_desc, cl, plot);
            RenderPosition(pos_rsrc_desc, cl, plot, delta);   
        }




        private void RenderVelocity(ResourceSetDescription RSetDesc, CommandList cl, PlottedGraph plot)
        {
            _timer.Restart();
            cl.Begin();

            ResourceSet resourceSet = _gd.ResourceFactory.CreateResourceSet(RSetDesc);

            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderVelocityBlocks  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            GraphLayoutState layout = plot.LayoutState;
            VelocityShaderParams parameters = new VelocityShaderParams
            {
                temperature = Math.Min(plot.Temperature, GlobalConfig.MaximumNodeTemperature),
                repulsionK = GlobalConfig.RepulsionK,
                blockCount = (uint)layout._VRAMBuffers.BlockCount
            };

            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} submit", Logging.LogFilterType.BulkDebugLogFile);

            cl.UpdateBuffer(_velocityParamsBuffer, 0, parameters);
            cl.SetPipeline(_velocityComputePipeline);
            cl.SetComputeResourceSet(0, resourceSet);

            //16 == sizeof(Vector4)
            cl.Dispatch((uint)Math.Ceiling(layout.VelocitiesVRAM1!.SizeInBytes / (256.0 * 16)), 1, 1);
            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} done in {watch.ElapsedMilliseconds} MS", Logging.LogFilterType.BulkDebugLogFile);

            cl.End();
            _timer.Stop();
            VelocitySetupTime = _timer.Elapsed.TotalMilliseconds;

            _timer.Restart();
            _gd!.SubmitCommands(cl);
            _gd!.WaitForIdle();

            _gd.DisposeWhenIdle(resourceSet);

            _timer.Stop();
            VelocityTime = _timer.Elapsed.TotalMilliseconds;
        }


        /// <summary>
        /// Used the velocity buffer to move the nodes in the positions buffer
        /// </summary>
        /// <param name="RSetDesc">Position shader resource set</param>
        /// <param name="cl">Commandlist to run the commands on</param>
        /// <param name="plot">PlottedGraph to compute</param>
        /// <param name="delta">A float representing how much time has passed since the last frame. Higher values => bigger movements</param>
        private unsafe void RenderPosition(ResourceSetDescription RSetDesc, CommandList cl, PlottedGraph plot, float delta)
        {
            _timer.Restart();
            cl.Begin();

            ResourceSet resourceSet = _gd.ResourceFactory.CreateResourceSet(RSetDesc);
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, positions));
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, velocities));

            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderPosition  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);

            PositionShaderParams parameters = new PositionShaderParams
            {
                delta = delta,
                NodeCount = (uint)plot.RenderedNodeCount(),
                blockNodeSeparation = 160
            };

            //Logging.WriteConsole($"POS Parambuffer Size is {(uint)Unsafe.SizeOf<PositionShaderParams>()}");

            cl.UpdateBuffer(_positionParamsBuffer, 0, parameters);
            cl.SetPipeline(_positionComputePipeline);
            cl.SetComputeResourceSet(0, resourceSet);
            cl.Dispatch((uint)Math.Ceiling(plot.LayoutState.PositionsVRAM1!.SizeInBytes / (256.0 * sizeof(Vector4))), 1, 1);
            cl.End();
            _timer.Stop();
            PositionSetupTime = _timer.Elapsed.TotalMilliseconds;


            _timer.Restart();
            _gd!.SubmitCommands(cl);
            _gd!.WaitForIdle();
            _gd.DisposeWhenIdle(resourceSet);
            _timer.Stop();
            PositionTime = _timer.Elapsed.TotalMilliseconds;
        }


        /*
         * 
         * Velocity computation shader assigns a velocity to each node based on nearby nodes, edges
         * or preset target positions
         * 
         */
        [StructLayout(LayoutKind.Sequential)]
        private struct VelocityShaderParams
        {
            public float temperature;
            public float repulsionK;
            public uint blockCount; 
            //must be multiple of 16
            private readonly uint _padding1;
        }

        /*
         * 
         * Position computation shader moves each node according to its velocity
         * For the block pipline it also places non-center nodes relative to their
         * blocks center node
         * 
         */
        [StructLayout(LayoutKind.Sequential)]
        private struct PositionShaderParams
        {
            public float delta;
            public uint NodeCount;
            public float blockNodeSeparation;
            //must be multiple of 16
            private readonly uint _padding1;
        }


        /// Creates an array of metadata for basic blocks used for basic-block-centric graph layout
        public static unsafe void CreateBlockMetadataBuffer(PlottedGraph plot, GraphicsDevice gdevice)
        {
            GraphLayoutState layout = plot.LayoutState;
            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"CreateBlockDataBuffer  {plot.TID}", Logging.LogFilterType.BulkDebugLogFile);

            GraphLayoutState.GPUBuffers VRAMBuffers = layout._VRAMBuffers;
            VeldridGraphBuffers.VRAMDispose(VRAMBuffers.BlockMetadata);
            VeldridGraphBuffers.VRAMDispose(VRAMBuffers.BlockMiddles);

            var textureSize = plot.EdgeTextureWidth();
            if (textureSize > 0)
            {
                CreateBlockMetadataBuf(plot, out NODE_BLOCK_METADATA_COMPUTEBUFFER[] blockdats, out int[] blockMiddles);

                VRAMBuffers.BlockMetadata = VeldridGraphBuffers.TrackedVRAMAlloc(gdevice,
                    (uint)blockdats.Length * NODE_BLOCK_METADATA_COMPUTEBUFFER.SizeInBytes,
                    BufferUsage.StructuredBufferReadOnly, sizeof(int), $"BlockMetadata_T{plot.TID}");

                VRAMBuffers.BlockMiddles = VeldridGraphBuffers.TrackedVRAMAlloc(gdevice,
                    (uint)blockMiddles.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, sizeof(int), $"BlockMiddles_T{plot.TID}");

                VRAMBuffers.BlockCount = blockMiddles.Length;

                if (blockdats.Length == 0)
                {
                    return;
                }

                fixed (NODE_BLOCK_METADATA_COMPUTEBUFFER* datsPtr = blockdats)
                {
                    fixed (int* middlesPtr = blockMiddles)
                    {
                        CommandList cl = gdevice.ResourceFactory.CreateCommandList();
                        cl.Begin();
                        cl.UpdateBuffer(VRAMBuffers.BlockMetadata, 0, (IntPtr)datsPtr, (uint)blockdats.Length * NODE_BLOCK_METADATA_COMPUTEBUFFER.SizeInBytes);
                        cl.UpdateBuffer(VRAMBuffers.BlockMiddles, 0, (IntPtr)middlesPtr, (uint)blockMiddles.Length * sizeof(int));
                        cl.End();
                        gdevice.SubmitCommands(cl);
                        gdevice.WaitForIdle();
                        cl.Dispose();
                    }
                }
            }

            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, newBuffer));

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"CreateBlockDataBuffer  {plot.TID} complete", Logging.LogFilterType.BulkDebugLogFile);
            //PrintBufferArray(textureArray, "Created data texture:");
        }

        public struct NODE_BLOCK_METADATA_COMPUTEBUFFER
        {
            public int MetaBlockIndex;
            public int OffsetFromCenter;
            public int BlockTopEdgeList;
            public int BlockBaseEdgeList;
            public const uint SizeInBytes = 16;
        };


        /// <summary>
        /// Creates an array of metadata for basic blocks used for basic-block-centric graph layout
        /// item[0] = blockID
        /// item[1] = offsetFromCenter; number of nodes ahead the center node is
        /// item[2] = centerPseudoBlockTopID; top of the block this node is in
        /// item[3] = centerPseudoBlockBaseID; base of the block this node is in
        /// </summary>
        /// <param name="plot">The graph being plotted</param>
        /// <param name="blockData">Output description of basic block information for each node</param>
        /// <param name="blockMiddles">Output List of basic block middle nodes</param>
        private static bool CreateBlockMetadataBuf(PlottedGraph plot, out NODE_BLOCK_METADATA_COMPUTEBUFFER[] blockData, out int[] blockMiddles)
        {
            ProtoGraph graph = plot.InternalProtoGraph;
            List<int>[] nodeNeighboursArray = plot.GetNodeNeighboursArray();
            int nodeCount = nodeNeighboursArray.Length;

            NODE_BLOCK_METADATA_COMPUTEBUFFER[] blockDataInts = new NODE_BLOCK_METADATA_COMPUTEBUFFER[nodeCount];
            Dictionary<int, int> blockMiddlesDict = new Dictionary<int, int>();
            List<int> blockMiddleNodesList = new List<int>();
            Dictionary<int, NodeData> exceptionBlocks = new();

            /*
             * Step 1: Build a list of active blocks (ie: blocks which currently have instructions in,
             * as opposed to blocks which have been split into new ones by control flow
             */
            List<int> activeBlockIDs = new();
            Dictionary<int, int> NodeBlockToBlockMetaIndex = new();
            Dictionary<int, int> BlockMetaToBlockFirstLastIndex = new();
            for (var i = 0; i < nodeCount; i++)
            {
                NodeData n = graph.NodeList[i];
                int nodeBlockID = (int)n.BlockID;
                if (NodeBlockToBlockMetaIndex.TryGetValue(nodeBlockID, out int metaBlockID) is false || activeBlockIDs.Contains(metaBlockID) is false)
                {
                    metaBlockID = activeBlockIDs.Count;
                    NodeBlockToBlockMetaIndex[nodeBlockID] = metaBlockID;
                    BlockMetaToBlockFirstLastIndex[metaBlockID] = nodeBlockID;
                    activeBlockIDs.Add(metaBlockID);

                    if(n.CausedException)
                    {
                        exceptionBlocks[metaBlockID] = n;
                    }
                }
            }


            //Step 2: Build the list of block center nodes that the block velocity shader will run over
            blockMiddleNodesList.Capacity = activeBlockIDs.Count;
            foreach (int blockIdx in activeBlockIDs)
            {
                if (blockIdx == -1)
                {
                    blockMiddleNodesList.Add(-1);
                }

                int originalBlockIndex = BlockMetaToBlockFirstLastIndex[blockIdx];

                if (originalBlockIndex < 0 || originalBlockIndex >= graph.BlocksFirstLastNodeList.Count)
                {
                    blockMiddlesDict[blockIdx] = -1; //instructions sent and not executed? why?
                    blockMiddleNodesList.Add((int)-1);

                    continue;
                }

                var firstIdx_LastIdx = graph.BlocksFirstLastNodeList[originalBlockIndex];
                if (firstIdx_LastIdx == null)
                {
                    continue;
                }

                if (firstIdx_LastIdx.Item1 == firstIdx_LastIdx.Item2)
                {
                    if (blockMiddleNodesList.Contains((int)firstIdx_LastIdx.Item1))
                    {
                        continue; 
                    }

                    blockMiddlesDict[blockIdx] = (int)firstIdx_LastIdx.Item1; //1 node block, top/mid/base is the same
                    blockMiddleNodesList.Add((int)firstIdx_LastIdx.Item1);
                    
                    //Debug.Assert(blockIdx == (blockMiddleNodesList.Count-1));
                }
                else
                {
                    var block = graph.ProcessData.BasicBlocksList[originalBlockIndex]?.Item2;
                    Debug.Assert(block is not null);
                    int midIdx = (int)Math.Ceiling((block.Count - 1.0) / 2.0);
                    var middleIns = block[midIdx];
                    if (!middleIns.GetThreadVert(graph.ThreadID, out uint centerNodeID))
                    {
                        blockMiddlesDict[blockIdx] = -1; //instructions sent and not executed? why?
                        //Debug.Assert(false, $"Instruction 0x{middleIns.address:X} not found in thread {tid}");
                    }
                    else
                    {
                        //if (blockMiddleNodesList.Contains((int)centerNodeID))
                        //{
                        //    continue;
                        //}
                        blockMiddlesDict[blockIdx] = (int)centerNodeID;
                        blockMiddleNodesList.Add((int)centerNodeID);
                        //Debug.Assert(blockIdx == (blockMiddleNodesList.Count - 1));
                    }
                }
            }


            /*
             * Step 3: Build the block metadata buffer which allows the position and velocity shaders to process each
             * node in the context of the block it is in 
             */
            int externals = 0;
            for (uint nodeIdx = 0; nodeIdx < nodeCount; nodeIdx++)
            {
                NodeData? n = graph.GetNode(nodeIdx);
                Debug.Assert(n is not null);

                int blockID;
                int offsetFromCenter;
                Tuple<uint, uint>? FirstLastIdx;
                if (!n.IsExternal)
                {
                    if (n.BlockID >= graph.BlocksFirstLastNodeList.Count)
                    {
                        continue;
                    }

                    FirstLastIdx = graph.BlocksFirstLastNodeList[(int)n.BlockID]; //bug: this can happen before bflnl is filled
                    if (FirstLastIdx == null)
                    {
                        continue;
                    }

                    blockID = NodeBlockToBlockMetaIndex[(int)n.BlockID];
                    if (!blockMiddlesDict.ContainsKey(blockID))
                    {
                        continue;
                    }

                    var blockEntry = graph.ProcessData.BasicBlocksList[(int)n.BlockID];
                    Debug.Assert(blockEntry is not null);
                    int blockNodeCount = blockEntry.Item2.Count;
                    if (exceptionBlocks.TryGetValue(blockID, out NodeData? exceptionNode) && exceptionNode is not null)
                    {
                        for (int bIdx = 0; bIdx < blockNodeCount; bIdx++)
                        {
                            if (blockEntry.Item2[bIdx].Address == exceptionNode.Address)
                            {
                                blockNodeCount = bIdx + 1;
                                break;
                            }
                        }
                    }
                    int midIdx = (int)Math.Ceiling((blockNodeCount - 1.0) / 2.0);
                    offsetFromCenter = n.BlockIndex - midIdx;
                }
                else
                {
                    externals += 1;
                    FirstLastIdx = new Tuple<uint, uint>(n.Index, n.Index);
                    offsetFromCenter = 0;
                    blockMiddleNodesList.Add((int)n.Index);

                    //external nodes dont have a block id so just give them a unique one
                    //all that matters in the shader is it's unique
                    blockID = blockMiddleNodesList.Count;
                    blockMiddlesDict[blockID] = (int)n.Index;
                }


                int blockTopNodeIndex = -1;
                int blockBaseNodeIndex = -1;
                if (offsetFromCenter is 0)
                {
                    if (graph.GetNode(FirstLastIdx.Item1)?.IncomingNeighboursSet.Count > 0)
                    {
                        blockTopNodeIndex = (int)FirstLastIdx.Item1;
                    }
                    else
                    {
                        //these are all back edges, which have 0 force
                        /*
                        //the top of the block wasnt connected to anything
                        //there might be a connection below though
                        List<InstructionData>? blockInslist = graph.ProcessData.BasicBlocksList[(int)n.BlockID]?.Item2;
                        if (blockInslist is not null)
                        {
                            for (var i = 1; i < blockInslist.Count; i++)
                            {
                                uint n2Idx = (uint)(FirstLastIdx.Item1 + i);
                                NodeData? n2 = graph.GetNode(n2Idx);
                                if (n2 is not null && n2.IncomingNeighboursSet.Count > 0)
                                {
                                    blockTopNodeIndex = (int)n2Idx;
                                    break;
                                }
                            }
                        } 
                        */
                    }

                    if (graph.GetNode(FirstLastIdx.Item2)?.OutgoingNeighboursSet.Count > 0)
                    {
                        blockBaseNodeIndex = (int)FirstLastIdx.Item2;
                    }
                }
                
                blockDataInts[nodeIdx].MetaBlockIndex = blockID;
                blockDataInts[nodeIdx].OffsetFromCenter = offsetFromCenter;
                blockDataInts[nodeIdx].BlockTopEdgeList = blockTopNodeIndex;
                blockDataInts[nodeIdx].BlockBaseEdgeList = blockBaseNodeIndex != blockTopNodeIndex ? blockBaseNodeIndex : -1;
                //Debug.Assert(offsetFromCenter is not 0 || n.IsExternal || (blockMiddleNodesList[blockID] == (int)nodeIdx));
            }

            blockMiddles = blockMiddleNodesList.ToArray();
            blockData = blockDataInts;

            return true;
        }

    }
}
