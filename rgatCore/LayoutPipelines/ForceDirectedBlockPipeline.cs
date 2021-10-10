using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Veldrid;

namespace rgat.Layouts
{
    class ForceDirectedBlockPipeline : LayoutPipelines.LayoutPipeline
    {

        public ForceDirectedBlockPipeline(GraphicsDevice gdev) : base(gdev)
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
                    _velocityComputeLayout?.Dispose();
                    _velocityComputePipeline?.Dispose();
                    _positionShader?.Dispose();
                    _positionComputeLayout?.Dispose();
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

            _velocityComputeLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeStrengths", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockMiddles", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));

            ComputePipelineDescription VelocityBlockCPD = new ComputePipelineDescription(_velocityShader, _velocityComputeLayout, 16, 16, 1);

            _velocityComputePipeline = factory.CreateComputePipeline(VelocityBlockCPD);

            _positionComputeLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)
            ));


            byte[]? positionShaderBytes = ImGuiNET.ImGuiController.LoadEmbeddedShaderCode(factory, "sim-blockPosition", ShaderStages.Vertex);
            _positionShader = factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, positionShaderBytes, "FS")); //todo ... not fragment

            ComputePipelineDescription PositionCPD = new ComputePipelineDescription(_positionShader, _positionComputeLayout, 16, 16, 1);
            _positionComputePipeline = factory.CreateComputePipeline(PositionCPD);
            _positionParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<PositionShaderParams>(), BufferUsage.UniformBuffer, name: "PositionShaderParams");
        }


        public override void Compute(PlottedGraph plot, bool flip, float delta)
        {
            GraphLayoutState layout = plot.LayoutState;
            ResourceSetDescription velocity_rsrc_desc, pos_rsrc_desc;
            if (flip)
            {
                velocity_rsrc_desc = new ResourceSetDescription(_velocityComputeLayout,
                    _velocityParamsBuffer, layout.PositionsVRAM1, layout.VelocitiesVRAM1, layout.EdgeConnectionIndexes,
                    layout.EdgeConnections, layout.EdgeStrengths, layout.BlockMetadata, layout.BlockMiddles,
                layout.VelocitiesVRAM2
                );

                pos_rsrc_desc = new ResourceSetDescription(_positionComputeLayout,
                    _positionParamsBuffer, layout.PositionsVRAM1, layout.VelocitiesVRAM2, layout.BlockMetadata,
                   layout.PositionsVRAM2);
            }
            else
            {
                velocity_rsrc_desc = new ResourceSetDescription(_velocityComputeLayout,
                _velocityParamsBuffer, layout.PositionsVRAM2, layout.VelocitiesVRAM2, layout.EdgeConnectionIndexes,
                layout.EdgeConnections, layout.EdgeStrengths, layout.BlockMetadata, layout.BlockMiddles,
                layout.VelocitiesVRAM1
                );

                pos_rsrc_desc = new ResourceSetDescription(_positionComputeLayout,
                    _positionParamsBuffer, layout.PositionsVRAM2, layout.VelocitiesVRAM1, layout.BlockMetadata,
                    layout.PositionsVRAM1);
            }

            RenderVelocity(velocity_rsrc_desc, plot);
            RenderPosition(pos_rsrc_desc, plot, delta);   
        }




        private void RenderVelocity(ResourceSetDescription RSetDesc, PlottedGraph plot)
        {
            _timer.Restart();
            _cl.Begin();

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

            _cl.UpdateBuffer(_velocityParamsBuffer, 0, parameters);
            _cl.SetPipeline(_velocityComputePipeline);
            _cl.SetComputeResourceSet(0, resourceSet);

            //16 == sizeof(Vector4)
            _cl.Dispatch((uint)Math.Ceiling(layout.VelocitiesVRAM1!.SizeInBytes / (256.0 * 16)), 1, 1);
            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} done in {watch.ElapsedMilliseconds} MS", Logging.LogFilterType.BulkDebugLogFile);

            _cl.End();
            _timer.Stop();
            VelocitySetupTime = _timer.Elapsed.TotalMilliseconds;

            _timer.Restart();
            _gd!.SubmitCommands(_cl);
            _gd!.WaitForIdle();

            _gd.DisposeWhenIdle(resourceSet);

            _timer.Stop();
            VelocityTime = _timer.Elapsed.TotalMilliseconds;
        }


        /// <summary>
        /// Used the velocity buffer to move the nodes in the positions buffer
        /// </summary>
        /// <param name="cl">Thread-specific Veldrid command list to use</param>
        /// <param name="graph">PlottedGraph to compute</param>
        /// <param name="resources">Position shader resource set</param>
        /// <param name="delta">A float representing how much time has passed since the last frame. Higher values => bigger movements</param>
        private unsafe void RenderPosition(ResourceSetDescription RSetDesc, PlottedGraph plot, float delta)
        {
            _timer.Restart();
            _cl.Begin();

            ResourceSet resourceSet = _gd.ResourceFactory.CreateResourceSet(RSetDesc);
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, positions));
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, velocities));

            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderPosition  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            var textureSize = plot.LinearIndexTextureSize();

            PositionShaderParams parameters = new PositionShaderParams
            {
                delta = delta,
                NodesTexWidth = textureSize,
                blockNodeSeperation = 160,
                fixedInternalNodes = 1,
                activatingPreset = plot.LayoutState.ActivatingPreset
            };

            //Logging.WriteConsole($"POS Parambuffer Size is {(uint)Unsafe.SizeOf<PositionShaderParams>()}");

            _cl.UpdateBuffer(_positionParamsBuffer, 0, parameters);
            _cl.SetPipeline(_positionComputePipeline);
            _cl.SetComputeResourceSet(0, resourceSet);
            _cl.Dispatch((uint)Math.Ceiling(plot.LayoutState.PositionsVRAM1!.SizeInBytes / (256.0 * sizeof(Vector4))), 1, 1);
            _cl.End();
            _timer.Stop();
            PositionSetupTime = _timer.Elapsed.TotalMilliseconds;


            _timer.Restart();
            _gd!.SubmitCommands(_cl);
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
         * 
         */
        [StructLayout(LayoutKind.Sequential)]
        private struct PositionShaderParams
        {
            public float delta;
            public uint NodesTexWidth;
            public float blockNodeSeperation;
            public uint fixedInternalNodes;
            public bool activatingPreset;
            //must be multiple of 16
            private readonly uint _padding1;
            private readonly uint _padding3;
            private readonly bool _padding4;

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
            public int BlockIndex;
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
            List<int> blockMiddlesList = new List<int>();

            /*
             * Step 1: Build a list of active blocks (ie: blocks which currently have instructions in,
             * as opposed to blocks which have been split into new ones by control flow
             */
            List<int> activeBlockIDs = new();
            Dictionary<int, int> NodeBlockToBlockMetaIndex = new();
            Dictionary<int, int> BlockMetaToBlockFirstLastIndex = new();
            for (var i = 0; i < nodeCount; i++)
            {
                int nodeBlockID = (int)graph.NodeList[i].BlockID;
                if (NodeBlockToBlockMetaIndex.TryGetValue(nodeBlockID, out int metaBlockID) is false || activeBlockIDs.Contains(metaBlockID) is false)
                {
                    NodeBlockToBlockMetaIndex[nodeBlockID] = activeBlockIDs.Count;
                    BlockMetaToBlockFirstLastIndex[activeBlockIDs.Count] = nodeBlockID;
                    activeBlockIDs.Add(activeBlockIDs.Count);
                }
            }


            //Step 2: Build the list of block center nodes that the block velocity shader will run over
            blockMiddlesList.Capacity = activeBlockIDs.Count;
            foreach (int blockIdx in activeBlockIDs)
            {
                if (blockIdx == -1)
                {
                    blockMiddlesList.Add(-1);
                }

                int originalBlockIndex = BlockMetaToBlockFirstLastIndex[blockIdx];

                if (originalBlockIndex < 0 || originalBlockIndex >= graph.BlocksFirstLastNodeList.Count)
                {
                    continue;
                }

                var firstIdx_LastIdx = graph.BlocksFirstLastNodeList[originalBlockIndex];
                if (firstIdx_LastIdx == null)
                {
                    continue;
                }

                if (firstIdx_LastIdx.Item1 == firstIdx_LastIdx.Item2)
                {
                    if (blockMiddlesList.Contains((int)firstIdx_LastIdx.Item1)) continue;
                    blockMiddlesDict[blockIdx] = (int)firstIdx_LastIdx.Item1; //1 node block, top/mid/base is the same
                    blockMiddlesList.Add((int)firstIdx_LastIdx.Item1);
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
                        if (blockMiddlesList.Contains((int)centerNodeID)) continue;
                        blockMiddlesDict[blockIdx] = (int)centerNodeID;
                        blockMiddlesList.Add((int)centerNodeID);
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

                uint blockSize;
                int blockMid;
                int blockID;
                int offsetFromCenter = 0;
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

                    blockMid = blockMiddlesDict[blockID];

                    var blockEntry = graph.ProcessData.BasicBlocksList[(int)n.BlockID];
                    Debug.Assert(blockEntry is not null);
                    blockSize = (uint)blockEntry.Item2.Count;
                    int midIdx = (int)Math.Ceiling((blockEntry.Item2.Count - 1.0) / 2.0);
                    offsetFromCenter = n.BlockIndex - midIdx;
                }
                else
                {
                    externals += 1;
                    FirstLastIdx = new Tuple<uint, uint>(n.Index, n.Index);
                    blockMid = (int)n.Index;
                    blockSize = 1;
                    offsetFromCenter = 0;
                    blockMiddlesList.Add((int)n.Index);

                    //external nodes dont have a block id so just give them a unique one
                    //all that matters in the shader is it's unique
                    blockID = blockMiddlesList.Count;
                    blockMiddlesDict[blockID] = (int)n.Index;
                }


                int blockTopNodeIndex = -1;
                int blockBaseNodeIndex = -1;
                if (nodeIdx == blockMid || blockSize == 1)
                {
                    if (graph.GetNode(FirstLastIdx.Item1)?.IncomingNeighboursSet.Count > 0)
                    {
                        blockTopNodeIndex = (int)FirstLastIdx.Item1;
                    }

                    if (graph.GetNode(FirstLastIdx.Item2)?.OutgoingNeighboursSet.Count > 0)
                    {
                        blockBaseNodeIndex = (int)FirstLastIdx.Item2;
                    }
                }

                blockDataInts[nodeIdx].BlockIndex = blockID;
                blockDataInts[nodeIdx].OffsetFromCenter = offsetFromCenter;
                blockDataInts[nodeIdx].BlockTopEdgeList = blockTopNodeIndex;
                blockDataInts[nodeIdx].BlockBaseEdgeList = blockBaseNodeIndex != blockTopNodeIndex ? blockBaseNodeIndex : -1;
            }

            blockMiddles = blockMiddlesList.ToArray();
            blockData = blockDataInts;

            return true;
        }

    }
}
