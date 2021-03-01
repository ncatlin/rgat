using ImGuiNET;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Veldrid;

namespace rgatCore
{
    class GraphLayoutEngine
    {

        public GraphLayoutEngine(GraphicsDevice gdev, ImGuiController controller)
        {
            _gd = gdev;
            _factory = gdev.ResourceFactory;
            _controller = controller;
        }
        GraphicsDevice _gd;
        ResourceFactory _factory;
        ImGuiController _controller;

        PlottedGraph _activeGraph;
        Pipeline _positionComputePipeline, _velocityComputePipeline, _nodeAttribComputePipeline;
        private Shader _positionShader, _velocityShader, _nodeAttribShader;

        DeviceBuffer _velocityParamsBuffer, _positionParamsBuffer, _attribsParamsBuffer;
        DeviceBuffer _PresetLayoutFinalPositionsBuffer, _edgesConnectionDataBuffer, _edgesConnectionDataOffsetsBuffer;
        DeviceBuffer _activePositionsBuffer1, _activePositionsBuffer2;
        DeviceBuffer _activeNodeAttribBuffer1, _activeNodeAttribBuffer2;
        DeviceBuffer _activeVelocityBuffer1, _activeVelocityBuffer2;

        Dictionary<PlottedGraph, Tuple<DeviceBuffer, DeviceBuffer>> _cachedPositionBuffers = new Dictionary<PlottedGraph, Tuple<DeviceBuffer, DeviceBuffer>>();
        Dictionary<PlottedGraph, Tuple<DeviceBuffer, DeviceBuffer>> _cachedNodeAttribBuffers = new Dictionary<PlottedGraph, Tuple<DeviceBuffer, DeviceBuffer>>();
        Dictionary<PlottedGraph, Tuple<DeviceBuffer, DeviceBuffer>> _cachedVelocityBuffers = new Dictionary<PlottedGraph, Tuple<DeviceBuffer, DeviceBuffer>>();
        Dictionary<PlottedGraph, ulong> _cachedVersions = new Dictionary<PlottedGraph, ulong>();

        ResourceLayout _velocityComputeLayout, _positionComputeLayout, _nodeAttribComputeLayout;

        ReaderWriterLock _computeLock = new ReaderWriterLock();

        public void Set_activeGraph(PlottedGraph newgraph)
        {
            if (newgraph == _activeGraph) return;

            //make sure the graph has the latest version of the data in case a different widget wants it
            if (_activeGraph != null)
            {
                StoreCurrentGraphData();
            }

            if (newgraph == null)
            {
                _computeLock.AcquireWriterLock(0);
                _activeGraph = null;
                _computeLock.ReleaseWriterLock();
                return;
            }

            _computeLock.AcquireWriterLock(0);
            _activeGraph = newgraph;
            LoadCurrentGraphData();
            _computeLock.ReleaseWriterLock();
        }


        //If graph buffers already stored in VRAM, load the reference
        //Otherwise, fill GPU buffers from stored data in the plottedgraph
        public void LoadCurrentGraphData()
        {
            ulong cachedVersion;
            if (_cachedVersions.TryGetValue(_activeGraph, out cachedVersion) && cachedVersion == _activeGraph.renderFrameVersion)
            {
                Tuple<DeviceBuffer, DeviceBuffer> bufs = _cachedVelocityBuffers[_activeGraph];
                _activeVelocityBuffer1 = bufs.Item1;
                _activeVelocityBuffer2 = bufs.Item2; 
                bufs = _cachedNodeAttribBuffers[_activeGraph];
                _activeNodeAttribBuffer1 = bufs.Item1;
                _activeNodeAttribBuffer2 = bufs.Item2; 
                bufs = _cachedPositionBuffers[_activeGraph];
                _activePositionsBuffer1 = bufs.Item1;
                _activePositionsBuffer2 = bufs.Item2;
            }
            else
            {
                InitComputeBuffersFrom_activeGraph();
                _cachedVersions[_activeGraph] = _activeGraph.renderFrameVersion;
            }

            //data which is always more uptodate in the graph
            //not sure it's worth cacheing
            _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPresetPositionFloats(), _gd);
            _edgesConnectionDataOffsetsBuffer = _CreateEdgesConnectionDataOffsetsBuffer();
            _edgesConnectionDataBuffer = CreateEdgesConnectionDataBuffer();
        }


        public void ChangePreset()
        {

            if (_activeGraph.LayoutStyle == eGraphLayout.eForceDirected3D)
            {
                _cachedVersions[_activeGraph] = 0;
                //_activeGraph.GetPresetPositionFloats();
                LoadCurrentGraphData();
            }
            else
            {
                _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPresetPositionFloats(), _gd);
            }
            _activeGraph.IncreaseTemperature(100f);
            _activatingPreset = true;
        }

        public void StoreCurrentGraphData()
        {
            lock (_activeGraph.RenderingLock)
            {
                ulong currentRenderVersion = _cachedVersions[_activeGraph];
                if (currentRenderVersion > _activeGraph.renderFrameVersion)
                {
                    StoreNodePositions(_activeGraph);
                    StoreNodeVelocity(_activeGraph);
                    _activeGraph.UpdateRenderFrameVersion(currentRenderVersion);
                }
            }
        }

        public void StoreGraphData(PlottedGraph graph)
        {
            if (_cachedVersions.ContainsKey(graph))
            {
                ulong currentRenderVersion = _cachedVersions[graph];
                if (currentRenderVersion > graph.renderFrameVersion)
                {
                    StoreNodePositions(graph);
                    StoreNodeVelocity(graph);
                    graph.UpdateRenderFrameVersion(currentRenderVersion);
                }
            }
        }


        //read node positions from the GPU and store in provided plottedgraph
        public void StoreNodePositions(PlottedGraph graph)
        {
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, _activePositionsBuffer1);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            uint floatCount = graph.ComputeBufferNodeCount*sizeof(float);
            if (floatCount > 0)
            { 
                graph.UpdateNodePositions(destinationReadView, floatCount); 
            }
            _gd.Unmap(destinationReadback);
            destinationReadback.Dispose();
        }


        //read node velocities from the GPU and store in provided plottedgraph
        public void StoreNodeVelocity(PlottedGraph graph)
        {
            uint textureSize = graph.LinearIndexTextureSize();
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, _activeVelocityBuffer1);
            MappedResourceView<float>  destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            uint floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
            _activeGraph.UpdateNodeVelocities(destinationReadView, floatCount);
            _gd.Unmap(destinationReadback);
            destinationReadback.Dispose();
        }


        //todo - only dispose and recreate if too small
        void InitComputeBuffersFrom_activeGraph()
        {
            _activeVelocityBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetVelocityFloats(), _gd);
            _activeVelocityBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _activeVelocityBuffer1.SizeInBytes, Usage = _activeVelocityBuffer1.Usage, StructureByteStride = 4 });
            _cachedVelocityBuffers[_activeGraph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeVelocityBuffer1, _activeVelocityBuffer2);

            _activePositionsBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPositionFloats(), _gd);
            _activePositionsBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _activePositionsBuffer1.SizeInBytes, Usage = _activePositionsBuffer1.Usage, StructureByteStride = 4 });
            _cachedPositionBuffers[_activeGraph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activePositionsBuffer1, _activePositionsBuffer2);

            _activeNodeAttribBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetNodeAttribFloats(), _gd);
            _activeNodeAttribBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _activeNodeAttribBuffer1.SizeInBytes, Usage = _activeNodeAttribBuffer1.Usage, StructureByteStride = 4 });
            _cachedNodeAttribBuffers[_activeGraph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeNodeAttribBuffer1, _activeNodeAttribBuffer2);

            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.CopyBuffer(_activeVelocityBuffer1, 0, _activeVelocityBuffer2, 0, _activeVelocityBuffer1.SizeInBytes);
            cl.CopyBuffer(_activePositionsBuffer1, 0, _activePositionsBuffer2, 0, _activePositionsBuffer1.SizeInBytes);
            cl.CopyBuffer(_activeNodeAttribBuffer1, 0, _activeNodeAttribBuffer2, 0, _activeNodeAttribBuffer1.SizeInBytes);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
        }


        public unsafe void SetupComputeResources()
        {
            if (!_gd.Features.ComputeShader) { Console.WriteLine("Error: No computeshader feature"); return; }

            byte[] velocityShaderBytes = _controller.LoadEmbeddedShaderCode(_factory, "sim-velocity", ShaderStages.Fragment);
            _velocityShader = _factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, velocityShaderBytes, "FS"));

            _velocityComputeLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("layoutPositions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));

            _velocityParamsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<VelocityShaderParams>(), BufferUsage.UniformBuffer));

            ComputePipelineDescription VelocityCPD = new ComputePipelineDescription(_velocityShader, _velocityComputeLayout, 16, 16, 1);

            _velocityComputePipeline = _factory.CreateComputePipeline(VelocityCPD);

            _positionComputeLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));


            byte[] positionShaderBytes = _controller.LoadEmbeddedShaderCode(_factory, "sim-position", ShaderStages.Vertex);
            _positionShader = _factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, positionShaderBytes, "FS"));

            ComputePipelineDescription PositionCPD = new ComputePipelineDescription(_positionShader, _positionComputeLayout, 16, 16, 1);
            _positionComputePipeline = _factory.CreateComputePipeline(PositionCPD);
            _positionParamsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<PositionShaderParams>(), BufferUsage.UniformBuffer));



            byte[] noteattribShaderBytes = _controller.LoadEmbeddedShaderCode(_factory, "sim-nodeAttrib", ShaderStages.Vertex);
            _nodeAttribShader = _factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, noteattribShaderBytes, "FS"));

            _nodeAttribComputeLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("nodeAttrib", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));
            _attribsParamsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<AttribShaderParams>(), BufferUsage.UniformBuffer));



            ComputePipelineDescription attribCPL = new ComputePipelineDescription(_nodeAttribShader, _nodeAttribComputeLayout, 16, 16, 1);

            _nodeAttribComputePipeline = _factory.CreateComputePipeline(attribCPL);
        }


        unsafe void AddNewNodesToComputeBuffers(int finalCount)
        {

            uint newNodeCount = (uint)finalCount - _activeGraph.ComputeBufferNodeCount;
            if (newNodeCount == 0) return;

            float[] newPositions = _activeGraph.GetPositionFloats();
            float[] newVelocities = _activeGraph.GetVelocityFloats();
            float[] newAttribs = _activeGraph.GetNodeAttribFloats();

            uint offset = _activeGraph.ComputeBufferNodeCount * 4 * sizeof(float);
            uint updateSize = 4 * sizeof(float) * newNodeCount;

            if ((offset + updateSize) > _activeVelocityBuffer1.SizeInBytes)
            {
                var bufferWidth = _activeGraph.NestedIndexTextureSize();
                var bufferFloatCount = bufferWidth * bufferWidth * 4;
                var bufferSize = bufferFloatCount * sizeof(float);
                Debug.Assert(bufferSize >= updateSize);

                Console.WriteLine($"Recreating buffers as {bufferSize} > {_activeVelocityBuffer1.SizeInBytes}");
                resizeComputeBuffers(bufferSize);
            }


            uint floatOffset = _activeGraph.ComputeBufferNodeCount * 4;
            fixed (float* dataPtr = newPositions)
            {
                _gd.UpdateBuffer(_activePositionsBuffer1, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
                _gd.UpdateBuffer(_activePositionsBuffer2, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
            }

            fixed (float* dataPtr = newVelocities)
            {
                _gd.UpdateBuffer(_activeVelocityBuffer1, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
                _gd.UpdateBuffer(_activeVelocityBuffer2, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
            }

            fixed (float* dataPtr = newAttribs)
            {
                _gd.UpdateBuffer(_activeNodeAttribBuffer1, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
                _gd.UpdateBuffer(_activeNodeAttribBuffer2, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
            }
        }


        void RegenerateEdgeDataBuffers()
        {
            _edgesConnectionDataBuffer?.Dispose();
            _edgesConnectionDataBuffer = CreateEdgesConnectionDataBuffer();
            _edgesConnectionDataOffsetsBuffer?.Dispose();
            _edgesConnectionDataOffsetsBuffer = _CreateEdgesConnectionDataOffsetsBuffer();
        }


        void resizeComputeBuffers(uint bufferSize)
        {
            BufferDescription bd = new BufferDescription(bufferSize, BufferUsage.StructuredBufferReadWrite, 4);
            DeviceBuffer velocityBuffer1B = _factory.CreateBuffer(bd);
            DeviceBuffer positionsBuffer1B = _factory.CreateBuffer(bd);
            DeviceBuffer velocityBuffer2B = _factory.CreateBuffer(bd);
            DeviceBuffer positionsBuffer2B = _factory.CreateBuffer(bd);
            DeviceBuffer attribsBuffer1B = _factory.CreateBuffer(bd);
            DeviceBuffer attribsBuffer2B = _factory.CreateBuffer(bd);


            CommandList cl = _factory.CreateCommandList();
            cl.Begin();

            cl.CopyBuffer(_activeVelocityBuffer1, 0, velocityBuffer1B, 0, _activeVelocityBuffer1.SizeInBytes);
            cl.CopyBuffer(_activeVelocityBuffer2, 0, velocityBuffer2B, 0, _activeVelocityBuffer1.SizeInBytes);
            cl.CopyBuffer(_activePositionsBuffer1, 0, positionsBuffer1B, 0, _activePositionsBuffer1.SizeInBytes);
            cl.CopyBuffer(_activePositionsBuffer2, 0, positionsBuffer2B, 0, _activePositionsBuffer1.SizeInBytes);
            cl.CopyBuffer(_activeNodeAttribBuffer1, 0, attribsBuffer1B, 0, _activeNodeAttribBuffer1.SizeInBytes);
            cl.CopyBuffer(_activeNodeAttribBuffer2, 0, attribsBuffer2B, 0, _activeNodeAttribBuffer1.SizeInBytes);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            cl.Dispose();

            _activeVelocityBuffer1.Dispose(); _activeVelocityBuffer1 = velocityBuffer1B;
            _activeVelocityBuffer2.Dispose(); _activeVelocityBuffer2 = velocityBuffer2B;
            _cachedVelocityBuffers[_activeGraph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeVelocityBuffer1, _activeVelocityBuffer2);
            _activePositionsBuffer1.Dispose(); _activePositionsBuffer1 = positionsBuffer1B;
            _activePositionsBuffer2.Dispose(); _activePositionsBuffer2 = positionsBuffer2B;
            _cachedPositionBuffers[_activeGraph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activePositionsBuffer1, _activePositionsBuffer2);
            _activeNodeAttribBuffer1.Dispose(); _activeNodeAttribBuffer1 = attribsBuffer1B;
            _activeNodeAttribBuffer2.Dispose(); _activeNodeAttribBuffer2 = attribsBuffer2B;
            _cachedNodeAttribBuffers[_activeGraph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeNodeAttribBuffer1, _activeNodeAttribBuffer2);
        }


        //Texture describes how many nodes each node is linked to
        public unsafe DeviceBuffer _CreateEdgesConnectionDataOffsetsBuffer()
        {
            int[] targetArray = _activeGraph.GetNodeNeighbourDataOffsets();
            uint textureSize = PlottedGraph.indexTextureSize(targetArray.Length);
            uint intCount = textureSize * textureSize;
            BufferDescription bd = new BufferDescription(intCount * sizeof(int), BufferUsage.StructuredBufferReadWrite, 1);
            DeviceBuffer newBuffer = _factory.CreateBuffer(bd);

            fixed (int* dataPtr = targetArray)
            {
                _gd.UpdateBuffer(newBuffer, 0, (IntPtr)(dataPtr), intCount * sizeof(int));
                _gd.WaitForIdle();
            }

            return newBuffer;
        }


        public unsafe DeviceBuffer CreateEdgesConnectionDataBuffer()
        {
            var textureSize = _activeGraph != null ? _activeGraph.LinearIndexTextureSize() : 0;
            BufferDescription bd = new BufferDescription(textureSize * textureSize * 4 * sizeof(int), BufferUsage.StructuredBufferReadOnly, 4);
            DeviceBuffer newBuffer = _factory.CreateBuffer(bd);

            if (textureSize > 0)
            {
                int[] edgeDataInts = _activeGraph.GetEdgeDataInts();
                fixed (int* dataPtr = edgeDataInts)
                {
                    _gd.UpdateBuffer(newBuffer, 0, (IntPtr)dataPtr, textureSize * textureSize * 16);
                    _gd.WaitForIdle();
                }
            }

            //PrintBufferArray(textureArray, "Created data texture:");
            return newBuffer;
        }



        /*
         * 
         * Velocity computation shader assigns a velocity to each node based on nearby nodes, edges
         * or preset target positions
         * 
         */
        [StructLayout(LayoutKind.Sequential)]
        struct VelocityShaderParams
        {
            public float delta;
            public float k;
            public float temperature;
            public uint NodesTexWidth;
            public uint EdgesTexWidth;

            private uint _padding1; //must be multiple of 16
            private uint _padding2; //must be multiple of 16
            private uint _padding3; //must be multiple of 16
        }



        //todo : everything in here should be class variables defined once
        public unsafe void RenderVelocity(DeviceBuffer positions, DeviceBuffer velocities,
            DeviceBuffer destinationBuffer, float delta, float temperature)
        {

            var textureSize = _activeGraph.LinearIndexTextureSize();
            VelocityShaderParams parms = new VelocityShaderParams
            {
                delta = delta,
                k = 100.0f,
                temperature = temperature,
                NodesTexWidth = textureSize,
                EdgesTexWidth = _activeGraph.EdgeTextureWidth()
            };
            _gd.UpdateBuffer(_velocityParamsBuffer, 0, parms);
            _gd.WaitForIdle();

            ResourceSet velocityComputeResourceSet = _factory.CreateResourceSet(
                new ResourceSetDescription(_velocityComputeLayout,
                _velocityParamsBuffer, positions, _PresetLayoutFinalPositionsBuffer, velocities, _edgesConnectionDataOffsetsBuffer, _edgesConnectionDataBuffer, 
                destinationBuffer));


            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.SetPipeline(_velocityComputePipeline);
            cl.SetComputeResourceSet(0, velocityComputeResourceSet);
            cl.Dispatch(textureSize, textureSize, 1); //todo, really?
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            if ( _activatingPreset)
            {
                //DebugPrintOutputFloatBuffer((int)textureSize, destinationBuffer, "Velocity Computation Done. Result: ", 150);
                float highest = FindHighXYZ(textureSize, destinationBuffer, 0.005f);
                if (highest < 0.05)
                { 
                    if (_activeGraph.LayoutStyle == eGraphLayout.eForceDirected3D)
                    {
                        _activeGraph.InitBlankPresetLayout();
                        _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPresetPositionFloats(), _gd);
                    }
                    _activatingPreset = false;
                }
            }
            


            velocityComputeResourceSet.Dispose();
            cl.Dispose();
        }

        public bool ActivatingPreset => _activatingPreset == true;

        /// <summary>
        /// See if any velocities in a velocity texture are below maxLimit
        /// </summary>
        /// <param name="textureSize"></param>
        /// <param name="buf"></param>
        /// <param name="maxLimit"></param>
        /// <returns></returns>
        float FindHighXYZ(uint textureSize, DeviceBuffer buf, float maxLimit)
        {
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, buf);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            float highest = 0f;
            for (uint index = 0; index < textureSize * textureSize * 4; index += 4)
            {
                if (index >= destinationReadView.Count) break;
                if (destinationReadView[index + 3] != 1.0f) break; //past end of nodes
                if (Math.Abs(destinationReadView[index]) > highest) highest = Math.Abs(destinationReadView[index]);
                if (Math.Abs(destinationReadView[index+1]) > highest) highest = Math.Abs(destinationReadView[index+1]);
                if (Math.Abs(destinationReadView[index+2]) > highest) highest = Math.Abs(destinationReadView[index+2]);
            }
            destinationReadback.Dispose();
            return highest;
        }


        /*
         * 
         * Position computation shader moves each node according to its velocity
         * 
         */
        [StructLayout(LayoutKind.Sequential)]
        struct PositionShaderParams
        {
            public float delta;
            public uint NodesTexWidth;

            private uint _padding1; //must be multiple of 16
            private uint _padding2;
        }


        //todo : everything in here should be class variables defined once
        public unsafe void RenderPosition(DeviceBuffer positions, DeviceBuffer velocities, DeviceBuffer output, float delta)
        {
            var textureSize = _activeGraph.LinearIndexTextureSize();

            uint width = textureSize;
            uint height = textureSize;

            PositionShaderParams parms = new PositionShaderParams
            {
                delta = delta,
                NodesTexWidth = textureSize
            };

            //Console.WriteLine($"POS Parambuffer Size is {(uint)Unsafe.SizeOf<PositionShaderParams>()}");

            _gd.UpdateBuffer(_positionParamsBuffer, 0, parms);
            _gd.WaitForIdle();

            ResourceSet crs = _factory.CreateResourceSet(
                new ResourceSetDescription(_positionComputeLayout, _positionParamsBuffer, positions, velocities, output));

            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.SetPipeline(_positionComputePipeline);
            cl.SetComputeResourceSet(0, crs);
            cl.Dispatch(width, height, 1);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            //DebugPrintOutputFloatBuffer((int)textureSize, output, "Position Computation Done. Result: ", 32);

            cl.Dispose();
            crs.Dispose();
        }


        /*
         * 
         * Node attribute shader does a few cosmetic things to nodes (alpha, size) for highlighting and animation
         * 
         */
        [StructLayout(LayoutKind.Sequential)]
        struct AttribShaderParams
        {
            public float delta;            // requestAnimationFrame delta
            public int selectedNode;     // selectedNode
            public float hoverMode;     // selectedNode
            public int nodesTexWidth;     // will be the same for neighbors

            public int edgesTexWidth;     // neighbor data
            public bool isAnimated;
            private uint _padding2b;
            private uint _padding2c;
        }

        public unsafe void RenderNodeAttribs(DeviceBuffer attribBufIn, DeviceBuffer attribBufOut, float delta, int mouseoverNodeID, bool useAnimAttribs)
        {
            uint textureSize = _activeGraph.LinearIndexTextureSize();
            AttribShaderParams parms = new AttribShaderParams
            {
                delta = delta,
                selectedNode = mouseoverNodeID,
                edgesTexWidth = (int)textureSize,
                nodesTexWidth = (int)textureSize,
                hoverMode = 1,
                isAnimated = useAnimAttribs
            };
            _gd.UpdateBuffer(_attribsParamsBuffer, 0, parms);
            _gd.WaitForIdle();


            CommandList cl = _factory.CreateCommandList();

            _activeGraph.GetActiveNodeIDs(out List<uint> pulseNodes, out List<uint> lingerNodes, out uint[] deactivatedNodes);

            cl.Begin();
            float[] valArray = new float[3];
            foreach (uint idx in pulseNodes)
            {
                if (idx >= _activeGraph.RenderedNodeCount()) break;
                if (attribBufIn.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;

                valArray[0] = 300f; //start big
                valArray[1] = 1.0f; //full alpha
                valArray[2] = 1.0f; //pulse
                fixed (float* dataPtr = valArray)
                {
                    cl.UpdateBuffer(attribBufIn, idx * 4 * sizeof(float), (IntPtr)dataPtr, (uint)valArray.Length * sizeof(float));
                }
            }

            float currentPulseAlpha = Math.Max(GlobalConfig.AnimatedFadeMinimumAlpha, GraphicsMaths.getPulseAlpha());
            foreach (uint idx in lingerNodes)
            {
                if (idx >= _activeGraph.RenderedNodeCount()) break;
                if (attribBufIn.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;

                valArray[0] = 2.0f + currentPulseAlpha;
                fixed (float* dataPtr = valArray)
                {
                    cl.UpdateBuffer(attribBufIn, idx * 4 * sizeof(float) + (2 * sizeof(float)), (IntPtr)dataPtr, sizeof(float));
                }
            }

            foreach (uint idx in deactivatedNodes)
            {
                if (idx >= _activeGraph.RenderedNodeCount()) break;
                if (attribBufIn.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;
                valArray[0] = 0.8f;
                fixed (float* dataPtr = valArray)
                {
                    cl.UpdateBuffer(attribBufIn, idx * 4 * sizeof(float) + (2 * sizeof(float)), (IntPtr)dataPtr, sizeof(float));
                }
            }

            cl.End();
            _gd.SubmitCommands(cl);


            ResourceSet attribComputeResourceSet = _factory.CreateResourceSet(new ResourceSetDescription(_nodeAttribComputeLayout,
                _attribsParamsBuffer, attribBufIn, _edgesConnectionDataOffsetsBuffer, _edgesConnectionDataBuffer, attribBufOut));

            cl.Begin();
            cl.SetPipeline(_nodeAttribComputePipeline);
            cl.SetComputeResourceSet(0, attribComputeResourceSet);
            cl.Dispatch(textureSize, textureSize, 1);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            //DebugPrintOutputFloatBuffer((int)textureSize, attribBufOut, "attrib Computation Done. Result: ", 32);

            cl.Dispose();
            attribComputeResourceSet.Dispose();
        }


        //recreate node attributes with default state
        //useful for ending an animation sequence
        public void ResetNodeAttributes(PlottedGraph argGraph)
        {
            uint bufferWidth = _activeGraph.LinearIndexTextureSize();
            float[] storedAttributes = _activeGraph.GetNodeAttribFloats();

            _activeNodeAttribBuffer1?.Dispose();
            _activeNodeAttribBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(storedAttributes, _gd);
            _activeNodeAttribBuffer2?.Dispose();
            _activeNodeAttribBuffer2 = _factory.CreateBuffer(
                new BufferDescription
                {
                    SizeInBytes = _activeNodeAttribBuffer1.SizeInBytes,
                    Usage = _activeNodeAttribBuffer1.Usage,
                    StructureByteStride = 4
                });
            _cachedNodeAttribBuffers[_activeGraph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeNodeAttribBuffer1, _activeNodeAttribBuffer2);
            _activeGraph.flipflop = true; //process attribs buffer 1 first into buffer 2

            /*
            _crs_nodesEdges.Dispose();
            _crs_nodesEdges = _factory.CreateResourceSet(
                new ResourceSetDescription(_nodesEdgesRsrclayout, _activeNodeAttribBuffer1, _NodeCircleSpritetview));
            flipflop = true; 
            */
        }


        public bool GetPositionsBuffer(PlottedGraph argGraph, out DeviceBuffer positionsBuf) {
            Tuple<DeviceBuffer, DeviceBuffer> result;
            if (_cachedVersions.TryGetValue(argGraph, out ulong storedVersion) && storedVersion < argGraph.renderFrameVersion)
            {
                positionsBuf = null;
                return false;
            }    
            if (_cachedPositionBuffers.TryGetValue(key: argGraph, out result))
            { 
                positionsBuf = result.Item1;
                return true;
            }
            positionsBuf = null;
            return false;
        }


        public bool GetNodeAttribsBuffer(PlottedGraph argGraph, out DeviceBuffer attribBuf)
        {
            Tuple<DeviceBuffer, DeviceBuffer> result; 
            if (_cachedVersions.TryGetValue(argGraph, out ulong storedVersion) && storedVersion < argGraph.renderFrameVersion)
            {
                attribBuf = null;
                return false;
            }
            if (_cachedNodeAttribBuffers.TryGetValue(key: argGraph, out result))
            {
                attribBuf = result.Item1;
                return true;
            }
            attribBuf = null;
            return false;
        }

        bool _activatingPreset = false;
        public ulong Compute(uint drawnEdgeCount, int mouseoverNodeID, bool useAnimAttribs)
        {
            Debug.Assert(_activeGraph != null, "Layout engine called to compute without active graph");
            if (_velocityShader == null)
            {
                SetupComputeResources();
            }

            if (drawnEdgeCount > _activeGraph.RenderedEdgeCount)
            {
                RegenerateEdgeDataBuffers();
                _activeGraph.RenderedEdgeCount = drawnEdgeCount;
            }

            int graphNodeCount = _activeGraph.RenderedNodeCount();
            if (_activeGraph.ComputeBufferNodeCount < graphNodeCount)
            {
                AddNewNodesToComputeBuffers(graphNodeCount);
                _activeGraph.ComputeBufferNodeCount = (uint)graphNodeCount;
            }


            var now = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
            float delta = Math.Min((now - _activeGraph.lastRenderTime) / 1000f, 1.0f);// safety cap on large deltas

            if (_activatingPreset)
            {
                delta *= 7.5f;
            }

            _activeGraph.lastRenderTime = now;
            float _activeGraphTemperature = _activeGraph.temperature;
            if (_activeGraph.flipflop)
            {
                if (_activeGraphTemperature > 0.1)
                {
                    RenderVelocity(_activePositionsBuffer1, _activeVelocityBuffer1, _activeVelocityBuffer2, delta, false ? 250.0f : _activeGraphTemperature);
                    RenderPosition(_activePositionsBuffer1, _activeVelocityBuffer1, _activePositionsBuffer2, delta);
                    _cachedVersions[_activeGraph]++;
                }
                RenderNodeAttribs(_activeNodeAttribBuffer1, _activeNodeAttribBuffer2, delta, mouseoverNodeID, useAnimAttribs);
            }
            else
            {

                if (_activeGraphTemperature > 0.1)
                {
                    RenderVelocity(_activePositionsBuffer2, _activeVelocityBuffer2, _activeVelocityBuffer1, delta, false ? 250.0f : _activeGraphTemperature);
                    RenderPosition(_activePositionsBuffer2, _activeVelocityBuffer1, _activePositionsBuffer1, delta);
                    _cachedVersions[_activeGraph]++;
                }
                RenderNodeAttribs(_activeNodeAttribBuffer2, _activeNodeAttribBuffer1, delta, mouseoverNodeID, useAnimAttribs);
            }

            _activeGraph.flipflop = !_activeGraph.flipflop;
            if (_activeGraphTemperature > 0.1)
                _activeGraph.temperature *= 0.99f;
            else
                _activeGraph.temperature = 0;

            return _cachedVersions[_activeGraph];
        }


        void DebugPrintOutputFloatBuffer(int textureSize, DeviceBuffer buf, string message, int printCount)
        {
            float[] outputArray = new float[textureSize * textureSize * 4];
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, buf);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            for (int index = 0; index < textureSize * textureSize * 4; index++)
            {
                if (index >= destinationReadView.Count) break;
                outputArray[index] = destinationReadView[index];
            }
            destinationReadback.Dispose();
            PrintBufferArray(outputArray, message, printCount);
        }


        static void PrintBufferArray<T>(T[] sourceData, string premsg, int limit = 0)
        {
            Console.WriteLine(premsg);
            for (var i = 0; i < sourceData.Length; i += 4)
            {
                if (limit > 0 && i > limit) break;
                if (i != 0 && (i % 8 == 0))
                    Console.WriteLine();
                Console.Write($"({sourceData[i]:f3},{sourceData[i + 1]:f3},{sourceData[i + 2]:f3},{sourceData[i + 3]}:f3)");
            }
            Console.WriteLine();

        }

    }
}
