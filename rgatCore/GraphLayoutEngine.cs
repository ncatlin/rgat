using ImGuiNET;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
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
        DeviceBuffer _PresetLayoutFinalPositionsBuffer, _edgesConnectionDataBuffer, _edgesConnectionDataOffsetsBuffer, _edgeStrengthDataBuffer, _blockDataBuffer;
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
            _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPresetPositionFloats(out _activatingPreset), _gd);
            _edgesConnectionDataOffsetsBuffer = CreateEdgesConnectionDataOffsetsBuffer();
            _edgesConnectionDataBuffer = CreateEdgesConnectionDataBuffer();
            _edgeStrengthDataBuffer = CreateEdgeStrengthDataBuffer();
            _blockDataBuffer = CreateBlockDataBuffer();
        }


        public void ChangePreset()
        {
            eGraphLayout graphStyle = _activeGraph.LayoutStyle;
            if (PlottedGraph.LayoutIsForceDirected(graphStyle))
            {
                _cachedVersions[_activeGraph] = 0;
                LoadCurrentGraphData();
            }
            else
            {
                _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPresetPositionFloats(out _activatingPreset), _gd);
                _activatingPreset = true;
            }
            _activeGraph.IncreaseTemperature(100f);
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
            uint floatCount = graph.ComputeBufferNodeCount * sizeof(float);
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
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            uint floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
            _activeGraph.UpdateNodeVelocities(destinationReadView, floatCount);
            _gd.Unmap(destinationReadback);
            destinationReadback.Dispose();
        }

        /// <summary>
        /// Iterates over the position of every node, translating it to a screen position
        /// Returns the offsets of the furthest nodes of the edges of the screen
        /// To fit the graph in the screen, each offset needs to be as close to be as small as possible without being smaller than 0
        /// </summary>
        /// <param name="graphWidgetSize">Size of the graph widget</param>
        /// <param name="xoffsets">xoffsets.X = distance of furthest left node from left of the widget. Ditto xoffsets.Y for right node/side</param>
        /// <param name="yoffsets">yoffsets.X = distance of furthest bottom node from base of the widget. Ditto yoffsets.Y for top node/side</param>
        public void GetScreenFitOffsets(Vector2 graphWidgetSize, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets)
        {

            float aspectRatio = graphWidgetSize.X / graphWidgetSize.Y;
            Matrix4x4 viewMatrix = _activeGraph.GetViewMatrix();
            Matrix4x4 projectionMatrix = _activeGraph.GetProjectionMatrix(aspectRatio);

            Vector2 xlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ylimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 zlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ev = new Vector2(0, 0);
            Vector2 xmin = ev, xmax = ev, ymin = ev, ymax = ev, zmin = ev, zmax = ev;
            int fZ1 = 0;
            int fZ2 = 0;

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, _activePositionsBuffer1);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);

            if (destinationReadView.Count < 4)
            {

                xoffsets = new Vector2(0, 0);
                yoffsets = new Vector2(0, 0);
                zoffsets = new Vector2(0, 0);

                return;
            }

            for (int idx = 0; idx < destinationReadView.Count; idx += 4)
            {
                if (destinationReadView[idx + 3] == -1) break;
                float x = destinationReadView[idx];
                float y = destinationReadView[idx + 1];
                float z = destinationReadView[idx + 2];
                Vector3 worldpos = new Vector3(x, y, z);


                Vector2 ndcPos = WorldToNDCPos(worldpos, viewMatrix, projectionMatrix);
                if (ndcPos.X < xlimits.X) { xlimits = new Vector2(ndcPos.X, xlimits.Y); xmin = ndcPos; }
                if (ndcPos.X > xlimits.Y) { xlimits = new Vector2(xlimits.X, ndcPos.X); xmax = ndcPos; }
                if (ndcPos.Y < ylimits.X) { ylimits = new Vector2(ndcPos.Y, ylimits.Y); ymin = ndcPos; }
                if (ndcPos.Y > ylimits.Y) { ylimits = new Vector2(ylimits.X, ndcPos.Y); ymax = ndcPos; }
                if (worldpos.Z < zlimits.X) { zlimits = new Vector2(worldpos.Z, zlimits.Y); zmin = ndcPos; fZ1 = (idx / 4); }
                if (worldpos.Z > zlimits.Y) { zlimits = new Vector2(zlimits.X, worldpos.Z); zmax = ndcPos; fZ2 = (idx / 4); }
            }

            Vector2 minxS = NdcToScreenPos(xmin, graphWidgetSize);
            Vector2 maxxS = NdcToScreenPos(xmax, graphWidgetSize);
            Vector2 minyS = NdcToScreenPos(ymin, graphWidgetSize);
            Vector2 maxyS = NdcToScreenPos(ymax, graphWidgetSize);
            xoffsets = new Vector2(minxS.X, graphWidgetSize.X - maxxS.X);
            yoffsets = new Vector2(minyS.Y, graphWidgetSize.Y - maxyS.Y);
            zoffsets = new Vector2(zlimits.X - _activeGraph.CameraZoom, zlimits.Y - _activeGraph.CameraZoom);

            _gd.Unmap(destinationReadback);
            destinationReadback.Dispose();
        }




        Vector2 WorldToNDCPos(Vector3 worldpos, Matrix4x4 viewMatriwx, Matrix4x4 projectionMatrix)
        {
            Vector3 translation = new Vector3(_activeGraph.CameraXOffset, _activeGraph.CameraYOffset, _activeGraph.CameraZoom);
            Matrix4x4 viewMatrixe = Matrix4x4.CreateTranslation(translation);
            Matrix4x4 rotation = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY,0);
            viewMatrixe = Matrix4x4.Multiply(viewMatrixe, rotation);

            Vector4 clipSpacePos = Vector4.Transform(Vector4.Transform(new Vector4(worldpos, 1.0f), viewMatrixe), projectionMatrix);
            Vector3 ndcSpacePos = Vector3.Divide(new Vector3(clipSpacePos.X, clipSpacePos.Y, clipSpacePos.Z), clipSpacePos.W);
            return new Vector2(ndcSpacePos.X, ndcSpacePos.Y);
        }

        Vector2 NdcToScreenPos(Vector2 ndcSpacePos, Vector2 graphWidgetSize)
        {
            return Vector2.Divide(new Vector2(ndcSpacePos.X + 1f, ndcSpacePos.Y + 1f), 2.0f) * graphWidgetSize;
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
            new ResourceLayoutElementDescription("edgeStrengths", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));

            _velocityParamsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<VelocityShaderParams>(), BufferUsage.UniformBuffer));

            ComputePipelineDescription VelocityCPD = new ComputePipelineDescription(_velocityShader, _velocityComputeLayout, 16, 16, 1);

            _velocityComputePipeline = _factory.CreateComputePipeline(VelocityCPD);

            _positionComputeLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
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
            _edgesConnectionDataOffsetsBuffer = CreateEdgesConnectionDataOffsetsBuffer();
            _edgeStrengthDataBuffer?.Dispose();
            _edgeStrengthDataBuffer = CreateEdgeStrengthDataBuffer();
            _blockDataBuffer = CreateBlockDataBuffer();
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
        public unsafe DeviceBuffer CreateEdgesConnectionDataOffsetsBuffer()
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
            PlottedGraph activeGraph = _activeGraph;
            if (activeGraph == null) return _factory.CreateBuffer(new BufferDescription(0, BufferUsage.StructuredBufferReadOnly, 4));

            int[] edgeDataInts = _activeGraph.GetEdgeDataInts();
            if (edgeDataInts.Length == 0) return _factory.CreateBuffer(new BufferDescription(0, BufferUsage.StructuredBufferReadOnly, 4));


            BufferDescription bd = new BufferDescription((uint)edgeDataInts.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, structureByteStride: 4);
            DeviceBuffer newBuffer = _factory.CreateBuffer(bd);


            fixed (int* dataPtr = edgeDataInts)
            {
                _gd.UpdateBuffer(newBuffer, 0, (IntPtr)dataPtr, (uint)edgeDataInts.Length * sizeof(int));
                _gd.WaitForIdle();
            }

            //PrintBufferArray(textureArray, "Created data texture:");
            return newBuffer;
        }



        public unsafe DeviceBuffer CreateEdgeStrengthDataBuffer()
        {

            var textureSize = _activeGraph != null ? _activeGraph.EdgeTextureWidth() : 0;
            DeviceBuffer newBuffer = null;
            if (textureSize > 0)
            {
                float[] attractions = _activeGraph.GetEdgeStrengthFloats();
                BufferDescription bd = new BufferDescription((uint)attractions.Length * sizeof(float), BufferUsage.StructuredBufferReadOnly, 4);
                newBuffer = _factory.CreateBuffer(bd);

                fixed (float* dataPtr = attractions)
                {
                    _gd.UpdateBuffer(newBuffer, 0, (IntPtr)dataPtr, (uint)attractions.Length * 4);
                    _gd.WaitForIdle();
                }
            }

            //PrintBufferArray(textureArray, "Created data texture:");
            return newBuffer;
        }


        public unsafe DeviceBuffer CreateBlockDataBuffer()
        {

            var textureSize = _activeGraph != null ? _activeGraph.EdgeTextureWidth() : 0;
            DeviceBuffer newBuffer = null;
            if (textureSize > 0)
            {
                int[] blockdats = _activeGraph.GetNodeBlockData();
                BufferDescription bd = new BufferDescription((uint)blockdats.Length * sizeof(float), BufferUsage.StructuredBufferReadOnly, 4);
                newBuffer = _factory.CreateBuffer(bd);

                fixed (int* dataPtr = blockdats)
                {
                    _gd.UpdateBuffer(newBuffer, 0, (IntPtr)dataPtr, (uint)blockdats.Length * 4);
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
            public uint EdgeCount;
            public uint fixedInternalNodes;

            private uint _padding1; //must be multiple of 16
            private uint _padding2; //must be multiple of 16
        }



        //todo : everything in here should be class variables defined once
        public unsafe void RenderVelocity(DeviceBuffer positions, DeviceBuffer velocities,
            DeviceBuffer destinationBuffer, float delta, float temperature)
        {

            var textureSize = _activeGraph.LinearIndexTextureSize();
            uint fixedNodes = 0;
            if (_activeGraph.LayoutStyle == eGraphLayout.eForceDirected3DBlocks) fixedNodes = 1;

            VelocityShaderParams parms = new VelocityShaderParams
            {
                delta = delta,
                k = 100.0f,
                temperature = temperature,
                NodesTexWidth = textureSize,
                EdgeCount = (uint)_activeGraph.internalProtoGraph.edgeList.Count,
                fixedInternalNodes = fixedNodes
            };
            _gd.UpdateBuffer(_velocityParamsBuffer, 0, parms);
            _gd.WaitForIdle();

            ResourceSet velocityComputeResourceSet = _factory.CreateResourceSet(
                new ResourceSetDescription(_velocityComputeLayout,
                _velocityParamsBuffer, positions, _PresetLayoutFinalPositionsBuffer, velocities, _edgesConnectionDataOffsetsBuffer,
                _edgesConnectionDataBuffer, _edgeStrengthDataBuffer, _blockDataBuffer, destinationBuffer));


            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.SetPipeline(_velocityComputePipeline);
            cl.SetComputeResourceSet(0, velocityComputeResourceSet);
            cl.Dispatch(textureSize, textureSize, 1); //todo, really?
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            //DebugPrintOutputFloatBuffer(destinationBuffer, "Velocity Computation Done. Result: ", 1500);


            if (_activatingPreset)
            {
                float highest = FindHighXYZ(textureSize, destinationBuffer, 0.005f);
                if (highest < 0.05)
                {
                    if (PlottedGraph.LayoutIsForceDirected(_activeGraph.LayoutStyle))
                    {
                        _activeGraph.InitBlankPresetLayout();
                        _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPresetPositionFloats(out bool f), _gd);
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
                if (Math.Abs(destinationReadView[index + 1]) > highest) highest = Math.Abs(destinationReadView[index + 1]);
                if (Math.Abs(destinationReadView[index + 2]) > highest) highest = Math.Abs(destinationReadView[index + 2]);
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
            public float blockNodeSeperation;
            public uint fixedInternalNodes;
            public bool activatingPreset;
            //must be multiple of 16
            private uint _padding1;
            private uint _padding3;
            private bool y;

        }


        //todo : everything in here should be class variables defined once
        public unsafe void RenderPosition(DeviceBuffer positions, DeviceBuffer velocities, DeviceBuffer output, float delta)
        {
            var textureSize = _activeGraph.LinearIndexTextureSize();

            uint width = textureSize;
            uint height = textureSize;

            uint fixedNodes = 0;
            if (_activeGraph.LayoutStyle == eGraphLayout.eForceDirected3DBlocks) fixedNodes = 1;
            PositionShaderParams parms = new PositionShaderParams
            {
                delta = delta,
                NodesTexWidth = textureSize,
                blockNodeSeperation = 60,
                fixedInternalNodes = fixedNodes,
                activatingPreset = _activatingPreset
            };

            //Console.WriteLine($"POS Parambuffer Size is {(uint)Unsafe.SizeOf<PositionShaderParams>()}");

            _gd.UpdateBuffer(_positionParamsBuffer, 0, parms);
            _gd.WaitForIdle();

            ResourceSet crs = _factory.CreateResourceSet(
                new ResourceSetDescription(_positionComputeLayout, _positionParamsBuffer, positions, velocities, _blockDataBuffer, output));

            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.SetPipeline(_positionComputePipeline);
            cl.SetComputeResourceSet(0, crs);
            cl.Dispatch(width, height, 1);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            //DebugPrintOutputFloatBuffer(output, "Position Computation Done. Result: ", 50);

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

        }


        public bool GetPositionsBuffer(PlottedGraph argGraph, out DeviceBuffer positionsBuf)
        {
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
            delta *= (_activatingPreset ? 7.5f : 1.0f); //without this the preset animation will 'bounce'


            _activeGraph.lastRenderTime = now;
            float _activeGraphTemperature = _activeGraph.temperature;
            if (_activeGraph.flipflop)
            {
                if (_activeGraphTemperature > 0.1)
                {
                    RenderVelocity(_activePositionsBuffer1, _activeVelocityBuffer1, _activeVelocityBuffer2, delta, _activeGraphTemperature);
                    RenderPosition(_activePositionsBuffer1, _activeVelocityBuffer1, _activePositionsBuffer2, delta);
                    _cachedVersions[_activeGraph]++;
                }
                RenderNodeAttribs(_activeNodeAttribBuffer1, _activeNodeAttribBuffer2, delta, mouseoverNodeID, useAnimAttribs);
            }
            else
            {

                if (_activeGraphTemperature > 0.1)
                {
                    RenderVelocity(_activePositionsBuffer2, _activeVelocityBuffer2, _activeVelocityBuffer1, delta, _activeGraphTemperature);
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


        void DebugPrintOutputFloatBuffer(DeviceBuffer buf, string message, int printCount)
        {
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, buf);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            float[] outputArray = new float[destinationReadView.Count];
            for (int index = 0; index < destinationReadView.Count; index++)
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
                Console.Write($"({sourceData[i]:f3},{sourceData[i + 1]:f3},{sourceData[i + 2]:f3},{sourceData[i + 3]:f3})");
            }
            Console.WriteLine();

        }

    }
}
