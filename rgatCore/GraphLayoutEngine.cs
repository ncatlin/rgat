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
        DeviceBuffer _positionsBuffer1, _positionsBuffer2;
        DeviceBuffer _rtNodeAttribBuffer1, _rtNodeAttribBuffer2;
        DeviceBuffer _velocityBuffer1, _velocityBuffer2;

        ResourceLayout _velocityComputeLayout, _positionComputeLayout, _nodeAttribComputeLayout;

        ReaderWriterLock _computeLock = new ReaderWriterLock();

        public void Set_activeGraph(PlottedGraph graph)
        {
            if (graph == _activeGraph) return;

            if (graph == null)
            {
                _computeLock.AcquireWriterLock(0);
                _activeGraph = null;
                _computeLock.ReleaseWriterLock();
                return;
            }
            else
            {
                if (_activeGraph != null)
                {

                    StoreNodePositions(_activeGraph);

                    if (_activeGraph.temperature > 0.1)
                    {
                        StoreNodeVelocity(_activeGraph);
                    }
                }
            }


            //todo - is this still needed? do we need to store multiple graphs in GPU ram at once? 
            //i think not since rendering is so fast now
            //store old positions/verts floats in graph when switching
            /*
            if (!graphBufferDict.TryGetValue(graph, out graphBuffers))
            {
                graphBuffers = new VeldridGraphBuffers();
                graphBufferDict.Add(graph, graphBuffers);
                //graph.UpdateGraphicBuffers(graphWidgetSize, _gd);
                //graphBuffers.InitPipelines(_gd, CreateGraphShaders(), graph._outputFramebuffer, true);
            }
            */

            _computeLock.AcquireWriterLock(0);
            _activeGraph = graph;
            InitComputeBuffersFrom_activeGraph();
            _computeLock.ReleaseWriterLock();
        }

        public void StoreNodePositions(PlottedGraph graph)
        {
            if (!graph.UpdatedNodePositions) return;
            uint textureSize = graph.LinearIndexTextureSize();
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, _positionsBuffer1);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            uint floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
            if (floatCount > 0)
            { 
                graph.UpdateNodePositions(destinationReadView, floatCount); 
            }
            _gd.Unmap(destinationReadback);
            destinationReadback.Dispose();

            graph.UpdatedNodePositions = false;
        }

        public void StoreNodeVelocity(PlottedGraph graph)
        {
            uint textureSize = graph.LinearIndexTextureSize();
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, _velocityBuffer1);
            MappedResourceView<float>  destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            uint floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
            _activeGraph.UpdateNodeVelocities(destinationReadView, floatCount);
            _gd.Unmap(destinationReadback);
            destinationReadback.Dispose();
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


        void InitComputeBuffersFrom_activeGraph()
        {
            if (_velocityBuffer1 != null)
            {
                _velocityBuffer1.Dispose();
                _velocityBuffer2.Dispose();
                _positionsBuffer1.Dispose();
                _positionsBuffer2.Dispose();
                _rtNodeAttribBuffer1.Dispose();
                _rtNodeAttribBuffer2.Dispose();
                _PresetLayoutFinalPositionsBuffer.Dispose();
                _edgesConnectionDataOffsetsBuffer.Dispose();
                _edgesConnectionDataBuffer.Dispose();
            }

            _velocityBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetVelocityFloats(), _gd);
            _velocityBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _velocityBuffer1.SizeInBytes, Usage = _velocityBuffer1.Usage, StructureByteStride = 4 });
            _positionsBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPositionFloats(), _gd);
            _positionsBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _positionsBuffer1.SizeInBytes, Usage = _positionsBuffer1.Usage, StructureByteStride = 4 });
            _rtNodeAttribBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetNodeAttribFloats(), _gd);
            _rtNodeAttribBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _rtNodeAttribBuffer1.SizeInBytes, Usage = _rtNodeAttribBuffer1.Usage, StructureByteStride = 4 });

            _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(_activeGraph.GetPresetPositionFloats(), _gd); //todo: actually empty
            _edgesConnectionDataOffsetsBuffer = _CreateEdgesConnectionDataOffsetsBuffer();
            _edgesConnectionDataBuffer = CreateEdgesConnectionDataBuffer();


            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.CopyBuffer(_velocityBuffer1, 0, _velocityBuffer2, 0, _velocityBuffer1.SizeInBytes);
            cl.CopyBuffer(_positionsBuffer1, 0, _positionsBuffer2, 0, _positionsBuffer1.SizeInBytes);
            cl.CopyBuffer(_rtNodeAttribBuffer1, 0, _rtNodeAttribBuffer2, 0, _rtNodeAttribBuffer1.SizeInBytes);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
        }



        unsafe void AddNewNodesToComputeBuffers(int finalCount)
        {

            uint newNodeCount = (uint)finalCount - _activeGraph.RenderedNodeCount;
            if (newNodeCount == 0) return;

            float[] newPositions = _activeGraph.GetPositionFloats();
            float[] newVelocities = _activeGraph.GetVelocityFloats();
            float[] newAttribs = _activeGraph.GetNodeAttribFloats();

            uint offset = _activeGraph.RenderedNodeCount * 4 * sizeof(float);
            uint updateSize = 4 * sizeof(float) * newNodeCount;

            if ((offset + updateSize) > _velocityBuffer1.SizeInBytes)
            {
                var bufferWidth = _activeGraph.NestedIndexTextureSize();
                var bufferFloatCount = bufferWidth * bufferWidth * 4;
                var bufferSize = bufferFloatCount * sizeof(float);
                Debug.Assert(bufferSize >= updateSize);

                Console.WriteLine($"Recreating buffers as {bufferSize} > {_velocityBuffer1.SizeInBytes}");
                recreateComputeBuffers(bufferSize);
            }


            uint floatOffset = _activeGraph.RenderedNodeCount * 4;
            fixed (float* dataPtr = newPositions)
            {
                _gd.UpdateBuffer(_positionsBuffer1, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
                _gd.UpdateBuffer(_positionsBuffer2, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
            }

            fixed (float* dataPtr = newVelocities)
            {
                _gd.UpdateBuffer(_velocityBuffer1, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
                _gd.UpdateBuffer(_velocityBuffer2, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
            }

            fixed (float* dataPtr = newAttribs)
            {
                _gd.UpdateBuffer(_rtNodeAttribBuffer1, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
                _gd.UpdateBuffer(_rtNodeAttribBuffer2, offset, (IntPtr)(dataPtr + floatOffset), updateSize);
            }
        }


        void RegenerateEdgeDataBuffers()
        {
            Console.WriteLine("===RegenerateEdgeDataBuffers===");


            _edgesConnectionDataBuffer.Dispose();
            _edgesConnectionDataBuffer = CreateEdgesConnectionDataBuffer();

            _edgesConnectionDataOffsetsBuffer.Dispose();
            _edgesConnectionDataOffsetsBuffer = _CreateEdgesConnectionDataOffsetsBuffer();
        }


        void recreateComputeBuffers(uint bufferSize)
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
            cl.CopyBuffer(_velocityBuffer1, 0, velocityBuffer1B, 0, _velocityBuffer1.SizeInBytes);
            cl.CopyBuffer(_velocityBuffer2, 0, velocityBuffer2B, 0, _velocityBuffer1.SizeInBytes);
            cl.CopyBuffer(_positionsBuffer1, 0, positionsBuffer1B, 0, _positionsBuffer1.SizeInBytes);
            cl.CopyBuffer(_positionsBuffer2, 0, positionsBuffer2B, 0, _positionsBuffer1.SizeInBytes);
            cl.CopyBuffer(_rtNodeAttribBuffer1, 0, attribsBuffer1B, 0, _rtNodeAttribBuffer1.SizeInBytes);
            cl.CopyBuffer(_rtNodeAttribBuffer2, 0, attribsBuffer2B, 0, _rtNodeAttribBuffer1.SizeInBytes);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            cl.Dispose();

            _velocityBuffer1.Dispose(); _velocityBuffer1 = velocityBuffer1B;
            _velocityBuffer2.Dispose(); _velocityBuffer2 = velocityBuffer2B;
            _positionsBuffer1.Dispose(); _positionsBuffer1 = positionsBuffer1B;
            _positionsBuffer2.Dispose(); _positionsBuffer2 = positionsBuffer2B;
            _rtNodeAttribBuffer1.Dispose(); _rtNodeAttribBuffer1 = attribsBuffer1B;
            _rtNodeAttribBuffer2.Dispose(); _rtNodeAttribBuffer2 = attribsBuffer2B;


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


            //DebugPrintOutputFloatBuffer((int)textureSize, destinationBuffer, "Velocity Computation Done. Result: ", 32);


            velocityComputeResourceSet.Dispose();
            cl.Dispose();
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
            public uint isAnimated;
            private uint _padding2b;
            private uint _padding2c;
        }

        public unsafe void RenderNodeAttribs(DeviceBuffer attribBufIn, DeviceBuffer attribBufOut, float delta, int mouseoverNodeID)
        {
            uint textureSize = _activeGraph.LinearIndexTextureSize();
            uint isan;
            if (_activeGraph.IsAnimated == true) isan = 1; else isan = 0;
            AttribShaderParams parms = new AttribShaderParams
            {
                delta = delta,
                selectedNode = mouseoverNodeID,
                edgesTexWidth = (int)textureSize,
                nodesTexWidth = (int)textureSize,
                hoverMode = 1,
                isAnimated = isan
            };
            _gd.UpdateBuffer(_attribsParamsBuffer, 0, parms);
            _gd.WaitForIdle();


            CommandList cl = _factory.CreateCommandList();

            _activeGraph.GetActiveNodeIDs(out List<uint> pulseNodes, out List<uint> lingerNodes, out uint[] deactivatedNodes);

            cl.Begin();
            float[] valArray = new float[3];
            foreach (uint idx in pulseNodes)
            {
                if (idx >= _activeGraph.NodeCount()) break;
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
                if (idx >= _activeGraph.NodeCount()) break;
                if (attribBufIn.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;

                valArray[0] = 2.0f + currentPulseAlpha;
                fixed (float* dataPtr = valArray)
                {
                    cl.UpdateBuffer(attribBufIn, idx * 4 * sizeof(float) + (2 * sizeof(float)), (IntPtr)dataPtr, sizeof(float));
                }
            }

            foreach (uint idx in deactivatedNodes)
            {
                if (idx >= _activeGraph.NodeCount()) break;
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

            _rtNodeAttribBuffer1?.Dispose();
            _rtNodeAttribBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(storedAttributes, _gd);
            _rtNodeAttribBuffer2?.Dispose();
            _rtNodeAttribBuffer2 = _factory.CreateBuffer(
                new BufferDescription
                {
                    SizeInBytes = _rtNodeAttribBuffer1.SizeInBytes,
                    Usage = _rtNodeAttribBuffer1.Usage,
                    StructureByteStride = 4
                });
            _activeGraph.flipflop = true; //process attribs buffer 1 first into buffer 2

            /*
            _crs_nodesEdges.Dispose();
            _crs_nodesEdges = _factory.CreateResourceSet(
                new ResourceSetDescription(_nodesEdgesRsrclayout, _rtNodeAttribBuffer1, _NodeCircleSpritetview));
            flipflop = true; 
            */
        }

       public DeviceBuffer GetPositionsBuffer(PlottedGraph argGraph) { 
            return _positionsBuffer1; 
        }
       public  DeviceBuffer GetNodeAttribsBuffer(PlottedGraph argGraph) {
            return _rtNodeAttribBuffer1; 
       }






        public void Compute(uint drawnEdgeCount, int mouseoverNodeID)
        {
            if (_velocityShader == null)
            {
                SetupComputeResources();
            }
            if (drawnEdgeCount > _activeGraph.RenderedEdgeCount)
            {
                RegenerateEdgeDataBuffers();
                _activeGraph.RenderedEdgeCount = drawnEdgeCount;
            }

            int graphNodeCount = _activeGraph.NodeCount();
            if (_activeGraph.RenderedNodeCount < graphNodeCount)
            {
                AddNewNodesToComputeBuffers(graphNodeCount);
                _activeGraph.RenderedNodeCount = (uint)graphNodeCount;
            }




            var now = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
            float delta = Math.Min((now - _activeGraph.lastRenderTime) / 1000f, 1.0f);// safety cap on large deltas
            _activeGraph.lastRenderTime = now;
            float _activeGraphTemperature = _activeGraph.temperature;
            //Console.WriteLine($"Temp: {temperature} Delta: {_delta}");
            if (_activeGraph.flipflop)
            {
                if (_activeGraphTemperature > 0.1)
                {
                    RenderVelocity(_positionsBuffer1, _velocityBuffer1, _velocityBuffer2, delta, _activeGraphTemperature);
                    RenderPosition(_positionsBuffer1, _velocityBuffer2, _positionsBuffer2, delta);
                    _activeGraph.UpdatedNodePositions = true;
                }

                RenderNodeAttribs(_rtNodeAttribBuffer1, _rtNodeAttribBuffer2, delta, mouseoverNodeID);
            }
            else
            {

                if (_activeGraphTemperature > 0.1)
                {
                    RenderVelocity(_positionsBuffer2, _velocityBuffer2, _velocityBuffer1, delta, _activeGraphTemperature);
                    RenderPosition(_positionsBuffer2, _velocityBuffer1, _positionsBuffer1, delta);
                    _activeGraph.UpdatedNodePositions = true;
                }
                RenderNodeAttribs(_rtNodeAttribBuffer2, _rtNodeAttribBuffer1, delta, mouseoverNodeID);
            }

            _activeGraph.flipflop = !_activeGraph.flipflop;
            if (_activeGraphTemperature > 0.1)
                _activeGraph.temperature *= 0.99f;
            else
                _activeGraph.temperature = 0;


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
