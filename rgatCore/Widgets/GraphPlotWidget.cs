using ImGuiNET;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using Veldrid;
using Veldrid.ImageSharp;
using Veldrid.SPIRV;

namespace rgatCore
{
    class GraphPlotWidget
    {
        public PlottedGraph ActiveGraph { get; private set; } = null;

        private bool inited1 = false;


        System.Timers.Timer IrregularActionTimer;
        bool IrregularActionTimerFired = false;

        Dictionary<PlottedGraph, VeldridGraphBuffers> graphBufferDict = new Dictionary<PlottedGraph, VeldridGraphBuffers>();
        VeldridGraphBuffers graphBuffers = null;
        ImGuiController _controller;
        ReaderWriterLock renderLock = new ReaderWriterLock();

        private Vector2 graphWidgetSize;


        GraphicsDevice _gd;
        ResourceFactory _factory;

        public GraphPlotWidget(ImGuiController controller, GraphicsDevice gdev, Vector2? initialSize = null)
        {
            _controller = controller;
            _gd = gdev;
            _factory = _gd.ResourceFactory;
            graphWidgetSize = initialSize ?? new Vector2(400, 400);
            IrregularActionTimer = new System.Timers.Timer(600);
            IrregularActionTimer.Elapsed += FireIrregularTimer;
            IrregularActionTimer.AutoReset = true;
            IrregularActionTimer.Start();

            SetupComputeResources();
        }

        public void SetActiveGraph(PlottedGraph graph)
        {
            if (graph == ActiveGraph) return;

            //todo - grab lock
            if (graph == null)
            {
                renderLock.AcquireWriterLock(0);
                ActiveGraph = null;
                RecreateGraphicsBuffers();
                renderLock.ReleaseWriterLock();
                return;
            }
            else
            {
                if (ActiveGraph != null)
                {
                    uint textureSize = ActiveGraph.LinearIndexTextureSize();
                    DeviceBuffer destinationReadback = GetReadback(_positionsBuffer1);
                    MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
                    uint floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
                    ActiveGraph.UpdateNodePositions(destinationReadView, floatCount);
                    _gd.Unmap(destinationReadback);
                    destinationReadback.Dispose();


                    if (ActiveGraph.temperature > 0.1)
                    {
                        destinationReadback = GetReadback(_velocityBuffer1);
                        destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
                        floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
                        ActiveGraph.UpdateNodeVelocities(destinationReadView, floatCount);
                        _gd.Unmap(destinationReadback);
                        destinationReadback.Dispose();
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

            renderLock.AcquireWriterLock(0);
            ActiveGraph = graph;
            RecreateGraphicsBuffers(); 
            InitComputeBuffersFromActiveGraph();
            renderLock.ReleaseWriterLock();
        }

        private void RecreateGraphicsBuffers()
        {
            currentGraphNodeCount = 0;
            _EdgeVertBuffer?.Dispose();
            _EdgeVertBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            _EdgeIndexBuffer?.Dispose();
            _EdgeIndexBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));
            _edgeDataBuffer?.Dispose();
            _edgeDataBuffer = CreateEdgeDataBuffer();
            _edgeIndicesBuffer?.Dispose();
            _edgeIndicesBuffer = CreateTestEdgeIndicesBuffer();

            BufferDescription vbDescription = new BufferDescription(1, BufferUsage.VertexBuffer);
            _NodeVertexBuffer?.Dispose();
            _NodeVertexBuffer = _factory.CreateBuffer(vbDescription);
            _NodePickingBuffer?.Dispose();
            _NodePickingBuffer = _factory.CreateBuffer(vbDescription);
        }

        private void FireIrregularTimer(object sender, ElapsedEventArgs e) { IrregularActionTimerFired = true; }

        /* 
	 * Triggered automatically when main window is resized
	 * Manually called when we detect window changes size otherwise
	 */
        public void AlertResized(Vector2 size)
        {
            lastResizeSize = size;
            lastResize = DateTime.Now;
            scheduledGraphResize = true;
        }

        private DateTime lastResize = DateTime.Now;
        private bool scheduledGraphResize = true;
        private Vector2 lastResizeSize = new Vector2(0, 0);

        public void ApplyZoom(float direction)
        {
            if (ActiveGraph != null)
            {
                float newValue = ActiveGraph.CameraZoom - (direction * 100);
                if (newValue >= 100)
                    ActiveGraph.CameraZoom = newValue;
            }
        }

        static public bool IsMouseInWidget(Vector2 graphSize)
        {
            Vector2 MousePos = ImGui.GetMousePos();
            Vector2 WidgetPos = ImGui.GetCursorScreenPos();

            if (MousePos.X >= WidgetPos.X && MousePos.X < (WidgetPos.X + graphSize.X))
            {
                if (MousePos.Y >= WidgetPos.Y && MousePos.Y < (WidgetPos.Y + graphSize.Y))
                {
                    return true;
                }
            }
            return false;
        }

        public void HandleInput(Vector2 graphSize)
        {
            bool mouseInWidget = IsMouseInWidget(graphSize);


            if (mouseInWidget)
            {
                float scroll = ImGui.GetIO().MouseWheel;
                if (scroll != 0) ApplyZoom(scroll);

                if (ActiveGraph != null && ImGui.GetIO().MouseDown[0])
                {
                    ActiveGraph.ApplyMouseDelta(ImGui.GetIO().MouseDelta);
                }
            }


        }


        public void Draw(Vector2 graphSize, ImGuiController _ImGuiController)
        {
            if (_velocityShader == null)
            {
                SetupComputeResources();
            }

            HandleInput(graphSize);

            if (IrregularActionTimerFired) PerformIrregularActions();

            if (ActiveGraph != null)
            {
                renderLock.AcquireReaderLock(10); //todo handle timeout
                doTestRender(_ImGuiController);
                renderLock.ReleaseReaderLock();
            }
            /*
            

            if (scheduledGraphResize)
            {
                double TimeSinceLastResize = (DateTime.Now - lastResize).TotalMilliseconds;
                if (TimeSinceLastResize > 150)
                {
                    graphWidgetSize = graphSize;
                    ActiveGraph.InitGraphTexture(graphWidgetSize, _gd);
                    scheduledGraphResize = false;
                }
            }
            //Can't find an event for in-imgui resize of childwindows so have to check on every render
            if (graphSize != graphWidgetSize && graphSize != lastResizeSize) AlertResized(graphSize);

            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            Vector2 pos = ImGui.GetCursorScreenPos();
            IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, ActiveGraph._outputTexture);
            imdp.AddImage(CPUframeBufferTextureId,
                pos,
                new Vector2(pos.X + ActiveGraph._outputTexture.Width, pos.Y + ActiveGraph._outputTexture.Height), new Vector2(0, 1), new Vector2(1, 0));

            Vector2 textpos = ImGui.GetCursorScreenPos();
            //textpos += txtitm.screenXY;

            GraphicsMaths.SCREENINFO scrn;
            scrn.X = 0;// ImGui.GetCursorScreenPos().X;
            scrn.Y = 0;// ImGui.GetCursorScreenPos().Y;
            scrn.Width = graphWidgetSize.X;
            scrn.Height = graphWidgetSize.Y;
            scrn.MaxDepth = ActiveGraph.scalefactors.plotSize;
            scrn.MinDepth = 1;
            scrn.CamZoom = ActiveGraph.CameraZoom;


            foreach (PlottedGraph.TEXTITEM txtitm in ActiveGraph.GetOnScreenTexts(scrn))
            {
                PlottedGraph.TEXTITEM txtitm2 = txtitm;
                txtitm2.screenXY.X += 5;
                txtitm2.screenXY.X += ImGui.GetCursorScreenPos().X;

                txtitm2.screenXY.Y += ImGui.GetCursorScreenPos().Y;
                txtitm2.screenXY.Y -= ImGui.CalcTextSize(txtitm.contents).Y / 2;
                imdp.AddText(_ImGuiController._unicodeFont, txtitm2.fontSize, txtitm2.screenXY, (uint)txtitm2.color.ToArgb(), txtitm2.contents);
            }


            //drawHUD();
            */
        }


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


        [StructLayout(LayoutKind.Sequential)]
        struct PositionShaderParams
        {
            public float delta;
            public uint NodesTexWidth;

            private uint _padding1; //must be multiple of 16
            private uint _padding2;
        }



        [StructLayout(LayoutKind.Sequential)]
        struct AttribShaderParams
        {
            public float delta;            // requestAnimationFrame delta
            public float minTime;          // epoch min
            public float maxTime;          // epoch max
            public int selectedNode;     // selectedNode
            public float hoverMode;     // selectedNode
            public int nodesTexWidth;     // will be the same for epoch and neighbors
            public int epochsTexWidth;   // epoch data
            public int edgesTexWidth;     // neighbor data
        }



        protected DeviceBuffer GetReadback(DeviceBuffer buffer)
        {
            DeviceBuffer readback;
            if ((buffer.Usage & BufferUsage.Staging) != 0)
            {
                readback = buffer;
            }
            else
            {
                readback = _factory.CreateBuffer(new BufferDescription(buffer.SizeInBytes, BufferUsage.Staging));
                CommandList cl = _factory.CreateCommandList();
                cl.Begin();
                cl.CopyBuffer(buffer, 0, readback, 0, buffer.SizeInBytes);
                cl.End();
                _gd.SubmitCommands(cl);
                _gd.WaitForIdle();
                cl.Dispose();
            }

            return readback;
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

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gd.PointSampler, _positionsBuffer1);
            _crs_core.Dispose();
            _crs_core = _factory.CreateResourceSet(crs_core_rsd);

            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, _rtNodeAttribBuffer1, _NodeCircleSpritetview);
            _crs_nodesEdges.Dispose();
            _crs_nodesEdges = _factory.CreateResourceSet(crs_nodesEdges_rsd);

        }






        //Texture describes how many nodes each node is linked to
        public unsafe DeviceBuffer CreateTestEdgeIndicesBuffer()
        {
            int[] targetArray = ActiveGraph.GetEdgeIndicesInts();
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

        static void PrintBufferArray<T>(T[] sourceData, string premsg)
        {
            Console.WriteLine(premsg);
            for (var i = 0; i < sourceData.Length; i += 4)
            {
                if (i != 0 && (i % 8 == 0))
                    Console.WriteLine();
                Console.Write($"({sourceData[i]:f3},{sourceData[i + 1]:f3},{sourceData[i + 2]:f3},{sourceData[i + 3]}:f3)");
            }
            Console.WriteLine();

        }


        public unsafe DeviceBuffer CreateFloatsDeviceBuffer(float[] floats)
        {
            var bufferWidth = ActiveGraph.LinearIndexTextureSize();
            BufferDescription bd = new BufferDescription((uint)floats.Length * sizeof(float), BufferUsage.StructuredBufferReadWrite, 4);
            DeviceBuffer newBuffer = _factory.CreateBuffer(bd);

            //PrintBufferArray(textureArray, "Created velocity buffer:");
            fixed (float* dataPtr = floats)
            {
                _gd.UpdateBuffer(newBuffer, 0, (IntPtr)dataPtr, (uint)floats.Length * sizeof(float));
                _gd.WaitForIdle();
            }

            /*
            float[] outputArray = new float[bufferWidth * bufferWidth * 4];
            DeviceBuffer destinationReadback = GetReadback(newBuffer);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            for (int index = 0; index < bufferWidth * bufferWidth * 4; index++)
            {
                outputArray[index] = destinationReadView[index];
            }
            destinationReadback.Dispose();
            PrintBufferArray(outputArray, "Buffer created: ");
            */
            return newBuffer;
        }


        public unsafe DeviceBuffer CreateEdgeDataBuffer()
        {
            var textureSize = ActiveGraph != null ? ActiveGraph.LinearIndexTextureSize() : 0;
            BufferDescription bd = new BufferDescription(textureSize * textureSize * 4 * sizeof(int), BufferUsage.StructuredBufferReadOnly, 4);
            DeviceBuffer newBuffer = _factory.CreateBuffer(bd);

            if (textureSize > 0)
            {
                int[] edgeDataInts = ActiveGraph.GetEdgeDataInts();
                fixed (int* dataPtr = edgeDataInts)
                {
                    _gd.UpdateBuffer(newBuffer, 0, (IntPtr)dataPtr, textureSize * textureSize * 16);
                    _gd.WaitForIdle();
                }
            }

            //PrintBufferArray(textureArray, "Created data texture:");
            return newBuffer;
        }


        //todo : everything in here should be class variables defined once
        public unsafe void RenderVelocity(DeviceBuffer positions, DeviceBuffer velocities,
            DeviceBuffer destinationBuffer, float delta, float temperature)
        {

            var textureSize = ActiveGraph.LinearIndexTextureSize();
            VelocityShaderParams parms = new VelocityShaderParams
            {
                delta = delta,
                k = 100.0f,
                temperature = temperature,
                NodesTexWidth = textureSize,
                EdgesTexWidth = ActiveGraph.EdgeTextureWidth()
            };
            _gd.UpdateBuffer(_velocityParamsBuffer, 0, parms);
            _gd.WaitForIdle();

            ResourceSet velocityComputeResourceSet = _factory.CreateResourceSet(new ResourceSetDescription(_velocityComputeLayout,
                _velocityParamsBuffer, positions, _PresetLayoutFinalPositionsBuffer, velocities, _edgeIndicesBuffer, _edgeDataBuffer, destinationBuffer));



            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.SetPipeline(_velocityComputePipeline);
            cl.SetComputeResourceSet(0, velocityComputeResourceSet);
            cl.Dispatch(textureSize, textureSize, 1); //todo, really?
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            /*
            float[] outputArray = new float[textureSize * textureSize * 4];
            DeviceBuffer destinationReadback = GetReadback(destinationBuffer);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            for (int index = 0; index < textureSize * textureSize * 4; index++) {
                if (index >= destinationReadView.Count) break;
                outputArray[index] = destinationReadView[index];
            }
            destinationReadback.Dispose();
            _gd.Unmap(destinationReadback);
            PrintBufferArray(outputArray, "Velocity Computation Done. Result: ");
            */

            velocityComputeResourceSet.Dispose();
            cl.Dispose();
        }




        //todo : everything in here should be class variables defined once
        public unsafe void RenderPosition(DeviceBuffer positions, DeviceBuffer velocities, DeviceBuffer output, float delta)
        {
            var textureSize = ActiveGraph.LinearIndexTextureSize();

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



            ResourceSet crs = _factory.CreateResourceSet(new ResourceSetDescription(_positionComputeLayout,
                _positionParamsBuffer, positions, velocities, output));


            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.SetPipeline(_positionComputePipeline);
            cl.SetComputeResourceSet(0, crs);
            cl.Dispatch(width, height , 1);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            /*
            float[] outputArray = new float[textureSize * textureSize * 4];
            DeviceBuffer destinationReadback = GetReadback(output);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            for (int index = 0; index < textureSize * textureSize * 4; index++)
            {
                if (index >= destinationReadView.Count) break;
                outputArray[index] = destinationReadView[index];
            }
            destinationReadback.Dispose();
            PrintBufferArray(outputArray, "Position Computation Done. Result: ");
            */

            cl.Dispose();
            crs.Dispose();
        }


        public unsafe void RenderNodeAttribs(DeviceBuffer attribBufIn, DeviceBuffer attribBufOut, float windowStart, float windowEnd, float delta)
        {
            /*
             * todo window/epoch values need to be replaced with a buffer
            containing active nodes and remaining alpha/time
            */

            uint textureSize = ActiveGraph.LinearIndexTextureSize();
            AttribShaderParams parms = new AttribShaderParams
            {
                delta = delta,
                selectedNode = _mouseoverNodeID,
                maxTime = 9,
                minTime = 0,
                edgesTexWidth = (int)textureSize,
                nodesTexWidth = (int)textureSize,
                epochsTexWidth = (int)textureSize,
                hoverMode = 1
            };
            _gd.UpdateBuffer(_attribsParamsBuffer, 0, parms);
            _gd.WaitForIdle();



            ResourceSet attribComputeResourceSet = _factory.CreateResourceSet(new ResourceSetDescription(_nodeAttribComputeLayout,
                _attribsParamsBuffer, attribBufIn, attribBufIn, attribBufIn,
                _edgeIndicesBuffer, _edgeDataBuffer, attribBufIn,
                attribBufOut));

            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.SetPipeline(_nodeAttribComputePipeline);
            cl.SetComputeResourceSet(0, attribComputeResourceSet);
            cl.Dispatch(textureSize / 16, textureSize / 16, 1);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            cl.Dispose();
            attribComputeResourceSet.Dispose();

        }







        DeviceBuffer _PresetLayoutFinalPositionsBuffer, _edgeDataBuffer;
        DeviceBuffer _positionsBuffer1, _positionsBuffer2;
        DeviceBuffer _rtNodeAttribBuffer1, _rtNodeAttribBuffer2;
        DeviceBuffer _velocityBuffer1, _velocityBuffer2;
        public float _delta;
        long last;
        bool flipflop = true;
        public DeviceBuffer _viewBuffer { get; private set; }
        Framebuffer _outputFramebuffer, _pickingFrameBuffer;

        uint currentGraphNodeCount = 0;

        /// <summary>
        /// Edges pipeline = line list or line strp
        /// Points pipeline = visible nodes where we draw sphere/etc texture
        /// Picking pipleine = same as points but different data, not drawn to screen. Seperate shaders to reduce branching
        /// Font pipeline = triangles
        /// </summary>
        Pipeline _edgesPipeline, _pointsPipeline, _pickingPipeline, _fontPipeline;
        Pipeline _positionComputePipeline, _velocityComputePipeline, _nodeAttribComputePipeline;
        private Shader _positionShader, _velocityShader, _nodeAttribShader;

        ResourceLayout _velocityComputeLayout, _positionComputeLayout, _nodeAttribComputeLayout;

        ResourceLayout _coreRsrcLayout, _nodesEdgesRsrclayout, _fontRsrcLayout;
        Texture _testoutputTexture, _testPickingTexture, _pickingStagingTexture;
        DeviceBuffer _velocityParamsBuffer, _positionParamsBuffer, _attribsParamsBuffer;

        //vert/frag rendering buffers
        ResourceSet _crs_core, _crs_nodesEdges, _crs_font;
        DeviceBuffer _EdgeVertBuffer, _EdgeIndexBuffer, _edgeIndicesBuffer;
        DeviceBuffer _NodeVertexBuffer, _NodePickingBuffer, _NodeIndexBuffer;
        DeviceBuffer _FontVertBuffer, _FontIndexBuffer;
        DeviceBuffer _paramsBuffer;

        Texture _NodeCircleSprite;
        TextureView _NodeCircleSpritetview;

        public DeviceBuffer _animBuffer { get; private set; }

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
            new ResourceLayoutElementDescription("epochsIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("epochsData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("nodeIDMappings", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));
            _attribsParamsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<AttribShaderParams>(), BufferUsage.UniformBuffer));



            ComputePipelineDescription attribCPL = new ComputePipelineDescription(_nodeAttribShader, _nodeAttribComputeLayout, 16, 16, 1);

            _nodeAttribComputePipeline = _factory.CreateComputePipeline(attribCPL);


            _paramsBuffer = _factory.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<graphShaderParams>(), BufferUsage.UniformBuffer));

            _coreRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Vertex),
               new ResourceLayoutElementDescription("Sampler", ResourceKind.Sampler, ShaderStages.Fragment),
               new ResourceLayoutElementDescription("Positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex)
               ));



            string imgpath = @"C:\Users\nia\Desktop\rgatstuff\js\analytics-master\textures\new_circle.png";
            _NodeCircleSprite = new ImageSharpTexture(imgpath, true, true).CreateDeviceTexture(_gd, _factory);
            _NodeCircleSpritetview = _factory.CreateTextureView(_NodeCircleSprite);


            _nodesEdgesRsrclayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("NodeAttribs", ResourceKind.StructuredBufferReadOnly, ShaderStages.Vertex),
                new ResourceLayoutElementDescription("NodeTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));


            // Create pipelines
            GraphicsPipelineDescription pipelineDescription = new GraphicsPipelineDescription();
            pipelineDescription.BlendState = BlendStateDescription.SingleAlphaBlend;
            pipelineDescription.DepthStencilState = new DepthStencilStateDescription(
                depthTestEnabled: true,
                depthWriteEnabled: true,
                comparisonKind: ComparisonKind.LessEqual);

            pipelineDescription.RasterizerState = new RasterizerStateDescription(
                cullMode: FaceCullMode.Back,
                fillMode: PolygonFillMode.Solid,
                frontFace: FrontFace.Clockwise,
                depthClipEnabled: true,
                scissorTestEnabled: false);
            pipelineDescription.ResourceLayouts = new[] { _coreRsrcLayout, _nodesEdgesRsrclayout };
            pipelineDescription.ShaderSet = CreateNodeShaders();

            _testoutputTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                    (uint)graphWidgetSize.X, (uint)graphWidgetSize.Y, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.RenderTarget | TextureUsage.Sampled));
            _outputFramebuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _testoutputTexture));


            _testPickingTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                    1000, 500, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.RenderTarget | TextureUsage.Sampled));
            _pickingFrameBuffer = _gd.ResourceFactory.CreateFramebuffer(new FramebufferDescription(null, _testPickingTexture));
            _pickingStagingTexture = _gd.ResourceFactory.CreateTexture(TextureDescription.Texture2D(
                    (uint)graphWidgetSize.X, (uint)graphWidgetSize.Y, 1, 1,
                    PixelFormat.R32_G32_B32_A32_Float,
                    TextureUsage.Staging));

            pipelineDescription.Outputs = _outputFramebuffer.OutputDescription;

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.ShaderSet = CreateTestGraphPickingShaders();
            _pickingPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);


            /*
             * this can probably be a linestrip, but for now lets see if linelist lets us do something more
             * like multiple graphs
             */
            pipelineDescription.ShaderSet = CreateEdgeShaders();
            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _edgesPipeline = _factory.CreateGraphicsPipeline(pipelineDescription);



            //font -----------------------

            _fontRsrcLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
                new ResourceLayoutElementDescription("FontTexture", ResourceKind.TextureReadOnly, ShaderStages.Fragment)
                ));

            ResourceSetDescription crs_font_rsd = new ResourceSetDescription(_fontRsrcLayout, _controller._fontTextureView);
            _crs_font = _factory.CreateResourceSet(crs_font_rsd);


            GraphicsPipelineDescription fontpd = new GraphicsPipelineDescription(
                BlendStateDescription.SingleAlphaBlend,
                new DepthStencilStateDescription(false, false, ComparisonKind.Always),
                new RasterizerStateDescription(FaceCullMode.None, PolygonFillMode.Solid, FrontFace.Clockwise, false, true),
                PrimitiveTopology.TriangleList, CreateFontShaders(), new ResourceLayout[] { _coreRsrcLayout, _fontRsrcLayout },
                _outputFramebuffer.OutputDescription);
            _fontPipeline = _factory.CreateGraphicsPipeline(fontpd);
        }

        void InitComputeBuffersFromActiveGraph()
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
                _edgeIndicesBuffer.Dispose();
                _edgeDataBuffer.Dispose();
            }

            _velocityBuffer1 = CreateFloatsDeviceBuffer(ActiveGraph.GetVelocityFloats());
            _velocityBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _velocityBuffer1.SizeInBytes, Usage = _velocityBuffer1.Usage, StructureByteStride = 4 });
            _positionsBuffer1 = CreateFloatsDeviceBuffer(ActiveGraph.GetPositionFloats());
            _positionsBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _positionsBuffer1.SizeInBytes, Usage = _positionsBuffer1.Usage, StructureByteStride = 4 });
            _rtNodeAttribBuffer1 = CreateFloatsDeviceBuffer(ActiveGraph.GetNodeAttribFloats());
            _rtNodeAttribBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _rtNodeAttribBuffer1.SizeInBytes, Usage = _rtNodeAttribBuffer1.Usage, StructureByteStride = 4 });

            ResourceSetDescription crs_core_rsd = new ResourceSetDescription(_coreRsrcLayout, _paramsBuffer, _gd.PointSampler, _positionsBuffer1);
            _crs_core = _factory.CreateResourceSet(crs_core_rsd);

            ResourceSetDescription crs_nodesEdges_rsd = new ResourceSetDescription(_nodesEdgesRsrclayout, _rtNodeAttribBuffer1, _NodeCircleSpritetview);
            _crs_nodesEdges = _factory.CreateResourceSet(crs_nodesEdges_rsd);


            _PresetLayoutFinalPositionsBuffer = CreateFloatsDeviceBuffer(ActiveGraph.GetPresetPositionFloats()); //todo: actually empty
            _edgeIndicesBuffer = CreateTestEdgeIndicesBuffer();
            _edgeDataBuffer = CreateEdgeDataBuffer();


            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.CopyBuffer(_velocityBuffer1, 0, _velocityBuffer2, 0, _velocityBuffer1.SizeInBytes);
            cl.CopyBuffer(_positionsBuffer1, 0, _positionsBuffer2, 0, _positionsBuffer1.SizeInBytes);
            cl.CopyBuffer(_rtNodeAttribBuffer1, 0, _rtNodeAttribBuffer2, 0, _rtNodeAttribBuffer1.SizeInBytes);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            currentGraphNodeCount = (uint)ActiveGraph.NodeCount();
        }


        private ShaderSetDescription CreateNodeShaders()
        {
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, Encoding.UTF8.GetBytes(vsnodeglsl), "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, Encoding.UTF8.GetBytes(fsnodeglsl), "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: _factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

            _NodeVertexBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            _NodeIndexBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));

            return shaderSetDesc;
        }

        ShaderSetDescription CreateTestGraphPickingShaders()
        {
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, Encoding.UTF8.GetBytes(vspickingglsl), "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, Encoding.UTF8.GetBytes(fspickingglsl), "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: _factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

            _NodePickingBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));

            return shaderSetDesc;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct fontStruc
        {
            public uint nodeIdx;
            public Vector3 screenCoord;
            public Vector2 fontCoord;
            public const uint SizeInBytes = 24;
        }

        ShaderSetDescription CreateFontShaders()
        {
            VertexElementDescription nodeIdx = new VertexElementDescription("nodeIdx", VertexElementSemantic.TextureCoordinate, VertexElementFormat.UInt1);
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float3);
            VertexElementDescription Charpos = new VertexElementDescription("CharCoord", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(nodeIdx, VEDpos, Charpos);

            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, Encoding.UTF8.GetBytes(vsfontglsl), "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, Encoding.UTF8.GetBytes(fsfontglsl), "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: _factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

            _FontVertBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            _FontIndexBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));

            return shaderSetDesc;
        }

        private ShaderSetDescription CreateEdgeShaders()
        {
            VertexElementDescription VEDpos = new VertexElementDescription("Position", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float2);
            VertexElementDescription VEDcol = new VertexElementDescription("Color", VertexElementSemantic.TextureCoordinate, VertexElementFormat.Float4);
            VertexLayoutDescription vertexLayout = new VertexLayoutDescription(VEDpos, VEDcol);

            ShaderDescription vertexShaderDesc = new ShaderDescription(ShaderStages.Vertex, Encoding.UTF8.GetBytes(vsedgeglsl), "main");
            ShaderDescription fragmentShaderDesc = new ShaderDescription(ShaderStages.Fragment, Encoding.UTF8.GetBytes(fsedgeglsl), "main");

            ShaderSetDescription shaderSetDesc = new ShaderSetDescription(
                vertexLayouts: new VertexLayoutDescription[] { vertexLayout },
                shaders: _factory.CreateFromSpirv(vertexShaderDesc, fragmentShaderDesc));

            _EdgeVertBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.VertexBuffer));
            _EdgeIndexBuffer = _factory.CreateBuffer(new BufferDescription(1, BufferUsage.IndexBuffer));

            return shaderSetDesc;
        }

        public struct TestVertexPositionColor
        {
            public Vector2 TexPosition;
            public WritableRgbaFloat Color;
            public const uint SizeInBytes = 24;

            public TestVertexPositionColor(Vector2 position, WritableRgbaFloat color)
            {
                TexPosition = position;
                Color = color;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct graphShaderParams
        {
            public Matrix4x4 rotatedView;
            public Matrix4x4 nonRotatedView;
            public uint TexWidth;
            public int pickingNode;
            //must be multiple of 16
            private uint _padding1;
            private uint _padding2;
        }


        unsafe void AddNewNodesToComputeBuffers()
        {
            float[] newPositions = ActiveGraph.GetPositionFloats();
            float[] newVelocities = ActiveGraph.GetVelocityFloats();
            float[] newAttribs = ActiveGraph.GetNodeAttribFloats();

            var bufferWidth = ActiveGraph.LinearIndexTextureSize();
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            var bufferSize = bufferFloatCount * sizeof(float);

            if (bufferSize > _velocityBuffer1.SizeInBytes)
            {
                Console.WriteLine($"Recreating buffers as {bufferSize} > {_velocityBuffer1.SizeInBytes}");
                recreateComputeBuffers(bufferSize);
            }

            uint newNodeCount = ((uint)ActiveGraph.NodeCount()) - currentGraphNodeCount;
            uint offset = currentGraphNodeCount * 4 * sizeof(float);
            uint updateSize = 4 * sizeof(float) * newNodeCount;

            fixed (float* dataPtr = newPositions)
            {
                _gd.UpdateBuffer(_positionsBuffer1, offset, (IntPtr)(dataPtr + (currentGraphNodeCount * 4)), updateSize);
                _gd.UpdateBuffer(_positionsBuffer2, offset, (IntPtr)(dataPtr + (currentGraphNodeCount * 4)), updateSize);
            }

            fixed (float* dataPtr = newVelocities)
            {
                _gd.UpdateBuffer(_velocityBuffer1, offset, (IntPtr)(dataPtr + (currentGraphNodeCount * 4)), updateSize);
                _gd.UpdateBuffer(_velocityBuffer2, offset, (IntPtr)(dataPtr + (currentGraphNodeCount * 4)), updateSize);
            }

            fixed (float* dataPtr = newAttribs)
            {
                _gd.UpdateBuffer(_rtNodeAttribBuffer1, offset, (IntPtr)(dataPtr + (currentGraphNodeCount * 4)), updateSize);
                _gd.UpdateBuffer(_rtNodeAttribBuffer2, offset, (IntPtr)(dataPtr + (currentGraphNodeCount * 4)), updateSize);
            }
        }


        void RegenerateEdgeDataBuffers(TestVertexPositionColor[] TestEdgeLineVerts, List<uint> edgeIndices)
        {
            _EdgeVertBuffer.Dispose();
            BufferDescription tvbDescription = new BufferDescription((uint)TestEdgeLineVerts.Length * TestVertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
            _EdgeVertBuffer = _factory.CreateBuffer(tvbDescription);

            _EdgeIndexBuffer.Dispose();
            BufferDescription eibDescription = new BufferDescription((uint)edgeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer);
            _EdgeIndexBuffer = _factory.CreateBuffer(eibDescription);

            _gd.UpdateBuffer(_EdgeVertBuffer, 0, TestEdgeLineVerts);
            _gd.UpdateBuffer(_EdgeIndexBuffer, 0, edgeIndices.ToArray());

            _edgeDataBuffer.Dispose();
            _edgeDataBuffer = CreateEdgeDataBuffer();
            _edgeIndicesBuffer.Dispose();
            _edgeIndicesBuffer = CreateTestEdgeIndicesBuffer();
        }



        void processKeyPresses()
        {
            bool kp = false;
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.UpArrow))) { ActiveGraph.CameraYOffset += 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.DownArrow))) { ActiveGraph.CameraYOffset -= 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.LeftArrow))) { ActiveGraph.CameraXOffset -= 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.RightArrow))) { ActiveGraph.CameraXOffset += 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.PageUp))) { ActiveGraph.CameraZoom += 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.PageDown))) { ActiveGraph.CameraZoom -= 50; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.End))) { ActiveGraph.PlotZRotation += 0.05f; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.Delete))) { ActiveGraph.PlotZRotation -= 0.05f; kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.V))) { ActiveGraph.IncreaseTemperature(); kp = true; }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.X))) { ActiveGraph.AddTestNodes(); }
            if (ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.Y))) { ActiveGraph.AddRandomEdge(); }

            if (kp) Console.WriteLine($"xZoom: { ActiveGraph.CameraXOffset}, yZoom: { ActiveGraph.CameraYOffset} zzoom: {ActiveGraph.CameraZoom}");

        }



        void stringToVertexes(string inputString, uint nodeIdx, float fontScale, ref List<fontStruc> stringVerts)
        {
            float yPos = 50;
            float yOff = 10;
            float xPos = 0;

            for (var i = 0; i < inputString.Length; i++)
            {
                ImFontGlyphPtr glyph = _controller._unicodeFont.FindGlyph(inputString[i]);
                float charWidth = glyph.AdvanceX * fontScale;
                float charHeight = fontScale * (glyph.Y1 - glyph.Y0);
                float xEnd = xPos + charWidth;
                float yBase = yPos + (yOff - glyph.Y1) * fontScale;
                float yTop = yBase + charHeight;
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yTop, 0), fontCoord = new Vector2(glyph.U0, glyph.V0) }); ;
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yBase, 0), fontCoord = new Vector2(glyph.U0, glyph.V1) });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yBase, 0), fontCoord = new Vector2(glyph.U1, glyph.V1) });

                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xPos, yTop, 0), fontCoord = new Vector2(glyph.U0, glyph.V0) });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yBase, 0), fontCoord = new Vector2(glyph.U1, glyph.V1) });
                stringVerts.Add(new fontStruc { nodeIdx = nodeIdx, screenCoord = new Vector3(xEnd, yTop, 0), fontCoord = new Vector2(glyph.U1, glyph.V0) });
                xPos += charWidth;
            }
        }

        graphShaderParams updateShaderParams(uint textureSize)
        {
            graphShaderParams shaderParams = new graphShaderParams { TexWidth = textureSize, pickingNode = _mouseoverNodeID };

            float aspectRatio = graphWidgetSize.X / graphWidgetSize.Y;
            Matrix4x4 projection = Matrix4x4.CreatePerspectiveFieldOfView(ActiveGraph.CameraFieldOfView,
                aspectRatio, ActiveGraph.CameraClippingNear, ActiveGraph.CameraClippingFar);
            Vector3 translation = new Vector3(ActiveGraph.CameraXOffset, ActiveGraph.CameraYOffset, ActiveGraph.CameraZoom);
            Matrix4x4 cameraTranslation = Matrix4x4.CreateTranslation(translation);

            Matrix4x4 newView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, ActiveGraph.PlotZRotation);
            newView = Matrix4x4.Multiply(newView, cameraTranslation);
            newView = Matrix4x4.Multiply(newView, projection);
            shaderParams.rotatedView = newView;

            newView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0);
            newView = Matrix4x4.Multiply(newView, cameraTranslation);
            shaderParams.nonRotatedView = newView;

            _gd.UpdateBuffer(_paramsBuffer, 0, shaderParams);
            _gd.WaitForIdle();

            return shaderParams;
        }


        public void renderTestGraph(ImGuiController _ImGuiController)
        {

            //rotval += 0.01f; //autorotate
            if (ActiveGraph.PlotZRotation >= 360) ActiveGraph.PlotZRotation = 0;
            var textureSize = ActiveGraph.LinearIndexTextureSize();
            updateShaderParams(textureSize);

            TestVertexPositionColor[] TestNodeVerts = ActiveGraph.GetNodeVerts(out List<uint> nodeIndices, out TestVertexPositionColor[] nodePickingColors);

            if (_NodeVertexBuffer.SizeInBytes < TestNodeVerts.Length * TestVertexPositionColor.SizeInBytes ||
                (_NodeIndexBuffer.SizeInBytes < nodeIndices.Count * sizeof(uint)))
            {
                BufferDescription vbDescription = new BufferDescription((uint)TestNodeVerts.Length * TestVertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
                _NodeVertexBuffer.Dispose();
                _NodeVertexBuffer = _factory.CreateBuffer(vbDescription);
                _NodePickingBuffer.Dispose();
                _NodePickingBuffer = _factory.CreateBuffer(vbDescription);

                BufferDescription ibDescription = new BufferDescription((uint)nodeIndices.Count * sizeof(uint), BufferUsage.IndexBuffer);
                _NodeIndexBuffer.Dispose();
                _NodeIndexBuffer = _factory.CreateBuffer(ibDescription);
            }

            _gd.UpdateBuffer(_NodeVertexBuffer, 0, TestNodeVerts);
            _gd.UpdateBuffer(_NodePickingBuffer, 0, nodePickingColors);
            _gd.UpdateBuffer(_NodeIndexBuffer, 0, nodeIndices.ToArray());



            uint telvTextSize = ActiveGraph.EdgeTextureWidth();
            TestVertexPositionColor[] TestEdgeLineVerts = ActiveGraph.GetEdgeLineVerts(out List<uint> edgeIndices);

            //todo - this needs to happen at start as well, otherwise stuck until node added?
            if (_EdgeIndexBuffer.SizeInBytes < edgeIndices.Count * sizeof(uint))
            {
                RegenerateEdgeDataBuffers(TestEdgeLineVerts, edgeIndices);
            }

            if (currentGraphNodeCount < nodeIndices.Count)
            {
                AddNewNodesToComputeBuffers();
                currentGraphNodeCount = (uint)nodeIndices.Count;
            }

            //have hacked in an easy solution here but codepoint/visible (which we don't use) wont work. 
            //https://github.com/mellinoe/ImGui.NET/issues/206
            System.Diagnostics.Debug.Assert(_controller._unicodeFont.GetCharAdvance('4') == _controller._unicodeFont.FindGlyph('4').AdvanceX);

            Dictionary<uint, string> stringTexts = new Dictionary<uint, string>()
            {
                [0] = "node 0",
                [2] = "node 2",
                [6] = "node 6"
            };

            const float fontScale = 15.0f;
            List<fontStruc> stringVerts = new List<fontStruc>();

            foreach (KeyValuePair<uint, string> entry in stringTexts)
            {
                stringToVertexes(entry.Value, entry.Key, fontScale, ref stringVerts);
            }
            ushort[] charIndexes = Enumerable.Range(0, stringVerts.Count).Select(i => (ushort)i).ToArray();

            if (stringVerts.Count * fontStruc.SizeInBytes > _FontVertBuffer.SizeInBytes)
            {
                _FontVertBuffer.Dispose();
                BufferDescription tfontvDescription = new BufferDescription((uint)stringVerts.Count * fontStruc.SizeInBytes, BufferUsage.VertexBuffer);
                _FontVertBuffer = _factory.CreateBuffer(tfontvDescription);
                _gd.UpdateBuffer(_FontVertBuffer, 0, stringVerts.ToArray());

                _FontIndexBuffer.Dispose();
                BufferDescription tfontIdxDescription = new BufferDescription((uint)charIndexes.Length * sizeof(ushort), BufferUsage.IndexBuffer);
                _FontIndexBuffer = _factory.CreateBuffer(tfontIdxDescription);
                _gd.UpdateBuffer(_FontIndexBuffer, 0, charIndexes);
            }

            //draw nodes and edges
            CommandList _cl = _factory.CreateCommandList();
            _cl.Begin();
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.ClearColorTarget(0, new RgbaFloat(0.2f, 0.2f, 0.2f, 1));
            _cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, -2200, 1000));

            _cl.SetPipeline(_pointsPipeline);
            _cl.SetVertexBuffer(0, _NodeVertexBuffer);
            _cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            _cl.SetGraphicsResourceSet(0, _crs_core);
            _cl.SetGraphicsResourceSet(1, _crs_nodesEdges);
            _cl.DrawIndexed(indexCount: (uint)nodeIndices.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            _cl.SetPipeline(_edgesPipeline);
            _cl.SetVertexBuffer(0, _EdgeVertBuffer);
            _cl.SetIndexBuffer(_EdgeIndexBuffer, IndexFormat.UInt32);
            _cl.DrawIndexed(indexCount: (uint)edgeIndices.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            _cl.End();
            _gd.SubmitCommands(_cl);

            _gd.WaitForIdle(); //needed?

            //draw text
            _cl.Begin();
            _cl.SetFramebuffer(_outputFramebuffer);
            _cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, -2200, 1000));

            _cl.SetPipeline(_fontPipeline);
            _cl.SetVertexBuffer(0, _FontVertBuffer);
            _cl.SetIndexBuffer(_FontIndexBuffer, IndexFormat.UInt16);
            _cl.SetGraphicsResourceSet(0, _crs_core);
            _cl.SetGraphicsResourceSet(1, _crs_font);
            _cl.DrawIndexed(indexCount: (uint)stringVerts.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);

            _cl.End();
            _gd.SubmitCommands(_cl);

            _gd.WaitForIdle(); //needed?

            //update the picking framebuffer
            _cl.Begin();
            _cl.SetPipeline(_pickingPipeline);
            _cl.SetGraphicsResourceSet(0, _crs_core);
            _cl.SetGraphicsResourceSet(1, _crs_nodesEdges);
            _cl.SetVertexBuffer(0, _NodePickingBuffer);
            _cl.SetIndexBuffer(_NodeIndexBuffer, IndexFormat.UInt32);
            _cl.SetFramebuffer(_pickingFrameBuffer);

            _cl.ClearColorTarget(0, new RgbaFloat(0f, 0f, 0f, 0f));
            _cl.SetViewport(0, new Viewport(0, 0, graphWidgetSize.X, graphWidgetSize.Y, -2200, 1000));
            _cl.DrawIndexed(indexCount: (uint)nodeIndices.Count, instanceCount: 1, indexStart: 0, vertexOffset: 0, instanceStart: 0);
            _cl.CopyTexture(_testPickingTexture, _pickingStagingTexture);
            _cl.End();
            _gd.SubmitCommands(_cl);
            _gd.WaitForIdle();


            //now draw the output to the screen
            Vector2 pos = ImGui.GetCursorScreenPos();
            ImDrawListPtr imdp = ImGui.GetWindowDrawList(); //draw on and clipped to this window 
            IntPtr CPUframeBufferTextureId = _ImGuiController.GetOrCreateImGuiBinding(_gd.ResourceFactory, _testoutputTexture);
            imdp.AddImage(CPUframeBufferTextureId, pos,
            new Vector2(pos.X + _testoutputTexture.Width, pos.Y + _testoutputTexture.Height),
            new Vector2(0, 1), new Vector2(1, 0));

            _cl.Dispose();

            Vector2 mp = new Vector2(ImGui.GetMousePos().X + 8, ImGui.GetMousePos().Y - 12);
            ImGui.GetWindowDrawList().AddText(_ImGuiController._unicodeFont, 16, mp, 0xffffffff, $"{ImGui.GetMousePos().X},{ImGui.GetMousePos().Y}");

        }


        private const string vsfontglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in uint nodeIdx;
layout(location = 1) in vec3 vertex;
layout(location = 2) in vec2 fontCrd;
layout(location = 0) out vec2 texCoords;


layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    uint TexWidth;
    int pickingNodeID;
};
layout(set = 0, binding=1) uniform sampler nodeTexView; //point sampler
layout(set = 0, binding=2) buffer bufpositionTexture{
    vec4 positionTexture[];
};

void main()
{
    //uint index = uint(vertex.y * TexWidth + vertex.x);
    vec3 nodePosition = positionTexture[nodeIdx].xyz;

    gl_Position = modelViewMatrix * (vec4(nodePosition.xyz, 1.0)) +  projectionMatrix * vec4(vertex.xy,0,0);// - vec4(vertex.x / 1.1, 0,0,0);


    //gl_Position =  vec4(vertex.xy, 0.0, 1.0);
    texCoords = fontCrd;
}  
";

        private const string fsfontglsl = @"
#version 450
layout(location = 0) in vec2 TexCoords;
layout(location = 0) out vec4 color;

layout(set = 0, binding=1) uniform sampler pointSampler; //point sampler
layout(set = 1, binding=0) uniform texture2D fontTexture;   //font graphic

void main()
{   
    vec4 sampled =  texture(sampler2D(fontTexture, pointSampler), TexCoords);
    color = vec4(1.0, 0.3, 1.0, 1.0) * sampled;
}  
";



        private const string vsnodeglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec2 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;
layout(location = 1) out vec2 vPosition;

layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    uint TexWidth;
    int pickingNodeID;
};
layout(set = 0, binding=2) buffer bufpositionTexture{
    vec4 positionTexture[];
};
layout(set = 1, binding=0) buffer bufnodeAttribTexture{
    vec4 nodeAttribTexture[];
};


void main() {
    uint index = uint(Position.y * TexWidth + Position.x);

    if (index == pickingNodeID){
        vColor = vec4(1.0,0.0,1.0,1.0);
    } else {
        vColor = vec4(Color.xyz, nodeAttribTexture[index].y) ;
    }

    vec3 nodePosition = positionTexture[index].xyz;
    vPosition = Position;

    float nodeSize = 150.0;
    gl_Position =  modelViewMatrix * vec4(nodePosition,1);
    float mush = nodeSize / length(gl_Position.xyz);
    gl_PointSize = nodeAttribTexture[index].x * mush;
}

";

        private const string fsnodeglsl = @"
#version 430

layout(location = 0) in vec4 fsin_Color;
layout(location = 1) in vec2 fsin_Position;
layout(location = 0) out vec4 fsout_Color;

layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    uint TexWidth;
    int pickingNodeID;
};
layout(set = 0, binding=1) uniform sampler nodeTexView; //point sampler
layout(set = 1, binding=1) uniform texture2D nodeTex;   //sphere graphic


void main() 
{

        //draw the sphere texture over the node point
        vec4 node = texture(sampler2D(nodeTex, nodeTexView), gl_PointCoord);
        fsout_Color = vec4( fsin_Color.xyzw ) * node;
}
";


        private const string vspickingglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec2 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;
layout(location = 1) out vec2 vPosition;

layout(set = 0, binding=0) uniform ParamsBuf
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    uint TexWidth;
    int pickingNodeID;
};
layout(set = 0, binding=2) buffer bufpositionTexture{
    vec4 positionTexture[];
};
layout(set = 1, binding=0) buffer bufnodeAttribTexture{
    vec4 nodeAttribTexture[];
};


void main() {
    vColor = Color;
    vPosition = Position;

    uint index = uint(Position.y * TexWidth + Position.x);
    vec3 nodePosition = positionTexture[index].xyz;
    gl_Position =  modelViewMatrix * vec4(nodePosition,1);
    gl_PointSize = 10;
}";


        private const string fspickingglsl = @"
    #version 430

    layout(location = 0) in vec4 fsin_Color;
    layout(location = 1) in vec2 fsin_Position;
    layout(location = 0) out vec4 fsout_Color;

    void main() 
    {
        fsout_Color = fsin_Color;
    }";



        private const string vsedgeglsl = @"
#version 450
#extension GL_ARB_separate_shader_objects : enable
#extension GL_ARB_shading_language_420pack : enable


layout(location = 0) in vec2 Position;
layout(location = 1) in vec4 Color;
layout(location = 0) out vec4 vColor;

layout(set = 0, binding=2) buffer bufpositionTexture{  vec4 positionTexture[];};
layout(set = 1, binding=0) buffer bufnodeAttribTexture{ vec4 nodeAttribTexture[];};
layout(set = 0, binding=0) uniform ViewBuffer
{
    mat4 modelViewMatrix;
    mat4 projectionMatrix;
    uint TexWidth;
    int pickingNodeID;
};


void main() {

    uint index = uint(Position.y * TexWidth + Position.x);
    vColor = vec4(Color.xyz, nodeAttribTexture[index].y);

    vec3 nodePosition = positionTexture[index].xyz;
    gl_Position =  modelViewMatrix * vec4(nodePosition,1);
    
}

";

        private const string fsedgeglsl = @"
#version 430

layout(location = 0) in vec4 fsin_Color;
layout(location = 0) out vec4 fsout_Color;

void main() {
    fsout_Color = fsin_Color;
}
";








        public unsafe void doTestRender(ImGuiController _ImGuiController)
        {

            processKeyPresses();

            float epochMax = 0;
            float epochMin = 0;

            var now = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
            _delta = (now - last) / 1000f;
            if (_delta > 1) _delta = 1; // safety cap on large deltas
            last = now;

            //Console.WriteLine($"Temp: {temperature} Delta: {_delta}");
            if (flipflop)
            {
                if (ActiveGraph.temperature > 0.1)
                {
                    RenderVelocity(_positionsBuffer1, _velocityBuffer1, _velocityBuffer2, _delta, ActiveGraph.temperature);
                    RenderPosition(_positionsBuffer1, _velocityBuffer2, _positionsBuffer2, _delta);
                }

                RenderNodeAttribs(_rtNodeAttribBuffer1, _rtNodeAttribBuffer2, epochMin, epochMax, _delta);
            }
            else
            {

                if (ActiveGraph.temperature > 0.1)
                {
                    RenderVelocity(_positionsBuffer2, _velocityBuffer2, _velocityBuffer1, _delta, ActiveGraph.temperature);
                    RenderPosition(_positionsBuffer2, _velocityBuffer1, _positionsBuffer1, _delta);
                }
                RenderNodeAttribs(_rtNodeAttribBuffer2, _rtNodeAttribBuffer1, epochMin, epochMax, _delta);
            }

            flipflop = !flipflop;
            if (ActiveGraph.temperature > 0.1)
                ActiveGraph.temperature *= 0.99f;
            else
                ActiveGraph.temperature = 0;

            doPicking(_gd);
            renderTestGraph(_ImGuiController);
        }

        int _mouseoverNodeID = -1;
        void doPicking(GraphicsDevice _gd)
        {
            Vector2 WidgetPos = ImGui.GetCursorScreenPos();
            Vector2 mpos = ImGui.GetMousePos();
            float mouseX = (mpos.X - WidgetPos.X);
            float mouseY = (WidgetPos.Y + _pickingStagingTexture.Height) - mpos.Y;
            bool hit = false;

            //mouse is in graph widget
            if (mouseX > 0 && mouseY > 0 && mouseX < _pickingStagingTexture.Width && mouseY < _pickingStagingTexture.Height)
            {
                MappedResourceView<RgbaFloat> readView = _gd.Map<RgbaFloat>(_pickingStagingTexture, MapMode.Read);
                RgbaFloat f = readView[(int)mouseX, (int)mouseY];
                _gd.Unmap(_pickingStagingTexture);
                if (f.A != 0) //mouse is over something on picking texture
                {
                    if (f.A == 1) //mouse is over a node
                    {
                        if (f.R != _mouseoverNodeID) //mouse is over a different node
                        {
                            Console.WriteLine($"Mouse: {mouseX},{mouseY} on node {f.R},{f.G},{f.B}");
                            _mouseoverNodeID = (int)f.R;
                        }
                        hit = true;
                    }
                }
            }
            if (!hit) //mouse is not over a node
            {
                _mouseoverNodeID = -1;
            }

        }







        private const string OldVertexCode = @"
#version 450

layout(location = 0) in vec3 Position;
layout(location = 1) in vec4 Color;
layout(location = 2) in float ActiveAnimAlpha;


layout(set = 0, binding = 0) uniform ViewBuffer
{
    mat4 View;
};

layout(location = 0) out vec4 fsin_Color;
layout(location = 1) out float fsin_ActiveAnimAlpha;

void main()
{

    gl_PointSize = 6.0f;
    gl_Position = View * vec4(Position,1);
    fsin_Color = Color;
    fsin_ActiveAnimAlpha = ActiveAnimAlpha;
}";


        private const string OldFragmentCode = @"
#version 450

layout(location = 0) in vec4 fsin_Color;
layout(location = 1) in float fsin_ActiveAnimAlpha;
layout(location = 0) out vec4 fsout_Color;


layout(set = 1, binding = 0) uniform AnimBuffer
{
    int AnimEnabled;
};


void main()
{
  
    fsout_Color = (AnimEnabled == 1) ? vec4(fsin_Color.xyz, fsin_ActiveAnimAlpha) : fsin_Color;
}";







        bool setMouseoverNode()
        {
            //if (ActiveGraph == null)
            //	return false;
            /*
			float zmul = ActiveGraph.zoomMultiplier();
			if (!_rgatState.should_show_external_symbols(zmul) && !_rgatState.should_show_internal_symbols(zmul))
				return false;

			//mouse still over same node?
			if (activeMouseoverNode && mouseoverNodeRect.rect.contains(mousePos.x(), mousePos.y()))
			{
				node_data* nodeptr = ActiveGraph.get_protoGraph()->safe_get_node(mouseoverNode());
				if (nodeptr->external)
					return _rgatState.should_show_external_symbols(zmul);
				else
					return _rgatState.should_show_internal_symbols(zmul);
			}

			//mouse over any node?
			for each(TEXTRECT nodelabel in ActiveGraph.labelPositions)
			{
				if (nodelabel.rect.contains(mousePos.x(), mousePos.y()))
				{
					node_data* nodeptr = ActiveGraph.get_protoGraph()->safe_get_node(nodelabel.index);
					if (nodeptr->external)
					{
						if (!_rgatState.should_show_external_symbols(zmul))
							return false;
					}
					else
					{
						if (!_rgatState.should_show_internal_symbols(zmul))
							return false;
					}

					mouseoverNodeRect = nodelabel;
					activeMouseoverNode = true;
					return false;
				}
			}

			activeMouseoverNode = false;
			*/
            return false;
        }



        private void PerformIrregularActions()
        {
            //bool haveDisplayGraph = chooseGraphToDisplay();
            if (ActiveGraph == null)
                return;

            //highlight new nodes with highlighted address
            ActiveGraph.DoHighlightAddresses();

            if (ActiveGraph.ReplayState == PlottedGraph.REPLAY_STATE.ePlaying)
            {
                //ui->replaySlider->setValue(1000 * ActiveGraph.getAnimationPercent());
            }

            if (ActiveGraph.ReplayState == PlottedGraph.REPLAY_STATE.eEnded)
            {
                //ui->dynamicAnalysisContentsTab->stopAnimation();
            }

            if (!setMouseoverNode())
            {
                //_rgatState.labelMouseoverWidget->hide();
            }
        }



    }
}
