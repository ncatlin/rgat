using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Veldrid;

namespace rgat
{
    public class GraphLayoutEngine
    {
        /// <summary>
        /// Runs the computation shaders on graph layout buffers 
        /// </summary>
        /// <param name="gdev">GPU GraphicsDevice to perform computation with</param>
        /// <param name="controller">An ImGuiController to load shader code from [todo: remove it from the controller, will need these in non-imgui runners]</param>
        /// <param name="name">A name to identify the layout engine in logfiles</param>
        public GraphLayoutEngine(GraphicsDevice gdev, ImGuiController controller, string name)
        {
            _gd = gdev;
            _factory = gdev.ResourceFactory;
            _controller = controller;
            EngineID = name;
        }

        readonly GraphicsDevice _gd;
        readonly ResourceFactory _factory;
        readonly ImGuiController _controller;

        /// <summary>
        /// The unique name of the layout engine
        /// </summary>
        public string EngineID { get; private set; }

        Pipeline _positionComputePipeline, _velocityComputePipeline, _nodeAttribComputePipeline;
        private Shader _positionShader, _velocityShader, _nodeAttribShader;

        DeviceBuffer _velocityParamsBuffer, _positionParamsBuffer, _attribsParamsBuffer;
        ResourceLayout _velocityComputeLayout, _positionComputeLayout, _nodeAttribComputeLayout;

        readonly object _lock = new object();


        /// <summary>
        /// Iterates over the position of every node, translating it to a screen position
        /// Returns the offsets of the furthest nodes of the edges of the screen
        /// To fit the graph in the screen, each offset needs to be as small as possible above 0
        /// 
        /// Acquires reader lock
        /// </summary>
        /// <param name="graph">The graph being measured</param>
        /// <param name="graphWidgetSize">Size of the graph widget</param>
        /// <param name="xoffsets">xoffsets.X = distance of furthest left node from left of the widget. Ditto xoffsets.Y for right node/side</param>
        /// <param name="yoffsets">yoffsets.X = distance of furthest bottom node from base of the widget. Ditto yoffsets.Y for top node/side</param>
        /// <param name="zoffsets">zoffsets.X = distance of furthest bottom node from base of the widget. Ditto yoffsets.Y for top node/side</param>
        public void GetScreenFitOffsets(PlottedGraph graph, Matrix4x4 worldView, Vector2 graphWidgetSize,
            out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets)
        {
            Logging.RecordLogEvent($"GetScreenFitOffsets ", Logging.LogFilterType.BulkDebugLogFile);
            float aspectRatio = graphWidgetSize.X / graphWidgetSize.Y;
            Matrix4x4 projectionMatrix = graph.GetProjectionMatrix(aspectRatio);

            Vector2 xlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ylimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 zlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ev = new Vector2(0, 0);
            Vector2 xmin = ev, xmax = ev, ymin = ev, ymax = ev, zmin = ev, zmax = ev;
            float maxWorldX = 0, maxWorldY = 0, maxWorldZ = 0;
            int fZ1 = 0;
            int fZ2 = 0;

            float[] positions = graph.LayoutState.DownloadVRAMPositions();


            if (positions.Length < 4)
            {
                xoffsets = new Vector2(0, 0);
                yoffsets = new Vector2(0, 0);
                zoffsets = new Vector2(0, 0);
            }
            else
            {
                for (int idx = 0; idx < positions.Length; idx += 4)
                {
                    if (positions[idx + 3] == -1) break;
                    float x = positions[idx];
                    float y = positions[idx + 1];
                    float z = positions[idx + 2];

                    maxWorldX = Math.Max(maxWorldX, Math.Abs(x));
                    maxWorldY = Math.Max(maxWorldY, Math.Abs(y));
                    maxWorldZ = Math.Max(maxWorldZ, Math.Abs(z));
                    Vector3 worldpos = new Vector3(x, y, z);

                    Vector2 ndcPos = GraphicsMaths.WorldToNDCPos(worldpos, worldView, projectionMatrix);

                    if (ndcPos.X < xlimits.X) { xlimits = new Vector2(ndcPos.X, xlimits.Y); xmin = ndcPos; }
                    if (ndcPos.X > xlimits.Y) { xlimits = new Vector2(xlimits.X, ndcPos.X); xmax = ndcPos; }
                    if (ndcPos.Y < ylimits.X) { ylimits = new Vector2(ndcPos.Y, ylimits.Y); ymin = ndcPos; }
                    if (ndcPos.Y > ylimits.Y) { ylimits = new Vector2(ylimits.X, ndcPos.Y); ymax = ndcPos; }
                    if (worldpos.Z < zlimits.X) { zlimits = new Vector2(worldpos.Z, zlimits.Y); zmin = ndcPos; fZ1 = (idx / 4); }
                    if (worldpos.Z > zlimits.Y) { zlimits = new Vector2(zlimits.X, worldpos.Z); zmax = ndcPos; fZ2 = (idx / 4); }
                }

                Vector2 minxS = GraphicsMaths.NdcToScreenPos(xmin, graphWidgetSize);
                Vector2 maxxS = GraphicsMaths.NdcToScreenPos(xmax, graphWidgetSize);
                Vector2 minyS = GraphicsMaths.NdcToScreenPos(ymin, graphWidgetSize);
                Vector2 maxyS = GraphicsMaths.NdcToScreenPos(ymax, graphWidgetSize);
                xoffsets = new Vector2(minxS.X, graphWidgetSize.X - maxxS.X);
                yoffsets = new Vector2(minyS.Y, graphWidgetSize.Y - maxyS.Y);
                zoffsets = new Vector2(zlimits.X - graph.CameraZoom, zlimits.Y - graph.CameraZoom);
            }
        }


        /// <summary>
        /// Iterate over all the nodes and figure out how far they are from the edges of the screen in each dimension
        /// </summary>
        /// <param name="graphWidgetSize">Size of the rendering widget</param>
        /// <param name="graph">Graph being displayed in the widget</param>
        /// <param name="xoffsets">Furthest from the left and right sides of the widget</param>
        /// <param name="yoffsets">Furthest from the top and bottom of the widget</param>
        /// <param name="zoffsets">Furthest from in front of/behind the camera lens in the Z direction</param>
        /// <returns>true if a meaningful result was returned</returns>
        public bool GetPreviewFitOffsets(Vector2 graphWidgetSize, PlottedGraph graph, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets)
        {
            Logging.RecordLogEvent($"GetPreviewFitOffsets Start {graph.TID} layout {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            float zoom;
            xoffsets = new Vector2(0, 0);
            yoffsets = new Vector2(0, 0);
            zoffsets = new Vector2(0, 0);

            zoom = graph.PreviewCameraZoom;

            float[] positions = graph.LayoutState.DownloadVRAMPositions();
            float aspectRatio = graphWidgetSize.X / graphWidgetSize.Y;

            //todo: difference is here, merge to make one function?
            Matrix4x4 projection = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, aspectRatio, 1, 50000);
            Vector3 translation = new Vector3(graph.PreviewCameraXOffset, graph.PreviewCameraYOffset, graph.PreviewCameraZoom);
            Matrix4x4 worldView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0) * Matrix4x4.CreateTranslation(translation);

            Vector2 xlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ylimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 zlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ev = new Vector2(0, 0);
            Vector2 xmin = ev, xmax = ev, ymin = ev, ymax = ev;


            bool result;
            if (positions.Length < 4)
            {
                result = false;
            }
            else
            {
                result = true;
                for (int idx = 0; idx < positions.Length; idx += 4)
                {
                    if (positions[idx + 3] == -1) break;
                    float x = positions[idx];
                    float y = positions[idx + 1];
                    float z = positions[idx + 2];
                    Vector3 worldpos = new Vector3(x, y, z);


                    Vector2 ndcPos = GraphicsMaths.WorldToNDCPos(worldpos, worldView, projection);
                    if (ndcPos.X < xlimits.X) { xlimits = new Vector2(ndcPos.X, xlimits.Y); xmin = ndcPos; }
                    if (ndcPos.X > xlimits.Y) { xlimits = new Vector2(xlimits.X, ndcPos.X); xmax = ndcPos; }
                    if (ndcPos.Y < ylimits.X) { ylimits = new Vector2(ndcPos.Y, ylimits.Y); ymin = ndcPos; }
                    if (ndcPos.Y > ylimits.Y) { ylimits = new Vector2(ylimits.X, ndcPos.Y); ymax = ndcPos; }
                    if (worldpos.Z < zlimits.X) { zlimits = new Vector2(worldpos.Z, zlimits.Y); }
                    if (worldpos.Z > zlimits.Y) { zlimits = new Vector2(zlimits.X, worldpos.Z); }
                }

                Vector2 minxS = GraphicsMaths.NdcToScreenPos(xmin, graphWidgetSize);
                Vector2 maxxS = GraphicsMaths.NdcToScreenPos(xmax, graphWidgetSize);
                xoffsets = new Vector2(minxS.X, graphWidgetSize.X - maxxS.X);

                Vector2 minyS = GraphicsMaths.NdcToScreenPos(ymin, graphWidgetSize);
                Vector2 maxyS = GraphicsMaths.NdcToScreenPos(ymax, graphWidgetSize);
                yoffsets = new Vector2(minyS.Y, graphWidgetSize.Y - maxyS.Y);

                zoffsets = new Vector2(zlimits.X - zoom, zlimits.Y - zoom);
            }

            Logging.RecordLogEvent($"GetPreviewFitOffsets exit", Logging.LogFilterType.BulkDebugLogFile);
            return result;
        }


        unsafe void SetupComputeResources()
        {
            if (!_gd.Features.ComputeShader) { Console.WriteLine("Error: No computeshader feature"); return; }

            byte[]? velocityShaderBytes = _controller.LoadEmbeddedShaderCode(_factory, "sim-velocity", ShaderStages.Fragment);
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

            _velocityParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<VelocityShaderParams>(), BufferUsage.UniformBuffer, name: "VelocityShaderParams");

            ComputePipelineDescription VelocityCPD = new ComputePipelineDescription(_velocityShader, _velocityComputeLayout, 16, 16, 1);

            _velocityComputePipeline = _factory.CreateComputePipeline(VelocityCPD);

            _positionComputeLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));


            byte[]? positionShaderBytes = _controller.LoadEmbeddedShaderCode(_factory, "sim-position", ShaderStages.Vertex);
            _positionShader = _factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, positionShaderBytes, "FS")); //todo ... not fragment

            ComputePipelineDescription PositionCPD = new ComputePipelineDescription(_positionShader, _positionComputeLayout, 16, 16, 1);
            _positionComputePipeline = _factory.CreateComputePipeline(PositionCPD);
            _positionParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<PositionShaderParams>(), BufferUsage.UniformBuffer, name: "PositionShaderParams");

            byte[]? noteattribShaderBytes = _controller.LoadEmbeddedShaderCode(_factory, "sim-nodeAttrib", ShaderStages.Vertex);
            _nodeAttribShader = _factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, noteattribShaderBytes, "FS"));

            _nodeAttribComputeLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("nodeAttrib", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));
            _attribsParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<AttribShaderParams>(), BufferUsage.UniformBuffer, name: "AttribShaderParams");



            ComputePipelineDescription attribCPL = new ComputePipelineDescription(_nodeAttribShader, _nodeAttribComputeLayout, 16, 16, 1);

            _nodeAttribComputePipeline = _factory.CreateComputePipeline(attribCPL);
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
            public uint snappingToPreset;
            public uint nodeCount;

            //private readonly uint _padding1; //must be multiple of 16
        }


        /// <summary>
        /// Must have read lock to call
        /// Find the node with the highest x/y/z dimension. Ignores w.
        /// </summary>
        /// <param name="buf">Device buffer containing values (can be speeds or positions)</param>
        /// <param name="nodeCount">Number of nodes to iterate over</param>
        /// <param name="highIndex">set to the index of the highest node</param>
        /// <returns></returns>
        float FindHighXYZ(DeviceBuffer buf, int nodeCount, out int highIndex)
        {
            Logging.RecordLogEvent($"FindHighXYZ  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, buf);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            float highest = 0f;
            highIndex = 0;
            for (int testNodeIndex = 0; testNodeIndex < nodeCount; testNodeIndex += 1)
            {
                int bufIndex = testNodeIndex * 4;
                Debug.Assert(bufIndex + 3 < destinationReadView.Count);

                if (Math.Abs(destinationReadView[bufIndex]) > highest)
                {
                    highest = Math.Abs(destinationReadView[bufIndex]);
                    highIndex = bufIndex;
                }
                if (Math.Abs(destinationReadView[bufIndex + 1]) > highest)
                {
                    highest = Math.Abs(destinationReadView[bufIndex + 1]);
                    highIndex = bufIndex + 1;
                }
                if (Math.Abs(destinationReadView[bufIndex + 2]) > highest)
                {
                    highest = Math.Abs(destinationReadView[bufIndex + 2]);
                    highIndex = bufIndex + 2;
                }
            }
            highIndex = (int)Math.Floor(highIndex / 4f);
            _gd.Unmap(destinationReadback);
            VeldridGraphBuffers.VRAMDispose(destinationReadback);
            return highest;
        }


        /// <summary>
        /// Do the actual computation of graph layout and animation
        /// Uses the velocity shader to adjust the velocity based on relative positions
        /// Uses the position shader to move the nodes at the calculated velocity
        /// Adjusts the size/alpha of nodes based on the attribute buffer
        /// </summary>
        /// <param name="cl">Thread-specific command list</param>
        /// <param name="graph">Graph to perform computation on</param>
        /// <param name="mouseoverNodeID">The index of the node the users mouse is hovering over</param>
        /// <param name="isAnimated">If the graph should have animation attributes computed (ie: main graph with live/replay active)</param>
        /// <returns>The version ID associated with the produced graph layout computed</returns>
        public ulong Compute(CommandList cl, PlottedGraph graph, int mouseoverNodeID, bool isAnimated)
        {
            ulong newversion;
            Stopwatch timer = new Stopwatch();
            timer.Start();

            if (graph.DrawnEdgesCount == 0 || !GlobalConfig.LayoutAllComputeEnabled)
            {
                newversion = graph.LayoutState.RenderVersion;
                return newversion;
            }

            int edgesCount = graph.DrawnEdgesCount;
            Logging.RecordLogEvent($"Marker Compute start {EngineID} graph {graph.TID}", Logging.LogFilterType.BulkDebugLogFile);

            Debug.Assert(graph != null, "Layout engine called to compute without active graph");
            if (_velocityShader == null)
            {
                SetupComputeResources();
            }

            graph.LayoutState.Lock.EnterUpgradeableReadLock();

            graph.AddNewEdgesToLayoutBuffers(edgesCount);


            var now = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
            float delta = Math.Min((now - graph.lastRenderTime) / 1000f, 1.0f);// safety cap on large deltas
            delta *= (graph.LayoutState.ActivatingPreset ? 7.5f : 1.0f); //without this the preset animation will 'bounce'

            graph.lastRenderTime = now;

            ResourceSet? attribComputeResourceSet = null;
            ResourceSetDescription velocity_rsrc_desc, pos_rsrc_desc, attr_rsrc_desc;
            GraphLayoutState layout = graph.LayoutState;
            DeviceBuffer inputAttributes;

            //todo set this on layout change
            bool isForceDirected = CONSTANTS.LayoutStyles.IsForceDirected(graph.ActiveLayoutStyle);

            bool forceComputationActive = GlobalConfig.LayoutPositionsActive && graph.Temperature > 0 && (graph.LayoutState.ActivatingPreset || isForceDirected);

            if (graph.LayoutState.flip())
            {
                //todo unified resource layout
                velocity_rsrc_desc = new ResourceSetDescription(_velocityComputeLayout, _velocityParamsBuffer,
                    layout.PositionsVRAM1, layout.PresetPositions, layout.VelocitiesVRAM1,
                    layout.EdgeConnectionIndexes, layout.EdgeConnections, layout.EdgeStrengths, layout.BlockMetadata,
                layout.VelocitiesVRAM2);

                pos_rsrc_desc = new ResourceSetDescription(_positionComputeLayout, _positionParamsBuffer,
                   layout.PositionsVRAM1, layout.VelocitiesVRAM2, layout.BlockMetadata,
                   layout.PositionsVRAM2);

                attr_rsrc_desc = new ResourceSetDescription(_nodeAttribComputeLayout,
                    _attribsParamsBuffer, layout.AttributesVRAM1, layout.EdgeConnectionIndexes,
                    layout.EdgeConnections, layout.AttributesVRAM2);
                inputAttributes = layout.AttributesVRAM1!;
                //outputAttributes = layout.AttributesVRAM2;

            }

            else
            {
                velocity_rsrc_desc = new ResourceSetDescription(_velocityComputeLayout,
                _velocityParamsBuffer,
                layout.PositionsVRAM2, layout.PresetPositions, layout.VelocitiesVRAM2,
                layout.EdgeConnectionIndexes, layout.EdgeConnections, layout.EdgeStrengths, layout.BlockMetadata,
                layout.VelocitiesVRAM1);

                pos_rsrc_desc = new ResourceSetDescription(_positionComputeLayout, _positionParamsBuffer,
                 layout.PositionsVRAM2, layout.VelocitiesVRAM1, layout.BlockMetadata,
                  layout.PositionsVRAM1);

                attr_rsrc_desc = new ResourceSetDescription(_nodeAttribComputeLayout,
                    _attribsParamsBuffer, layout.AttributesVRAM2, layout.EdgeConnectionIndexes,
                    layout.EdgeConnections, layout.AttributesVRAM1);
                inputAttributes = layout.AttributesVRAM2!;
                //outputAttributes = layout.AttributesVRAM1;
            }

            ResourceSet velocityComputeResourceSet = _factory.CreateResourceSet(velocity_rsrc_desc);
            ResourceSet posRS = _factory.CreateResourceSet(pos_rsrc_desc);

            cl.Begin();



            if (forceComputationActive)
            {
                RenderVelocity(cl, graph, velocityComputeResourceSet, delta, graph.Temperature);
                RenderPosition(cl, graph, posRS, delta);
                layout.IncrementVersion();

                graph.Temperature *= CONSTANTS.Layout_Constants.TemperatureStepMultiplier;
                if (graph.Temperature <= CONSTANTS.Layout_Constants.MinimumTemperature)
                    graph.Temperature = 0;

            }

            if (rgatUI.ResponsiveKeyHeld)
            {
                // todo - don't iterate over every node every frame!
                // not sure whether to make this timer based or do it in the shader
                // it looks pretty bad doing it every 10 frames
                // for now just do it every 3 frames

                if (forceComputationActive && (layout.RenderVersion % 3) == 0)
                {

                    float highPosition = FindHighXYZ(graph.LayoutState.PositionsVRAM1, graph.ComputeBufferNodeCount, out int furthestNodeIdx);
                    if (furthestNodeIdx != -1)
                    {
                        graph.SetFurthestNodeDimension(furthestNodeIdx, highPosition);
                    }

                }
            }

            if (GlobalConfig.LayoutAttribsActive)
            {
                attribComputeResourceSet = _factory.CreateResourceSet(attr_rsrc_desc);
                RenderNodeAttribs(cl, graph, inputAttributes, attribComputeResourceSet, delta, mouseoverNodeID, isAnimated);
            }


            cl.End();

            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            //DebugPrintOutputFloatBuffer(layout.AttributesVRAM1, "Atts1", 32);
            //DebugPrintOutputFloatBuffer(layout.AttributesVRAM2, "Atts2", 32);

            if (graph.LayoutState.ActivatingPreset && graph.LayoutState.IncrementPresetSteps() > 10) //todo look at this again, should it be done after compute?
            {
                //when the nodes are near their targets, instead of bouncing around while coming to a slow, just snap them into position
                float highest = FindHighXYZ(layout.VelocitiesVRAM1, graph.ComputeBufferNodeCount, out int highIndex);
                Console.WriteLine($"Presetspeed: {highest}");
                if (highest < 1)
                {
                    Console.WriteLine("Preset done");
                    graph.LayoutState.CompleteLayoutChange();
                }
            }
            graph.LayoutState.Lock.ExitUpgradeableReadLock();

            //should we be dispose/recreating these? probably not. todo
            if (attribComputeResourceSet != null)
                _gd.DisposeWhenIdle(attribComputeResourceSet);//attribComputeResourceSet.Dispose();
            if (velocityComputeResourceSet != null)
                _gd.DisposeWhenIdle(velocityComputeResourceSet);//velocityComputeResourceSet.Dispose();
            if (posRS != null)
                _gd.DisposeWhenIdle(posRS);//posRS.Dispose();

            newversion = layout.RenderVersion;


            timer.Stop();
            lock (_lock)
            {
                _lastComputeMS.Add(timer.ElapsedMilliseconds);
                if (_lastComputeMS.Count > GlobalConfig.StatisticsTimeAvgWindow)
                    _lastComputeMS = _lastComputeMS.TakeLast(GlobalConfig.StatisticsTimeAvgWindow).ToList();
                AverageComputeTime = _lastComputeMS.Average();
            }
            if (GlobalConfig.LayoutPositionsActive)
                graph.RecordComputeTime(timer.ElapsedMilliseconds);

            Logging.RecordLogEvent($"Marker Compute end {EngineID} graph {graph.TID}", Logging.LogFilterType.BulkDebugLogFile);

            return newversion;
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
            private readonly uint _padding1;
            private readonly uint _padding3;
            private readonly bool _padding4;

        }


        /// <summary>
        /// Used the velocity buffer to move the nodes in the positions buffer
        /// </summary>
        /// <param name="cl">Thread-specific Veldrid command list to use</param>
        /// <param name="graph">PlottedGraph to compute</param>
        /// <param name="resources">Position shader resource set</param>
        /// <param name="delta">A float representing how much time has passed since the last frame. Higher values => bigger movements</param>
        unsafe void RenderPosition(CommandList cl, PlottedGraph graph, ResourceSet resources, float delta)
        {

            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, positions));
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, velocities));


            Logging.RecordLogEvent($"RenderPosition  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            var textureSize = graph.LinearIndexTextureSize();

            uint width = textureSize;
            uint height = textureSize;

            uint fixedNodes = 0;
            if (graph.ActiveLayoutStyle == CONSTANTS.LayoutStyles.Style.ForceDirected3DBlocks) fixedNodes = 1;
            PositionShaderParams parms = new PositionShaderParams
            {
                delta = delta,
                NodesTexWidth = textureSize,
                blockNodeSeperation = 60,
                fixedInternalNodes = fixedNodes,
                activatingPreset = graph.LayoutState.ActivatingPreset
            };

            //Console.WriteLine($"POS Parambuffer Size is {(uint)Unsafe.SizeOf<PositionShaderParams>()}");

            cl.UpdateBuffer(_positionParamsBuffer, 0, parms);
            cl.SetPipeline(_positionComputePipeline);
            cl.SetComputeResourceSet(0, resources);
            cl.Dispatch((uint)Math.Ceiling(graph.LayoutState.PositionsVRAM1!.SizeInBytes / (256.0 * sizeof(Vector4))), 1, 1);
        }



        /// <summary>
        /// Pass the graph plot through the velocity compute shader, to adjust the node velocity based on the positions of other nodes
        /// </summary>
        /// <param name="cl">Thread-specific Veldrid command list to use</param>
        /// <param name="graph">PlottedGraph to compute</param>
        /// <param name="resources">Velocity shader resource set</param>
        /// <param name="delta">A float representing how much time has passed since the last frame. Higher values => bigger movements</param>
        /// <param name="temperature">The activity level of the layout state. Higher balues => bigger movements</param>
        unsafe void RenderVelocity(CommandList cl, PlottedGraph graph, ResourceSet resources, float delta, float temperature)
        {
            Logging.RecordLogEvent($"RenderVelocity  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            uint fixedNodes = 0;
            if (graph.ActiveLayoutStyle == CONSTANTS.LayoutStyles.Style.ForceDirected3DBlocks) fixedNodes = 1;

            VelocityShaderParams parms = new VelocityShaderParams
            {
                delta = delta,
                k = 100f,
                temperature = Math.Min(temperature, GlobalConfig.NodeSoftSpeedLimit),
                NodesTexWidth = (uint)Math.Sqrt(graph.LayoutState.PositionsVRAM1!.SizeInBytes) / 4,//no longer used?
                EdgeCount = (uint)graph.InternalProtoGraph.EdgeCount,
                fixedInternalNodes = fixedNodes,
                snappingToPreset = (uint)(graph.LayoutState.ActivatingPreset ? 1 : 0),
                nodeCount = (uint)graph.LayoutState.PositionsVRAM1.SizeInBytes / 16
            };

            Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} submit", Logging.LogFilterType.BulkDebugLogFile);

            cl.UpdateBuffer(_velocityParamsBuffer, 0, parms);
            cl.SetPipeline(_velocityComputePipeline);
            cl.SetComputeResourceSet(0, resources);
            cl.Dispatch((uint)Math.Ceiling(graph.LayoutState.PositionsVRAM1.SizeInBytes / (256.0 * sizeof(Vector4))), 1, 1);

            Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} done", Logging.LogFilterType.BulkDebugLogFile);
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
            public int edgesTexCount;     // will be the same for neighbors

            public float MinimumAlpha;
            public bool isAnimated;

            private readonly uint _padding2b;
            private readonly uint _padding2c;
        }


        /// <summary>
        /// Update the node attributes compute VRAM buffer (alpha, node size, mouseover details)
        /// </summary>
        /// <param name="cl">Thread-specific CommandList</param>
        /// <param name="graph">ProtoGraph being drawn</param>
        /// <param name="inputAttributes">Attributes buffer being updated</param>
        /// <param name="resources">Shader resources ResourceSet</param>
        /// <param name="delta">Time-delta from the last update</param>
        /// <param name="mouseoverNodeID">Index of the node the mouse is over</param>
        /// <param name="useAnimAttribs">Flag to specify the graph is in animated-alpha mode</param>
        unsafe void RenderNodeAttribs(CommandList cl, PlottedGraph graph, DeviceBuffer inputAttributes,
            ResourceSet resources, float delta, int mouseoverNodeID, bool useAnimAttribs)
        {
            Logging.RecordLogEvent($"RenderNodeAttribs  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            AttribShaderParams parms = new AttribShaderParams
            {
                delta = delta,
                selectedNode = mouseoverNodeID,
                edgesTexCount = (int)graph.LayoutState.EdgeConnections!.SizeInBytes / 4,
                MinimumAlpha = GlobalConfig.MinimumAlpha,
                hoverMode = 1,
                isAnimated = useAnimAttribs
            };


            graph.GetActiveNodeIndexes(out List<uint> pulseNodes, out List<uint> lingerNodes, out uint[] deactivatedNodes);

            Logging.RecordLogEvent($"RenderNodeAttribs creaters  {this.EngineID} updating attribsbuf {inputAttributes.Name}", Logging.LogFilterType.BulkDebugLogFile);

            cl.UpdateBuffer(_attribsParamsBuffer, 0, parms);

            float currentPulseAlpha = Math.Max(GlobalConfig.AnimatedFadeMinimumAlpha, GraphicsMaths.getPulseAlpha());

            //todo - merge contiguous regions to reduce command count
            float[] valArray = new float[3];
            foreach (uint idx in pulseNodes)
            {
                if (idx >= graph.RenderedNodeCount()) break;
                if (inputAttributes.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;

                valArray[0] = 300f; //start big
                valArray[1] = 1.0f; //full alpha
                valArray[2] = 1.0f; //pulse
                fixed (float* dataPtr = valArray)
                {
                    Debug.Assert((idx * 4 * sizeof(float) + valArray.Length * sizeof(float)) < inputAttributes.SizeInBytes);
                    cl.UpdateBuffer(inputAttributes, idx * 4 * sizeof(float), (IntPtr)dataPtr, (uint)valArray.Length * sizeof(float));
                }
            }

            //make the active node pulse
            if (graph.IsAnimated)
            {
                uint activeNodeIdx = graph.LastAnimatedVert;
                if (!lingerNodes.Contains(activeNodeIdx))
                {
                    valArray[0] = currentPulseAlpha;
                    fixed (float* dataPtr = valArray)
                    {
                        uint nodeAlphaOffset = (activeNodeIdx * 4 * sizeof(float)) + (2 * sizeof(float));
                        if (nodeAlphaOffset + sizeof(float) <= inputAttributes.SizeInBytes)
                        {
                            cl.UpdateBuffer(inputAttributes, nodeAlphaOffset, (IntPtr)dataPtr, sizeof(float));
                        }
                    }
                }

            }

            foreach (uint idx in lingerNodes)
            {
                if (idx >= graph.RenderedNodeCount()) break;
                if (inputAttributes.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;

                valArray[0] = 2.0f + currentPulseAlpha;
                fixed (float* dataPtr = valArray)
                {
                    Debug.Assert((idx * 4 * sizeof(float) + (2 * sizeof(float)) + sizeof(float)) < inputAttributes.SizeInBytes);
                    cl.UpdateBuffer(inputAttributes, idx * 4 * sizeof(float) + (2 * sizeof(float)), (IntPtr)dataPtr, sizeof(float));
                }
            }

            foreach (uint idx in deactivatedNodes)
            {
                if (idx >= graph.RenderedNodeCount()) break;
                if (inputAttributes.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;
                valArray[0] = 0.8f;
                fixed (float* dataPtr = valArray)
                {
                    Debug.Assert((idx * 4 * sizeof(float) + (2 * sizeof(float)) + sizeof(float)) < inputAttributes.SizeInBytes);
                    cl.UpdateBuffer(inputAttributes, idx * 4 * sizeof(float) + (2 * sizeof(float)), (IntPtr)dataPtr, sizeof(float));
                }
            }

            if (graph.HighlightsChanged)
            {
                ApplyHighlightAttributes(cl, graph, inputAttributes);
            }

            cl.SetPipeline(_nodeAttribComputePipeline);
            cl.SetComputeResourceSet(0, resources);
            cl.Dispatch((uint)Math.Ceiling(inputAttributes.SizeInBytes / (256.0 * 4.0 * 4.0)), 1, 1);
            //DebugPrintOutputFloatBuffer((int)textureSize, attribBufOut, "attrib Computation Done. Result: ", 32);
        }


        /// <summary>
        /// Set the highlight state of nodes in the attributes buffer so they can be animated/have their icon set
        /// </summary>
        /// <param name="cl">Thread specific Veldrid CommandList</param>
        /// <param name="graph">Graph with highlights to apply</param>
        /// <param name="attribsBuf">Attributes buffer to apply highlight data to</param>
        public void ApplyHighlightAttributes(CommandList cl, PlottedGraph graph, DeviceBuffer attribsBuf)
        {
            graph.GetHighlightChanges(out List<uint> added, out List<uint> removed);

            if (added.Any() is true)
            {
                SetHighlightedNodes(cl, added, attribsBuf, CONSTANTS.HighlightType.Addresses);
            }

            if (removed.Any() is true)
            {
                UnsetHighlightedNodes(cl, removed, attribsBuf);
            }
        }


        /// <summary>
        /// Set a node to highlighted in the attribute buffer
        /// </summary>
        /// <param name="cl">Thread specific Veldrid CommandList</param>
        /// <param name="nodeIdxs">List of node indexes to set as highlighted</param>
        /// <param name="attribsBuf">Attributes buffer to set highlight state in</param>
        /// <param name="highlightType">CONSTANTS.HighlightType of highlight [Currently unused, could be used to select the icon]</param>
        public unsafe void SetHighlightedNodes(CommandList cl, List<uint> nodeIdxs, DeviceBuffer attribsBuf, CONSTANTS.HighlightType highlightType)
        {
            float[] val = new float[] { 400f,//bigger
                1.0f, //full alpha 
                1.0f,
                1.0f //target icon
            };
            foreach (uint nidx in nodeIdxs)
            {
                fixed (float* dataPtr = val)
                {
                    cl.UpdateBuffer(attribsBuf, nidx * 4 * sizeof(float) + (0 * sizeof(float)), (IntPtr)dataPtr, (uint)val.Length * sizeof(float));
                }
            }
        }

        /// <summary>
        /// Remove a nodes highlighted state in the attribute buffer
        /// </summary>
        /// <param name="cl">Thread specific Veldrid CommandList</param>
        /// <param name="nodeIdxs">List of node indexes to set as not highlighted</param>
        /// <param name="attribsBuf">Attributes buffer to set highlight state in</param>
        public unsafe void UnsetHighlightedNodes(CommandList cl, List<uint> nodeIdxs, DeviceBuffer attribsBuf)
        {
            float[] val = new float[] { 400f,//still big, let the shader shrink it
                1.0f, //full alpha 
                0.5f, //below the deflate threshold. this is not clear, needs refactoring
                0f //no highlight
            };
            foreach (uint nidx in nodeIdxs)
            {
                fixed (float* dataPtr = val)
                {
                    cl.UpdateBuffer(attribsBuf, nidx * 4 * sizeof(float) + (0 * sizeof(float)), (IntPtr)dataPtr, (uint)val.Length * sizeof(float));
                }
            }
        }



        /// <summary>
        /// Average time in Milliseconds taken by the GPU to perform a round of velocity/position/attribute computation
        /// Average computed over GlobalConfig.StatisticsTimeAvgWindow frames
        /// </summary>
        public double AverageComputeTime { get; private set; } = 0;
        List<long> _lastComputeMS = new List<long>() { 0 };

        /// <summary>
        /// Read out some values from a DeviceBuffer and print them to the console. Just for debugging.
        /// </summary>
        /// <param name="buf">GPU DeviceBuffer to read</param>
        /// <param name="message">Caption for the printout</param>
        /// <param name="printCount">Max values to print</param>
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
            _gd.Unmap(destinationReadback);
            PrintBufferArray(outputArray, message, printCount);
            VeldridGraphBuffers.VRAMDispose(destinationReadback);
        }


        static void PrintBufferArray(float[] sourceData, string premsg, int limit = 0)
        {

            Console.WriteLine(premsg);
            for (var i = 0; i < sourceData.Length; i += 4)
            {
                if (limit > 0 && i > limit) break;
                if (i != 0 && (i % 8 == 0))
                    Console.WriteLine();
                //if (sourceData[i] == 0 && sourceData[i+1] == 0)
                if ((i + 3) > sourceData.Length) break;
                Console.Write($"{i / 4}({sourceData[i]:f3},{sourceData[i + 1]:f3},{sourceData[i + 2]:f3},{sourceData[i + 3]:f3})");
            }
            Console.WriteLine();

        }

    }
}
