using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Veldrid;

namespace rgatCore
{
    public class GraphLayoutEngine
    {

        public GraphLayoutEngine(GraphicsDevice gdev, ImGuiController controller, string name)
        {
            _gd = gdev;
            _factory = gdev.ResourceFactory;
            _controller = controller;
            EngineID = name;
        }
        GraphicsDevice _gd;
        ResourceFactory _factory;
        ImGuiController _controller;
        public string EngineID { get; private set; }

        Pipeline _positionComputePipeline, _velocityComputePipeline, _nodeAttribComputePipeline;
        private Shader _positionShader, _velocityShader, _nodeAttribShader;

        DeviceBuffer _velocityParamsBuffer, _positionParamsBuffer, _attribsParamsBuffer;
        ResourceLayout _velocityComputeLayout, _positionComputeLayout, _nodeAttribComputeLayout;

        readonly object _lock = new object();

        /*
         * Having a list of other layout engines (eg previews, main widget) lets us grab the most up 
         * to date rendering of a graph without replicating the effort for each type of rendering
         */
        List<GraphLayoutEngine> _parallelLayoutEngines = new List<GraphLayoutEngine>();
        public void AddParallelLayoutEngine(GraphLayoutEngine engine)
        {
            lock (_lock)
            {
                _parallelLayoutEngines.Add(engine);
            }
        }
        List<GraphLayoutEngine> GetParallelLayoutEngines()
        {
            lock (_lock)
            {
                return _parallelLayoutEngines.ToList();
            }
        }




        /// <summary>
        /// Must have writer lock
        /// If graph buffers already stored in VRAM, load the reference
        /// Otherwise, fill GPU buffers from stored data in the plottedgraph
        /// 
        /// </summary>
        /// 


        public void ChangePreset(PlottedGraph graph)
        {
            Logging.RecordLogEvent($"ChangePreset to style {graph.ActiveLayoutStyle}", Logging.LogFilterType.BulkDebugLogFile);
            graph.ResetLayoutStats();
            graph.IncreaseTemperature(100f);
        }


        /// <summary>
        /// Iterates over the position of every node, translating it to a screen position
        /// Returns the offsets of the furthest nodes of the edges of the screen
        /// To fit the graph in the screen, each offset needs to be as close to be as small as possible without being smaller than 0
        /// 
        /// Acquires reader lock
        /// </summary>
        /// <param name="graphWidgetSize">Size of the graph widget</param>
        /// <param name="xoffsets">xoffsets.X = distance of furthest left node from left of the widget. Ditto xoffsets.Y for right node/side</param>
        /// <param name="yoffsets">yoffsets.X = distance of furthest bottom node from base of the widget. Ditto yoffsets.Y for top node/side</param>
        /// <param name="yoffsets">yoffsets.X = distance of furthest bottom node from base of the widget. Ditto yoffsets.Y for top node/side</param>
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





        public bool GetPreviewFitOffsets(Vector2 graphWidgetSize, PlottedGraph graph, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets)
        {
            Logging.RecordLogEvent($"GetPreviewFitOffsets Start {graph.tid} layout {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
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

            _velocityParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<VelocityShaderParams>(), BufferUsage.UniformBuffer, name: "VelocityShaderParams");

            ComputePipelineDescription VelocityCPD = new ComputePipelineDescription(_velocityShader, _velocityComputeLayout, 16, 16, 1);

            _velocityComputePipeline = _factory.CreateComputePipeline(VelocityCPD);

            _positionComputeLayout = _factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("blockData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));


            byte[] positionShaderBytes = _controller.LoadEmbeddedShaderCode(_factory, "sim-position", ShaderStages.Vertex);
            _positionShader = _factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, positionShaderBytes, "FS")); //todo ... not fragment

            ComputePipelineDescription PositionCPD = new ComputePipelineDescription(_positionShader, _positionComputeLayout, 16, 16, 1);
            _positionComputePipeline = _factory.CreateComputePipeline(PositionCPD);
            _positionParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<PositionShaderParams>(), BufferUsage.UniformBuffer, name: "PositionShaderParams");

            byte[] noteattribShaderBytes = _controller.LoadEmbeddedShaderCode(_factory, "sim-nodeAttrib", ShaderStages.Vertex);
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
        /// Find fastest node speed
        /// </summary>
        /// <param name="textureSize"></param>
        /// <param name="buf"></param>
        /// <param name="maxLimit"></param>
        /// <returns></returns>
        float FindHighXYZ(DeviceBuffer buf)
        {
            Logging.RecordLogEvent($"FindHighXYZ  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, buf);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            float highest = 0f;
            for (uint index = 0; index < destinationReadView.Count; index += 4)
            {
                if (destinationReadView[index + 3] != 1.0f) break; //past end of nodes
                if (Math.Abs(destinationReadView[index]) > highest) highest = Math.Abs(destinationReadView[index]);
                if (Math.Abs(destinationReadView[index + 1]) > highest) highest = Math.Abs(destinationReadView[index + 1]);
                if (Math.Abs(destinationReadView[index + 2]) > highest) highest = Math.Abs(destinationReadView[index + 2]);
            }
            _gd.Unmap(destinationReadback);
            VeldridGraphBuffers.DoDispose(destinationReadback);
            return highest;
        }

        public ulong Compute(CommandList cl, PlottedGraph graph, int mouseoverNodeID, bool useAnimAttribs)
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
            Logging.RecordLogEvent($"Marker Compute start {EngineID} graph {graph.tid}", Logging.LogFilterType.BulkDebugLogFile);

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

            ResourceSet attribComputeResourceSet = null;
            ResourceSetDescription velocity_rsrc_desc, pos_rsrc_desc, attr_rsrc_desc;
            GraphLayoutState layout = graph.LayoutState;
            DeviceBuffer inputAttributes;
            DeviceBuffer outputAttributes;

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
                inputAttributes = layout.AttributesVRAM1;
                outputAttributes = layout.AttributesVRAM2;

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
                inputAttributes = layout.AttributesVRAM2;
                outputAttributes = layout.AttributesVRAM1;
            }

            ResourceSet velocityComputeResourceSet = _factory.CreateResourceSet(velocity_rsrc_desc);
            ResourceSet posRS = _factory.CreateResourceSet(pos_rsrc_desc);

            cl.Begin();


            bool forceComputationActive =
                GlobalConfig.LayoutPositionsActive &&
                graph.temperature > 0 && (
                graph.LayoutState.ActivatingPreset || LayoutStyles.IsForceDirected(graph.ActiveLayoutStyle)
                );

            if (forceComputationActive)
            {
                RenderVelocity(cl, graph, velocityComputeResourceSet, delta, graph.temperature);
                RenderPosition(cl, graph, posRS, delta);
                layout.IncrementVersion();

                graph.temperature *= Layout_Constants.TemperatureStepMultiplier;
                if (graph.temperature <= Layout_Constants.MinimumTemperature)
                    graph.temperature = 0;
            }


            if (GlobalConfig.LayoutAttribsActive)
            {
                attribComputeResourceSet = _factory.CreateResourceSet(attr_rsrc_desc);
                RenderNodeAttribs(cl, graph, inputAttributes, attribComputeResourceSet, delta, mouseoverNodeID, useAnimAttribs);
            }


            cl.End();

            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();

            //DebugPrintOutputFloatBuffer(inputAttributes, "AttsIn", 64);
            //DebugPrintOutputFloatBuffer(outputAttributes, "AttsOut", 64);

            if (graph.LayoutState.ActivatingPreset && graph.LayoutState.IncrementPresetSteps() > 10) //todo look at this again, should it be done after compute?
            {
                //when the nodes are near their targets, instead of bouncing around while coming to a slow, just snap them into position
                float highest = FindHighXYZ(layout.VelocitiesVRAM1);
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
                lastComputeMS.Add(timer.ElapsedMilliseconds);
                if (lastComputeMS.Count > GlobalConfig.StatisticsTimeAvgWindow)
                    lastComputeMS = lastComputeMS.TakeLast(GlobalConfig.StatisticsTimeAvgWindow).ToList();
                AverageComputeTime = lastComputeMS.Average();
            }
            if (GlobalConfig.LayoutPositionsActive)
                graph.RecordComputeTime(timer.ElapsedMilliseconds);

            Logging.RecordLogEvent($"Marker Compute end {EngineID} graph {graph.tid}", Logging.LogFilterType.BulkDebugLogFile);

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


        //todo : everything in here should be class variables defined once
        unsafe void RenderPosition(CommandList cl, PlottedGraph graph, ResourceSet resources, float delta)
        {

            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, positions));
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, velocities));


            Logging.RecordLogEvent($"RenderPosition  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            var textureSize = graph.LinearIndexTextureSize();

            uint width = textureSize;
            uint height = textureSize;

            uint fixedNodes = 0;
            if (graph.ActiveLayoutStyle == LayoutStyles.Style.ForceDirected3DBlocks) fixedNodes = 1;
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
            cl.Dispatch((uint)Math.Ceiling(graph.LayoutState.PositionsVRAM1.SizeInBytes / (256.0 * sizeof(Vector4))), 1, 1);
        }




        //todo : everything in here should be class variables defined once
        unsafe void RenderVelocity(CommandList cl, PlottedGraph graph, ResourceSet resources, float delta, float temperature)
        {
            Logging.RecordLogEvent($"RenderVelocity  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            var textureSize = graph.LinearIndexTextureSize();
            uint fixedNodes = 0;
            if (graph.ActiveLayoutStyle == LayoutStyles.Style.ForceDirected3DBlocks) fixedNodes = 1;

            VelocityShaderParams parms = new VelocityShaderParams
            {
                delta = delta,
                k = 100f,
                temperature = Math.Min(temperature, GlobalConfig.NodeSoftSpeedLimit),
                NodesTexWidth = (uint)Math.Sqrt(graph.LayoutState.PositionsVRAM1.SizeInBytes) / 4,//no longer used?
                EdgeCount = (uint)graph.InternalProtoGraph.EdgeList.Count,
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

            public int fff;     // neighbor data
            public bool isAnimated;

            private readonly uint _padding2b;
            private readonly uint _padding2c;
        }


        unsafe void RenderNodeAttribs(CommandList cl, PlottedGraph graph, DeviceBuffer inputAttributes,
            ResourceSet resources, float delta, int mouseoverNodeID, bool useAnimAttribs)
        {
            Logging.RecordLogEvent($"RenderNodeAttribs  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            uint textureSize = graph.LinearIndexTextureSize();
            AttribShaderParams parms = new AttribShaderParams
            {
                delta = delta,
                selectedNode = mouseoverNodeID,
                edgesTexCount = (int)graph.LayoutState.EdgeConnections.SizeInBytes / 4,
                fff = (int)0,
                hoverMode = 1,
                isAnimated = useAnimAttribs
            };


            graph.GetActiveNodeIDs(out List<uint> pulseNodes, out List<uint> lingerNodes, out uint[] deactivatedNodes);

            Logging.RecordLogEvent($"RenderNodeAttribs creaters  {this.EngineID} updating attribsbuf {inputAttributes.Name}", Logging.LogFilterType.BulkDebugLogFile);

            cl.UpdateBuffer(_attribsParamsBuffer, 0, parms);


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

            float currentPulseAlpha = Math.Max(GlobalConfig.AnimatedFadeMinimumAlpha, GraphicsMaths.getPulseAlpha());
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

            cl.SetPipeline(_nodeAttribComputePipeline);
            cl.SetComputeResourceSet(0, resources);
            cl.Dispatch((uint)Math.Ceiling(inputAttributes.SizeInBytes / (256.0 * 4.0 * 4.0)), 1, 1);

            //DebugPrintOutputFloatBuffer((int)textureSize, attribBufOut, "attrib Computation Done. Result: ", 32);

        }



























        List<long> lastComputeMS = new List<long>() { 0 };
        public double AverageComputeTime { get; private set; } = 0;





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
            VeldridGraphBuffers.DoDispose(destinationReadback);
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
