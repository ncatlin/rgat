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
    /// <summary>
    /// A thread safe interface to the GPU for running compute shaders
    /// Has a position, velocity and attribute pipeline for laying out and animating graphs
    /// </summary>
    public class GraphLayoutEngine
    {
        /// <summary>
        /// Runs the computation shaders on graph layout buffers 
        /// </summary>
        /// <param name="name">A name to identify the layout engine in logfiles</param>
        public GraphLayoutEngine(string name)
        {
            EngineID = name;
        }


        /// <summary>
        /// Set the graphics device and controller once they are created
        /// </summary>
        /// <param name="gdev">GPU GraphicsDevice to perform computation with</param>
        public bool Init(GraphicsDevice gdev)
        {
            _gd = gdev;
            _factory = gdev.ResourceFactory;

            if (!SetupComputeResources())
            {
                return false;
            }

            ForceNodesLayout = new Layouts.ForceDirectedNodePipeline(_gd);
            ForceBlocksLayout = new Layouts.ForceDirectedBlockPipeline(_gd);
            PresetLayout = new Layouts.PresetSnappingPipeline(_gd);
            return true;
        }

        private GraphicsDevice? _gd;
        private ResourceFactory? _factory;

        /// <summary>
        /// The unique name of the layout engine
        /// </summary>
        public string EngineID { get; private set; }


        LayoutPipelines.LayoutPipeline? ForceNodesLayout;
        LayoutPipelines.LayoutPipeline? ForceBlocksLayout;
        LayoutPipelines.LayoutPipeline? PresetLayout;

        private Pipeline? _nodeAttribComputePipeline;
        private Shader? _nodeAttribShader;
        private DeviceBuffer? _attribsParamsBuffer;
        private ResourceLayout? _nodeAttribComputeLayout;
        private readonly object _lock = new object();

        double? attributeTime = null;
        double? attributeSetupTime = null;


        /// <summary>
        /// Iterates over the position of every node, translating it to a widget position
        /// Returns the offsets of the furthest nodes of the edges of the widget
        /// To fit the graph in the screen, each offset needs to be as small as possible above 0
        /// 
        /// Acquires reader lock
        /// </summary>
        /// <param name="graphWidgetSize">Size of the rendering widget</param>
        /// <param name="graph">Graph being displayed in the widget</param>
        /// <param name="isPreview">True if preview widget, false if main</param>
        /// <param name="xoffsets">Furthest from the left and right sides of the widget</param>
        /// <param name="yoffsets">Furthest from the top and bottom of the widget</param>
        /// <param name="zoffsets">Furthest from in front of/behind the camera lens in the Z direction</param>
        /// <returns>true if a meaningful result was returned</returns>
        public static bool GetWidgetFitOffsets(Vector2 graphWidgetSize, PlottedGraph graph, bool isPreview,
            out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets)
        {
            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"GetWidgetFitOffsets Start {graph.TID} layout", Logging.LogFilterType.BulkDebugLogFile);
            xoffsets = new Vector2(0, 0);
            yoffsets = new Vector2(0, 0);
            zoffsets = new Vector2(0, 0);
            float zoom = isPreview ? graph.CameraState.PreviewCameraZoom : graph.CameraState.MainCameraZoom;

            float aspectRatio = graphWidgetSize.X / graphWidgetSize.Y;

            Matrix4x4 translation = isPreview ? graph.CameraState.PreviewCameraTranslation : graph.CameraState.MainCameraTranslation;
            Matrix4x4 projection = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, aspectRatio, 1, 80000);
            Matrix4x4 worldView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0) * translation;

            Vector2 xlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ylimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 zlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ev = new Vector2(0, 0);
            Vector2 xmin = ev, xmax = ev, ymin = ev, ymax = ev;

            float[] positions = graph.LayoutState.DownloadVRAMPositions();

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
                    float guard = positions[idx + 3];
                    if (guard is not 1)
                    {
                        break;
                    }

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
                Vector2 minyS = GraphicsMaths.NdcToScreenPos(ymin, graphWidgetSize);
                Vector2 maxyS = GraphicsMaths.NdcToScreenPos(ymax, graphWidgetSize);

                xoffsets = new Vector2(minxS.X, graphWidgetSize.X - maxxS.X);
                yoffsets = new Vector2(minyS.Y, graphWidgetSize.Y - maxyS.Y);
                zoffsets = new Vector2(zlimits.X - zoom, zlimits.Y - zoom);
            }

            if (isPreview is false)
            {
                Console.WriteLine($"xmin: {xmin}, xmax:{xmax} xoffsets:{xoffsets}");
                Console.WriteLine($"ymin: {ymin}, ymax:{ymax} yoffsets:{yoffsets}");
            }

            //Sometimes the position buffer is full of terrible data.
            //Seems to just be for the preview graph? Only happens at the start so must have gotten hold of uninitialised data
            if (zoffsets.X > 100000000000 || zoffsets.X < -100000000000)
            {
                if (isPreview)
                {
                    graph.CameraState.PreviewCameraZoom = -60000;
                }
                else
                {
                    graph.CameraState.MainCameraZoom = -60000;
                }
                return false;
            }
            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"GetWidgetFitOffsets exit", Logging.LogFilterType.BulkDebugLogFile);
            return result;
        }


        private unsafe bool SetupComputeResources()
        {
            Debug.Assert(_gd is not null, "Init not called");
            ResourceFactory factory = _gd.ResourceFactory;

            if (_gd.Features.ComputeShader is false) { Logging.RecordError("Error: Compute shaders are unavailable"); return false; }

            byte[]? noteattribShaderBytes = ImGuiController.LoadEmbeddedShaderCode(factory, "sim-nodeAttrib", ShaderStages.Vertex);
            _nodeAttribShader = factory.CreateShader(new ShaderDescription(ShaderStages.Fragment, noteattribShaderBytes, "FS"));

            _nodeAttribComputeLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("nodeAttrib", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));
            _attribsParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<AttribShaderParams>(), BufferUsage.UniformBuffer, name: "AttribShaderParams");

            ComputePipelineDescription attribCPL = new ComputePipelineDescription(_nodeAttribShader, _nodeAttribComputeLayout, 16, 16, 1);

            _nodeAttribComputePipeline = factory.CreateComputePipeline(attribCPL);
            return true;
        }






        /// <summary>
        /// Must have read lock to call
        /// Find the node with the highest x/y/z dimension. Ignores w.
        /// </summary>
        /// <param name="buf">Device buffer containing values (can be speeds or positions)</param>
        /// <param name="nodeCount">Number of nodes to iterate over</param>
        /// <param name="highIndex">set to the index of the highest node</param>
        /// <returns></returns>
        private float FindHighXYZ(DeviceBuffer buf, int nodeCount, out int highIndex)
        {

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"FindHighXYZ  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd!, buf);
            MappedResourceView<float> destinationReadView = _gd!.Map<float>(destinationReadback, MapMode.Read);
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

        readonly private Stopwatch _stepTimer = new Stopwatch();
        readonly private Stopwatch _attSetupTimer = new Stopwatch();
        readonly private Stopwatch _attShaderTimer = new Stopwatch();
        private bool ErrorState = false;

        /// <summary>
        /// Do the actual computation of graph layout and animation
        /// Uses the velocity shader to adjust the velocity based on relative positions
        /// Uses the position shader to move the nodes at the calculated velocity
        /// Adjusts the size/alpha of nodes based on the attribute buffer
        /// </summary>
        /// <param name="cl">Thread-specific command list</param>
        /// <param name="plot">Graph to perform computation on</param>
        /// <param name="mouseoverNodeID">The index of the node the users mouse is hovering over</param>
        /// <param name="isAnimated">If the graph should have animation attributes computed (ie: main graph with live/replay active)</param>
        /// <returns>The version ID associated with the produced graph layout computed</returns>
        public ulong Compute(CommandList cl, PlottedGraph plot, int mouseoverNodeID, bool isAnimated)
        {
            Debug.Assert(_gd is not null);

            if (plot.DrawnEdgesCount == 0 || !GlobalConfig.LayoutAllComputeEnabled || ErrorState)
            {
                return plot.LayoutState.RenderVersion;
            }

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Marker Compute start {EngineID} graph {plot.TID}", Logging.LogFilterType.BulkDebugLogFile);

            int edgesCount = plot.DrawnEdgesCount;
            Debug.Assert(plot != null, "Layout engine called to compute without active graph");
            GraphLayoutState layout = plot.LayoutState;

            _stepTimer.Restart();
            layout.Lock.EnterUpgradeableReadLock();
            try
            {
                if (!layout.ActivatingPreset)
                {
                    plot.AddNewEdgesToLayoutBuffers(edgesCount);
                }

                var now = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
                float delta = Math.Min((now - plot.LastComputeTime) / 1000f, 1.0f);// safety cap on large deltas
                delta *= (layout.ActivatingPreset ? 7.5f : 1.0f); //without this the preset animation will 'bounce'

                plot.LastComputeTime = now;


                //todo set this on layout change
                bool isForceDirected = CONSTANTS.LayoutStyles.IsForceDirected(plot.ActiveLayoutStyle);

                bool forceComputationActive = GlobalConfig.LayoutPositionsActive && plot.Temperature > 0 && (layout.ActivatingPreset || isForceDirected);

                LayoutPipelines.LayoutPipeline? activePipeline = SelectPipeline(layout);
                if (activePipeline is null)
                {
                    ErrorState = true;
                    Logging.RecordError("Error selecting active layout - it's either invalid or the pipeline is uninitialised");
                    return layout.RenderVersion;
                }

                bool flip = layout.flip();
                if (forceComputationActive)
                {
                    if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Layout computation starting in engine {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
                    activePipeline.Compute(plot, flip, delta);
                    if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Layout computation finished in engine {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);

                    layout.IncrementVersion();

                    if (plot.OPT_LOCK_TEMPERATURE is false)
                    {
                        plot.Temperature *= CONSTANTS.Layout_Constants.TemperatureStepMultiplier;
                        if (plot.Temperature <= CONSTANTS.Layout_Constants.MinimumTemperature)
                        {
                            plot.Temperature = 0;
                        }
                    }
                }

                if (rgatUI.ResponsiveKeyHeld || plot.FurthestNodeDimension == 0)
                {
                    // todo - don't iterate over every node every frame!
                    // not sure whether to make this timer based or do it in the shader
                    // it looks pretty bad doing it every 10 frames
                    // for now just do it every 3 frames
                    if ((forceComputationActive && (layout.RenderVersion % 3) == 0) || plot.FurthestNodeDimension == 0)
                    {
                        if (layout.PositionsVRAM1 is not null && (plot.ComputeBufferNodeCount * 4 * sizeof(float)) <= layout.PositionsVRAM1.SizeInBytes)
                        {
                            float highPosition = FindHighXYZ(layout.PositionsVRAM1!, plot.ComputeBufferNodeCount, out int furthestNodeIdx);
                            if (furthestNodeIdx != -1)
                            {
                                plot.SetFurthestNodeDimension(furthestNodeIdx, highPosition);
                            }
                        }
                    }
                }

                if (GlobalConfig.LayoutAttribsActive)
                {
                    if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Attribute computation starting in engine {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
                    ComputeAttributes(flip, layout, cl, plot, delta, mouseoverNodeID, isAnimated);
                    if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Attribute computation finished in engine {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
                }

                if (layout.ActivatingPreset && layout.IncrementPresetSteps() > 10) //todo look at this again, should it be done after compute?
                {
                    if (layout.VelocitiesVRAM1 is not null && (plot.ComputeBufferNodeCount * 4 * sizeof(float)) <= layout.VelocitiesVRAM1.SizeInBytes)
                    {
                        //when the nodes are near their targets, instead of bouncing around while coming to a stop, just snap them into position
                        float fastest = FindHighXYZ(layout.VelocitiesVRAM1, plot.ComputeBufferNodeCount, out int _);
                        if (fastest < 1)
                        {
                            Logging.RecordLogEvent("Preset done", filter: Logging.LogFilterType.Debug);
                            layout.CompleteLayoutChange();
                        }
                    }
                }

                if (GlobalConfig.LayoutPositionsActive)
                {
                    _stepTimer.Stop();
                    plot.RecordComputeTime(stepMSTotal: _stepTimer.Elapsed.TotalMilliseconds,
                        positionSetupTime: activePipeline.PositionSetupTime, positionShaderTime: activePipeline.PositionTime,
                        velocitySetupTime: activePipeline.VelocitySetupTime, velocityShaderTime: activePipeline.VelocityTime,
                        attributeSetupTime: attributeSetupTime, attributeShaderTime: attributeTime);
                }

            }
            catch (Exception e)
            {
                Logging.RecordException($"Error during layout compute: {e.Message}", e, plot.InternalProtoGraph);
                ErrorState = true;
            }
            finally
            {
                layout.Lock.ExitUpgradeableReadLock();
            }


            _stepTimer.Stop();
            if (_stepTimer.ElapsedMilliseconds > 100)
                Logging.RecordLogEvent($"Compute step took {_stepTimer.ElapsedMilliseconds}ms", Logging.LogFilterType.Debug);



            //DebugPrintOutputIntBuffer(layout.BlockMiddles!, "Middles", 100);
            //DebugPrintOutputFloatBuffer(layout.VelocitiesVRAM1!, "Vel1", 32);
            //DebugPrintOutputFloatBuffer(layout.PositionsVRAM1!, "pos1", 32);
            //DebugPrintOutputFloatBuffer(layout.PositionsVRAM2!, "pos2", 32);
            //DebugPrintOutputFloatBuffer(layout.AttributesVRAM, "Atts2", 32);


            lock (_lock)
            {
                _lastComputeMS.Add(_stepTimer.Elapsed.TotalMilliseconds);
                if (_lastComputeMS.Count > GlobalConfig.StatisticsTimeAvgWindow)
                {
                    _lastComputeMS = _lastComputeMS.TakeLast(GlobalConfig.StatisticsTimeAvgWindow).ToList();
                }
                AverageComputeTime = _lastComputeMS.Average();
            }

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"Marker Compute end {EngineID} graph {plot.TID}", Logging.LogFilterType.BulkDebugLogFile);

            return layout.RenderVersion;
        }

        void ComputeAttributes(bool flip, GraphLayoutState layout, CommandList cl, PlottedGraph graph, float delta, int mouseoverNodeID, bool isAnimated)
        {
            ResourceSetDescription attr_rsrc_desc;
            DeviceBuffer inputAttributes;
            if (flip)
            {
                attr_rsrc_desc = new ResourceSetDescription(_nodeAttribComputeLayout, _attribsParamsBuffer, layout.AttributesVRAM1,
                    layout.EdgeConnectionIndexes, layout.EdgeConnections, layout.AttributesVRAM2);
                inputAttributes = layout.AttributesVRAM1!;
            }
            else
            {
                attr_rsrc_desc = new ResourceSetDescription(_nodeAttribComputeLayout, _attribsParamsBuffer, layout.AttributesVRAM2,
                    layout.EdgeConnectionIndexes, layout.EdgeConnections, layout.AttributesVRAM1);
                inputAttributes = layout.AttributesVRAM2!;
            }

            ResourceSet attribComputeResourceSet = _factory!.CreateResourceSet(attr_rsrc_desc);

            _attSetupTimer.Restart();
            cl.Begin();
            RenderNodeAttribs(cl, graph, inputAttributes, attribComputeResourceSet, delta, mouseoverNodeID, isAnimated);
            cl.End();
            _attSetupTimer.Stop();

            _attShaderTimer.Restart();
            _gd!.SubmitCommands(cl);
            _gd!.WaitForIdle();

            //should we be dispose/recreating these? probably not. todo
            _gd.DisposeWhenIdle(attribComputeResourceSet);

            _attShaderTimer.Stop();

            attributeSetupTime = _attSetupTimer.Elapsed.TotalMilliseconds;
            attributeTime = _attShaderTimer.Elapsed.TotalMilliseconds;
            //DebugPrintOutputFloatBuffer(layout.AttributesVRAM1!, "Atts1", 32);
        }


        LayoutPipelines.LayoutPipeline? SelectPipeline(GraphLayoutState layout)
        {
            if (layout.ActivatingPreset)
            {
                return this.PresetLayout;
            }
            switch (layout.Style)
            {
                case CONSTANTS.LayoutStyles.Style.ForceDirected3DBlocks:
                    return this.ForceBlocksLayout;

                case CONSTANTS.LayoutStyles.Style.ForceDirected3DNodes:
                    return this.ForceNodesLayout;

                case CONSTANTS.LayoutStyles.Style.CylinderLayout:
                case CONSTANTS.LayoutStyles.Style.Circle:
                    return this.PresetLayout;

                default:
                    Logging.RecordError($"Layout {layout.Style} requested but not handled by SelectPipeline");
                    return null;
            }

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
















        /*
         * 
         * Node attribute shader does a few cosmetic things to nodes (alpha, size) for highlighting and animation
         * 
         */
        [StructLayout(LayoutKind.Sequential)]
        private struct AttribShaderParams
        {
            public float delta;            // requestAnimationFrame delta
            public int selectedNode;     // selectedNode
            public float hoverMode;     // selectedNode
            public uint nodeCount;     

            public float MinimumAlpha;
            public int isAnimated;

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
        private unsafe void RenderNodeAttribs(CommandList cl, PlottedGraph graph, DeviceBuffer inputAttributes,
            ResourceSet resources, float delta, int mouseoverNodeID, bool useAnimAttribs)
        {
            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderNodeAttribs  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            AttribShaderParams parms = new AttribShaderParams
            {
                delta = delta,
                selectedNode = mouseoverNodeID,
                nodeCount = (uint)Math.Min(graph.RenderedNodeCount(), graph.LayoutState.AttributesVRAM1!.SizeInBytes / 16),
                MinimumAlpha = GlobalConfig.AnimatedFadeMinimumAlpha,
                hoverMode = (mouseoverNodeID != -1) ? 1 : 0,
                isAnimated = useAnimAttribs ? 1: 0
            };


            graph.GetActiveNodeIndexes(out List<uint> pulseNodes, out List<uint> lingerNodes, out uint[] deactivatedNodes);

            if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderNodeAttribs {this.EngineID} updating attribsbuf {inputAttributes.Name}", Logging.LogFilterType.BulkDebugLogFile);

            cl.UpdateBuffer(_attribsParamsBuffer, 0, parms);

            float currentPulseAlpha = Math.Max(GlobalConfig.AnimatedFadeMinimumAlpha, GraphicsMaths.getPulseAlpha());

            //todo - merge contiguous regions to reduce command count
            float[] valArray = new float[3];
            foreach (uint idx in pulseNodes)
            {
                if (idx >= graph.RenderedNodeCount())
                {
                    break;
                }

                if (inputAttributes.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float)))
                {
                    break;
                }

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
                if (idx >= graph.RenderedNodeCount())
                {
                    break;
                }

                if (inputAttributes.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float)))
                {
                    break;
                }

                valArray[0] = 2.0f + currentPulseAlpha;
                fixed (float* dataPtr = valArray)
                {
                    Debug.Assert((idx * 4 * sizeof(float) + (2 * sizeof(float)) + sizeof(float)) < inputAttributes.SizeInBytes);
                    cl.UpdateBuffer(inputAttributes, idx * 4 * sizeof(float) + (2 * sizeof(float)), (IntPtr)dataPtr, sizeof(float));
                }
            }

            foreach (uint idx in deactivatedNodes)
            {
                if (idx >= graph.RenderedNodeCount())
                {
                    break;
                }

                if (inputAttributes.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float)))
                {
                    break;
                }

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

            cl.Dispatch((uint)Math.Ceiling(inputAttributes.SizeInBytes / (256.0 * sizeof(Vector4))), 1, 1);
        }


        /// <summary>
        /// Set the highlight state of nodes in the attributes buffer so they can be animated/have their icon set
        /// </summary>
        /// <param name="cl">Thread specific Veldrid CommandList</param>
        /// <param name="graph">Graph with highlights to apply</param>
        /// <param name="attribsBuf">Attributes buffer to apply highlight data to</param>
        public static void ApplyHighlightAttributes(CommandList cl, PlottedGraph graph, DeviceBuffer attribsBuf)
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
        public static unsafe void SetHighlightedNodes(CommandList cl, List<uint> nodeIdxs, DeviceBuffer attribsBuf, CONSTANTS.HighlightType highlightType)
        {
            float[] val = new float[] { 400f,//bigger
                1.0f, //full alpha 
                1.0f,
                1.0f //target icon
            };
            foreach (uint nidx in nodeIdxs)
            {
                if ((nidx * 4 * sizeof(float)) < attribsBuf.SizeInBytes)
                {
                    fixed (float* dataPtr = val)
                    {
                        cl.UpdateBuffer(attribsBuf, nidx * 4 * sizeof(float) + (0 * sizeof(float)), (IntPtr)dataPtr, (uint)val.Length * sizeof(float));
                    }
                }
            }
        }

        /// <summary>
        /// Remove a nodes highlighted state in the attribute buffer
        /// </summary>
        /// <param name="cl">Thread specific Veldrid CommandList</param>
        /// <param name="nodeIdxs">List of node indexes to set as not highlighted</param>
        /// <param name="attribsBuf">Attributes buffer to set highlight state in</param>
        public static unsafe void UnsetHighlightedNodes(CommandList cl, List<uint> nodeIdxs, DeviceBuffer attribsBuf)
        {
            float[] val = new float[] { 400f,//still big, let the shader shrink it
                1.0f, //full alpha 
                0.5f, //below the deflate threshold. this is not clear, needs refactoring
                0f //no highlight
            };
            foreach (uint nidx in nodeIdxs)
            {
                if ((nidx * 4 * sizeof(float)) < attribsBuf.SizeInBytes)
                {
                    fixed (float* dataPtr = val)
                    {
                        cl.UpdateBuffer(attribsBuf, nidx * 4 * sizeof(float) + (0 * sizeof(float)), (IntPtr)dataPtr, (uint)val.Length * sizeof(float));
                    }
                }
            }
        }



        /// <summary>
        /// Average time in Milliseconds taken by the GPU to perform a round of velocity/position/attribute computation
        /// Average computed over GlobalConfig.StatisticsTimeAvgWindow frames
        /// </summary>
        public double AverageComputeTime { get; private set; } = 0;

        private List<double> _lastComputeMS = new List<double>() { 0 };

        /// <summary>
        /// Read out some values from a DeviceBuffer and print them to the console. Just for debugging.
        /// </summary>
        /// <param name="buf">GPU DeviceBuffer to read</param>
        /// <param name="message">Caption for the printout</param>
        /// <param name="printCount">Max values to print</param>
        private void DebugPrintOutputFloatBuffer(DeviceBuffer buf, string message, int printCount)
        {
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd!, buf);
            MappedResourceView<float> destinationReadView = _gd!.Map<float>(destinationReadback, MapMode.Read);
            float[] outputArray = new float[destinationReadView.Count];
            for (int index = 0; index < destinationReadView.Count; index++)
            {
                if (index >= destinationReadView.Count)
                {
                    break;
                }

                outputArray[index] = destinationReadView[index];
            }
            _gd.Unmap(destinationReadback);
            PrintFloatBufferArray(outputArray, message, printCount);
            VeldridGraphBuffers.VRAMDispose(destinationReadback);
        }

        private static void PrintFloatBufferArray(float[] sourceData, string premsg, int limit = 0)
        {

            Logging.WriteConsole(premsg);
            bool printed = false;
            for (var i = 0; i < sourceData.Length; i += 4)
            {
                if (limit > 0 && i > limit)
                {
                    break;
                }

                if (i != 0 && (i % 8 == 0))
                {
                    if (printed)
                        Logging.WriteConsole();
                    printed = false;
                }
                //if (sourceData[i] == 0 && sourceData[i+1] == 0)
                if ((i + 3) > sourceData.Length)
                {
                    break;
                }
                //if (sourceData[i + 3] != 181) continue;
                Console.Write($"{i / 4}({sourceData[i]:f3},{sourceData[i + 1]:f3},{sourceData[i + 2]:f3},{sourceData[i + 3]:f3})");
                printed = true;
            }
            Logging.WriteConsole();

        }




        private void DebugPrintOutputIntBuffer(DeviceBuffer buf, string message, int printCount)
        {
            if (buf is null)
            {
                Console.WriteLine("Skipping debug output of null buffer:" + message);
                return;
            }
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd!, buf);
            MappedResourceView<int> destinationReadView = _gd!.Map<int>(destinationReadback, MapMode.Read);
            int[] outputArray = new int[destinationReadView.Count];
            for (int index = 0; index < destinationReadView.Count; index++)
            {
                if (index >= destinationReadView.Count)
                {
                    break;
                }

                outputArray[index] = destinationReadView[index];
            }
            _gd.Unmap(destinationReadback);
            PrintIntBufferArray(outputArray, message, printCount);
            VeldridGraphBuffers.VRAMDispose(destinationReadback);
        }

        private static void PrintIntBufferArray(int[] sourceData, string premsg, int limit = 0)
        {

            Logging.WriteConsole(premsg);
            for (var i = 0; i < sourceData.Length; i += 4)
            {
                if (limit > 0 && i > limit)
                {
                    break;
                }

                if (i != 0 && (i % 8 == 0))
                {
                    Logging.WriteConsole();
                }
                //if (sourceData[i] == 0 && sourceData[i+1] == 0)
                if ((i + 3) > sourceData.Length)
                {
                    break;
                }
                //if (sourceData[i + 3] != 181) continue;
                Console.Write($"{i / 4}({sourceData[i]},{sourceData[i + 1]},{sourceData[i + 2]},{sourceData[i + 3]})");
            }
            Logging.WriteConsole();

        }


    }
}
