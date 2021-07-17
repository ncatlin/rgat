using ImGuiNET;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
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

        PlottedGraph _activeGraph;
        TraceRecord _activeTrace;

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

        ReaderWriterLockSlim _computeLock = new ReaderWriterLockSlim();

        /*
         * Having a list of other layout engines (eg previews, main widget) lets us grab the most up 
         * to date rendering of a graph without replicating the effort for each type of rendering
         */
        List<GraphLayoutEngine> _parallelLayoutEngines = new List<GraphLayoutEngine>();
        public void AddParallelLayoutEngine(GraphLayoutEngine engine)
        {
            _parallelLayoutEngines.Add(engine);
        }
        List<GraphLayoutEngine> GetParallelLayoutEngines()
        {
            return _parallelLayoutEngines.ToList();
        }




        /// <summary>
        /// Must have writer lock
        /// If graph buffers already stored in VRAM, load the reference
        /// Otherwise, fill GPU buffers from stored data in the plottedgraph
        /// 
        /// </summary>
        void LoadActivegraphComputeBuffersIntoVRAM()
        {
            Logging.RecordLogEvent($"LoadActivegraphComputeBuffersIntoVRAM with graph {_activeGraph.tid}", Logging.LogFilterType.BulkDebugLogFile);

            PlottedGraph graph = _activeGraph;
            //Console.WriteLine($"LoadActivegraphComputeBuffersIntoVRAM::Loading buffers of graph {graph.tid}");

            ulong cachedVersion;

            // already in VRAM, assign to the working buffers
            if (_cachedVersions.TryGetValue(graph, out cachedVersion) && cachedVersion == graph.renderFrameVersion)
            {
                Tuple<DeviceBuffer, DeviceBuffer> bufs = _cachedVelocityBuffers[graph];
                _activeVelocityBuffer1 = bufs.Item1;
                _activeVelocityBuffer2 = bufs.Item2;

                bufs = _cachedNodeAttribBuffers[graph];
                _activeNodeAttribBuffer1 = bufs.Item1;
                _activeNodeAttribBuffer2 = bufs.Item2;

                bufs = _cachedPositionBuffers[graph];
                _activePositionsBuffer1 = bufs.Item1;
                _activePositionsBuffer2 = bufs.Item2;
            }
            else
            {
                //flush current progress of other engine to graph
                foreach (GraphLayoutEngine engine in GetParallelLayoutEngines())
                {
                    engine.Download_VRAM_Buffers_To_Graph(graph, haveLock: true);
                }

                UploadGraphDataToVRAM(graph);
                _cachedVersions[graph] = graph.renderFrameVersion;

            }

            //data which is always more uptodate in the graph
            //not sure it's worth cacheing
            Logging.RecordLogEvent($"LoadActivegraphComputeBuffersIntoVRAM {EngineID} disposals", filter: Logging.LogFilterType.BulkDebugLogFile);
            VeldridGraphBuffers.DoDispose(_PresetLayoutFinalPositionsBuffer);
            VeldridGraphBuffers.DoDispose(_edgesConnectionDataOffsetsBuffer);
            VeldridGraphBuffers.DoDispose(_edgesConnectionDataBuffer);
            VeldridGraphBuffers.DoDispose(_edgeStrengthDataBuffer);
            VeldridGraphBuffers.DoDispose(_blockDataBuffer);

            Logging.RecordLogEvent("LoadActivegraphComputeBuffersIntoVRAM creations", filter: Logging.LogFilterType.BulkDebugLogFile);
            _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(graph.GetPresetPositionFloats(out _activatingPreset), _gd);
            _blockDataBuffer = CreateBlockMetadataBuffer(graph);

            CreateEdgeDataBuffers(graph, out _edgesConnectionDataBuffer, out _edgeStrengthDataBuffer, out _edgesConnectionDataOffsetsBuffer);
            Logging.RecordLogEvent("LoadActivegraphComputeBuffersIntoVRAM complete", filter: Logging.LogFilterType.BulkDebugLogFile);

        }


        public void ChangePreset()
        {
            PlottedGraph graph = _activeGraph;
            eGraphLayout graphStyle = graph.LayoutStyle;

            Logging.RecordLogEvent($"ChangePreset to style {graphStyle}", Logging.LogFilterType.BulkDebugLogFile);

            while (!_computeLock.TryEnterWriteLock(20))
            {
                Thread.Sleep(30);
            }
            {
                if (PlottedGraph.LayoutIsForceDirected(graphStyle))
                {
                    InvalidateCache(graph);
                    LoadActivegraphComputeBuffersIntoVRAM();
                }
                else
                {
                    VeldridGraphBuffers.DoDispose(_PresetLayoutFinalPositionsBuffer);
                    _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(graph.GetPresetPositionFloats(out _activatingPreset), _gd);
                    _activatingPreset = true;
                }
            }
            _computeLock.ExitWriteLock();

            graph.IncreaseTemperature(100f);
        }


        /// <summary>
        /// Set the recorded version of VRAM buffers to zero
        /// Forces most recent graph data to be restored from RAM next time they are used
        /// This is needed for completely re-rendering the graph, such as changing the layout
        /// Must have writer lock to call
        /// </summary>
        /// <param name="graph"></param>
        /// <param name="nested"></param>
        public void InvalidateCache(PlottedGraph graph, bool nested = true)
        {
            Logging.RecordLogEvent($"InvalidateCache", Logging.LogFilterType.BulkDebugLogFile);
            _cachedVersions[graph] = 0; //invalidate everything in VRAM
            if (nested)
            {
                foreach (GraphLayoutEngine engine in GetParallelLayoutEngines())
                {
                    if (engine != this)
                        engine.InvalidateCache(graph, false);
                }
            }
        }


        public void SaveComputeBuffers()
        {
            TraceRecord trace = _activeTrace;
            if (trace != null)
            {
                Logging.RecordLogEvent($"SaveComputeBuffers", Logging.LogFilterType.BulkDebugLogFile);
                var graphs = trace.GetPlottedGraphs(eRenderingMode.eStandardControlFlow);
                foreach (PlottedGraph graph in graphs)
                {
                    Download_VRAM_Buffers_To_Graph(graph);
                }
            }
        }


        /// <summary>
        /// Acquires reader lock
        /// </summary>
        /// <param name="graph"></param>
        public void Download_VRAM_Buffers_To_Graph(PlottedGraph graph, bool haveLock = false)
        {
            Logging.RecordLogEvent($"Download_VRAM_Buffers_To_Graph {graph.tid} layout {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            if (!haveLock) { _computeLock.EnterReadLock(); }
            {
                if (_cachedVersions.TryGetValue(graph, out ulong currentRenderVersion))
                {
                    if (graph.StartUpdateIfNewVersion(currentRenderVersion))
                    {
                        Logging.RecordLogEvent($"{graph.tid} layout {this.EngineID} version {currentRenderVersion}>{graph.renderFrameVersion}", Logging.LogFilterType.BulkDebugLogFile);
                        Download_NodePositions_VRAM_to_Graph(graph);
                        Download_NodeVelocity_VRAM_to_Graph(graph);
                        graph.BufferDownloadComplete(currentRenderVersion);
                        Logging.RecordLogEvent($"{graph.tid} layout {this.EngineID} version updated", Logging.LogFilterType.BulkDebugLogFile);

                    }
                }
            }
            if (!haveLock) { _computeLock.ExitReadLock(); }

            Logging.RecordLogEvent($"Download_VRAM_Buffers_To_Graph done {graph.tid} layout {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
        }


        /// <summary>
        /// Must hold reader lock before calling
        /// </summary>
        /// <param name="graph"></param>
        //read node positions from the GPU and store in provided plottedgraph
        void Download_NodePositions_VRAM_to_Graph(PlottedGraph graph)
        {
            if (graph.ComputeBufferNodeCount == 0) return;
            if (graph.renderFrameVersion == _cachedVersions[graph]) return;

            DeviceBuffer positionsBuffer = _cachedPositionBuffers[graph].Item1;

            Logging.RecordLogEvent($"Download_NodePositions_VRAM_to_Graph {graph.tid} layout {this.EngineID} size {positionsBuffer.SizeInBytes}", Logging.LogFilterType.BulkDebugLogFile);

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, positionsBuffer);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            graph.UpdateNodePositions(destinationReadView);
            _gd.Unmap(destinationReadback);

            Logging.RecordLogEvent($"Download_NodePositions_VRAM_to_Graph finished");
        }

        /// <summary>
        /// Must hold reader lock before calling
        /// </summary>
        /// <param name="graph"></param>
        //read node velocities from the GPU and store in provided plottedgraph
        void Download_NodeVelocity_VRAM_to_Graph(PlottedGraph graph)
        {

            if (graph.ComputeBufferNodeCount == 0) return;
            if (graph.renderFrameVersion == _cachedVersions[graph]) return;
            if (_cachedVelocityBuffers[graph] == null) return;

            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph {graph.tid} layout {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            DeviceBuffer velocityBuffer = _cachedVelocityBuffers[graph].Item1;

            uint textureSize = graph.LinearIndexTextureSize();
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, velocityBuffer);

            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph readview map buf size {destinationReadback.SizeInBytes}", Logging.LogFilterType.BulkDebugLogFile);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            //uint floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
            uint floatCount = (uint)destinationReadView.Count;
            graph.UpdateNodeVelocities(destinationReadView, floatCount);
            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph done updatenode", Logging.LogFilterType.BulkDebugLogFile);
            _gd.Unmap(destinationReadback);
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
        public void GetScreenFitOffsets(Matrix4x4 worldView, Vector2 graphWidgetSize, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets)
        {
            PlottedGraph graph = _activeGraph;
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

            _computeLock.EnterReadLock(); //todo this can actually just return but need some sensible values
            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, _activePositionsBuffer1);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);

            if (destinationReadView.Count < 4)
            {
                xoffsets = new Vector2(0, 0);
                yoffsets = new Vector2(0, 0);
                zoffsets = new Vector2(0, 0);
            }
            else
            {
                for (int idx = 0; idx < destinationReadView.Count; idx += 4)
                {
                    if (destinationReadView[idx + 3] == -1) break;
                    float x = destinationReadView[idx];
                    float y = destinationReadView[idx + 1];
                    float z = destinationReadView[idx + 2];
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

            _gd.Unmap(destinationReadback);
            _computeLock.ExitReadLock();
        }




        DeviceBuffer GetPositionsVRAMBuffer(PlottedGraph graph)
        {

            if (_cachedPositionBuffers.TryGetValue(graph, out Tuple<DeviceBuffer, DeviceBuffer> posBuffers))
            {
                return posBuffers.Item1;
            }
            return null;
        }

        public void UpdatePositionCaches()
        {
            TraceRecord trace = _activeTrace;
            if (trace == null) return;
            Logging.RecordLogEvent($"UpdatePositionCaches layout {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            var graphs = trace.GetPlottedGraphs(eRenderingMode.eStandardControlFlow);

            var engines = GetParallelLayoutEngines();
            foreach (PlottedGraph graph in graphs)
            {
                if (graph.InternalProtoGraph.get_num_nodes() == 0) continue;

                foreach (var engine in engines) engine.Download_VRAM_Buffers_To_Graph(graph);

                var latestVersion = graph.renderFrameVersion;
                if (!_cachedVersions.TryGetValue(graph, out ulong cachedVersion) || latestVersion > cachedVersion)
                {
                    Set_activeGraph(graph);
                    _computeLock.EnterWriteLock();
                    LoadActivegraphComputeBuffersIntoVRAM();
                    _computeLock.ExitWriteLock();
                }
            }

        }



        public bool GetPreviewFitOffsets(Vector2 graphWidgetSize, PlottedGraph graph, out Vector2 xoffsets, out Vector2 yoffsets, out Vector2 zoffsets)
        {
            Logging.RecordLogEvent($"GetPreviewFitOffsets Start {graph.tid} layout {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            float zoom;
            DeviceBuffer positionsBuffer;

            xoffsets = new Vector2(0, 0);
            yoffsets = new Vector2(0, 0);
            zoffsets = new Vector2(0, 0);

            zoom = graph.PreviewCameraZoom;

            _computeLock.EnterReadLock(); //todo this can actually just return but need some sensible values

            positionsBuffer = GetPositionsVRAMBuffer(graph);
            if (positionsBuffer == null)
            {
                _computeLock.ExitReadLock();
                return false;
            }

            float aspectRatio = graphWidgetSize.X / graphWidgetSize.Y;
            Matrix4x4 projection = Matrix4x4.CreatePerspectiveFieldOfView(1.0f, aspectRatio, 1, 50000);

            Vector3 translation = new Vector3(graph.PreviewCameraXOffset, graph.PreviewCameraYOffset, graph.PreviewCameraZoom);
            Matrix4x4 worldView = Matrix4x4.CreateFromAxisAngle(Vector3.UnitY, 0) * Matrix4x4.CreateTranslation(translation);

            Vector2 xlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ylimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 zlimits = new Vector2(float.MaxValue, float.MinValue);
            Vector2 ev = new Vector2(0, 0);
            Vector2 xmin = ev, xmax = ev, ymin = ev, ymax = ev;

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, positionsBuffer);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);


            bool result;
            if (destinationReadView.Count < 4)
            {
                result = false;
            }
            else
            {
                result = true;
                for (int idx = 0; idx < destinationReadView.Count; idx += 4)
                {
                    if (destinationReadView[idx + 3] == -1) break;
                    float x = destinationReadView[idx];
                    float y = destinationReadView[idx + 1];
                    float z = destinationReadView[idx + 2];
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

            _gd.Unmap(destinationReadback);
            _computeLock.ExitReadLock();
            Logging.RecordLogEvent($"GetPreviewFitOffsets exit", Logging.LogFilterType.BulkDebugLogFile);
            return result;
        }





        /// <summary>
        /// Must hold writer lock to call this
        /// </summary>
        //todo - only dispose and recreate if too small
        void UploadGraphDataToVRAM(PlottedGraph graph)
        {
            Logging.RecordLogEvent($"UploadGraphDataToVRAM Start {graph.tid} layout {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            if (_cachedPositionBuffers.ContainsKey(graph))
            {
                Logging.RecordLogEvent($"UploadGraphDataToVRAM disposing", Logging.LogFilterType.BulkDebugLogFile);
                VeldridGraphBuffers.DoDispose(_cachedVelocityBuffers[graph].Item1);
                VeldridGraphBuffers.DoDispose(_cachedVelocityBuffers[graph].Item2);
                _cachedVelocityBuffers[graph] = null;
                VeldridGraphBuffers.DoDispose(_cachedNodeAttribBuffers[graph].Item1);
                VeldridGraphBuffers.DoDispose(_cachedNodeAttribBuffers[graph].Item2);
                _cachedNodeAttribBuffers[graph] = null;
                VeldridGraphBuffers.DoDispose(_cachedPositionBuffers[graph].Item1);
                VeldridGraphBuffers.DoDispose(_cachedPositionBuffers[graph].Item2);
                _cachedPositionBuffers[graph] = null;
                _activeVelocityBuffer1 = null;
                _activeVelocityBuffer2 = null;
                _activePositionsBuffer1 = null;
                _activePositionsBuffer2 = null;
                _activeNodeAttribBuffer1 = null;
                _activeNodeAttribBuffer2 = null;
            }

            Logging.RecordLogEvent($"UploadGraphDataToVRAM disposed", Logging.LogFilterType.BulkDebugLogFile);
            _activeVelocityBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(graph.GetVelocityFloats(), _gd);
            _activeVelocityBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _activeVelocityBuffer1.SizeInBytes, Usage = _activeVelocityBuffer1.Usage, StructureByteStride = 4 });

            _activePositionsBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(graph.GetPositionFloats(), _gd);
            _activePositionsBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _activePositionsBuffer1.SizeInBytes, Usage = _activePositionsBuffer1.Usage, StructureByteStride = 4 });

            _activeNodeAttribBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(graph.GetNodeAttribFloats(), _gd);
            _activeNodeAttribBuffer2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = _activeNodeAttribBuffer1.SizeInBytes, Usage = _activeNodeAttribBuffer1.Usage, StructureByteStride = 4 }); // needed?

            Logging.RecordLogEvent($"UploadGraphDataToVRAM copying {_activeVelocityBuffer1.SizeInBytes},{_activePositionsBuffer1.SizeInBytes},{_activeNodeAttribBuffer1.SizeInBytes}", Logging.LogFilterType.BulkDebugLogFile);

            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.CopyBuffer(_activeVelocityBuffer1, 0, _activeVelocityBuffer2, 0, _activeVelocityBuffer1.SizeInBytes);
            cl.CopyBuffer(_activePositionsBuffer1, 0, _activePositionsBuffer2, 0, _activePositionsBuffer1.SizeInBytes);
            cl.CopyBuffer(_activeNodeAttribBuffer1, 0, _activeNodeAttribBuffer2, 0, _activeNodeAttribBuffer1.SizeInBytes);
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            cl.Dispose();

            Logging.RecordLogEvent($"UploadGraphDataToVRAM copied", Logging.LogFilterType.BulkDebugLogFile);
            _cachedVelocityBuffers[graph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeVelocityBuffer1, _activeVelocityBuffer2);
            _cachedNodeAttribBuffers[graph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeNodeAttribBuffer1, _activeNodeAttribBuffer2);
            _cachedPositionBuffers[graph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activePositionsBuffer1, _activePositionsBuffer2);

        }

        /*
         * 
         * 
         * the math works, need to fix the buffers/mem/cache positions for previews
         * 
         * 
         * 
         * */
        /*
        void InitPreviewPositionBuffers(PlottedGraph graph)
        {

            if (!_cachedPositionBuffers.ContainsKey(graph))
            {
                DeviceBuffer pos1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(graph.GetPositionFloats(), _gd);
                DeviceBuffer pos2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = pos1.SizeInBytes, Usage = pos1.Usage, StructureByteStride = 4 });
                _cachedPositionBuffers[graph] = new Tuple<DeviceBuffer, DeviceBuffer>(pos1, pos2);

                CommandList cl = _factory.CreateCommandList();
                cl.Begin();
                cl.CopyBuffer(pos1, 0, pos2, 0, pos1.SizeInBytes);
                cl.End();
                _gd.SubmitCommands(cl);
                _gd.WaitForIdle();
                cl.Dispose();
            }
            else
            {
                DeviceBuffer pos1 = _cachedPositionBuffers[graph].Item1;
                DeviceBuffer pos2 = _cachedPositionBuffers[graph].Item1;

                float[] newPositions = graph.GetPositionFloats();

                uint oldSize = pos1.SizeInBytes;
                int currentSize = sizeof(float) * newPositions.Length;

                if (true)//currentSize > oldSize) //todo!
                {
                    pos1.Dispose();
                    pos2.Dispose();
                    pos1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(graph.GetPositionFloats(), _gd);
                    pos2 = _factory.CreateBuffer(new BufferDescription { SizeInBytes = pos1.SizeInBytes, Usage = pos1.Usage, StructureByteStride = 4 });
                    _cachedPositionBuffers[graph] = new Tuple<DeviceBuffer, DeviceBuffer>(pos1, pos2);

                    CommandList cl = _factory.CreateCommandList();
                    cl.Begin();
                    cl.CopyBuffer(pos1, 0, pos2, 0, pos1.SizeInBytes);
                    cl.End();
                    _gd.SubmitCommands(cl);
                    _gd.WaitForIdle();
                    cl.Dispose();
                }

            }



        }
        */

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



        /// <summary>
        /// Must hold writer lock before calling
        /// </summary>
        /// <param name="bufferSize"></param>
        void resizeComputeBuffers(PlottedGraph graph, uint bufferSize)
        {

            Logging.RecordLogEvent($"resizeComputeBuffers {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            BufferDescription bd = new BufferDescription(bufferSize, BufferUsage.StructuredBufferReadWrite, 4);
            DeviceBuffer velocityBuffer1B = _factory.CreateBuffer(bd);
            DeviceBuffer positionsBuffer1B = _factory.CreateBuffer(bd);
            DeviceBuffer velocityBuffer2B = _factory.CreateBuffer(bd);
            DeviceBuffer positionsBuffer2B = _factory.CreateBuffer(bd);
            DeviceBuffer attribsBuffer1B = _factory.CreateBuffer(bd);
            DeviceBuffer attribsBuffer2B = _factory.CreateBuffer(bd);


            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.CopyBuffer(_activeVelocityBuffer1, 0, velocityBuffer1B, 0, Math.Min(velocityBuffer1B.SizeInBytes, _activeVelocityBuffer1.SizeInBytes));
            cl.CopyBuffer(_activeVelocityBuffer2, 0, velocityBuffer2B, 0, Math.Min(velocityBuffer2B.SizeInBytes, _activeVelocityBuffer1.SizeInBytes));
            cl.CopyBuffer(_activePositionsBuffer1, 0, positionsBuffer1B, 0, Math.Min(positionsBuffer1B.SizeInBytes, _activePositionsBuffer1.SizeInBytes));
            cl.CopyBuffer(_activePositionsBuffer2, 0, positionsBuffer2B, 0, Math.Min(positionsBuffer2B.SizeInBytes, _activePositionsBuffer1.SizeInBytes));
            cl.CopyBuffer(_activeNodeAttribBuffer1, 0, attribsBuffer1B, 0, Math.Min(attribsBuffer1B.SizeInBytes, _activeNodeAttribBuffer1.SizeInBytes));
            cl.CopyBuffer(_activeNodeAttribBuffer2, 0, attribsBuffer2B, 0, Math.Min(attribsBuffer2B.SizeInBytes, _activeNodeAttribBuffer1.SizeInBytes));
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            cl.Dispose();

            VeldridGraphBuffers.DoDispose(_activeVelocityBuffer1); _activeVelocityBuffer1 = velocityBuffer1B;
            VeldridGraphBuffers.DoDispose(_activeVelocityBuffer2); _activeVelocityBuffer2 = velocityBuffer2B;
            _cachedVelocityBuffers[graph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeVelocityBuffer1, _activeVelocityBuffer2);

            VeldridGraphBuffers.DoDispose(_activePositionsBuffer1); _activePositionsBuffer1 = positionsBuffer1B;
            VeldridGraphBuffers.DoDispose(_activePositionsBuffer2); _activePositionsBuffer2 = positionsBuffer2B;

            _cachedPositionBuffers[graph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activePositionsBuffer1, _activePositionsBuffer2);

            VeldridGraphBuffers.DoDispose(_activeNodeAttribBuffer1); _activeNodeAttribBuffer1 = attribsBuffer1B;
            VeldridGraphBuffers.DoDispose(_activeNodeAttribBuffer2); _activeNodeAttribBuffer2 = attribsBuffer2B;
            _cachedNodeAttribBuffers[graph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeNodeAttribBuffer1, _activeNodeAttribBuffer2);

        }


        /// <summary>
        /// This buffer list the index of every node each node is connected to
        /// </summary>
        /// <param name="graph"></param>
        /// <returns></returns>
        unsafe bool CreateEdgeDataBuffers(PlottedGraph graph, out DeviceBuffer EdgeTargetsBuf, out DeviceBuffer EdgeStrengthsBuf,
            out DeviceBuffer EdgeOffsetsBuf)
        {
            Logging.RecordLogEvent($"CreateEdgeDataBuffers  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);

            if (!graph.GetEdgeRenderingData(out float[] edgeStrengths, out int[] edgeTargets, out int[] edgeMetaOffsets))
            {
                Logging.RecordLogEvent($"CreateEdgeDataBuffers zerobuf", Logging.LogFilterType.BulkDebugLogFile);
                EdgeTargetsBuf = _factory.CreateBuffer(new BufferDescription(4, BufferUsage.StructuredBufferReadOnly, 4));
                EdgeStrengthsBuf = _factory.CreateBuffer(new BufferDescription(4, BufferUsage.StructuredBufferReadOnly, 4));
                EdgeOffsetsBuf = _factory.CreateBuffer(new BufferDescription(4, BufferUsage.StructuredBufferReadOnly, 4));
                return false;
            }


            BufferDescription bd = new BufferDescription((uint)edgeTargets.Length * sizeof(int),
                BufferUsage.StructuredBufferReadOnly, structureByteStride: 4);
            EdgeTargetsBuf = _factory.CreateBuffer(bd);

            bd = new BufferDescription((uint)edgeStrengths.Length * sizeof(float),
                BufferUsage.StructuredBufferReadOnly, structureByteStride: 4);
            EdgeStrengthsBuf = _factory.CreateBuffer(bd);

            bd = new BufferDescription((uint)edgeMetaOffsets.Length * sizeof(int), BufferUsage.StructuredBufferReadWrite, sizeof(int));
            EdgeOffsetsBuf = _factory.CreateBuffer(bd);

            Logging.RecordLogEvent($"CreateEdgeDataBuffers processing {edgeStrengths.Length * sizeof(int)} bufsize {EdgeStrengthsBuf.SizeInBytes}", Logging.LogFilterType.BulkDebugLogFile);
            fixed (int* targsPtr = edgeTargets)
            {
                fixed (float* strengthsPtr = edgeStrengths)
                {
                    fixed (int* offsetsPtr = edgeMetaOffsets)
                    {
                        CommandList cl = _factory.CreateCommandList();
                        cl.Begin();
                        Debug.Assert(EdgeOffsetsBuf.SizeInBytes >= (edgeMetaOffsets.Length * sizeof(int)));
                        Debug.Assert(EdgeTargetsBuf.SizeInBytes >= (edgeTargets.Length * sizeof(int)));
                        Debug.Assert(EdgeStrengthsBuf.SizeInBytes >= (edgeStrengths.Length * sizeof(float)));
                        cl.UpdateBuffer(EdgeTargetsBuf, 0, (IntPtr)targsPtr, (uint)edgeTargets.Length * sizeof(int));
                        cl.UpdateBuffer(EdgeStrengthsBuf, 0, (IntPtr)strengthsPtr, (uint)edgeStrengths.Length * sizeof(float));
                        cl.UpdateBuffer(EdgeOffsetsBuf, 0, (IntPtr)offsetsPtr, (uint)edgeMetaOffsets.Length * sizeof(int));
                        cl.End();
                        _gd.SubmitCommands(cl);
                        _gd.WaitForIdle();
                        cl.Dispose();
                    }
                }
            }

            Logging.RecordLogEvent($"CreateEdgeDataBuffers done", Logging.LogFilterType.BulkDebugLogFile);
            //PrintBufferArray(textureArray, "Created data texture:");
            return true;
        }


        /// Creates an array of metadata for basic blocks used for basic-block-centric graph layout
        unsafe DeviceBuffer CreateBlockMetadataBuffer(PlottedGraph graph)
        {

            Logging.RecordLogEvent($"CreateBlockDataBuffer  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            var textureSize = graph.EdgeTextureWidth();
            DeviceBuffer newBuffer = null;
            if (textureSize > 0)
            {
                int[] blockdats = graph.GetBlockRenderingMetadata();
                if (blockdats == null)
                    blockdats = new int[] { 0 };
                BufferDescription bd = new BufferDescription((uint)blockdats.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, sizeof(int));
                newBuffer = _factory.CreateBuffer(bd);
                if (blockdats.Length == 0) return newBuffer;

                fixed (int* dataPtr = blockdats)
                {
                    CommandList cl = _factory.CreateCommandList();
                    cl.Begin();
                    cl.UpdateBuffer(newBuffer, 0, (IntPtr)dataPtr, (uint)blockdats.Length * sizeof(int));
                    cl.End();
                    _gd.SubmitCommands(cl);
                    _gd.WaitForIdle();
                    cl.Dispose();
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

            private readonly uint _padding1; //must be multiple of 16
            private readonly uint _padding2; //must be multiple of 16
        }



        //todo : everything in here should be class variables defined once
        unsafe void RenderVelocity(PlottedGraph graph, DeviceBuffer positions, DeviceBuffer velocities,
            DeviceBuffer destinationBuffer, float delta, float temperature)
        {

            Logging.RecordLogEvent($"RenderVelocity  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            var textureSize = graph.LinearIndexTextureSize();
            uint fixedNodes = 0;
            if (graph.LayoutStyle == eGraphLayout.eForceDirected3DBlocks) fixedNodes = 1;

            VelocityShaderParams parms = new VelocityShaderParams
            {
                delta = delta,
                k = 100f,
                temperature = temperature,
                NodesTexWidth = textureSize,
                EdgeCount = (uint)graph.InternalProtoGraph.EdgeList.Count,
                fixedInternalNodes = fixedNodes
            };


            ResourceSetDescription velocity_rsrc_desc = new ResourceSetDescription(_velocityComputeLayout,
                _velocityParamsBuffer, positions, _PresetLayoutFinalPositionsBuffer, velocities, _edgesConnectionDataOffsetsBuffer,
                _edgesConnectionDataBuffer, _edgeStrengthDataBuffer, _blockDataBuffer, destinationBuffer);
            ResourceSet velocityComputeResourceSet = _factory.CreateResourceSet(velocity_rsrc_desc);

            Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} submit", Logging.LogFilterType.BulkDebugLogFile);
            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.UpdateBuffer(_velocityParamsBuffer, 0, parms);

            cl.SetPipeline(_velocityComputePipeline);
            cl.SetComputeResourceSet(0, velocityComputeResourceSet);
            cl.Dispatch(textureSize, textureSize, 1); //todo, really?
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} done", Logging.LogFilterType.BulkDebugLogFile);
            //DebugPrintOutputFloatBuffer(destinationBuffer, "Velocity Computation Done. Result: ", 1500);


            if (_activatingPreset)
            {
                float highest = FindHighXYZ(textureSize, destinationBuffer, 0.005f);
                if (highest < 0.05)
                {
                    if (PlottedGraph.LayoutIsForceDirected(graph.LayoutStyle))
                    {
                        graph.InitBlankPresetLayout();
                        float[] presetPosFloats = graph.GetPresetPositionFloats(out bool hasPresets);
                        VeldridGraphBuffers.DoDispose(_PresetLayoutFinalPositionsBuffer);
                        _PresetLayoutFinalPositionsBuffer = VeldridGraphBuffers.CreateFloatsDeviceBuffer(presetPosFloats, _gd);
                    }
                    _activatingPreset = false;
                }
            }

            velocityComputeResourceSet.Dispose();
            cl.Dispose();
        }

        public bool ActivatingPreset => _activatingPreset == true;

        /// <summary>
        /// Must have read lock to call
        /// See if any velocities in a velocity texture are below maxLimit
        /// </summary>
        /// <param name="textureSize"></param>
        /// <param name="buf"></param>
        /// <param name="maxLimit"></param>
        /// <returns></returns>
        float FindHighXYZ(uint textureSize, DeviceBuffer buf, float maxLimit)
        {
            Logging.RecordLogEvent($"FindHighXYZ  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
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
            _gd.Unmap(destinationReadback);
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
            private readonly uint _padding1;
            private readonly uint _padding3;
            private readonly bool _padding4;

        }


        //todo : everything in here should be class variables defined once
        unsafe void RenderPosition(PlottedGraph graph, DeviceBuffer positions, DeviceBuffer velocities, DeviceBuffer output, float delta)
        {
            Logging.RecordLogEvent($"RenderPosition  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            var textureSize = graph.LinearIndexTextureSize();

            uint width = textureSize;
            uint height = textureSize;

            uint fixedNodes = 0;
            if (graph.LayoutStyle == eGraphLayout.eForceDirected3DBlocks) fixedNodes = 1;
            PositionShaderParams parms = new PositionShaderParams
            {
                delta = delta,
                NodesTexWidth = textureSize,
                blockNodeSeperation = 60,
                fixedInternalNodes = fixedNodes,
                activatingPreset = _activatingPreset
            };

            //Console.WriteLine($"POS Parambuffer Size is {(uint)Unsafe.SizeOf<PositionShaderParams>()}");

            ResourceSet crs = _factory.CreateResourceSet(
                new ResourceSetDescription(_positionComputeLayout, _positionParamsBuffer, positions, velocities, _blockDataBuffer, output));

            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.UpdateBuffer(_positionParamsBuffer, 0, parms);
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

            private readonly uint _padding2b;
            private readonly uint _padding2c;
        }


        unsafe void RenderNodeAttribs(PlottedGraph graph, DeviceBuffer attribBufIn, DeviceBuffer attribBufOut, float delta, int mouseoverNodeID, bool useAnimAttribs)
        {
            Logging.RecordLogEvent($"RenderNodeAttribs  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            uint textureSize = graph.LinearIndexTextureSize();
            AttribShaderParams parms = new AttribShaderParams
            {
                delta = delta,
                selectedNode = mouseoverNodeID,
                edgesTexWidth = (int)textureSize,
                nodesTexWidth = (int)textureSize,
                hoverMode = 1,
                isAnimated = useAnimAttribs
            };


            graph.GetActiveNodeIDs(out List<uint> pulseNodes, out List<uint> lingerNodes, out uint[] deactivatedNodes);


            ResourceSetDescription attRSD = new ResourceSetDescription(_nodeAttribComputeLayout,
                _attribsParamsBuffer, attribBufIn, _edgesConnectionDataOffsetsBuffer, _edgesConnectionDataBuffer, attribBufOut);
            ResourceSet attribComputeResourceSet = _factory.CreateResourceSet(attRSD);

            Logging.RecordLogEvent($"RenderNodeAttribs creaters  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            CommandList cl = _factory.CreateCommandList();
            cl.Begin();
            cl.UpdateBuffer(_attribsParamsBuffer, 0, parms);


            float[] valArray = new float[3];
            foreach (uint idx in pulseNodes)
            {
                if (idx >= graph.RenderedNodeCount()) break;
                if (attribBufIn.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;

                valArray[0] = 300f; //start big
                valArray[1] = 1.0f; //full alpha
                valArray[2] = 1.0f; //pulse
                fixed (float* dataPtr = valArray)
                {
                    Debug.Assert((idx * 4 * sizeof(float) + valArray.Length * sizeof(float)) < attribBufIn.SizeInBytes);
                    cl.UpdateBuffer(attribBufIn, idx * 4 * sizeof(float), (IntPtr)dataPtr, (uint)valArray.Length * sizeof(float));
                }
            }

            float currentPulseAlpha = Math.Max(GlobalConfig.AnimatedFadeMinimumAlpha, GraphicsMaths.getPulseAlpha());
            foreach (uint idx in lingerNodes)
            {
                if (idx >= graph.RenderedNodeCount()) break;
                if (attribBufIn.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;

                valArray[0] = 2.0f + currentPulseAlpha;
                fixed (float* dataPtr = valArray)
                {
                    Debug.Assert((idx * 4 * sizeof(float) + (2 * sizeof(float)) + sizeof(float)) < attribBufIn.SizeInBytes);
                    cl.UpdateBuffer(attribBufIn, idx * 4 * sizeof(float) + (2 * sizeof(float)), (IntPtr)dataPtr, sizeof(float));
                }
            }

            foreach (uint idx in deactivatedNodes)
            {
                if (idx >= graph.RenderedNodeCount()) break;
                if (attribBufIn.SizeInBytes <= idx * 4 * sizeof(float) + (2 * sizeof(float))) break;
                valArray[0] = 0.8f;
                fixed (float* dataPtr = valArray)
                {
                    Debug.Assert((idx * 4 * sizeof(float) + (2 * sizeof(float)) + sizeof(float)) < attribBufIn.SizeInBytes);
                    cl.UpdateBuffer(attribBufIn, idx * 4 * sizeof(float) + (2 * sizeof(float)), (IntPtr)dataPtr, sizeof(float));
                }
            }

            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();


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
            Logging.RecordLogEvent($"ResetNodeAttributes  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            uint bufferWidth = argGraph.LinearIndexTextureSize();
            float[] storedAttributes = argGraph.GetNodeAttribFloats();

            VeldridGraphBuffers.DoDispose(_activeNodeAttribBuffer1);
            VeldridGraphBuffers.DoDispose(_activeNodeAttribBuffer2);
            _activeNodeAttribBuffer1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(storedAttributes, _gd);
            _activeNodeAttribBuffer2 = _factory.CreateBuffer(
                new BufferDescription
                {
                    SizeInBytes = _activeNodeAttribBuffer1.SizeInBytes,
                    Usage = _activeNodeAttribBuffer1.Usage,
                    StructureByteStride = 4
                });
            _cachedNodeAttribBuffers[argGraph] = new Tuple<DeviceBuffer, DeviceBuffer>(_activeNodeAttribBuffer1, _activeNodeAttribBuffer2);
            argGraph.flipflop = true; //process attribs buffer 1 first into buffer 2

        }


        public bool GetPositionsBuffer(PlottedGraph argGraph, out DeviceBuffer positionsBuf)
        {

            Logging.RecordLogEvent($"GetPositionsBuffer", Logging.LogFilterType.BulkDebugLogFile);
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
            Logging.RecordLogEvent($"GetNodeAttribsBuffer  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            Tuple<DeviceBuffer, DeviceBuffer> result;
            if (_cachedVersions.TryGetValue(argGraph, out ulong storedVersion) && storedVersion < argGraph.renderFrameVersion)
            {
                attribBuf = null;
                return false;
            }
            if (_cachedNodeAttribBuffers.TryGetValue(key: argGraph, out result) && result != null)
            {
                attribBuf = result.Item1;
                return true;
            }
            attribBuf = null;
            return false;
        }


        public void LayoutPreviewGraphs(PlottedGraph IgnoreGraph)
        {
            if (_activeTrace == null) return;
            Logging.RecordLogEvent($"LayoutPreviewGraphs", Logging.LogFilterType.BulkDebugLogFile);
            var graphs = _activeTrace.GetPlottedGraphs(eRenderingMode.eStandardControlFlow);
            foreach (PlottedGraph graph in graphs)
            {
                if (graph != null && graph != IgnoreGraph)
                {
                    Set_activeGraph(graph);
                    Compute(graph, -1, false);
                    Download_VRAM_Buffers_To_Graph(_activeGraph);
                }
            }
        }


        public void SetActiveTrace(TraceRecord trace)
        {
            if (_activeTrace != trace)
            {
                Logging.RecordLogEvent($"SetActiveTrace  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
                Set_activeGraph(trace.GetFirstGraph());
            }
        }

        /// <summary>
        /// Acquires Reader and Writer lock
        /// </summary>
        /// <param name="newgraph"></param>
        public void Set_activeGraph(PlottedGraph newgraph)
        {
            if (newgraph == _activeGraph) return;

            Logging.RecordLogEvent($"Set_activeGraph", Logging.LogFilterType.BulkDebugLogFile);
            //make sure the graph object has the latest version of the data in case a different widget wants it
            //this should probably be done on a demand basis
            if (_activeGraph != null)
            {
                Download_VRAM_Buffers_To_Graph(_activeGraph);
            }

            _computeLock.EnterWriteLock();
            if (newgraph == null)
            {
                _activeGraph = null;
                _activeTrace = null;
            }
            else
            {
                _activeGraph = newgraph;
                _activeTrace = newgraph.InternalProtoGraph.TraceData;
                LoadActivegraphComputeBuffersIntoVRAM();
            }
            _computeLock.ExitWriteLock();
        }



        bool _activatingPreset;
        public ulong Compute(PlottedGraph graph, int mouseoverNodeID, bool useAnimAttribs)
        {
            ulong newversion;
            _computeLock.EnterUpgradeableReadLock();
            if (_activeGraph != graph || graph.DrawnEdgesCount == 0)
            {
                newversion = _cachedVersions.GetValueOrDefault(graph, (ulong)0);
                _computeLock.ExitUpgradeableReadLock();
                return newversion;
            }
            int edgesCount = graph.DrawnEdgesCount;
            Logging.RecordLogEvent($"Compute start {EngineID}", Logging.LogFilterType.BulkDebugLogFile);

            Debug.Assert(graph != null, "Layout engine called to compute without active graph");
            if (_velocityShader == null)
            {
                SetupComputeResources();
            }

            Debug.Assert(edgesCount >= graph.DrawnEdgesCount);
            if (edgesCount > graph.RenderedEdgeCount || (new Random()).Next(0, 100) == 1)
            {
                _computeLock.EnterWriteLock();
                RegenerateEdgeDataBuffers(graph);
                _computeLock.ExitWriteLock();
                graph.RenderedEdgeCount = (uint)edgesCount;
            }

            int graphNodeCount = graph.RenderedNodeCount();
            if (graph.ComputeBufferNodeCount < graphNodeCount)
            {
                Logging.RecordLogEvent($"Adding {graphNodeCount - graph.ComputeBufferNodeCount} nodes to compute buffer of graph {graph.tid}");
                AddNewNodesToComputeBuffers(graphNodeCount);
            }


            var now = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
            float delta = Math.Min((now - graph.lastRenderTime) / 1000f, 1.0f);// safety cap on large deltas
            delta *= (_activatingPreset ? 7.5f : 1.0f); //without this the preset animation will 'bounce'


            graph.lastRenderTime = now;
            float _activeGraphTemperature = graph.temperature;

            if (graph.flipflop)
            {
                if (_activeGraphTemperature > 0.1)
                {
                    RenderVelocity(graph, _activePositionsBuffer1, _activeVelocityBuffer1, _activeVelocityBuffer2, delta, _activeGraphTemperature);
                    RenderPosition(graph, _activePositionsBuffer1, _activeVelocityBuffer1, _activePositionsBuffer2, delta);
                    _cachedVersions[graph]++;
                }
                RenderNodeAttribs(graph, _activeNodeAttribBuffer1, _activeNodeAttribBuffer2, delta, mouseoverNodeID, useAnimAttribs);
            }
            else
            {
                if (_activeGraphTemperature > 0.1)
                {
                    RenderVelocity(graph, _activePositionsBuffer2, _activeVelocityBuffer2, _activeVelocityBuffer1, delta, _activeGraphTemperature);
                    RenderPosition(graph, _activePositionsBuffer2, _activeVelocityBuffer1, _activePositionsBuffer1, delta);
                    _cachedVersions[graph]++;

                }
                RenderNodeAttribs(graph, _activeNodeAttribBuffer2, _activeNodeAttribBuffer1, delta, mouseoverNodeID, useAnimAttribs);
            }

            graph.flipflop = !graph.flipflop;
            if (_activeGraphTemperature > 0.1)
                graph.temperature *= 0.99f;
            else
                graph.temperature = 0;

            newversion = _cachedVersions.GetValueOrDefault(graph, (ulong)0);

            _computeLock.ExitUpgradeableReadLock();

            Logging.RecordLogEvent($"Compute end {EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            return newversion;
        }

        /// <summary>
        /// Must hold writer lock before calling
        /// </summary>
        void RegenerateEdgeDataBuffers(PlottedGraph graph)
        {
            Logging.RecordLogEvent($"RegenerateEdgeDataBuffers  {this.EngineID} start", Logging.LogFilterType.BulkDebugLogFile);
            VeldridGraphBuffers.DoDispose(_edgesConnectionDataBuffer);
            VeldridGraphBuffers.DoDispose(_edgesConnectionDataOffsetsBuffer);
            VeldridGraphBuffers.DoDispose(_edgeStrengthDataBuffer);
            VeldridGraphBuffers.DoDispose(_blockDataBuffer);

            CreateEdgeDataBuffers(graph, out _edgesConnectionDataBuffer, out _edgeStrengthDataBuffer, out _edgesConnectionDataOffsetsBuffer);
            //_edgesConnectionDataOffsetsBuffer = CreateEdgesConnectionDataOffsetsBuffer(graph);
            _blockDataBuffer = CreateBlockMetadataBuffer(graph);
            Logging.RecordLogEvent($"RegenerateEdgeDataBuffers  {this.EngineID} complete", Logging.LogFilterType.BulkDebugLogFile);
        }


        /// <summary>
        /// Must have upgradable readlock
        /// </summary>
        /// <param name="finalCount"></param>
        unsafe void AddNewNodesToComputeBuffers(int finalCount)
        {
            Logging.RecordLogEvent($"AddNewNodesToComputeBuffers  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            PlottedGraph graph = _activeGraph;
            int newNodeCount = finalCount - graph.ComputeBufferNodeCount;
            if (newNodeCount == 0) return;

            uint offset = (uint)graph.ComputeBufferNodeCount * 4 * sizeof(float);
            uint updateSize = 4 * sizeof(float) * (uint)newNodeCount;

            if ((offset + updateSize) > _activeVelocityBuffer1.SizeInBytes)
            {
                var bufferWidth = graph.NestedIndexTextureSize();
                var bufferFloatCount = bufferWidth * bufferWidth * 4;
                var bufferSize = bufferFloatCount * sizeof(float);
                Debug.Assert(bufferSize >= updateSize);

                Logging.RecordLogEvent($"Recreating buffers as {bufferSize} > {_activeVelocityBuffer1.SizeInBytes}", Logging.LogFilterType.TextDebug);

                _computeLock.EnterWriteLock();
                resizeComputeBuffers(graph, bufferSize);
                _computeLock.ExitWriteLock();
            }

            CommandList cl = _factory.CreateCommandList();
            cl.Begin();

            uint endOfComputeBufferOffset = (uint)graph.ComputeBufferNodeCount * 4;
            float[] newPositions = graph.GetPositionFloats();
            fixed (float* dataPtr = newPositions)
            {
                cl.UpdateBuffer(_activePositionsBuffer1, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
                cl.UpdateBuffer(_activePositionsBuffer2, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
            }

            float[] newVelocities = graph.GetVelocityFloats();
            fixed (float* dataPtr = newVelocities)
            {
                cl.UpdateBuffer(_activeVelocityBuffer1, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
                cl.UpdateBuffer(_activeVelocityBuffer2, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
            }

            float[] newAttribs = graph.GetNodeAttribFloats();
            fixed (float* dataPtr = newAttribs)
            {
                cl.UpdateBuffer(_activeNodeAttribBuffer1, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
                cl.UpdateBuffer(_activeNodeAttribBuffer2, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
            }
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            cl.Dispose();

            graph.ComputeBufferNodeCount = finalCount;
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
            _gd.Unmap(destinationReadback);
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
