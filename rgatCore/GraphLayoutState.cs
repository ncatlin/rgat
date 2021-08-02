using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using Veldrid;

namespace rgatCore
{
    public class GraphLayoutState
    {
        public GraphLayoutState(PlottedGraph tempDebugGraph, GraphicsDevice device, LayoutStyles.Style style)
        {

            dbgGraphDeleteMe = tempDebugGraph; //todo remove
            _VRAMBuffers.Style = style;
            _gd = device;
            Logging.RecordLogEvent($"Layout state {dbgGraphDeleteMe.tid} inited", Logging.LogFilterType.BulkDebugLogFile);
        }

        ~GraphLayoutState()
        {

            Logging.RecordLogEvent($"Layout state {dbgGraphDeleteMe.tid} disposed", Logging.LogFilterType.BulkDebugLogFile);
        }

        public PlottedGraph dbgGraphDeleteMe;

        static GraphicsDevice _gd;

        public LayoutStyles.Style Style => _VRAMBuffers.Style;


        //active layout data for display and computation on the GPU
        public GPUBuffers _VRAMBuffers = new GPUBuffers();


        //data for the most recent layout retrieved from VRAM, for serialisation and caching to disk to free up VRAM
        Dictionary<LayoutStyles.Style, CPUBuffers> SavedStates = new Dictionary<LayoutStyles.Style, CPUBuffers>();


        public class GPUBuffers
        {
            public DeviceBuffer Positions1;
            public DeviceBuffer Velocities1;
            public DeviceBuffer Attributes1;
            public DeviceBuffer Positions2;
            public DeviceBuffer Velocities2;
            public DeviceBuffer Attributes2;

            public DeviceBuffer PresetPositions;
            public DeviceBuffer EdgeConnections;
            public DeviceBuffer EdgeConnectionIndexes;
            public DeviceBuffer EdgeStrengths;
            public DeviceBuffer BlockMetadata;

            public ulong RenderVersion;
            public bool Initialised;
            public LayoutStyles.Style Style;

            public bool _flop;
        }

        public DeviceBuffer PositionsVRAM1 => _VRAMBuffers.Positions1;
        public DeviceBuffer PositionsVRAM2 => _VRAMBuffers.Positions2;
        public DeviceBuffer VelocitiesVRAM1 => _VRAMBuffers.Velocities1;
        public DeviceBuffer VelocitiesVRAM2 => _VRAMBuffers.Velocities2;
        public DeviceBuffer AttributesVRAM1 => _VRAMBuffers.Attributes1;
        public DeviceBuffer AttributesVRAM2 => _VRAMBuffers.Attributes2;
        public DeviceBuffer EdgeConnections => _VRAMBuffers.EdgeConnections;
        public DeviceBuffer EdgeConnectionIndexes => _VRAMBuffers.EdgeConnectionIndexes;
        public DeviceBuffer BlockMetadata => _VRAMBuffers.BlockMetadata;
        public DeviceBuffer EdgeStrengths => _VRAMBuffers.EdgeStrengths;
        public DeviceBuffer PresetPositions => _VRAMBuffers.PresetPositions;
        public ulong RenderVersion => _VRAMBuffers.RenderVersion;
        public bool Initialised => _VRAMBuffers.Initialised;

        public bool ActivatingPreset { get; private set; }
        public LayoutStyles.Style PresetStyle { get; private set; }

        int presetSteps = 0;
        public int IncrementPresetSteps() => presetSteps++;
        public void IncrementVersion() => _VRAMBuffers.RenderVersion++;

        ReaderWriterLockSlim _lock = new ReaderWriterLockSlim();
        public ReaderWriterLockSlim Lock => _lock;

        public bool flip()
        {
            bool result = _VRAMBuffers._flop;
            _VRAMBuffers._flop = !_VRAMBuffers._flop;
            return result;
        }

        public class CPUBuffers
        {
            public CPUBuffers(LayoutStyles.Style style)
            {
                PositionsArray = new float[] { };
                VelocityArray = new float[] { };
                NodeAttribArray = new float[] { };

                PresetPositions = new float[] { };
                EdgeConnections = new int[] { };
                EdgeConnectionIndexes = new int[] { };
                EdgeStrengths = new float[] { };
                BlockMetadata = new int[] { };

                RenderVersion = 0;
                Style = style;
            }

            public float[] PositionsArray;
            public float[] VelocityArray;
            public float[] NodeAttribArray;
            public float[] PresetPositions;
            public ulong RenderVersion;
            public int EdgeCount;
            public LayoutStyles.Style Style;

            public int[] EdgeConnections;
            public int[] EdgeConnectionIndexes;
            public float[] EdgeStrengths;
            public int[] BlockMetadata;
        }


        void LockedUploadStateToVRAM(LayoutStyles.Style style)
        {
            Logging.RecordLogEvent($"UploadGraphDataToVRAMA Start {dbgGraphDeleteMe.tid} layout {Thread.CurrentThread.Name}", Logging.LogFilterType.BulkDebugLogFile);
            if (!SavedStates.TryGetValue(style, out CPUBuffers sourceBuffers))
            {
                sourceBuffers = new CPUBuffers(style);
                SavedStates[style] = sourceBuffers;
            }
            LockedUploadStateToVRAM(sourceBuffers);
        }

        /// <summary>
        /// Must hold writer lock
        /// Refreshes VRAM layout buffers from cached RAM data
        /// </summary>
        /// <param name="_gd"></param>
        void LockedUploadStateToVRAM(CPUBuffers sourceBuffers)
        {
            Logging.RecordLogEvent($"UploadGraphDataToVRAMB Start {dbgGraphDeleteMe.tid} layout {Thread.CurrentThread.Name}", Logging.LogFilterType.BulkDebugLogFile);


            var bufferPair = VeldridGraphBuffers.CreateFloatsDeviceBufferPair(sourceBuffers.VelocityArray, _gd, $"_AvelBuf_{dbgGraphDeleteMe.tid}_");
            _VRAMBuffers.Velocities1 = bufferPair.Item1;
            _VRAMBuffers.Velocities2 = bufferPair.Item2;


            bufferPair = VeldridGraphBuffers.CreateFloatsDeviceBufferPair(sourceBuffers.PositionsArray, _gd, $"_AvelBuf_{dbgGraphDeleteMe.tid}_");

            _VRAMBuffers.Positions1 = bufferPair.Item1;
            _VRAMBuffers.Positions2 = bufferPair.Item2;

            bufferPair = VeldridGraphBuffers.CreateFloatsDeviceBufferPair(sourceBuffers.NodeAttribArray, _gd, $"_AvelBuf_{dbgGraphDeleteMe.tid}_");
            _VRAMBuffers.Attributes1 = bufferPair.Item1;
            _VRAMBuffers.Attributes2 = bufferPair.Item2;
            _VRAMBuffers.RenderVersion = sourceBuffers.RenderVersion;

            RegenerateEdgeDataBuffers(dbgGraphDeleteMe);

            _VRAMBuffers.Initialised = true;
            Logging.RecordLogEvent($"UploadGraphDataToVRAM copied", Logging.LogFilterType.BulkDebugLogFile);

        }

        //todo we dont actually want to immediately purge, we want to purge oldest if we are over VRAM limit
        void PurgeVRAMBuffers()
        {
            _VRAMBuffers.Initialised = false;
            _VRAMBuffers.RenderVersion = 0;
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.Positions1);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.Positions2);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.Attributes1);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.Attributes2);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.Velocities1);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.Velocities2);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.EdgeConnectionIndexes);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.EdgeConnections);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.EdgeStrengths);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.PresetPositions);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.BlockMetadata);
        }

        public float[] DownloadVRAMPositions()
        {
            _lock.EnterReadLock();

            LayoutStyles.Style layout = _VRAMBuffers.Style;
            if (SavedStates.TryGetValue(layout, out CPUBuffers saved) && saved.RenderVersion == _VRAMBuffers.RenderVersion)
            {
                _lock.ExitReadLock();
                return saved.PositionsArray.ToArray();
            }

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, _VRAMBuffers.Positions1);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            float[] destbuffer = new float[destinationReadView.Count];
            for (var i = 0; i < destinationReadView.Count; i++)
            {
                destbuffer[i] = destinationReadView[i];
            }
            _gd.Unmap(destinationReadback);
            destinationReadback.Dispose();

            _lock.ExitReadLock();

            return destbuffer;
        }


        public void SyncRAMToVRAM(LayoutStyles.Style layout, GraphicsDevice _gd)
        {
            _lock.EnterUpgradeableReadLock();

            //upload from RAM to VRAM if VRAM bufs not initialised at all or the VRAM has a different layout style or has an older version than in RAM
            if (SavedStates.TryGetValue(layout, out CPUBuffers savedLayout) &&
                (
                !_VRAMBuffers.Initialised ||
                savedLayout.Style != _VRAMBuffers.Style ||
                savedLayout.RenderVersion > _VRAMBuffers.RenderVersion
                )
                )
            {
                _lock.EnterWriteLock();
                //if the vram has the newest version of a force directed layout, save it to RAM
                //todo actually only do this if swapping layouts
                if (
                    _VRAMBuffers.Initialised &&
                    (
                    !SavedStates.TryGetValue(_VRAMBuffers.Style, out CPUBuffers existingState) ||
                    (existingState.RenderVersion < _VRAMBuffers.RenderVersion && LayoutStyles.RequiresCaching(_VRAMBuffers.Style))
                    )
                    )
                {
                    DownloadStateFromVRAM();//todo possibly skip attributes, they are very ephemerial
                }

                PurgeVRAMBuffers();

                LockedUploadStateToVRAM(layout);

                _lock.ExitWriteLock();
            }
            _lock.ExitUpgradeableReadLock();
        }

        /// <summary>
        /// must hold write lock
        /// </summary>
        public void DownloadStateFromVRAM()
        {

            if (!SavedStates.TryGetValue(_VRAMBuffers.Style, out CPUBuffers destbuffers))
            {
                destbuffers = new CPUBuffers(_VRAMBuffers.Style);

                SavedStates[_VRAMBuffers.Style] = destbuffers;
            }


            if (_VRAMBuffers.RenderVersion > destbuffers.RenderVersion)
            {
                //Logging.RecordLogEvent($"{graph.tid} layout {this.EngineID} version {currentRenderVersion}>{graph.renderFrameVersion}", Logging.LogFilterType.BulkDebugLogFile);
                Download_NodePositions_VRAM_to_Graph(destbuffers);
                Download_NodeVelocity_VRAM_to_Graph(destbuffers);
                destbuffers.RenderVersion = _VRAMBuffers.RenderVersion;
                Logging.RecordLogEvent($"{dbgGraphDeleteMe.tid} layout version updated", Logging.LogFilterType.BulkDebugLogFile);

            }
        }

        void Download_NodePositions_VRAM_to_Graph(CPUBuffers destbuffers)
        {

            DeviceBuffer positionsBuffer = _VRAMBuffers.Positions1;
            //
            Logging.RecordLogEvent($"Download_NodePositions_VRAM_to_Graph fetching {dbgGraphDeleteMe.tid} posbufs {positionsBuffer.Name}", Logging.LogFilterType.BulkDebugLogFile);

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, positionsBuffer);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            UpdateNodePositions(destinationReadView, destbuffers.PositionsArray);
            _gd.Unmap(destinationReadback);
            VeldridGraphBuffers.DoDispose(destinationReadback);
            Logging.RecordLogEvent($"Download_NodePositions_VRAM_to_Graph finished");

        }

        public void UpdateNodePositions(MappedResourceView<float> newPositions, float[] destbuffer)
        {
            int floatCount = newPositions.Count;//xyzw
            if (destbuffer.Length < floatCount)
            {
                Logging.RecordLogEvent($"UpdateNodePositions called changing grp_{dbgGraphDeleteMe.tid} size from {destbuffer.Length} to {newPositions.Count}", Logging.LogFilterType.BulkDebugLogFile);
                destbuffer = new float[floatCount]; //todo should be lots bigger
            }

            for (var i = 0; i < floatCount; i++)
            {
                destbuffer[i] = newPositions[i];
            }
        }


        void Download_NodeVelocity_VRAM_to_Graph(CPUBuffers destbuffers)
        {

            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph {dbgGraphDeleteMe.tid} layout", Logging.LogFilterType.BulkDebugLogFile);
            DeviceBuffer velocityBuffer = _VRAMBuffers.Velocities1;

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, velocityBuffer);

            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph readview map buf size {destinationReadback.SizeInBytes}", Logging.LogFilterType.BulkDebugLogFile);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            //uint floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
            uint floatCount = (uint)destinationReadView.Count;
            UpdateNodeVelocities(destinationReadView, destbuffers.VelocityArray);
            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph done updatenode", Logging.LogFilterType.BulkDebugLogFile);
            _gd.Unmap(destinationReadback);
            VeldridGraphBuffers.DoDispose(destinationReadback);
        }


        //This is assumed to never shrink
        public void UpdateNodeVelocities(MappedResourceView<float> newVelocities, float[] destbuffer)
        {

            int floatCount = newVelocities.Count;//xyzw
            if (destbuffer.Length < floatCount)
            {
                Logging.RecordLogEvent($"UpdateNodeVelocities called changing grp_{dbgGraphDeleteMe.tid} velsize from {destbuffer.Length} to {newVelocities.Count}");
                destbuffer = new float[floatCount];
            }

            for (var i = 0; i < floatCount; i++)
            {
                destbuffer[i] = newVelocities[i];
            }
        }




        /// <summary>
        /// Must hold writer lock before calling
        /// </summary>
        public void RegenerateEdgeDataBuffers(PlottedGraph graph)
        {
            Logging.RecordLogEvent($"RegenerateEdgeDataBuffers start", Logging.LogFilterType.BulkDebugLogFile);


            CreateEdgeDataBuffers(graph);
            CreateBlockMetadataBuffer(graph);
            //if (_VRAMBuffers.PresetPositions == null)
            //{
            RegeneratePresetBuffer(graph);
            //}

            Logging.RecordLogEvent($"RegenerateEdgeDataBuffers  {graph.tid} complete", Logging.LogFilterType.BulkDebugLogFile);
        }


        public void RegeneratePresetBuffer(PlottedGraph graph)
        {
            if (_VRAMBuffers.PresetPositions == null)
            {
                _VRAMBuffers.PresetPositions = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.StructuredBufferReadOnly, stride: 4, "DummyPresetAlloc");
            }


            //preset.PositionsArray = graph.CreateBlankPresetLayout();

            //VeldridGraphBuffers.DoDispose(_VRAMBuffers.PresetPositions);
            // _VRAMBuffers.PresetPositions = _VRAMBuffers.Positions1;
            //VeldridGraphBuffers.CreateFloatsDeviceBuffer(SavedStates[Style].PositionsArray, _gd, $"PLP_PresetPosbuf_{graph.tid}");

        }

        //must hold writer lock
        /*
        public void LoadPreset(PlottedGraph graph)
        {
            if (LayoutStyles.IsForceDirected(graph.ActiveLayoutStyle) )
            {
                PurgeVRAMBuffers();
                if (SavedStates.ContainsKey(graph.ActiveLayoutStyle))
                {
                    LockedUploadStateToVRAM(graph.ActiveLayoutStyle);
                }
                else
                {
                    //random
                }

                //_VRAMBuffers.PresetPositions =
                //    VeldridGraphBuffers.CreateFloatsDeviceBuffer(SavedStates[Style].PositionsArray, _gd, $"PLP_PresetPosbuf_{graph.tid}");

            }
            else
            {
                _VRAMBuffers.PresetPositions =  VeldridGraphBuffers.CreateFloatsDeviceBuffer(graph.GeneratePresetPositions(), _gd, "PresetPos");
                _VRAMBuffers.Style = graph.ActiveLayoutStyle;
            }
        }
        */

        /// <summary>
        /// This buffer list the index of every node each node is connected to
        /// </summary>
        /// <param name="graph"></param>
        /// <returns></returns>
        unsafe bool CreateEdgeDataBuffers(PlottedGraph graph)
        {
            Logging.RecordLogEvent($"CreateEdgeDataBuffers  {graph.tid}", Logging.LogFilterType.BulkDebugLogFile);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.EdgeConnections);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.EdgeConnectionIndexes);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.EdgeStrengths);

            if (!graph.GetEdgeRenderingData(out float[] edgeStrengths, out int[] edgeTargets, out int[] edgeMetaOffsets))
            {
                Logging.RecordLogEvent($"CreateEdgeDataBuffers zerobuf", Logging.LogFilterType.BulkDebugLogFile);
                _VRAMBuffers.EdgeConnections = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.StructuredBufferReadOnly, 4, $"BadFillerBufEdgeTargets_T{graph.tid}");
                _VRAMBuffers.EdgeStrengths = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.StructuredBufferReadOnly, 4, $"BadFillerBufEdgeStrengths_T{graph.tid}");
                _VRAMBuffers.EdgeConnectionIndexes = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.StructuredBufferReadOnly, 4, $"BadFillerBufEdgeOffsets_T{graph.tid}");
                return false;
            }


            _VRAMBuffers.EdgeConnections = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)edgeTargets.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, 4, $"EdgeTargetsBuf_T{graph.tid}");
            _VRAMBuffers.EdgeStrengths = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)edgeStrengths.Length * sizeof(float), BufferUsage.StructuredBufferReadOnly, 4, $"EdgeStrengthsBuf_T{graph.tid}");
            _VRAMBuffers.EdgeConnectionIndexes = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)edgeMetaOffsets.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, 4, $"EdgeOffsetsBuf_T{graph.tid}");

            //Logging.RecordLogEvent($"CreateEdgeDataBuffers processing {edgeStrengths.Length * sizeof(int)} bufsize {EdgeStrengthsBuf.SizeInBytes}", Logging.LogFilterType.BulkDebugLogFile);
            fixed (int* targsPtr = edgeTargets)
            {
                fixed (float* strengthsPtr = edgeStrengths)
                {
                    fixed (int* offsetsPtr = edgeMetaOffsets)
                    {

                        CommandList cl = _gd.ResourceFactory.CreateCommandList();
                        cl.Begin();
                        Debug.Assert(_VRAMBuffers.EdgeConnectionIndexes.SizeInBytes >= (edgeMetaOffsets.Length * sizeof(int)));
                        Debug.Assert(_VRAMBuffers.EdgeConnections.SizeInBytes >= (edgeTargets.Length * sizeof(int)));
                        Debug.Assert(_VRAMBuffers.EdgeStrengths.SizeInBytes >= (edgeStrengths.Length * sizeof(float)));
                        cl.UpdateBuffer(_VRAMBuffers.EdgeConnections, 0, (IntPtr)targsPtr, (uint)edgeTargets.Length * sizeof(int));
                        cl.UpdateBuffer(_VRAMBuffers.EdgeStrengths, 0, (IntPtr)strengthsPtr, (uint)edgeStrengths.Length * sizeof(float));
                        cl.UpdateBuffer(_VRAMBuffers.EdgeConnectionIndexes, 0, (IntPtr)offsetsPtr, (uint)edgeMetaOffsets.Length * sizeof(int));
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
        unsafe void CreateBlockMetadataBuffer(PlottedGraph graph)
        {

            Logging.RecordLogEvent($"CreateBlockDataBuffer  {graph.tid}", Logging.LogFilterType.BulkDebugLogFile);

            VeldridGraphBuffers.DoDispose(_VRAMBuffers.BlockMetadata);

            var textureSize = graph.EdgeTextureWidth();
            if (textureSize > 0)
            {
                int[] blockdats = graph.GetBlockRenderingMetadata();
                if (blockdats == null)
                    blockdats = new int[] { 0 };

                _VRAMBuffers.BlockMetadata = VeldridGraphBuffers.TrackedVRAMAlloc(_gd,
                    (uint)blockdats.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, sizeof(int), $"BlockMetadata_T{graph.tid}");

                if (blockdats.Length == 0) return;

                fixed (int* dataPtr = blockdats)
                {
                    CommandList cl = _gd.ResourceFactory.CreateCommandList();
                    cl.Begin();
                    cl.UpdateBuffer(_VRAMBuffers.BlockMetadata, 0, (IntPtr)dataPtr, (uint)blockdats.Length * sizeof(int));
                    cl.End();
                    _gd.SubmitCommands(cl);
                    _gd.WaitForIdle();
                    cl.Dispose();
                }
            }


            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, newBuffer));

            Logging.RecordLogEvent($"CreateBlockDataBuffer  {graph.tid} complete", Logging.LogFilterType.BulkDebugLogFile);
            //PrintBufferArray(textureArray, "Created data texture:");
        }




        /// <summary>
        /// Must have upgradable readlock
        /// </summary>
        /// <param name="finalCount"></param>
        public unsafe void AddNewNodesToComputeBuffers(int finalCount, PlottedGraph graph)
        {
            Logging.RecordLogEvent($"AddNewNodesToComputeBuffers <{finalCount - graph.ComputeBufferNodeCount}?  {graph.tid} start", Logging.LogFilterType.BulkDebugLogFile);
            int newNodeCount = finalCount - graph.ComputeBufferNodeCount;
            if (newNodeCount == 0) return;

            Debug.Assert(graph.ActiveLayoutStyle == _VRAMBuffers.Style);

            uint offset = (uint)graph.ComputeBufferNodeCount * 4 * sizeof(float);
            uint updateSize = 4 * sizeof(float) * (uint)newNodeCount;
            List<DeviceBuffer> disposals = new List<DeviceBuffer>();
            CPUBuffers RAMbufs = SavedStates[graph.LayoutState.Style];

            CommandList cl = _gd.ResourceFactory.CreateCommandList();
            cl.Begin();


            if (!_VRAMBuffers.Initialised || (offset + updateSize) > _VRAMBuffers.Velocities1.SizeInBytes)
            {
                _lock.EnterWriteLock();
                if (!_VRAMBuffers.Initialised || (offset + updateSize) > _VRAMBuffers.Velocities1.SizeInBytes)
                {
                    var bufferWidth = graph.NestedIndexTextureSize();
                    var bufferFloatCount = bufferWidth * bufferWidth * 4;
                    var bufferSize = bufferFloatCount * sizeof(float);
                    Debug.Assert(bufferSize >= updateSize);

                    if (_VRAMBuffers.Initialised)
                    {
                        Logging.RecordLogEvent($"Recreating buffers as {bufferSize} > {_VRAMBuffers.Velocities1.SizeInBytes}", Logging.LogFilterType.TextDebug);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Creating VRAM buffers size {bufferSize} for graph {graph.tid}", Logging.LogFilterType.TextDebug);
                    }
                    ResizeComputeBuffers(graph, bufferSize, cl, ref disposals);
                }
                _lock.ExitWriteLock();
                Logging.RecordLogEvent($"AddNewNodesToComputeBuffers  {graph.tid} done", Logging.LogFilterType.BulkDebugLogFile);
            }



            uint endOfComputeBufferOffset = (uint)graph.ComputeBufferNodeCount * 4;
            float[] newPositions = RAMbufs.PositionsArray;
            Logging.RecordLogEvent($"Writing new nodes from {offset / 16} to {offset / 16 + updateSize / 16} -> finalcount {finalCount}", Logging.LogFilterType.BulkDebugLogFile);
            fixed (float* dataPtr = newPositions)
            {
                cl.UpdateBuffer(_VRAMBuffers.Positions1, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
                cl.UpdateBuffer(_VRAMBuffers.Positions2, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
            }

            float[] newVelocities = RAMbufs.VelocityArray;
            fixed (float* dataPtr = newVelocities)
            {
                cl.UpdateBuffer(_VRAMBuffers.Velocities1, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
                cl.UpdateBuffer(_VRAMBuffers.Velocities2, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
            }

            float[] newAttribs = RAMbufs.NodeAttribArray;
            fixed (float* dataPtr = newAttribs)
            {
                cl.UpdateBuffer(_VRAMBuffers.Attributes1, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
                cl.UpdateBuffer(_VRAMBuffers.Attributes2, offset, (IntPtr)(dataPtr + endOfComputeBufferOffset), updateSize);
            }
            cl.End();
            _gd.SubmitCommands(cl);
            _gd.WaitForIdle();
            cl.Dispose();

            disposals.ForEach(buf => VeldridGraphBuffers.DoDispose(buf));

            graph.ComputeBufferNodeCount = finalCount;
        }





        /// <summary>
        /// Must hold writer lock before calling
        /// </summary>
        /// <param name="bufferSize"></param>
        void ResizeComputeBuffers(PlottedGraph graph, uint bufferSize, CommandList cl, ref List<DeviceBuffer> disposals)
        {

            uint zeroFillStart = 0;
            if (_VRAMBuffers.Initialised)
                zeroFillStart = _VRAMBuffers.Positions1.SizeInBytes;

            BufferDescription bd = new BufferDescription(bufferSize, BufferUsage.StructuredBufferReadWrite, 4);

            DeviceBuffer velocityBuffer1B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Vel1ZeroFilled_T{graph.tid}");
            DeviceBuffer positionsBuffer1B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Pos1ZeroFilled_T{graph.tid}");
            DeviceBuffer velocityBuffer2B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Vel2ZeroFilled_T{graph.tid}");
            DeviceBuffer positionsBuffer2B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Pos2ZeroFilled_T{graph.tid}");
            DeviceBuffer attribsBuffer1B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Att1ZeroFilled_T{graph.tid}");
            DeviceBuffer attribsBuffer2B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Att2ZeroFilled_T{graph.tid}");

            if (_VRAMBuffers.Initialised)
            {
                cl.CopyBuffer(_VRAMBuffers.Velocities1, 0, velocityBuffer1B, 0, zeroFillStart);
                cl.CopyBuffer(_VRAMBuffers.Velocities2, 0, velocityBuffer2B, 0, zeroFillStart);
                cl.CopyBuffer(_VRAMBuffers.Positions1, 0, positionsBuffer1B, 0, zeroFillStart);
                cl.CopyBuffer(_VRAMBuffers.Positions2, 0, positionsBuffer2B, 0, zeroFillStart);
                cl.CopyBuffer(_VRAMBuffers.Attributes1, 0, attribsBuffer1B, 0, zeroFillStart);
                cl.CopyBuffer(_VRAMBuffers.Attributes2, 0, attribsBuffer2B, 0, zeroFillStart);
            }



            disposals.Add(_VRAMBuffers.Velocities1);
            disposals.Add(_VRAMBuffers.Velocities2);
            disposals.Add(_VRAMBuffers.Positions1);
            disposals.Add(_VRAMBuffers.Positions2);
            disposals.Add(_VRAMBuffers.Attributes1);
            disposals.Add(_VRAMBuffers.Attributes2);

            _VRAMBuffers.Velocities1 = velocityBuffer1B;
            _VRAMBuffers.Velocities2 = velocityBuffer2B;
            _VRAMBuffers.Positions1 = positionsBuffer1B;
            _VRAMBuffers.Positions2 = positionsBuffer2B;
            _VRAMBuffers.Attributes1 = attribsBuffer1B;
            _VRAMBuffers.Attributes2 = attribsBuffer2B;


            _VRAMBuffers.Initialised = true;
        }



        //recreate node attributes with default state
        //useful for ending an animation sequence
        public void ResetNodeAttributes(GraphicsDevice _gd)
        {
            Logging.RecordLogEvent($"ResetNodeAttributes ", Logging.LogFilterType.BulkDebugLogFile);
            float[] storedAttributes = SavedStates[Style].NodeAttribArray;

            VeldridGraphBuffers.DoDispose(_VRAMBuffers.Attributes1);
            VeldridGraphBuffers.DoDispose(_VRAMBuffers.Attributes2);
            _VRAMBuffers.Attributes1 = VeldridGraphBuffers.CreateFloatsDeviceBuffer(storedAttributes, _gd, $"RNA_AattBuf1_{dbgGraphDeleteMe.tid}");
            _VRAMBuffers.Attributes2 = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, _VRAMBuffers.Attributes1.SizeInBytes, _VRAMBuffers.Attributes1.Usage, 4, $"RNA_AattBuf2_{ dbgGraphDeleteMe.tid}");

            _VRAMBuffers._flop = true; //process attribs buffer 1 first into buffer 2, saves on an extra copy
        }


        public bool GetSavedLayout(LayoutStyles.Style layoutStyle, out float[] buf)
        {
            if (SavedStates.TryGetValue(layoutStyle, out CPUBuffers saved) && saved.PositionsArray.Any())
            {
                buf = saved.PositionsArray;
                return true;
            }
            else
            {
                buf = null;
                return false;
            }

        }


        //Must hold upgradable read lock
        public bool GetAttributes(LayoutStyles.Style layoutStyle, out float[] buf)
        {
            if (SavedStates.TryGetValue(layoutStyle, out CPUBuffers saved))
            {
                buf = saved.NodeAttribArray;
                return true;
            }
            else
            {
                Lock.EnterWriteLock();
                if (SavedStates.TryGetValue(layoutStyle, out saved))
                {
                    buf = saved.NodeAttribArray;
                    Lock.ExitWriteLock();
                    return true;
                }
                else
                {
                    CPUBuffers layout = new CPUBuffers(layoutStyle);
                    SavedStates.Add(layoutStyle, layout);
                }

                buf = null;
                Lock.ExitWriteLock();
                return false;
            }

        }


        public unsafe void AddNode(uint nodeIdx, uint futureCount, uint bufferWidth, EdgeData edge = null)
        {

            var bounds = Math.Min(1000, (nodeIdx * 2) + 500);
            var bounds_half = bounds / 2;

            PlottedGraph graph = dbgGraphDeleteMe;
            if (!SavedStates.TryGetValue(graph.ActiveLayoutStyle, out CPUBuffers bufs))
            {
                _lock.EnterWriteLock();
                bufs = new CPUBuffers(graph.ActiveLayoutStyle);
                SavedStates[graph.ActiveLayoutStyle] = bufs;
                _lock.ExitWriteLock();
            }

            int oldVelocityArraySize = (bufs.VelocityArray != null) ? bufs.VelocityArray.Length * sizeof(float) : 0;
            var bufferFloatCount = bufferWidth * bufferWidth * 4;
            var bufferSize = bufferFloatCount * sizeof(float);

            uint currentOffset = (futureCount - 1) * 4;

            //Debug.Assert(!BufferDownloadActive);
            Debug.Assert(bufs.PositionsArray.Length == bufs.VelocityArray.Length);
            Debug.Assert(bufs.NodeAttribArray.Length == bufs.PositionsArray.Length);

            if (bufferSize > oldVelocityArraySize ||
                currentOffset >= oldVelocityArraySize ||
                bufs.PresetPositions.Length != bufs.PositionsArray.Length
                ) //todo this is bad
            {
                _lock.EnterWriteLock();
                uint newSize = Math.Max(currentOffset + 4, bufferFloatCount);
                Logging.RecordLogEvent($"Recreating graph RAM buffers as {newSize} > {oldVelocityArraySize}", Logging.LogFilterType.TextDebug);
                EnlargeRAMDataBuffers(newSize, bufs);
                _lock.ExitWriteLock();
            }

            Debug.Assert(bufs.PresetPositions.Length == bufs.PositionsArray.Length);

            //possible todo here - shift Y down as the index increases
            Random rnd = new Random();
            float[] nodePositionEntry = {
                ((float)rnd.NextDouble() * bounds) - bounds_half,
                ((float)rnd.NextDouble() * bounds) - bounds_half,
                ((float)rnd.NextDouble() * bounds) - bounds_half, 1 };


            bufs.PositionsArray[currentOffset] = nodePositionEntry[0];      //X
            bufs.PositionsArray[currentOffset + 1] = nodePositionEntry[1];  //Y
            bufs.PositionsArray[currentOffset + 2] = nodePositionEntry[2];  //Z
            bufs.PositionsArray[currentOffset + 3] = nodePositionEntry[3];  //type of position (none, preset, force directed)

            bufs.PresetPositions[currentOffset] = 0;      //X
            bufs.PresetPositions[currentOffset + 1] = 0;  //Y
            bufs.PresetPositions[currentOffset + 2] = 0;  //Z
            bufs.PresetPositions[currentOffset + 3] = 0;  //>=1 => an active preset

            bufs.VelocityArray[currentOffset] = 0;
            bufs.VelocityArray[currentOffset + 1] = 0;
            bufs.VelocityArray[currentOffset + 2] = 0;
            bufs.VelocityArray[currentOffset + 3] = 1;

            bufs.NodeAttribArray[currentOffset] = 200f;
            bufs.NodeAttribArray[currentOffset + 1] = 1f;// 0.5f;
            bufs.NodeAttribArray[currentOffset + 2] = 0;
            bufs.NodeAttribArray[currentOffset + 3] = 0;


        }


        void EnlargeRAMDataBuffers(uint size, CPUBuffers bufs)
        {
            float[] newVelocityArr1 = new float[size];
            float[] newPositionsArr1 = new float[size];
            float[] newAttsArr1 = new float[size];
            float[] newPresetsArray = new float[size];

            int endLength = 0;
            if (bufs.VelocityArray != null)
            {
                endLength = bufs.VelocityArray.Length;
                for (var i = 0; i < endLength; i++)
                {
                    newVelocityArr1[i] = bufs.VelocityArray[i];
                    newPositionsArr1[i] = bufs.PositionsArray[i];
                    newAttsArr1[i] = bufs.NodeAttribArray[i];
                }
                for (var i = 0; i < bufs.PresetPositions.Length; i++)
                {
                    newPresetsArray[i] = bufs.PresetPositions[i];
                }
            }

            for (var i = endLength; i < size; i++)
            {
                newVelocityArr1[i] = -1;
                newPositionsArr1[i] = -1;
                newAttsArr1[i] = -1;
                newPresetsArray[i] = -1;
            }


            bufs.PositionsArray = newPositionsArr1;
            bufs.VelocityArray = newVelocityArr1;
            bufs.NodeAttribArray = newAttsArr1;
            bufs.PresetPositions = newPresetsArray;

        }



        public void TriggerLayoutChange(LayoutStyles.Style newStyle)
        {

            if (newStyle == _VRAMBuffers.Style) return;
            Lock.EnterWriteLock();
            Console.WriteLine("Preset start");
            //save the old layout if it was computed
            if (LayoutStyles.IsForceDirected(_VRAMBuffers.Style))
            {
                DownloadStateFromVRAM();
            }

            //graph.LayoutState.RegeneratePresetBuffer(graph);
            //graph.LayoutState.LoadPreset(graph);

            /*
            if (LayoutStyles.IsForceDirected(newStyle) && !SavedStates.ContainsKey(newStyle))
            {



            }
            */

            presetSteps = 0;
            PresetStyle = newStyle;
            _VRAMBuffers.PresetPositions = VeldridGraphBuffers.CreateFloatsDeviceBuffer(dbgGraphDeleteMe.GeneratePresetPositions(PresetStyle), _gd, "Preset1");
            ActivatingPreset = true;

            Lock.ExitWriteLock();
        }

        public void CompleteLayoutChange()
        {
            Lock.EnterWriteLock();
            ActivatingPreset = false;
            this._VRAMBuffers.Style = PresetStyle;

            if (LayoutStyles.IsForceDirected(PresetStyle))
            {
                if (SavedStates.TryGetValue(PresetStyle, out CPUBuffers cpubufs))
                {
                    this.LockedUploadStateToVRAM(cpubufs);
                }
                else
                {
                    //Debug.Assert(false, "shouldn't be snapping to nonexistent preset");
                    VeldridGraphBuffers.DoDispose(_VRAMBuffers.Positions1);
                    VeldridGraphBuffers.DoDispose(_VRAMBuffers.Positions2);
                    VeldridGraphBuffers.CreateBufferCopyPair(_VRAMBuffers.PresetPositions, _gd, out _VRAMBuffers.Positions1, out _VRAMBuffers.Positions2, name: "PresetCopy");

                    RegenerateEdgeDataBuffers(dbgGraphDeleteMe);
                }
            }
            else
            {
                VeldridGraphBuffers.DoDispose(_VRAMBuffers.Positions1);
                VeldridGraphBuffers.DoDispose(_VRAMBuffers.Positions2);
                VeldridGraphBuffers.CreateBufferCopyPair(_VRAMBuffers.PresetPositions, _gd, out _VRAMBuffers.Positions1, out _VRAMBuffers.Positions2, name: "PresetCopy");

            }

            //

            Lock.ExitWriteLock();

        }


    }



}
