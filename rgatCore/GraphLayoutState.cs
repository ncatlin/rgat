using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using Veldrid;
using static rgat.CONSTANTS;

namespace rgat
{
    /// <summary>
    /// Contains the actual geometry of a renered graph as RAM and VRAM buffers
    /// Contains one set of VRAM buffers for active drawing and a dictionary
    /// of RAM buffers for previously computed states. This way we can switch between
    /// layouts without having to recompute them
    /// </summary>
    public class GraphLayoutState
    {
        /// <summary>
        /// Create buffers for a graph rendering
        /// </summary>
        /// <param name="graph">The graph the layout applies to</param>
        /// <param name="device">The graphicsdevice for VRAM operations</param>
        /// <param name="style">The intial style of the layout</param>
        public GraphLayoutState(PlottedGraph graph, GraphicsDevice device, LayoutStyles.Style style)
        {
            GraphPlot = graph;
            _VRAMBuffers.Style = style;
            _gd = device;
            Logging.RecordLogEvent($"Layout state {GraphPlot.TID} inited", Logging.LogFilterType.BulkDebugLogFile);
        }

        /// <summary>
        /// Destructor to log destruction
        /// </summary>
        ~GraphLayoutState()
        {
            Logging.RecordLogEvent($"Layout state {GraphPlot.TID} disposed", Logging.LogFilterType.BulkDebugLogFile);
        }

        /// <summary>
        /// The graph for this layout
        /// </summary>
        public PlottedGraph GraphPlot;

        /// <summary>
        /// Veldrid GraphicsDevice for GPU operations
        /// </summary>
        private readonly GraphicsDevice _gd;

        /// <summary>
        /// The layout style currently plotted in the VRAM buffers
        /// </summary>
        public LayoutStyles.Style Style => _VRAMBuffers.Style;


        /// <summary>
        /// Active VRAM resident layout data for display and computation on the GPU
        /// </summary>
        public GPUBuffers _VRAMBuffers = new GPUBuffers();


        //data for the most recent layout retrieved from VRAM, for serialisation and caching to disk to free up VRAM
        private readonly Dictionary<LayoutStyles.Style, CPUBuffers> SavedStates = new Dictionary<LayoutStyles.Style, CPUBuffers>();


        Random _rng = new Random();


        /// <summary>
        /// Active graph layout in VRAM
        /// </summary>
        public class GPUBuffers
        {
            /// <summary>
            /// Positions buffers, contains node positions
            /// </summary>
            public DeviceBuffer? Positions1, Positions2;
            /// <summary>
            /// Velocity buffers, with the velocity of each node
            /// </summary>
            public DeviceBuffer? Velocities1, Velocities2;
            /// <summary>
            /// Node attributes buffers, contains node animation data
            /// </summary>
            public DeviceBuffer? Attributes1, Attributes2;

            /// <summary>
            /// Preset positions buffers, holds a target state for nodes to be moved towards
            /// </summary>
            public DeviceBuffer? PresetPositions;
            /// <summary>
            /// Edge connections, describes which nodes each node is connected to
            /// </summary>
            public DeviceBuffer? EdgeConnections;
            /// <summary>
            /// Edge Connection Indexes, used to speed up Edge connection buffer lookups
            /// </summary>
            public DeviceBuffer? EdgeConnectionIndexes;
            /// <summary>
            /// Edge strengths, the attraction force between each connected node
            /// </summary>
            public DeviceBuffer? EdgeStrengths;
            /// <summary>
            /// Various descriptions of basic blocks, for the block-based layouts
            /// </summary>
            public DeviceBuffer? BlockMetadata;
            /// <summary>
            /// Indexes of basic block centers
            /// </summary>
            public DeviceBuffer? BlockMiddles;

            /// <summary>
            /// The current version of the layout, incremented every time a compute pass is done
            /// Used to compare RAM and VRAM buffers
            /// </summary>
            public ulong RenderVersion;

            /// <summary>
            /// Have the buffers been assigned
            /// </summary>
            public bool Initialised;

            /// <summary>
            /// The style of the layout in the active buffers
            /// </summary>
            public LayoutStyles.Style Style;

            /// <summary>
            /// Whether buffers 1 or 2 are being written to
            /// </summary>
            public bool _flop;
        }

        /// <summary>
        /// First VRAM node postions buffer 
        /// </summary>
        public DeviceBuffer? PositionsVRAM1 => _VRAMBuffers.Positions1;
        /// <summary>
        /// Second VRAM node postions buffer
        /// </summary>
        public DeviceBuffer? PositionsVRAM2 => _VRAMBuffers.Positions2;
        /// <summary>
        /// First VRAM node velocity buffer 
        /// </summary>
        public DeviceBuffer? VelocitiesVRAM1 => _VRAMBuffers.Velocities1;
        /// <summary>
        /// First VRAM node velocity buffer 
        /// </summary>
        public DeviceBuffer? VelocitiesVRAM2 => _VRAMBuffers.Velocities2;
        /// <summary>
        /// First VRAM node attributes buffer
        /// </summary>
        public DeviceBuffer? AttributesVRAM1 => _VRAMBuffers.Attributes1;
        /// <summary>
        /// Second VRAM node attributes buffer
        /// </summary>
        public DeviceBuffer? AttributesVRAM2 => _VRAMBuffers.Attributes2;
        /// <summary>
        /// VRAM Edge connections buffer
        /// </summary>
        public DeviceBuffer? EdgeConnections => _VRAMBuffers.EdgeConnections;
        /// <summary>
        /// VRAM Edge connections indexes buffer
        /// </summary>
        public DeviceBuffer? EdgeConnectionIndexes => _VRAMBuffers.EdgeConnectionIndexes;
        /// <summary>
        /// VRAM Basic Block descriptions buffer
        /// </summary>
        public DeviceBuffer? BlockMetadata => _VRAMBuffers.BlockMetadata;
        /// <summary>
        /// VRAM Basic Block middle indexes
        /// </summary>
        public DeviceBuffer? BlockMiddles => _VRAMBuffers.BlockMiddles;

        /// <summary>
        /// VRAM Edge attraction strenths buffer
        /// </summary>
        public DeviceBuffer? EdgeStrengths => _VRAMBuffers.EdgeStrengths;
        /// <summary>
        /// VRAM preset node postions buffer
        /// </summary>
        public DeviceBuffer? PresetPositions => _VRAMBuffers.PresetPositions;
        /// <summary>
        /// VRAM latest render version
        /// </summary>
        public ulong RenderVersion => _VRAMBuffers.RenderVersion;
        /// <summary>
        /// Are VRAM buffers initialised
        /// </summary>
        public bool Initialised => _VRAMBuffers.Initialised;

        /// <summary>
        /// Is the layout currently snapping towards a preset layout
        /// </summary>
        public bool ActivatingPreset { get; private set; }
        /// <summary>
        /// Current preset style
        /// </summary>
        public LayoutStyles.Style PresetStyle { get; private set; }

        private int presetSteps = 0;
        /// <summary>
        /// Increment and return the preset counter
        /// </summary>
        /// <returns>The preset counter</returns>
        public int IncrementPresetSteps() => presetSteps++;
        /// <summary>
        /// Increment the VRAM layout version
        /// </summary>
        public void IncrementVersion() => _VRAMBuffers.RenderVersion++;


        private readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim();
        /// <summary>
        /// Get the VRAM buffer lock
        /// </summary>
        public ReaderWriterLockSlim Lock => _lock;

        /// <summary>
        /// Flip to the next buffer set and return the flop result
        /// </summary>
        /// <returns>flop (which buffer set to use)</returns>
        public bool flip()
        {
            bool result = _VRAMBuffers._flop;
            _VRAMBuffers._flop = !_VRAMBuffers._flop;
            return result;
        }

        /// <summary>
        /// RAM stored layout states
        /// </summary>
        public class CPUBuffers
        {
            /// <summary>
            /// Create a RAM storage object for a layout state
            /// </summary>
            /// <param name="style">The style of the layout</param>
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
                BlockMiddles = new int[] { };

                RenderVersion = 0;
                Style = style;
            }
            /// <summary>
            /// Stored node positions
            /// </summary>
            public float[] PositionsArray;
            /// <summary>
            /// Stored node velocities
            /// </summary>
            public float[] VelocityArray;
            /// <summary>
            /// Stored node attributes
            /// </summary>
            public float[] NodeAttribArray;
            /// <summary>
            /// Stored node preset positions
            /// </summary>
            public float[] PresetPositions;
            /// <summary>
            /// Layout version of the stored state
            /// </summary>
            public ulong RenderVersion;
            /// <summary>
            /// Number of edges rendered in the stored state
            /// </summary>
            public int EdgeCount;
            /// <summary>
            /// Layout style of the stored state
            /// </summary>
            public LayoutStyles.Style Style;
            /// <summary>
            /// Edge connection descriptors
            /// </summary>
            public int[] EdgeConnections; //unreferenced?
            /// <summary>
            /// Edge connection buffer indexes
            /// </summary>
            public int[] EdgeConnectionIndexes; //unreferenced?
            /// <summary>
            /// The attraction strength of each edge 
            /// </summary>
            public float[] EdgeStrengths; //unreferenced?
            /// <summary>
            /// Basic Block metadata
            /// </summary>
            public int[] BlockMetadata; //unreferenced?
            /// <summary>
            /// Basic Block middles
            /// </summary>
            public int[] BlockMiddles;
        }

        private void LockedUploadStateToVRAM(LayoutStyles.Style style)
        {
            Logging.RecordLogEvent($"UploadGraphDataToVRAMA Start {GraphPlot.TID} layout {Thread.CurrentThread.Name}", Logging.LogFilterType.BulkDebugLogFile);
            if (!SavedStates.TryGetValue(style, out CPUBuffers? sourceBuffers))
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
        /// <param name="sourceBuffers">CPUBuffers stored graph layout data to upload</param>
        private void LockedUploadStateToVRAM(CPUBuffers sourceBuffers)
        {
            Logging.RecordLogEvent($"UploadGraphDataToVRAMB Start {GraphPlot.TID} layout {Thread.CurrentThread.Name}", Logging.LogFilterType.BulkDebugLogFile);


            var bufferPair = VeldridGraphBuffers.CreateFloatsDeviceBufferPair(sourceBuffers.VelocityArray, _gd, $"_AvelBuf_{GraphPlot.TID}_");
            _VRAMBuffers.Velocities1 = bufferPair.Item1;
            _VRAMBuffers.Velocities2 = bufferPair.Item2;


            bufferPair = VeldridGraphBuffers.CreateFloatsDeviceBufferPair(sourceBuffers.PositionsArray, _gd, $"_AposBuf_{GraphPlot.TID}_");

            _VRAMBuffers.Positions1 = bufferPair.Item1;
            _VRAMBuffers.Positions2 = bufferPair.Item2;

            /*
            bufferPair = VeldridGraphBuffers.CreateFloatsDeviceBufferPair(sourceBuffers.NodeAttribArray, _gd, $"_AattBuf_{GraphPlot.TID}_");
            _VRAMBuffers.Attributes1 = bufferPair.Item1;
            _VRAMBuffers.Attributes2 = bufferPair.Item2;
            */
            _VRAMBuffers.RenderVersion = sourceBuffers.RenderVersion;

            RegenerateEdgeDataBuffers(GraphPlot);

            _VRAMBuffers.Initialised = true;
            Logging.RecordLogEvent($"UploadGraphDataToVRAM copied", Logging.LogFilterType.BulkDebugLogFile);

        }

        //todo we dont actually want to immediately purge, we want to purge oldest if we are over VRAM limit
        private void PurgeVRAMBuffers()
        {
            _VRAMBuffers.Initialised = false;
            _VRAMBuffers.RenderVersion = 0;
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Positions1);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Positions2);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Attributes1);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Attributes2);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Velocities1);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Velocities2);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.EdgeConnectionIndexes);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.EdgeConnections);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.EdgeStrengths);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.PresetPositions);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.BlockMetadata);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.BlockMiddles);
        }


        /// <summary>
        /// Retrieve the current node postitions from VRAM
        /// </summary>
        /// <returns>Array of XYZW floats</returns>
        public float[] DownloadVRAMPositions()
        {
            _lock.EnterReadLock();

            LayoutStyles.Style layout = _VRAMBuffers.Style;
            if (SavedStates.TryGetValue(layout, out CPUBuffers? saved) && saved.RenderVersion == _VRAMBuffers.RenderVersion)
            {
                _lock.ExitReadLock();
                return saved.PositionsArray.ToArray();
            }

            Debug.Assert(_VRAMBuffers.Positions1 is not null);
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


        /// <summary>
        /// Upload the CPUBuffers for a specific layout into VRAM
        /// </summary>
        /// <param name="layout">The layout state to be uploaded</param>
        public void SyncRAMToVRAM(LayoutStyles.Style layout)
        {
            _lock.EnterUpgradeableReadLock();

            //upload from RAM to VRAM if VRAM bufs not initialised at all or the VRAM has a different layout style or has an older version than in RAM
            if (SavedStates.TryGetValue(layout, out CPUBuffers? savedLayout) &&
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
                    !SavedStates.TryGetValue(_VRAMBuffers.Style, out CPUBuffers? existingState) ||
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

            if (!SavedStates.TryGetValue(_VRAMBuffers.Style, out CPUBuffers? destbuffers))
            {
                destbuffers = new CPUBuffers(_VRAMBuffers.Style);

                SavedStates[_VRAMBuffers.Style] = destbuffers;
            }


            if (_VRAMBuffers.RenderVersion > destbuffers.RenderVersion)
            {
                //Logging.RecordLogEvent($"{graph.TID} layout {this.EngineID} version {currentRenderVersion}>{graph.renderFrameVersion}", Logging.LogFilterType.BulkDebugLogFile);
                Download_NodePositions_VRAM_to_Graph(destbuffers);
                Download_NodeVelocity_VRAM_to_Graph(destbuffers);
                destbuffers.RenderVersion = _VRAMBuffers.RenderVersion;
                Logging.RecordLogEvent($"{GraphPlot.TID} layout version updated", Logging.LogFilterType.BulkDebugLogFile);

            }
        }

        private void Download_NodePositions_VRAM_to_Graph(CPUBuffers destbuffers)
        {
            Debug.Assert(PositionsVRAM1 is not null);
            Logging.RecordLogEvent($"Download_NodePositions_VRAM_to_Graph fetching {GraphPlot.TID} posbufs {PositionsVRAM1.Name}", Logging.LogFilterType.BulkDebugLogFile);

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, PositionsVRAM1);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            CopyMappedVRAMBufferToFloatArray(destinationReadView, ref destbuffers.PositionsArray);
            _gd.Unmap(destinationReadback);
            VeldridGraphBuffers.VRAMDispose(destinationReadback);
            Logging.RecordLogEvent($"Download_NodePositions_VRAM_to_Graph finished", Logging.LogFilterType.BulkDebugLogFile);

        }

        /// <summary>
        /// Set the saved float buffer in the graph after computing them in the GPU
        /// </summary>
        /// <param name="VRAMBuf">Mapped GPU buffer</param>
        /// <param name="destbuffer">RAM buffer to copy them to</param>
        public void CopyMappedVRAMBufferToFloatArray(MappedResourceView<float> VRAMBuf, ref float[] destbuffer)
        {
            int floatCount = VRAMBuf.Count;//xyzw
            if (destbuffer.Length < floatCount)
            {
                Logging.RecordLogEvent($"UpdateNodePositions called changing grp_{GraphPlot.TID} size from {destbuffer.Length} to {VRAMBuf.Count}", Logging.LogFilterType.BulkDebugLogFile);
                destbuffer = new float[floatCount]; //todo should be lots bigger
            }

            for (var i = 0; i < floatCount; i++)
            {
                destbuffer[i] = VRAMBuf[i];
            }
        }

        private void Download_NodeVelocity_VRAM_to_Graph(CPUBuffers destbuffers)
        {

            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph {GraphPlot.TID} layout", Logging.LogFilterType.BulkDebugLogFile);
            Debug.Assert(VelocitiesVRAM1 is not null);

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, VelocitiesVRAM1);

            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph readview map buf size {destinationReadback.SizeInBytes}", Logging.LogFilterType.BulkDebugLogFile);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            //uint floatCount = Math.Min(textureSize * textureSize * 4, (uint)destinationReadView.Count);
            uint floatCount = (uint)destinationReadView.Count;
            CopyMappedVRAMBufferToFloatArray(destinationReadView, ref destbuffers.VelocityArray);
            Logging.RecordLogEvent($"Download_NodeVelocity_VRAM_to_Graph done updatenode", Logging.LogFilterType.BulkDebugLogFile);
            _gd.Unmap(destinationReadback);
            VeldridGraphBuffers.VRAMDispose(destinationReadback);
        }


        /// <summary>
        /// Must hold writer lock before calling
        /// </summary>
        public void RegenerateEdgeDataBuffers(PlottedGraph graph)
        {
            Logging.RecordLogEvent($"RegenerateEdgeDataBuffers start", Logging.LogFilterType.BulkDebugLogFile);


            CreateEdgeDataBuffers(graph);
            CreateBlockMetadataBuffer(graph);
            RegeneratePresetBuffer(graph);
            if (!LayoutStyles.IsForceDirected(graph.ActiveLayoutStyle))//todo and not done
            {
                ActivatingPreset = true;
            }
            //}

            Logging.RecordLogEvent($"RegenerateEdgeDataBuffers  {graph.TID} complete", Logging.LogFilterType.BulkDebugLogFile);
        }


        /// <summary>
        /// Prepare a preset buffer to generate a non-force directed layout
        /// </summary>
        /// <param name="graph"></param>
        private void RegeneratePresetBuffer(PlottedGraph graph)
        {
            if (!LayoutStyles.IsForceDirected(graph.ActiveLayoutStyle))
            {
                VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.PresetPositions);
                float[]? presetPositons = graph.GeneratePresetPositions(PresetStyle);
                Debug.Assert(presetPositons is not null);
                _VRAMBuffers.PresetPositions = VeldridGraphBuffers.CreateFloatsDeviceBuffer(presetPositons, _gd, "Preset1");
            }

            //VeldridGraphBuffers.DoDispose(_VRAMBuffers.PresetPositions);
            // _VRAMBuffers.PresetPositions = _VRAMBuffers.Positions1;
            //VeldridGraphBuffers.CreateFloatsDeviceBuffer(SavedStates[Style].PositionsArray, _gd, $"PLP_PresetPosbuf_{graph.TID}");

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
                //    VeldridGraphBuffers.CreateFloatsDeviceBuffer(SavedStates[Style].PositionsArray, _gd, $"PLP_PresetPosbuf_{graph.TID}");

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
        private unsafe bool CreateEdgeDataBuffers(PlottedGraph graph)
        {
            Logging.RecordLogEvent($"CreateEdgeDataBuffers  {graph.TID}", Logging.LogFilterType.BulkDebugLogFile);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.EdgeConnections);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.EdgeConnectionIndexes);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.EdgeStrengths);

            if (!graph.GetEdgeRenderingData(out float[] edgeStrengths, out int[] edgeTargets, out int[] edgeMetaOffsets))
            {
                Logging.RecordLogEvent($"CreateEdgeDataBuffers zerobuf", Logging.LogFilterType.BulkDebugLogFile);
                _VRAMBuffers.EdgeConnections = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.StructuredBufferReadOnly, 4, $"BadFillerBufEdgeTargets_T{graph.TID}");
                _VRAMBuffers.EdgeStrengths = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.StructuredBufferReadOnly, 4, $"BadFillerBufEdgeStrengths_T{graph.TID}");
                _VRAMBuffers.EdgeConnectionIndexes = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.StructuredBufferReadOnly, 4, $"BadFillerBufEdgeOffsets_T{graph.TID}");
                return false;
            }


            _VRAMBuffers.EdgeConnections = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)edgeTargets.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, 4, $"EdgeTargetsBuf_T{graph.TID}");
            _VRAMBuffers.EdgeStrengths = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)edgeStrengths.Length * sizeof(float), BufferUsage.StructuredBufferReadOnly, 4, $"EdgeStrengthsBuf_T{graph.TID}");
            _VRAMBuffers.EdgeConnectionIndexes = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)edgeMetaOffsets.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, 4, $"EdgeOffsetsBuf_T{graph.TID}");

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

            //just to avoid passing null as a resource
            if (_VRAMBuffers.PresetPositions == null)
            {
                _VRAMBuffers.PresetPositions = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, 4, BufferUsage.StructuredBufferReadOnly, stride: 4, "DummyPresetAlloc");
            }

            Logging.RecordLogEvent($"CreateEdgeDataBuffers done", Logging.LogFilterType.BulkDebugLogFile);
            //PrintBufferArray(textureArray, "Created data texture:");
            return true;
        }


        /// Creates an array of metadata for basic blocks used for basic-block-centric graph layout
        private unsafe void CreateBlockMetadataBuffer(PlottedGraph graph)
        {

            Logging.RecordLogEvent($"CreateBlockDataBuffer  {graph.TID}", Logging.LogFilterType.BulkDebugLogFile);

            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.BlockMetadata);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.BlockMiddles);

            var textureSize = graph.EdgeTextureWidth();
            if (textureSize > 0)
            {
                graph.GetBlockRenderingMetadata(out int[] blockdats, out int[] blockMiddles);

                _VRAMBuffers.BlockMetadata = VeldridGraphBuffers.TrackedVRAMAlloc(_gd,
                    (uint)blockdats.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, sizeof(int), $"BlockMetadata_T{graph.TID}");

                _VRAMBuffers.BlockMiddles = VeldridGraphBuffers.TrackedVRAMAlloc(_gd,
                    (uint)blockMiddles.Length * sizeof(int), BufferUsage.StructuredBufferReadOnly, sizeof(int), $"BlockMiddles_T{graph.TID}");

                if (blockdats.Length == 0)
                {
                    return;
                }

                fixed (int* datsPtr = blockdats, midsPtr = blockMiddles)
                {
                    CommandList cl = _gd.ResourceFactory.CreateCommandList();
                    cl.Begin();
                    cl.UpdateBuffer(_VRAMBuffers.BlockMetadata, 0, (IntPtr)datsPtr, (uint)blockdats.Length * sizeof(int));
                    cl.UpdateBuffer(_VRAMBuffers.BlockMiddles, 0, (IntPtr)midsPtr, (uint)blockMiddles.Length * sizeof(int));
                    cl.End();
                    _gd.SubmitCommands(cl);
                    _gd.WaitForIdle();
                    cl.Dispose();
                }
            }


            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, newBuffer));

            Logging.RecordLogEvent($"CreateBlockDataBuffer  {graph.TID} complete", Logging.LogFilterType.BulkDebugLogFile);
            //PrintBufferArray(textureArray, "Created data texture:");
        }




        /// <summary>
        /// Takes new nodes from a graph with trace data and adds them to the compute buffers for layout
        /// Must have upgradable readlock
        /// </summary>
        /// <param name="finalCount">how many nodes to add</param>
        /// <param name="graph">The graph with new nodes</param>
        public unsafe void AddNewNodesToComputeBuffers(int finalCount, PlottedGraph graph)
        {
            Logging.RecordLogEvent($"AddNewNodesToComputeBuffers <{finalCount - graph.ComputeBufferNodeCount}?  {graph.TID} start", Logging.LogFilterType.BulkDebugLogFile);
            int newNodeCount = finalCount - graph.ComputeBufferNodeCount;
            if (newNodeCount == 0)
            {
                return;
            }

            Debug.Assert(graph.ActiveLayoutStyle == _VRAMBuffers.Style);

            uint offset = (uint)graph.ComputeBufferNodeCount * 4 * sizeof(float);
            uint updateSize = 4 * sizeof(float) * (uint)newNodeCount;
            List<DeviceBuffer?> disposals = new List<DeviceBuffer?>();
            CPUBuffers RAMbufs = SavedStates[graph.LayoutState.Style];

            CommandList cl = _gd.ResourceFactory.CreateCommandList();
            cl.Begin();


            if (!_VRAMBuffers.Initialised || (offset + updateSize) > VelocitiesVRAM1!.SizeInBytes)
            {
                _lock.EnterWriteLock();
                if (!_VRAMBuffers.Initialised || (offset + updateSize) > VelocitiesVRAM1!.SizeInBytes)
                {
                    var bufferWidth = graph.NestedIndexTextureSize();
                    var bufferFloatCount = bufferWidth * bufferWidth * 4;
                    var bufferSize = bufferFloatCount * sizeof(float);
                    Debug.Assert(bufferSize >= updateSize);

                    if (_VRAMBuffers.Initialised)
                    {
                        Logging.RecordLogEvent($"Recreating buffers as {bufferSize} > {VelocitiesVRAM1!.SizeInBytes}", Logging.LogFilterType.TextDebug);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Creating VRAM buffers size {bufferSize} for graph {graph.TID}", Logging.LogFilterType.TextDebug);
                    }
                    ResizeComputeBuffers(graph, bufferSize, cl, ref disposals);
                }
                _lock.ExitWriteLock();
                Logging.RecordLogEvent($"AddNewNodesToComputeBuffers  {graph.TID} done", Logging.LogFilterType.BulkDebugLogFile);
            }

            Debug.Assert(VelocitiesVRAM1 is not null);


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

            disposals.ForEach(buf => VeldridGraphBuffers.VRAMDispose(buf));

            graph.ComputeBufferNodeCount = finalCount;
        }





        /// <summary>
        /// Adjust the compute buffers to fit new nodes
        /// Must hold writer lock before calling
        /// </summary>
        /// <param name="graph">The graph with new nodes</param>
        /// <param name="bufferSize">The new buffer size</param>
        /// <param name="cl">Veldrid CommandList to place commands on</param>
        /// <param name="disposals">Buffers to dispose of</param>
        private void ResizeComputeBuffers(PlottedGraph graph, uint bufferSize, CommandList cl, ref List<DeviceBuffer?> disposals)
        {

            uint zeroFillStart = 0;
            if (_VRAMBuffers.Initialised)
            {
                zeroFillStart = PositionsVRAM1!.SizeInBytes;
            }

            BufferDescription bd = new BufferDescription(bufferSize, BufferUsage.StructuredBufferReadWrite, 4);

            DeviceBuffer velocityBuffer1B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Vel1ZeroFilled_T{graph.TID}");
            DeviceBuffer positionsBuffer1B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Pos1ZeroFilled_T{graph.TID}");
            DeviceBuffer velocityBuffer2B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Vel2ZeroFilled_T{graph.TID}");
            DeviceBuffer positionsBuffer2B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Pos2ZeroFilled_T{graph.TID}");
            DeviceBuffer attribsBuffer1B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Att1ZeroFilled_T{graph.TID}");
            DeviceBuffer attribsBuffer2B = VeldridGraphBuffers.CreateZeroFilledBuffer(bd, _gd, zeroFillStart, $"Att2ZeroFilled_T{graph.TID}");

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



        /// <summary>
        /// recreate node attributes with zero state
        /// useful for ending an animation sequence
        /// </summary>
        /// <param name="_gd">Veldrid GraphicsDevice</param>
        public void ResetNodeAttributes(GraphicsDevice _gd)
        {
            Logging.RecordLogEvent($"ResetNodeAttributes ", Logging.LogFilterType.BulkDebugLogFile);

            uint bufferSize = AttributesVRAM1?.SizeInBytes ?? 1024;
            BufferDescription bd = new BufferDescription(bufferSize, BufferUsage.StructuredBufferReadWrite, 4);

            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Attributes1);
            VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Attributes2);

            _VRAMBuffers.Attributes1 = VeldridGraphBuffers.CreateDefaultAttributesBuffer(bd, _gd, "NodeAttribs");
            _VRAMBuffers.Attributes2 = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, _VRAMBuffers.Attributes1.SizeInBytes, _VRAMBuffers.Attributes1.Usage, 4, $"RNA_AattBuf2_{ GraphPlot.TID}");

            _VRAMBuffers._flop = true; //process attribs buffer 1 first into buffer 2, saves on an extra copy
        }


        /// <summary>
        /// Get a previously computed set of positions
        /// </summary>
        /// <param name="layoutStyle">style to fetch</param>
        /// <param name="buf">output xyzw positions floats</param>
        /// <returns></returns>
        public bool GetSavedLayout(LayoutStyles.Style layoutStyle, out float[]? buf)
        {
            if (SavedStates.TryGetValue(layoutStyle, out CPUBuffers? saved) && saved.PositionsArray.Any())
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


        /// <summary>
        /// Get the stored (RAM) attribute buffers 
        /// Must hold upgradable read lock
        /// </summary>
        /// <param name="layoutStyle">The saved plot</param>
        /// <param name="buf">The outout float buffer containing the retrieved values</param>
        /// <returns>true if found</returns>
        public bool GetAttributes(LayoutStyles.Style layoutStyle, out float[]? buf)
        {
            if (SavedStates.TryGetValue(layoutStyle, out CPUBuffers? saved))
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


        /// <summary>
        /// Add a new node to the active compute buffers
        /// </summary>
        /// <param name="nodeIdx">Index of nodes we are adding</param>
        /// <param name="futureCount">Expected number of nodes after this is added</param>
        /// <param name="bufferWidth">Width of the compute buffer</param>
        /// <param name="edge"></param>
        public unsafe void AddNode(uint nodeIdx, uint futureCount, uint bufferWidth, EdgeData? edge = null)
        {

            var bounds = Math.Max(1000, (nodeIdx * 12) + 500);
            var bounds_half = bounds / 2;

            PlottedGraph graph = GraphPlot;
            if (!SavedStates.TryGetValue(graph.ActiveLayoutStyle, out CPUBuffers? bufs))
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
            Debug.Assert(bufs.VelocityArray is not null && bufs.PositionsArray.Length == bufs.VelocityArray.Length);
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
            float[] nodePositionEntry = {
                ((float)_rng.NextDouble() * bounds) - bounds_half,
                ((float)_rng.NextDouble() * bounds) - bounds_half,
                ((float)_rng.NextDouble() * bounds) - bounds_half, 1 };


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

            bufs.NodeAttribArray[currentOffset] = CONSTANTS.Anim_Constants.DEFAULT_NODE_DIAMETER;
            bufs.NodeAttribArray[currentOffset + 1] = 1f;// 0.5f;
            bufs.NodeAttribArray[currentOffset + 2] = 0;
            bufs.NodeAttribArray[currentOffset + 3] = 0;


        }


        private static void EnlargeRAMDataBuffers(uint size, CPUBuffers bufs)
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


        /// <summary>
        /// Initiate the swap of layout buffers into VRAM
        /// </summary>
        /// <param name="newStyle">The style of the layout to change to</param>
        /// <param name="forceSame">If true then the same layout can be replot</param>
        public void TriggerLayoutChange(LayoutStyles.Style newStyle, bool forceSame = false)
        {

            if (newStyle == _VRAMBuffers.Style && forceSame is false)
            {
                return;
            }

            Lock.EnterWriteLock();

            DownloadStateFromVRAM();

            presetSteps = 0;
            PresetStyle = newStyle;
            float[]? positions = GraphPlot.GeneratePresetPositions(PresetStyle);
            Debug.Assert(positions is not null);
            _VRAMBuffers.PresetPositions = VeldridGraphBuffers.CreateFloatsDeviceBuffer(positions, _gd, "Preset1");
            ActivatingPreset = true;

            Lock.ExitWriteLock();
        }


        /// <summary>
        /// Layout randomisation methods
        /// </summary>
        public enum PositionResetStyle
        {
            ///Scatter in a wide area
            Scatter,
            ///Gather in a tiny mass
            Explode,
            ///Distribute around the edge
            Implode,
            ///Spread out in a vertical line
            Pillar
        }


        /// <summary>
        /// Cause a force directed plot to be randomly re-distributed in the
        /// specified style. Use this to try a different arrangement.
        /// </summary>
        /// <param name="resetMethod">The initial randomisation method</param>
        /// <param name="spread">How far to spread the replotted nodes</param>
        public void ResetForceLayout(PositionResetStyle resetMethod, float spread = 2)
        {

            if (LayoutStyles.IsForceDirected(this.Style) is false) return;

            _lock.EnterWriteLock();

            DownloadStateFromVRAM();

            CPUBuffers oldData = this.SavedStates[this.Style];

            switch (resetMethod)
            {
                case PositionResetStyle.Scatter:
                    ScatterPositions(oldData, spread: spread);
                    break;
                case PositionResetStyle.Explode:
                    ExplodePositions(oldData);
                    break;
                case PositionResetStyle.Implode:
                    ImplodePositions(oldData, spread: spread);
                    break;
                case PositionResetStyle.Pillar:
                    PillarPositions(oldData, spread: spread);
                    break;

            }

            this.LockedUploadStateToVRAM(oldData);
            _lock.ExitWriteLock();
        }


        /// <summary>
        /// Distributes the nodes in a concentrated central mass so they repel each other out
        /// and then into arrangement
        /// </summary>
        /// <param name="layoutRAMBuffers">CPUBuffers of the plot to be randomised</param>
        private static void ExplodePositions(CPUBuffers layoutRAMBuffers)
        {
            Random rnd = new Random();

            int endLength = layoutRAMBuffers.PositionsArray.Length;
            for (var i = 0; i < endLength; i += 4)
            {
                if (layoutRAMBuffers.PositionsArray[i + 3] == 0)
                {
                    break;
                }

                layoutRAMBuffers.VelocityArray[i] = 0; //rnd.Next(100);
                layoutRAMBuffers.VelocityArray[i + 1] = 0; //rnd.Next(100);
                layoutRAMBuffers.VelocityArray[i + 2] = 0;// rnd.Next(100);

                layoutRAMBuffers.PositionsArray[i] = (float)rnd.NextDouble();
                layoutRAMBuffers.PositionsArray[i + 1] = (float)rnd.NextDouble();
                layoutRAMBuffers.PositionsArray[i + 2] = (float)rnd.NextDouble();
            }
        }


        /// <summary>
        /// Distributes the nodes on the edge of a sphere. 
        /// Attraction dominates the intial stages of layout
        /// </summary>
        /// <param name="layoutRAMBuffers">CPUBuffers of the plot to be randomised</param>
        /// <param name="spread">How far to spread nodes</param>
        private static void ImplodePositions(CPUBuffers layoutRAMBuffers, float spread = 2)
        {
            Random rnd = new Random();

            float radius = (layoutRAMBuffers.PositionsArray.Length / 4) * spread;
            int endLength = layoutRAMBuffers.PositionsArray.Length;
            for (var i = 0; i < endLength; i += 4)
            {
                layoutRAMBuffers.VelocityArray[i] = rnd.Next(100);
                layoutRAMBuffers.VelocityArray[i + 1] = rnd.Next(100);
                layoutRAMBuffers.VelocityArray[i + 2] = rnd.Next(100);

                getPoint(rnd, radius, out float x, out float y, out float z);
                layoutRAMBuffers.PositionsArray[i] = x;
                layoutRAMBuffers.PositionsArray[i + 1] = y;
                layoutRAMBuffers.PositionsArray[i + 2] = z;
            }
        }


        //https://karthikkaranth.me/blog/generating-random-points-in-a-sphere/
        private static void getPoint(Random rnd, float radius, out float x, out float y, out float z)
        {
            var u = rnd.NextDouble();
            var v = rnd.NextDouble();
            var theta = u * 2.0 * Math.PI;
            var phi = Math.Acos(2.0 * v - 1.0);
            //var r = Math.Cbrt(rnd.NextDouble());
            var sinTheta = Math.Sin(theta);
            var cosTheta = Math.Cos(theta);
            var sinPhi = Math.Sin(phi);
            var cosPhi = Math.Cos(phi);
            x = (float)(radius * sinPhi * cosTheta);
            y = (float)(radius * sinPhi * sinTheta);
            z = (float)(radius * cosPhi);
        }


        /// <summary>
        /// Distributes the nodes randomly in a wide area. 
        /// Balance of attraction and repulsion will move them into position
        /// </summary>
        /// <param name="layoutRAMBuffers">CPUBuffers of the plot to be randomised</param>
        /// <param name="spread">How far to spread nodes</param>
        private static void ScatterPositions(CPUBuffers layoutRAMBuffers, float spread = 2)
        {
            Random rnd = new Random();
            float MaxDimension = (layoutRAMBuffers.VelocityArray.Length / 4) * spread;
            float MinDimension = -1 * MaxDimension;

            int endLength = layoutRAMBuffers.VelocityArray.Length;
            for (var i = 0; i < endLength; i += 4)
            {
                layoutRAMBuffers.VelocityArray[i] = rnd.Next(100);
                layoutRAMBuffers.VelocityArray[i + 1] = rnd.Next(100);
                layoutRAMBuffers.VelocityArray[i + 2] = rnd.Next(100);

                layoutRAMBuffers.PositionsArray[i] = RandomFloat(rnd, MinDimension, MaxDimension);
                layoutRAMBuffers.PositionsArray[i + 1] = RandomFloat(rnd, MinDimension, MaxDimension);
                layoutRAMBuffers.PositionsArray[i + 2] = RandomFloat(rnd, MinDimension, MaxDimension);
            }
        }


        private static void PillarPositions(CPUBuffers layoutRAMBuffers, float spread = 2)
        {

            Random rnd = new Random();
            float MaxDimension = 40 * spread;
            float MinDimension = -1 * MaxDimension;

            int endLength = layoutRAMBuffers.VelocityArray.Length;
            for (var i = 0; i < endLength; i += 4)
            {
                layoutRAMBuffers.VelocityArray[i] = rnd.Next(100);
                layoutRAMBuffers.VelocityArray[i + 1] = rnd.Next(100);
                layoutRAMBuffers.VelocityArray[i + 2] = rnd.Next(100);

                layoutRAMBuffers.PositionsArray[i] = RandomFloat(rnd, MinDimension, MaxDimension);
                layoutRAMBuffers.PositionsArray[i + 1] = -1 * i * spread;
                layoutRAMBuffers.PositionsArray[i + 2] = RandomFloat(rnd, MinDimension, MaxDimension);
            }
        }



        static float RandomFloat(Random rnd, float min, float max)
        {
            return (float)rnd.NextDouble() * (max - min) + min;
        }


        /// <summary>
        /// The layout is now in RAM. Positions are in the preset buffer. 
        /// Start moving the existing nodes towards them
        /// </summary>
        public void CompleteLayoutChange()
        {
            Lock.EnterWriteLock();
            ActivatingPreset = false;
            this._VRAMBuffers.Style = PresetStyle;

            if (LayoutStyles.IsForceDirected(PresetStyle))
            {
                if (SavedStates.TryGetValue(PresetStyle, out CPUBuffers? cpubufs))
                {
                    this.LockedUploadStateToVRAM(cpubufs);
                }
                else
                {
                    //Debug.Assert(false, "shouldn't be snapping to nonexistent preset");
                    VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Positions1);
                    VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Positions2);
                    VeldridGraphBuffers.CreateBufferCopyPair(_VRAMBuffers.PresetPositions!, _gd, out _VRAMBuffers.Positions1, out _VRAMBuffers.Positions2, name: "PresetCopyFD");

                    RegenerateEdgeDataBuffers(GraphPlot);
                }
            }
            else
            {
                VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Positions1);
                VeldridGraphBuffers.VRAMDispose(_VRAMBuffers.Positions2);
                VeldridGraphBuffers.CreateBufferCopyPair(_VRAMBuffers.PresetPositions!, _gd, out _VRAMBuffers.Positions1, out _VRAMBuffers.Positions2, name: "PresetCopy");

            }

            //

            Lock.ExitWriteLock();

        }


    }



}
