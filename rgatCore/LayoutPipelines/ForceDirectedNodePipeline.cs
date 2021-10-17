using System;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Veldrid;

namespace rgat.Layouts
{
    class ForceDirectedNodePipeline : LayoutPipelines.LayoutPipeline
    {
        public ForceDirectedNodePipeline(GraphicsDevice gdev) : base(gdev)
        {
            SetupComputeResources();
        }

        bool _disposed = false;
        public override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _velocityShader?.Dispose();
                    _velocityShaderRsrcLayout?.Dispose();
                    _velocityComputePipeline?.Dispose();
                    _positionShader?.Dispose();
                    _positionShaderRsrcLayout?.Dispose();
                    _positionComputePipeline?.Dispose();
                }
                _disposed = true;
            }
            base.Dispose(disposing);
        }

        /*
         * 
         * Velocity computation shader assigns a velocity to each node based on nearby nodes, edges
         * or preset target positions
         * 
         */
        [StructLayout(LayoutKind.Sequential)]
        private struct VelocityShaderParams
        {
            public float delta;
            public float temperature;
            public float repulsionK;
            public uint nodeCount;
        }

        private unsafe void SetupComputeResources()
        {
            ResourceFactory factory = _gd.ResourceFactory;

            if (_gd.Features.ComputeShader is false) { Logging.RecordError("Error: Compute shaders are unavailable"); return; }

            _velocityParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<VelocityShaderParams>(), BufferUsage.UniformBuffer, name: "VelocityShaderParams");

            byte[]? velocityShaderBytes = ImGuiNET.ImGuiController.LoadEmbeddedShaderCode(factory, "sim-nodeVelocity", ShaderStages.Compute);
            _velocityShader = factory.CreateShader(new ShaderDescription(ShaderStages.Compute, velocityShaderBytes, "main"));

            _velocityShaderRsrcLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("presetPositions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeIndices", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeData", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("edgeStrengths", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)));

            ComputePipelineDescription VelocityCPD = new ComputePipelineDescription(_velocityShader, _velocityShaderRsrcLayout, 16, 16, 1); //todo: i dont understand this. experiment with group sizes.

            _velocityComputePipeline = factory.CreateComputePipeline(VelocityCPD);


            _positionShaderRsrcLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(
            new ResourceLayoutElementDescription("Params", ResourceKind.UniformBuffer, ShaderStages.Compute),
            new ResourceLayoutElementDescription("positions", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("velocities", ResourceKind.StructuredBufferReadOnly, ShaderStages.Compute),
            new ResourceLayoutElementDescription("resultData", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)
            ));


            byte[]? positionShaderBytes;
            /*
             * This is how we would compile the compute shaders instead of loading pre-compiled 
             * 177ms~ ish for this simple shader - multiplied by the different pipelines and stages this would add a lot to startup time
             *   so for now going to keep embedding them in resources. This at least illustrates how to do startup-time compilation.
            */
            /*
            if (velocityShaderBytes is null)
            {
                _timer.Restart();
                positionShaderBytes = Veldrid.SPIRV.SpirvCompilation.CompileGlslToSpirv(positionShaderSource, null, ShaderStages.Compute, Veldrid.SPIRV.GlslCompileOptions.Default).SpirvBytes;
                _timer.Stop();
                Logging.RecordLogEvent($"Compilation for ForceDirectedNode Position shader took {_timer.Elapsed.TotalMilliseconds:F1}ms");
            }
            */
            positionShaderBytes = ImGuiNET.ImGuiController.LoadEmbeddedShaderCode(factory, "sim-nodePosition", ShaderStages.Compute);

            _positionShader = factory.CreateShader(new ShaderDescription(ShaderStages.Compute, positionShaderBytes, "main"));
            ComputePipelineDescription PositionCPD = new ComputePipelineDescription(_positionShader, _positionShaderRsrcLayout, 16, 16, 1);
            _positionComputePipeline = factory.CreateComputePipeline(PositionCPD);
            _positionParamsBuffer = VeldridGraphBuffers.TrackedVRAMAlloc(_gd, (uint)Unsafe.SizeOf<PositionShaderParams>(), BufferUsage.UniformBuffer, name: "PositionShaderParams");
        }





        public override void Compute(PlottedGraph plot, bool flip, float delta)
        {
            GraphLayoutState layout = plot.LayoutState;
            ResourceSetDescription velocity_rsrc_desc, pos_rsrc_desc;
            if (flip)
            {
                velocity_rsrc_desc = new ResourceSetDescription(_velocityShaderRsrcLayout,
                    _velocityParamsBuffer, layout.PositionsVRAM1, layout.VelocitiesVRAM1, layout.PresetPositions, layout.EdgeConnectionIndexes,
                    layout.EdgeConnections, layout.EdgeStrengths, 
                layout.VelocitiesVRAM2
                );

                pos_rsrc_desc = new ResourceSetDescription(_positionShaderRsrcLayout,
                    _positionParamsBuffer, layout.PositionsVRAM1, layout.VelocitiesVRAM2,
                   layout.PositionsVRAM2);
            }
            else
            {
                velocity_rsrc_desc = new ResourceSetDescription(_velocityShaderRsrcLayout,
                _velocityParamsBuffer, layout.PositionsVRAM2, layout.VelocitiesVRAM2, layout.PresetPositions, layout.EdgeConnectionIndexes,
                layout.EdgeConnections, layout.EdgeStrengths, 
                layout.VelocitiesVRAM1
                );

                pos_rsrc_desc = new ResourceSetDescription(_positionShaderRsrcLayout,
                    _positionParamsBuffer, layout.PositionsVRAM2, layout.VelocitiesVRAM1,
                    layout.PositionsVRAM1);
            }

            RenderVelocity(velocity_rsrc_desc, plot, delta);
            RenderPosition(pos_rsrc_desc, plot, delta);
        }



        /// <summary>
        /// Pass the graph plot through the velocity compute shader, to adjust the node velocity based on the positions of other nodes
        /// </summary>
        /// <param name="RSetDesc">Velocity shader resource set</param>
        /// <param name="plot">PlottedGraph to compute</param>
        /// <param name="delta">A float representing how much time has passed since the last frame. Higher values => bigger movements</param>
        private void RenderVelocity(ResourceSetDescription RSetDesc, PlottedGraph plot, float delta)
        {
            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderVelocity  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);

            _timer.Restart();
            _cl.Begin();

            ResourceSet resourceSet = _gd.ResourceFactory.CreateResourceSet(RSetDesc);
            uint nodeCount = (uint)plot.RenderedNodeCount();
            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderVelocityBlocks  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);
            GraphLayoutState layout = plot.LayoutState;
            VelocityShaderParams parameters = new VelocityShaderParams
            {
                delta = delta, //not used
                temperature = Math.Min(plot.Temperature, GlobalConfig.MaximumNodeTemperature),
                repulsionK = GlobalConfig.RepulsionK,
                nodeCount = nodeCount
            };

            Debug.Assert(nodeCount <= (layout.VelocitiesVRAM1!.SizeInBytes/16));
            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} submit", Logging.LogFilterType.BulkDebugLogFile);

            _cl.UpdateBuffer(_velocityParamsBuffer, 0, parameters);
            _cl.SetPipeline(_velocityComputePipeline);
            _cl.SetComputeResourceSet(0, resourceSet);

            //16 == sizeof(Vector4)
            uint elemCount = layout.VelocitiesVRAM1!.SizeInBytes / 16;
            uint grpSizeX = (uint)Math.Ceiling(elemCount / 256.0);
            //Console.WriteLine($"VRAM Size: {layout.VelocitiesVRAM1!.SizeInBytes}bytes, WkX: {grpSizeX}, nodeCount: {nodeCount}, bufVel4Count: {layout.VelocitiesVRAM1!.SizeInBytes/16}");
            _cl.Dispatch(grpSizeX, 1, 1);
            //_cl.Dispatch((uint)Math.Ceiling(layout.VelocitiesVRAM1!.SizeInBytes / (256.0 * 16)), 1, 1);
            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderVelocity  {this.EngineID} done in {watch.ElapsedMilliseconds} MS", Logging.LogFilterType.BulkDebugLogFile);

            _cl.End();
            _timer.Stop();
            VelocitySetupTime = _timer.Elapsed.TotalMilliseconds;

            _timer.Restart();
            _gd!.SubmitCommands(_cl);
            _gd!.WaitForIdle();
            _gd.DisposeWhenIdle(resourceSet);

            _timer.Stop();
            VelocityTime = _timer.Elapsed.TotalMilliseconds;
        }


        /// <summary>
        /// Used the velocity buffer to move the nodes in the positions buffer
        /// </summary>
        /// <param name="RSetDesc">Position shader resource set</param>
        /// <param name="plot">PlottedGraph to compute</param>
        /// <param name="delta">A float representing how much time has passed since the last frame. Higher values => bigger movements</param>
        private unsafe void RenderPosition(ResourceSetDescription RSetDesc, PlottedGraph plot, float delta)
        {
            _timer.Restart();
            _cl.Begin();

            ResourceSet resourceSet = _gd.ResourceFactory.CreateResourceSet(RSetDesc);
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, positions));
            //Debug.Assert(!VeldridGraphBuffers.DetectNaN(_gd, velocities));

            //if (GlobalConfig.Settings.Logs.BulkLogging) Logging.RecordLogEvent($"RenderPosition  {this.EngineID}", Logging.LogFilterType.BulkDebugLogFile);

            PositionShaderParams parameters = new PositionShaderParams
            {
                delta = delta,
                nodeCount = (uint)plot.RenderedNodeCount()
            };

            //Logging.WriteConsole($"RenderPosition Parambuffer Size is {(uint)Unsafe.SizeOf<PositionShaderParams>()}");

            _cl.UpdateBuffer(_positionParamsBuffer, 0, parameters);
            _cl.SetPipeline(_positionComputePipeline);
            _cl.SetComputeResourceSet(0, resourceSet);
            _cl.Dispatch((uint)Math.Ceiling(plot.LayoutState.PositionsVRAM1!.SizeInBytes / (256.0 * sizeof(Vector4))), 1, 1);
            _cl.End();
            _timer.Stop();
            PositionSetupTime = _timer.Elapsed.TotalMilliseconds;

            _timer.Restart();
            _gd!.SubmitCommands(_cl);
            _gd!.WaitForIdle();
            _gd.DisposeWhenIdle(resourceSet);
            _timer.Stop();
            PositionTime = _timer.Elapsed.TotalMilliseconds;    
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
            public uint nodeCount;
            //must be multiple of 16
            private readonly uint _padding1;
            private readonly uint _padding2;

        }

        /// <summary>
        /// No real reason for this to be here - just illustrating that these can be compiled
        /// at runtime
        /// </summary>
        const string positionShaderSource = @"
/*
Copyright (c) 2014-2015, MetaStack Inc.
All rights reserved.

Code vulkanised from https://github.com/jaredmcqueen/analytics/blob/7fa833bb07e2f145dba169b674f8865566970a68/shaders/sim-position.glsl

See included licence: METASTACK ANALYTICS LICENSE

to compile 

glslangValidator.exe  -V sim-nodePosition.glsl -o sim-nodePosition.spv -S comp
*/

#version 450

struct PositionParams
{
    float delta;
    uint nodeCount;
};
layout(set = 0, binding=0) uniform Params{  PositionParams fieldParams;};
layout(set = 0, binding=1) buffer bufpositions{vec4 positions[];};
layout(set = 0, binding=2) buffer bufvelocities{vec4 velocities[];};
layout(set = 0, binding=3) buffer resultData{  vec4 field_Destination[];};


layout (local_size_x = 256) in;

void main()	{ 
    uint index = gl_GlobalInvocationID.x;

    if (index < fieldParams.nodeCount)
    {
        vec4 selfPosition = positions[index];    
        field_Destination[index] = vec4( selfPosition.xyz + velocities[index].xyz * fieldParams.delta * 50.0, selfPosition.w );
    }
}
";

    }
}
