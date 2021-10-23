using System;
using Veldrid;

namespace rgat.LayoutPipelines
{
    abstract class LayoutPipeline : IDisposable
    {
        public string Name { get; private set; } = "Unset";
        protected Pipeline? _positionComputePipeline, _velocityComputePipeline;
        protected Shader? _positionShader, _velocityShader;
        protected DeviceBuffer? _velocityParamsBuffer, _positionParamsBuffer;
        protected ResourceLayout? _velocityShaderRsrcLayout;
        protected ResourceLayout? _positionShaderRsrcLayout;

        protected readonly object _lock = new object();
        protected readonly GraphicsDevice _gd;


        readonly protected System.Diagnostics.Stopwatch _timer = new();

        public double? PositionTime { get; protected set; } = null;
        public double? VelocityTime { get; protected set; } = null;
        public double? PositionSetupTime { get; protected set; } = null;
        public double? VelocitySetupTime { get; protected set; } = null;
        bool _disposed = false;

        protected LayoutPipeline(GraphicsDevice gdev, string name)
        {
            _gd = gdev;
            Name = name;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public virtual void Dispose(bool disposing)
        {
            if (_disposed) { 
                return; 
            }

            if (disposing)
            {
                //there used to be a command list here
            }
            _disposed = true;
        }

        public abstract void Compute(PlottedGraph plot, CommandList cl, bool flip, float delta);
    }
}
