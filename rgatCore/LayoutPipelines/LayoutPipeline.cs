using System;
using Veldrid;

namespace rgat.LayoutPipelines
{
    abstract class LayoutPipeline : IDisposable
    {
        protected Pipeline? _positionComputePipeline, _velocityComputePipeline;
        protected Shader? _positionShader, _velocityShader;
        protected DeviceBuffer? _velocityParamsBuffer, _positionParamsBuffer;
        protected ResourceLayout? _velocityShaderRsrcLayout;
        protected ResourceLayout? _positionShaderRsrcLayout;

        protected readonly object _lock = new object();
        protected readonly GraphicsDevice _gd;
        protected readonly CommandList _cl;


        readonly protected System.Diagnostics.Stopwatch _timer = new();

        public double? PositionTime { get; protected set; } = null;
        public double? VelocityTime { get; protected set; } = null;
        public double? PositionSetupTime { get; protected set; } = null;
        public double? VelocitySetupTime { get; protected set; } = null;
        bool _disposed = false;

        protected LayoutPipeline(GraphicsDevice gdev)
        {
            _gd = gdev;
            _cl = _gd.ResourceFactory.CreateCommandList();
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
                _cl.Dispose();
            }
            _disposed = true;
        }

        public abstract void Compute(PlottedGraph plot, bool flip, float delta);
    }
}
