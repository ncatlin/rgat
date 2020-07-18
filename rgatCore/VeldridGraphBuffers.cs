using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Veldrid;

namespace rgatCore
{
    class VeldridGraphBuffers
    {
        public VeldridGraphBuffers(PlottedGraph _graph) => graph = _graph;

        PlottedGraph graph;
        Pipeline _linesPipeline;
        VertexPositionColor[] _LineVertices;
        DeviceBuffer _LineVertexBuffer;
        DeviceBuffer _LineIndexBuffer;

        Pipeline _wireframePipeline;
        VertexPositionColor[] _WireframeVertices;
        DeviceBuffer _WireframeVertexBuffer;
        DeviceBuffer _WireframeIndexBuffer;

        Pipeline _pointsPipeline;
        VertexPositionColor[] _PointVertices;
        DeviceBuffer _PointVertexBuffer;
        DeviceBuffer _PointIndexBuffer;

        ResourceSet _projViewSet;
        public DeviceBuffer _worldBuffer { get; private set; }
        public DeviceBuffer _projectionBuffer { get; private set; }
        public DeviceBuffer _viewBuffer { get; private set; }

        public void InitLineVertexData(GraphicsDevice _gd)
        {

            if (!(graph.previewlines.safe_get_vert_array(out _LineVertices)))
            {
                Console.WriteLine("Unhandled error 1");
            }

            Console.WriteLine($"Initing graph with {_LineVertices.Length} line verts");

            ResourceFactory factory = _gd.ResourceFactory;
            if (_LineIndexBuffer != null)
            {
                _LineIndexBuffer.Dispose();
                _LineVertexBuffer.Dispose();
            }

            BufferDescription vbDescription = new BufferDescription(
                (uint)_LineVertices.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
            _LineVertexBuffer = factory.CreateBuffer(vbDescription);
            _gd.UpdateBuffer(_LineVertexBuffer, 0, _LineVertices);


            List<ushort> lineIndices = Enumerable.Range(0, _LineVertices.Length)
                .Select(i => (ushort)i)
                .ToList();

            BufferDescription ibDescription = new BufferDescription((uint)lineIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
            _LineIndexBuffer = factory.CreateBuffer(ibDescription);
            _gd.UpdateBuffer(_LineIndexBuffer, 0, lineIndices.ToArray());
        }

        ResourceLayout SetupProjectionBuffers(ResourceFactory factory)
        {
            ResourceLayoutElementDescription pb = new ResourceLayoutElementDescription("ProjectionBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex);
            ResourceLayoutElementDescription vb = new ResourceLayoutElementDescription("ViewBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex);
            ResourceLayoutElementDescription wb = new ResourceLayoutElementDescription("WorldBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex);
            ResourceLayout projViewLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(pb, vb, wb));
            _worldBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer));
            _projectionBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer));
            _viewBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer));
            _projViewSet = factory.CreateResourceSet(new ResourceSetDescription(projViewLayout, _projectionBuffer, _viewBuffer, _worldBuffer));
            return projViewLayout;
        }

        public void InitWireframeVertexData(GraphicsDevice _gd)
        {

            if (!(graph.wireframelines.safe_get_vert_array(out _WireframeVertices)))
            {
                Console.WriteLine("Unhandled error 1");
            }


            Console.WriteLine($"Initing graph with {_WireframeVertices.Length} wireframe verts");

            ResourceFactory factory = _gd.ResourceFactory;

            if (_WireframeIndexBuffer != null)
            {
                _WireframeIndexBuffer.Dispose();
                _WireframeVertexBuffer.Dispose();
            }


            BufferDescription vbDescription = new BufferDescription(
                (uint)_WireframeVertices.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
            _WireframeVertexBuffer = factory.CreateBuffer(vbDescription);
            _gd.UpdateBuffer(_WireframeVertexBuffer, 0, _WireframeVertices);

            List<ushort> wfIndices = Enumerable.Range(0, _WireframeVertices.Length)
                .Select(i => (ushort)i)
                .ToList();

            BufferDescription ibDescription = new BufferDescription((uint)wfIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
            _WireframeIndexBuffer = factory.CreateBuffer(ibDescription);
            _gd.UpdateBuffer(_WireframeIndexBuffer, 0, wfIndices.ToArray());
        }

        public void InitPipelines(GraphicsDevice _gd, ShaderSetDescription shaders, Framebuffer frmbuf, bool wireframe = false)
        {
            ResourceFactory factory = _gd.ResourceFactory;
            ResourceLayout projViewLayout = SetupProjectionBuffers(factory);


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
            pipelineDescription.ResourceLayouts = new[] { projViewLayout };
            pipelineDescription.ShaderSet = shaders;

            pipelineDescription.Outputs = frmbuf.OutputDescription;

            if (wireframe)
            {
                pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
                _wireframePipeline = factory.CreateGraphicsPipeline(pipelineDescription);
            }

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineStrip;
            _linesPipeline = factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = factory.CreateGraphicsPipeline(pipelineDescription);
        }

        public void DrawWireframe(CommandList _cl)
        {
            _cl.SetVertexBuffer(0, _WireframeVertexBuffer);
            _cl.SetIndexBuffer(_WireframeIndexBuffer, IndexFormat.UInt16);
            _cl.SetPipeline(_wireframePipeline);
            _cl.SetGraphicsResourceSet(0, _projViewSet);
            _cl.DrawIndexed(
                indexCount: (uint)_WireframeVertices.Length,
                instanceCount: 1,
                indexStart: 0,
                vertexOffset: 0,
                instanceStart: 0);

        }

        public void DrawLines(CommandList _cl)
        {
            _cl.SetVertexBuffer(0, _LineVertexBuffer);
            _cl.SetIndexBuffer(_LineIndexBuffer, IndexFormat.UInt16);
            _cl.SetPipeline(_linesPipeline);
            _cl.SetGraphicsResourceSet(0, _projViewSet);
            _cl.DrawIndexed(
                indexCount: (uint)_LineVertices.Length,
                instanceCount: 1,
                indexStart: 0,
                vertexOffset: 0,
                instanceStart: 0);
        }

        public void DrawPoints(CommandList _cl)
        {
            _cl.SetVertexBuffer(0, _PointVertexBuffer);
            _cl.SetIndexBuffer(_PointIndexBuffer, IndexFormat.UInt16);
            _cl.SetPipeline(_pointsPipeline);
            _cl.SetGraphicsResourceSet(0, _projViewSet);
            _cl.DrawIndexed(
                indexCount: (uint)_PointVertices.Length,
                instanceCount: 1,
                indexStart: 0,
                vertexOffset: 0,
                instanceStart: 0);
        }


        public void InitNodeVertexData(GraphicsDevice _gd)
        {

            if (!(graph.previewnodes.safe_get_vert_array(out _PointVertices)))
            {
                Console.WriteLine("Unhandled error 1");
            }
            Console.WriteLine($"Initing graph with {_PointVertices.Length} node verts");


            ResourceFactory factory = _gd.ResourceFactory;
            uint bufferSize = (uint)_PointVertices.Length * VertexPositionColor.SizeInBytes;
            /*
			 * 
			 * 
			TODO: can be much much more efficient here with option to just update new stuff
			*
			*
			*/

            if (_PointIndexBuffer != null)
            {
                _PointIndexBuffer.Dispose();
                _PointVertexBuffer.Dispose();
            }
            BufferDescription vbDescription = new BufferDescription(bufferSize, BufferUsage.VertexBuffer);
            _PointVertexBuffer = factory.CreateBuffer(vbDescription);

            _gd.UpdateBuffer(_PointVertexBuffer, 0, _PointVertices);

            List<ushort> pointIndices = Enumerable.Range(0, _PointVertices.Length)
                .Select(i => (ushort)i)
                .ToList();

            BufferDescription ibDescription = new BufferDescription((uint)pointIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
            _PointIndexBuffer = factory.CreateBuffer(ibDescription);
            _gd.UpdateBuffer(_PointIndexBuffer, 0, pointIndices.ToArray());
        }
    }

}
