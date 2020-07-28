using ImGuiNET;
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
        public DeviceBuffer _viewBuffer { get; private set; }

        ResourceSet _animBuffSet;
        public DeviceBuffer _animBuffer { get; private set; }

        ResourceLayout SetupProjectionBuffers(ResourceFactory factory)
        {
            ResourceLayoutElementDescription vb = new ResourceLayoutElementDescription("ViewBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex);
            ResourceLayout projViewLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(vb));
            _viewBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer));
            _projViewSet = factory.CreateResourceSet(new ResourceSetDescription(projViewLayout, _viewBuffer));
            return projViewLayout;
        }

        ResourceLayout SetupAnimDataBuffers(ResourceFactory factory)
        {
            ResourceLayoutElementDescription vb = new ResourceLayoutElementDescription("AnimBuffer", ResourceKind.UniformBuffer, ShaderStages.Fragment);
            ResourceLayout animLayout = factory.CreateResourceLayout(new ResourceLayoutDescription(vb));
            _animBuffer = factory.CreateBuffer(new BufferDescription(64, BufferUsage.UniformBuffer));
            _animBuffSet = factory.CreateResourceSet(new ResourceSetDescription(animLayout, _animBuffer));
            return animLayout;
        }

        public struct AnimDataStruct
        {
            public int animEnabled; //if the basealpha overrides the true alpha of each vert
            //public float baseAlpha; //the base alpha to override it with
        }

        public void InitPipelines(GraphicsDevice _gd, ShaderSetDescription shaders, Framebuffer frmbuf, bool wireframe = false)
        {
            ResourceFactory factory = _gd.ResourceFactory;
            ResourceLayout projViewLayout = SetupProjectionBuffers(factory);
            ResourceLayout AnimDataLayout = SetupAnimDataBuffers(factory);


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
            pipelineDescription.ResourceLayouts = new[] { projViewLayout,  AnimDataLayout };
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

        void InitWireframeVertexData(GraphicsDevice _gd, GraphDisplayData lines)
        {

            if (!(lines.safe_get_vert_array(out _WireframeVertices)))
            {
                Console.WriteLine("Unhandled error 1 InitWireframeVertexData lines.safe_get_vert_array");
                return;
            }


            Console.WriteLine($"Initing wireframe with {_WireframeVertices.Length} wireframe verts");

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
        void InitNodeVertexData(GraphicsDevice _gd, GraphDisplayData nodes)
        {

            if (!(nodes.safe_get_vert_array(out _PointVertices)))
            {
                Console.WriteLine("Unhandled error 1");
            }
            //Console.WriteLine($"Initing graph with {_PointVertices.Length} node verts");


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

        void InitLineVertexData(GraphicsDevice _gd, GraphDisplayData lines)
        {

            if (!(lines.safe_get_vert_array(out _LineVertices)))
            {
                Console.WriteLine("Unhandled error 1");
            }

            //Console.WriteLine($"Initing graph with {_LineVertices.Length} line verts");

            ResourceFactory factory = _gd.ResourceFactory;
            if (_LineIndexBuffer != null)
            {
                _LineIndexBuffer.Dispose();
                _LineVertexBuffer.Dispose();
            }

            BufferDescription vbDescription = new BufferDescription((uint)_LineVertices.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);
            _LineVertexBuffer = factory.CreateBuffer(vbDescription);
            _gd.UpdateBuffer(_LineVertexBuffer, 0, _LineVertices);


            List<ushort> lineIndices = Enumerable.Range(0, _LineVertices.Length)
                                                 .Select(i => (ushort)i)
                                                 .ToList();

            BufferDescription ibDescription = new BufferDescription((uint)lineIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
            _LineIndexBuffer = factory.CreateBuffer(ibDescription);
            _gd.UpdateBuffer(_LineIndexBuffer, 0, lineIndices.ToArray());
        }

        public void DrawWireframe(CommandList _cl, GraphicsDevice _gd, GraphDisplayData lines)
        {
            if (_WireframeVertexBuffer == null || lines.DataChanged)
            {
                InitWireframeVertexData(_gd, lines);
                lines.SignalDataRead();
            }
            _cl.SetVertexBuffer(0, _WireframeVertexBuffer);
            _cl.SetIndexBuffer(_WireframeIndexBuffer, IndexFormat.UInt16);
            _cl.SetPipeline(_wireframePipeline);
            _cl.SetGraphicsResourceSet(0, _projViewSet);
            _cl.SetGraphicsResourceSet(1, _animBuffSet);

            _cl.DrawIndexed(
                indexCount: (uint)_WireframeVertices.Length,
                instanceCount: 1,
                indexStart: 0,
                vertexOffset: 0,
                instanceStart: 0);


        }

        public void DrawLines(CommandList _cl, GraphicsDevice _gd, GraphDisplayData lines)
        {
            if (_LineVertexBuffer == null || lines.DataChanged)
            {
                InitLineVertexData(_gd, lines);
                lines.SignalDataRead();
            }
            _cl.SetVertexBuffer(0, _LineVertexBuffer);
            _cl.SetIndexBuffer(_LineIndexBuffer, IndexFormat.UInt16);
            _cl.SetPipeline(_linesPipeline);
            _cl.SetGraphicsResourceSet(0, _projViewSet);
            _cl.SetGraphicsResourceSet(1, _animBuffSet);
            _cl.DrawIndexed(
                indexCount: (uint)_LineVertices.Length,
                instanceCount: 1,
                indexStart: 0,
                vertexOffset: 0,
                instanceStart: 0);
        }

        public void DrawPoints(CommandList _cl, GraphicsDevice _gd, GraphDisplayData nodes)
        {
            //todo:! update, dont refill
            if (_PointVertexBuffer == null || nodes.DataChanged)
            {
                InitNodeVertexData(_gd, nodes);
                nodes.SignalDataRead();
            }
            _cl.SetVertexBuffer(0, _PointVertexBuffer);
            _cl.SetIndexBuffer(_PointIndexBuffer, IndexFormat.UInt16);
            _cl.SetPipeline(_pointsPipeline);
            _cl.SetGraphicsResourceSet(0, _projViewSet);
            _cl.SetGraphicsResourceSet(1, _animBuffSet);
            _cl.DrawIndexed(
                indexCount: (uint)_PointVertices.Length,
                instanceCount: 1,
                indexStart: 0,
                vertexOffset: 0,
                instanceStart: 0);
        }

    }

}
