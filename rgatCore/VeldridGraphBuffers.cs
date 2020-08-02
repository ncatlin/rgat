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
        public VeldridGraphBuffers() { }

        //LineStrip
        Pipeline _linesPipeline;
        VertexPositionColor[] _EdgeLineVertices;
        DeviceBuffer _EdgeLineVertexBuffer;
        DeviceBuffer _EdgeLineIndexBuffer;

        //LineList
        Pipeline _IllustrationLinePipeline;
        VertexPositionColor[] _IllustrationLineVertices;
        DeviceBuffer _IllustrationLineVertexBuffer;
        DeviceBuffer _IllustrationLineIndexBuffer;

        //Nodes
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

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineList;
            _IllustrationLinePipeline = factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.LineStrip;
            _linesPipeline = factory.CreateGraphicsPipeline(pipelineDescription);

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.PointList;
            _pointsPipeline = factory.CreateGraphicsPipeline(pipelineDescription);
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

            if (!(lines.safe_get_vert_array(out _EdgeLineVertices)))
            {
                Console.WriteLine("Unhandled error 1");
            }

            //Console.WriteLine($"Initing graph with {_LineVertices.Length} line verts");

            ResourceFactory factory = _gd.ResourceFactory;
            if (_EdgeLineIndexBuffer != null)
            {
                _EdgeLineIndexBuffer.Dispose();
                _EdgeLineVertexBuffer.Dispose();
            }

            BufferDescription vbDescription = new BufferDescription((uint)_EdgeLineVertices.Length * VertexPositionColor.SizeInBytes, 
                BufferUsage.VertexBuffer);
            _EdgeLineVertexBuffer = factory.CreateBuffer(vbDescription);
            _gd.UpdateBuffer(_EdgeLineVertexBuffer, 0, _EdgeLineVertices);

            List<ushort> lineIndices = Enumerable.Range(0, _EdgeLineVertices.Length)
                                                 .Select(i => (ushort)i)
                                                 .ToList();

            BufferDescription ibDescription = new BufferDescription((uint)lineIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
            _EdgeLineIndexBuffer = factory.CreateBuffer(ibDescription);
            _gd.UpdateBuffer(_EdgeLineIndexBuffer, 0, lineIndices.ToArray());
        }


        void InitIllustrationLineVertexData(GraphicsDevice _gd, PlottedGraph graph)
        {
            List<VertexPositionColor> vertslist = null;

            GraphDisplayData wireframeLines = graph.wireframelines;
            if (!wireframeLines.safe_get_vert_list(out vertslist))
            {
                Console.WriteLine("Unhandled error 1 InitWireframeVertexData wireframeLines.safe_get_vert_array");
                vertslist = new List<VertexPositionColor>();
            }


            GraphDisplayData higlightlines = graph.HighlightsDisplayData;
            if (higlightlines.safe_get_vert_list(out List<VertexPositionColor> highlightvertslist))
            {
                vertslist.AddRange(highlightvertslist);
            }
            else
            {
                Console.WriteLine("Unhandled error 2 InitWireframeVertexData higlightlines.safe_get_vert_array");
            }

            _IllustrationLineVertices = vertslist.ToArray();

            ResourceFactory factory = _gd.ResourceFactory;
            BufferDescription vbDescription = new BufferDescription(
                (uint)_IllustrationLineVertices.Length * VertexPositionColor.SizeInBytes, BufferUsage.VertexBuffer);

            if (_IllustrationLineIndexBuffer != null)
            {
                _IllustrationLineIndexBuffer.Dispose();
                _IllustrationLineVertexBuffer.Dispose();
            }

            _IllustrationLineVertexBuffer = factory.CreateBuffer(vbDescription);
            _gd.UpdateBuffer(_IllustrationLineVertexBuffer, 0, _IllustrationLineVertices);

            List<ushort> wfIndices = Enumerable.Range(0, _IllustrationLineVertices.Length)
                .Select(i => (ushort)i)
                .ToList();
            
            BufferDescription ibDescription = new BufferDescription((uint)wfIndices.Count * sizeof(ushort), BufferUsage.IndexBuffer);
            _IllustrationLineIndexBuffer = factory.CreateBuffer(ibDescription);
            _gd.UpdateBuffer(_IllustrationLineIndexBuffer, 0, wfIndices.ToArray());
        }


        public void DrawIllustrationLines(CommandList _cl, GraphicsDevice _gd, PlottedGraph graph)
        {
            if (_IllustrationLineVertexBuffer == null 
                || graph.wireframelines.DataChanged
                || graph.HighlightsDisplayData.DataChanged)
            {
                InitIllustrationLineVertexData(_gd, graph);
                graph.wireframelines.SignalDataRead();
                graph.HighlightsDisplayData.SignalDataRead();
            }

            _cl.SetVertexBuffer(0, _IllustrationLineVertexBuffer);
            _cl.SetIndexBuffer(_IllustrationLineIndexBuffer, IndexFormat.UInt16);
            _cl.SetPipeline(_IllustrationLinePipeline);
            _cl.SetGraphicsResourceSet(0, _projViewSet);
            _cl.SetGraphicsResourceSet(1, _animBuffSet);

            _cl.DrawIndexed(
                indexCount: (uint)_IllustrationLineVertices.Length,
                instanceCount: 1,
                indexStart: 0,
                vertexOffset: 0,
                instanceStart: 0);

        }



        public void DrawEdges(CommandList _cl, GraphicsDevice _gd, GraphDisplayData lines)
        {
            if (_EdgeLineVertexBuffer == null || lines.DataChanged)
            {
                InitLineVertexData(_gd, lines);
                lines.SignalDataRead();
            }

            _cl.SetVertexBuffer(0, _EdgeLineVertexBuffer);
            _cl.SetIndexBuffer(_EdgeLineIndexBuffer, IndexFormat.UInt16);
            _cl.SetPipeline(_linesPipeline);
            _cl.SetGraphicsResourceSet(0, _projViewSet);
            _cl.SetGraphicsResourceSet(1, _animBuffSet);
            _cl.DrawIndexed(
                indexCount: (uint)_EdgeLineVertices.Length,
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
