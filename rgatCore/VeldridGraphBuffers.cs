using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using Veldrid;

namespace rgatCore
{
    public class VeldridGraphBuffers
    {
        public VeldridGraphBuffers() { }

        //LineStrip
        Pipeline _linesPipeline;
        Position2DColour[] _EdgeLineVertices;
        DeviceBuffer _EdgeLineVertexBuffer;
        DeviceBuffer _EdgeLineIndexBuffer;

        //LineList
        Pipeline _IllustrationLinePipeline;
        Position2DColour[] _IllustrationLineVertices;
        DeviceBuffer _IllustrationLineVertexBuffer;
        DeviceBuffer _IllustrationLineIndexBuffer;

        //Nodes
        Pipeline _pointsPipeline;
        Position2DColour[] _PointVertices;
        DeviceBuffer _PointVertexBuffer;
        DeviceBuffer _PointIndexBuffer;


        //Triangles
        Pipeline _trianglesPipeline;
        Position2DColour[] _TriangleVertices;
        DeviceBuffer _TriangleVertexBuffer;
        DeviceBuffer _TriangleIndexBuffer;
        

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

            pipelineDescription.PrimitiveTopology = PrimitiveTopology.TriangleList;
            _trianglesPipeline = factory.CreateGraphicsPipeline(pipelineDescription);
        }


        /// <summary>
        /// This is used for shaders where the coordinate being referenced is contained in a texture. 
        /// The Texposition is the location (in the positions texture) to read and then draw geometry at with the specified colour.
        /// </summary>
        public struct Position2DColour
        {
            public Vector2 Position;
            public WritableRgbaFloat Color;
            public const uint SizeInBytes = 24;

            public Position2DColour(Vector2 position, WritableRgbaFloat color)
            {
                Position = position;
                Color = color;
            }
        }


        /// <summary>
        /// This just describes raw position and colour of geometry. Used for things unrelated to graph geometry like wireframes
        /// If Position.W == 1 then x,y are used as a positions texture reference as in TextureOffsetColour
        /// </summary>
        public struct GeomPositionColour
        {
            public Vector4 Position;
            public WritableRgbaFloat Color;
            public const uint SizeInBytes = 32;

            public GeomPositionColour(Vector3 position, WritableRgbaFloat color, float posIsNodeRef = 0f)
            {
                Position = new Vector4(position, posIsNodeRef);
                Color = color;
            }
        }



        public static DeviceBuffer GetReadback(GraphicsDevice gd, DeviceBuffer buffer)
        {
            DeviceBuffer readback;
            if ((buffer.Usage & BufferUsage.Staging) != 0)
            {
                readback = buffer;
            }
            else
            {
                ResourceFactory factory = gd.ResourceFactory;
                readback = factory.CreateBuffer(new BufferDescription(buffer.SizeInBytes, BufferUsage.Staging));
                CommandList cl = factory.CreateCommandList();
                cl.Begin();
                cl.CopyBuffer(buffer, 0, readback, 0, buffer.SizeInBytes);
                cl.End();
                gd.SubmitCommands(cl);
                gd.WaitForIdle();
                cl.Dispose();
            }

            return readback;
        }


        public static unsafe DeviceBuffer CreateFloatsDeviceBuffer(float[] floats, GraphicsDevice gdev)
        {
            BufferDescription bd = new BufferDescription((uint)floats.Length * sizeof(float), BufferUsage.StructuredBufferReadWrite, 4);
            DeviceBuffer newBuffer = gdev.ResourceFactory.CreateBuffer(bd);

            fixed (float* dataPtr = floats)
            {
                gdev.UpdateBuffer(newBuffer, 0, (IntPtr)dataPtr, (uint)floats.Length * sizeof(float));
                gdev.WaitForIdle();
            }

            return newBuffer;
        }


    }

}
