using ImGuiNET;
using rgatCore.Shaders.SPIR_V;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Veldrid;
using Veldrid.SPIRV;

namespace rgatCore
{
    public class VeldridGraphBuffers
    {
        public VeldridGraphBuffers() { }

        //LineStrip
        Pipeline _linesPipeline;
        //LineList
        Pipeline _IllustrationLinePipeline;
        //Nodes
        Pipeline _pointsPipeline;
        //Triangles
        Pipeline _trianglesPipeline;

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

        //todo unused?
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
            pipelineDescription.ResourceLayouts = new[] { projViewLayout, AnimDataLayout };
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

        public static void DoDispose(Texture tx)
        {
            if (tx != null && tx.IsDisposed == false) tx.Dispose();
        }
        public static void DoDispose(Framebuffer fb)
        {
            if (fb != null && fb.IsDisposed == false) fb.Dispose();
        }
        public static void DoDispose(ResourceSet rs)
        {
            if (rs != null && rs.IsDisposed == false) rs.Dispose();
        }

        public static void DoDispose(DeviceBuffer db)
        {
            if (db != null && db.IsDisposed == false) db.Dispose();
        }

        public static bool DetectNaN(GraphicsDevice _gd, DeviceBuffer buf)
        {

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, buf);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            float[] outputArray = new float[destinationReadView.Count];
            for (int index = 0; index < destinationReadView.Count; index++)
            {
                if (index >= destinationReadView.Count) break;
                outputArray[index] = destinationReadView[index];
                //Console.WriteLine($"{index}:{outputArray[index]}");
                if (float.IsNaN(outputArray[index]))
                {
                    Console.WriteLine($"{index}:{outputArray[index]}");
                    return true;
                }
            }
            _gd.Unmap(destinationReadback);
            return false;
        }

        public static unsafe DeviceBuffer CreateFloatsDeviceBuffer(float[] floats, GraphicsDevice gdev)
        {
            BufferDescription bd = new BufferDescription((uint)floats.Length * sizeof(float), BufferUsage.StructuredBufferReadWrite, 4);
            DeviceBuffer buffer = gdev.ResourceFactory.CreateBuffer(bd);

            Logging.RecordLogEvent($"CreateFloatsDevBuf {buffer.SizeInBytes}, {floats.Length * sizeof(float)}");
            fixed (float* dataPtr = floats)
            {
                CommandList cl = gdev.ResourceFactory.CreateCommandList();
                cl.Begin();
                cl.UpdateBuffer(buffer, 0, (IntPtr)dataPtr, buffer.SizeInBytes);
                cl.End();
                gdev.SubmitCommands(cl);
                gdev.WaitForIdle();
                cl.Dispose();
            }

            return buffer;
        }






        static Pipeline ZeroFillPipeline;

        public static void SetupZeroFillshader(ImGuiController controller)
        {
            GraphicsDevice gd = controller.graphicsDevice;
            ResourceFactory rf = gd.ResourceFactory;

            if (!gd.Features.ComputeShader) { Console.WriteLine("Error: No computeshader feature"); return; }

            ResourceLayout fillShaderLayout = rf.CreateResourceLayout(new ResourceLayoutDescription(
               new ResourceLayoutElementDescription("params", ResourceKind.UniformBuffer, ShaderStages.Compute),
               new ResourceLayoutElementDescription("targ", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute)
               ));

            ComputePipelineDescription pipelineDescription = new ComputePipelineDescription();
            pipelineDescription.ResourceLayouts = new[] { fillShaderLayout, };
            pipelineDescription.ComputeShader = rf.CreateFromSpirv(SPIRVShaders.CreateZeroFillShader(rf));
            pipelineDescription.ThreadGroupSizeX = 256;
            pipelineDescription.ThreadGroupSizeY = 1;
            pipelineDescription.ThreadGroupSizeZ = 1;

            ZeroFillPipeline = rf.CreateComputePipeline(pipelineDescription);

            paramsBuffer = rf.CreateBuffer(new BufferDescription((uint)Unsafe.SizeOf<FillParams>(), BufferUsage.UniformBuffer));
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FillParams
        {
            public uint width;
            public uint value;
            private readonly uint _padding1; //must be multiple of 16
            private readonly uint _padding2; //must be multiple of 16
        }


        static DeviceBuffer paramsBuffer;

        public static void ZeroFillBuffers(List<DeviceBuffer> buffers, GraphicsDevice gd)
        {
            ResourceFactory rf = gd.ResourceFactory;

            CommandList cl = rf.CreateCommandList();
            cl.Begin();
            cl.SetPipeline(ZeroFillPipeline);

            List<ResourceSet> rls = new List<ResourceSet>();
            foreach (var bw in buffers)
            {
                FillParams params1 = new FillParams()
                {
                    value = 50,
                    width = bw.SizeInBytes / 256
                };
                ResourceLayout rl = rf.CreateResourceLayout(new ResourceLayoutDescription(
    new ResourceLayoutElementDescription("params", ResourceKind.UniformBuffer, ShaderStages.Compute, ResourceLayoutElementOptions.None),
    new ResourceLayoutElementDescription("targ", ResourceKind.StructuredBufferReadWrite, ShaderStages.Compute, ResourceLayoutElementOptions.None)));
                ResourceSet res = rf.CreateResourceSet(new ResourceSetDescription(rl, paramsBuffer, bw));
                cl.UpdateBuffer(paramsBuffer, 0, params1);
                cl.SetComputeResourceSet(0, res);
                cl.Dispatch(params1.width, 1, 1);
                rls.Add(res);
                rl.Dispose();
            }
            cl.End();
            gd.SubmitCommands(cl);
            gd.WaitForIdle();
            //paramsBuffer.Dispose();
            cl.Dispose();

            foreach (var r in rls) r.Dispose();
        }



        public unsafe static void ZeroFillBuffer(DeviceBuffer buffer, GraphicsDevice gd, uint zeroStartOffset)
        {
            ResourceFactory rf = gd.ResourceFactory;

            int[] zeros = new int[(int)(buffer.SizeInBytes / 4)];


            CommandList cl = rf.CreateCommandList();
            cl.Begin();
            //cl.SetPipeline(ZeroFillPipeline);
            fixed (int* dataPtr = zeros)
            {
                cl.UpdateBuffer(buffer, zeroStartOffset, (IntPtr)dataPtr, buffer.SizeInBytes-zeroStartOffset);
            }
            cl.End();
            gd.SubmitCommands(cl);
            gd.WaitForIdle();
            //paramsBuffer.Dispose();
            cl.Dispose();
        }

        public unsafe static DeviceBuffer CreateZeroFilledBuffer(BufferDescription bd, GraphicsDevice gd, uint zeroStartOffset=0)
        {
            DeviceBuffer buf = gd.ResourceFactory.CreateBuffer(bd);
            ZeroFillBuffer(buf, gd, zeroStartOffset);
            return buf;
        }
    }
}
