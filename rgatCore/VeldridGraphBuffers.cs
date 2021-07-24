using ImGuiNET;
using rgatCore.Shaders.SPIR_V;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

        ResourceLayout SetupProjectionBuffers(GraphicsDevice gd)
        {
            ResourceLayoutElementDescription vb = new ResourceLayoutElementDescription("ViewBuffer", ResourceKind.UniformBuffer, ShaderStages.Vertex);
            ResourceLayout projViewLayout = gd.ResourceFactory.CreateResourceLayout(new ResourceLayoutDescription(vb));
            _viewBuffer = TrackedVRAMAlloc(gd, 64, BufferUsage.UniformBuffer, name: "ViewBuffer");
            _projViewSet = gd.ResourceFactory.CreateResourceSet(new ResourceSetDescription(projViewLayout, _viewBuffer));
            return projViewLayout;
        }

        ResourceLayout SetupAnimDataBuffers(GraphicsDevice gd)
        {
            ResourceLayoutElementDescription vb = new ResourceLayoutElementDescription("AnimBuffer", ResourceKind.UniformBuffer, ShaderStages.Fragment);
            ResourceLayout animLayout = gd.ResourceFactory.CreateResourceLayout(new ResourceLayoutDescription(vb));
            _animBuffer = TrackedVRAMAlloc(gd, 64, BufferUsage.UniformBuffer, name: "AnimDataBuffer");
            _animBuffSet = gd.ResourceFactory.CreateResourceSet(new ResourceSetDescription(animLayout, _animBuffer));
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
            ResourceLayout projViewLayout = SetupProjectionBuffers(_gd);
            ResourceLayout AnimDataLayout = SetupAnimDataBuffers(_gd);


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
                readback = TrackedVRAMAlloc(gd, buffer.SizeInBytes, BufferUsage.Staging, name: "ReadBack");
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
            // if (tx != null && tx.IsDisposed == false) tx.Dispose();
            if (tx != null) tx.Dispose();
        }
        public static void DoDispose(Framebuffer fb)
        {
            // if (fb != null && fb.IsDisposed == false) fb.Dispose();
            if (fb != null) fb.Dispose();
        }
        public static void DoDispose(ResourceSet rs)
        {
            if (rs != null) rs.Dispose();
            //if (rs != null && rs.IsDisposed == false) rs.Dispose();
        }

        static long total_1 = 0;
        public static void DoDispose(DeviceBuffer db)
        {
            lock (b_lock)
            {
                if (db != null && db.IsDisposed == false)
                {
                    total_1 -= db.SizeInBytes;
                    Logging.RecordLogEvent($"DEALLOC! Disposing devicebuff of size {db.SizeInBytes} name {db.Name}  totl[{total_1}]");
                    db.Dispose();
                    _allocatedBufs.Remove(db.Name);
                }
            }
        }

        readonly static object b_lock = new object();
        static List<string> _allocatedBufs = new List<string>();

        public static DeviceBuffer TrackedVRAMAlloc(GraphicsDevice gd, uint size, BufferUsage usage = BufferUsage.StructuredBufferReadWrite, uint stride = 0, string name = "?")
        {
            lock (b_lock)
            {
                total_1 += size;
                Logging.RecordLogEvent($"ALLOC! {size} name:{name} totl[{total_1}]", Logging.LogFilterType.BulkDebugLogFile);
                DeviceBuffer result = gd.ResourceFactory.CreateBuffer(new BufferDescription(size, usage, stride));
                result.Name = name;
                _allocatedBufs.Add(result.Name);
                return result;
            }
        }


        public static unsafe DeviceBuffer CreateFloatsDeviceBuffer(float[] floats, GraphicsDevice gdev, string name = "?")
        {
            DeviceBuffer buffer = TrackedVRAMAlloc(gdev, (uint)floats.Length * sizeof(float), stride: 4, name: name);
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

        public static unsafe void CreateBufferCopyPair(DeviceBuffer source, GraphicsDevice gdev, out DeviceBuffer dest1, out DeviceBuffer dest2, string name = "?")
        {
            dest1 = TrackedVRAMAlloc(gdev, source.SizeInBytes, stride: 4, name: name + "_1");
            dest2 = TrackedVRAMAlloc(gdev, source.SizeInBytes, stride: 4, name: name + "_2");

            CommandList cl = gdev.ResourceFactory.CreateCommandList();
            cl.Begin();
            cl.CopyBuffer(source, 0, dest1, 0, source.SizeInBytes);
            cl.CopyBuffer(source, 0, dest2, 0, source.SizeInBytes);
            cl.End();
            gdev.SubmitCommands(cl);
            gdev.WaitForIdle();
            cl.Dispose();
        }


        public static unsafe Tuple<DeviceBuffer, DeviceBuffer> CreateFloatsDeviceBufferPair(float[] floats, GraphicsDevice gdev, string name = "?")
        {
            DeviceBuffer buffer1 = TrackedVRAMAlloc(gdev, (uint)floats.Length * sizeof(float), stride: 4, name: name + "1");
            DeviceBuffer buffer2 = TrackedVRAMAlloc(gdev, (uint)floats.Length * sizeof(float), stride: 4, name: name + "2");
            fixed (float* dataPtr = floats)
            {
                CommandList cl = gdev.ResourceFactory.CreateCommandList();
                cl.Begin();
                cl.UpdateBuffer(buffer1, 0, (IntPtr)dataPtr, buffer1.SizeInBytes);
                //do we need a fence here?
                cl.CopyBuffer(buffer1, 0, buffer2, 0, buffer1.SizeInBytes);
                cl.End();
                gdev.SubmitCommands(cl);
                gdev.WaitForIdle();
                cl.Dispose();
            }

            return new Tuple<DeviceBuffer, DeviceBuffer>(buffer1, buffer2);
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
            pipelineDescription.ComputeShader = rf.CreateFromSpirv(SPIRVShaders.CreateZeroFillShader(gd));
            pipelineDescription.ThreadGroupSizeX = 256;
            pipelineDescription.ThreadGroupSizeY = 1;
            pipelineDescription.ThreadGroupSizeZ = 1;

            ZeroFillPipeline = rf.CreateComputePipeline(pipelineDescription);

            paramsBuffer = TrackedVRAMAlloc(gd, (uint)Unsafe.SizeOf<FillParams>(), BufferUsage.UniformBuffer, name: "ZeroFillShaderParam");
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

            float[] zeros = new float[(int)(buffer.SizeInBytes / 4)];
            //for (var i = 0; i < zeros.Length; i++)
            //   zeros[i] = 74;

            CommandList cl = rf.CreateCommandList();
            cl.Begin();
            //cl.SetPipeline(ZeroFillPipeline);
            fixed (float* dataPtr = zeros)
            {
                cl.UpdateBuffer(buffer, zeroStartOffset, (IntPtr)dataPtr, buffer.SizeInBytes - zeroStartOffset);
            }
            cl.End();
            gd.SubmitCommands(cl);
            gd.WaitForIdle();
            //paramsBuffer.Dispose();
            cl.Dispose();
        }

        public unsafe static DeviceBuffer CreateZeroFilledBuffer(BufferDescription bd, GraphicsDevice gd, uint zeroStartOffset = 0, string name = "")
        {
            DeviceBuffer buf = TrackedVRAMAlloc(gd, bd.SizeInBytes, bd.Usage, bd.StructureByteStride, name);
            ZeroFillBuffer(buf, gd, zeroStartOffset);
            return buf;
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

    }
}
