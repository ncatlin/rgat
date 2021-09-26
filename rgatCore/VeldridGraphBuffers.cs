using System;
using System.Collections.Generic;
using System.Numerics;
using Veldrid;

namespace rgat
{
    /// <summary>
    /// Class for managing VRAM buffers
    /// </summary>
    public class VeldridGraphBuffers
    {
        /// <summary>
        /// Total allocated VRAM DeviceBuffer size
        /// </summary>
        public static long AllocatedBytes { get; private set; } = 0;

        /// <summary>
        /// Number of allocated VRAM device buffers
        /// </summary>
        public static long AllocatedBuffers { get; private set; } = 0;


        /// <summary>
        /// Get a CPU readable mapping of VRAM
        /// </summary>
        /// <param name="gd">A veldrid graphics device</param>
        /// <param name="buffer">The buffer to read</param>
        /// <returns></returns>
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


        /// <summary>
        /// Dispose of a Texture
        /// </summary>
        /// <param name="tx">Texture set to dispose</param>
        public static void DoDispose(Texture? tx)
        {
            // if (tx != null && tx.IsDisposed == false) tx.Dispose();
            if (tx != null)
            {
                tx.Dispose();
            }
        }


        /// <summary>
        /// Dispose of a Framebuffer
        /// </summary>
        /// <param name="fb">Framebuffer set to dispose</param>
        public static void DoDispose(Framebuffer? fb)
        {
            // if (fb != null && fb.IsDisposed == false) fb.Dispose();
            if (fb != null)
            {
                fb.Dispose();
            }
        }


        /// <summary>
        /// Dispose of a ResourceSet
        /// </summary>
        /// <param name="rs">Resource set to dispose</param>
        public static void DoDispose(ResourceSet? rs)
        {
            if (rs != null)
            {
                rs.Dispose();
            }
            //if (rs != null && rs.IsDisposed == false) rs.Dispose();
        }


        /// <summary>
        /// Dispose of a VRAM devide buffer and track the deallocation
        /// </summary>
        /// <param name="db">DeviceBuffer to dispose</param>
        public static void VRAMDispose(DeviceBuffer? db)
        {
            lock (b_lock)
            {
                if (db != null && db.IsDisposed == false)
                {
                    AllocatedBytes -= db.SizeInBytes;
                    AllocatedBuffers -= 1;
                    //Logging.RecordLogEvent($"DEALLOC! Disposing devicebuff of size {db.SizeInBytes} name {db.Name}  totl[{total_1}]");
                    db.Dispose();
                    _allocatedBufs.Remove(db.Name);
                }
            }
        }

        private static readonly object b_lock = new object();
        private static readonly List<string> _allocatedBufs = new List<string>();

        /// <summary>
        /// Allocate tracked VRAM memory
        /// </summary>
        /// <param name="gd">GraphicsDevice</param>
        /// <param name="size">Size of the buffer to allocate</param>
        /// <param name="usage">How the buffer is used</param>
        /// <param name="stride">Data stride</param>
        /// <param name="name">Name for the buffer</param>
        /// <returns>Allocated device buffer</returns>
        public static DeviceBuffer TrackedVRAMAlloc(GraphicsDevice gd, uint size, BufferUsage usage = BufferUsage.StructuredBufferReadWrite, uint stride = 0, string name = "?")
        {
            lock (b_lock)
            {
                AllocatedBytes += size;
                AllocatedBuffers += 1;
                //Logging.RecordLogEvent($"ALLOC! {size} name:{name} totl[{total_1}]", Logging.LogFilterType.BulkDebugLogFile);
                DeviceBuffer result = gd.ResourceFactory.CreateBuffer(new BufferDescription(size, usage, stride));
                result.Name = name;
                _allocatedBufs.Add(result.Name);
                return result;
            }
        }


        /// <summary>
        /// Upload an array of floats to a new VRAM buffer
        /// </summary>
        /// <param name="floats">floats</param>
        /// <param name="gdev">Graphics Device</param>
        /// <param name="name">Buffer name</param>
        /// <returns>VRAM DeviceBuffer</returns>
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


        /// <summary>
        /// Create two duplicates of a devicebuffer
        /// </summary>
        /// <param name="source">Input</param>
        /// <param name="gdev">GPU GraphicsDevice</param>
        /// <param name="dest1">Output 1</param>
        /// <param name="dest2">Output 2</param>
        /// <param name="name">buffer name prefix</param>
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


        /// <summary>
        /// Create two GPU buffer copies of a RAM buffer 
        /// </summary>
        /// <param name="floats">Float array to copy</param>
        /// <param name="gdev">Veldrid graphicsdevice</param>
        /// <param name="name">Name prefix of the buffers</param>
        /// <returns>Pair of DeviceBuffers</returns>
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


        /// <summary>
        /// Fill a devicebuffer with null bytes
        /// </summary>
        /// <param name="buffer">Buffer to fill</param>
        /// <param name="gd">GraphicsDevice to use</param>
        /// <param name="zeroStartOffset">Offset to start filling from</param>
        public unsafe static void ZeroFillBuffer(DeviceBuffer buffer, GraphicsDevice gd, uint zeroStartOffset)
        {
            ResourceFactory rf = gd.ResourceFactory;

            float[] zeros = new float[(int)(buffer.SizeInBytes / 4)];
            CommandList cl = rf.CreateCommandList();
            cl.Begin();
            fixed (float* dataPtr = zeros)
            {
                cl.UpdateBuffer(buffer, zeroStartOffset, (IntPtr)dataPtr, buffer.SizeInBytes - zeroStartOffset);
            }
            cl.End();
            gd.SubmitCommands(cl);
            gd.WaitForIdle();
            cl.Dispose();
        }


        /// <summary>
        /// Create a devicebuffer filled with null bytes
        /// </summary>
        /// <param name="bd">Description of the buffer to fill</param>
        /// <param name="gd">GraphicsDevice to use</param>
        /// <param name="zeroStartOffset">Where to start filling with zeros (before these is reserved for copying existing data)</param>
        /// <param name="name">Name for the buffer</param>
        /// <returns></returns>
        public unsafe static DeviceBuffer CreateZeroFilledBuffer(BufferDescription bd, GraphicsDevice gd, uint zeroStartOffset = 0, string name = "")
        {
            DeviceBuffer buf = TrackedVRAMAlloc(gd, bd.SizeInBytes, bd.Usage, bd.StructureByteStride, name);
            ZeroFillBuffer(buf, gd, zeroStartOffset);
            return buf;
        }


        /// <summary>
        /// Create a node attributes buffer with standard values
        /// </summary>
        /// <param name="bd">BufferDescription</param>
        /// <param name="gd">GraphicsDevice</param>
        /// <param name="name">Buuffer name</param>
        /// <returns>Created attributes buffer</returns>
        public unsafe static DeviceBuffer CreateDefaultAttributesBuffer(BufferDescription bd, GraphicsDevice gd, string name = "")
        {
            DeviceBuffer buf = TrackedVRAMAlloc(gd, bd.SizeInBytes, bd.Usage, bd.StructureByteStride, name);
            ResourceFactory rf = gd.ResourceFactory;

            int floatCount = (int)(buf.SizeInBytes / 4);
            float[] output = new float[floatCount];
            float[] item = new float[4] { CONSTANTS.Anim_Constants.DEFAULT_NODE_DIAMETER, 1, 0, 0 };
            int itemSize = item.Length * sizeof(float);
            for (var i = 0; i < floatCount; i += 4)
            {
                Array.Copy(item, 0, output, i, item.Length);
            }
            CommandList cl = rf.CreateCommandList();
            cl.Begin();
            fixed (float* dataPtr = output)
            {
                cl.UpdateBuffer(buf, 0, (IntPtr)dataPtr, buf.SizeInBytes);
            }
            cl.End();
            gd.SubmitCommands(cl);
            gd.WaitForIdle();
            cl.Dispose();

            return buf;
        }


        /// <summary>
        /// Debugging routine to find NaN values in a VRAM buffer
        /// </summary>
        /// <param name="_gd">Graphics device</param>
        /// <param name="buf">Buffer to search</param>
        /// <returns>true if NaN was found</returns>
        public static bool DetectNaN(GraphicsDevice _gd, DeviceBuffer buf)
        {

            DeviceBuffer destinationReadback = VeldridGraphBuffers.GetReadback(_gd, buf);
            MappedResourceView<float> destinationReadView = _gd.Map<float>(destinationReadback, MapMode.Read);
            float[] outputArray = new float[destinationReadView.Count];
            for (int index = 0; index < destinationReadView.Count; index++)
            {
                if (index >= destinationReadView.Count)
                {
                    break;
                }

                outputArray[index] = destinationReadView[index];
                //Logging.WriteConsole($"{index}:{outputArray[index]}");
                if (float.IsNaN(outputArray[index]))
                {
                    Logging.WriteConsole($"{index}:{outputArray[index]}");
                    return true;
                }
            }
            _gd.Unmap(destinationReadback);
            return false;
        }


        /// <summary>
        /// This is used for shaders where the coordinate being referenced is contained in a texture. 
        /// The Texposition is the location (in the positions texture) to read and then draw geometry at with the specified colour.
        /// </summary>
        public struct Position2DColour
        {
            /// <summary>
            /// Texture coordinate
            /// </summary>
            public Vector2 Position;
            /// <summary>
            /// Colour of the geometry
            /// </summary>
            public WritableRgbaFloat Color;
            /// <summary>
            /// Size of this structure in bytes
            /// </summary>
            public const uint SizeInBytes = 24;
        }


        /// <summary>
        /// This just describes raw position and colour of geometry. Used for things unrelated to graph geometry like wireframes
        /// If Position.W == 1 then x,y are used as a positions texture reference as in TextureOffsetColour
        /// </summary>
        public struct GeomPositionColour
        {
            /// <summary>
            /// Item position
            /// </summary>
            public Vector4 Position;
            /// <summary>
            /// Item colour
            /// </summary>
            public WritableRgbaFloat Color;

            /// <summary>
            /// Size of this structure
            /// </summary>
            public const uint SizeInBytes = 32;
        }


    }
}
