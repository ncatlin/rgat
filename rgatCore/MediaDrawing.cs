using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using Veldrid;

namespace rgat
{
    class MediaDrawing
    {
        /*
         * 
         *             
         *             
         *             


        */

        public static void SetController(ImGuiNET.ImGuiController controller)
        {
            _controller = controller;
            _commandList = controller.graphicsDevice.ResourceFactory.CreateCommandList();
        }

        public static void Cleanup() => _commandList.Dispose();


        static Texture _recordingStager;
        static ImGuiNET.ImGuiController _controller;
        static CommandList _commandList;

        public static unsafe Bitmap CreateRecordingFrame(Framebuffer fbuf,  float startX, float startY, float drawWidth, float drawHeight)
        {
            GraphicsDevice gd = _controller.graphicsDevice;
            Texture ftex = fbuf.ColorTargets[0].Target;
            if (_recordingStager == null || _recordingStager.Width != ftex.Width || _recordingStager.Height != ftex.Height)
            {
                VeldridGraphBuffers.DoDispose(_recordingStager);
                _recordingStager = gd.ResourceFactory.CreateTexture(new TextureDescription(ftex.Width, ftex.Height,
                    1, 1, 1, PixelFormat.B8_G8_R8_A8_UNorm, TextureUsage.Staging, TextureType.Texture2D));
            }

            _commandList.Begin();
            _commandList.CopyTexture(ftex, _recordingStager);
            _commandList.End();
            gd.SubmitCommands(_commandList);
            gd.WaitForIdle();


            //draw it onto a bitmap
            Bitmap bmp = new Bitmap((int)_recordingStager.Width, (int)_recordingStager.Height, System.Drawing.Imaging.PixelFormat.Format32bppArgb);

            if (drawWidth == -1 || drawHeight == -1)
            {
                drawHeight = _recordingStager.Height;
                drawWidth = _recordingStager.Width;
            }
            else
            {
                drawWidth = Math.Min(drawWidth, bmp.Width);
                drawHeight = Math.Min(drawHeight, bmp.Height);
            }

            System.Drawing.Imaging.BitmapData data = bmp.LockBits(new System.Drawing.Rectangle(0, 0, (int)_recordingStager.Width, (int)_recordingStager.Height),
                System.Drawing.Imaging.ImageLockMode.WriteOnly, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            byte* scan0 = (byte*)data.Scan0;

            MappedResourceView<SixLabors.ImageSharp.PixelFormats.Rgba32> res = gd.Map<SixLabors.ImageSharp.PixelFormats.Rgba32>(_recordingStager, MapMode.Read);

            for (int y = 0; y < drawHeight; y += 1)
            {
                for (int x = 0; x < drawWidth; x += 1)
                {
                    int xPixel = (int)startX + x;
                    int yPixel = (int)startY + y;
                    SixLabors.ImageSharp.PixelFormats.Rgba32 px = res[xPixel, yPixel];
                    byte* ptr = scan0 + yPixel * data.Stride + (xPixel * 4);
                    ptr[0] = px.R;
                    ptr[1] = px.G;
                    ptr[2] = px.B;
                    ptr[3] = 255;
                }
            }
            bmp.UnlockBits(data);
            gd.Unmap(_recordingStager);

            return bmp;
        }

    }
}
