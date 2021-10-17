using System;
using System.Drawing;
using System.Numerics;
using Veldrid;
/*
This class holds (and provides dubiously mutex guarded access to) OpenGl vertex and colour data
*/
namespace rgat
{
    /// <summary>
    /// A colour format conversion class for dealing with colours 
    /// in formats that Veldrid, ImGui and .NET require
    /// </summary>
    public struct WritableRgbaFloat
    {
        /// <summary>
        /// Create a colour from a .NET drawing Colour
        /// </summary>
        /// <param name="col">Colour</param>
        public WritableRgbaFloat(Color col)
        {
            R = col.R / 255f;
            G = col.G / 255f;
            B = col.B / 255f;
            A = col.A / 255f;
        }


        /// <summary>
        /// Create a colour from float colour values (0-1)
        /// Values higher than 1 can be specified for non-colour rendering usage
        /// </summary>
        /// <param name="Rf">red</param>
        /// <param name="Gf">green</param>
        /// <param name="Bf">blue</param>
        /// <param name="Af">alpha</param>
        public WritableRgbaFloat(float Rf, float Gf, float Bf, float Af)
        {
            R = (float)Rf;
            G = (float)Gf;
            B = (float)Bf;
            A = (float)Af;
        }


        /// <summary>
        /// Create a colour from uint colour values (0-255)
        /// </summary>
        /// <param name="Ru">red</param>
        /// <param name="Gu">green</param>
        /// <param name="Bu">blue</param>
        /// <param name="Au">alpha</param>
        public WritableRgbaFloat(uint Ru, uint Gu, uint Bu, uint Au)
        {
            System.Diagnostics.Debug.Assert(Ru <= 255 && Gu <= 255 && Bu <= 255 && Au <= 255);
            R = (float)(Ru / 255.0);
            G = (float)(Gu / 255.0);
            B = (float)(Bu / 255.0);
            A = (float)(Au / 255.0);
        }


        /// <summary>
        /// Create a colour from a Vector
        /// </summary>
        /// <param name="col">Vector4 of rgba</param>
        public WritableRgbaFloat(Vector4 col)
        {
            R = col.X;
            G = col.Y;
            B = col.Z;
            A = col.W;
        }

        /// <summary>
        /// Create a colour from an ImGui uint 
        /// </summary>
        /// <param name="col">uint colour</param>
        public WritableRgbaFloat(uint col)
        {
            A = ((col & 0xff000000) >> 24) / 255f;
            B = ((col & 0xff0000) >> 16) / 255f;
            G = ((col & 0xff00) >> 8) / 255f;
            R = ((col & 0xff)) / 255f;
        }


        /// <summary>
        /// Get the uint value of this colour required by ImGui
        /// </summary>
        /// <param name="customAlpha">An optional alpha value</param>
        /// <returns>This colour as a uint</returns>
        public uint ToUint(uint? customAlpha = null)
        {
            if (customAlpha != null)
            {
                return (customAlpha.Value << 24) + ((uint)(B * 255) << 16) + ((uint)(G * 255) << 8) + ((uint)(R * 255));
            }

            return ((uint)(A * 255) << 24) + ((uint)(B * 255) << 16) + ((uint)(G * 255) << 8) + ((uint)(R * 255));
        }


        /// <summary>
        /// Change the alpha of a uint colour
        /// </summary>
        /// <param name="original">The colour to change the alpha of</param>
        /// <param name="customAlpha">An optional alpha value</param>
        /// <returns>This colour as a uint</returns>
        public static uint ToUint(uint original, uint customAlpha)
        {
            return (customAlpha << 24) + (original & 0xffffff);
        }


        /// <summary>
        /// This colour as a vector
        /// </summary>
        /// <returns>Vector4</returns>
        public Vector4 ToVec4()
        {
            return new Vector4(R, G, B, A);
        }

        /// <summary>
        /// Convert a .NET Colour to a Vector4
        /// </summary>
        /// <param name="col">Input Colour</param>
        /// <returns>output Vector4</returns>
        public static Vector4 ToVec4(Color col)
        {
            float R = col.R / 255f;
            float G = col.G / 255f;
            float B = col.B / 255f;
            float A = col.A / 255f;
            return new Vector4(R, G, B, A);
        }

        /// <summary>
        /// Convert a .NET Colour to a Veldrid RgbaFloat
        /// </summary>
        /// <param name="col"></param>
        /// <returns>RgbaFloat</returns>
        public static RgbaFloat ToRgbaFloat(Color col)
        {
            float R = col.R / 255f;
            float G = col.G / 255f;
            float B = col.B / 255f;
            float A = col.A / 255f;
            return new RgbaFloat(R, G, B, A);
        }

        /// <summary>
        /// Convert a .NET Colour to a uint
        /// </summary>
        /// <param name="col">Input Colour</param>
        /// <returns>output uint</returns>
        public static uint ToUint(Color col)
        {
            float R = col.R / 255f;
            float G = col.G / 255f;
            float B = col.B / 255f;
            float A = col.A / 255f;
            return CreateUint(R, G, B, A);
        }


        /// <summary>
        /// Convert float colour components to an imgui uint
        /// </summary>
        /// <param name="R">Red component 0-1</param>
        /// <param name="G">Green component 0-1</param>
        /// <param name="B">Blue component 0-1</param>
        /// <param name="A">Alpha component 0-1</param>
        /// <returns>uint colour</returns>
        public static uint CreateUint(float R, float G, float B, float A)
        {
            R = Math.Min(R, 1);
            G = Math.Min(G, 1);
            B = Math.Min(B, 1);
            A = Math.Min(A, 1);
            return ((uint)(A * 255) << 24) + ((uint)(B * 255) << 16) + ((uint)(G * 255) << 8) + ((uint)(R * 255));
        }


        /// <summary>
        /// Brighten a uint colour of a UI theme
        /// </summary>
        /// <param name="inputColour">uint colour</param>
        /// <param name="amount">How much to brighten it (0.0-2.0)</param>
        /// <returns></returns>
        public static uint Brighten(uint inputColour, float amount)
        {
            float A = ((inputColour & 0xff000000) >> 24) / 255f;
            float B = ((inputColour & 0xff0000) >> 16) / 255f;
            float G = ((inputColour & 0xff00) >> 8) / 255f;
            float R = ((inputColour & 0xff)) / 255f;
            return CreateUint(Math.Min(R * amount, 1), Math.Min(G * amount, 1), Math.Min(B * amount, 1), A);
        }


        /// <summary>
        /// Get this colour as a Veldrid RgbaFloat
        /// </summary>
        /// <returns>RgbaFloat</returns>
        public RgbaFloat ToRgbaFloat()
        {
            return new RgbaFloat(R, G, B, A);
        }

        /// <summary>
        /// The red value
        /// </summary>
        public float R { get; set; }
        /// <summary>
        /// The green value
        /// </summary>
        public float G { get; set; }
        /// <summary>
        /// The blue value
        /// </summary>
        public float B { get; set; }
        /// <summary>
        /// The alpha value
        /// </summary>
        public float A { get; set; }

    }

}
