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
            R = (float)col.R / 255f;
            G = (float)col.G / 255f;
            B = (float)col.B / 255f;
            A = (float)col.A / 255f;
        }


        /// <summary>
        /// Create a colour float colour values (0-1)
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

        //todo static version
        /// <summary>
        /// Get the uint value of this colour required by ImGui
        /// </summary>
        /// <param name="customAlpha">An optional alpha value</param>
        /// <returns>This colour as a uint</returns>
        public uint ToUint(uint? customAlpha = null)
        {
            if (customAlpha != null)
                return (customAlpha.Value << 24) + ((uint)(B * 255) << 16) + ((uint)(G * 255) << 8) + ((uint)(R * 255));
            return ((uint)(A * 255) << 24) + ((uint)(B * 255) << 16) + ((uint)(G * 255) << 8) + ((uint)(R * 255));
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
            float R = (float)col.R / 255f;
            float G = (float)col.G / 255f;
            float B = (float)col.B / 255f;
            float A = (float)col.A / 255f;
            return new Vector4(R, G, B, A);
        }

        /// <summary>
        /// Convert a .NET Colour to a Veldrid RgbaFloat
        /// </summary>
        /// <param name="col"></param>
        /// <returns>RgbaFloat</returns>
        public static RgbaFloat ToRgbaFloat(Color col)
        {
            float R = (float)col.R / 255f;
            float G = (float)col.G / 255f;
            float B = (float)col.B / 255f;
            float A = (float)col.A / 255f;
            return new RgbaFloat(R, G, B, A);
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
