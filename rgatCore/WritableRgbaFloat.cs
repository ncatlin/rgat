using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using Veldrid;
/*
This class holds (and provides dubiously mutex guarded access to) OpenGl vertex and colour data
*/
namespace rgatCore
{
    struct WritableRgbaFloat
    {
        public WritableRgbaFloat(Color col)
        {
            R = (float)col.R / 255f;
            G = (float)col.G / 255f;
            B = (float)col.B / 255f;
            A = (float)col.A / 255f;
        }

        public WritableRgbaFloat(float Rf, float Gf, float Bf, float Af)
        {
            R = (float)Rf;
            G = (float)Gf;
            B = (float)Bf;
            A = (float)Af;
        }

        public WritableRgbaFloat(Vector4 col)
        {
            R = col.X;
            G = col.Y;
            B = col.Z;
            A = col.W;
        }

        public WritableRgbaFloat(uint col)
        {
            A = ((col & 0xff000000) >> 24) / 255f;
            B = ((col & 0xff0000) >> 16) / 255f;
            G = ((col & 0xff00) >> 8) / 255f;
            R = ((col & 0xff)) / 255f;
        }

        public uint ToUint(uint? customAlpha = null)
        {
            if (customAlpha != null)
                return (customAlpha.Value << 24) + ((uint)(B * 255) << 16) + ((uint)(G * 255) << 8) + ((uint)(R * 255));
            return ((uint)(A * 255) << 24) + ((uint)(B * 255) << 16) + ((uint)(G * 255) << 8) + ((uint)(R * 255));
        }

        public Vector4 ToVec4()
        {
            return new Vector4(R, G, B, A);
        }

        public static Vector4 ToVec4(Color col)
        {
            float R = (float)col.R / 255f;
            float G = (float)col.G / 255f;
            float B = (float)col.B / 255f;
            float A = (float)col.A / 255f;
            return new Vector4(R, G, B, A);
        }

        public static RgbaFloat ToRgbaFloat(Color col)
        {
            float R = (float)col.R / 255f;
            float G = (float)col.G / 255f;
            float B = (float)col.B / 255f;
            float A = (float)col.A / 255f;
            return new RgbaFloat(R, G, B, A);
        }
        public RgbaFloat ToRgbaFloat()
        {
            return new RgbaFloat(R, G, B, A);
        }


        public float R { get; set; }
        public float G { get; set; }
        public float B { get; set; }
        public float A { get; set; }

    }

}
