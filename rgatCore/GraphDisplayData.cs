﻿using rgatCore.Threads;
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

    
    struct VertexPositionColorOld
    {
        public Vector3 Position;
        public WritableRgbaFloat Color;
        public float ActiveAnimAlpha;
        public const uint SizeInBytes = 32;

        public VertexPositionColorOld(Vector3 position, WritableRgbaFloat color, float AnimDarkAlpha)
        {
            Position = position;
            Color = color;
            ActiveAnimAlpha = AnimDarkAlpha;
        }
        public void SetAlpha(float alpha) => Color.A = alpha;
        public void SetAnimAlpha(float alpha)
        {
            ActiveAnimAlpha = alpha;
        }

        public VertexPositionColorOld(Vector3 position, Veldrid.RgbaFloat color, float AnimDarkAlpha)
        {
            Position = position;
            Color = new WritableRgbaFloat()
            {
                A = color.A,
                B = color.B,
                G = color.G,
                R = color.R
            };
            ActiveAnimAlpha = AnimDarkAlpha;
        }
    }

}
