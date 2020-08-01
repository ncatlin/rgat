using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace rgatCore
{
    class GraphicsMaths
    {
        public struct PROJECTDATA
        {
            public double[] model_view; //size 16
            public double[] projection; //size 16
            public int[] viewport; //size 4
        };

        //middle of line c1.c2 placed in c3
        static public void midpoint(Vector3 lineStart, Vector3 lineEnd, out Vector3 midPointCoord)
        {
            midPointCoord = new Vector3();
            midPointCoord.X = (lineStart.X + lineEnd.X) / 2;
            midPointCoord.Y = (lineStart.Y + lineEnd.Y) / 2;
            midPointCoord.Z = (lineStart.Z + lineEnd.Z) / 2;
        }

        //distance between two points
        public static float linedist(Vector3 c1, Vector3 c2)
        {
            double dist = Math.Pow((c2.X - c1.X), 2);
            dist += Math.Pow((c2.Y - c1.Y), 2);
            dist += Math.Pow((c2.Z - c1.Z), 2);
            return (float)Math.Sqrt(dist);
        }

        
        public static float getPulseAlpha()
        {
            const float period = 1; //number of seconds to go from 0..1..0
            double ticksMS = DateTime.Now.TimeOfDay.TotalMilliseconds;
            float pulsePoint = (float)ticksMS % (1000 * period);
            float pulsePercent = (float)pulsePoint / (float)(1000 * period);
            float pulseInTermsOfPI = (pulsePercent * 2f * (float)Math.PI) - (float)Math.PI;
            float sinVal = (float)Math.Sin(pulseInTermsOfPI);
            float res = (sinVal + 1) / 2;
            return res;
        }

        //returns a small number indicating rough zoom
        static public float zoomFactor(double cameraZoom, float plotSize)
        {
            return (float)((Math.Abs(cameraZoom) - plotSize) / 1000) - 1;
        }

        //computes location of point 'pointnum' on a quadratic bezier curve divided into totalpoints segments
        static public Vector3 bezierPT(Vector3 startC, Vector3 bezierC, Vector3 endC, int pointnum, int totalpoints)
        {
            float t = pointnum / totalpoints;

            //quadratic bezier
            float x = ((1 - t) * (1 - t) * startC.X + 2 * (1 - t) * t * bezierC.X + t * t * endC.X);
            float y = ((1 - t) * (1 - t) * startC.Y + 2 * (1 - t) * t * bezierC.Y + t * t * endC.Y);
            float z = ((1 - t) * (1 - t) * startC.Z + 2 * (1 - t) * t * bezierC.Z + t * t * endC.Z);
            return new Vector3(x, y, z);
        }
        public struct SCREENINFO
        {
            public float X, Y, Width, Height, MinDepth, MaxDepth, CamZoom;
        }

        //https://gist.github.com/sixman9/871099
        private static bool WithinEpsilon(float a, float b)
        {
            float num = a - b;
            return ((-1.401298E-45f <= num) && (num <= float.Epsilon));
        }

        public static Vector3 Project(Vector3 source, Matrix4x4 projection, Matrix4x4 view, Matrix4x4 world, SCREENINFO box)
        {
            Matrix4x4 matrix = Matrix4x4.Multiply(Matrix4x4.Multiply(world, view), projection);
            Vector3 vector = Vector3.Transform(source, matrix);
            float a = (((source.X * matrix.M14) + (source.Y * matrix.M24)) + (source.Z * matrix.M34)) + matrix.M44;
            if (!WithinEpsilon(a, 1f))
            {
                vector = vector / a;
            }
            vector.X = (((vector.X + 1f) * 0.5f) * box.Width) + box.X;
            vector.Y = (((-vector.Y + 1f) * 0.5f) * box.Height) + box.Y;
            vector.Z = (vector.Z * (box.MaxDepth - box.MinDepth)) + box.MinDepth;
            return vector;
        }

         public static Vector3 Unproject(Vector3 source, Matrix4x4 projection, Matrix4x4 view, Matrix4x4 world, SCREENINFO box)
        {
            Matrix4x4.Invert(Matrix4x4.Multiply(Matrix4x4.Multiply(world, view), projection), out Matrix4x4 matrix);
            source.X = (((source.X - box.X) / (box.Width)) * 2f) - 1f;
            source.Y = -((((source.Y - box.Y) / (box.Height)) * 2f) - 1f);
            source.Z = (source.Z - box.MinDepth) / (box.MaxDepth - box.MinDepth);

            Vector3 vector = Vector3.Transform(source, matrix);
            float a = (((source.X * matrix.M14) + (source.Y * matrix.M24)) + (source.Z * matrix.M34)) + matrix.M44;
            if (!WithinEpsilon(a, 1f))
            {
                vector = (Vector3)(vector / a);
            }
            return vector;
        }
         

    }
}
