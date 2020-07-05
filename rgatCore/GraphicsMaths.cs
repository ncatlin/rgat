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
            long clockVal = DateTime.Now.Ticks;
            int millisecond = ((int)(clockVal / 100)) % 10;
            int countUp = ((int)(clockVal / 1000) % 10) % 2;

            float pulseAlpha;
            if (countUp == 0)
                pulseAlpha = (float)millisecond / 10.0f;
            else
                pulseAlpha = 1.0f - (millisecond / 10.0f);

            return pulseAlpha;
        }

        //returns a small number indicating rough zoom
        static public float zoomFactor(double cameraZoom, float plotSize)
        {
            return (float)((Math.Abs(cameraZoom) - plotSize) / 1000) - 1;
        }

    }
}
