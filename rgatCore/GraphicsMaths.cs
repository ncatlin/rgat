using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace rgatCore
{
    class GraphicsMaths
    {




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

        //https://gist.github.com/sixman9/871099
        private static bool WithinEpsilon(float a, float b)
        {
            float num = a - b;
            return ((-1.401298E-45f <= num) && (num <= float.Epsilon));
        }

         

    }
}
