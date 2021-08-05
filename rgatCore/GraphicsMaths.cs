using System;
using System.Numerics;

namespace rgat
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


        static Vector2 ScreenToNDCPos(Vector2 screenPos, Vector2 graphWidgetSize)
        {
            Vector2 temp = Vector2.Multiply(Vector2.Divide(screenPos, graphWidgetSize), 2.0f);
            Vector2 NDCPos = new Vector2(temp.X - 1f, temp.Y - 1f);
            return NDCPos;
        }

        public static Vector3 ScreenToWorldCoord(Vector2 screenCoord, float NDCZ, float CLIPW, Matrix4x4 invWV, Matrix4x4 invProj, Vector2 graphWidgetSize)
        {
            Vector2 NDCPos = ScreenToNDCPos(screenCoord, graphWidgetSize);
            Vector4 BCLIP_AfterWMul = Vector4.Multiply(new Vector4(NDCPos.X, NDCPos.Y, NDCZ, 1), CLIPW);
            Vector4 worldCoord = Vector4.Transform(Vector4.Transform(BCLIP_AfterWMul, invProj), invWV);
            return new Vector3(worldCoord.X, worldCoord.Y, worldCoord.Z);
        }

        public static Vector2 NdcToScreenPos(Vector2 ndcSpacePos, Vector2 graphWidgetSize)
        {
            return Vector2.Divide(new Vector2(ndcSpacePos.X + 1f, ndcSpacePos.Y + 1f), 2.0f) * graphWidgetSize;
        }

        public static Vector2 WorldToNDCPos(Vector3 worldCoord, Matrix4x4 worldView, Matrix4x4 projection)
        {
            Vector4 clipSpacePos = Vector4.Transform(Vector4.Transform(new Vector4(worldCoord, 1.0f), worldView), projection);
            Vector3 ndcSpacePos = Vector3.Divide(new Vector3(clipSpacePos.X, clipSpacePos.Y, clipSpacePos.Z), clipSpacePos.W);
            return new Vector2(ndcSpacePos.X, ndcSpacePos.Y);
        }

        public static Vector2 WorldToScreenCoord(Vector3 worldCoord, Matrix4x4 worldView, Matrix4x4 projection, Vector2 screenSize)
        {
            Vector4 clipSpacePos = Vector4.Transform(Vector4.Transform(new Vector4(worldCoord, 1.0f), worldView), projection);
            Vector3 ndcSpacePos = Vector3.Divide(new Vector3(clipSpacePos.X, clipSpacePos.Y, clipSpacePos.Z), clipSpacePos.W);
            Vector2 ndcPos = new Vector2(ndcSpacePos.X, ndcSpacePos.Y);

            Vector2 screenPos = NdcToScreenPos(ndcPos, screenSize);
            return screenPos;
        }


    }
}
