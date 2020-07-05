using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Text;

namespace rgatCore.Threads
{
    class GlobalConfig
    {
        public static int Preview_PerProcessLoopSleepMS = 100;
        public static int Preview_PerThreadLoopSleepMS = 20;

        public static float animationFadeRate = 0.07f;
        public static int renderFrequency = 25;

        public static bool showRisingAnimated = true;

        public static class mainColours
        {
            public static Color background = Color.Black;
            public static Color highlightLine = Color.Green;
            public static Color instructionText = Color.White;
            public static Color symbolTextExternal = Color.Green;
            public static Color symbolTextExternalRising = Color.Green;
            public static Color symbolTextInternal = Color.Gray;
            public static Color symbolTextInternalRising = Color.LightGray;
            public static Color symbolTextPlaceholder = Color.LightGray;
            public static Color activityLine = Color.Red;

            public static Color edgeCall = Color.Purple;
            public static Color edgeOld = Color.White;
            public static Color edgeReg = Color.Orange;
            public static Color edgeLib = Color.Green;
            public static Color edgeNew = Color.Yellow;
            public static Color edgeExcept = Color.Cyan;

            public static Color nodeStd = Color.Yellow;
            public static Color nodeJump = Color.Red;
            public static Color nodeCall = Color.Purple;
            public static Color nodeRet = Color.Orange;
            public static Color nodeExtern = Color.Green;
            public static Color nodeExcept = Color.Cyan;
        }

        public static List<Color> defaultGraphColours = new List<Color>();

        public static void InitDefaultConfig()
        {
            defaultGraphColours = new List<Color> { 
                mainColours.edgeCall, mainColours.edgeOld, mainColours.edgeReg, mainColours.edgeLib, mainColours.edgeNew, mainColours.edgeExcept,
                mainColours.nodeStd, mainColours.nodeJump, mainColours.nodeCall, mainColours.nodeRet, mainColours.nodeExtern, mainColours.nodeExcept
            };
        }
    }
}
