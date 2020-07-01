using System;
using System.Collections.Generic;
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

        public class mainColours
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
        }
    }
}
