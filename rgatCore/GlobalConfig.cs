using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Text;

namespace rgatCore.Threads
{
    class GlobalConfig
    {
        public struct SYMS_VISIBILITY
        {
            public bool enabled;
            public bool showWhenZoomed;
            public float autoVisibleZoom;

            public bool duringAnimationFaded;
            public bool duringAnimationHighlighted;
            public bool notAnimated;
            public bool fullPaths;
            public bool addresses;
            public bool offsets;
            public bool extraDetail;
        };

        public static uint Preview_PerProcessLoopSleepMS = 100;
        public static uint Preview_PerThreadLoopSleepMS = 20;
        public static uint Preview_EdgesPerRender = 60;

        public static float animationFadeRate = 0.07f;
        public static int renderFrequency = 25;
        public static int animationUpdatesPerFrame = 500;
        public static uint TraceBufferSize = 400000;

        public static int ArgStorageMax = 100;

        public static bool showRisingAnimated = true;

        public static SYMS_VISIBILITY externalSymbolVisibility;
        public static SYMS_VISIBILITY internalSymbolVisibility;
        public static SYMS_VISIBILITY placeholderLabelVisibility;
        public static SYMS_VISIBILITY instructionTextVisibility;
        public static float insTextCompactThreshold = 2.5f;
        public static int OnScreenNodeTextCountLimit = 100;

        public static float FurthestInstructionText = 2000f;
        public static float FurthestSymbol = 5000f;

        public static class mainColours
        {
            public static WritableRgbaFloat background = new WritableRgbaFloat(Color.Black);
            public static WritableRgbaFloat highlightLine = new WritableRgbaFloat(Color.Green);
            public static WritableRgbaFloat wireframe = new WritableRgbaFloat(Color.LightGray);
            public static WritableRgbaFloat instructionText = new WritableRgbaFloat(Color.White);
            public static WritableRgbaFloat symbolTextExternal = new WritableRgbaFloat(Color.Green);
            public static WritableRgbaFloat symbolTextExternalRising = new WritableRgbaFloat(Color.Green);
            public static WritableRgbaFloat symbolTextInternal = new WritableRgbaFloat(Color.Gray);
            public static WritableRgbaFloat symbolTextInternalRising = new WritableRgbaFloat(Color.LightGray);
            public static WritableRgbaFloat symbolTextPlaceholder = new WritableRgbaFloat(Color.LightGray);
            public static WritableRgbaFloat activityLine = new WritableRgbaFloat(Color.Red);

            public static WritableRgbaFloat edgeCall = new WritableRgbaFloat(Color.Purple);
            public static WritableRgbaFloat edgeOld = new WritableRgbaFloat(Color.FromArgb(0,244,244,244));
            public static WritableRgbaFloat edgeReg = new WritableRgbaFloat(Color.Orange);
            public static WritableRgbaFloat edgeLib = new WritableRgbaFloat(Color.Green);
            public static WritableRgbaFloat edgeNew = new WritableRgbaFloat(Color.Yellow);
            public static WritableRgbaFloat edgeExcept = new WritableRgbaFloat(Color.Cyan);

            public static WritableRgbaFloat nodeStd = new WritableRgbaFloat(Color.Yellow);
            public static WritableRgbaFloat nodeJump = new WritableRgbaFloat(Color.Red);
            public static WritableRgbaFloat nodeCall = new WritableRgbaFloat(Color.Purple);
            public static WritableRgbaFloat nodeRet = new WritableRgbaFloat(Color.Orange);
            public static WritableRgbaFloat nodeExtern = new WritableRgbaFloat(Color.Green);
            public static WritableRgbaFloat nodeExcept = new WritableRgbaFloat(Color.Cyan);
        }

        public static List<WritableRgbaFloat> defaultGraphColours = new List<WritableRgbaFloat>();

        public static void InitDefaultConfig()
        {
            defaultGraphColours = new List<WritableRgbaFloat> { 
                mainColours.edgeCall, mainColours.edgeOld, mainColours.edgeReg, mainColours.edgeLib, mainColours.edgeNew, mainColours.edgeExcept,
                mainColours.nodeStd, mainColours.nodeJump, mainColours.nodeCall, mainColours.nodeRet, mainColours.nodeExtern, mainColours.nodeExcept
            };

            const int EXTERN_VISIBLE_ZOOM_FACTOR = 40;
            const int INSTEXT_VISIBLE_ZOOMFACTOR = 5;

            externalSymbolVisibility = new SYMS_VISIBILITY();
            externalSymbolVisibility.enabled = true;
            externalSymbolVisibility.autoVisibleZoom = EXTERN_VISIBLE_ZOOM_FACTOR;
            externalSymbolVisibility.offsets = true;
            externalSymbolVisibility.addresses = false;
            externalSymbolVisibility.fullPaths = false;
            externalSymbolVisibility.extraDetail = true;
            externalSymbolVisibility.duringAnimationFaded = false;
            externalSymbolVisibility.duringAnimationHighlighted = true;
            externalSymbolVisibility.notAnimated = true;

            internalSymbolVisibility = new SYMS_VISIBILITY();
            internalSymbolVisibility.enabled = true;
            internalSymbolVisibility.autoVisibleZoom = EXTERN_VISIBLE_ZOOM_FACTOR;
            internalSymbolVisibility.addresses = false;
            internalSymbolVisibility.fullPaths = false;
            internalSymbolVisibility.extraDetail = true;
            internalSymbolVisibility.duringAnimationFaded = false;
            internalSymbolVisibility.duringAnimationHighlighted = true;
            internalSymbolVisibility.notAnimated = true;

            placeholderLabelVisibility = new SYMS_VISIBILITY();
            placeholderLabelVisibility.enabled = true;
            placeholderLabelVisibility.autoVisibleZoom = EXTERN_VISIBLE_ZOOM_FACTOR;
            placeholderLabelVisibility.addresses = false;
            placeholderLabelVisibility.fullPaths = false;
            placeholderLabelVisibility.extraDetail = true;
            placeholderLabelVisibility.duringAnimationFaded = false;
            placeholderLabelVisibility.duringAnimationHighlighted = true;
            placeholderLabelVisibility.notAnimated = true;


            instructionTextVisibility = new SYMS_VISIBILITY();
            instructionTextVisibility.enabled = true;
            instructionTextVisibility.autoVisibleZoom = INSTEXT_VISIBLE_ZOOMFACTOR;
            instructionTextVisibility.addresses = true;
            instructionTextVisibility.offsets = true;
            instructionTextVisibility.fullPaths = true; //label for targets of calls/jmps
            instructionTextVisibility.extraDetail = true; //only show control flow
        }
    }
}
