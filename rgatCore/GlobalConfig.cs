using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using Veldrid;

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

        /* 
         * Rendering config 
         */
        public static uint Preview_PerProcessLoopSleepMS = 100;
        public static uint Preview_PerThreadLoopSleepMS = 20;
        public static uint Preview_EdgesPerRender = 60;

        public static float animationFadeRate = 0.07f; //amount of alpha to reduce fading item by each frame
        public static int animationLingerFrames = 0; //number of frames before fade begins
        public static int renderFrequency = 25;
        public static int LiveAnimationUpdatesPerFrame = 500;

        public static bool showRisingAnimated = true;

        public static SYMS_VISIBILITY externalSymbolVisibility;
        public static SYMS_VISIBILITY internalSymbolVisibility;
        public static SYMS_VISIBILITY placeholderLabelVisibility;
        public static SYMS_VISIBILITY instructionTextVisibility;
        public static float insTextCompactThreshold = 2.5f;
        public static int OnScreenNodeTextCountLimit = 100;

        public static float FurthestInstructionText = 2500f;
        public static float FurthestSymbol = 5000f;

        public static float AnimatedFadeMinimumAlpha = 0.3f;
        public static float WireframeAnimatedAlpha = 0.7f;

        public static int ExternAnimDisplayFrames = 60;
        public static float ExternAnimRisePerFrame = 1.4f;

        public static uint MaximumLoadedGraphs = 1; //todo for dev - change to something like 20 later

        public static class mainColours
        {
            public static WritableRgbaFloat background = new WritableRgbaFloat(Color.Black);
            public static WritableRgbaFloat runningPreview = new WritableRgbaFloat(Color.FromArgb(180, 0, 42, 0));
            public static WritableRgbaFloat terminatedPreview = new WritableRgbaFloat(Color.FromArgb(180, 42, 0, 0));
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
            public static WritableRgbaFloat edgeOld = new WritableRgbaFloat(Color.FromArgb(150, 150, 150, 150));
            public static WritableRgbaFloat edgeRet = new WritableRgbaFloat(Color.Orange);
            public static WritableRgbaFloat edgeLib = new WritableRgbaFloat(Color.Green);
            public static WritableRgbaFloat edgeNew = new WritableRgbaFloat(Color.Yellow);
            public static WritableRgbaFloat edgeExcept = new WritableRgbaFloat(Color.Cyan);

            public static WritableRgbaFloat nodeStd = new WritableRgbaFloat(Color.Yellow);
            public static WritableRgbaFloat nodeJump = new WritableRgbaFloat(Color.Red);
            public static WritableRgbaFloat nodeCall = new WritableRgbaFloat(Color.Purple);
            public static WritableRgbaFloat nodeRet = new WritableRgbaFloat(Color.Orange);
            public static WritableRgbaFloat nodeExtern = new WritableRgbaFloat(Color.FromArgb(255, 40, 255, 0));
            public static WritableRgbaFloat nodeExcept = new WritableRgbaFloat(Color.Cyan);
        }

        public static List<WritableRgbaFloat> defaultGraphColours = new List<WritableRgbaFloat>();

        /*
         * UI/App related config
         */

        public static string SaveDirectory = @"C:\Users\nia\Source\Repos\rgatPrivate\rgatCore\bin\Debug\netcoreapp3.1\testsaves";// "[not set]";
        public static string PinPath = @"C:\devel\libs\pin-3.17\pin.exe";
        public static string PinToolPath32 = @"C:\Users\nia\Documents\Visual Studio 2017\Projects\rgatPinClients\Debug\pingat.dll";

        public static Dictionary<Tuple<Key,ModifierKeys>, eKeybind> Keybinds = new Dictionary<Tuple<Key, ModifierKeys>, eKeybind>();
        public static Dictionary<eKeybind, Tuple<Key, ModifierKeys>> PrimaryKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
        public static Dictionary<eKeybind, Tuple<Key, ModifierKeys>> AlternateKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
        public static List<Key> ResponsiveKeys = new List<Key>();
        public static List<eKeybind> ResponsiveHeldActions = new List<eKeybind>();

        /*
         * Trace related config
         */

        public static uint TraceBufferSize = 400000;
        //how many bytes back from an instruction to search for a symbol
        public static ulong SymbolSearchDistance = 4096;
        public static int ArgStorageMax = 100;

        public static void InitDefaultKeybinds()
        {
            SetKeybind(eKeybind.eMoveUp, 1, Key.W, ModifierKeys.None);
            SetKeybind(eKeybind.eMoveUp, 2, Key.Up, ModifierKeys.None);
            SetKeybind(eKeybind.eMoveDown, 1, Key.S, ModifierKeys.None);
            SetKeybind(eKeybind.eMoveDown, 2, Key.Down, ModifierKeys.None);
            SetKeybind(eKeybind.eMoveLeft, 1, Key.A, ModifierKeys.None);
            SetKeybind(eKeybind.eMoveLeft, 2, Key.Left, ModifierKeys.None);
            SetKeybind(eKeybind.eMoveRight, 1, Key.D, ModifierKeys.None);
            SetKeybind(eKeybind.eMoveRight, 2, Key.Right, ModifierKeys.None);

            SetKeybind(eKeybind.ePitchXFwd, 1, Key.PageUp, ModifierKeys.None);
            SetKeybind(eKeybind.ePitchXBack, 1, Key.PageDown, ModifierKeys.None);
            SetKeybind(eKeybind.eYawYLeft, 1, Key.Delete, ModifierKeys.None);
            SetKeybind(eKeybind.eYawYRight, 1, Key.End, ModifierKeys.None);
            SetKeybind(eKeybind.eRollGraphZAnti, 1, Key.Insert, ModifierKeys.None);
            SetKeybind(eKeybind.eRollGraphZClock, 1, Key.Home, ModifierKeys.None);

            SetKeybind(eKeybind.eCancel, 1, Key.Escape, ModifierKeys.None);
            SetKeybind(eKeybind.eCenterFrame, 1, Key.Q, ModifierKeys.None);
            SetKeybind(eKeybind.eLockCenterFrame, 1, Key.Q, ModifierKeys.Shift);
            SetKeybind(eKeybind.eRaiseForceTemperature, 1, Key.V, ModifierKeys.None);
            SetKeybind(eKeybind.eToggleHeatmap, 1, Key.X, ModifierKeys.None);
            SetKeybind(eKeybind.eToggleConditional, 1, Key.C, ModifierKeys.None);

            SetKeybind(eKeybind.eToggleText, 1, Key.I, ModifierKeys.None);
            SetKeybind(eKeybind.eToggleInsText, 1, Key.I, ModifierKeys.Shift);
            SetKeybind(eKeybind.eToggleLiveText, 1, Key.I, ModifierKeys.Control);
        }

        /// <summary>
        /// Some keybinds we don't want to wait for the OS repeat detection (S........SSSSSSSSSSS) because it makes
        /// things like graph movement and rotation clunky. Instead we read for their keypress every update instead
        /// of listening for the key action
        /// 
        /// Alt/Shift/Ctrl modifiers are reserved for these keys, so two different actions can't be bound to a key this way.
        /// </summary>
        static void InitResponsiveKeys()
        {
            ResponsiveHeldActions.Clear();
            ResponsiveHeldActions.Add(eKeybind.eMoveRight);
            ResponsiveHeldActions.Add(eKeybind.eMoveLeft);
            ResponsiveHeldActions.Add(eKeybind.eMoveDown);
            ResponsiveHeldActions.Add(eKeybind.eMoveUp);
            ResponsiveHeldActions.Add(eKeybind.ePitchXBack);
            ResponsiveHeldActions.Add(eKeybind.ePitchXFwd);
            ResponsiveHeldActions.Add(eKeybind.eYawYLeft);
            ResponsiveHeldActions.Add(eKeybind.eYawYRight);
            ResponsiveHeldActions.Add(eKeybind.eRollGraphZAnti);
            ResponsiveHeldActions.Add(eKeybind.eRollGraphZClock);

            ResponsiveKeys = Keybinds.Where(x => ResponsiveHeldActions.Contains(x.Value)).Select(x => x.Key.Item1).ToList();
        }

        public static void SetKeybind(eKeybind action, int bindIndex, Key k, ModifierKeys mod)
        {
            //reserved actions cant have modifier keys
            if (ResponsiveHeldActions.Contains(action))
                mod = ModifierKeys.None;

            Tuple<Key, ModifierKeys> keymod = new Tuple<Key, ModifierKeys>(k, mod);

            //if this keybind was used on another key, get rid of it
            foreach (var item in PrimaryKeybinds.Where(kvp => kvp.Value.GetHashCode() == keymod.GetHashCode()).ToList())
            {
                PrimaryKeybinds.Remove(item.Key);
            }
            foreach (var item in AlternateKeybinds.Where(kvp => kvp.Value.GetHashCode() == keymod.GetHashCode()).ToList())
            {
                AlternateKeybinds.Remove(item.Key);
            }

            //set the keybind
            if (bindIndex == 1)
            {
                PrimaryKeybinds[action] = keymod;
            }
            else
            {
                AlternateKeybinds[action] = keymod;
            }

            //regenerate the keybinds lists
            Keybinds.Clear();
            foreach (var kvp in PrimaryKeybinds) { Keybinds[kvp.Value] = kvp.Key; }
            foreach (var kvp in AlternateKeybinds) { Keybinds[kvp.Value] = kvp.Key; }

            ResponsiveKeys = Keybinds.Where(x => ResponsiveHeldActions.Contains(x.Value)).Select(x => x.Key.Item1).ToList();
        }

        public static void InitDefaultConfig()
        {
            InitDefaultKeybinds();
            //LoadCustomKeybinds();
            InitResponsiveKeys();


            defaultGraphColours = new List<WritableRgbaFloat> { 
                mainColours.edgeCall, mainColours.edgeOld, mainColours.edgeRet, mainColours.edgeLib, mainColours.edgeNew, mainColours.edgeExcept,
                mainColours.nodeStd, mainColours.nodeJump, mainColours.nodeCall, mainColours.nodeRet, mainColours.nodeExtern, mainColours.nodeExcept
            };

            const int EXTERN_VISIBLE_ZOOM_FACTOR = 40;
            const int INSTEXT_VISIBLE_ZOOMFACTOR = 5;

            externalSymbolVisibility = new SYMS_VISIBILITY
            {
                enabled = true,
                autoVisibleZoom = EXTERN_VISIBLE_ZOOM_FACTOR,
                offsets = true,
                addresses = false,
                fullPaths = false,
                extraDetail = true,
                duringAnimationFaded = false,
                duringAnimationHighlighted = true,
                notAnimated = true
            };

            internalSymbolVisibility = new SYMS_VISIBILITY
            {
                enabled = true,
                autoVisibleZoom = EXTERN_VISIBLE_ZOOM_FACTOR,
                addresses = false,
                fullPaths = false,
                extraDetail = true,
                duringAnimationFaded = false,
                duringAnimationHighlighted = true,
                notAnimated = true
            };

            placeholderLabelVisibility = new SYMS_VISIBILITY
            {
                enabled = true,
                autoVisibleZoom = EXTERN_VISIBLE_ZOOM_FACTOR,
                addresses = false,
                fullPaths = false,
                extraDetail = true,
                duringAnimationFaded = false,
                duringAnimationHighlighted = true,
                notAnimated = true
            };


            instructionTextVisibility = new SYMS_VISIBILITY
            {
                enabled = true,
                autoVisibleZoom = INSTEXT_VISIBLE_ZOOMFACTOR,
                addresses = true,
                offsets = true,
                fullPaths = true, //label for targets of calls/jmps
                extraDetail = true //only show control flow
            };
        }
    }
}
