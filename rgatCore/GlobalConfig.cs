using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
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

        public static uint IngestStatsPerSecond = 6; //granularity of thread update rate plot
        public static float IngestStatWindow = 5f; //length of time a small thread activity plot covers (last X seconds)

        public static int KeystrokeDisplayMS = 4000;
        public static int KeystrokeStartFadeMS = 350;
        public static int KeystrokeDisplayMaxCount = 5;
        public static bool ShowKeystrokes = true;


        public static int VisMessageMaxLingerTime = 6500;
        public static int VisMessageFadeStartTime = 500;
        public static bool ShowVisMessages = true;


        public static class mainColours
        {
            public static WritableRgbaFloat background = new WritableRgbaFloat(Color.Black);
            public static WritableRgbaFloat runningPreview = new WritableRgbaFloat(Color.FromArgb(180, 0, 42, 0));
            public static WritableRgbaFloat terminatedPreview = new WritableRgbaFloat(Color.FromArgb(180, 42, 0, 0));
            public static WritableRgbaFloat suspendedPreview = new WritableRgbaFloat(Color.FromArgb(150, 245, 163, 71));
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
         * Theme - probably going to put in own class
         */
        //todo should be lists not dicts
        public enum eThemeColour { ePreviewText, ePreviewTextBackground, ePreviewPaneBorder, ePreviewPaneBackground,
            ePreviewZoomEnvelope, 
            eHeat0Lowest, eHeat1, eHeat2, eHeat3, eHeat4, eHeat5, eHeat6, eHeat7, eHeat8, eHeat9Highest,
            eVisBarPlotLine, eVisBarBg, eAlertWindowBg, eAlertWindowBorder,
            COUNT
        }
        public enum eThemeSize
        {
            ePreviewSelectedBorder,
            COUNT
        }
        public static Dictionary<ImGuiCol, uint> ThemeColoursStandard = new Dictionary<ImGuiCol, uint>();
        public static Dictionary<eThemeColour, uint> ThemeColoursCustom = new Dictionary<eThemeColour, uint>();
        public static Dictionary<eThemeSize, float> ThemeSizesCustom = new Dictionary<eThemeSize, float>();
        public static Dictionary<eThemeSize, Vector2> ThemeSizeLimits = new Dictionary<eThemeSize, Vector2>();


        public unsafe static void InitDefaultTheme()
        {
            for (int colI = 0; colI < (int)ImGuiCol.COUNT; colI++)
            {
                ImGuiCol col = (ImGuiCol)colI;
                Vector4 ced4vec = *ImGui.GetStyleColorVec4(col);
                if (ced4vec.W < 0.3) ced4vec.W = 0.7f;

                ThemeColoursStandard[col] = new WritableRgbaFloat(ced4vec).ToUint();
            }

            ThemeColoursCustom[eThemeColour.ePreviewText] = new WritableRgbaFloat(Af: 1f, Gf: 1, Bf: 1, Rf: 1).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewTextBackground] = new WritableRgbaFloat(Af: 0.3f, Gf: 0, Bf: 0, Rf: 0).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewPaneBorder] = new WritableRgbaFloat(Af: 1f, Gf: 0, Bf: 0, Rf: 1).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewPaneBackground] = new WritableRgbaFloat(Af: 1f, Gf: 0.05f, Bf: 0.05f, Rf: 0.05f).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewZoomEnvelope] = new WritableRgbaFloat(Af: 0.7f, Gf: 0.7f, Bf: 0.7f, Rf: 0.7f).ToUint();

            ThemeColoursCustom[eThemeColour.eHeat0Lowest] = new WritableRgbaFloat(0, 0, 155f/255f, 0.7f).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat1] = new WritableRgbaFloat(46f/255f, 28f/255f, 155f/255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat2] = new WritableRgbaFloat(95f/255f, 104f/255f, 226f/255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat3] = new WritableRgbaFloat(117f/255f, 143f/255f, 223f/255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat4] = new WritableRgbaFloat(255f/255f, 255f/225f, 255f/255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat5] = new WritableRgbaFloat(252f/255f, 196f/255f, 180f/255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat6] = new WritableRgbaFloat(242f/255f, 152f/255f, 152f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat7] = new WritableRgbaFloat(249f / 255f, 107f/255f, 107f/255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat8] = new WritableRgbaFloat(255f/255f, 64f/255f, 64f/255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat9Highest] = new WritableRgbaFloat(1, 0f, 0f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eVisBarPlotLine] = new WritableRgbaFloat(1, 0f, 0f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eVisBarBg] = new WritableRgbaFloat(Color.Black).ToUint();
            ThemeColoursCustom[eThemeColour.eAlertWindowBg] = new WritableRgbaFloat(Color.SlateBlue).ToUint();
            ThemeColoursCustom[eThemeColour.eAlertWindowBorder] = new WritableRgbaFloat(Color.GhostWhite).ToUint();


            ThemeSizesCustom[eThemeSize.ePreviewSelectedBorder] = 1f;
            ThemeSizeLimits[eThemeSize.ePreviewSelectedBorder] = new Vector2(0, 30);

        }

        public static uint GetThemeColour(eThemeColour item)
        {
            Debug.Assert(ThemeColoursCustom.ContainsKey(item));
            Debug.Assert((uint)item < ThemeColoursCustom.Count);
            return ThemeColoursCustom[item];
        }

        public static WritableRgbaFloat GetThemeColourB(eThemeColour item)
        {
            Debug.Assert(ThemeColoursCustom.ContainsKey(item));
            Debug.Assert((uint)item < ThemeColoursCustom.Count);
            return new WritableRgbaFloat(ThemeColoursCustom[item]);
        }

        public static uint GetThemeColour(ImGuiCol item)
        {
            Debug.Assert(ThemeColoursStandard.ContainsKey(item));
            Debug.Assert((uint)item < ThemeColoursStandard.Count);
            return ThemeColoursStandard[item];
        }
        public static float GetThemeSize(eThemeSize item)
        {
            Debug.Assert(ThemeSizesCustom.ContainsKey(item));
            Debug.Assert((uint)item < ThemeSizesCustom.Count);
            return ThemeSizesCustom[item];
        }

        /*
         * Trace related config
         */

        public static uint TraceBufferSize = 400000;
        //how many bytes back from an instruction to search for a symbol
        public static ulong SymbolSearchDistance = 4096;
        public static int ArgStorageMax = 100;

        public static void InitDefaultKeybinds()
        {
            SetKeybind(eKeybind.MoveUp, 1, Key.W, ModifierKeys.None);
            SetKeybind(eKeybind.MoveUp, 2, Key.Up, ModifierKeys.None);
            SetKeybind(eKeybind.MoveDown, 1, Key.S, ModifierKeys.None);
            SetKeybind(eKeybind.MoveDown, 2, Key.Down, ModifierKeys.None);
            SetKeybind(eKeybind.MoveLeft, 1, Key.A, ModifierKeys.None);
            SetKeybind(eKeybind.MoveLeft, 2, Key.Left, ModifierKeys.None);
            SetKeybind(eKeybind.MoveRight, 1, Key.D, ModifierKeys.None);
            SetKeybind(eKeybind.MoveRight, 2, Key.Right, ModifierKeys.None);

            SetKeybind(eKeybind.PitchXFwd, 1, Key.PageUp, ModifierKeys.None);
            SetKeybind(eKeybind.PitchXBack, 1, Key.PageDown, ModifierKeys.None);
            SetKeybind(eKeybind.YawYLeft, 1, Key.Delete, ModifierKeys.None);
            SetKeybind(eKeybind.YawYRight, 1, Key.End, ModifierKeys.None);
            SetKeybind(eKeybind.RollGraphZAnti, 1, Key.Insert, ModifierKeys.None);
            SetKeybind(eKeybind.RollGraphZClock, 1, Key.Home, ModifierKeys.None);

            SetKeybind(eKeybind.Cancel, 1, Key.Escape, ModifierKeys.None);
            SetKeybind(eKeybind.CenterFrame, 1, Key.Q, ModifierKeys.None);
            SetKeybind(eKeybind.LockCenterFrame, 1, Key.Q, ModifierKeys.Shift);
            SetKeybind(eKeybind.RaiseForceTemperature, 1, Key.V, ModifierKeys.None);
            SetKeybind(eKeybind.ToggleHeatmap, 1, Key.X, ModifierKeys.None);
            SetKeybind(eKeybind.ToggleConditionals, 1, Key.C, ModifierKeys.None);

            SetKeybind(eKeybind.ToggleAllText, 1, Key.I, ModifierKeys.None);
            SetKeybind(eKeybind.ToggleInsText, 1, Key.I, ModifierKeys.Shift);
            SetKeybind(eKeybind.ToggleLiveText, 1, Key.I, ModifierKeys.Control);
            SetKeybind(eKeybind.QuickMenu, 1, Key.M, ModifierKeys.None);
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
            ResponsiveHeldActions.Add(eKeybind.MoveRight);
            ResponsiveHeldActions.Add(eKeybind.MoveLeft);
            ResponsiveHeldActions.Add(eKeybind.MoveDown);
            ResponsiveHeldActions.Add(eKeybind.MoveUp);
            ResponsiveHeldActions.Add(eKeybind.PitchXBack);
            ResponsiveHeldActions.Add(eKeybind.PitchXFwd);
            ResponsiveHeldActions.Add(eKeybind.YawYLeft);
            ResponsiveHeldActions.Add(eKeybind.YawYRight);
            ResponsiveHeldActions.Add(eKeybind.RollGraphZAnti);
            ResponsiveHeldActions.Add(eKeybind.RollGraphZClock);

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
            InitDefaultTheme();

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
