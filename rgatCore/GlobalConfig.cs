using ImGuiNET;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
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

        public static Dictionary<Tuple<Key, ModifierKeys>, eKeybind> Keybinds = new Dictionary<Tuple<Key, ModifierKeys>, eKeybind>();
        public static Dictionary<eKeybind, Tuple<Key, ModifierKeys>> PrimaryKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
        public static Dictionary<eKeybind, Tuple<Key, ModifierKeys>> AlternateKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
        public static List<Key> ResponsiveKeys = new List<Key>();
        public static List<eKeybind> ResponsiveHeldActions = new List<eKeybind>();

        /*
         * Theme - probably going to put in own class
         */
        //todo should be lists not dicts
        public enum eThemeColour
        {
            ePreviewText, ePreviewTextBackground, ePreviewPaneBorder, ePreviewPaneBackground,
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
        public static Dictionary<string, string> ThemeMetadata = new Dictionary<string, string>();
        public static bool IsBuiltinTheme = true;
        public static bool UnsavedTheme = false;


        public static void InitFallbackTheme()
        {
            InitDefaultImGuiColours();

            ThemeMetadata["Name"] = "Fallback";
            ThemeMetadata["Description"] = "Fallback theme for when preloaded and custom themes failed to load";
            ThemeMetadata["Author"] = "rgat fallback theme";
            ThemeMetadata["Author2"] = "https://github.com/ncatlin/rgat";

            ThemeColoursCustom[eThemeColour.ePreviewText] = new WritableRgbaFloat(Af: 1f, Gf: 1, Bf: 1, Rf: 1).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewTextBackground] = new WritableRgbaFloat(Af: 0.3f, Gf: 0, Bf: 0, Rf: 0).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewPaneBorder] = new WritableRgbaFloat(Af: 1f, Gf: 0, Bf: 0, Rf: 1).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewPaneBackground] = new WritableRgbaFloat(Af: 1f, Gf: 0.05f, Bf: 0.05f, Rf: 0.05f).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewZoomEnvelope] = new WritableRgbaFloat(Af: 0.7f, Gf: 0.7f, Bf: 0.7f, Rf: 0.7f).ToUint();

            ThemeColoursCustom[eThemeColour.eHeat0Lowest] = new WritableRgbaFloat(0, 0, 155f / 255f, 0.7f).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat1] = new WritableRgbaFloat(46f / 255f, 28f / 255f, 155f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat2] = new WritableRgbaFloat(95f / 255f, 104f / 255f, 226f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat3] = new WritableRgbaFloat(117f / 255f, 143f / 255f, 223f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat4] = new WritableRgbaFloat(255f / 255f, 255f / 225f, 255f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat5] = new WritableRgbaFloat(252f / 255f, 196f / 255f, 180f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat6] = new WritableRgbaFloat(242f / 255f, 152f / 255f, 152f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat7] = new WritableRgbaFloat(249f / 255f, 107f / 255f, 107f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat8] = new WritableRgbaFloat(255f / 255f, 64f / 255f, 64f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat9Highest] = new WritableRgbaFloat(1, 0f, 0f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eVisBarPlotLine] = new WritableRgbaFloat(1, 0f, 0f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eVisBarBg] = new WritableRgbaFloat(Color.Black).ToUint();
            ThemeColoursCustom[eThemeColour.eAlertWindowBg] = new WritableRgbaFloat(Color.SlateBlue).ToUint();
            ThemeColoursCustom[eThemeColour.eAlertWindowBorder] = new WritableRgbaFloat(Color.GhostWhite).ToUint();


            ThemeSizesCustom[eThemeSize.ePreviewSelectedBorder] = 1f;
            ThemeSizeLimits[eThemeSize.ePreviewSelectedBorder] = new Vector2(0, 30);
            IsBuiltinTheme = true;
        }


        static unsafe void InitDefaultImGuiColours()
        {
            for (int colI = 0; colI < (int)ImGuiCol.COUNT; colI++)
            {
                ImGuiCol col = (ImGuiCol)colI;
                Vector4 ced4vec = *ImGui.GetStyleColorVec4(col);
                if (ced4vec.W < 0.3) ced4vec.W = 0.7f;

                ThemeColoursStandard[col] = new WritableRgbaFloat(ced4vec).ToUint();
            }
        }


        public static uint GetThemeColourUINT(eThemeColour item)
        {
            Debug.Assert(ThemeColoursCustom.ContainsKey(item));
            Debug.Assert((uint)item < ThemeColoursCustom.Count);
            return ThemeColoursCustom[item];
        }

        public static WritableRgbaFloat GetThemeColourWRF(eThemeColour item)
        {
            Debug.Assert(ThemeColoursCustom.ContainsKey(item));
            Debug.Assert((uint)item < ThemeColoursCustom.Count);
            return new WritableRgbaFloat(ThemeColoursCustom[item]);
        }

        public static uint GetThemeColourImGui(ImGuiCol item)
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

        public static Dictionary<string, string> LoadedStringResources = new Dictionary<string, string>();

        /*
         * This will load valid but incomplete theme data into the existing theme, but not if there
         * is any invalid data
         */
        static bool ActivateThemeObject(JObject theme)
        {
            Dictionary<string, string> pendingMetadata = new Dictionary<string, string>();
            Dictionary<ImGuiCol, uint> pendingColsStd = new Dictionary<ImGuiCol, uint>();
            Dictionary<eThemeColour, uint> pendingColsCustom = new Dictionary<eThemeColour, uint>();
            Dictionary<eThemeSize, float> pendingSizes = new Dictionary<eThemeSize, float>();
            Dictionary<eThemeSize, Vector2> pendingLimits = new Dictionary<eThemeSize, Vector2>();

            if (!LoadMetadataStrings(theme, out pendingMetadata, out string errorMsg))
            {
                Logging.RecordLogEvent(errorMsg); return false;
            }

            if (theme.TryGetValue("CustomColours", out JToken customColTok) && customColTok.Type == JTokenType.Object)
            {
                foreach (var item in customColTok.ToObject<JObject>())
                {
                    eThemeColour customcolType;
                    try
                    {
                        customcolType = (eThemeColour)Enum.Parse(typeof(eThemeColour), item.Key, true);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Theme has invalid custom colour type {item.Key.ToString()}"); return false;
                    }
                    if (customcolType >= eThemeColour.COUNT)
                    {
                        Logging.RecordLogEvent($"Theme has invalid custom colour type {item.Key.ToString()}"); return false;
                    }
                    if (item.Value.Type != JTokenType.Integer)
                    {
                        Logging.RecordLogEvent($"Theme has custom colour with non-integer colour entry {item.Key}"); return false;
                    }
                    pendingColsCustom[customcolType] = item.Value.ToObject<uint>();
                }
            }

            if (theme.TryGetValue("StandardColours", out JToken stdColTok) && stdColTok.Type == JTokenType.Object)
            {
                foreach (var item in stdColTok.ToObject<JObject>())
                {
                    ImGuiCol stdcolType;
                    try
                    {
                        stdcolType = (ImGuiCol)Enum.Parse(typeof(ImGuiCol), item.Key, true);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Theme has invalid standard colour type {item.Key.ToString()}"); return false;
                    }
                    if (stdcolType >= ImGuiCol.COUNT)
                    {
                        Logging.RecordLogEvent($"Theme has invalid standard colour type {item.Key.ToString()}"); return false;
                    }
                    if (item.Value.Type != JTokenType.Integer)
                    {
                        Logging.RecordLogEvent($"Theme has custom colour with non-integer colour entry {item.Key}"); return false;
                    }
                    pendingColsStd[stdcolType] = item.Value.ToObject<uint>();
                }
            }

            if (theme.TryGetValue("Sizes", out JToken sizesTok) && sizesTok.Type == JTokenType.Object)
            {
                foreach (var item in sizesTok.ToObject<JObject>())
                {
                    eThemeSize sizeType;
                    try
                    {
                        sizeType = (eThemeSize)Enum.Parse(typeof(eThemeSize), item.Key, true);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Theme has invalid size type {item.Key.ToString()}"); return false;
                    }
                    if (sizeType >= eThemeSize.COUNT)
                    {
                        Logging.RecordLogEvent($"Theme has invalid size type {item.Key.ToString()}"); return false;
                    }
                    if (item.Value.Type != JTokenType.Float)
                    {
                        Logging.RecordLogEvent($"Theme has size with non-float size entry {item.Key}"); return false;
                    }
                    ThemeSizesCustom[sizeType] = item.Value.ToObject<float>();
                }
            }


            if (theme.TryGetValue("SizeLimits", out JToken sizelimTok) && sizesTok.Type == JTokenType.Object)
            {
                foreach (var item in sizelimTok.ToObject<JObject>())
                {
                    eThemeSize sizeType;
                    try
                    {
                        sizeType = (eThemeSize)Enum.Parse(typeof(eThemeSize), item.Key, true);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Theme has invalid sizelimit type {item.Key}"); return false;
                    }
                    if (sizeType >= eThemeSize.COUNT)
                    {
                        Logging.RecordLogEvent($"Theme has invalid sizelimit type {item.Key}"); return false;
                    }
                    if (item.Value.Type != JTokenType.Array)
                    {
                        Logging.RecordLogEvent($"Theme has sizelimit with non-array entry {item.Key}"); return false;
                    }
                    JArray limits = item.Value.ToObject<JArray>();
                    if (limits.Count != 2 || limits[0].Type != JTokenType.Float || limits[1].Type != JTokenType.Float)
                    {
                        Logging.RecordLogEvent($"Theme has sizelimit with invalid array size or item types (should be 2 floats) {item.Key}"); return false;
                    }
                    pendingLimits[sizeType] = new Vector2(limits[0].ToObject<float>(), limits[1].ToObject<float>());
                }
            }

            //all loaded and validated, load them into the UI
            foreach (var kvp in pendingMetadata) ThemeMetadata[kvp.Key] = kvp.Value;
            foreach (var kvp in pendingColsCustom) ThemeColoursCustom[kvp.Key] = kvp.Value;
            foreach (var kvp in pendingColsStd) ThemeColoursStandard[kvp.Key] = kvp.Value;
            foreach (var kvp in pendingLimits) ThemeSizeLimits[kvp.Key] = kvp.Value;
            foreach (var kvp in pendingSizes) ThemeSizesCustom[kvp.Key] = kvp.Value;

            IsBuiltinTheme = BuiltinThemes.ContainsKey(ThemeMetadata["Name"]);

            return true;
        }

        public static void SaveMetadataChange(string key, string value)
        {
            ThemeMetadata[key] = value;
            currentThemeJSON["Metadata"][key] = value;
            UnsavedTheme = true;
        }

        public static void SavePresetTheme(string name)
        {
            if (name != ThemeMetadata["Name"])
            {
                SaveMetadataChange("Name", name);
            }

            if (!BuiltinThemes.ContainsKey(name))
            {
                CustomThemes[name] = currentThemeJSON;
                ThemesMetadataCatalogue[name] = ThemeMetadata;
                UnsavedTheme = false;
            }
        }

        static JObject currentThemeJSON;

        public static string RegenerateUIThemeJSON()
        {

            JObject themeJsnObj = new JObject();

            JObject themeCustom = new JObject();
            foreach (var kvp in GlobalConfig.ThemeColoursCustom) themeCustom.Add(kvp.Key.ToString(), kvp.Value);
            themeJsnObj.Add("CustomColours", themeCustom);

            JObject themeImgui = new JObject();
            foreach (var kvp in GlobalConfig.ThemeColoursStandard) themeImgui.Add(kvp.Key.ToString(), kvp.Value);
            themeJsnObj.Add("StandardColours", themeImgui);

            JObject sizesObj = new JObject();
            foreach (var kvp in GlobalConfig.ThemeSizesCustom) sizesObj.Add(kvp.Key.ToString(), kvp.Value);
            themeJsnObj.Add("Sizes", sizesObj);

            JObject sizeLimitsObj = new JObject();
            foreach (var kvp in GlobalConfig.ThemeSizeLimits) sizeLimitsObj.Add(kvp.Key.ToString(), new JArray(new List<float>() { kvp.Value.X, kvp.Value.Y }));
            themeJsnObj.Add("SizeLimits", sizeLimitsObj);

            JObject metadObj = new JObject();

            foreach (var kvp in GlobalConfig.ThemeMetadata) 
            {
                metadObj.Add(kvp.Key.ToString(), kvp.Value.ToString()); 
            }
            themeJsnObj.Add("Metadata", metadObj);

            currentThemeJSON = themeJsnObj;
            return themeJsnObj.ToString();
        }


        public static bool ActivateThemeObject(string themeJSON, out string error)
        {
            JObject themeJson = null;
            try
            {
                themeJson = Newtonsoft.Json.Linq.JObject.Parse(themeJSON);
            }
            catch (Exception e)
            {
                error = "Error parsing JSON";
                return false;
            }

            if (ActivateThemeObject(themeJson))
            {
                error = "Success";
                UnsavedTheme = true;
                return true;
            }

            error = "Load of parsed JSON failed";
            return false;
        }


        static bool LoadMetadataStrings(JObject themeObj, out Dictionary<string, string> result, out string error)
        {
            result = new Dictionary<string, string>();

            JObject metadataObj;
            if (themeObj.TryGetValue("Metadata", out JToken mdTok) && mdTok.Type == JTokenType.Object)
            {
                metadataObj = mdTok.ToObject<JObject>();
            }
            else
            {
                error = "Unable to find \"Metadata\" object in theme";
                return false;
            }

            foreach (var item in metadataObj)
            {
                if (item.Key.Length > 255)
                {
                    error = $"Theme has metadata key with excessive length {item.Key.Length}"; return false;
                }
                if (item.Value.Type != JTokenType.String)
                {
                    error = $"Theme has non-string metadata item {item.Key}"; return false;
                }
                string mdvalue = item.Value.ToObject<string>();
                if (mdvalue.Length > 4096)
                {
                    error = $"Skipping Theme metadata value with excessive length {mdvalue.Length}"; return false;
                }
                result[item.Key] = mdvalue;
            }
            error = "Success";
            return true;
        }


        public static void LoadTheme(string themename)
        {
            if (ThemeMetadata.TryGetValue("Name", out string currentTheme) && currentTheme == themename)
            {
                return;
            }

            if (BuiltinThemes.ContainsKey(themename))
            {
                Logging.RecordLogEvent($"Loading builtin theme {themename}");
                ActivateThemeObject(BuiltinThemes[themename]);

                return;
            }
            if (CustomThemes.ContainsKey(themename))
            {
                Logging.RecordLogEvent($"Loading custom theme {themename}");
                ActivateThemeObject(CustomThemes[themename]);
                return;
            }
            Logging.RecordLogEvent($"Tried to load unknown theme {themename}", Logging.LogFilterType.TextError);
        }


        public static Dictionary<string, JObject> CustomThemes = new Dictionary<string, JObject>();
        public static Dictionary<string, JObject> BuiltinThemes = new Dictionary<string, JObject>();
        public static Dictionary<string, Dictionary<string, string>> ThemesMetadataCatalogue = new Dictionary<string, Dictionary<string, string>>();

        public static void LoadPresetThemes(JArray themesArray)
        {
            Console.WriteLine($"Loading {themesArray.Count} builtin themes");

            for (var i = 0; i < themesArray.Count; i++)
            {
                JObject theme = themesArray[i].Value<JObject>();
                if (!LoadMetadataStrings(theme, out Dictionary<string, string> metadata, out string error))
                {
                    Logging.RecordLogEvent($"Error loading metadata for preloaded theme {i}: {error}");
                    continue;
                }

                if (!metadata.TryGetValue("Name", out string themeName))
                {
                    Logging.RecordLogEvent($"Skipping load for preloaded theme {i} (no 'Name' in metadata)");
                    continue;
                }

                BuiltinThemes[themeName] = theme;
                ThemesMetadataCatalogue[themeName] = metadata;
            }
        }

        public static void LoadResources()
        {
            System.Reflection.Assembly assembly = typeof(ImGuiController).Assembly;
            System.IO.Stream fs = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames()[0]);
            System.Resources.ResourceReader r = new System.Resources.ResourceReader(fs);
            System.Collections.IDictionaryEnumerator dict = r.GetEnumerator();

            while (dict.MoveNext())
            {
                if (dict.Key.ToString() == "BuiltinJSONThemes")
                {
                    string themesjsn = (string)dict.Value.ToString();

                    Newtonsoft.Json.Linq.JArray themesListJson = new Newtonsoft.Json.Linq.JArray();
                    try
                    {
                        themesListJson = Newtonsoft.Json.Linq.JArray.Parse(themesjsn);
                        LoadPresetThemes(themesListJson);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Exception loading builtin themes: {e.Message}");
                    }
                }
            }
        }

        public static void InitDefaultConfig()
        {
            LoadResources();

            //todo - user default theme once setting loaded
            if (BuiltinThemes.Count > 0)
            {
                LoadTheme(BuiltinThemes.Keys.First());
            }

            if (ThemeColoursStandard.Count == 0)
            {
                InitFallbackTheme();
            }


            var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            var settings = configFile.AppSettings.Settings;
            settings.Add("Setting1", "setting1value");
            settings.Add("Theme1", "{Google play \"cards\"");
            Console.WriteLine(configFile.FilePath);
            configFile.Save();
            ConfigurationManager.RefreshSection("appSettings");


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
