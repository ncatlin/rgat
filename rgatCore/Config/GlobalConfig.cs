﻿using Humanizer;
using ImGuiNET;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Veldrid;
using static rgat.RGAT_CONSTANTS;

namespace rgat
{
    public partial class GlobalConfig
    {
        public class JSONBlobConverter : TypeConverter
        {
            public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
            {
                return (sourceType == typeof(JObject)) || sourceType == typeof(JArray) || (sourceType == typeof(string));
            }

            public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
            {
                if (value.GetType() == typeof(string))
                {
                    try
                    {
                        JToken result = JToken.Parse((String)value);
                        return result;
                    }
                    catch
                    {
                        throw new DataException($"JSONBlobConverter ConvertFrom Bad json value {value}");
                    }
                }
                throw new NotImplementedException($"JSONBlobConverter can only convert from string");
            }

            public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
            {
                return (destinationType == typeof(JObject))
                     || destinationType == typeof(JArray)
                     || (destinationType == typeof(string));
            }

            public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
            {
                if (destinationType == typeof(string))
                {
                    switch (value)
                    {
                        case JObject objToken: return objToken.ToString();
                        case JArray arrToken: return arrToken.ToString();
                        case string stringToken: return stringToken;
                        default:
                            break;
                    }
                }
                throw new NotImplementedException($"ConvertTo can't convert type {value.GetType()} to {destinationType}");
            }
        }


        public sealed class KeybindSection : ConfigurationSection
        {

            private static ConfigurationPropertyCollection _Properties;
            private static readonly ConfigurationProperty _keybindJSON = new ConfigurationProperty(
                "CustomKeybinds",
                typeof(JArray),
                new JArray(),
                new GlobalConfig.JSONBlobConverter(),
                null,
                ConfigurationPropertyOptions.None);

            public KeybindSection()
            {
                _Properties = new ConfigurationPropertyCollection();
                _Properties.Add(_keybindJSON);
            }

            protected override object GetRuntimeObject() => base.GetRuntimeObject();
            protected override ConfigurationPropertyCollection Properties => _Properties;

            public JArray CustomKeybinds
            {
                get => (JArray)this["CustomKeybinds"];
                set
                {
                    this["CustomKeybinds"] = value;
                }
            }
        }


        public sealed class RecentPathSection : ConfigurationSection
        {
            private static ConfigurationPropertyCollection _Properties;
            private static readonly ConfigurationProperty _recentPathJSON = new ConfigurationProperty(
                "RecentPaths",
                typeof(JObject),
                new JObject(),
                new GlobalConfig.JSONBlobConverter(),
                null,
                ConfigurationPropertyOptions.None);

            public RecentPathSection()
            {
                _Properties = new ConfigurationPropertyCollection();
                _Properties.Add(_recentPathJSON);
            }

            protected override object GetRuntimeObject() => base.GetRuntimeObject();
            protected override ConfigurationPropertyCollection Properties => _Properties;

            public JObject RecentPaths
            {
                get => (JObject)this["RecentPaths"];
                set { this["RecentPaths"] = value; }
            }
        }

        public sealed class RecentAddressesSection : ConfigurationSection
        {

            private static ConfigurationPropertyCollection _Properties;
            private static readonly ConfigurationProperty _addrJSON = new ConfigurationProperty(
                name: "RecentAddresses",
                type: typeof(JArray),
                defaultValue: new JArray(),
                typeConverter: new GlobalConfig.JSONBlobConverter(),
                validator: null,
                options: ConfigurationPropertyOptions.None);

            public RecentAddressesSection()
            {
                _Properties = new ConfigurationPropertyCollection();
                _Properties.Add(_addrJSON);
            }

            protected override object GetRuntimeObject() => base.GetRuntimeObject();
            protected override ConfigurationPropertyCollection Properties => _Properties;

            public JArray RecentAddresses
            {
                get => (JArray)this["RecentAddresses"];
                set { this["RecentAddresses"] = value; }
            }
        }


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
         * Launch config derived from command line arguments/defaults
         */
        public static Config.LaunchConfig StartOptions;

        /* 
         * Rendering config 
         */
        /// <summary>
        ///  Delay between rendering each preview trace (collection of threads)
        /// </summary>
        public static uint Preview_PerProcessLoopSleepMS = 25;
        /// <summary>
        /// Delay between preview rendering each thread in a trace
        /// </summary>
        public static uint Preview_PerThreadLoopSleepMS = 0;
        /// <summary>
        /// Maximum number of edges to plot for each round of preview
        /// graph plotting. This is CPU bound so shoudl be limited to ensure each graph gets
        /// a turn
        /// </summary>
        public static uint Preview_EdgesPerRender = 60;

        /// <summary>
        /// Amount of alpha to reduce fading item by each frame
        /// </summary>
        public static float animationFadeRate = 0.07f;
        public static int animationLingerFrames = 0; //number of frames before fade begins
        public static float MinimumAlpha = 0.06f;

        /// <summary>
        /// Milliseconds to wait between frames of Main (displayed) Graph rendering
        /// </summary>
        public static int MainGraphRenderDelay = 0;
        /// <summary>
        /// How many items of trace data to use to plot the graph per frame
        /// Lower for interactivity, increase for throughput
        /// </summary>
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

        public static bool ShowNodeMouseoverTooltip = true;

        public static int NodeClumpLimit = 50;
        public static float NodeClumpForce = 880.01f;

        /// <summary>
        /// Toggle use of the GPU computation engine for main/preview graphs
        /// </summary>
        public static bool LayoutAllComputeEnabled = true;
        /// <summary>
        /// Toggle position computation
        /// </summary>
        public static bool LayoutPositionsActive = true;
        /// <summary>
        /// Toggle attribute (animation brightness+size) computation
        /// </summary>
        public static bool LayoutAttribsActive = true;

        /// <summary>
        /// Maximum speed of force-directed nodes. Fast nodes will layout quickly but wobble
        /// in their low energy position
        /// </summary>
        public static float NodeSoftSpeedLimit = 200f;
        public static readonly float NodeHardSpeedLimit = 1000f; //match with value in velocity shader

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
        static readonly object _settingsLock = new object();
        public static string TraceSaveDirectory;
        public static string TestsDirectory;
        public static string PinPath;
        public static string PinToolPath32;
        public static string PinToolPath64;
        public static string DiESigsPath;
        public static string YARARulesDir;
        public static string MediaCapturePath;

        public static int MaxStoredRecentPaths = 10;
        public static Dictionary<string, string> BinaryValidationErrors = new Dictionary<string, string>();
        public static List<Tuple<string, string>> _BinaryValidationErrorCache = new List<Tuple<string, string>>();
        //true => traces we save will be added to recent traces list. false => only ones we load will
        public static bool StoreSavedTracesAsRecent = true;
        public static bool BulkLogging = false;

        public static Dictionary<Tuple<Key, ModifierKeys>, eKeybind> Keybinds = new Dictionary<Tuple<Key, ModifierKeys>, eKeybind>();
        public static Dictionary<eKeybind, Tuple<Key, ModifierKeys>> PrimaryKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
        public static Dictionary<eKeybind, Tuple<Key, ModifierKeys>> AlternateKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
        public static List<Key> ResponsiveKeys = new List<Key>();
        public static List<eKeybind> ResponsiveHeldActions = new List<eKeybind>();

        public static int StatisticsTimeAvgWindow = 10; //how many timing values to store for calculating recent average

        public static bool ScreencapAnimation = true;
        public static bool AlertAnimation = true;
        public static bool DoUpdateCheck = true;
        public static DateTime UpdateLastCheckTime = DateTime.MinValue;
        public static Version UpdateLastCheckVersion = RGAT_VERSION_SEMANTIC;
        public static string UpdateLastChanges = "";


        /*
         * Trace related config
         */

        public static uint TraceBufferSize = 400000;
        //how many bytes back from an instruction to search for a symbol
        public static ulong SymbolSearchDistance = 4096;
        public static int ArgStorageMax = 100;

        public static bool ScanFilesYARA = true;
        public static bool ScanFilesDiE = true;
        public static bool ScanMemoryYARA = true;
        public static bool ScanMemoryDiE = true;

        //~~user customised signature scan locations, to restrict certain signatures to scanning disk/mem/none. non-presence => scan all.~~
        // -> this idea is shelved for the foreseeable future, see https://trello.com/c/ShIWBywy/141-specify-rule-rule-group-exec-conditions-file-mem
        //public static Dictionary<string, eSigScanLocation> SignatureScanLimits = new Dictionary<string, eSigScanLocation>();


        /*
         * Video encoder config
         */
        public static string FFmpegPath = @"";
        public static string VideoCodec_Speed = "Medium";
        public static int VideoCodec_Quality = 6;
        public static double VideoCodec_FPS = 30;
        public static string VideoCodec_Content = "Graph";
        public static string ImageCapture_Format = "PNG";

        /*
         * Remote Tracing Config
         */
        public static string DefaultHeadlessAddress = "";
        public static int DefaultListenPort = -1;
        public static string DefaultNetworkKey = "";
        public static string DefaultListenModeIF = "";
        public static string DefaultConnectModeIF = "";
        public static List<string> _recentConnectedAddresses = new List<string>();
        public static List<string> RecentConnectedAddresses()
        {
            lock (_settingsLock)
            {
                return _recentConnectedAddresses.ToList();
            }
        }

        public static void RecordRecentConnectAddress(string address)
        {
            lock (_settingsLock)
            {
                _recentConnectedAddresses.Remove(address);
                _recentConnectedAddresses.Insert(0, address);
                if (_recentConnectedAddresses.Count > 6)
                    _recentConnectedAddresses.RemoveRange(5, _recentConnectedAddresses.Count - 1);

                var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                RecentAddressesSection sec = (RecentAddressesSection)configFile.GetSection("RecentAddresses");

                if (sec == null)
                {
                    sec = new RecentAddressesSection();
                    sec.RecentAddresses = new JArray();
                    configFile.Sections.Add("RecentAddresses", sec);
                }

                sec.RecentAddresses.Clear();

                foreach (string item in _recentConnectedAddresses)
                {
                    sec.RecentAddresses.Add(item);
                }
                sec.SectionInformation.ForceSave = true;
                configFile.Save();
            }
        }

        static void LoadRecentAddresses()
        {
            lock (_settingsLock)
            {
                List<string> result = new List<string>();
                try
                {
                    var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                    RecentAddressesSection sec = (RecentAddressesSection)configFile.GetSection("RecentAddresses");
                    if (sec != null && sec.RecentAddresses.Type == JTokenType.Array)
                    {
                        foreach (JToken entry in sec.RecentAddresses.ToObject<JArray>())
                        {
                            if (entry.Type != JTokenType.String) continue;
                            string address = entry.ToString();
                            result.Add(address);
                        }
                    }
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Error loading recent addresses: {e.Message}", Logging.LogFilterType.TextError);
                }
                _recentConnectedAddresses = result;
            }
        }

        /*
         * Keybinds config
         */
        public static void InitDefaultKeybinds()
        {

            SetKeybind(action: eKeybind.MoveUp, bindIndex: 1, Key.W, ModifierKeys.None);
            SetKeybind(action: eKeybind.MoveUp, bindIndex: 2, Key.Up, ModifierKeys.None);
            SetKeybind(action: eKeybind.MoveDown, bindIndex: 1, Key.S, ModifierKeys.None);
            SetKeybind(action: eKeybind.MoveDown, bindIndex: 2, Key.Down, ModifierKeys.None);
            SetKeybind(action: eKeybind.MoveLeft, bindIndex: 1, Key.A, ModifierKeys.None);
            SetKeybind(action: eKeybind.MoveLeft, bindIndex: 2, Key.Left, ModifierKeys.None);
            SetKeybind(action: eKeybind.MoveRight, bindIndex: 1, Key.D, ModifierKeys.None);
            SetKeybind(action: eKeybind.MoveRight, bindIndex: 2, Key.Right, ModifierKeys.None);

            SetKeybind(action: eKeybind.PitchXFwd, bindIndex: 1, Key.PageUp, ModifierKeys.None);
            SetKeybind(action: eKeybind.PitchXBack, bindIndex: 1, Key.PageDown, ModifierKeys.None);
            SetKeybind(action: eKeybind.YawYLeft, bindIndex: 1, Key.Delete, ModifierKeys.None);
            SetKeybind(action: eKeybind.YawYRight, bindIndex: 1, Key.End, ModifierKeys.None);
            SetKeybind(action: eKeybind.RollGraphZAnti, bindIndex: 1, Key.Insert, ModifierKeys.None);
            SetKeybind(action: eKeybind.RollGraphZClock, bindIndex: 1, Key.Home, ModifierKeys.None);

            SetKeybind(action: eKeybind.Cancel, bindIndex: 1, Key.Escape, ModifierKeys.None);
            SetKeybind(action: eKeybind.CenterFrame, bindIndex: 1, Key.Q, ModifierKeys.None);
            SetKeybind(action: eKeybind.LockCenterFrame, bindIndex: 1, Key.Q, ModifierKeys.Shift);
            SetKeybind(action: eKeybind.RaiseForceTemperature, bindIndex: 1, Key.V, ModifierKeys.None);
            SetKeybind(action: eKeybind.ToggleHeatmap, bindIndex: 1, Key.X, ModifierKeys.None);
            SetKeybind(action: eKeybind.ToggleConditionals, bindIndex: 1, Key.C, ModifierKeys.None);

            SetKeybind(action: eKeybind.ToggleAllText, bindIndex: 1, Key.I, ModifierKeys.None);
            SetKeybind(action: eKeybind.ToggleInsText, bindIndex: 1, Key.I, ModifierKeys.Shift);
            SetKeybind(action: eKeybind.ToggleLiveText, bindIndex: 1, Key.I, ModifierKeys.Control);
            SetKeybind(action: eKeybind.QuickMenu, bindIndex: 1, Key.M, ModifierKeys.None);

            SetKeybind(action: eKeybind.CaptureWindowImage, bindIndex: 1, Key.P, ModifierKeys.None);
            SetKeybind(action: eKeybind.CaptureGraphImage, bindIndex: 1, Key.P, ModifierKeys.Shift);
            SetKeybind(action: eKeybind.CaptureGraphPreviewImage, bindIndex: 1, Key.P, ModifierKeys.Control);
        }



        static void LoadCustomKeybinds()
        {
            try
            {
                var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                KeybindSection sec = (KeybindSection)configFile.GetSection("CustomKeybinds");
                if (sec != null)
                {
                    JArray keybinds = sec.CustomKeybinds;
                    foreach (var bindTok in keybinds)
                    {
                        if (bindTok.Type != JTokenType.Object)
                        {
                            Logging.RecordError("Bad type in loaded user keybinds array");
                            continue;
                        }
                        JObject bindObj = (JObject)bindTok;
                        RestoreCustomKeybind(bindObj);
                    }
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error loading keybinds: {e.Message}");
            }
        }


        static void RestoreCustomKeybind(JObject bindobj)
        {
            string errorString = "";
            bool success = bindobj.TryGetValue("Action", out JToken actionTok) && actionTok.Type == JTokenType.String;
            success &= bindobj.TryGetValue("BindIndex", out JToken indexTok) && indexTok.Type == JTokenType.Integer;
            success &= bindobj.TryGetValue("Key", out JToken keyTok) && keyTok.Type == JTokenType.String;
            success &= bindobj.TryGetValue("Modifiers", out JToken modifierTok) && keyTok.Type == JTokenType.String;

            bool error = !success;
            try
            {
                eKeybind action = (eKeybind)Enum.Parse(typeof(eKeybind), actionTok.ToObject<string>());
                Key key = (Key)Enum.Parse(typeof(Key), keyTok.ToObject<string>());
                int bindIndex = indexTok.ToObject<int>();
                error &= (bindIndex == 1 || bindIndex == 2);
                ModifierKeys mods = (ModifierKeys)Enum.Parse(typeof(ModifierKeys), modifierTok.ToObject<string>());
                SetKeybind(action, bindIndex, key, mods);
            }
            catch (Exception e)
            {
                error = true;
                errorString = e.Message;
            }

            if (error)
            {
                Logging.RecordError($"Error loading keybind {bindobj}: {errorString}");
            }
        }


        public static void StoreCustomKeybind(eKeybind action, int bindIndex, Key k, ModifierKeys mod)
        {
            JObject bindObj = new JObject();
            bindObj.Add("Action", action.ToString());
            bindObj.Add("BindIndex", bindIndex);
            bindObj.Add("Key", k.ToString());
            bindObj.Add("Modifiers", mod.ToString());

            var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            KeybindSection sec = (KeybindSection)configFile.GetSection("CustomKeybinds");
            JArray secarr;
            if (sec == null)
            {
                sec = new KeybindSection();
                secarr = new JArray();
                configFile.Sections.Add("CustomKeybinds", sec);
            }
            else
            {
                secarr = sec.CustomKeybinds;
            }
            secarr.Add(bindObj);

            sec.CustomKeybinds = secarr;

            sec.SectionInformation.ForceSave = true;
            configFile.Save();
        }

        public static void ResetKeybinds()
        {
            var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            KeybindSection sec = (KeybindSection)configFile.GetSection("CustomKeybinds");
            if (sec == null)
            {
                sec = new KeybindSection();
                configFile.Sections.Add("CustomKeybinds", sec);
            }

            sec.CustomKeybinds = new JArray();
            sec.SectionInformation.ForceSave = true;
            configFile.Save();

            PrimaryKeybinds.Clear();
            AlternateKeybinds.Clear();
            InitDefaultKeybinds();
            InitResponsiveKeys();
        }



        static void LoadUpdateDetails()
        {
            try
            {
                if (GetAppSetting("UpdateLastTime", out string updTime))
                {
                    if (DateTime.TryParse(updTime, out UpdateLastCheckTime) && UpdateLastCheckTime != DateTime.MinValue)
                    {
                        if (GetAppSetting("UpdateLastVersion", out string verString))
                        {
                            UpdateLastCheckVersion = new Version(verString);
                            //if (UpdateLastCheckVersion == RGAT_CONSTANTS.RGAT_VERSION_SEMANTIC) return; //todo uncomment after dev
                            if (GetAppSetting("UpdateLastChanges", out string updateLastChangesb64))
                            {
                                NewVersionAvailable = UpdateLastCheckVersion > RGAT_CONSTANTS.RGAT_VERSION_SEMANTIC;
                                UpdateLastChanges = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(updateLastChangesb64));
                                return;
                            }
                            else
                            {
                                Logging.RecordLogEvent("No UpdateLastChanges string for last fetch update", Logging.LogFilterType.TextDebug);
                            }
                        }
                    }
                }
                UpdateLastChanges = null;
                UpdateLastCheckVersion = null;
                UpdateLastCheckTime = DateTime.MinValue;
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error loading recent updates: {e.Message}");
            }
        }

        public static bool NewVersionAvailable = false;
        public static void RecordAvailableUpdateDetails(Version releaseVersion, string releaseCumulativeChanges)
        {
            try
            {
                lock (_settingsLock)
                {
                    UpdateLastCheckTime = DateTime.Now;
                    UpdateLastCheckVersion = releaseVersion;
                    UpdateLastChanges = releaseCumulativeChanges;

                    AddUpdateAppSettings("UpdateLastTime", UpdateLastCheckTime.ToString());
                    AddUpdateAppSettings("UpdateLastVersion", UpdateLastCheckVersion.ToString());
                    AddUpdateAppSettings("UpdateLastChanges", Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(releaseCumulativeChanges)));
                    NewVersionAvailable = UpdateLastCheckVersion > RGAT_CONSTANTS.RGAT_VERSION_SEMANTIC;
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error loading recent updates: {e.Message}");
            }
        }




        public struct CachedPathData
        {
            public string path;
            public DateTime firstSeen;
            public DateTime lastSeen;
            public uint count;
        }

        public enum eRecentPathType { Binary, Trace, Directory };
        static List<CachedPathData> _cachedRecentBins = new List<CachedPathData>();
        static List<CachedPathData> _cachedRecentTraces = new List<CachedPathData>();
        static List<CachedPathData> _cachedRecentDirectories = new List<CachedPathData>();

        public static CachedPathData[] RecentTraces
        {
            get
            {
                lock (_settingsLock) { return _cachedRecentTraces.ToArray(); }
            }
        }
        public static CachedPathData[] RecentBinaries
        {
            get
            {
                lock (_settingsLock) { return _cachedRecentBins.ToArray(); }
            }
        }
        public static CachedPathData[] RecentDirectories
        {
            get
            {
                lock (_settingsLock) { return _cachedRecentDirectories.ToArray(); }
            }
        }


        static List<CachedPathData> LoadRecentPaths(string pathType)
        {
            List<CachedPathData> result = new List<CachedPathData>();
            try
            {
                var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                RecentPathSection sec = (RecentPathSection)configFile.GetSection("RecentPaths");
                if (sec != null && sec.RecentPaths.Type == JTokenType.Object)
                {
                    if (sec.RecentPaths.TryGetValue(pathType, out JToken val) && val.Type == JTokenType.Object)
                    {
                        JObject tracesObj = val.ToObject<JObject>();

                        foreach (var entry in tracesObj)
                        {
                            if (entry.Value.Type != JTokenType.Object) continue;
                            JObject data = (JObject)entry.Value;
                            if (!data.TryGetValue("OpenCount", out JToken ocountTok) || ocountTok.Type != JTokenType.Integer ||
                                !data.TryGetValue("FirstOpen", out JToken firstOpenTok) || firstOpenTok.Type != JTokenType.Date ||
                                !data.TryGetValue("LastOpen", out JToken lastOpenTok) || lastOpenTok.Type != JTokenType.Date)
                                continue;
                            //todo remote
                            if (!File.Exists(entry.Key) && !Directory.Exists(entry.Key)) continue;
                            CachedPathData pd = new CachedPathData
                            {
                                path = entry.Key,
                                firstSeen = firstOpenTok.ToObject<DateTime>(),
                                lastSeen = lastOpenTok.ToObject<DateTime>(),
                                count = ocountTok.ToObject<uint>()
                            };
                            result.Add(pd);
                        }
                    }
                }
                result = result.OrderByDescending(x => x.lastSeen).Take(MaxStoredRecentPaths).ToList();
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error loading recent paths: {e.Message}");
            }
            return result;
        }

        static void RecordRecentPathLocked(string path, eRecentPathType pathType)
        {
            var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            RecentPathSection sec = (RecentPathSection)configFile.GetSection("RecentPaths");
            JObject SectionObj;
            if (sec == null)
            {
                sec = new RecentPathSection();
                SectionObj = new JObject();
                SectionObj.Add("RecentBinaries", new JObject());
                SectionObj.Add("RecentTraces", new JObject());
                SectionObj.Add("RecentDirectories", new JObject());
                sec.RecentPaths = SectionObj;
                configFile.Sections.Add("RecentPaths", sec);
            }
            else
            {
                SectionObj = sec.RecentPaths;
                if (!SectionObj.ContainsKey("RecentBinaries")) SectionObj.Add("RecentBinaries", new JObject());
                if (!SectionObj.ContainsKey("RecentTraces")) SectionObj.Add("RecentTraces", new JObject());
                if (!SectionObj.ContainsKey("RecentDirectories")) SectionObj.Add("RecentDirectories", new JObject());
            }

            try
            {
                List<CachedPathData> targetList = new List<CachedPathData>();
                string sectionTarget;
                switch (pathType)
                {
                    case eRecentPathType.Binary:
                        sectionTarget = "RecentBinaries";
                        break;
                    case eRecentPathType.Directory:
                        sectionTarget = "RecentDirectories";
                        break;
                    case eRecentPathType.Trace:
                        sectionTarget = "RecentTraces";
                        break;
                    default:
                        throw new InvalidEnumArgumentException("Bad recent path: " + pathType);
                }

                JObject targetObj = (JObject)SectionObj[sectionTarget];
                if (targetObj.TryGetValue(path, out JToken ExistingTok) && ExistingTok.Type == JTokenType.Object)
                {
                    JObject ExistingPathObj = ExistingTok.ToObject<JObject>();
                    if (ExistingPathObj.TryGetValue("OpenCount", out JToken countTok) && countTok.Type == JTokenType.Integer)
                    {
                        ExistingPathObj["OpenCount"] = countTok.ToObject<uint>() + 1;
                    }
                    ExistingPathObj["LastOpen"] = DateTime.Now;
                    targetObj[path] = ExistingPathObj;
                }
                else
                {
                    JObject NewPathObj = new JObject();
                    NewPathObj.Add("OpenCount", 1);
                    NewPathObj.Add("FirstOpen", DateTime.Now);
                    NewPathObj.Add("LastOpen", DateTime.Now);

                    targetObj.Add(path, NewPathObj);
                    if (targetObj.Count > MaxStoredRecentPaths)
                    {
                        List<Tuple<string, DateTime>> oldestPaths = new List<Tuple<string, DateTime>>();
                        foreach (var recentPath in targetObj)
                        {
                            var x = recentPath.Value;
                            JObject xval = x.ToObject<JObject>();
                            oldestPaths.Add(new Tuple<string, DateTime>(recentPath.Key, xval["LastOpen"].ToObject<DateTime>()));
                        }
                        var excessPaths = oldestPaths.OrderByDescending(x => x.Item2).Skip(MaxStoredRecentPaths);
                        foreach (var pathtime in excessPaths)
                        {
                            targetObj.Remove(pathtime.Item1);
                        }
                    }
                }


                foreach (var recentPath in targetObj)
                {
                    var x = recentPath.Value;
                    JObject xval = x.ToObject<JObject>();
                    var item = new CachedPathData()
                    {
                        count = recentPath.Value["OpenCount"].ToObject<uint>(),
                        firstSeen = recentPath.Value["FirstOpen"].ToObject<DateTime>(),
                        lastSeen = recentPath.Value["LastOpen"].ToObject<DateTime>(),
                        path = recentPath.Key
                    };
                    lock (_settingsLock)
                    {
                        targetList.Add(item);
                        targetList = targetList.OrderByDescending(x => x.lastSeen).ToList();
                    }
                }

                switch (pathType)
                {
                    case eRecentPathType.Binary:
                        _cachedRecentBins = targetList;
                        break;
                    case eRecentPathType.Directory:
                        _cachedRecentDirectories = targetList;
                        break;
                    case eRecentPathType.Trace:
                        _cachedRecentTraces = targetList;
                        break;
                    default:
                        throw new InvalidEnumArgumentException("Bad recent path: " + pathType);
                }
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"exception {e.Message} storing path {pathType} - {path}", Logging.LogFilterType.TextError);
            }


            sec.RecentPaths = SectionObj;
            sec.SectionInformation.ForceSave = true;
            configFile.Save();

            if (pathType != eRecentPathType.Directory)
            {
                try
                {
                    RecordRecentPath(Path.GetDirectoryName(path), eRecentPathType.Directory);
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Failed to record recent directory containing {path}: {e.Message}");
                }
            }
        }



        public static void RecordRecentPath(string path, eRecentPathType pathType)
        {
            lock (_settingsLock)
            {
                RecordRecentPathLocked(path, pathType);
            }
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


        public static void SetKeybind(eKeybind action, int bindIndex, Key k, ModifierKeys mod, bool userSpecified = false)
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

            if (userSpecified)
            {
                StoreCustomKeybind(action: action, bindIndex: bindIndex, k: k, mod: mod);
            }

            //regenerate the keybinds lists
            Keybinds.Clear();
            foreach (var kvp in PrimaryKeybinds) { Keybinds[kvp.Value] = kvp.Key; }
            foreach (var kvp in AlternateKeybinds) { Keybinds[kvp.Value] = kvp.Key; }

            ResponsiveKeys = Keybinds.Where(x => ResponsiveHeldActions.Contains(x.Value)).Select(x => x.Key.Item1).ToList();
        }

        public static Dictionary<string, string> LoadedStringResources = new Dictionary<string, string>();


        //https://docs.microsoft.com/en-us/dotnet/api/system.configuration.configurationmanager.appsettings?view=netcore-3.1
        public static void AddUpdateAppSettings(string key, string value)
        {
            try
            {
                var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                var settings = configFile.AppSettings.Settings;
                if (settings[key] == null)
                {
                    settings.Add(key, value);
                }
                else
                {
                    settings[key].Value = value;
                }
                configFile.Save(ConfigurationSaveMode.Modified);
                ConfigurationManager.RefreshSection(configFile.AppSettings.SectionInformation.Name);
            }
            catch (ConfigurationErrorsException e)
            {
                Logging.RecordLogEvent($"Error writing app setting {key}: {e.Message}");
            }
        }


        public static bool GetAppSetting(string key, out string value)
        {
            try
            {

                var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.PerUserRoamingAndLocal);

                var settings = configFile.AppSettings.Settings;
                if (settings[key] != null)
                {
                    value = settings[key].Value;
                    return true;
                }
            }
            catch (ConfigurationErrorsException e)
            {
                Logging.RecordLogEvent($"Error getting app setting {key}: {e.Message}", Logging.LogFilterType.TextError);
            }
            value = null;
            return false;
        }


        public static void LoadResources()
        {
            Logging.RecordLogEvent($"Loading Resources", Logging.LogFilterType.TextDebug);

            System.Reflection.Assembly assembly = typeof(ImGuiController).Assembly;
            System.IO.Stream fs = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames()[0]);
            System.Resources.ResourceReader r = new System.Resources.ResourceReader(fs);
            System.Collections.IDictionaryEnumerator dict = r.GetEnumerator();

            while (dict.MoveNext())
            {
                Logging.RecordLogEvent($"Loading Resource " + dict.Key.ToString(), Logging.LogFilterType.TextDebug);
                if (dict.Key.ToString() == "BuiltinJSONThemes")
                {
                    string themesjsn = (string)dict.Value.ToString();

                    try
                    {
                        Themes.LoadPresetThemes(Newtonsoft.Json.Linq.JArray.Parse(themesjsn));
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Exception loading builtin themes: {e.Message}");
                    }
                }
            }
        }


        public static string GetStorageDirectoryPath(string name)
        {
            List<string> candidates = new List<string>() {
                    AppContext.BaseDirectory,
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "rgat"),
                    Directory.GetCurrentDirectory()
                };
            foreach (string dir in candidates)
            {
                string candidate = Path.Combine(dir, name);
                if (Directory.Exists(candidate))
                {
                    return candidate;
                }
            }
            foreach (string dir in candidates)
            {
                if (!Directory.Exists(dir))
                {
                    //this is for creating an rgat dir in the application data dir
                    try
                    {
                        Directory.CreateDirectory(dir);
                    }
                    catch
                    {
                        continue;
                    }
                    if (!Directory.Exists(dir)) continue;
                }
                string candidate = Path.Combine(dir, name);
                try
                {
                    Directory.CreateDirectory(candidate);
                    if (Directory.Exists(candidate)) return candidate;
                }
                catch
                {
                    continue;
                }
            }
            return "";
        }


        public static bool BadSigners(out List<Tuple<string, string>> errors)
        {
            lock (_settingsLock)
            {
                if (_BinaryValidationErrorCache.Any())
                {
                    errors = _BinaryValidationErrorCache.ToList();
                    return true;
                }
            }
            errors = null;
            return false;
        }


        static bool VerifyCertificate(string path, string expectedSigner, out string error, out string warning)
        {
            error = null;
            warning = null;

            try
            {
                X509Certificate signer = X509Certificate.CreateFromSignedFile(path);
                if (!signer.Issuer.Contains($"O={expectedSigner},"))
                {
                    error = "Unexpected signer " + signer.Issuer;
                    return false;
                }

                X509Certificate2 certificate = new X509Certificate2(signer);
                if (certificate.NotBefore > DateTime.Now)
                {
                    DateTime limit = certificate.NotBefore;
                    warning = $"Signature Validity Starts {limit.ToLongDateString() + " " + limit.ToLongTimeString()} ({limit.Humanize()})";
                    return true;
                }
                if (certificate.NotAfter < DateTime.Now)
                {
                    DateTime limit = certificate.NotAfter;
                    warning = $"Signature Validity Ended {limit.ToLongDateString() + " " + limit.ToLongTimeString()} ({limit.Humanize()})";
                    return true; //the pin.exe cert has expired at the time of writing, not worth alerting about
                }

                var certificateChain = new X509Chain
                {
                    ChainPolicy = {
                        RevocationFlag = X509RevocationFlag.EntireChain,
                        RevocationMode = X509RevocationMode.Online,
                        UrlRetrievalTimeout = new TimeSpan(0, 1, 0),
                        VerificationFlags = X509VerificationFlags.NoFlag}
                };

                if (!certificateChain.Build(certificate))
                {
                    error = "Unverifiable signature";
                    return false;
                }
                error = "Success";
                return true;
            }
            catch (Exception e)
            {
                if (e.Message == "Cannot find the requested object.")
                {
                    error = "File is not signed";
                }
                else
                {
                    error = "Exception verifying certificate: " + e.Message;
                }
                return false;
            }
        }



        static void InitPaths()
        {
            //directories
            if (GetAppSetting("TraceSaveDirectory", out string tracedir) && Directory.Exists(tracedir))
            {
                TraceSaveDirectory = tracedir;
            }
            else
            {
                TraceSaveDirectory = GetStorageDirectoryPath("traces");
                if (!Directory.Exists(TraceSaveDirectory))
                {
                    Logging.RecordError("Warning: Failed to load an existing trace storage path");
                }
                else
                {
                    AddUpdateAppSettings("TraceSaveDirectory", TraceSaveDirectory);
                }
            }


            if (GetAppSetting("TestsDirectory", out string testsdir) && Directory.Exists(testsdir))
            {
                TestsDirectory = testsdir;
            }
            else
            {
                TestsDirectory = GetStorageDirectoryPath("tests");
                if (!Directory.Exists(TestsDirectory))
                {
                    Logging.RecordLogEvent("No tests path, can't enable tests");
                }
                else
                {
                    AddUpdateAppSettings("TestsDirectory", TestsDirectory);
                }
            }

            if (GetAppSetting("DiESigsPath", out string diedbpath) && Directory.Exists(diedbpath))
            {
                DiESigsPath = diedbpath;
            }
            else
            {
                DiESigsPath = GetStorageDirectoryPath("signatures\\detectiteasy");
                if (Directory.Exists(DiESigsPath))
                {
                    AddUpdateAppSettings("DiESigsPath", DiESigsPath);
                }
                else
                {
                    Logging.RecordLogEvent("No Detect-It-Easy scripts directory configured. Configure this in the Settings->File pane to enable these scans.");
                }

            }

            if (GetAppSetting("YaraRulesPath", out string yaradbpath) && Directory.Exists(yaradbpath))
            {
                YARARulesDir = yaradbpath;
            }
            else
            {
                YARARulesDir = GetStorageDirectoryPath("signatures\\yara");
                if (Directory.Exists(YARARulesDir))
                {
                    AddUpdateAppSettings("YaraRulesPath", YARARulesDir);
                }
                else
                {
                    Logging.RecordLogEvent("No YARA rules directory was configured. Configure this in the Settings->File pane to enable these scans.");
                }
            }

            //binaries


            if (GetAppSetting("PinPath", out string pinexe) && File.Exists(pinexe))
            {
                SetBinaryPath("PinPath", pinexe, save: false);
            }
            else
            {
                List<string> pindirs = Directory.GetDirectories(AppContext.BaseDirectory)
                    .Where(dir => Path.GetFileName(dir).StartsWith("pin"))
                    .ToList();
                foreach (string dir in pindirs)
                {
                    string candidate = Path.Combine(dir, "pin.exe");
                    if (File.Exists(candidate))
                    {
                        SetBinaryPath("PinPath", pinexe, save: true);
                        break;
                    }
                }
            }

            if (GetAppSetting("PinToolPath32", out string pintool32) && File.Exists(pintool32))
            {
                SetBinaryPath("PinToolPath32", pintool32, save: false);
            }
            else
            {
                string candidate = Path.Combine(AppContext.BaseDirectory, "pingat32.dll");
                if (File.Exists(candidate))
                {
                    SetBinaryPath("PinToolPath32", candidate, save: true);
                }
            }


            if (GetAppSetting("PinToolPath64", out string pintool64) && File.Exists(pintool64))
            {
                SetBinaryPath("PinToolPath64", pintool64, save: false);
            }
            else
            {
                string candidate = Path.Combine(AppContext.BaseDirectory, "pingat64.dll");
                if (File.Exists(candidate))
                {
                    SetBinaryPath("PinToolPath64", candidate, save: true);
                }
            }

            if (GetAppSetting("FFmpegPath", out string ffmpegbinary) && File.Exists(ffmpegbinary))
            {
                SetBinaryPath("FFmpegPath", ffmpegbinary, save: false);
            }
        }

        public static void SetDirectoryPath(string setting, string path, bool save = true)
        {
            switch (setting)
            {
                case "TraceSaveDirectory":
                    TraceSaveDirectory = path;
                    break;
                case "TestsDirectory":
                    TestsDirectory = path;
                    break;
                case "DiESigsPath":
                    DiESigsPath = path;
                    break;
                case "YaraRulesPath":
                    YARARulesDir = path;
                    break;
                case "MediaCapturePath":
                    MediaCapturePath = path;
                    break;
                default:
                    Logging.RecordLogEvent($"Bad nonbinary path setting: {setting} => {path}", Logging.LogFilterType.TextError);
                    return;
            }
            if (save)
            {
                AddUpdateAppSettings(setting, path);
            }
        }

        public static bool SetBinaryPath(string setting, string path, bool save = true)
        {
            bool validSignature = false;
            if (setting == "PinPath")
            {
                if (VerifyCertificate(path, SIGNERS.PIN_SIGNER, out string error, out string warning))
                {
                    Logging.RecordLogEvent($"Binary signature validation warning for {path}: {warning}");
                    validSignature = true;
                }
                else
                {
                    Logging.RecordError($"Binary signature validation failed for {path}: {error}");
                    lock (_settingsLock) { BinaryValidationErrors[path] = error; }
                }
                PinPath = path;
            }
            if (setting == "PinToolPath32")
            {
                if (VerifyCertificate(path, SIGNERS.PINTOOL_SIGNER, out string error, out string warning))
                {
                    Logging.RecordLogEvent($"Binary signature validation warning for {path}: {warning}");
                    validSignature = true;
                }
                else
                {
                    Logging.RecordError($"Binary signature validation failed for {path}: {error}");
                    lock (_settingsLock) { BinaryValidationErrors[path] = error; }
                }
                PinToolPath32 = path;
            }
            if (setting == "PinToolPath64")
            {
                if (VerifyCertificate(path, SIGNERS.PINTOOL_SIGNER, out string error, out string warning))
                {
                    Logging.RecordLogEvent($"Binary signature validation warning for {path}: {warning}");
                    validSignature = true;
                }
                else
                {
                    Logging.RecordError($"Binary signature validation failed for {path}: {error}");
                    lock (_settingsLock) { BinaryValidationErrors[path] = error; }
                }
                PinToolPath64 = path;
            }
            if (setting == "FFmpegPath")
            {
                FFmpegPath = path;
            }


            if (save)
            {
                AddUpdateAppSettings(setting, path);
            }

            if (!validSignature)
            {
                lock (_settingsLock)
                {
                    if (BinaryValidationErrors.Any())
                    {
                        _BinaryValidationErrorCache = BinaryValidationErrors.Select(kvp => new Tuple<string, string>(kvp.Key, kvp.Value)).ToList();
                    }
                }
                return false;
            }


            return true;
        }

        public static bool CheckSignatureError(string path, out string error, out bool timeWarning)
        {
            timeWarning = false;
            if (GlobalConfig.BadSigners(out List<Tuple<string, string>> signerErrors))
            {
                foreach (var val in signerErrors)
                {
                    if (val.Item1 == path)
                    {
                        if (val.Item2.StartsWith("Signature Validity"))
                        {
                            error = val.Item2;
                            timeWarning = true;
                            return false;
                        }
                        else
                        {
                            error = val.Item2;
                            return false;
                        }
                        break;
                    }
                }
            }

            error = "No Error";
            return true;
        }


        static void LoadSettings()
        {
            //logging
            if (GetAppSetting("BulkLogging", out string bulklogging))
            {
                BulkLogging = (bulklogging.ToLower() == "true");
            }

            if (GetAppSetting("ScreencapAnimation", out string animScreencap))
            {
                ScreencapAnimation = (animScreencap.ToLower() == "true");
            }

            if (GetAppSetting("AlertAnimation", out string animAlert))
            {
                AlertAnimation = (animAlert.ToLower() == "true");
            }

            //rendering
            if (GetAppSetting("MinimumGraphAlpha", out string minalpha))
            {
                if (!float.TryParse(minalpha, out MinimumAlpha))
                {
                    MinimumAlpha = 0.06f;
                }
            }

            // video encoding settings

            if (GetAppSetting("VideoCodec_Speed", out string vidspeed))
            {
                VideoCodec_Speed = vidspeed;
            }
            if (GetAppSetting("VideoCodec_Quality", out string vid1))
            {
                int.TryParse(vid1, out VideoCodec_Quality);
            }
            if (GetAppSetting("VideoCodec_FPS", out vid1))
            {
                double.TryParse(vid1, out VideoCodec_FPS);
            }
            if (GetAppSetting("VideoCodec_Content", out string content) && content.Length > 0)
            {
                VideoCodec_Content = content.Humanize(LetterCasing.Sentence);
            }
            if (GetAppSetting("ImageCapture_Format", out string imageformat) && imageformat.Length > 0)
            {
                ImageCapture_Format = imageformat.ToUpper();
            }

            //remote tracing

            if (GetAppSetting("DefaultNetworkKey", out string netkey) && netkey.Length > 0)
            {
                DefaultNetworkKey = netkey;
            }
            if (GetAppSetting("DefaultHeadlessAddress", out string conaddr) && conaddr.Length > 0)
            {
                DefaultHeadlessAddress = conaddr;
            }
            if (GetAppSetting("DefaultListenPort", out string defaultport) && defaultport.Length > 0)
            {
                int.TryParse(defaultport, out DefaultListenPort);
            }
            GetAppSetting("DefaultListenModeIF", out DefaultListenModeIF);
            GetAppSetting("DefaultConnectModeIF", out DefaultConnectModeIF);

            // updates
            if (GetAppSetting("DoUpdateCheck", out string updateState))
            {
                DoUpdateCheck = (updateState.ToLower() == "true");
            }

        }

        static void LoadTextSettingsColours()
        {
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

        public static double LoadProgress { get; private set; } = 0;


        public static void LoadConfig(IProgress<float> progress)
        {
            System.Diagnostics.Stopwatch timer = new System.Diagnostics.Stopwatch();
            timer.Start();

            LoadResources();
            progress?.Report(0.3f);

            try
            {
                LoadSettings();
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Exception loading settings: {e.Message}", Logging.LogFilterType.TextError);
            }

            try
            {
                Themes.LoadCustomThemes();
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Error loading custom themes: {e.Message}", Logging.LogFilterType.TextError);
            }
            Themes.ActivateDefaultTheme();
            progress?.Report(0.5f);

            //load base keybinds
            InitDefaultKeybinds();
            InitResponsiveKeys();

            //overwrite with any user configured binds

            LoadCustomKeybinds();

            progress?.Report(0.7f);

            InitPaths();
            var recentTraces = LoadRecentPaths("RecentTraces");
            var recentBins = LoadRecentPaths("RecentBinaries");
            var recentDirectories = LoadRecentPaths("RecentDirectories");

            lock (_settingsLock)
            {
                _cachedRecentTraces = recentTraces;
                _cachedRecentBins = recentBins;
                _cachedRecentDirectories = recentDirectories;
            }
            LoadRecentAddresses();

            progress?.Report(0.9f);

            LoadTextSettingsColours();
            LoadUpdateDetails();

            Logging.RecordLogEvent($"Startup: Config loaded in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Stop();
            progress?.Report(1f);
        }
    }
}
