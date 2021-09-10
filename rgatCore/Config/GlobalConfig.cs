using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.IO;
using System.Text.Json;
using System.Linq;
using Veldrid;
using static rgat.RGAT_CONSTANTS;
using rgat.Config;
using System.Security.Cryptography.X509Certificates;
using Humanizer;

namespace rgat
{
    public partial class GlobalConfig
    {

        /// <summary>
        /// Checks that a binary has a valid code signing certificate issued to one of the expected subject names
        /// </summary>
        /// <param name="path">Path of binary to be tested</param>
        /// <param name="expectedSigners">Comma seperated list of valid certificate subject names</param>
        /// <param name="error">Errors encountered in validating the certificate (no or invalid signer)</param>
        /// <param name="warning">Warnings encountered validating the certificate (time issues)</param>
        /// <returns>Whether the certificate was valid. Expired/Not yet valid certs will return true with the warning field set</returns>
        public static bool VerifyCertificate(string path, string expectedSigners, out string error, out string warning)
        {
            error = null;
            warning = null;

            try
            {
                X509Certificate signer = X509Certificate.CreateFromSignedFile(path);

                bool hasValidSigner = expectedSigners.Split(',').Any(validSigner => signer.Subject.ToLower().Contains($"O={validSigner},".ToLower()));
                if (!hasValidSigner)
                {
                    error = "Unexpected signer " + signer.Subject;
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
                    return true;
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

        public static bool NewVersionAvailable = false;
        public static void RecordAvailableUpdateDetails(Version releaseVersion, string releaseCumulativeChanges, string downloadLink)
        {
            try
            {
                Settings.Updates.UpdateLastCheckVersion = releaseVersion;
                Settings.Updates.UpdateLastChanges = releaseCumulativeChanges;
                Settings.Updates.UpdateDownloadLink = downloadLink;
                NewVersionAvailable = Settings.Updates.UpdateLastCheckVersion > RGAT_CONSTANTS.RGAT_VERSION_SEMANTIC;
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error loading recent updates: {e.Message}");
            }
        }




        public static Dictionary<string, string> LoadedStringResources = new Dictionary<string, string>();


        public static void LoadResources()
        {
            Logging.RecordLogEvent($"Loading Resources", Logging.LogFilterType.TextDebug);

            System.Reflection.Assembly assembly = typeof(ImGuiController).Assembly;
            System.IO.Stream fs = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames()[0]);
            System.Resources.ResourceReader r = new System.Resources.ResourceReader(fs);

            r.GetResourceData("BuiltinJSONThemes", out string type, out byte[] themesjsn);
            if (type == "ResourceTypeCode.String" && themesjsn.Length > 0)
            {
                try
                {
                    string preset = System.Text.Encoding.ASCII.GetString(themesjsn, 0, themesjsn.Length);
                    Themes.LoadPresetThemes(Newtonsoft.Json.Linq.JArray.Parse(preset));
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Exception loading builtin themes: {e.Message}");
                }
            }
        }


        public static string GetStorageDirectoryPath(string baseDir, string name)
        {
            List<string> candidates = new List<string>() {
                    baseDir,
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







        static void InitPaths(string baseDir)
        {

            //directories
            if (!Directory.Exists(Settings.ToolPaths.Get("TraceSaveDirectory")))
            {
                string TraceSaveDirectory = GetStorageDirectoryPath(baseDir, "traces");
                if (!Directory.Exists(TraceSaveDirectory))
                {
                    Logging.RecordError("Warning: Failed to load an existing trace storage path");
                }
                else
                {
                    Settings.ToolPaths.SetDirectoryPath("TraceSaveDirectory", TraceSaveDirectory);
                }
            }


            if (!Directory.Exists(Settings.ToolPaths.Get("TestsDirectory")))
            {
                string TestsDirectory = GetStorageDirectoryPath(baseDir, "tests");
                if (!Directory.Exists(TestsDirectory))
                {
                    Logging.RecordLogEvent("No tests directory configured, can't enable tests");
                }
                else
                {
                    Settings.ToolPaths.SetDirectoryPath("TestsDirectory", TestsDirectory);
                }
            }

            if (!Directory.Exists(Settings.ToolPaths.Get("DiESigsDirectory")))
            {
                string DiESigsDirectory = GetStorageDirectoryPath(baseDir, "signatures\\detectiteasy");
                if (Directory.Exists(DiESigsDirectory))
                {
                    Settings.ToolPaths.SetDirectoryPath("DiESigsDirectory", DiESigsDirectory);
                }
                else
                {
                    Logging.RecordLogEvent("No Detect-It-Easy scripts directory configured. Configure this in the Settings->File pane to enable these scans.");
                }

            }

            if (!Directory.Exists(Settings.ToolPaths.Get("YaraRulesDirectory")))
            {
                string YaraRulesDirectory = GetStorageDirectoryPath(baseDir, "signatures\\yara");
                if (Directory.Exists(YaraRulesDirectory))
                {
                    Settings.ToolPaths.SetDirectoryPath("YaraRulesDirectory", YaraRulesDirectory);
                }
                else
                {
                    Logging.RecordLogEvent("No YARA rules directory was configured. Configure this in the Settings->File pane to enable these scans.");
                }
            }

            //binaries
            if (!File.Exists(Settings.ToolPaths.Get("PinPath")))
            {
                List<string> pindirs = Directory.GetDirectories(AppContext.BaseDirectory)
                    .Where(dir => Path.GetFileName(dir).StartsWith("pin"))
                    .ToList();
                foreach (string dir in pindirs)
                {
                    string candidate = Path.Combine(dir, "pin.exe");
                    if (File.Exists(candidate))
                    {
                        if(Settings.ToolPaths.SetBinaryPath("PinPath", candidate))                        
                            break;
                    }
                }
            }

            if (!File.Exists(Settings.ToolPaths.Get("PinToolPath32")))
            {
                string candidate = Path.Combine(AppContext.BaseDirectory, "pingat32.dll");
                if (File.Exists(candidate)) //todo sigcheck. also maybe load from resource first
                {
                    SetBinaryPath("PinToolPath32", candidate);
                }
            }            
            
            if (!File.Exists(Settings.ToolPaths.Get("PinToolPath64")))
            {
                string candidate = Path.Combine(AppContext.BaseDirectory, "pingat64.dll");
                if (File.Exists(candidate)) //todo sigcheck. also maybe load from resource first
                {
                    SetBinaryPath("PinToolPath64", candidate);
                }
            }
        }



        public static bool PreviousSignatureCheckPassed(string path, out string error, out bool timeWarning)
        {
            timeWarning = false;
            if (Settings.ToolPaths.BadSigners(out List<Tuple<string, string>> signerErrors))
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


        static bool _dirtyConfig = false;
        static System.Timers.Timer _saveTimer = new System.Timers.Timer(800);
        static void SaveConfigTimerElapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            lock (_settingsLock)
            {
                if (_dirtyConfig)
                {
                    SaveConfig();
                    _dirtyConfig = false;
                }
            }
        }


        static void SaveConfig()
        {
            try
            {
                string path = Settings.FilePath;
                if (File.Exists(path))
                {
                    JsonSerializerOptions serialiseOpts = new JsonSerializerOptions() { WriteIndented = true };
                    string saveText = JsonSerializer.Serialize(Settings, options: serialiseOpts);
                    File.WriteAllText(path, saveText);
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to save config: {e.Message}");
            }
        }


        static void MarkDirty()
        {
            lock (_settingsLock)
            {
                if (!Settings.Inited) return;
                if (!_dirtyConfig)
                {
                    _dirtyConfig = true;
                    _saveTimer.Elapsed += SaveConfigTimerElapsed;
                    _saveTimer.Interval = 800;
                    _saveTimer.Start();
                }
            }
        }




        public static string GetSettingPath(string setting) => Settings.ToolPaths.Get(setting);
        public static void SetBinaryPath(string setting, string value) => Settings.ToolPaths.SetBinaryPath(setting, value);
        public static void SetDirectoryPath(string setting, string value) => Settings.ToolPaths.SetDirectoryPath(setting, value);

        /// <summary>
        /// The main user-settings storage object which is serialised to settings.json
        /// </summary>
        public static rgatSettings Settings = new rgatSettings();


        /// <summary>
        /// UI/App related config
        /// </summary>
        static readonly object _settingsLock = new object();

        /// <summary>
        /// These keys trigger actions that need to be reacted to repeatedly and immediately (mainly graphical actions like rotation)
        /// </summary>
        public static List<Key> ResponsiveKeys = new List<Key>();

        /// <summary>
        /// Keybinds triggered by responsive keys
        /// </summary>
        public static List<eKeybind> ResponsiveHeldActions = new List<eKeybind>();

        /// <summary>
        /// how many frame timing values to store for calculating UI performance statistics
        /// </summary>
        public static int StatisticsTimeAvgWindow = 10;


        /*
         * Trace related config
         */


        public static bool ScanFilesYARA = true;
        public static bool ScanFilesDiE = true;
        public static bool ScanMemoryYARA = true;
        public static bool ScanMemoryDiE = true;

        //~~user customised signature scan locations, to restrict certain signatures to scanning disk/mem/none. non-presence => scan all.~~
        // -> this idea is shelved for the foreseeable future, see https://trello.com/c/ShIWBywy/141-specify-rule-rule-group-exec-conditions-file-mem
        //public static Dictionary<string, eSigScanLocation> SignatureScanLimits = new Dictionary<string, eSigScanLocation>();



        public static void LoadConfig(IProgress<float> progress)
        {
            string baseDir = Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]); //with single executables the AppContext.BaseDirectory value is the temp extract dir
            string settingsPath = Path.Combine(baseDir, "settings.json");
            if (!File.Exists(settingsPath))
            {
                Logging.RecordLogEvent($"{settingsPath} did not exist, creating empty");
                try
                {
                    File.WriteAllText(settingsPath, "{}");
                }
                catch(Exception e)
                {
                    Logging.RecordError($"{settingsPath} could not be created ({e.Message}), creating in temporary directory");
                    try
                    {
                        settingsPath = Path.GetTempFileName();
                        File.WriteAllText(settingsPath, "{}");
                    }
                    catch(Exception e2)
                    {
                        Logging.RecordError($"Temporary settings {settingsPath} could not be created ({e.Message})");
                        return;
                    }
                }
            }
            Console.WriteLine($"Loading config from {settingsPath} {File.Exists(settingsPath)}");

            string settingsContents = File.ReadAllText(settingsPath);
            System.Text.Json.JsonSerializerOptions settingParserOptions = new System.Text.Json.JsonSerializerOptions() { AllowTrailingCommas = true };
            Settings = System.Text.Json.JsonSerializer.Deserialize<rgatSettings>(settingsContents, settingParserOptions);
            Settings.FilePath = settingsPath;
            rgatSettings.SetChangeCallback(MarkDirty);
            Settings.EnsureValidity();


            System.Diagnostics.Stopwatch timer = new System.Diagnostics.Stopwatch();
            timer.Start();

            LoadResources();
            progress?.Report(0.3f);

            lock (_settingsLock)
            {
                Themes.ActivateDefaultTheme();
            }

            progress?.Report(0.5f);

            Settings.Keybinds.ApplyUserKeybinds();

            progress?.Report(0.7f);

            InitPaths(baseDir);

            progress?.Report(0.9f);

            LoadTextSettingsColours();

            Logging.RecordLogEvent($"Startup: Config loaded in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Stop();
            progress?.Report(1f);
        }
    }
}
