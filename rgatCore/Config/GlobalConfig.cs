using Humanizer;
using ImGuiNET;
using rgat.Config;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Veldrid;
using static rgat.CONSTANTS;

namespace rgat
{
    /// <summary>
    /// Runtime rgat settings
    /// </summary>
    public partial class GlobalConfig
    {
        static GlobalConfig()
        {
            //with single executables the AppContext.BaseDirectory value is the temp extract dir
            BaseDirectory = Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]) ?? AppContext.BaseDirectory;
            StartOptions = new LaunchConfig(); //dummy to avoid nullable warning
        }

        /// <summary>
        /// Checks that a binary has a valid code signing certificate issued to one of the expected subject names
        /// </summary>
        /// <param name="path">Path of binary to be tested</param>
        /// <param name="expectedSigners">Comma seperated list of valid certificate subject names</param>
        /// <param name="error">Errors encountered in validating the certificate (no or invalid signer)</param>
        /// <param name="warning">Warnings encountered validating the certificate (time issues)</param>
        /// <returns>Whether the certificate was valid. Expired/Not yet valid certs will return true with the warning field set</returns>
        public static bool VerifyCertificate(string path, string expectedSigners, out string? error, out string? warning)
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


        /// <summary>
        /// Launch config derived from command line arguments/defaults
        /// </summary>
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

        /// <summary>
        /// Minimum brighteness for faded animated geometry
        /// </summary>
        public static float AnimatedFadeMinimumAlpha = 0.3f;

        /// <summary>
        /// How long to linger animated geometry before fading it
        /// </summary>
        public static int AnimationLingerFrames = 6; //number of frames before fade begins


        /// <summary>
        /// Milliseconds to wait between frames of Main (displayed) Graph rendering
        /// </summary>
        public static int MainGraphRenderDelay = 0;
        /// <summary>
        /// How many items of trace data to use to plot the graph per frame
        /// Lower for interactivity, increase for throughput
        /// </summary>
        public static int LiveAnimationUpdatesPerFrame = 500;

        /// <summary>
        /// Animate a rising caption of API nodes when they are animated
        /// </summary>
        public static bool showRisingAnimated = true;

        /// <summary>
        /// Size of standard instruction text
        /// </summary>
        public static float InsTextScale = 13.0f;

        /// <summary>
        /// When to make ins text smaller  [todo: reimplement]
        /// </summary>
        public static float insTextCompactThreshold = 2.5f;
        /// <summary>
        /// Upper limit on how many labels to draw on screen at once [todo: reimplement]
        /// </summary>
        public static int OnScreenNodeTextCountLimit = 100;
        /// <summary>
        /// Upper limit on how far an instruction can be from the camera to be drawn [todo: reimplement]
        /// </summary>
        public static float FurthestInstructionText = 2500f;
        /// <summary>
        /// Upper limit on how far a symbol can be from the camera to be drawn [todo: reimplement]
        /// </summary>
        public static float FurthestSymbol = 5000f;

        /// <summary>
        /// How many frames to animate API calls for
        /// </summary>
        public static int ExternAnimDisplayFrames = 60;
        /// <summary>
        /// How far API labels rise during animation frames [todo should be in consts]
        /// </summary>
        public static float ExternAnimRisePerFrame = 1.4f;

        //public static uint MaximumLoadedGraphs = 1; //todo for dev - change to something like 20 later

        /// <summary>
        /// granularity of thread update rate plot
        /// </summary>
        public static uint IngestStatsPerSecond = 6;
        /// <summary>
        /// length of time a small thread activity plot covers (last X seconds)
        /// </summary>
        public static float IngestStatWindow = 5f;

        /// <summary>
        /// How long to display shortcut keypresses
        /// </summary>
        public static int KeystrokeDisplayMS = 4000;
        /// <summary>
        /// How long remaining on the keypress label to start fading it
        /// </summary>
        public static int KeystrokeStartFadeMS = 350;
        /// <summary>
        /// Max keyboard shortcuts to display
        /// </summary>
        public static int KeystrokeDisplayMaxCount = 5;
        /// <summary>
        /// Show keyboard shortcut activations
        /// </summary>
        public static bool ShowKeystrokes = true;

        /// <summary>
        /// How long to display in-visualiser messages
        /// </summary>
        public static int VisMessageMaxLingerTime = 6500;
        /// <summary>
        /// When to fade in-visualiser messages as they approach the end of their display
        /// </summary>
        public static int VisMessageFadeStartTime = 500;

        /// <summary>
        /// Whether a tooltip should be shown on graph node mouseover
        /// </summary>
        public static bool ShowNodeMouseoverTooltip = true;

        /// <summary>
        ///  work in progress  
        /// </summary>
        public static int NodeClumpLimit = 50;
        /// <summary>
        /// work in progress 
        /// </summary>
        public static float NodeClumpForce = 0.1f;

        /// <summary>
        /// The initial graph layout used for new traces
        /// </summary>
        public static CONSTANTS.LayoutStyles.Style NewGraphLayout = CONSTANTS.LayoutStyles.Style.ForceDirected3DNodes;

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
        /// Maximum temperature that will be applied to force-directed nodes. Fast nodes will layout quickly but wobble
        /// in their low energy position.
        /// </summary>
        public static float NodeSpeedLimit = 3000f;

        /// <summary>
        /// Maximum speed limit available on the GUI
        /// </summary>
        public static readonly float TemperatureLimit = 3000f;

        /// <summary>
        /// Velocity shader attraction constant
        /// </summary>
        public static float AttractionK = 100f;

        /// <summary>
        /// Velocity shader repulsion constant
        /// </summary>
        public static float RepulsionK = 100f;

        /// <summary>
        /// A new rgat release is available to download
        /// </summary>
        public static bool NewVersionAvailable = false;

        /// <summary>
        /// Record the details of a new rgat version
        /// </summary>
        /// <param name="releaseVersion">The release version</param>
        /// <param name="releaseCumulativeChanges">Text of changes from the current version</param>
        /// <param name="downloadLink">Link to download the release from</param>
        public static void RecordAvailableUpdateDetails(Version releaseVersion, string releaseCumulativeChanges, string downloadLink)
        {
            try
            {
                Settings.Updates.UpdateLastCheckVersion = releaseVersion;
                Settings.Updates.UpdateLastChanges = releaseCumulativeChanges;
                Settings.Updates.UpdateDownloadLink = downloadLink;
                NewVersionAvailable = Settings.Updates.UpdateLastCheckVersion > CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC;
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error loading recent updates: {e.Message}");
            }
        }



        //public static Dictionary<string, string> LoadedStringResources = new Dictionary<string, string>();

        /// <summary>
        /// Fetch and load builtin rgat themes from the Assembly resources
        /// </summary>
        public static void LoadThemesFromResource()
        {
            Logging.RecordLogEvent($"Loading Resources", Logging.LogFilterType.TextDebug);

            System.Reflection.Assembly assembly = typeof(ImGuiController).Assembly;
            System.IO.Stream? fs = null;
            try
            {
                fs = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames()[0]);
                if (fs is null)
                {
                    Logging.RecordError("LoadThemesFromResource: Failed to load manifest resource stream");
                    return;
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"LoadThemesFromResource: Failed to load manifest resource stream: {e.Message}");
                return;
            }
            System.Resources.ResourceReader r = new System.Resources.ResourceReader(fs);

            r.GetResourceData("BuiltinJSONThemes", out string? type, out byte[] themesjsn);
            if (themesjsn != null && type == "ResourceTypeCode.String" && themesjsn.Length > 0)
            {
                try
                {
                    string preset = System.Text.Encoding.ASCII.GetString(themesjsn, 0, themesjsn.Length);
                    Themes.LoadBuiltinThemes(Newtonsoft.Json.Linq.JArray.Parse(preset));
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Exception loading builtin themes: {e.Message}");
                }
            }
        }


        /// <summary>
        /// Try to find a path to store working data
        /// </summary>
        /// <param name="baseDir">Directory to search in</param>
        /// <param name="name">Name of directory to create</param>
        /// <returns>Path of created directory</returns>
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
                    if (!Directory.Exists(dir))
                    {
                        continue;
                    }
                }
                string candidate = Path.Combine(dir, name);
                try
                {
                    Directory.CreateDirectory(candidate);
                    if (Directory.Exists(candidate))
                    {
                        return candidate;
                    }
                }
                catch
                {
                    continue;
                }
            }
            return "";
        }

        private static void InitPaths()
        {

            //directories
            if (!Directory.Exists(Settings.ToolPaths.Get(CONSTANTS.PathKey.TraceSaveDirectory)))
            {
                string TraceSaveDirectory = GetStorageDirectoryPath(BaseDirectory, "traces");
                if (!Directory.Exists(TraceSaveDirectory))
                {
                    Logging.RecordError("Warning: Failed to load an existing trace storage path");
                }
                else
                {
                    Settings.ToolPaths.SetDirectoryPath(CONSTANTS.PathKey.TraceSaveDirectory, TraceSaveDirectory);
                }
            }


            if (!Directory.Exists(Settings.ToolPaths.Get(CONSTANTS.PathKey.TestsDirectory)))
            {
                string TestsDirectory = GetStorageDirectoryPath(BaseDirectory, "tests");
                if (!Directory.Exists(TestsDirectory))
                {
                    Logging.RecordLogEvent("No tests directory configured, can't enable tests");
                }
                else
                {
                    Settings.ToolPaths.SetDirectoryPath(CONSTANTS.PathKey.TestsDirectory, TestsDirectory);
                }
            }

            if (!Directory.Exists(Settings.ToolPaths.Get(CONSTANTS.PathKey.DiESigsDirectory)))
            {
                string DiESigsDirectory = GetStorageDirectoryPath(BaseDirectory, "signatures\\detectiteasy");
                if (Directory.Exists(DiESigsDirectory))
                {
                    Settings.ToolPaths.SetDirectoryPath(CONSTANTS.PathKey.DiESigsDirectory, DiESigsDirectory);
                }
                else
                {
                    Logging.RecordLogEvent("No Detect-It-Easy scripts directory configured. Configure this in the Settings->File pane to enable these scans.");
                }

            }

            if (!Directory.Exists(Settings.ToolPaths.Get(CONSTANTS.PathKey.YaraRulesDirectory)))
            {
                string YaraRulesDirectory = GetStorageDirectoryPath(BaseDirectory, "signatures\\yara");
                if (Directory.Exists(YaraRulesDirectory))
                {
                    Settings.ToolPaths.SetDirectoryPath(CONSTANTS.PathKey.YaraRulesDirectory, YaraRulesDirectory);
                }
                else
                {
                    Logging.RecordLogEvent("No YARA rules directory was configured. Configure this in the Settings->File pane to enable these scans.");
                }
            }

            //binaries
            if (!File.Exists(Settings.ToolPaths.Get(CONSTANTS.PathKey.PinPath)))
            {
                List<string> pindirs = Directory.GetDirectories(BaseDirectory)
                    .Where(dir => Path.GetFileName(dir).StartsWith("pin"))
                    .ToList();
                foreach (string dir in pindirs)
                {
                    string candidate = Path.Combine(dir, "pin.exe");
                    if (File.Exists(candidate))
                    {
                        if (Settings.ToolPaths.SetBinaryPath(CONSTANTS.PathKey.PinPath, candidate))
                        {
                            break;
                        }
                    }
                }
            }
            else
            {
                SetBinaryPath(CONSTANTS.PathKey.PinPath, Settings.ToolPaths.Get(CONSTANTS.PathKey.PinPath)); //force signature check
            }


            if (!File.Exists(Settings.ToolPaths.Get(CONSTANTS.PathKey.PinToolPath32)))
            {
                string candidate = Path.Combine(BaseDirectory, "tools", "pintool32.dll");
                if (File.Exists(candidate)) //todo sigcheck
                {
                    SetBinaryPath(CONSTANTS.PathKey.PinToolPath32, candidate);
                }
            }
            else
            {
                SetBinaryPath(CONSTANTS.PathKey.PinToolPath32, Settings.ToolPaths.Get(CONSTANTS.PathKey.PinToolPath32)); //force signature check
            }

            if (!File.Exists(Settings.ToolPaths.Get(CONSTANTS.PathKey.PinToolPath64)))
            {
                string candidate = Path.Combine(BaseDirectory, "tools", "pintool64.dll");
                if (File.Exists(candidate)) //todo sigcheck. also maybe load from resource first
                {
                    SetBinaryPath(CONSTANTS.PathKey.PinToolPath64, candidate);
                }
            }
            else
            {
                SetBinaryPath(CONSTANTS.PathKey.PinToolPath64, Settings.ToolPaths.Get(CONSTANTS.PathKey.PinToolPath64)); //force signature check
            }
        }


        /// <summary>
        /// Failed signature checks
        /// </summary>
        /// <param name="errors">Signature validation errors</param>
        /// <returns>Errors were found</returns>
        public static bool BadSigners(out List<Tuple<string, string>>? errors) => rgatSettings.PathSettings.BadSigners(out errors);


        /// <summary>
        /// Get the code signing certificate validation result for a binary
        /// </summary>
        /// <param name="path">Path of the binary</param>
        /// <param name="error">Certificate error reason</param>
        /// <param name="timeWarning">If the failure was due to a time issue (before/after validity)</param>
        /// <returns>If the certificate is valid</returns>
        public static bool PreviousSignatureCheckPassed(string path, out string? error, out bool timeWarning)
        {
            timeWarning = false;
            if (BadSigners(out List<Tuple<string, string>>? signerErrors))
            {
                foreach (var val in signerErrors!)
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
                    }
                }
            }

            error = "No Error";
            return true;
        }

        private static bool _dirtyConfig = false;
        private static readonly System.Timers.Timer _saveTimer = new System.Timers.Timer(800);

        private static void SaveConfigTimerElapsed(object sender, System.Timers.ElapsedEventArgs e)
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

        private static void SaveConfig()
        {
            try
            {
                string? path = Settings.FilePath;
                if (path is not null && File.Exists(path))
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

        private static void MarkDirty()
        {
            lock (_settingsLock)
            {
                if (!Settings.Inited)
                {
                    return;
                }

                if (!_dirtyConfig)
                {
                    _dirtyConfig = true;
                    _saveTimer.Elapsed += SaveConfigTimerElapsed;
                    _saveTimer.Interval = 800;
                    _saveTimer.Start();
                }
            }
        }



        /// <summary>
        /// Get the filepath associated with a setting
        /// </summary>
        /// <param name="setting">The setting</param>
        /// <returns>The path</returns>
        public static string GetSettingPath(CONSTANTS.PathKey setting) => Settings.ToolPaths.Get(setting);

        /// <summary>
        /// Set a binary path assocated for a setting
        /// </summary>
        /// <param name="setting">The setting</param>
        /// <param name="value">The path</param>
        public static void SetBinaryPath(CONSTANTS.PathKey setting, string value) => Settings.ToolPaths.SetBinaryPath(setting, value);


        /// <summary>
        /// Set a directory path setting
        /// </summary>
        /// <param name="setting">The setting</param>
        /// <param name="value">The path</param>
        public static void SetDirectoryPath(PathKey setting, string value) => Settings.ToolPaths.SetDirectoryPath(setting, value);

        /// <summary>
        /// The main user-settings storage object which is serialised to settings.json
        /// </summary>
        public static rgatSettings Settings = new rgatSettings();


        /// <summary>
        /// UI/App related config
        /// </summary>
        private static readonly object _settingsLock = new object();

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

        /// <summary>
        /// Static file YARA scanning enabled
        /// </summary>
        public static bool ScanFilesYARA = true;
        /// <summary>
        /// Static file Detect It Easy scanning enabled
        /// </summary>
        public static bool ScanFilesDiE = true;
        /// <summary>
        /// Yara scanning of memory enabled
        /// </summary>
        public static bool ScanMemoryYARA = true;
        /// <summary>
        /// Detect it easy of file-like memory enabled
        /// </summary>
        public static bool ScanMemoryDiE = true;

        //~~user customised signature scan locations, to restrict certain signatures to scanning disk/mem/none. non-presence => scan all.~~
        // -> this idea is shelved for the foreseeable future, see https://trello.com/c/ShIWBywy/141-specify-rule-rule-group-exec-conditions-file-mem
        //public static Dictionary<string, eSigScanLocation> SignatureScanLimits = new Dictionary<string, eSigScanLocation>();

        /// <summary>
        /// The directory of the original rgat.exe, rather than the rgat.dll runtime directory
        /// </summary>
        public static string BaseDirectory { get; private set; }


        /// <summary>
        /// Load the rgat settings.json
        /// </summary>
        /// <param name="GUI">true if loading in GUI mode</param>
        /// <param name="progress">optional IProgress</param>
        public static void LoadConfig(bool GUI, IProgress<float>? progress = null)
        {
            System.Diagnostics.Stopwatch timer = new System.Diagnostics.Stopwatch();
            timer.Start();

            string settingsPath = Path.Combine(BaseDirectory, "settings.json");
            if (!File.Exists(settingsPath))
            {
                Logging.RecordLogEvent($"{settingsPath} did not exist, creating empty");
                try
                {
                    File.WriteAllText(settingsPath, "{}");
                }
                catch (Exception e)
                {
                    Logging.RecordError($"{settingsPath} could not be created ({e.Message}), creating in temporary directory");
                    try
                    {
                        settingsPath = Path.GetTempFileName();
                        File.WriteAllText(settingsPath, "{}");
                    }
                    catch (Exception e2)
                    {
                        Logging.RecordError($"Temporary settings {settingsPath} could not be created ({e2.Message})");
                        return;
                    }
                }
            }
            Logging.WriteConsole($"Loading config from {settingsPath} {File.Exists(settingsPath)}");

            string settingsContents = File.ReadAllText(settingsPath);
            System.Text.Json.JsonSerializerOptions settingParserOptions = new System.Text.Json.JsonSerializerOptions() { AllowTrailingCommas = true };
            rgatSettings? loadedSettings = null;
            try
            {
                loadedSettings = System.Text.Json.JsonSerializer.Deserialize<rgatSettings>(settingsContents, settingParserOptions);
                Settings = loadedSettings!;
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error: {e.Message} parsing exceptions file {settingsPath}");
            }
            if (Settings is null)
            {
                Settings = new rgatSettings();
            }
            Settings.FilePath = settingsPath;
            rgatSettings.SetChangeCallback(MarkDirty);
            Settings.EnsureValidity();

            Logging.WriteConsole("initial config load done after" + timer.ElapsedMilliseconds);
            if (Settings.UI.InstalledVersion != CONSTANTS.PROGRAMVERSION.RGAT_VERSION)
            {
                InstallNewTools();
                Settings.UI.InstalledVersion = CONSTANTS.PROGRAMVERSION.RGAT_VERSION;
            }

            InitPaths();


            if (GUI)
            {
                LoadThemesFromResource();
                progress?.Report(0.3f);

                lock (_settingsLock)
                {
                    Themes.ActivateDefaultTheme();
                }

                progress?.Report(0.5f);

                Settings.Keybinds.ApplyUserKeybinds();

                progress?.Report(0.7f);
            }


            progress?.Report(0.9f);

            Logging.RecordLogEvent($"Startup: Config loaded in {timer.ElapsedMilliseconds} ms", Logging.LogFilterType.TextDebug);
            timer.Stop();
            progress?.Report(1f);
        }

        private static void InstallNewTools()
        {
            string toolsDirectory = GetStorageDirectoryPath(BaseDirectory, "tools");
            if (!Directory.Exists(toolsDirectory))
            {
                try
                {
                    Directory.CreateDirectory(toolsDirectory);
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Failed to create tools directory: {toolsDirectory}: {e.Message}");
                    return;
                }
            }

            try
            {
                string tool32Path = Path.Combine(BaseDirectory, "tools", "pintool32.dll");
                byte[]? tool32bytes = rgatState.ReadBinaryResource("PinTool32");
                if (tool32bytes is null)
                {
                    throw new EndOfStreamException("No PinTool32 resource available");
                }

                File.WriteAllBytes(tool32Path, tool32bytes);
                SetBinaryPath(CONSTANTS.PathKey.PinToolPath32, tool32Path);

                string tool64Path = Path.Combine(BaseDirectory, "tools", "pintool64.dll");
                byte[]? tool64bytes = rgatState.ReadBinaryResource("PinTool64");
                if (tool64bytes is null)
                {
                    throw new EndOfStreamException("No PinTool64 resource available");
                }

                File.WriteAllBytes(tool64Path, tool64bytes);
                SetBinaryPath(CONSTANTS.PathKey.PinToolPath64, tool64Path);
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to install new pin tools: {e}");
            }
        }
    }
}
