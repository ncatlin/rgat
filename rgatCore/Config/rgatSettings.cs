using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Veldrid;
using static rgat.CONSTANTS;
using static rgat.Logging;
using System.Text.Json;
using System.IO;
using System.Diagnostics;
using static rgat.GlobalConfig;
using Humanizer;

namespace rgat.Config
{
    public class rgatSettings
    {

        public enum eRecentPathType { Binary, Trace, Directory };
        public string FilePath { get; set; }

        static Action MarkDirtyCallback = null;
        public static void SetChangeCallback(Action _updateAction) => MarkDirtyCallback = _updateAction;

        static void MarkDirty()
        {
            if (MarkDirtyCallback != null) MarkDirtyCallback();
        }

        /// <summary>
        /// A flag used to prevent saving of the settings during the loading process
        /// </summary>
        public bool Inited = false;
        readonly static object _lock = new object();

        /// <summary>
        /// Perform some checks on the loaded config to try and make sure it won't crash the program
        /// Adds any values that might have appeared in a new version
        /// </summary>
        public void EnsureValidity()
        {
            Inited = true;
            RecentPaths.EnsureValidity();
            ToolPaths.EnsureValidity();
            Signatures.EnsureValidity();
        }


        public CachedRecentPaths RecentPaths { get; set; } = new CachedRecentPaths();
        public NetworkSettings Network { get; set; } = new NetworkSettings();
        public PathSettings ToolPaths { get; set; } = new PathSettings();
        public UISettings UI { get; set; } = new UISettings();
        public TracingSettings Tracing { get; set; } = new TracingSettings();
        public MediaCaptureSettings Media { get; set; } = new MediaCaptureSettings();
        public KeybindSettings Keybinds { get; set; } = new KeybindSettings();
        public UpdateSettings Updates { get; set; } = new UpdateSettings();
        public LogSettings Logs { get; set; } = new LogSettings();
        public SignatureSettings Signatures { get; set; } = new SignatureSettings();
        public ThemeSettings Themes { get; set; } = new ThemeSettings();



        public class ThemeSettings
        {

            string _DefaultTheme = "";
            public string DefaultTheme { get => _DefaultTheme; set { _DefaultTheme = value; MarkDirty(); } }

            Dictionary<string, string> _CustomThemes = new Dictionary<string, string>();
            public Dictionary<string, string> CustomThemes
            {
                get { lock (_lock) { return _CustomThemes; } }
                set { lock (_lock) { _CustomThemes = value; } }
            }

            public void SetCustomThemes(Dictionary<string, string> themes)
            {
                lock (_lock) { CustomThemes = themes; }
                MarkDirty();
            }
        }



        public class PathRecord
        {
            public string Path { get; set; }
            public uint OpenCount { get; set; }
            public DateTime FirstOpen { get; set; }
            public DateTime LastOpen { get; set; }
        }


        /// <summary>
        /// Connection settings for remote tracing
        /// </summary>
        public class NetworkSettings
        {
            string _DefaultHeadlessAddress = "";
            public string DefaultHeadlessAddress { get => _DefaultHeadlessAddress; set { _DefaultHeadlessAddress = value; MarkDirty(); } }

            int _DefaultListenPort = -1;
            public int DefaultListenPort { get => _DefaultListenPort; set { _DefaultListenPort = value; MarkDirty(); } }

            string _DefaultNetworkKey = "";
            public string DefaultNetworkKey { get => _DefaultNetworkKey; set { _DefaultNetworkKey = value; MarkDirty(); } }

            string _DefaultListenModeIF = "";
            public string DefaultListenModeIF { get => _DefaultListenModeIF; set { _DefaultListenModeIF = value; MarkDirty(); } }

            string _DefaultConnectModeIF = "";
            public string DefaultConnectModeIF { get => _DefaultConnectModeIF; set { _DefaultConnectModeIF = value; MarkDirty(); } }

            [JsonPropertyName("RecentConnectedAddresses")]
            public List<string> _RecentConnectedAddresses { get; set; } = new List<string>();

            public void RecordRecentConnectAddress(string address)
            {
                lock (_lock)
                {
                    _RecentConnectedAddresses.Remove(address);
                    _RecentConnectedAddresses.Insert(0, address);
                    if (_RecentConnectedAddresses.Count > 6)
                        _RecentConnectedAddresses.RemoveRange(5, _RecentConnectedAddresses.Count - 1);
                    MarkDirty();
                }
            }
            public List<string> RecentConnectedAddresses()
            {
                lock (_lock)
                {
                    return _RecentConnectedAddresses.ToList();
                }
            }


        }

        public class UISettings
        {

            public bool ScreencapAnimation = true;
            public bool AlertAnimation = true;

            string _InstalledVersion = "None";
            public string InstalledVersion { get => _InstalledVersion; set { _InstalledVersion = value; MarkDirty(); } }
        }


        public class LogSettings
        {

            int _MaxStoredRecentPaths = 10;
            public int MaxStoredRecentPaths { get => _MaxStoredRecentPaths; set { _MaxStoredRecentPaths = value; MarkDirty(); } }

            bool _BulkLogging = false;
            public bool BulkLogging { get => _BulkLogging; set { _BulkLogging = value; MarkDirty(); } }

            //true => traces we save will be added to recent traces list. false => only ones we load will
            bool _StoreSavedTracesAsRecent = true;
            public bool StoreSavedTracesAsRecent { get => _StoreSavedTracesAsRecent; set { _StoreSavedTracesAsRecent = value; MarkDirty(); } }
        }

        public class KeybindSettings
        {
            public KeybindSettings()
            {
                ResponsiveHeldActions = new List<eKeybind>();
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

                InitDefaultKeybinds();
                InitResponsiveKeys();
            }

            public class CustomKeybind
            {
                public eKeybind Action { get; set; }
                public int BindIndex { get; set; }
                public Key Key { get; set; }
                public ModifierKeys Modifiers { get; set; }
            }
            public void ResetKeybinds()
            {
                PrimaryKeybinds.Clear();
                AlternateKeybinds.Clear();
                InitDefaultKeybinds();
                InitResponsiveKeys();
            }


            /// <summary>
            /// A set of standard keybinds for new installs
            /// </summary>
            public void InitDefaultKeybinds()
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
                SetKeybind(action: eKeybind.ToggleVideo, bindIndex: 1, Key.U, ModifierKeys.None);
                SetKeybind(action: eKeybind.PauseVideo, bindIndex: 1, Key.U, ModifierKeys.Shift);
            }


            /// <summary>
            /// Some keybinds we don't want to wait for the OS repeat detection (S........SSSSSSSSSSS) because it makes
            /// things like graph movement and rotation clunky. Instead we read for their keypress every update instead
            /// of listening for the key action
            /// 
            /// Alt/Shift/Ctrl modifiers are reserved for these keys, so two different actions can't be bound to a key this way.
            /// </summary>
            public void InitResponsiveKeys()
            {
                ResponsiveKeys = Active.Where(x => ResponsiveHeldActions.Contains(x.Value)).Select(x => x.Key.Item1).ToList();
            }

            public void ApplyUserKeybinds()
            {
                UserKeybinds.ForEach(kb => SetKeybind(kb.Action, kb.BindIndex, kb.Key, kb.Modifiers));
            }


            public void SetKeybind(eKeybind action, int bindIndex, Key k, ModifierKeys mod, bool userSpecified = false)
            {
                lock (_lock)
                {
                    //reserved actions cant have modifier keys
                    if (ResponsiveHeldActions != null && ResponsiveHeldActions.Contains(action))
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
                        CustomKeybind bind = new CustomKeybind()
                        {
                            Action = action,
                            BindIndex = bindIndex,
                            Key = k,
                            Modifiers = mod
                        };
                        UserKeybinds.RemoveAll(x => x.Key == k && x.Modifiers == mod);
                        UserKeybinds.Add(bind);
                        MarkDirty();
                    }

                    //regenerate the keybinds lists
                    Active.Clear();
                    foreach (var kvp in PrimaryKeybinds) { Active[kvp.Value] = kvp.Key; }
                    foreach (var kvp in AlternateKeybinds) { Active[kvp.Value] = kvp.Key; }

                    ResponsiveKeys = Active.Where(x => ResponsiveHeldActions.Contains(x.Value)).Select(x => x.Key.Item1).ToList();
                }
            }

            public List<CustomKeybind> UserKeybinds { get; set; } = new List<CustomKeybind>();
            public Dictionary<Tuple<Key, ModifierKeys>, eKeybind> Active = new Dictionary<Tuple<Key, ModifierKeys>, eKeybind>();
            public Dictionary<eKeybind, Tuple<Key, ModifierKeys>> PrimaryKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
            public Dictionary<eKeybind, Tuple<Key, ModifierKeys>> AlternateKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
        }


        public class PathSettings
        {
            public string Get(CONSTANTS.PathKey setting)
            {
                lock (_lock)
                {
                    if (Paths.TryGetValue(setting, out string result)) return result;
                }
                return "";
            }


            void SetPath(CONSTANTS.PathKey setting, string value)
            {
                lock (_lock)
                {
                    //we call this when the values are the same to cause a signature check
                    if (Paths[setting] != value)
                    {
                        Paths[setting] = value;
                        MarkDirty();
                    }
                }
            }

            public void EnsureValidity()
            {
                if (Paths == null)
                {
                    Paths = new Dictionary<CONSTANTS.PathKey, string>();
                    MarkDirty();
                }
            }

            /// <summary>
            /// Filesystem locations containing things rgat needs (instrumentation tools, signatures, etc)
            /// </summary>
            public Dictionary<CONSTANTS.PathKey, string> Paths { get; set; }

            /// <summary>
            /// Errors such as bad signatures encountered while validating binaries used by rgat (pintools, etc).
            /// </summary>
            public static Dictionary<string, string> BinaryValidationErrors = new Dictionary<string, string>();

            /// <summary>
            /// BinaryValidationErrors stored in a faster data structure for access by the UI each frame
            /// </summary>
            public static List<Tuple<string, string>> _BinaryValidationErrorCache = new List<Tuple<string, string>>();


            /// <summary>
            /// Set the value of a binary path setting (a tool like pin/ffmpeg or a library such as a pintool)
            /// </summary>
            /// <param name="setting">A BinaryPathKey value</param>
            /// <param name="path">A filesystem path for the setting</param>
            /// <returns></returns>
            public bool SetBinaryPath(PathKey setting, string path)
            {

                bool validSignature = false;
                switch (setting)
                {
                    case PathKey.PinPath:
                        {
                            if (VerifyCertificate(path, SIGNERS.PIN_SIGNERS, out string error, out string warning))
                            {
                                if (warning != null)
                                    Logging.RecordLogEvent($"Binary signature validation warning for {path}: {warning}");
                                validSignature = true;
                            }
                            else
                            {
                                Logging.RecordError($"Binary signature validation failed for {path}: {error}");
                                lock (_lock) { BinaryValidationErrors[path] = error; }
                            }
                            SetPath(setting, path);
                            break;
                        }

                    case PathKey.PinToolPath32:
                        {
                            if (VerifyCertificate(path, SIGNERS.RGAT_SIGNERS, out string error, out string warning))
                            {
                                if (warning != null)
                                    Logging.RecordLogEvent($"Binary signature validation warning for {path}: {warning}");
                                validSignature = true;
                            }
                            else
                            {
                                Logging.RecordError($"Binary signature validation failed for {path}: {error}");
                                lock (_lock) { BinaryValidationErrors[path] = error; }
                            }
                            SetPath(setting, path);
                            break;
                        }

                    case PathKey.PinToolPath64:
                        {
                            if (VerifyCertificate(path, SIGNERS.RGAT_SIGNERS, out string error, out string warning))
                            {
                                if (warning != null)
                                    Logging.RecordLogEvent($"Binary signature validation warning for {path}: {warning}");
                                validSignature = true;
                            }
                            else
                            {
                                Logging.RecordError($"Binary signature validation failed for {path}: {error}");
                                lock (_lock) { BinaryValidationErrors[path] = error; }
                            }
                            SetPath(setting, path);
                            break;
                        }

                    case PathKey.FFmpegPath:
                        {
                            SetPath(setting, path);
                            break;
                        }

                    default:
                        Logging.RecordError($"Trying to save bad binary: {setting}");
                        return false;
                }

                if (!validSignature)
                {
                    lock (_lock)
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

            public void SetDirectoryPath(CONSTANTS.PathKey setting, string path, bool save = true)
            {
                switch (setting)
                {
                    case CONSTANTS.PathKey.TraceSaveDirectory:
                    case CONSTANTS.PathKey.TestsDirectory:
                    case CONSTANTS.PathKey.DiESigsDirectory:
                    case CONSTANTS.PathKey.YaraRulesDirectory:
                    case CONSTANTS.PathKey.MediaCapturePath:
                        SetPath(setting, path);
                        break;
                    default:
                        Logging.RecordLogEvent($"Bad directory path setting: {setting} => {path}", Logging.LogFilterType.TextError);
                        return;
                }
            }

            public bool BadSigners(out List<Tuple<string, string>> errors)
            {
                lock (_lock)
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
        }

        public class TracingSettings
        {
            uint _TraceBufferSize = 400000;
            public uint TraceBufferSize { get => _TraceBufferSize; set { _TraceBufferSize = value; MarkDirty(); } }

            ulong _SymbolSearchDistance = 4096;
            public ulong SymbolSearchDistance { get => _SymbolSearchDistance; set { _SymbolSearchDistance = value; MarkDirty(); } }

            int _ArgStorageMax = 100;
            /// <summary>
            /// how many bytes back from an instruction to search for a symbol of the function it belongs to
            /// </summary>
            public int ArgStorageMax { get => _ArgStorageMax; set { _ArgStorageMax = value; MarkDirty(); } }

        }


        public class UpdateSettings
        {
            bool _DoUpdateCheck = true;
            public bool DoUpdateCheck { get => _DoUpdateCheck; set { _DoUpdateCheck = value; MarkDirty(); } }

            DateTime _UpdateLastCheckTime = DateTime.MinValue;
            public DateTime UpdateLastCheckTime { get => _UpdateLastCheckTime; set { lock (_lock) { _UpdateLastCheckTime = value; } MarkDirty(); } }

            Version _UpdateLastCheckVersion = RGAT_VERSION_SEMANTIC;

            [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
            public Version UpdateLastCheckVersion { get => _UpdateLastCheckVersion; 
                set
                {
                    try
                    {
                        _UpdateLastCheckVersion = value;
                        _UpdateLastCheckVersionString = value.ToString();
                        GlobalConfig.NewVersionAvailable = _UpdateLastCheckVersion > CONSTANTS.RGAT_VERSION_SEMANTIC;
                    }
                    catch(Exception e)
                    {
                        Logging.RecordLogEvent($"Failed to parse update version ({value}) from settings: {e.Message}");
                    }
                    
                    MarkDirty(); 
                }
            }

            public string _UpdateLastCheckVersionString;
            public string UpdateLastCheckVersionString
            {
                get => UpdateLastCheckVersion.ToString();
                set
                {
                    try
                    {
                        UpdateLastCheckVersion = Version.Parse(value);
                        _UpdateLastCheckVersionString = value;
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Failed to parse update version ({value}) from settings: {e.Message}");
                    }

                    MarkDirty();
                }
            }


            string _UpdateLastChanges = "";
            public string UpdateLastChanges { get => _UpdateLastChanges; set { _UpdateLastChanges = value; MarkDirty(); } }



            string _UpdateDownloadLink = "";
            public string UpdateDownloadLink { get => _UpdateDownloadLink; set { _UpdateDownloadLink = value; MarkDirty(); } }

            string _StagedDownloadPath = "";
            public string StagedDownloadPath { get => _StagedDownloadPath; set { _StagedDownloadPath = value; MarkDirty(); } }

            string _StagedDownloadVersion = "";
            public string StagedDownloadVersion { get => _StagedDownloadVersion; set { _StagedDownloadVersion = value; MarkDirty(); } }
        }



        /// <summary>
        /// Video encoding and screenshot related config
        /// </summary>
        public class MediaCaptureSettings
        {
            string _FFmpegPath = "";
            public string FFmpegPath { get => _FFmpegPath; set { _FFmpegPath = value; MarkDirty(); } }

            string _VideoCodec_Speed = "Medium";
            public string VideoCodec_Speed { get => _VideoCodec_Speed; set { _VideoCodec_Speed = value; MarkDirty(); } }

            int _VideoCodec_Quality = 6;
            public int VideoCodec_Quality { get => _VideoCodec_Quality; set { _VideoCodec_Quality = value; MarkDirty(); } }

            double _VideoCodec_FPS = 30;
            public double VideoCodec_FPS { get => _VideoCodec_FPS; set { _VideoCodec_FPS = value; MarkDirty(); } }

            string _VideoCodec_Content = "Graph";
            public string VideoCodec_Content { get => _VideoCodec_Content; set { _VideoCodec_Content = value; MarkDirty(); } }

            string _ImageCapture_Format = "PNG";
            public string ImageCapture_Format { get => _VideoCodec_Speed; set { _VideoCodec_Speed = value; MarkDirty(); } }
        }

        public class CachedRecentPaths
        {


            /// <summary>
            /// Filesystem locations the user has accessed (opened binaries, opened traces, filepicker directories)
            /// </summary>
            public Dictionary<eRecentPathType, List<PathRecord>> RecentPaths { get; set; } = new Dictionary<eRecentPathType, List<PathRecord>>();
            public PathRecord[] Get(eRecentPathType pathType)
            {
                lock (_lock)
                {
                    if (RecentPaths.ContainsKey(pathType)) return RecentPaths[pathType].ToArray();
                }
                return new PathRecord[] { };
            }



            public void RecordRecentPath(eRecentPathType pathType, string path)
            {
                lock (_lock)
                {
                    List<PathRecord> targetList = new List<PathRecord>();
                    targetList = RecentPaths[pathType];

                    PathRecord found = targetList.Find(x => x.Path == path);
                    if (found == null)
                    {
                        found = new PathRecord()
                        {
                            Path = path,
                            FirstOpen = DateTime.Now,
                            LastOpen = DateTime.Now,
                            OpenCount = 1
                        };
                        targetList.Add(found);
                    }
                    else
                    {
                        found.OpenCount += 1;
                        found.LastOpen = DateTime.Now;
                    }

                    if (pathType != eRecentPathType.Directory)
                    {
                        try
                        {
                            RecordRecentPath(eRecentPathType.Directory, Path.GetDirectoryName(path));
                        }
                        catch (Exception e)
                        {
                            Logging.RecordLogEvent($"Failed to record recent directory containing {path}: {e.Message}");
                        }
                    }
                }
                MarkDirty();
            }


            public void EnsureValidity()
            {
                eRecentPathType[] requiredRecentPathTypes = new eRecentPathType[] { eRecentPathType.Binary, eRecentPathType.Trace, eRecentPathType.Directory };
                foreach (var pathType in requiredRecentPathTypes)
                {
                    if (!RecentPaths.ContainsKey(pathType)) { RecentPaths.Add(pathType, new List<PathRecord>()); MarkDirty(); }
                }
            }


        }

        public class SignatureSettings
        {
            bool inited = false;

            Dictionary<string, SignatureSource> _signatureSources = null;

            [JsonPropertyName("SignatureSources")]
            public Dictionary<string, SignatureSource> SignatureSources { get => _signatureSources; set { Debug.Assert(!inited); _signatureSources = value; inited = true; } }


            public void ReplaceSignatureSources(List<SignatureSource> sources)
            {
                lock (_lock)
                {
                    SignatureSources = new Dictionary<string, SignatureSource>();
                    foreach (var src in sources)
                    {
                        SignatureSources[src.FetchPath] = src;
                    }
                    MarkDirty();
                }
            }


            public void UpdateSignatureSource(SignatureSource source)
            {
                lock (_lock)
                {
                    SignatureSources[source.FetchPath] = source;
                    MarkDirty();
                }
            }

            public void AddSignatureSource(SignatureSource source)
            {
                lock (_lock)
                {
                    SignatureSources[source.FetchPath] = source;
                    MarkDirty();
                }
            }
            public void DeleteSignatureSource(string sourcePath)
            {
                lock (_lock)
                {
                    //there is no way to re-add the DIE path other than manually editing the config, so disallow deletion
                    if (_signatureSources.ContainsKey(sourcePath))
                    {
                        _signatureSources.Remove(sourcePath);
                        MarkDirty();
                    }
                }
            }
            public SignatureSource? GetSignatureRepo(string path)
            {
                lock (_lock)
                {
                    if (_signatureSources.TryGetValue(path, out SignatureSource value)) return value;
                    return null;
                }
            }

            public void InitDefaultSignatureSources()
            {
                //todo embed as a resource

                Dictionary<string, SignatureSource> result = new Dictionary<string, SignatureSource>();
                SignatureSource item1 = new SignatureSource()
                {
                    OrgName = "horsicq",
                    RepoName = "Detect-It-Easy",
                    SubDir = "db",
                    LastUpdate = DateTime.MinValue,
                    LastCheck = DateTime.MinValue,
                    LastFetch = DateTime.MinValue,
                    RuleCount = -1,
                    SignatureType = eSignatureType.DIE
                };
                result.Add(item1.FetchPath, item1);

                SignatureSource item2 = new SignatureSource()
                {
                    OrgName = "h3x2b",
                    RepoName = "yara-rules",
                    SubDir = "malware",
                    LastUpdate = DateTime.MinValue,
                    LastCheck = DateTime.MinValue,
                    LastFetch = DateTime.MinValue,
                    RuleCount = -1,
                    SignatureType = eSignatureType.YARA
                };
                result.Add(item2.FetchPath, item2);

                lock (_lock)
                {
                    _signatureSources = result;
                    MarkDirty();
                }
            }


            public SignatureSource[] GetSignatureSources()
            {
                lock (_lock)
                {
                    return _signatureSources.Values.ToArray();
                }
            }


            public bool RepoExists(string githubPath)
            {
                lock (_lock)
                {
                    return _signatureSources.ContainsKey(githubPath);
                }
            }

            public void EnsureValidity()
            {
                lock (_lock)
                {
                    if (_signatureSources == null)
                    {
                        InitDefaultSignatureSources();
                    }
                }
            }
        }

    }



}
