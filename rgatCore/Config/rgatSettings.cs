using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json.Serialization;
using Veldrid;
using static rgat.CONSTANTS;
using static rgat.GlobalConfig;

namespace rgat.Config
{
    /// <summary>
    /// Storage class for settings that can be stored/loaded
    /// </summary>
    public class rgatSettings
    {
        /// <summary>
        /// Path categories for recently recorded paths
        /// </summary>
        public enum PathType
        {
            /// <summary>
            /// A tracing binary
            /// </summary>
            Binary,
            /// <summary>
            /// A recorded trace
            /// </summary>
            Trace,
            /// <summary>
            /// A directory
            /// </summary>
            Directory
        };

        /// <summary>
        /// Path to the loaded settings file
        /// </summary>
        public string FilePath { get; set; }


        static Action? MarkDirtyCallback = null;
        /// <summary>
        /// Set the action to perform when a setting is changed
        /// </summary>
        /// <param name="_updateAction">callback</param>
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
            Signatures.EnsureValidity();
        }

        /// <summary>
        /// Recently accessed files
        /// </summary>
        public CachedRecentPaths RecentPaths { get; set; } = new CachedRecentPaths();
        /// <summary>
        /// Remote tracing settings
        /// </summary>
        public NetworkSettings Network { get; set; } = new NetworkSettings();
        /// <summary>
        /// Paths for tools rgat uses
        /// </summary>
        public PathSettings ToolPaths { get; set; } = new PathSettings();
        /// <summary>
        /// UI Settings
        /// </summary>
        public UISettings UI { get; set; } = new UISettings();
        /// <summary>
        /// Instrumentation settings
        /// </summary>
        public TracingSettings Tracing { get; set; } = new TracingSettings();
        /// <summary>
        /// Video/screenshot settings
        /// </summary>
        public MediaCaptureSettings Media { get; set; } = new MediaCaptureSettings();
        /// <summary>
        /// Keyboard shortcuts
        /// </summary>
        public KeybindSettings Keybinds { get; set; } = new KeybindSettings();
        /// <summary>
        /// rgat update settings
        /// </summary>
        public UpdateSettings Updates { get; set; } = new UpdateSettings();
        /// <summary>
        /// Log related settings
        /// </summary>
        public LogSettings Logs { get; set; } = new LogSettings();
        /// <summary>
        /// Signature scanning settings
        /// </summary>
        public SignatureSettings Signatures { get; set; } = new SignatureSettings();
        /// <summary>
        /// UI/Graph theme settings
        /// </summary>
        public ThemeSettings Themes { get; set; } = new ThemeSettings();

        /// <summary>
        /// Configurable UI/Graph themes
        /// </summary>
        public class ThemeSettings
        {

            string _DefaultTheme = "";
            /// <summary>
            /// The theme that will be loaded on rgat start
            /// </summary>
            public string DefaultTheme { get => _DefaultTheme; set { _DefaultTheme = value; MarkDirty(); } }

            Dictionary<string, string> _CustomThemes = new Dictionary<string, string>();
            /// <summary>
            /// User themes (as opposed to built in)
            /// </summary>
            public Dictionary<string, string> CustomThemes
            {
                get { lock (_lock) { return _CustomThemes; } }
                set { lock (_lock) { _CustomThemes = value; } }
            }

            /// <summary>
            /// Store a dictionary of custom themes
            /// </summary>
            /// <param name="themes"></param>
            public void SetCustomThemes(Dictionary<string, string> themes)
            {
                lock (_lock) { CustomThemes = themes; }
                MarkDirty();
            }
        }


        /// <summary>
        /// A class for recording filesystem paths and when rgat accessed them
        /// </summary>
        public class PathRecord
        {
            /// <summary>
            /// Filesystem path of the file
            /// </summary>
            public string Path { get; set; }
            /// <summary>
            /// How many times rgat has opened the file
            /// </summary>
            public uint OpenCount { get; set; }
            /// <summary>
            /// When the file was first opened by rgat
            /// </summary>
            public DateTime FirstOpen { get; set; }
            /// <summary>
            /// The most recent time the file was opened
            /// </summary>
            public DateTime LastOpen { get; set; }

            /// <summary>
            /// Sort by the latest open time
            /// </summary>
            public class SortLatestAccess : IComparer<PathRecord>
            {
                /// <summary>
                /// Compare last open times
                /// </summary>
                /// <param name="x">obj 1</param>
                /// <param name="y">obj 2</param>
                /// <returns></returns>
                public int Compare(PathRecord? x, PathRecord? y)
                {
                    Debug.Assert(x is not null && y is not null);
                    return DateTime.Compare(y.LastOpen, x.LastOpen);
                }
            }
        }

        /// <summary>
        /// Connection settings for remote tracing
        /// </summary>
        public class NetworkSettings
        {
            string _DefaultConnectAddress = "";
            /// <summary>
            /// Default address to connect to
            /// </summary>
            public string DefaultConnectAddress { get => _DefaultConnectAddress; set { _DefaultConnectAddress = value; MarkDirty(); } }

            int _DefaultListenPort = -1;
            /// <summary>
            /// Default port to listen on
            /// </summary>
            public int DefaultListenPort { get => _DefaultListenPort; set { _DefaultListenPort = value; MarkDirty(); } }

            string _DefaultNetworkKey = "";
            /// <summary>
            /// Saved network key
            /// </summary>
            public string DefaultNetworkKey { get => _DefaultNetworkKey; set { _DefaultNetworkKey = value; MarkDirty(); } }

            string _DefaultListenModeIF = "";
            /// <summary>
            /// Default network interface to listen on
            /// </summary>
            public string DefaultListenModeIF { get => _DefaultListenModeIF; set { _DefaultListenModeIF = value; MarkDirty(); } }

            string _DefaultConnectModeIF = "";
            /// <summary>
            /// Default network interface for outgoing connections
            /// </summary>
            public string DefaultConnectModeIF { get => _DefaultConnectModeIF; set { _DefaultConnectModeIF = value; MarkDirty(); } }

            /// <summary>
            /// Addresses we have connected to recently
            /// </summary>
            [JsonPropertyName("RecentConnectedAddresses")]
            public List<string> _RecentConnectedAddresses { get; set; } = new List<string>();


            /// <summary>
            /// Record an address we have connected to
            /// </summary>
            /// <param name="address">network address</param>
            public void RecordRecentConnectAddress(string? address)
            {
                if (address is not null)
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
            }



            /// <summary>
            /// List of recently connected network addresses
            /// </summary>
            /// <returns>Address list</returns>
            public List<string> RecentConnectedAddresses()
            {
                lock (_lock)
                {
                    return _RecentConnectedAddresses.ToList();
                }
            }


        }


        /// <summary>
        /// User interface settings
        /// </summary>
        public class UISettings
        {
            int _MaxStoredRecentPaths = 10;
            /// <summary>
            /// Max number of recent paths to store
            /// </summary>
            public int MaxStoredRecentPaths { get => _MaxStoredRecentPaths; set { _MaxStoredRecentPaths = value; MarkDirty(); } }

            /// <summary>
            /// Display an box around the area that was screencaptured
            /// </summary>
            public bool ScreencapAnimation = true;
            /// <summary>
            /// Display a ring around alerts
            /// </summary>
            public bool AlertAnimation = true;

            string _InstalledVersion = "None";
            /// <summary>
            /// The version of rgat this config file was created by
            /// Used on updating to trigger the writing of the latest tools to disk
            /// </summary>
            public string InstalledVersion { get => _InstalledVersion; set { _InstalledVersion = value; MarkDirty(); } }
        }

        /// <summary>
        /// Logging settings
        /// </summary>
        public class LogSettings
        {
            bool _BulkLogging = false;
            /// <summary>
            /// Highly verbose logging to a file in the trace directory used for debugging.
            /// </summary>
            public bool BulkLogging { get => _BulkLogging; set { _BulkLogging = value; MarkDirty(); } }

            bool _StoreSavedTracesAsRecent = true;
            /// <summary>
            /// true => traces we save will be added to recent traces list. false => only ones we load will
            /// </summary>
            public bool StoreSavedTracesAsRecent { get => _StoreSavedTracesAsRecent; set { _StoreSavedTracesAsRecent = value; MarkDirty(); } }
        }


        /// <summary>
        /// Keyboard shortcuts
        /// </summary>
        public class KeybindSettings
        {
            /// <summary>
            /// Create keybind settings
            /// </summary>
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

            /// <summary>
            /// A keybind for an action
            /// </summary>
            public class CustomKeybind
            {
                /// <summary>
                /// The action the keybind triggers
                /// </summary>
                public eKeybind Action { get; set; }
                /// <summary>
                /// Primary or secondary keybind for this action
                /// </summary>
                public int BindIndex { get; set; }
                /// <summary>
                /// Key for the keybind
                /// </summary>
                public Key Key { get; set; }
                /// <summary>
                /// Modifier keys
                /// </summary>
                public ModifierKeys Modifiers { get; set; }
            }


            /// <summary>
            /// Clear all keybinds and restore to default
            /// </summary>
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


            /// <summary>
            /// Enable user keybinds
            /// </summary>
            public void ApplyUserKeybinds()
            {
                UserKeybinds.ForEach(kb => SetKeybind(kb.Action, kb.BindIndex, kb.Key, kb.Modifiers));
            }


            /// <summary>
            /// Set a keybind to an action
            /// </summary>
            /// <param name="action">The action to activate</param>
            /// <param name="bindIndex">Primary or secondardy keybind set</param>
            /// <param name="k">The keybind key</param>
            /// <param name="mod">Modifier keys</param>
            /// <param name="userSpecified">Is a user specified keybind</param>
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

                    ResponsiveKeys = Active.Where(x => ResponsiveHeldActions!.Contains(x.Value)).Select(x => x.Key.Item1).ToList();
                }
            }

            /// <summary>
            /// User-defined keybinds
            /// </summary>
            public List<CustomKeybind> UserKeybinds { get; set; } = new List<CustomKeybind>();
            /// <summary>
            /// All active keybinds
            /// </summary>
            public Dictionary<Tuple<Key, ModifierKeys>, eKeybind> Active = new Dictionary<Tuple<Key, ModifierKeys>, eKeybind>();
            /// <summary>
            /// The first set of keybinds
            /// </summary>
            public Dictionary<eKeybind, Tuple<Key, ModifierKeys>> PrimaryKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
            /// <summary>
            /// The second set of keybinds
            /// </summary>
            public Dictionary<eKeybind, Tuple<Key, ModifierKeys>> AlternateKeybinds = new Dictionary<eKeybind, Tuple<Key, ModifierKeys>>();
        }


        /// <summary>
        /// Paths for tools and directories rgat uses
        /// </summary>
        public class PathSettings
        {
            /// <summary>
            /// Fetch the value of a setting
            /// </summary>
            /// <param name="setting">Setting to fetch</param>
            /// <returns>Path result</returns>
            public string Get(CONSTANTS.PathKey setting)
            {
                lock (_lock)
                {
                    if (Paths.TryGetValue(setting, out string? result))
                        return result;
                }
                return "";
            }


            void SetPath(CONSTANTS.PathKey setting, string value)
            {
                lock (_lock)
                {
                    //we call this when the values are the same to cause a signature check
                    if (!Paths.TryGetValue(setting, out string? oldval) || oldval != value)
                    {
                        Paths[setting] = value;
                        MarkDirty();
                    }
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
                            if (VerifyCertificate(path, SIGNERS.PIN_SIGNERS, out string? error, out string? warning))
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
                            if (VerifyCertificate(path, SIGNERS.RGAT_SIGNERS, out string? error, out string? warning))
                            {
                                if (warning != null)
                                    Logging.RecordLogEvent($"Binary signature validation warning for {path}: {warning}");
                                validSignature = true;
                            }
                            else
                            {
                                Logging.RecordError($"Binary signature validation failed for {path}: {error}");
                                if (error is not null)
                                {
                                    lock (_lock) { BinaryValidationErrors[path] = error; }
                                }
                            }
                            SetPath(setting, path);
                            break;
                        }

                    case PathKey.PinToolPath64:
                        {
                            if (VerifyCertificate(path, SIGNERS.RGAT_SIGNERS, out string? error, out string? warning))
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

            /// <summary>
            /// Set a directory setting
            /// </summary>
            /// <param name="setting">The setting</param>
            /// <param name="path">The path</param>
            public void SetDirectoryPath(CONSTANTS.PathKey setting, string path)
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

            /// <summary>
            /// Failed signature checks
            /// </summary>
            /// <param name="errors">Signature validation errors</param>
            /// <returns>Errors were found</returns>
            public bool BadSigners(out List<Tuple<string, string>>? errors)
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

        /// <summary>
        /// Configuration for tracing
        /// </summary>
        public class TracingSettings
        {
            uint _TraceBufferSize = 400000;
            /// <summary>
            /// How big the tracebuffer can get before we pause instrumentation
            /// </summary>
            public uint TraceBufferSize { get => _TraceBufferSize; set { _TraceBufferSize = value; MarkDirty(); } }

            ulong _SymbolSearchDistance = 4096;
            /// <summary>
            /// How far back from an address to search for a symbol
            /// </summary>
            public ulong SymbolSearchDistance { get => _SymbolSearchDistance; set { _SymbolSearchDistance = value; MarkDirty(); } }

            int _ArgStorageMax = 100;
            /// <summary>
            /// Maximum number of arguments to store for an API, to prevent excess memory usage
            /// </summary>
            public int ArgStorageMax { get => _ArgStorageMax; set { _ArgStorageMax = value; MarkDirty(); } }

        }


        public class UpdateSettings
        {
            bool _DoUpdateCheck = true;
            /// <summary>
            /// Checking the rgat repo for updates is enabled
            /// </summary>
            public bool DoUpdateCheck { get => _DoUpdateCheck; set { _DoUpdateCheck = value; MarkDirty(); } }

            DateTime _UpdateLastCheckTime = DateTime.MinValue;
            /// <summary>
            /// When the last check for an update was performed
            /// </summary>
            public DateTime UpdateLastCheckTime { get => _UpdateLastCheckTime; set { lock (_lock) { _UpdateLastCheckTime = value; } MarkDirty(); } }

            Version _UpdateLastCheckVersion = PROGRAMVERSION.RGAT_VERSION_SEMANTIC;

            /// <summary>
            /// The most recently found rgat version
            /// </summary>
            [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
            public Version UpdateLastCheckVersion
            {
                get => _UpdateLastCheckVersion;
                set
                {
                    try
                    {
                        _UpdateLastCheckVersion = value;
                        _UpdateLastCheckVersionString = value.ToString();
                        GlobalConfig.NewVersionAvailable = _UpdateLastCheckVersion > CONSTANTS.PROGRAMVERSION.RGAT_VERSION_SEMANTIC;
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Failed to parse update version ({value}) from settings: {e.Message}");
                    }

                    MarkDirty();
                }
            }

            string? _UpdateLastCheckVersionString;
            /// <summary>
            /// Latest available rgat version
            /// </summary>
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
            /// <summary>
            /// List of changes in the most recenly available update (from this version)
            /// </summary>
            public string UpdateLastChanges { get => _UpdateLastChanges; set { _UpdateLastChanges = value; MarkDirty(); } }



            string _UpdateDownloadLink = "";
            /// <summary>
            /// Link to fetch the new version
            /// </summary>
            public string UpdateDownloadLink { get => _UpdateDownloadLink; set { _UpdateDownloadLink = value; MarkDirty(); } }

            string _StagedDownloadPath = "";
            /// <summary>
            /// Path to download the new version 
            /// </summary>
            public string StagedDownloadPath { get => _StagedDownloadPath; set { _StagedDownloadPath = value; MarkDirty(); } }

            string _StagedDownloadVersion = "";
            /// <summary>
            /// Version of rgat staged for download
            /// </summary>
            public string StagedDownloadVersion { get => _StagedDownloadVersion; set { _StagedDownloadVersion = value; MarkDirty(); } }
        }



        /// <summary>
        /// Video encoding and screenshot related config
        /// </summary>
        public class MediaCaptureSettings
        {
            string _FFmpegPath = "";
            /// <summary>
            /// Path to ffmpeg.exe
            /// </summary>
            public string FFmpegPath { get => _FFmpegPath; set { _FFmpegPath = value; MarkDirty(); } }

            string _VideoCodec_Speed = "Medium";
            /// <summary>
            /// FFMpeg speed setting
            /// </summary>
            public string VideoCodec_Speed { get => _VideoCodec_Speed; set { _VideoCodec_Speed = value; MarkDirty(); } }

            int _VideoCodec_Quality = 6;
            /// <summary>
            /// FFMpeg quality setting
            /// </summary>
            public int VideoCodec_Quality { get => _VideoCodec_Quality; set { _VideoCodec_Quality = value; MarkDirty(); } }

            double _VideoCodec_FPS = 30;
            /// <summary>
            /// FFMpeg framerate setting
            /// </summary>
            public double VideoCodec_FPS { get => _VideoCodec_FPS; set { _VideoCodec_FPS = value; MarkDirty(); } }

            string _VideoCodec_Content = "Graph";
            /// <summary>
            /// Which content to capture
            /// </summary>
            public string VideoCodec_Content { get => _VideoCodec_Content; set { _VideoCodec_Content = value; MarkDirty(); } }

            string _ImageCapture_Format = "PNG";
            /// <summary>
            /// The format for image capture files
            /// </summary>
            public string ImageCapture_Format { get => _ImageCapture_Format; set { _ImageCapture_Format = value; MarkDirty(); } }
        }


        /// <summary>
        /// Storage of recently accessed paths
        /// </summary>
        public class CachedRecentPaths
        {
            /// <summary>
            /// Filesystem locations the user has accessed (opened binaries, opened traces, filepicker directories)
            /// </summary>
            public Dictionary<PathType, List<PathRecord>> RecentPaths { get; set; } = new Dictionary<PathType, List<PathRecord>>();
            public PathRecord[] Get(PathType pathType)
            {
                lock (_lock)
                {
                    if (RecentPaths.ContainsKey(pathType)) return RecentPaths[pathType].ToArray();
                }
                return new PathRecord[] { };
            }


            /// <summary>
            /// Record a recently accessed path
            /// </summary>
            /// <param name="pathType">The category of file accessed</param>
            /// <param name="path">The path</param>
            public void RecordRecentPath(PathType pathType, string path)
            {
                lock (_lock)
                {
                    List<PathRecord> targetList = new List<PathRecord>();
                    targetList = RecentPaths[pathType];

                    PathRecord? found = targetList.Find(x => x.Path == path);
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

                    targetList.Sort(new rgatSettings.PathRecord.SortLatestAccess());

                    if (pathType != PathType.Directory)
                    {
                        try
                        {
                            RecordRecentPath(PathType.Directory, Path.GetDirectoryName(path));
                        }
                        catch (Exception e)
                        {
                            Logging.RecordLogEvent($"Failed to record recent directory containing {path}: {e.Message}");
                        }
                    }
                }
                MarkDirty();
            }

            /// <summary>
            /// Check the loaded data won't crash us
            /// </summary>
            public void EnsureValidity()
            {
                PathType[] requiredRecentPathTypes = new PathType[] { PathType.Binary, PathType.Trace, PathType.Directory };
                foreach (var pathType in requiredRecentPathTypes)
                {
                    if (!RecentPaths.ContainsKey(pathType)) { RecentPaths.Add(pathType, new List<PathRecord>()); MarkDirty(); }
                }
            }


        }


        /// <summary>
        /// Configuration for signature scanning
        /// </summary>
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

            /// <summary>
            /// Replace the metadata of a signature repo
            /// </summary>
            /// <param name="source">new data</param>
            public void UpdateSignatureSource(SignatureSource source)
            {
                lock (_lock)
                {
                    SignatureSources[source.FetchPath] = source;
                    MarkDirty();
                }
            }

            /// <summary>
            /// Add a new signature repo
            /// </summary>
            /// <param name="source">new data</param>
            public void AddSignatureSource(SignatureSource source)
            {
                lock (_lock)
                {
                    SignatureSources[source.FetchPath] = source;
                    MarkDirty();
                }
            }

            /// <summary>
            /// Delete a repo
            /// </summary>
            /// <param name="sourcePath">github path</param>
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

            /// <summary>
            /// Get a signature repos metadata
            /// </summary>
            /// <param name="path">github path</param>
            /// <returns></returns>
            public SignatureSource? GetSignatureRepo(string path)
            {
                lock (_lock)
                {
                    return _signatureSources[path];
                }
            }


            /// <summary>
            /// Add some default signature sources
            /// </summary>
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


            /// <summary>
            /// Get all signature repos
            /// </summary>
            /// <returns>Array of repo metadata</returns>
            public SignatureSource[] GetSignatureSources()
            {
                lock (_lock)
                {
                    return _signatureSources.Values.ToArray();
                }
            }


            /// <summary>
            /// Check a repo path exists
            /// </summary>
            /// <param name="githubPath">path</param>
            /// <returns></returns>
            public bool RepoExists(string githubPath)
            {
                lock (_lock)
                {
                    return _signatureSources.ContainsKey(githubPath);
                }
            }

            /// <summary>
            /// Init the signature sources if invalid
            /// </summary>
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
