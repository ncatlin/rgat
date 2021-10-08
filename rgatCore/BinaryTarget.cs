using Humanizer;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace rgat
{
    /// <summary>
    /// How the instrumentation handles code in different modules
    /// </summary>
    public enum ModuleTracingMode
    {
        /// <summary>
        /// Code will not be traced unless explicitly requested
        /// </summary>
        eDefaultIgnore = 0,

        /// <summary>
        /// Code will be traced unless explicitly ignored
        /// </summary>
        eDefaultTrace = 1
    };

    /// <summary>
    /// Settings for how rgat chooses which code to trace or ignore
    /// </summary>
    public class TraceChoiceSettings
    {
        /// <summary>
        /// Whether rgat traces or ignores modules which are not in the ignore/trace lists
        /// </summary>
        public ModuleTracingMode TracingMode { get; set; } = ModuleTracingMode.eDefaultTrace;

        /// <summary>
        /// Binaries in these directories will be traced in default ignore mode
        /// </summary>
        public HashSet<string> TraceDirs { get; set; } = new();

        /// <summary>
        /// The number of directories listed for instrumentation
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public int TraceDirCount => TraceDirs.Count;

        /// <summary>
        /// These binaries will be instrumentated in default ignore mode
        /// </summary>
        public HashSet<string> TraceFiles { get; set; } = new();

        /// <summary>
        /// The number of modules that are listed for tracing
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public int TraceFilesCount => TraceFiles.Count;


        /// <summary>
        /// Binaries in these directories will be ignored in default trace mode
        /// </summary>
        public HashSet<string> IgnoreDirs { get; set; } = new();

        /// <summary>
        /// The number of directories which are explicitly ignored in default trace mode
        /// </summary>
        public int IgnoreDirsCount => IgnoreDirs.Count;

        /// <summary>
        /// These binaries will be ignored in default trace mode
        /// </summary>
        public HashSet<string> IgnoreFiles { get; set; } = new();

        /// <summary>
        /// The number of files which are explicitly ignored in default trace mode
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public int IgnoreFilesCount => IgnoreFiles.Count;

        private readonly object _lock = new();

        /// <summary>
        /// Get the list of directories which contain modules which should not be instrumented
        /// </summary>
        /// <returns>A list of directory paths</returns>
        public List<string> GetIgnoredDirs() { lock (_lock) { return IgnoreDirs.ToList<string>(); } }
        /// <summary>
        /// Clear the list of ignored directories
        /// </summary>
        public void ClearIgnoredDirs() { lock (_lock) { IgnoreDirs.Clear(); } }
        /// <summary>
        /// Get the list of modules which should not be instrumented
        /// </summary>
        /// <returns>A list of file paths</returns>
        public List<string> GetIgnoredFiles() { lock (_lock) { return IgnoreFiles.ToList<string>(); } }
        /// <summary>
        /// Clear the list of ignored files
        /// </summary>
        public void ClearIgnoredFiles() { lock (_lock) { IgnoreFiles.Clear(); } }
        /// <summary>
        /// Get the list of directories which contain modules which should be instrumented even in ignore mode
        /// </summary>
        /// <returns>A list of directory paths</returns>
        public List<string> GetTracedDirs() { lock (_lock) { return TraceDirs.ToList<string>(); } }
        /// <summary>
        /// Clear the list of explicitly instrumented directories
        /// </summary>
        public void ClearTracedDirs() { lock (_lock) { TraceDirs.Clear(); } }
        /// <summary>
        /// Get the list of modules which should be instrumented even in ignore mode
        /// </summary>
        /// <returns>A list of file paths</returns>
        public List<string> GetTracedFiles() { lock (_lock) { return TraceFiles.ToList<string>(); } }
        /// <summary>
        /// Clear the list of explicitly instrumented modules
        /// </summary>
        public void ClearTracedFiles() { lock (_lock) { TraceFiles.Clear(); } }
        /// <summary>
        /// Add a directory whose contents should be instrumented in default-ignore mode
        /// </summary>
        /// <param name="path">A directory path</param>
        public void AddTracedDirectory(string path) { lock (_lock) { if (!TraceDirs.Contains(path)) { TraceDirs.Add(path); } } }
        /// <summary>
        /// Remove a directory from the list of directories to trace in ignore mode
        /// </summary>
        /// <param name="path">A directory path</param>
        public void RemoveTracedDirectory(string path) { lock (_lock) { TraceDirs.Remove(path); } }
        /// <summary>
        /// Add a module which should be instrumented in default-ignore mode
        /// </summary>
        /// <param name="path">A file path</param>
        public void AddTracedFile(string path) { lock (_lock) { if (!TraceFiles.Contains(path)) { TraceFiles.Add(path); } } }
        /// <summary>
        /// Remove a file from the list of files to trace in ignore mode
        /// </summary>
        /// <param name="path">A file path</param>
        public void RemoveTracedFile(string path) { lock (_lock) { TraceFiles.Remove(path); } }
        /// <summary>
        /// Add a directory whose contents should be ignored in default-trace mode
        /// </summary>
        /// <param name="path">A directory path</param>
        public void AddIgnoredDirectory(string path) { lock (_lock) { if (!IgnoreDirs.Contains(path)) { IgnoreDirs.Add(path); } } }
        /// <summary>
        /// Remove a directory from the list of directories to ignore in default-trace mode
        /// </summary>
        /// <param name="path">A directory path</param>
        public void RemoveIgnoredDirectory(string path) { lock (_lock) { IgnoreDirs.Remove(path); } }
        /// <summary>
        /// Add a file which should not be instrumented in default-instrument mode
        /// </summary>
        /// <param name="path">A file path</param>
        public void AddIgnoredFile(string path) { lock (_lock) { if (!IgnoreFiles.Contains(path)) { IgnoreFiles.Add(path); } } }
        /// <summary>
        /// Remove a file from the list of files to ignore in default-trace mode
        /// </summary>
        /// <param name="path">A file path</param>
        public void RemoveIgnoredFile(string path) { lock (_lock) { IgnoreFiles.Remove(path); } }

        /// <summary>
        /// Add some standard default paths to always ignore
        /// At the moment this is just the windows directory as tracing the workings of kernel32/ntdll/etc is generally not useful
        /// </summary>
        public void InitDefaultExclusions()
        {
            if (OSHelpers.OperatingSystem.IsWindows())
            {
                string? windowsDir = Environment.GetEnvironmentVariable("windir", EnvironmentVariableTarget.Machine);
                if (windowsDir is not null)
                {
                    IgnoreDirs.Add(windowsDir);
                }

                IgnoreFiles.Add("shf篸籊籔籲.txtui@siojf췳츲췥췂췂siojfios.dll"); //TODO: make+trace a test program loading this, fix whatever breaks
            }
        }
    }

    /// <summary>
    /// A binary file (.exe/.dll) that rgat can trace
    /// </summary>
    public class BinaryTarget
    {
        private string _sha1hash = "";
        private string _sha256hash = "";
        private long fileSize = 0;

        /// <summary>
        /// The network address this target resides on
        /// </summary>
        public string? RemoteHost { get; private set; } = null;
        /// <summary>
        /// True if this target was loaded on a remote host in remote tracing mode
        /// </summary>
        public bool IsRemoteBinary => RemoteHost != null;
        /// <summary>
        /// Do we have an active connection to the host this file resides on?
        /// </summary>
        public bool RemoteAccessible => rgatState.ConnectedToRemote && RemoteHost == rgatState.NetworkBridge.LastAddress;
        /// <summary>
        /// Was the initialisation data for this file sent from the tracing side to the GUI side? 
        /// Used by the GUI to see if this data needs requesting
        /// </summary>
        public bool InitialisedFromRemote { get; private set; } = false;

        /// <summary>
        /// Was the initialisation data for this file sent *to* the GUI side from the tracing side? (Used by the tracer)
        /// Used during tracing to see if the GUI needs this sent
        /// </summary>
        public bool RemoteInitDataSent { get; private set; } = false;

        /// <summary>
        /// Is this file accessible at the moment?
        /// </summary>
        public bool IsAccessible => IsRemoteBinary ? RemoteAccessible : File.Exists(FilePath);

        /// <summary>
        /// A snippet of the first bytes of the file
        /// </summary>
        public byte[]? StartBytes = null;
        /// <summary>
        /// An object representing the parsed PE File header/structure
        /// </summary>
        public PeNet.PeFile? PEFileObj = null;
        /// <summary>
        /// Is this target an rgat test binary
        /// </summary>
        public bool IsTestBinary { get; private set; }
        /// <summary>
        /// Mark this file as an rgat test binary
        /// </summary>
        public void MarkTestBinary() => IsTestBinary = true;
        /// <summary>
        /// 32 or 64 bit
        /// </summary>
        public int BitWidth = 0;
        /// <summary>
        /// Local path to the file
        /// </summary>
        public string FilePath { get; private set; } = "";
        /// <summary>
        /// Name of the file
        /// </summary>
        public string FileName { get; private set; } = "";
        /// <summary>
        /// Formatted hex preview of the file start bytes
        /// </summary>
        public string HexPreview { get; private set; } = "";
        /// <summary>
        /// Formatted ASCII preview of the start bytes
        /// </summary>
        public string ASCIIPreview { get; private set; } = "";

        private string _hexTooltip = "";

        /// <summary>
        /// This file is a DLL
        /// </summary>
        public bool IsLibrary = false;

        /// <summary>
        /// Which library export to run
        /// </summary>
        public int SelectedExportIndex = -1;
        /// <summary>
        /// The filename rgat will give the library loader
        /// </summary>
        public string LoaderName = "rgatLoadDll.exe";

        /// <summary>
        /// List of (name,ordinal) tuples of library exports
        /// </summary>
        public List<Tuple<string?, ushort>> Exports = new List<Tuple<string?, ushort>>();

        /// <summary>
        /// Settings for launching this binary including module tracing options
        /// and instrumentation toggles
        /// </summary>
        public ProcessLaunchSettings LaunchSettings { get; private set; }


        /// <summary>
        /// Create a BinaryTarget object for a binary that rgat can trace
        /// </summary>
        /// <param name="filepath">The filesystem path of the binary</param>
        /// <param name="bitWidth_">32 or 64</param>
        /// <param name="remoteAddr">The address of the remote rgat instance where this target is being traced</param>
        /// <param name="isLibrary">if the target is a library or not. This value will be used if the binary cannot be found and parsed</param>
        public BinaryTarget(string filepath, int bitWidth_ = 0, string? remoteAddr = null, bool isLibrary = false)
        {
            FilePath = filepath;
            BitWidth = bitWidth_; //overwritten by PE parser if PE
            IsLibrary = isLibrary;
            FileName = Path.GetFileName(FilePath);
            if ((rgatState.NetworkBridge.ActiveNetworking is false || rgatState.NetworkBridge.HeadlessMode) && File.Exists(filepath))
            {
                try
                {
                    ParseFile();
                    if (bitWidth_ != 0 && bitWidth_ != BitWidth)
                    {
                        Logging.RecordError($"Warning: bitwidth of {filepath} changed from provided value {bitWidth_} to {BitWidth}");
                    }
                }
                catch (Exception e)
                {
                    Logging.RecordError($"BinaryTarget.Parse threw exception {e.Message}");
                }
            }
            else
            {
                RemoteHost = remoteAddr;
            }

            if (!GlobalConfig.Settings.GetPreviousLaunchSettings(_sha1hash, out ProcessLaunchSettings? settings) || settings is null)
            {
                settings = new ProcessLaunchSettings(filepath);
                settings.TraceChoices.InitDefaultExclusions();
            }
            LaunchSettings = settings;
        }





        /// <summary>
        /// This file is on a headless remote tracing host. 
        /// Fetch some JSON serialised intialisation data to send to the GUI host.
        /// </summary>
        /// <returns>JSON serialised initialisation data</returns>
        public JToken GetRemoteLoadInitData(bool requested = false)
        {
            Debug.Assert(requested is true || RemoteInitDataSent is false, "Init data was already gathered for this target");

            JObject result = new JObject
            {
                { "Size", fileSize }
            };
            if (StartBytes is not null)
            {
                result.Add("StartBytes", StartBytes); //any benefit to obfuscating?
            }

            result.Add("SHA1", GetSHA1Hash());
            result.Add("SHA256", GetSHA256Hash());
            if (PEFileObj != null)
            {
                result.Add("PEBitWidth", BitWidth);
                result.Add("IsDLL", PEFileObj.IsDll);

                JArray exportsArr = new JArray();
                foreach (var item in Exports)
                {
                    JObject exportItem = new JObject();
                    if (item.Item1 != null)
                    {
                        exportItem.Add("Name", item.Item1);
                    }

                    exportItem.Add("Ordinal", item.Item2);
                    exportsArr.Add(exportItem);
                }
                result.Add("Exports", exportsArr);
            }
            else
            {
                result.Add("PEBitWidth", 0);
            }

            RemoteInitDataSent = true;
            return result;
        }

        private bool InitialiseFromRemoteDataInner(Newtonsoft.Json.Linq.JToken dataTok)
        {
            Logging.WriteConsole("Initing from remote");
            if (dataTok.Type != JTokenType.Object)
            {
                Logging.RecordLogEvent($"Got non-obj InitialiseFromRemoteData param <{dataTok.Type}>", Logging.LogFilterType.Error);
                return false;
            }


            JObject? data = dataTok.ToObject<JObject>();
            if (data is null)
            {
                Logging.RecordLogEvent($"InitialiseFromRemoteData missing or bad data", Logging.LogFilterType.Error);
                return false;
            }

            bool success = true;
            JToken? sizeTok = null, sha1Tok = null, sha256Tok = null, bitTok = null;
            success = success && data.TryGetValue("Size", out sizeTok) && sizeTok is not null && sizeTok.Type == JTokenType.Integer;
            success = success && data.TryGetValue("SHA1", out sha1Tok) && (sha1Tok.Type == JTokenType.String || sha1Tok == null);
            success = success && data.TryGetValue("SHA256", out sha256Tok) && (sha256Tok.Type == JTokenType.String || sha256Tok == null);
            success = success && data.TryGetValue("PEBitWidth", out bitTok) && bitTok is not null && bitTok.Type == JTokenType.Integer;
            if (!success)
            {
                Logging.RecordLogEvent($"InitialiseFromRemoteData bad or missing field", Logging.LogFilterType.Error);
                return false;
            }


            if (data.TryGetValue("IsDLL", out JToken? dllBoolTok) && dllBoolTok.Type == JTokenType.Boolean)
            {
                IsLibrary = dllBoolTok.ToObject<bool>();
            }

            if (data.TryGetValue("Exports", out JToken? exportArrTok) && exportArrTok.Type == JTokenType.Array)
            {
                JArray? exportsArr = exportArrTok.ToObject<JArray>();
                if (exportsArr is not null)
                {
                    foreach (JToken itemTok in exportsArr)
                    {
                        string? name = null;
                        ushort ordinal;
                        if (itemTok.Type == JTokenType.Object)
                        {
                            JObject? exportObj = itemTok.ToObject<JObject>();
                            if (exportObj is null)
                            {
                                continue;
                            }

                            if (exportObj.TryGetValue("Name", out JToken? nameTok) && nameTok.Type == JTokenType.String)
                            {
                                name = nameTok.ToString();
                            }
                            if (exportObj.TryGetValue("Ordinal", out JToken? ordTok) && ordTok.Type == JTokenType.Integer)
                            {
                                ordinal = ordTok.ToObject<ushort>();
                                Exports.Add(new Tuple<string?, ushort>(name, ordinal));
                            }
                        }
                    }
                }
            }


            fileSize = sizeTok!.ToObject<long>();

            if (data.TryGetValue("StartBytes", out JToken? snipTok) && snipTok is not null && snipTok.Type == JTokenType.String)
            {
                string? b64snippet = snipTok!.ToObject<string>();
                StartBytes = b64snippet is not null ? Convert.FromBase64String(b64snippet) : Array.Empty<byte>();
                InitPreviews();
            }

            if (sha1Tok is not null)
            {
                _sha1hash = sha1Tok.ToObject<string>() ?? "";
                if (_sha1hash != null && _sha1hash.Length > 0)
                {
                    rgatState.targets.RegisterTarget(this);
                }
                else
                {
                    Logging.RecordLogEvent($"InitialiseFromRemoteData invalid SHA1", Logging.LogFilterType.Error);
                    return false;
                }
            }

            if (sha256Tok is not null)
            {
                _sha256hash = sha256Tok.ToObject<string>() ?? "";
            }

            BitWidth = bitTok!.ToObject<int>();

            if (!GlobalConfig.Settings.GetPreviousLaunchSettings(_sha1hash, out ProcessLaunchSettings? settings) || settings is null)
            {
                settings = new ProcessLaunchSettings(this.FilePath);
                settings.TraceChoices.InitDefaultExclusions();
            }
            LaunchSettings = settings;

            InitialisedFromRemote = true;
            return true;
        }


        /// <summary>
        /// Load serialsed target data into this object 
        /// </summary>
        /// <param name="dataTok">JSON target data</param>
        /// <returns>Success or failure</returns>
        public bool InitialiseFromRemoteData(Newtonsoft.Json.Linq.JToken dataTok)
        {
            if (dataTok.Type != JTokenType.Object)
            {
                return false;
            }

            JObject? dataObj = dataTok.ToObject<JObject>();
            if (dataObj is not null && dataObj.TryGetValue("Error", out JToken? errTok))
            {
                Logging.RecordError("Error loading remote binary: " + errTok.ToString());
                return false;
            }
            try
            {
                return InitialiseFromRemoteDataInner(dataTok);
            }
            catch (Exception e)
            {
                Logging.RecordError($"Exception parsing Remote Target init data: {e.Message}");
                return false;
            }
        }


        /// <summary>
        /// Get an annoted hexdump snippet of the start of the target binary
        /// </summary>
        /// <returns>The snippet as a string</returns>
        public string HexTooltip()
        {
            if (StartBytes is null)
            {
                return "";
            }

            if (_hexTooltip?.Length > 0)
            {
                return _hexTooltip;
            }

            _hexTooltip = "";
            byte[] fragment;
            for (var i = 0; i < 64; i++)
            {
                fragment = StartBytes.Skip(i * 16).Take(16).ToArray();
                int fragLen = Math.Min(16, fragment.Length);
                if (fragLen == 0)
                {
                    break;
                }

                _hexTooltip += $"{i * 16:X3}  ";
                _hexTooltip += BitConverter.ToString(fragment, 0, fragLen).Replace("-", " ");
                _hexTooltip += " | ";
                _hexTooltip += TextUtils.IllustrateASCIIBytesCompact(fragment, fragLen);
                _hexTooltip += $"\n";
            }
            return _hexTooltip;
        }

        private readonly List<string> signatureHitsDIE = new List<string>();
        private readonly List<YARAScanner.YARAHit> signatureHitsYARA = new List<YARAScanner.YARAHit>();




        /// <summary>
        /// Get Yara hits recorded for the target
        /// </summary>
        /// <param name="hits">Array of YARAHit objects describing rule hits from the last scan</param>
        /// <returns>true if there were any hits</returns>
        public bool GetYaraHits(out YARAScanner.YARAHit[] hits)
        {
            hits = signatureHitsYARA.ToArray();
            return hits.Length > 0;
        }


        /// <summary>
        /// Get an array of Detect It Easy signature hits from the last scan of the target
        /// </summary>
        /// <param name="hits">Array of hit texts</param>
        /// <returns>true if there were any hits</returns>
        public bool GetDieHits(out string[] hits)
        {
            hits = signatureHitsDIE.ToArray();
            return hits.Length > 0;
        }



        private readonly object signaturesLock = new object();
        /// <summary>
        /// Purge the signature hits recorded by the last scan
        /// </summary>
        /// <param name="sigType">Type of signature hits to remove</param>
        public void ClearSignatureHits(CONSTANTS.eSignatureType sigType)
        {
            lock (signaturesLock)
            {
                switch (sigType)
                {
                    case CONSTANTS.eSignatureType.DIE:
                        signatureHitsDIE?.Clear();
                        break;
                    case CONSTANTS.eSignatureType.YARA:
                        signatureHitsYARA?.Clear();
                        break;
                    default:
                        Logging.RecordError("ClearSignatureHits: Bad signature type " + sigType);
                        break;
                }
            }
        }


        /// <summary>
        /// Record a Detect It Easy (dotnet) signature hit for this target binary
        /// </summary>
        /// <param name="hitstring">The signature hit data</param>
        public void AddDiESignatureHit(string hitstring)
        {
            lock (signaturesLock)
            {
                signatureHitsDIE.Add(hitstring);
                if (rgatState.NetworkBridge is not null && rgatState.NetworkBridge.Connected && rgatState.NetworkBridge.GUIMode is false)
                {
                    JObject hitObj = new JObject
                    {
                        { "Type", "DIE" },
                        { "TargetSHA", this._sha1hash },
                        { "Obj", hitstring }
                    };
                    rgatState.NetworkBridge.SendAsyncData("SigHit", hitObj);
                }
            }
        }

        /// <summary>
        /// Record a local Yara signature hit for this target binary
        /// It will also be sent to any connected remote sessions
        /// </summary>
        /// <param name="hit">The ScanResult hit data generated by dnYara</param>
        public void AddYaraSignatureHit(dnYara.ScanResult hit)
        {
            lock (signaturesLock)
            {
                YARAScanner.YARAHit managedHit = new YARAScanner.YARAHit(hit);
                signatureHitsYARA.Add(managedHit);
                if (rgatState.NetworkBridge.Connected && rgatState.NetworkBridge.GUIMode is false)
                {
                    JObject hitObj = new JObject
                    {
                        { "Type", "YARA" },
                        { "TargetSHA", this._sha1hash },
                        { "Obj", JObject.FromObject(managedHit) }
                    };
                    rgatState.NetworkBridge.SendAsyncData("SigHit", hitObj);
                }
            }
        }

        /// <summary>
        /// Record a remote Yara signature hit for this target binary recieved from a remote session
        /// </summary>
        /// <param name="hit">The YARAHit hit data</param>
        public void AddYaraSignatureHit(YARAScanner.YARAHit hit)
        {
            lock (signaturesLock)
            {
                signatureHitsYARA.Add(hit);
            }
        }


        private readonly object tracesLock = new object();
        private readonly Dictionary<DateTime, TraceRecord> RecordedTracesByTime = new Dictionary<DateTime, TraceRecord>();
        //private readonly Dictionary<string, TraceRecord> RecordedTraceIDs = new Dictionary<string, TraceRecord>();
        private readonly List<TraceRecord> RecordedTraces = new List<TraceRecord>();

        /// <summary>
        /// The number of traces that have been generated for this target
        /// </summary>
        public int TracesCount => RecordedTraces.Count;

        /// <summary>
        /// Delete a trace record
        /// </summary>
        /// <param name="timestarted"></param>
        public void DeleteTrace(DateTime timestarted)
        {
            lock (tracesLock)
            {
                if (RecordedTracesByTime.TryGetValue(timestarted, out TraceRecord? record) && record is not null)
                {
                    RecordedTracesByTime.Remove(timestarted);
                    RecordedTraces.Remove(record);
                }
            }
        }

        /// <summary>
        /// Retrieve the data for a trace record
        /// </summary>
        /// <param name="pid">Process ID of the trace</param>
        /// <param name="ID">Unique ID of the trace</param>
        /// <param name="result">TraceRecord of the associated trace</param>
        /// <returns>true if a trace was found</returns>
        public bool GetTraceByIDs(uint pid, long ID, out TraceRecord? result)
        {
            result = null;
            lock (tracesLock)
            {
                result = RecordedTraces.Find(x => x.PID == pid && x.randID == ID);
                return (result != null);
            }
        }

        /// <summary>
        /// Retrieve the data for a trace record
        /// </summary>
        /// <param name="time">Start time of the trace</param>
        /// <param name="ID">Unique ID of the trace</param>
        /// <param name="result">TraceRecord of the associated trace</param>
        /// <returns>true if a trace was found</returns>
        public bool GetTraceByTime(DateTime time, long ID, out TraceRecord? result)
        {
            result = null;
            lock (tracesLock)
            {
                result = RecordedTraces.Find(x => x.LaunchedTime == time && x.randID == ID);
                return (result != null);
            }
        }


        /// <summary>
        /// Get a list of start time/tracerecord pairs for thread-safe iteration
        /// </summary>
        /// <returns>A list of times and trace records</returns>
        public TraceRecord[] GetTracesUIList()
        {
            lock (tracesLock)
            {
                return RecordedTraces.ToArray();
            }
        }

        /// <summary>
        /// Get a thread safe list of all recorded traces for this binary
        /// </summary>
        /// <returns>A list of tracerecords</returns>
        public List<TraceRecord> GetTracesList()
        {
            lock (tracesLock)
            {
                return RecordedTracesByTime.Values.ToList();
            }
        }

        /// <summary>
        /// Get the SHA1 hash of this binary
        /// </summary>
        /// <returns>A SHA1 string</returns>
        public string GetSHA1Hash()
        {
            if (_sha1hash.Length > 0)
            {
                return _sha1hash;
            }

            if (File.Exists(FilePath))
            {
                ParseFile();
            }

            return _sha1hash;
        }

        /// <summary>
        /// Get the SHA256 hash of this binary
        /// </summary>
        /// <returns>A SHA256 string</returns>
        public string GetSHA256Hash()
        {
            if (_sha256hash.Length > 0)
            {
                return _sha256hash;
            }

            if (File.Exists(FilePath))
            {
                ParseFile();
            }

            return _sha1hash;
        }

        /// <summary>
        /// Load the file from disk to fill the data of this object
        /// </summary>
        private void ParseFile()
        {
            if (RemoteHost != null && InitialisedFromRemote == false)
            {
                return;
            }

            Debug.Assert(RemoteHost == null);
            try
            {
                FileInfo fileinfo = new FileInfo(FilePath);
                fileSize = fileinfo.Length;
                using FileStream fs = File.OpenRead(FilePath);
                StartBytes = new byte[Math.Min(1024, fileSize)];
                int bytesread = fs.Read(StartBytes, 0, StartBytes.Length);
                if (bytesread < StartBytes.Length)
                {
                    byte[] newBuf = new byte[StartBytes.Length];
                    Array.Copy(StartBytes, newBuf, newBuf.Length);
                    StartBytes = newBuf;
                }
                InitPreviews();

                SHA1 sha1 = new SHA1Managed();
                _sha1hash = BitConverter.ToString(sha1.ComputeHash(fs)).Replace("-", "");
                if (_sha1hash != null && _sha1hash.Length > 0)
                {
                    rgatState.targets.RegisterTarget(this);
                }

                SHA256 sha256 = new SHA256Managed();
                _sha256hash = BitConverter.ToString(sha256.ComputeHash(fs)).Replace("-", "");

                if (PeNet.PeFile.TryParse(FilePath, out PEFileObj) && PEFileObj is not null)
                {
                    IsLibrary = PEFileObj.IsDll;
                    this.BitWidth = PEFileObj.Is32Bit ? 32 :
                        (PEFileObj.Is64Bit ? 64 : 0);
                    if (IsLibrary && PEFileObj.ExportedFunctions is not null)
                    {
                        for (int ordI = 0; ordI < PEFileObj.ExportedFunctions.Length; ordI++)
                        {
                            var export = PEFileObj.ExportedFunctions[ordI];
                            Exports.Add(new Tuple<string?, ushort>(export.Name, export.Ordinal));
                        }
                    }
                }
                else
                {
                    PEFileObj = null;
                }


            }
            catch
            {
                Logging.WriteConsole("Error: Exception reading binary data");
                _sha1hash = "Error";
                _sha256hash = "Error";
                HexPreview = "Error";
            }
        }

        private void InitPreviews()
        {
            if (fileSize == 0 || StartBytes is null)
            {
                HexPreview = "[Empty File] ";
                ASCIIPreview = "[Empty File] ";
            }
            else
            {
                int previewSize = Math.Min(16, StartBytes.Length);
                HexPreview = BitConverter.ToString(StartBytes, 0, previewSize).Replace("-", " ");
                ASCIIPreview = TextUtils.IllustrateASCIIBytes(StartBytes, previewSize);
            }
        }


        /// <summary>
        /// Get a formatted file size string for display in the UI
        /// </summary>
        /// <returns>Humanised filesize string</returns>
        public string GetFileSizeString()
        {
            if (_cachedFileSize is not null)
            {
                return _cachedFileSize;
            }

            _cachedFileSize = fileSize.Bytes().ToString("0.00");
            return _cachedFileSize;
        }

        private string? _cachedFileSize = null;


        /// <summary>
        /// Create and record a new TraceRecord for an instrumentation run of this binary
        /// </summary>
        /// <param name="timeStarted">The time the trace was started</param>
        /// <param name="PID">The OS process ID of the first process</param>
        /// <param name="ID">The unique ID of the process recorded by the instrumentation tool</param>
        /// <param name="newRecord">The created TraceRecord</param>
        /// <returns>true is a new trace was created, false if an existing one was fetched</returns>
        public bool CreateNewTrace(DateTime timeStarted, uint PID, long ID, out TraceRecord newRecord)
        {
            lock (tracesLock)
            {
                if (RecordedTracesByTime.TryGetValue(key: timeStarted, value: out TraceRecord? found))
                {
                    newRecord = found;
                    return false;
                }
                newRecord = new TraceRecord(PID, ID, this, timeStarted);
                RecordedTracesByTime.Add(timeStarted, newRecord);
                RecordedTraces.Add(newRecord);
                rgatState.IncreaseLoadedTraceCount();
                return true;
            }
        }

        /// <summary>
        /// Get the first trace in the trace list. Use to just get any trace for display
        /// </summary>
        /// <returns>A TraceRecord, or null if none existed</returns>
        public TraceRecord? GetFirstTrace()
        {
            lock (tracesLock)
            {
                if (RecordedTraces.Count == 0)
                {
                    return null;
                }

                return RecordedTraces[0];
            }
        }

        /// <summary>
        /// Get the most recently recorded trace
        /// </summary>
        /// <returns>A TraceRecord, or null if none existed</returns>
        public TraceRecord? GetNewestTrace()
        {
            lock (tracesLock)
            {
                if (RecordedTraces.Count == 0)
                {
                    return null;
                }

                return RecordedTraces[^1];
            }
        }
    }
}
