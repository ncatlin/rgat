using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace rgat
{
    public enum eModuleTracingMode { eDefaultIgnore = 0, eDefaultTrace = 1 };
    public class TraceChoiceSettings
    {
        public eModuleTracingMode TracingMode
        {
            get { return _tracingMode; }
            set
            {
                _tracingMode = value;
                if (_tracingModeRef != (int)value) _tracingModeRef = (int)value;
            }
        }

        private eModuleTracingMode _tracingMode = eModuleTracingMode.eDefaultTrace;
        public int _tracingModeRef = 1;

        //Binaries in these directories will be traced in default ignore mode
        HashSet<string> traceDirs = new HashSet<string>();
        public int traceDirCount => traceDirs.Count;

        //These binaries will be traced in default ignore mode
        HashSet<string> traceFiles = new HashSet<string>();
        public int traceFilesCount => traceFiles.Count;

        //Binaries in these directories will be ignored in default trace mode
        HashSet<string> ignoreDirs = new HashSet<string>();
        public int ignoreDirsCount => ignoreDirs.Count;

        //These binaries will be ignored in default trace mode
        HashSet<string> ignoreFiles = new HashSet<string>();
        public int ignoreFilesCount => ignoreFiles.Count;

        readonly object _lock = new object();

        public List<string> GetIgnoredDirs() { lock (_lock) { return ignoreDirs.ToList<string>(); } }
        public void ClearIgnoredDirs() { lock (_lock) { ignoreDirs.Clear(); } }
        public List<string> GetIgnoredFiles() { lock (_lock) { return ignoreFiles.ToList<string>(); } }
        public void ClearIgnoredFiles() { lock (_lock) { ignoreFiles.Clear(); } }
        public List<string> GetTracedDirs() { lock (_lock) { return traceDirs.ToList<string>(); } }
        public void ClearTracedDirs() { lock (_lock) { traceDirs.Clear(); } }
        public List<string> GetTracedFiles() { lock (_lock) { return traceFiles.ToList<string>(); } }
        public void ClearTracedFiles() { lock (_lock) { traceFiles.Clear(); } }

        public void AddTracedDirectory(string path) { lock (_lock) { if (!traceDirs.Contains(path)) traceDirs.Add(path); } }
        public void RemoveTracedDirectory(string path) { lock (_lock) { traceDirs.Remove(path); } }

        public void AddTracedFile(string path) { lock (_lock) { if (!traceFiles.Contains(path)) traceFiles.Add(path); } }
        public void RemoveTracedFile(string path) { lock (_lock) { traceFiles.Remove(path); } }

        public void AddIgnoredDirectory(string path) { lock (_lock) { if (!ignoreDirs.Contains(path)) ignoreDirs.Add(path); } }
        public void RemoveIgnoredDirectory(string path) { lock (_lock) { ignoreDirs.Remove(path); } }

        public void AddIgnoredFile(string path) { lock (_lock) { if (!ignoreFiles.Contains(path)) ignoreFiles.Add(path); } }
        public void RemoveIgnoredFile(string path) { lock (_lock) { ignoreFiles.Remove(path); } }


        public void InitDefaultExclusions()
        {
            if (OSHelpers.OperatingSystem.IsWindows())
            {
                string windowsDir = Environment.GetEnvironmentVariable("windir", EnvironmentVariableTarget.Machine);
                ignoreDirs.Add(windowsDir);
                ignoreFiles.Add("shf篸籊籔籲.txtui@siojf췳츲췥췂췂siojfios.dll"); //TODO: make+trace a test program loading this, fix whatever breaks
            }
        }
    }

    public class BinaryTarget
    {
        private string _sha1hash = "";
        private string _sha256hash = "";
        private long fileSize = 0;
        public string RemoteHost { get; private set; } = null;
        public bool RemoteBinary => RemoteHost != null;
        public bool RemoteAccessible => rgatState.ConnectedToRemote && RemoteHost == rgatState.NetworkBridge.LastAddress;
        public bool RemoteInitialised { get; private set; } = false;
        public bool IsRunnable => RemoteBinary ? RemoteAccessible : File.Exists(FilePath);

        public TraceChoiceSettings traceChoices = new TraceChoiceSettings();
        public Byte[] StartBytes = null;
        public PeNet.PeFile PEFileObj;
        public bool IsTestBinary { get; private set; }
        public void MarkTestBinary() => IsTestBinary = true;

        public int BitWidth = 0;
        public string FilePath { get; private set; } = "";
        public string FileName { get; private set; } = "";
        public string HexPreview { get; private set; } = "";
        public string ASCIIPreview { get; private set; } = "";

        string _hexTooltip;

        public bool ProxyTarget = false;
        public bool IsLibrary = false;

        public int SelectedExportIndex = -1;
        public string LoaderName = "rgatLoadDll.exe";

        /// <summary>
        /// List of (name,ordinal) tuples of library exports
        /// </summary>
        public List<Tuple<string, ushort>> Exports = new List<Tuple<string, ushort>>();

        /// <summary>
        /// A binary that rgat has traced
        /// </summary>
        /// <param name="filepath">The filesystem path of the binary</param>
        /// <param name="bitWidth_">32 or 64</param>
        /// <param name="remoteAddr">The address of the remote rgat instance where this target is being traced</param>
        /// <param name="isLibrary">if the target is a library or not. This value will be used if the binary cannot be found and parsed</param>
        public BinaryTarget(string filepath, int bitWidth_ = 0, string remoteAddr = null, bool isLibrary = false)
        {
            FilePath = filepath;
            BitWidth = bitWidth_; //overwritten by PE parser if PE
            IsLibrary = isLibrary;
            FileName = Path.GetFileName(FilePath);
            if (remoteAddr == null && File.Exists(filepath))
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

            RemoteHost = remoteAddr;

            traceChoices.InitDefaultExclusions();
        }


        public JToken GetRemoteLoadInitData()
        {
            JObject result = new JObject();
            result.Add("Size", fileSize);
            result.Add("StartBytes", StartBytes); //any benefit to obfuscating?
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
                        exportItem.Add("Name", item.Item1);
                    exportItem.Add("Ordinal", item.Item2);
                    exportsArr.Add(exportItem);
                }
                result.Add("Exports", exportsArr);
            }
            else
            {
                result.Add("PEBitWidth", 0);
            }
            return result;
        }


        bool InitialiseFromRemoteDataInner(Newtonsoft.Json.Linq.JToken dataTok)
        {
            Console.WriteLine("Initing from remote");
            if (dataTok.Type != JTokenType.Object)
            {
                Logging.RecordLogEvent($"Got non-obj InitialiseFromRemoteData param <{dataTok.Type}>", Logging.LogFilterType.TextError);
                return false;
            }


            JObject data = dataTok.ToObject<JObject>();
            bool success = true;
            JToken sizeTok = null, snipTok = null, sha1Tok = null, sha256Tok = null, bitTok = null;
            success = success && data.TryGetValue("Size", out sizeTok) && sizeTok.Type == JTokenType.Integer;
            success = success && data.TryGetValue("StartBytes", out snipTok) && snipTok.Type == JTokenType.String;
            success = success && data.TryGetValue("SHA1", out sha1Tok) && (sha1Tok.Type == JTokenType.String || sha1Tok == null);
            success = success && data.TryGetValue("SHA256", out sha256Tok) && (sha256Tok.Type == JTokenType.String || sha256Tok == null);
            success = success && data.TryGetValue("PEBitWidth", out bitTok) && bitTok.Type == JTokenType.Integer;
            if (!success)
            {
                Logging.RecordLogEvent($"InitialiseFromRemoteData bad or missing field", Logging.LogFilterType.TextError);
                return false;
            }

            if (data.TryGetValue("IsDLL", out JToken dllBoolTok) && dllBoolTok.Type == JTokenType.Boolean)
            {
                IsLibrary = dllBoolTok.ToObject<bool>();
            }

            if (data.TryGetValue("Exports", out JToken exportArrTok) && exportArrTok.Type == JTokenType.Array)
            {
                JArray exportsArr = exportArrTok.ToObject<JArray>();
                foreach (JToken itemTok in exportsArr)
                {
                    string name = null;
                    ushort ordinal;
                    if (itemTok.Type == JTokenType.Object)
                    {
                        JObject exportObj = itemTok.ToObject<JObject>();
                        if (exportObj.TryGetValue("Name", out JToken nameTok) && nameTok.Type == JTokenType.String)
                        {
                            name = nameTok.ToString();
                        }
                        if (exportObj.TryGetValue("Ordinal", out JToken ordTok) && ordTok.Type == JTokenType.Integer)
                        {
                            ordinal = ordTok.ToObject<ushort>();
                            Exports.Add(new Tuple<string, ushort>(name, ordinal));
                        }
                    }
                }
            }


            fileSize = sizeTok.ToObject<long>();
            StartBytes = Convert.FromBase64String(snipTok.ToObject<string>());
            InitPreviews();

            _sha1hash = sha1Tok.ToObject<string>() ?? "";
            if (_sha1hash != null && _sha1hash.Length > 0)
                rgatState.targets.RegisterTargetSHA1(_sha1hash, this);

            _sha256hash = sha256Tok.ToObject<string>() ?? "";
            BitWidth = bitTok.ToObject<int>();

            RemoteInitialised = true;
            return true;
        }


        public bool InitialiseFromRemoteData(Newtonsoft.Json.Linq.JToken dataTok)
        {
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


        public string HexTooltip()
        {
            if (_hexTooltip?.Length > 0) return _hexTooltip;
            byte[] fragment;
            for (var i = 0; i < 64; i++)
            {
                fragment = StartBytes.Skip(i * 16).Take(16).ToArray();
                int fragLen = Math.Min(16, fragment.Length);
                if (fragLen == 0) break;

                _hexTooltip += $"{i * 16:X3}  ";
                _hexTooltip += BitConverter.ToString(fragment, 0, fragLen).Replace("-", " ");
                _hexTooltip += " | ";
                _hexTooltip += TextUtils.IllustrateASCIIBytesCompact(fragment, fragLen);
                _hexTooltip += $"\n";
            }
            return _hexTooltip;
        }


        List<string> signatureHitsDIE = new List<string>();
        List<dnYara.ScanResult> signatureHitsYARA = new List<dnYara.ScanResult>();

        Dictionary<string, string> _traceConfiguration = new Dictionary<string, string>();

        public Dictionary<string, string> GetCurrentTraceConfiguration()
        {
            lock (tracesLock) return new Dictionary<string, string>(_traceConfiguration);
        }
        public void SetTraceConfig(string key, string value)
        {
            if (key.Contains('@') || value.Contains('@')) { Console.WriteLine("invalid character '@' in config item"); return; }
            lock (tracesLock)
            {
                _traceConfiguration[key] = value;
            }
        }


        public bool GetYaraHits(out dnYara.ScanResult[] hits)
        {
            hits = signatureHitsYARA.ToArray();
            return hits.Length > 0;
        }


        public bool GetDieHits(out string[] hits)
        {
            hits = signatureHitsDIE.ToArray();
            return hits.Length > 0;
        }



        private readonly Object signaturesLock = new Object();
        public void ClearSignatureHits(RGAT_CONSTANTS.eSignatureType sigType)
        {
            lock (signaturesLock)
            {
                switch (sigType)
                {
                    case RGAT_CONSTANTS.eSignatureType.DIE:
                        signatureHitsDIE?.Clear();
                        break;
                    case RGAT_CONSTANTS.eSignatureType.YARA:
                        signatureHitsYARA?.Clear();
                        break;
                    default:
                        Logging.RecordError("ClearSignatureHits: Bad signature type " + sigType);
                        break;
                }
            }
        }


        public void AddDiESignatureHit(string hits)
        {
            lock (signaturesLock)
            {
                signatureHitsDIE.Add(hits);
            }
        }


        public void AddYaraSignatureHit(dnYara.ScanResult hit)
        {
            lock (signaturesLock)
            {
                signatureHitsYARA.Add(hit);
            }
        }


        private readonly Object tracesLock = new Object();
        private Dictionary<DateTime, TraceRecord> RecordedTraces = new Dictionary<DateTime, TraceRecord>();
        private Dictionary<string, TraceRecord> RecordedTraceIDs = new Dictionary<string, TraceRecord>();
        private List<TraceRecord> TraceRecordsList = new List<TraceRecord>();

        public int TracesCount => TraceRecordsList.Count;

        public void DeleteTrace(DateTime timestarted)
        {
            lock (tracesLock)
            {
                if (RecordedTraces.ContainsKey(timestarted))
                {
                    RecordedTraces.Remove(timestarted);
                }
            }
        }

        public bool GetTraceByIDs(uint pid, long ID, out TraceRecord result)
        {
            result = null;
            lock (tracesLock)
            {
                result = TraceRecordsList.Find(x => x.PID == pid && x.randID == ID);
                return (result != null);
            }
        }

        public List<Tuple<DateTime, TraceRecord>> GetTracesUIList()
        {
            List<Tuple<DateTime, TraceRecord>> uilist = new List<Tuple<DateTime, TraceRecord>>();
            lock (tracesLock)
            {
                foreach (var rec in RecordedTraces)
                {
                    uilist.Add(new Tuple<DateTime, TraceRecord>(rec.Key, rec.Value));
                }
            }
            return uilist;
        }

        public List<TraceRecord> GetTracesList()
        {
            lock (tracesLock)
            {
                return RecordedTraces.Values.ToList();
            }
        }





        public string GetSHA1Hash()
        {
            if (_sha1hash.Length > 0) return _sha1hash;
            if (File.Exists(FilePath)) ParseFile();
            return _sha1hash;
        }

        public string GetSHA256Hash()
        {
            if (_sha256hash.Length > 0) return _sha256hash;
            if (File.Exists(FilePath)) ParseFile();
            return _sha1hash;
        }

        private void ParseFile()
        {
            if (RemoteHost != null && RemoteInitialised == false) return;
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
                    rgatState.targets.RegisterTargetSHA1(_sha1hash, this);

                SHA256 sha256 = new SHA256Managed();
                _sha256hash = BitConverter.ToString(sha256.ComputeHash(fs)).Replace("-", "");

                if (PeNet.PeFile.TryParse(FilePath, out PEFileObj))
                {
                    IsLibrary = PEFileObj.IsDll;
                    this.BitWidth = PEFileObj.Is32Bit ? 32 :
                        (PEFileObj.Is64Bit ? 64 : 0);
                    if (IsLibrary)
                    {
                        for (int ordI = 0; ordI < PEFileObj.ExportedFunctions.Length; ordI++)
                        {
                            var export = PEFileObj.ExportedFunctions[ordI];
                            Exports.Add(new Tuple<string, ushort>(export.Name, export.Ordinal));
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
                Console.WriteLine("Error: Exception reading binary data");
                _sha1hash = "Error";
                _sha256hash = "Error";
                HexPreview = "Error";
            }
        }

        void InitPreviews()
        {
            int previewSize = Math.Min(16, StartBytes.Length);
            if (fileSize == 0)
            {
                HexPreview = "[Empty File] ";
                ASCIIPreview = "[Empty File] ";
            }
            else
            {
                HexPreview = BitConverter.ToString(StartBytes, 0, previewSize).Replace("-", " ");
                ASCIIPreview = TextUtils.IllustrateASCIIBytes(StartBytes, previewSize);
            }
        }

        public string GetFileSizeString()
        {
            return String.Format(new FileSizeFormatProvider(), "{0:fs}", fileSize);
        }





        public bool CreateNewTrace(DateTime timeStarted, uint PID, long ID, out TraceRecord newRecord)
        {
            lock (tracesLock)
            {
                if (RecordedTraces.TryGetValue(timeStarted, out newRecord))
                {
                    return false;
                }
                newRecord = new TraceRecord(PID, ID, this, timeStarted);
                RecordedTraces.Add(timeStarted, newRecord);
                TraceRecordsList.Add(newRecord);
                rgatState.IncreaseLoadedTraceCount();
                return true;
            }
        }

        public TraceRecord GetFirstTrace()
        {
            lock (tracesLock)
            {
                if (TraceRecordsList.Count == 0) return null;
                return TraceRecordsList[0];
            }
        }

        public TraceRecord GetNewestTrace()
        {
            lock (tracesLock)
            {
                if (TraceRecordsList.Count == 0) return null;
                return TraceRecordsList[^1];
            }
        }
    }
}
