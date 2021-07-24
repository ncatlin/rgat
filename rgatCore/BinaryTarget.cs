using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace rgatCore
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
        public int _tracingModeRef;

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

        public List<string> GetIgnoredDirs() => ignoreDirs.ToList<string>();
        public List<string> GetIgnoredFiles() => ignoreFiles.ToList<string>();
        public List<string> GetTracedDirs() => traceDirs.ToList<string>();
        public List<string> GetTracedFiles() => traceFiles.ToList<string>();

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
        public void ClearSignatureHits(eSignatureType sigType)
        {

            switch (sigType)
            {
                case eSignatureType.eDetectItEasy:
                    lock (signaturesLock) { signatureHitsDIE?.Clear(); }
                    break;
                case eSignatureType.eYARA:
                    lock (signaturesLock) { signatureHitsYARA?.Clear(); }
                    break;
                default:
                    Console.WriteLine("ClearSignatureHits: Bad signature type " + sigType);
                    break;
            }
        }


        public void AddDiESignatureHit(string hits)
        {
            signatureHitsDIE.Add(hits);
        }


        public void AddYaraSignatureHit(dnYara.ScanResult hit)
        {
            signatureHitsYARA.Add(hit);
        }


        private readonly Object tracesLock = new Object();
        private Dictionary<DateTime, TraceRecord> RecordedTraces = new Dictionary<DateTime, TraceRecord>();
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


        public BinaryTarget(string filepath, int bitWidth_ = 0)
        {
            FilePath = filepath;
            BitWidth = bitWidth_; //overwritten by PE parser if PE
            FileName = Path.GetFileName(FilePath);
            if (File.Exists(filepath))
            {
                try
                {
                    FileInfo fileinfo = new FileInfo(filepath);
                    fileSize = fileinfo.Length;
                    ParseFile();
                    if (bitWidth_ != 0 && bitWidth_ != BitWidth)
                    {
                        Console.WriteLine($"Warning: bitwidth changed from provided value {bitWidth_} to {BitWidth}");
                    }
                }
                catch { }
            }
            traceChoices.InitDefaultExclusions();
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
            try
            {
                using FileStream fs = File.OpenRead(FilePath);
                StartBytes = new byte[Math.Min(1024, fileSize)];
                int bytesread = fs.Read(StartBytes, 0, StartBytes.Length);
                int previewSize = Math.Min(16, bytesread);
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

                SHA1 sha1 = new SHA1Managed();
                _sha1hash = BitConverter.ToString(sha1.ComputeHash(fs)).Replace("-", "");
                SHA256 sha256 = new SHA256Managed();
                _sha256hash = BitConverter.ToString(sha256.ComputeHash(fs)).Replace("-", "");

                if (PeNet.PeFile.TryParse(FilePath, out PEFileObj))
                {
                    this.BitWidth = PEFileObj.Is32Bit ? 32 :
                        (PEFileObj.Is64Bit ? 64 : 0);
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
        public string GetFileSizeString()
        {
            return String.Format(new FileSizeFormatProvider(), "{0:fs}", fileSize);
        }





        public bool CreateNewTrace(DateTime timeStarted, uint PID, uint ID, out TraceRecord newRecord)
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
