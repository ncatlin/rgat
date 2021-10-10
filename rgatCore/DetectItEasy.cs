using DiELibDotNet;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace rgat
{
    /// <summary>
    /// Interface to DiELibDotNet, the Detect It Easy signature scanning library
    /// </summary>
    public class DetectItEasy
    {
        private readonly DiELibDotNet.DieLib dielib;

        /// <summary>
        /// Create a DIE scanner
        /// </summary>
        /// <param name="DBPath">Path to the DIE signatures</param>
        public DetectItEasy(string DBPath)
        {
            dielib = new DiELibDotNet.DieLib(GetScriptsPath(DBPath));
        }


        //takes a directory path. if it contains a db/_init path - returns db folder
        //otherwise if it contains a db.zip file - returns that
        //this allows a bit of flexibiilty if the user wants to cut down on files 
        private static string GetScriptsPath(string sigsDiEPath)
        {
            if (Path.GetDirectoryName(sigsDiEPath) == "db")
            {
                string? parent = Directory.GetParent(sigsDiEPath)?.FullName;
                if (parent is not null && Directory.Exists(parent))
                {
                    sigsDiEPath = parent;
                }
            }

            //Don't trust arbitrary scripts passed to jint, so only use original repo
            foreach (string path in Directory.GetDirectories(sigsDiEPath).Where(dirpath => Path.GetFileName(dirpath).StartsWith("horsicq_")))
            {
                if (File.Exists(Path.Combine(path, "db", "_init")))
                {
                    return Path.Combine(path, "db");
                }
            }
            if (File.Exists(Path.Combine(sigsDiEPath, "db.zip")))
            {
                return Path.Combine(sigsDiEPath, "db.zip");
            }
            return "";
        }


        /// <summary>
        /// Begin a scan
        /// </summary>
        /// <param name="targ">Target to scan</param>
        /// <param name="reload">If rules should be reloaded</param>
        public void StartDetectItEasyScan(BinaryTarget targ, bool reload = false)
        {
            targ.ClearSignatureHits(CONSTANTS.eSignatureType.DIE);
            if (rgatState.ConnectedToRemote && rgatState.NetworkBridge.GUIMode)
            {
                JObject cmdparams = new JObject();
                cmdparams.Add("Type", "DIE");
                cmdparams.Add("TargetSHA1", targ.GetSHA1Hash());
                cmdparams.Add("Reload", reload);
                rgatState.NetworkBridge.SendCommand("StartSigScan", null, null, cmdparams);
                return;
            }

            if (!dielib.DatabaseLoaded)
            {
                return;
            }

            if (!File.Exists(targ.FilePath))
            {
                return;
            }

            ulong handle = 0;
            lock (scansLock)
            {
                handle = dielib.CreateScanHandle();

                if (DIEScanHandles.ContainsKey(targ))
                {
                    DIEScanHandles[targ] = handle;
                }
                else
                {
                    DIEScanHandles.Add(targ, handle);
                }
            }

            List<object> args = new List<object>() { dielib, targ, handle };

            Thread DIEThread = new Thread(new ParameterizedThreadStart(DetectItScanThread));
            DIEThread.Name = "DetectItEasy_" + targ.FileName;
            DIEThread.Start(args);
        }

        private readonly object scansLock = new object();
        private readonly Dictionary<BinaryTarget, ulong> DIEScanHandles = new Dictionary<BinaryTarget, ulong>();


        /// <summary>
        /// Cancel all scans
        /// </summary>
        public void CancelAllScans()
        {
            lock (scansLock)
            {
                foreach (ulong handle in DIEScanHandles.Values)
                {
                    dielib.CancelScan(handle);
                }
            }
        }

        /// <summary>
        /// Last scan error
        /// </summary>
        public string LastError => dielib.LastError;
        /// <summary>
        /// Did the database load successfully
        /// </summary>
        public bool ScriptsLoaded => dielib.DatabaseLoaded;
        /// <summary>
        /// Number of scripts loaded
        /// </summary>
        public int NumScriptsLoaded => dielib.CountScriptsLoaded;
        /// <summary>
        /// Get the array of loaded signatures
        /// </summary>
        public DieScriptEngine.SIGNATURE_RECORD[] GetSignatures => dielib.GetSignatures;

        /// <summary>
        /// Reload the scripts database
        /// </summary>
        /// <param name="path"></param>
        public void ReloadDIEScripts(string path)
        {
            dielib.ReloadScriptDatabase(GetScriptsPath(path));
        }

        /// <summary>
        /// A DIE scan thread
        /// </summary>
        /// <param name="argslist">scanner, target args object</param> 
        private static void DetectItScanThread(object? argslist)
        {
            if (argslist is null)
            {
                return;
            }

            List<object> args = (List<object>)argslist;
            DiELibDotNet.DieLib scanner = (DiELibDotNet.DieLib)args[0];
            BinaryTarget targ = (BinaryTarget)args[1];

            if (!scanner.DatabaseLoaded)
            {
                return;
            }

            ulong handle = (ulong)args[2];


            string result;
            try
            {
                DiELibDotNet.DieScript.SCAN_OPTIONS options = new DiELibDotNet.DieScript.SCAN_OPTIONS();
                options.showOptions = true;
                options.showVersion = true;
                options.showType = true;
                options.deepScan = false; //very slow
                while (true)
                {
                    result = scanner.ScanFile(handle, targ.FilePath, options, out string? error);
                    if (result == "Reload In Progress")
                    {
                        Thread.Sleep(100);
                        continue;
                    }
                    else
                    {
                        if (error?.Length > 0)
                        {

                            Logging.RecordLogEvent($"DetectItEasy error: '{error}' for target {targ.FilePath}");
                        }
                        break;
                    }
                }
                scanner.CloseScanHandle(handle);
            }
            catch (Exception e)
            {
                result = "DIElib Scan failed with exeption: " + e.Message;
            }

            Logging.RecordLogEvent($"DetectItEasy result {result} for target {targ.FilePath}", Logging.LogFilterType.Debug);
            targ.AddDiESignatureHit(result);
        }


        /// <summary>
        /// Get progress of the current scan for a target
        /// </summary>
        /// <param name="targ">BinaryTarget being scanned</param>
        /// <returns>Progress value</returns>
        public DieScript.SCANPROGRESS? GetDIEScanProgress(BinaryTarget targ)
        {
            lock (scansLock)
            {
                if (DIEScanHandles.TryGetValue(targ, out ulong handle))
                {
                    return dielib?.QueryProgress(handle);
                }
                return new DieScript.SCANPROGRESS();
            }
        }

        /// <summary>
        /// Cancel the scan for the specified target
        /// </summary>
        /// <param name="targ">Target to cancel the scan for</param>
        public void CancelDIEScan(BinaryTarget targ)
        {
            lock (scansLock)
            {
                if (DIEScanHandles.TryGetValue(targ, out ulong handle))
                {
                    dielib.CancelScan(handle);
                }
            }
        }

        private readonly DateTime _lastCheck = DateTime.MinValue;
        /// <summary>
        /// Date of the newest signature in the DetectItEasy signatures directory of this machine
        /// </summary>
        public DateTime NewestSignature { get; private set; } = DateTime.MinValue;
        /// <summary>
        /// Date of the newest signature in the DetectItEasy signatures directory of the remote machine
        /// </summary>
        public DateTime EndpointNewestSignature = DateTime.MinValue;
        /// <summary>
        /// If the available signatures are newer than those on the remote host
        /// </summary>
        public bool StaleRemoteSignatures => (EndpointNewestSignature != DateTime.MinValue && EndpointNewestSignature > NewestSignature);

        private DateTime LatestSignatureChange(string rulesDir)
        {
            if ((DateTime.Now - _lastCheck).TotalSeconds < 20)
            {
                return NewestSignature;
            }

            var sigDirs = Directory.GetDirectories(rulesDir, "*", SearchOption.AllDirectories)
                .SelectMany(x => new List<DateTime>() { Directory.GetCreationTime(x), Directory.GetLastWriteTime(x) });

            var sigFiles = Directory.GetFiles(rulesDir, "*", SearchOption.AllDirectories)
                .Where(x => x.EndsWith(".sg", StringComparison.OrdinalIgnoreCase) || !x.Contains("."))
                .SelectMany(x => new List<DateTime>() { File.GetCreationTime(x), File.GetLastWriteTime(x) }.ToList()).ToList();

            DateTime newestDir = sigDirs.Max();
            DateTime newestFile = sigFiles.Max();

            NewestSignature = newestDir > newestFile ? newestDir : newestFile;
            return NewestSignature;
        }


        /// <summary>
        /// Zip up the DIE sigs database and sent it to the remote party
        /// </summary>
        public static void UploadSignatures()
        {
            try
            {
                string tempfile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                System.IO.Compression.ZipFile.CreateFromDirectory(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.DiESigsDirectory), tempfile);
                if (File.Exists(tempfile))
                {
                    byte[] zipfile = File.ReadAllBytes(tempfile);
                    JObject paramObj = new JObject();
                    paramObj.Add("Type", "DIE");
                    paramObj.Add("Zip", zipfile);
                    rgatState.NetworkBridge.SendCommand("UploadSignatures", null, null, paramObj);
                    File.Delete(tempfile);
                    rgatState.NetworkBridge.AddNetworkDisplayLogMessage("Uploaded DIE signatures", Themes.eThemeColour.eGoodStateColour);
                }
            }
            catch (Exception e)
            {
                Logging.RecordException($"Failed to upload DIE signatures: {e.Message}", e);
                rgatState.NetworkBridge.AddNetworkDisplayLogMessage("Failed to upload DIE signatures", Themes.eThemeColour.eBadStateColour);
            }


        }

        //todo this is a copy of the routine in yarascan. put a generic version somewhere
        /// <summary>
        /// Replace the DIE signatures directory
        /// </summary>
        /// <param name="zipfile">A zipfile of signatures</param>
        public static void ReplaceSignatures(byte[] zipfile)
        {
            Logging.WriteConsole($"Replacing die sigs with zip size {zipfile.Length}");
            try
            {
                string tempfile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                File.WriteAllBytes(tempfile, zipfile);
                if (File.Exists(tempfile))
                {
                    rgatState.DIELib?.CancelAllScans();
                    string original = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.DiESigsDirectory);
                    Directory.Delete(original, true);
                    System.IO.Compression.ZipFile.ExtractToDirectory(tempfile, original, true);
                    File.Delete(tempfile);
                    OperationModes.BridgedRunner.SendSigDates();
                    rgatState.NetworkBridge.SendLog("DIE signature replacement completed successfully", Logging.LogFilterType.Info);
                }
            }
            catch (Exception e)
            {
                Logging.RecordException($"Failed to replace signatures: {e.Message}", e);
                rgatState.NetworkBridge.SendLog($"DIE signature sync failed: {e.Message}", Logging.LogFilterType.Error);
            }
        }
    }
}
