﻿using DiELibDotNet;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace rgat
{
    public class DetectItEasy
    {
        readonly DiELibDotNet.DieLib dielib;

        public DetectItEasy(string DBPath)
        {
            dielib = new DiELibDotNet.DieLib(GetScriptsPath(DBPath));
        }


        //takes a directory path. if it contains a db/_init path - returns db folder
        //otherwise if it contains a db.zip file - returns that
        //this allows a bit of flexibiilty if the user wants to cut down on files 
        string GetScriptsPath(string sigsDiEPath)
        {
            if (Path.GetDirectoryName(sigsDiEPath) == "db")
            {
                string? parent = Directory.GetParent(sigsDiEPath)?.FullName;
                if (parent is not null && Directory.Exists(parent))
                    sigsDiEPath = parent;
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

            if (!dielib.DatabaseLoaded) return;
            if (!File.Exists(targ.FilePath)) return;

            ulong handle = 0;
            lock (scansLock)
            {
                handle = dielib.CreateScanHandle();

                if (DIEScanHandles.ContainsKey(targ))
                    DIEScanHandles[targ] = handle;
                else
                    DIEScanHandles.Add(targ, handle);
            }

            List<object> args = new List<object>() { dielib, targ, handle };

            Thread DIEThread = new Thread(new ParameterizedThreadStart(DetectItScanThread));
            DIEThread.Name = "DetectItEasy_" + targ.FileName;
            DIEThread.Start(args);
        }

        readonly object scansLock = new object();
        readonly Dictionary<BinaryTarget, ulong> DIEScanHandles = new Dictionary<BinaryTarget, ulong>();


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

        public string LastError => dielib.LastError;
        public bool ScriptsLoaded => dielib.DatabaseLoaded;
        public int NumScriptsLoaded => dielib.CountScriptsLoaded;
        public DieScriptEngine.SIGNATURE_RECORD[] GetSignatures => dielib.GetSignatures;


        public void ReloadDIEScripts(string path)
        {
            dielib.ReloadScriptDatabase(GetScriptsPath(path));
        }

        static void DetectItScanThread(object argslist)
        {

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

            Logging.RecordLogEvent($"DetectItEasy result {result} for target {targ.FilePath}", Logging.LogFilterType.TextDebug);
            targ.AddDiESignatureHit(result);
        }


        public DieScript.SCANPROGRESS? GetDIEScanProgress(BinaryTarget targ)
        {
            if (DIEScanHandles.TryGetValue(targ, out ulong handle))
            {
                return dielib?.QueryProgress(handle);
            }
            return new DieScript.SCANPROGRESS();
        }

        public void CancelDIEScan(BinaryTarget targ)
        {
            if (DIEScanHandles.TryGetValue(targ, out ulong handle))
            {
                dielib.CancelScan(handle);
            }
        }

        readonly DateTime _lastCheck = DateTime.MinValue;
        public DateTime NewestSignature { get; private set; } = DateTime.MinValue;
        public DateTime EndpointNewestSignature = DateTime.MinValue;
        public bool StaleRemoteSignatures => (EndpointNewestSignature != DateTime.MinValue && EndpointNewestSignature > NewestSignature);

        DateTime LatestSignatureChange(string rulesDir)
        {
            if (NewestSignature != null && (DateTime.Now - _lastCheck).TotalSeconds < 20) return NewestSignature;

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


        public void UploadSignatures()
        {
            try
            {
                string tempfile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                System.IO.Compression.ZipFile.CreateFromDirectory(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory), tempfile);
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
                Logging.RecordError($"Failed to upload DIE signatures: {e.Message}");
                rgatState.NetworkBridge.AddNetworkDisplayLogMessage("Failed to upload DIE signatures", Themes.eThemeColour.eBadStateColour);
            }


        }

        //todo this is a copy of the routine in yarascan. put a generic version somewhere
        public void ReplaceSignatures(byte[] zipfile)
        {
            Console.WriteLine($"Replacing die sigs with zip size {zipfile.Length}");
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
                    rgatState.NetworkBridge.SendLog("DIE signature replacement completed successfully", Logging.LogFilterType.TextInfo);
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to replace signatures: {e.Message}");
                rgatState.NetworkBridge.SendLog($"DIE signature sync failed: {e.Message}", Logging.LogFilterType.TextError);
            }
        }
    }
}
