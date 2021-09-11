using DiELibDotNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace rgat
{
    public class DetectItEasy
    {

        DiELibDotNet.DieLib dielib;

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
                string parent = Directory.GetParent(sigsDiEPath).FullName;
                if (Directory.Exists(parent)) sigsDiEPath = parent;
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


        public void StartDetectItEasyScan(BinaryTarget targ)
        {
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
        Dictionary<BinaryTarget, ulong> DIEScanHandles = new Dictionary<BinaryTarget, ulong>();


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
            targ.ClearSignatureHits(CONSTANTS.eSignatureType.DIE);

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
                    result = scanner.ScanFile(handle, targ.FilePath, options, out string error);
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


        public DieScript.SCANPROGRESS GetDIEScanProgress(BinaryTarget targ)
        {
            if (DIEScanHandles.TryGetValue(targ, out ulong handle))
            {
                return dielib.QueryProgress(handle);
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
    }
}
