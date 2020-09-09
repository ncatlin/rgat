using DiELibDotNet;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace rgatCore
{
    class DetectItEasy
    {

        DiELibDotNet.DieLib dielib;

        public DetectItEasy(string DBPath)
        {
            dielib = new DiELibDotNet.DieLib(DBPath);
        }


        public void StartDetectItEasyScan(BinaryTarget targ)
        {
            ulong handle = 0;
            lock (scansLock)
            {
                handle = dielib.CreateScanHandle();

                if (DIEScanHandles.ContainsKey(targ))
                    DIEScanHandles[targ] = handle;
                else
                    DIEScanHandles.Add(targ, handle);
            }

            List<object> args = new List<object>(){ dielib, targ, handle};

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


        public void ReloadDIEScripts()
        {
            dielib.ReloadScriptDatabase();
        }

        static void DetectItScanThread(object argslist)
        {
            List<object> args = (List<object>)argslist;
            DiELibDotNet.DieLib scanner = (DiELibDotNet.DieLib)args[0];
            BinaryTarget targ = (BinaryTarget)args[1];
            ulong handle = (ulong)args[2];

            targ.ClearSignatureHits(eSignatureType.eDetectItEasy);

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
                    result = scanner.ScanFile(handle, targ.FilePath, options);
                    if (result == "Reload In Progress")
                    {
                        Thread.Sleep(100);
                        continue;
                    }
                    else break;
                }
                scanner.CloseScanHandle(handle);
            }
            catch (Exception e)
            {
                result = "DIElib Scan failed with exeption: " + e.Message;
            }
            targ.AddSignatureHits(result, eSignatureType.eDetectItEasy);
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
