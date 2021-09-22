﻿using dnYara;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace rgat
{

    public class YARAScan
    {
        readonly object _scanLock = new object();
        readonly YaraContext ctx;

        CompiledRules loadedRules = null;

        public enum eYaraScanProgress { eRunning, eComplete, eNotStarted, eFailed };

        readonly Dictionary<BinaryTarget, eYaraScanProgress> targetScanProgress = new Dictionary<BinaryTarget, eYaraScanProgress>();

        [DllImport("libyara.dll")]
        private static extern void LibraryExistsTestMethod();


        public YARAScan(string rulesDir)
        {
            if (!CheckLibraryExists()) throw new DllNotFoundException("libyara.dll not available");

            ctx = new YaraContext();

            RefreshRules(rulesDir);
        }

        // have to check libyara exists before attempting to use dnYara
        // otherwise the destructor will crash us when it fails
        bool CheckLibraryExists()
        {
            try
            {
                LibraryExistsTestMethod();
            }
            catch (Exception e)
            {
                if (e.Message.StartsWith("Unable to find an entry point")) //method not found - so library does exist
                {
                    return true;
                }
                if (e.Message.StartsWith("Unable to load DLL")) //library does not exist
                {
                    return false;
                }
                Logging.RecordLogEvent($"Unexpected error {e.Message} when checking for yara");
            }

            return false;
        }

        ~YARAScan()
        {
            try
            {
                loadedRules?.Release();
            }
            catch (Exception e)
            {

            }
        }

        public class YARAHit
        {
            public YARAHit(dnYara.ScanResult marshalledHit)
            {
                MatchingRule = marshalledHit.MatchingRule;
                Matches = new Dictionary<string, List<YaraHitMatch>>();
                foreach (var kvp in marshalledHit.Matches)
                {
                    List<YaraHitMatch> sigHits = new List<YaraHitMatch>();
                    foreach (var hit in kvp.Value)
                    {
                        sigHits.Add(new YaraHitMatch() { Base = hit.Base, Data = hit.Data, Offset = hit.Offset });
                    }
                    Matches.Add(kvp.Key, sigHits);
                }
            }

            public YARAHit()
            {
            }


            public Rule MatchingRule;
            public Dictionary<string, List<YARAHit.YaraHitMatch>> Matches;

            public class YaraHitMatch
            {
                public YaraHitMatch()
                {

                }
                public long Base { get; set; }
                public long Offset { get; set; }
                public byte[] Data { get; set; }
            }

        }



        //scan a target binary file
        public void StartYARATargetScan(BinaryTarget targ, bool reload = false)
        {
            targ.ClearSignatureHits(CONSTANTS.eSignatureType.YARA);
            if (rgatState.ConnectedToRemote && rgatState.NetworkBridge.GUIMode)
            {
                JObject cmdparams = new JObject();
                cmdparams.Add("Type", "YARA");
                cmdparams.Add("Reload", reload);
                cmdparams.Add("TargetSHA1", targ.GetSHA1Hash());
                rgatState.NetworkBridge.SendCommand("StartSigScan", null, null, cmdparams);
                return;
            }
            try
            {
                if (reload)
                {
                    RefreshRules(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory), forceRecompile: true);
                }

                if (!File.Exists(targ.FilePath)) return;

                List<object> args = new List<object>() { targ };

                Thread YaraThread = new Thread(new ParameterizedThreadStart(YARATargetScanThread));
                YaraThread.Name = "YARA_F_" + targ.FileName;
                YaraThread.Start(args);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Error starting YARA scan: {e}");
            }
        }

        public void RefreshRules(string rulesDir, bool forceRecompile = false)
        {

            //find precompiled rules files in the current directory of the form "[disk_|mem_][UINT]_.yarac"
            string[] filesList = Directory.GetFiles(rulesDir, "precompiled_rules*.yarac", SearchOption.TopDirectoryOnly);
            string? compiledFile = null;

            //get the most recently modified disk_ and mem_ yarac files
            foreach (string filepath in filesList)
            {
                string filename = Path.GetFileName(filepath);
                if (filename.StartsWith("precompiled_rules"))
                {
                    if (compiledFile == null || File.GetLastWriteTime(filepath) > File.GetLastWriteTime(compiledFile))
                        compiledFile = filepath;
                }
            }

            //find the last time the compiled file was modified
            DateTime thresholdDate = DateTime.MinValue;
            try
            {
                DateTime sigsCompileDate = File.GetLastWriteTime(compiledFile);
                if (sigsCompileDate > thresholdDate)
                    thresholdDate = sigsCompileDate;
            }
            catch
            {
                thresholdDate = DateTime.MinValue;
            }

            //see if any directories/.txt/.yara files were created or modified since the rules were last compiled
            bool recompile = !File.Exists(compiledFile) || forceRecompile || thresholdDate < LatestSignatureChange(rulesDir);

            if (!recompile)
            {
                try
                {
                    loadedRules = new CompiledRules(compiledFile);
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Loading precompiled yara rules failed ({e.Message}) - regenerating");
                    recompile = true;
                }
            }

            lock (_scanLock)
            {
                if (recompile)
                {
                    string[] newFiles = RecompileRules(rulesDir);
                    foreach (string newCompiled in newFiles)
                    {
                        Logging.RecordLogEvent("Compiled yara rule file generated: " + newCompiled, Logging.LogFilterType.TextDebug);
                    }
                    if (newFiles.Length != 1)
                    {
                        Logging.RecordLogEvent($"Failed to compile new yara rules file)");
                    }
                }
            }
        }


        public Rule[]? GetRuleData()
        {
            if (loadedRules == null) return null;
            lock (_scanLock)
            {
                return loadedRules.Rules.ToArray();
            }
        }


        /// <summary>
        /// Compile all yara rules in the directory to memory and disk signature blobs, containing the respective rules enabled in the settings
        /// </summary>
        /// <param name="rulesDir">Directory containing directories full of yara rules</param>
        /// <returns>Paths to the sucessfully created rules files</returns>
        string[] RecompileRules(string rulesDir)
        {
            List<string> savedrules = new List<string>();
            EnumerationOptions opts = new EnumerationOptions()
            {
                MatchCasing = MatchCasing.CaseInsensitive,
                IgnoreInaccessible = true,
                RecurseSubdirectories = true
            };


            List<string> ruleFiles = Directory.GetFiles(rulesDir, "*.yar*", opts).ToList();
            ruleFiles.AddRange(Directory.GetFiles(rulesDir, "*.txt", opts).ToList());


            // Compile list of yara rules
            var AllRulesCompiler = new Compiler();
            while (true)
            {
                bool failed = false;
                foreach (string rulespath in ruleFiles)
                {
                    string contents = File.ReadAllText(rulespath);
                    if (contents.Contains("rule", StringComparison.OrdinalIgnoreCase) && contents.Contains("condition", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            //if (GlobalConfig.SignatureScanLimits.TryGetValue())
                            AllRulesCompiler.AddRuleString(contents);
                        }
                        catch (Exception e)
                        {
                            //a bad rule causes an exeption in compilation and cant be removed, so we have to remove the whole file and recompile all from scratch
                            failed = true;
                            Logging.RecordLogEvent($"Failed to compile Yara rule in file {rulespath}: {e.Message}", Logging.LogFilterType.TextError);
                            ruleFiles.Remove(rulespath);
                            if (!ruleFiles.Any())
                            {
                                Logging.RecordLogEvent($"No valid YARA rules found in directory {rulesDir}", Logging.LogFilterType.TextError);
                                return savedrules.ToArray();
                            }
                            AllRulesCompiler.Dispose();
                            AllRulesCompiler = new Compiler();
                            break;
                        }
                    }
                }
                if (!failed) break;
            }




            //compilation will fail if the variable used by a rule isn't declared at compile time
            AllRulesCompiler.DeclareExternalStringVariable("filename");
            AllRulesCompiler.DeclareExternalStringVariable("extension");
            AllRulesCompiler.DeclareExternalStringVariable("filepath");
            AllRulesCompiler.DeclareExternalStringVariable("filetype");
            loadedRules = AllRulesCompiler.Compile();
            AllRulesCompiler.Dispose();

            //memoryScanRules = compiler.Compile();
            // fileScanRules = compiler.Compile();
            //compiler.Dispose();

            if (loadedRules.RuleCount > 0)
            {
                string diskpath = Path.Combine(rulesDir, "precompiled_rules.yarac");
                if (File.Exists(diskpath))
                    File.Delete(diskpath);
                if (loadedRules.Save(diskpath))
                    savedrules.Add(diskpath);
            }

            return savedrules.ToArray();
        }

        readonly DateTime _lastCheck = DateTime.MinValue;
        public DateTime NewestSignature { get; private set; } = DateTime.MinValue;
        public DateTime EndpointNewestSignature = DateTime.MinValue;
        public bool StaleRemoteSignatures => (EndpointNewestSignature != DateTime.MinValue && EndpointNewestSignature > NewestSignature);

        DateTime LatestSignatureChange(string rulesDir)
        {
            if ((DateTime.Now - _lastCheck).TotalSeconds < 20) return NewestSignature;

            var sigDirs = Directory.GetDirectories(rulesDir, "*", SearchOption.AllDirectories)
                .SelectMany(x => new List<DateTime>() { Directory.GetCreationTime(x), Directory.GetLastWriteTime(x) });

            var sigFiles = Directory.GetFiles(rulesDir, "*", SearchOption.AllDirectories)
                .Where(x => x.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                            x.EndsWith(".yara", StringComparison.OrdinalIgnoreCase) ||
                            x.EndsWith(".yar", StringComparison.OrdinalIgnoreCase))
                .SelectMany(x => new List<DateTime>() { File.GetCreationTime(x), File.GetLastWriteTime(x) }.ToList()).ToList();

            DateTime newestDir = sigDirs.Max();
            DateTime newestFile = sigFiles.Max();

            NewestSignature = newestDir > newestFile ? newestDir : newestFile;
            return NewestSignature;
        }

        public uint LoadedRuleCount()
        {
            if (loadedRules == null) return 0;
            return loadedRules.RuleCount;
        }

        public eYaraScanProgress Progress(BinaryTarget target)
        {
            if (targetScanProgress.TryGetValue(target, out eYaraScanProgress result))
            {
                return result;
            }
            return eYaraScanProgress.eNotStarted;
        }


        void YARATargetScanThread(object argslist)
        {
            List<object> args = (List<object>)argslist;
            BinaryTarget targ = (BinaryTarget)args[0];

            try
            {
                lock (_scanLock)
                {
                    if (LoadedRuleCount() == 0) return;
                    if (targ.PEFileObj == null) return;

                    targetScanProgress[targ] = eYaraScanProgress.eRunning;
                    byte[] fileContentsBuf = targ.PEFileObj.RawFile.ToArray();

                    // Initialize the scanner
                    //var scanner = new dnYara.CustomScanner(loadedRules);
                    var scanner = new dnYara.Scanner();

                    ExternalVariables externalVariables = new ExternalVariables();
                    externalVariables.StringVariables.Add("filename", targ.FileName);
                    List<ScanResult> scanResults = scanner.ScanMemory(ref fileContentsBuf, loadedRules);// externalVariables);
                                                                                                        //scanner.Release();

                    foreach (ScanResult sighit in scanResults)
                    {
                        targ.AddYaraSignatureHit(sighit);
                    }

                }
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent("YARA Scan failed with exeption: " + e.Message, Logging.LogFilterType.TextError);
                targetScanProgress[targ] = eYaraScanProgress.eFailed;
            }

            targetScanProgress[targ] = eYaraScanProgress.eComplete;
        }



        public void CancelAllScans()
        {

        }

        public void UploadSignatures()
        {
            try
            {
                string tempfile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                ZipFile.CreateFromDirectory(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory), tempfile);
                if (File.Exists(tempfile))
                {
                    byte[] zipfile = File.ReadAllBytes(tempfile);
                    JObject paramObj = new JObject();
                    paramObj.Add("Type", "YARA");
                    paramObj.Add("Zip", zipfile);
                    rgatState.NetworkBridge.SendCommand("UploadSignatures", null, null, paramObj);
                    File.Delete(tempfile);
                    rgatState.NetworkBridge.AddNetworkDisplayLogMessage("Uploaded YARA signatures", Themes.eThemeColour.eGoodStateColour);
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to upload YARA signatures: {e.Message}");
                rgatState.NetworkBridge.AddNetworkDisplayLogMessage("Failed to upload YARA signatures", Themes.eThemeColour.eBadStateColour);
            }

        }

        public void ReplaceSignatures(byte[] zipfile)
        {
            Console.WriteLine($"Replacing yara sigs with zip size {zipfile.Length}");
            try
            {
                rgatState.YARALib?.CancelAllScans();
                string tempfile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                File.WriteAllBytes(tempfile, zipfile);
                if (File.Exists(tempfile))
                {
                    string original = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.YaraRulesDirectory);
                    Directory.Delete(original, true);
                    ZipFile.ExtractToDirectory(tempfile, original, true);
                    File.Delete(tempfile);
                    OperationModes.BridgedRunner.SendSigDates();
                    rgatState.NetworkBridge.SendLog("YARA signature replacement completed successfully", Logging.LogFilterType.TextInfo);
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to replace YARA signatures: {e.Message}");
                rgatState.NetworkBridge.SendLog($"YARA signature sync failed: {e.Message}", Logging.LogFilterType.TextError);
            }
        }

    }
}
