using dnYara;
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
    /// <summary>
    /// Interface to libyara via dnYara
    /// </summary>
    public class YARAScanner
    {
        private readonly object _scanLock = new object();
        private CompiledRules? loadedRules = null;

        /// <summary>
        /// State of the scanner
        /// </summary>
        public enum eYaraScanProgress
        {
            /// <summary>
            /// Scanning
            /// </summary>
            eRunning,
            /// <summary>
            /// Scan Finished
            /// </summary>
            eComplete,
            /// <summary>
            /// Not started
            /// </summary>
            eNotStarted,
            /// <summary>
            /// Scanner couldnt load
            /// </summary>
            eFailed
        };

        private readonly Dictionary<BinaryTarget, eYaraScanProgress> targetScanProgress = new Dictionary<BinaryTarget, eYaraScanProgress>();

        [DllImport("libyara.dll")]
        private static extern void LibraryExistsTestMethod();

        private readonly YaraContext ctx;

        /// <summary>
        /// Create a Yara scanner
        /// </summary>
        /// <param name="rulesDir">Directory of YARA rules</param>
        public YARAScanner(string rulesDir)
        {
            ctx = new YaraContext();
            ctx.GetType(); //prevent a 'this is never read' warning. It needs to be created and stay in memory but we dont reference it

            if (!CheckLibraryExists())
            {
                throw new DllNotFoundException("libyara.dll not available");
            }

            RefreshRules(rulesDir);
        }


        // have to check libyara exists before attempting to use dnYara
        // otherwise the destructor will crash us when it fails
        private static bool CheckLibraryExists()
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
                Logging.RecordException($"Unexpected error {e.Message} when checking for yara", e);
            }

            return false;
        }


        /// <summary>
        /// Destructor
        /// </summary>
        ~YARAScanner()
        {
            try
            {
                loadedRules?.Release();
            }
            catch (Exception)
            {

            }
        }


        /// <summary>
        /// A serialisable YARA hit record
        /// </summary>
        public class YARAHit
        {
            /// <summary>
            /// Create a yara hit record from a dnYara scan result
            /// </summary>
            /// <param name="marshalledHit"></param>
            public YARAHit(dnYara.ScanResult marshalledHit)
            {
                MatchingRule = marshalledHit.MatchingRule;
                Matches = new Dictionary<string, List<YaraHitMatch>>();
                foreach (var kvp in marshalledHit.Matches)
                {
                    List<YaraHitMatch> sigHits = new List<YaraHitMatch>();
                    foreach (var hit in kvp.Value)
                    {
                        sigHits.Add(new YaraHitMatch(hit.Base, hit.Offset, hit.Data));
                    }
                    Matches.Add(kvp.Key, sigHits);
                }
            }

            /// <summary>
            /// The rule that was hit on
            /// </summary>
            public Rule MatchingRule;

            /// <summary>
            /// A list of string matches
            /// </summary>
            public Dictionary<string, List<YARAHit.YaraHitMatch>> Matches;

            /// <summary>
            /// A serialisable description of a signature hit
            /// </summary>
            public class YaraHitMatch
            {
                /// <summary>
                /// create a YARA hit
                /// </summary>
                /// <param name="_base">base of the hit</param>
                /// <param name="offset">offset of the hit</param>
                /// <param name="data">data of the hit</param>
                public YaraHitMatch(long _base, long offset, byte[] data)
                {
                    Base = _base;
                    Offset = offset;
                    Data = data;
                }

                /// <summary>
                /// The base of the match (what is this?)
                /// </summary>
                public long Base { get; set; }
                /// <summary>
                /// The offset of the match
                /// </summary>
                public long Offset { get; set; }
                /// <summary>
                /// The data of the match
                /// </summary>
                public byte[] Data { get; set; }
            }

        }


        /// <summary>
        /// Scan a target binary file
        /// </summary>
        /// <param name="targ">File path</param>
        /// <param name="reload">reload the signatures first</param>
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

                if (!File.Exists(targ.FilePath))
                {
                    return;
                }

                List<object> args = new List<object>() { targ };

                Thread YaraThread = new Thread(new ParameterizedThreadStart(YARATargetScanThread));
                YaraThread.Name = "YARA_F_" + targ.FileName;
                YaraThread.Start(args);
            }
            catch (Exception e)
            {
                Logging.RecordException($"Error starting YARA scan: {e.Message}", e);
            }
        }

        /// <summary>
        /// Reload the signatures from disk
        /// </summary>
        /// <param name="rulesDir">Signatures directory</param>
        /// <param name="forceRecompile">Recompile the signatures even if no changes seen</param>
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
                    {
                        compiledFile = filepath;
                    }
                }
            }


            //find the last time the compiled file was modified
            DateTime thresholdDate = DateTime.MinValue;

            if (compiledFile is not null)
            {
                try
                {
                    DateTime sigsCompileDate = File.GetLastWriteTime(compiledFile);
                    if (sigsCompileDate > thresholdDate)
                    {
                        thresholdDate = sigsCompileDate;
                    }
                }
                catch
                {
                }
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
                    Logging.RecordException($"Loading precompiled yara rules failed ({e.Message}) - regenerating", e);
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
                        Logging.RecordLogEvent("Compiled yara rule file generated: " + newCompiled, Logging.LogFilterType.Debug);
                    }
                    if (newFiles.Length != 1)
                    {
                        Logging.RecordLogEvent($"Failed to compile new yara rules file");
                    }
                }
            }
        }


        /// <summary>
        /// Get the array of rules
        /// </summary>
        /// <returns>Array of Rule objects</returns>
        public Rule[]? GetRuleData()
        {
            if (loadedRules == null)
            {
                return null;
            }

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
        private string[] RecompileRules(string rulesDir)
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
                            Logging.RecordException($"Failed to compile Yara rule in file {rulespath}: {e.Message}", e);
                            ruleFiles.Remove(rulespath);
                            if (!ruleFiles.Any())
                            {
                                Logging.RecordLogEvent($"No valid YARA rules found in directory {rulesDir}", Logging.LogFilterType.Error);
                                return savedrules.ToArray();
                            }
                            AllRulesCompiler.Dispose();
                            AllRulesCompiler = new Compiler();
                            break;
                        }
                    }
                }
                if (!failed)
                {
                    break;
                }
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
                {
                    File.Delete(diskpath);
                }

                if (loadedRules.Save(diskpath))
                {
                    savedrules.Add(diskpath);
                }
            }

            return savedrules.ToArray();
        }

        private readonly DateTime _lastCheck = DateTime.MinValue;
        /// <summary>
        /// The most recent file creation/modification in this YARA signatures directory
        /// </summary>
        public DateTime NewestSignature { get; private set; } = DateTime.MinValue;
        /// <summary>
        /// The most recent file creation/modification in the remote machines YARA signatures directory
        /// </summary>
        public DateTime EndpointNewestSignature = DateTime.MinValue;
        /// <summary>
        /// The remote machine signatures can be updated
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
                .Where(x => x.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                            x.EndsWith(".yara", StringComparison.OrdinalIgnoreCase) ||
                            x.EndsWith(".yar", StringComparison.OrdinalIgnoreCase))
                .SelectMany(x => new List<DateTime>() { File.GetCreationTime(x), File.GetLastWriteTime(x) }.ToList()).ToList();

            DateTime newestDir = sigDirs.Any() ? sigDirs.Max() : DateTime.MinValue;
            DateTime newestFile = sigFiles.Any() ? sigFiles.Max() : DateTime.MinValue;

            NewestSignature = newestDir > newestFile ? newestDir : newestFile;
            return NewestSignature;
        }


        /// <summary>
        /// How many YARA rules are loaded
        /// </summary>
        /// <returns></returns>
        public uint LoadedRuleCount()
        {
            if (loadedRules == null)
            {
                return 0;
            }

            return loadedRules.RuleCount;
        }


        /// <summary>
        /// Get the progress of a YARA scan
        /// </summary>
        /// <param name="target">The target being scanned</param>
        /// <returns>a eYaraScanProgress value</returns>
        public eYaraScanProgress Progress(BinaryTarget target)
        {
            if (targetScanProgress.TryGetValue(target, out eYaraScanProgress result))
            {
                return result;
            }
            return eYaraScanProgress.eNotStarted;
        }

        private void YARATargetScanThread(object? argslist)
        {
            List<object> args = (List<object>)argslist!;
            BinaryTarget targ = (BinaryTarget)args[0];
            try
            {
                Inner(targ);
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
            }
        }

        int Inner(BinaryTarget targ)
        {

            try
            {
                lock (_scanLock)
                {
                    if (LoadedRuleCount() == 0)
                    {
                        return 0;
                    }

                    if (targ.PEFileObj == null)
                    {
                        return 0;
                    }

                    targetScanProgress[targ] = eYaraScanProgress.eRunning;
                    byte[] fileContentsBuf = targ.PEFileObj.RawFile.ToArray();

                    // Initialize the scanner
                    //var scanner = new dnYara.CustomScanner(loadedRules);
                    var scanner = new dnYara.Scanner();

                    ExternalVariables externalVariables = new ExternalVariables();
                    externalVariables.StringVariables.Add("filename", targ.FileName);
                    try
                    {
                        List<ScanResult> scanResults = scanner.ScanMemory(ref fileContentsBuf, loadedRules);// externalVariables);
                                                                                                            //scanner.Release();


                        foreach (ScanResult sighit in scanResults)
                        {
                            targ.AddYaraSignatureHit(sighit);
                        }
                    }
                    catch(Exception ev)
                    {
                        Console.WriteLine("sdf");
                    }

                }
            }
            catch (dnYara.Exceptions.YaraException e)
            {

                Logging.RecordException("YARA Scan failed with exeption: " + e.Message, e);
                targetScanProgress[targ] = eYaraScanProgress.eFailed;
            }
            catch (Exception e)
            {
                Logging.RecordException("YARA Scan failed with exeption: " + e.Message, e);
                targetScanProgress[targ] = eYaraScanProgress.eFailed;
            }


            targetScanProgress[targ] = eYaraScanProgress.eComplete;
            return 0;
        }


        /// <summary>
        /// Not implemented
        /// </summary>
        public void CancelAllScans()
        {

        }

        /// <summary>
        /// Send the signatures on this device to the connected device
        /// </summary>
        public static void UploadSignatures()
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
                    rgatState.NetworkBridge.AddNetworkDisplayLogMessage("Uploaded YARA signatures", Themes.eThemeColour.GoodStateColour);
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Failed to upload YARA signatures: {e.Message}");
                rgatState.NetworkBridge.AddNetworkDisplayLogMessage("Failed to upload YARA signatures", Themes.eThemeColour.BadStateColour);
            }

        }


        /// <summary>
        /// Replace the signatures on this device with signatures from the remote device
        /// </summary>
        /// <param name="zipfile">bytes of a zipped signature directory</param>
        public static void ReplaceSignatures(byte[] zipfile)
        {
            Logging.WriteConsole($"Replacing yara sigs with zip size {zipfile.Length}");
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
                    rgatState.NetworkBridge.SendLog("YARA signature replacement completed successfully", Logging.LogFilterType.Info);
                }
            }
            catch (Exception e)
            {
                Logging.RecordException($"Failed to replace YARA signatures: {e.Message}", e);
                rgatState.NetworkBridge.SendLog($"YARA signature sync failed: {e.Message}", Logging.LogFilterType.Error);
            }
        }

    }
}
