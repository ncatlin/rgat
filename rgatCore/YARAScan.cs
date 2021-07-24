using dnYara;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace rgatCore
{

    public class YARAScan
    {
        readonly object _scanLock = new object();
        YaraContext ctx;

        CompiledRules loadedRules = null;

        public enum eYaraScanProgress { eRunning, eComplete, eNotStarted, eFailed };
        Dictionary<BinaryTarget, eYaraScanProgress> targetScanProgress = new Dictionary<BinaryTarget, eYaraScanProgress>();

        public YARAScan(string rulesDir)
        {
            ctx = new YaraContext();
            RefreshRules();
        }

        ~YARAScan()
        {
            loadedRules?.Release();
        }

        public struct YARAHit
        {
            public string Identifier;
        }


        //scan a target binary file
        public void StartYARATargetScan(BinaryTarget targ)
        {
            if (!File.Exists(targ.FilePath)) return;

            List<object> args = new List<object>() { targ };

            Thread YaraThread = new Thread(new ParameterizedThreadStart(YARATargetScanThread));
            YaraThread.Name = "YARA_F_" + targ.FileName;
            YaraThread.Start(args);
        }

        public void RefreshRules(bool forceRecompile = false)
        {

            //find precompiled rules files in the current directory of the form "[disk_|mem_][UINT]_.yarac"
            string rulesDir = GlobalConfig.YARARulesDir;
            string[] filesList = Directory.GetFiles(rulesDir, "precompiled_rules*.yarac", SearchOption.TopDirectoryOnly);

            string compiledFile = null;

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
            bool recompile = forceRecompile || HasNewerRuleOrDirectory(rulesDir, thresholdDate);

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


        public Rule[] GetRuleData()
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



        bool HasNewerRuleOrDirectory(string rulesDir, DateTime thresholdDate)
        {

            bool newerDir = Directory.GetDirectories(rulesDir, "*", SearchOption.AllDirectories)
                .Where(x => Directory.GetCreationTime(x) > thresholdDate || Directory.GetLastWriteTime(x) > thresholdDate)
                .Any();
            if (newerDir) return true;

            bool newerFile = Directory.GetFiles(rulesDir, "*", SearchOption.AllDirectories)
                .Where(x => File.GetCreationTime(x) > thresholdDate || File.GetLastWriteTime(x) > thresholdDate)
                .Where(x => x.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                            x.EndsWith(".yara", StringComparison.OrdinalIgnoreCase) ||
                            x.EndsWith(".yar", StringComparison.OrdinalIgnoreCase))
                .Any();
            if (newerFile) return true;

            return false;

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
            targ.ClearSignatureHits(eSignatureType.eYARA);

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



    }
}
