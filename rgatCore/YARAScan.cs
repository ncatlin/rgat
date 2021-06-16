using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using dnYara;

namespace rgatCore
{
    public class YARAScan
    {

        readonly object scansLock = new object();

        public YARAScan (string rulesDir)
        {

        }

        //scan a target binary file
        public void StartYARAScan(BinaryTarget targ)
        {

            List<object> args = new List<object>() { targ };

            Thread YaraThread = new Thread(new ParameterizedThreadStart(YARAScanThread));
            YaraThread.Name = "YARA_" + targ.FileName;
            YaraThread.Start(args);            
        }


        static void YARAScanThread(object argslist)
        {

            List<object> args = (List<object>)argslist;

            BinaryTarget targ = (BinaryTarget)args[0];

            targ.ClearSignatureHits(eSignatureType.eYARA);

            string result;
            try
            {
                string ruleString = "import \"pe\"\r\nrule EXE_cloaked_as_TXT {condition:\nuint16(0) == 0x5a4d and filename matches /\\.exe$/is}";

                byte[] fileContentsBuf = targ.PEFileObj.RawFile.ToArray();

                using (YaraContext ctx = new YaraContext())
                {
                    // Compile list of yara rules
                    CompiledRules rules = null;
                    using (var compiler = new Compiler())
                    {
                        //compilation will fail if the variable used by a rule isn't declared at compile time
                        compiler.DeclareExternalStringVariable("filename");
                        compiler.AddRuleString(ruleString);
                        rules = compiler.Compile();
                        compiler.Dispose();
                    }

                    // Initialize the scanner
                    var scanner = new dnYara.CustomScanner(rules);

                    
                    ExternalVariables externalVariables = new ExternalVariables();
                    externalVariables.StringVariables.Add("filename", targ.FileName);
                    List<ScanResult> scanResults = scanner.ScanMemory(ref fileContentsBuf, externalVariables);
                    foreach (ScanResult sighit in scanResults)
                    {
                        targ.AddSignatureHits(sighit.MatchingRule.Identifier, eSignatureType.eYARA);
                        //foreach (Match sigmatch in sighit.Matches)
                        //{
                        // }
                    }

                    scanner.Release();
                    rules.Release();
                }
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent("YARA Scan failed with exeption: " + e.Message, Logging.LogFilterType.TextError);
            }
        }



        public void CancelAllScans()
        {

        }



    }
}
