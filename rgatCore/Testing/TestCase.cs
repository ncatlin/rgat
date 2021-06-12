using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace rgatCore.Testing
{
    public enum RequirementCondition { Equals, LessThan, LessThanOrEqualTo, GreaterThan, GreaterThanOrEqualTo, Exists, Absent, INVALID };
    public class TestRequirement
    {
        public TestRequirement(string name, JToken value, string condition)
        {
            Name = name;
            ExpectedValue = value;

            switch (condition.ToLower())
            {
                case "=":
                case "eq":
                case "equal":
                case "equals":
                    Condition = RequirementCondition.Equals;
                    break;

                case ">":
                case "gt":
                case "greater":
                case "greaterthan":
                    Condition = RequirementCondition.GreaterThan;
                    break;

                case ">=":
                case "ge":
                case "greaterorequal":
                case "greaterthanorequalto":
                    Condition = RequirementCondition.GreaterThanOrEqualTo;
                    break;

                case "<":
                case "lt":
                case "less":
                case "lessthan":
                    Condition = RequirementCondition.LessThan;
                    break;

                case "<=":
                case "le":
                case "lessorequal":
                case "lessthanorequalto":
                    Condition = RequirementCondition.LessThanOrEqualTo;
                    break;

                case "exists":
                    Condition = RequirementCondition.Exists;
                    break;

                case "absent":
                    Condition = RequirementCondition.Absent;
                    break;

                default:
                    Condition = RequirementCondition.INVALID;
                    break;
            }
        }
        public string Name { get; private set; }
        public JToken ExpectedValue { get; private set; }
        public RequirementCondition Condition { get; private set; }
    }

    public class ProcessTestRequirements
    {
        public ProcessTestRequirements()
        {

        }
        //list of requirements the process (ie: TraceRecord) must meet
        public List<TestRequirement> ProcessRequirements = new List<TestRequirement>();
        //list of requirements the threads (ie: ProtoGraphs) must meet
        public List<List<TestRequirement>> ThreadRequirements = new List<List<TestRequirement>>();
    }

    public enum eTestState { NotRun, Passed, Failed };
    public class TestCase
    {
        public TestCase(string jsonpath, string category)
        {
            TestName = Path.GetFileName(jsonpath).Split(TEST_CONSTANTS.testextension)[0];
            try
            {
                BinaryDirectory = Directory.GetParent(jsonpath).FullName;
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Exception {e.Message} getting directory of test {jsonpath}");
                return;
            }
            JSONPath = jsonpath;
            CategoryName = category;

            lock (_lock)
            {
                if (!ParseTestSpec(jsonpath, out JObject jsonObj)) return;
                Loaded = LoadTestCase(jsonObj);
            }
        }

        bool ParseTestSpec(string jsonpath, out Newtonsoft.Json.Linq.JObject jsnobj)
        {
            jsnobj = null;
            string jsnfile;
            try
            {
                StreamReader file = File.OpenText(jsonpath);
                jsnfile = file.ReadToEnd();
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Error reading test specification {jsonpath}: {e.Message}", Logging.LogFilterType.TextError);
                return false;
            }

            try
            {
                jsnobj = JObject.Parse(jsnfile);
                return true;
            }
            catch (Newtonsoft.Json.JsonReaderException e)
            {
                Logging.RecordLogEvent($"Error parsing JSON of test specification '{jsonpath}': {e.Message}", Logging.LogFilterType.TextError);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent("Error parsing test specification: " + e.Message, Logging.LogFilterType.TextError);
            }
            return false;
        }


        bool LoadTestCase(JObject testSpec)
        {
            //mandatory for test cases to have metadata
            if (!testSpec.TryGetValue("Meta", out JToken metaTok) && metaTok.Type == JTokenType.Object)
            {
                Logging.RecordLogEvent($"No test metadata in test specification '{JSONPath}'", Logging.LogFilterType.TextError);
                return false;
            }
            JObject metadata = metaTok.ToObject<JObject>();
            if (!LoadSpecMetadata(metadata)) return false;

            //optional: requirements for the trace state when the test execution has finished
            if (testSpec.TryGetValue("FinalRequirements", out JToken finalReqTok) && finalReqTok.Type == JTokenType.Object)
            {
                if (!LoadFinalRequirements(finalReqTok.ToObject<JObject>()))
                {
                    Logging.RecordLogEvent($"FinalRequirements were present in '{JSONPath}' but failed to load", Logging.LogFilterType.TextError);
                    return false;
                }
            }

            return _loadingError == false;
        }


        bool LoadSpecMetadata(JObject metaObj)
        {
            //mandatory fields

            if (!metaObj.TryGetValue("BinaryName", out JToken binNameTok) || binNameTok.Type != JTokenType.String)
            {
                Logging.RecordLogEvent($"No binary name in test specification '{JSONPath}'", Logging.LogFilterType.TextError);
                return false;
            }
            string candidatePath = Path.Combine(BinaryDirectory, binNameTok.ToObject<string>());
            if (File.Exists(candidatePath))
            {
                BinaryPath = candidatePath;
            }
            else
            {
                Logging.RecordLogEvent($"Test binary not found '{candidatePath}' while loading test {TestName}", Logging.LogFilterType.TextError);
                return false;
            }

            if (metaObj.TryGetValue("Bits", out JToken bitsTok) && bitsTok.Type == JTokenType.Integer)
            {
                TestBits = bitsTok.ToObject<int>();
            }
            else
            {
                Logging.RecordLogEvent($"No test bitwidth in test specification '{JSONPath}'", Logging.LogFilterType.TextError);
                return false;
            }

            if (metaObj.TryGetValue("OS", out JToken OSTok) && OSTok.Type == JTokenType.String)
            {
                TestOS = bitsTok.ToObject<string>();
            }
            else
            {
                Logging.RecordLogEvent($"No test OS in test specification '{JSONPath}'", Logging.LogFilterType.TextError);
                return false;
            }

            //optional fields
            if (metaObj.TryGetValue("Description", out JToken descTok) && descTok.Type == JTokenType.String)
            {
                Description = descTok.ToObject<string>();
            }
            return true;
        }


        bool LoadFinalRequirements(JObject reqsObj)
        {

            /// Optional requirements that the entire test must satisfy at completion (eg: time it took to run, total processes spawned)
            if (reqsObj.TryGetValue("Test", out JToken tok) && tok.Type == JTokenType.Object)
            {
                JObject items = tok.ToObject<JObject>();
                foreach (var req in items)
                {
                    if (req.Key == "Comment") continue;
                    if (LoadTestRequirement(req.Key, req.Value, out TestRequirement requirement))
                    {
                        _TestRunRequirements.Add(requirement);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Failed to load final overall test requirements from '{JSONPath}'", Logging.LogFilterType.TextError);
                        _loadingError = true;
                        return false;
                    }
                }
            }

            if (reqsObj.TryGetValue("Process", out tok) && tok.Type == JTokenType.Array)
            {
                JArray items = tok.ToObject<JArray>();
                foreach (var processReq in items)
                {
                    if (LoadProcessRequirements(processReq, out ProcessTestRequirements requirement))
                    {
                        _ProcessRequirements.Add(requirement);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Failed to load final process requirements from '{JSONPath}'", Logging.LogFilterType.TextError);
                        _loadingError = true;
                        return false;
                    }
                }
            }

            return true;
        }


        /// <summary>
        /// Load a JObject containing JToken value and string condition
        /// </summary>
        /// <param name="name">Name of the requirement</param>
        /// <param name="tok">JToken containing requirement</param>
        /// <param name="testRequirement">Result requirement object</param>
        /// <returns>true if it loaded without error</returns>
        bool LoadTestRequirement(string name, JToken tok, out TestRequirement testRequirement)
        {
            testRequirement = null;
            if (tok.Type != JTokenType.Object) return false;
            JObject requirement = tok.ToObject<JObject>();
            if (!requirement.TryGetValue("Value", out JToken resultValue) ||
                !requirement.TryGetValue("Condition", out JToken condTok) ||
                condTok.Type != JTokenType.String)
            {
                _loadingError = true;
                Logging.RecordLogEvent($"Requirement {name} had bad format", Logging.LogFilterType.TextError);
                return false;
            }

            string conditionText = condTok.ToObject<string>();
            testRequirement = new TestRequirement(name, resultValue, conditionText);
            if (testRequirement.Condition == RequirementCondition.INVALID)
            {
                Logging.RecordLogEvent($"Invalid condition {conditionText} in requirement {name}");
                _loadingError = true;
                return false;
            }

            return true;
        }


        bool LoadProcessRequirements(JToken procObj, out ProcessTestRequirements ptr)
        {
            ptr = new ProcessTestRequirements();
            if (procObj.Type != JTokenType.Object)
            {
                Logging.RecordLogEvent($"Test {TestName} JSON has invalid token type {procObj.Type} for a process object");
                _loadingError = true;
                return false;
            }

            //iterate through list of process+graph requirements
            foreach (var processTok in procObj.ToObject<JObject>())
            {
                if (processTok.Key == "Comment") continue;
                if (processTok.Key == "GraphRequirements" && processTok.Value.Type == JTokenType.Array)
                {
                    JArray graphToks = processTok.Value.ToObject<JArray>();
                    foreach (var graphTok in graphToks)
                    {
                        if (LoadGraphRequirementsObject(graphTok, out List<TestRequirement> graphRequirements))
                        {
                            ptr.ThreadRequirements.Add(graphRequirements);
                        }
                        else
                        {
                            Logging.RecordLogEvent($"Test {TestName} JSON has invalid GraphRequirements list");
                            _loadingError = true;
                            return false;
                        }
                    }
                }
                else
                {
                    if (LoadTestRequirement(processTok.Key, processTok.Value, out TestRequirement processReq))
                    {
                        ptr.ProcessRequirements.Add(processReq);
                    }
                    else
                    {
                        Logging.RecordLogEvent($"Test {TestName} JSON has invalid ProcessRequirement {processTok.Key}");
                        _loadingError = true;
                        return false;
                    }
                }
            }
            return true;
        }


        bool LoadGraphRequirementsObject(JToken threadReqsObj, out List<TestRequirement> graphRequirements)
        {
            graphRequirements = new List<TestRequirement>();
            if (threadReqsObj.Type != JTokenType.Object)
            {
                Logging.RecordLogEvent($"Test {TestName} JSON has invalid token type {threadReqsObj.Type} for a threads requirement list");
                _loadingError = true;
                return false;
            }


            foreach (var reqKVP in threadReqsObj.ToObject<JObject>())
            {
                if (reqKVP.Key == "Comment") continue;

                if (LoadTestRequirement(reqKVP.Key, reqKVP.Value, out TestRequirement graphReq))
                {
                    graphRequirements.Add(graphReq);
                }
                else
                {
                    Logging.RecordLogEvent($"Test {TestName} JSON has invalid Thread TestRequirement {reqKVP.Key}");
                    _loadingError = true;
                    return false;
                }
            }
            return true;
        }


        bool _loadingError = false;
        public bool Loaded { get; private set; }
        //the lastest test result
        public eTestState LatestResult = eTestState.NotRun;
        public string JSONPath { get; private set; }
        public string BinaryPath { get; private set; }
        public string BinaryDirectory { get; private set; }
        public string CategoryName { get; private set; }
        public string TestName { get; private set; }
        public bool Starred;
        public string Description { get; private set; }
        public int TestBits { get; private set; }
        public string TestOS { get; private set; }

        public int Running { get; private set; }
        Dictionary<int, int> _passed = new Dictionary<int, int>();
        Dictionary<int, int> _failed = new Dictionary<int, int>();

        /// <summary>
        /// A nested list of requirements for each thread
        /// vague pseudo-json example [{C:6, [C:1, C:3]},{C:1, [C:7,C:12]}]
        ///     This expects two processes, each producing 2 thread graphs
        ///     One process must meet condtion C6 has threads meeting condition C1, the other meeting condition C3. 
        ///     Ditto for the other process needing to meet condtion C1 with threads meeting conditions 7, 12
        /// </summary>
        List<ProcessTestRequirements> _ProcessRequirements = new List<ProcessTestRequirements>();
        /// <summary>
        /// A list of conditions met by the entire test itself
        /// </summary>
        List<TestRequirement> _TestRunRequirements = new List<TestRequirement>();

        public TestRequirement[] TestRunRequirements()
        {
            lock (_lock)
            {
                return _TestRunRequirements.ToArray();
            }
        }

        public ProcessTestRequirements[] ProcessRequirements()
        {
            lock (_lock)
            {
                return _ProcessRequirements.ToArray();
            }
        }

        readonly object _lock = new object();

        public void RecordRunning() { lock (_lock) { Running++; } }
        public void RecordFinished() { lock (_lock) { Running--; } }
        public void RecordPassed(int sessionID)
        {
            lock (_lock)
            {
                _passed.TryGetValue(sessionID, out int val);
                _passed[sessionID] = val + 1;
                LatestResult = eTestState.Passed;
            }
        }
        public int CountPassed(int sessionID) { lock (_lock) { _passed.TryGetValue(sessionID, out int val); return val; } }

        public void RecordFailed(int sessionID)
        {
            lock (_lock)
            {
                _failed.TryGetValue(sessionID, out int val);
                _failed[sessionID] = val + 1;
                LatestResult = eTestState.Failed;
            }
        }
        public int CountFailed(int sessionID) { lock (_lock) { _failed.TryGetValue(sessionID, out int val); return val; } }

    }
}
