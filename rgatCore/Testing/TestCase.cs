using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;

namespace rgat.Testing
{
    public enum RequirementCondition
    {
        Equals, LessThan, LessThanOrEqualTo, GreaterThan,
        GreaterThanOrEqualTo, Exists, Absent, Contains, OneOf, INVALID
    };

    public class REQUIREMENT_TEST_RESULTS
    {
        public REQUIREMENT_TEST_RESULTS()
        {
            Passed = new List<TestResultCommentary>();
            Failed = new List<TestResultCommentary>();
            Errors = new List<Tuple<TestRequirement, string>>();
        }
        public List<TestResultCommentary> Passed;
        public List<TestResultCommentary> Failed;
        public List<Tuple<TestRequirement, string>> Errors;
    }


    public class TRACE_TEST_RESULTS
    {
        public REQUIREMENT_TEST_RESULTS ProcessResults = new REQUIREMENT_TEST_RESULTS();

        public Dictionary<REQUIREMENTS_LIST, Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS>> ThreadResults =
            new Dictionary<REQUIREMENTS_LIST, Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS>>();

        public Dictionary<TraceRequirements, Dictionary<TraceRecord, TRACE_TEST_RESULTS>> ChildResults =
            new Dictionary<TraceRequirements, Dictionary<TraceRecord, TRACE_TEST_RESULTS>>();
    }

    public struct REQUIREMENTS_LIST
    {
        public List<TestRequirement> value;
    }

    public class TestRequirement
    {
        public TestRequirement(string name, JToken value, string condition)
        {
            Name = name;
            ExpectedValue = value;

            switch (ExpectedValue.Type)
            {
                case JTokenType.Integer:
                    ExpectedValueString = $"{ExpectedValue.ToObject<long>()}";
                    break;
                case JTokenType.String:
                    ExpectedValueString = $"{ExpectedValue.ToObject<string>()}";
                    break;
                case JTokenType.Float:
                    ExpectedValueString = $"{ExpectedValue.ToObject<float>()}";
                    break;
                case JTokenType.Array:
                    ExpectedValueString = "[";
                    JArray items = ExpectedValue.ToObject<JArray>();
                    for (int i = 0; i < items.Count; i++)
                    {
                        if (i > 0) ExpectedValueString += ",";
                        JToken arrayItem = items[i];
                        switch (arrayItem.Type)
                        {
                            case JTokenType.Integer:
                                ExpectedValueString += $"{arrayItem.ToObject<long>()}";
                                break;
                            case JTokenType.String:
                                ExpectedValueString += $"{arrayItem.ToObject<string>()}";
                                break;
                            case JTokenType.Float:
                                ExpectedValueString += $"{arrayItem.ToObject<float>()}";
                                break;
                            default:
                                ExpectedValueString += "?";
                                break;
                        }
                    }
                    ExpectedValueString += "]";
                    break;
                default:
                    ExpectedValueString = $"[{ExpectedValue.Type} value]";
                    break;
            }

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

                case "contains":
                    Condition = RequirementCondition.Contains;
                    break;

                case "in":
                case "oneof":
                    Condition = RequirementCondition.OneOf;
                    break;

                default:
                    Condition = RequirementCondition.INVALID;
                    break;
            }
        }


        public bool Compare(int value, out string error)
        {
            error = "";
            if (Condition == RequirementCondition.OneOf)
            {
                if (ExpectedValue.Type != JTokenType.Array)
                {
                    error = $"int 'OneOf' comparison requires array token, but token was of type {ExpectedValue.Type}";
                    return false;
                }
                foreach (JToken arrayItem in ExpectedValue.ToObject<JArray>())
                {
                    if (arrayItem.Type == JTokenType.Integer && arrayItem.ToObject<int>() == value) return true;
                }
                return false;
            }


            if (ExpectedValue.Type != JTokenType.Integer)
            {
                error = $"int comparison requires Integer expected value, but token was of type {ExpectedValue.Type}";
                return false;
            }

            int comparedValue = ExpectedValue.ToObject<int>();

            switch (Condition)
            {
                case RequirementCondition.Equals:
                    return value == comparedValue;
                case RequirementCondition.GreaterThan:
                    return value > comparedValue;
                case RequirementCondition.GreaterThanOrEqualTo:
                    return value >= comparedValue;
                case RequirementCondition.LessThan:
                    return value < comparedValue;
                case RequirementCondition.LessThanOrEqualTo:
                    return value <= comparedValue;
                case RequirementCondition.OneOf:
                    return value <= comparedValue;
                default:
                    error = "Bad comparison for integer value: " + Condition;
                    return false;
            }
        }


        public bool Compare(long value, out string error)
        {
            error = "";
            if (Condition == RequirementCondition.OneOf)
            {
                if (ExpectedValue.Type != JTokenType.Array)
                {
                    error = $"long 'OneOf' comparison requires array token, but token was of type {ExpectedValue.Type}";
                    return false;
                }
                foreach (JToken arrayItem in ExpectedValue.ToObject<JArray>())
                {
                    if (arrayItem.Type == JTokenType.Integer && arrayItem.ToObject<long>() == value) return true;
                }
                return false;
            }

            if (ExpectedValue.Type != JTokenType.Integer)
            {
                error = $"Comparison requires Integer token, but token was of type {ExpectedValue.Type}";
                return false;
            }
            long comparedValue = ExpectedValue.ToObject<long>();
            switch (Condition)
            {
                case RequirementCondition.Equals:
                    return value == comparedValue;
                case RequirementCondition.GreaterThan:
                    return value > comparedValue;
                case RequirementCondition.GreaterThanOrEqualTo:
                    return value >= comparedValue;
                case RequirementCondition.LessThan:
                    return value < comparedValue;
                case RequirementCondition.LessThanOrEqualTo:
                    return value <= comparedValue;
                default:
                    error = "Bad comparison for long value: " + Condition;
                    return false;
            }
        }


        public bool Compare(ulong value, out string error)
        {
            error = "";
            if (Condition == RequirementCondition.OneOf)
            {
                if (ExpectedValue.Type != JTokenType.Array)
                {
                    error = $"long 'OneOf' comparison requires array token, but token was of type {ExpectedValue.Type}";
                    return false;
                }
                foreach (JToken arrayItem in ExpectedValue.ToObject<JArray>())
                {
                    if (arrayItem.Type == JTokenType.Integer && arrayItem.ToObject<ulong>() == value) return true;
                }
                return false;
            }

            if (ExpectedValue.Type != JTokenType.Integer)
            {
                error = $"Comparison requires Integer token, but token was of type {ExpectedValue.Type}";
                return false;
            }
            ulong comparedValue = ExpectedValue.ToObject<ulong>();
            switch (Condition)
            {
                case RequirementCondition.Equals:
                    return value == comparedValue;
                case RequirementCondition.GreaterThan:
                    return value > comparedValue;
                case RequirementCondition.GreaterThanOrEqualTo:
                    return value >= comparedValue;
                case RequirementCondition.LessThan:
                    return value < comparedValue;
                case RequirementCondition.LessThanOrEqualTo:
                    return value <= comparedValue;
                default:
                    error = "Bad comparison for ulong value: " + Condition;
                    return false;
            }
        }

        public void SetComment(string value) { Comment = "Comment: " + value; }

        public string Name { get; private set; }
        public string Comment { get; private set; }
        public JToken ExpectedValue { get; private set; }
        public string ExpectedValueString { get; private set; }
        public RequirementCondition Condition { get; private set; }
    }

    public class TraceRequirements
    {
        public TraceRequirements()
        {

        }
        //list of requirements the process (ie: TraceRecord) must meet
        public List<TestRequirement> ProcessRequirements = new List<TestRequirement>();

        //list of requirements the process threads (ie: ProtoGraphs) must meet
        public List<REQUIREMENTS_LIST> ThreadRequirements = new List<REQUIREMENTS_LIST>();

        //lsit of requirements for descendant processes
        public List<TraceRequirements> ChildProcessRequirements = new List<TraceRequirements>();
    }

    public class TraceRequirementsEvalResults
    {
        public TraceRequirementsEvalResults()
        {

        }
        //list of requirements the process (ie: TraceRecord) must meet
        public List<TestRequirement> ProcessRequirements = new List<TestRequirement>();

        //list of requirements the process threads (ie: ProtoGraphs) must meet
        public List<REQUIREMENTS_LIST> ThreadRequirements = new List<REQUIREMENTS_LIST>();

        //lsit of requirements for descendant processes
        public List<TraceRequirements> ChildProcessRequirements = new List<TraceRequirements>();
    }


    public enum eTestState { NotRun, Passed, Failed };
    public class TestCase
    {
        public TestCase(string jsonpath, string category)
        {
            TestName = Path.GetFileName(jsonpath).Split(CONSTANTS.TESTS.testextension)[0];
            try
            {
                BinaryDirectory = Directory.GetParent(jsonpath).FullName;
            }
            catch (Exception e)
            {
                DeclareLoadingError($"Exception {e.Message} getting directory of test {jsonpath}");
                return;
            }
            JSONPath = jsonpath;
            CategoryName = category;

            lock (_lock)
            {
                JObject jsonObj;
                try
                {
                    if (!ParseTestSpec(jsonpath, out jsonObj)) return;
                }
                catch (Exception e)
                {
                    DeclareLoadingError($"Exception {e.Message} parsing spec of test {jsonpath}");
                    return;
                }
                try
                {
                    Loaded = LoadTestCase(jsonObj);
                }
                catch (Exception e)
                {
                    DeclareLoadingError($"Exception {e.Message} loading test {jsonpath}");
                    return;
                }
            }
        }


        bool _loadingError = false;

        public List<string> LoadingErrors = new List<string>();
        public bool Loaded { get; private set; }

        //the lastest test result
        public eTestState LatestResultState = eTestState.NotRun;
        public TestCaseRun LatestTestRun { get; private set; }
        public string LatestErrorReason { get; private set; }

        public string JSONPath { get; private set; }
        public string BinaryPath { get; private set; }
        public string BinaryDirectory { get; private set; }
        public string CategoryName { get; private set; }
        public string TestName { get; private set; }
        public bool Starred;
        public string Comment { get; private set; }
        public int TestBits { get; private set; }
        public string TestOS { get; private set; }

        public long LastErrorTestID { get; private set; }

        public int Running { get; private set; }
        Dictionary<int, int> _passed = new Dictionary<int, int>();
        Dictionary<int, int> _failed = new Dictionary<int, int>();

        /// <summary>
        /// A list of conditions met by the entire test itself
        /// </summary>
        List<TestRequirement> _TestRunRequirements = new List<TestRequirement>();

        /// <summary>
        /// A nested list of requirements for each thread
        /// vague pseudo-json example [{C:6, [C:1, C:3]},{C:1, [C:7,C:12]}]
        ///     This expects two processes, each producing 2 thread graphs
        ///     One process must meet condtion C6 has threads meeting condition C1, the other meeting condition C3. 
        ///     Ditto for the other process needing to meet condtion C1 with threads meeting conditions 7, 12
        /// </summary>
        TraceRequirements _TraceRequirements = new TraceRequirements();


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
                DeclareLoadingError($"Error reading test specification: {e.Message}");
                return false;
            }

            try
            {
                jsnobj = JObject.Parse(jsnfile);
                return true;
            }
            catch (Newtonsoft.Json.JsonReaderException e)
            {
                DeclareLoadingError($"Exception parsing JSON: {e.Message}");
            }
            catch (Exception e)
            {
                DeclareLoadingError("Exception parsing test specification: " + e.Message);
            }
            return false;
        }


        bool LoadTestCase(JObject testSpec)
        {
            //mandatory for test cases to have metadata
            if (!testSpec.TryGetValue("Meta", out JToken metaTok) && metaTok.Type == JTokenType.Object)
            {
                DeclareLoadingError($"No test metadata in test specification");
                return false;
            }
            JObject metadata = metaTok.ToObject<JObject>();
            if (!LoadSpecMetadata(metadata)) return false;

            //optional: requirements for the trace state when the test execution has finished
            if (testSpec.TryGetValue("FinalRequirements", out JToken finalReqTok) && finalReqTok.Type == JTokenType.Object)
            {
                if (!LoadFinalRequirements(finalReqTok.ToObject<JObject>()))
                {
                    DeclareLoadingError($"FinalRequirements were present in spec but failed to load");
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
                DeclareLoadingError($"No binary name in metadata");
                return false;
            }
            string candidatePath = Path.Combine(BinaryDirectory, binNameTok.ToObject<string>());
            if (File.Exists(candidatePath))
            {
                BinaryPath = candidatePath;
            }
            else
            {
                DeclareLoadingError($"Test binary not found at '{candidatePath}'");
                return false;
            }

            if (metaObj.TryGetValue("Bits", out JToken bitsTok) && bitsTok.Type == JTokenType.Integer)
            {
                TestBits = bitsTok.ToObject<int>();
            }
            else
            {
                DeclareLoadingError($"No test bitwidth in metadata");
                return false;
            }

            if (metaObj.TryGetValue("OS", out JToken OSTok) && OSTok.Type == JTokenType.String)
            {
                TestOS = bitsTok.ToObject<string>();
            }
            else
            {
                DeclareLoadingError($"No test OS in metadata");
                return false;
            }

            //optional fields
            if (metaObj.TryGetValue("Comment", out JToken descTok) && descTok.Type == JTokenType.String)
            {
                Comment = descTok.ToObject<string>();
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
                        DeclareLoadingError($"Failed to load final overall test requirements");
                        return false;
                    }
                }
            }

            if (reqsObj.TryGetValue("Process", out tok) && tok.Type == JTokenType.Object)
            {
                JObject items = tok.ToObject<JObject>();
                if (LoadProcessRequirements(items, out TraceRequirements requirement))
                {
                    _TraceRequirements = requirement;
                }
                else
                {
                    DeclareLoadingError($"Failed to load final process requirements");
                    return false;
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
                DeclareLoadingError($"Requirement {name} had bad format");
                return false;
            }



            string conditionText = condTok.ToObject<string>();
            testRequirement = new TestRequirement(name, resultValue, conditionText);
            if (testRequirement.Condition == RequirementCondition.INVALID)
            {
                DeclareLoadingError($"Invalid condition {conditionText} in requirement {name}");
                _loadingError = true;
                return false;
            }

            if (requirement.TryGetValue("Comment", out JToken commentTok) && commentTok.Type == JTokenType.String)
            {
                testRequirement.SetComment(commentTok.ToString());
            }


            return true;
        }


        bool LoadProcessRequirements(JToken procObj, out TraceRequirements ptr)
        {
            ptr = new TraceRequirements();
            if (procObj.Type != JTokenType.Object)
            {
                DeclareLoadingError($"JSON has invalid token type {procObj.Type} for a process object");
                return false;
            }

            //iterate through list of process+graph requirements
            foreach (var processTok in procObj.ToObject<JObject>())
            {
                switch (processTok.Key)
                {
                    case "Comment":
                        break;

                    case "ThreadRequirements":
                        if (processTok.Value.Type == JTokenType.Array)
                        {
                            JArray graphToks = processTok.Value.ToObject<JArray>();
                            foreach (var graphTok in graphToks)
                            {
                                if (LoadGraphRequirementsObject(graphTok, out REQUIREMENTS_LIST graphRequirements))
                                {
                                    ptr.ThreadRequirements.Add(graphRequirements);
                                }
                                else
                                {
                                    DeclareLoadingError($"JSON has invalid GraphRequirements list");
                                    return false;
                                }
                            }
                        }
                        break;

                    case "ProcessRequirements":
                        if (processTok.Value.Type == JTokenType.Object)
                        {
                            JObject processToks = processTok.Value.ToObject<JObject>();
                            foreach (var req in processToks)
                            {
                                if (LoadTestRequirement(req.Key, req.Value, out TestRequirement processReq))
                                {
                                    ptr.ProcessRequirements.Add(processReq);
                                }
                            }
                        }
                        break;

                    case "ChildProcessRequirements":
                        if (processTok.Value.Type == JTokenType.Array)
                        {
                            JArray items = processTok.Value.ToObject<JArray>();
                            foreach (var childProcessReq in items)
                            {
                                if (LoadProcessRequirements(childProcessReq, out TraceRequirements requirement))
                                {
                                    ptr.ChildProcessRequirements.Add(requirement);
                                }
                                else
                                {
                                    DeclareLoadingError($"Failed to load final childprocess requirements");
                                    return false;
                                }
                            }
                        }
                        else
                        {
                            DeclareLoadingError($"Non-array ChildProcessRequirements");
                            return false;
                        }
                        break;

                    default:

                        DeclareLoadingError($"JSON has invalid ProcessRequirement {processTok.Key}");
                        return false;
                }
            }
            return true;
        }


        bool LoadGraphRequirementsObject(JToken threadReqsObj, out REQUIREMENTS_LIST graphRequirements)
        {
            graphRequirements = new REQUIREMENTS_LIST()
            {
                value = new List<TestRequirement>()
            };
            if (threadReqsObj.Type != JTokenType.Object)
            {
                DeclareLoadingError($"JSON has invalid token type {threadReqsObj.Type} for a threads requirement list");
                return false;
            }


            foreach (var reqKVP in threadReqsObj.ToObject<JObject>())
            {
                if (reqKVP.Key == "Comment") continue;

                if (LoadTestRequirement(reqKVP.Key, reqKVP.Value, out TestRequirement graphReq))
                {
                    graphRequirements.value.Add(graphReq);
                }
                else
                {
                    DeclareLoadingError($"JSON has invalid Thread TestRequirement {reqKVP.Key}");
                    return false;
                }
            }
            return true;
        }

        void DeclareLoadingError(string error)
        {
            string log = $"Failed Loading TestCase '{JSONPath}': {error}";
            Logging.RecordLogEvent(log);
            LoadingErrors.Add(error);
            _loadingError = true;
        }



        public TestRequirement[] TestRunRequirements()
        {
            lock (_lock)
            {
                return _TestRunRequirements.ToArray();
            }
        }

        public TraceRequirements TraceRequirements()
        {
            lock (_lock)
            {
                return _TraceRequirements;
            }
        }

        readonly object _lock = new object();

        public void RecordRunning() { lock (_lock) { Running++; } }
        public void RecordFinished() { lock (_lock) { Running--; } }
        public void RecordPassed(int sessionID, TestCaseRun testrun)
        {
            lock (_lock)
            {
                _passed.TryGetValue(sessionID, out int val);
                _passed[sessionID] = val + 1;

                LatestResultState = eTestState.Passed;
                testrun.ResultCommentary.result = eTestState.Passed;
                LatestTestRun = testrun;
            }
        }
        public int CountPassed(int sessionID) { lock (_lock) { _passed.TryGetValue(sessionID, out int val); return val; } }

        public void RecordFailed(int sessionID, TestCaseRun testrun, string reason)
        {
            lock (_lock)
            {
                _failed.TryGetValue(sessionID, out int val);
                _failed[sessionID] = val + 1;
                LatestResultState = eTestState.Failed;
                testrun.ResultCommentary.result = eTestState.Failed;
                LatestTestRun = testrun;
                LatestErrorReason = reason;
            }
        }
        public int CountFailed(int sessionID) { lock (_lock) { _failed.TryGetValue(sessionID, out int val); return val; } }

    }
}
