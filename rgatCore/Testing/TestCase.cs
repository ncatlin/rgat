using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;

namespace rgat.Testing
{
    /// <summary>
    /// Comparisons that can be applied to process/thread attributes
    /// </summary>
    public enum RequirementCondition
    {
        /// <summary>
        /// The attribute is equal to a specified value
        /// </summary>
        Equals,
        /// <summary>
        /// The attribute is less than the specified value
        /// </summary>
        LessThan,
        /// <summary>
        /// The attribute is less than or equal to the specified value
        /// </summary>
        LessThanOrEqualTo,
        /// <summary>
        /// The attribute is greater than the specified value
        /// </summary>
        GreaterThan,
        /// <summary>
        /// The attribute is greater than or equal to the specified value
        /// </summary>
        GreaterThanOrEqualTo,
        /// <summary>
        /// The attribute exists in a collection
        /// </summary>
        Exists,
        /// <summary>
        /// The attribute does not exist in a specified list of values 
        /// /// </summary>
        Absent,
        /// <summary>
        /// The attribute is a collection which contains the value
        /// </summary>
        Contains,
        /// <summary>
        /// The attribute exists in a specified list of values
        /// </summary>
        OneOf,
        /// <summary>
        /// The attribute is equal to a specified value
        /// </summary>
        INVALID
    };

    /// <summary>
    /// Results from evaluating a test requirement
    /// </summary>
    public class REQUIREMENT_TEST_RESULTS
    {
        /// <summary>
        /// Results from evaluating a test requirement
        /// </summary>
        public REQUIREMENT_TEST_RESULTS()
        {
            Passed = new List<TestResultCommentary>();
            Failed = new List<TestResultCommentary>();
            Errors = new List<Tuple<TestRequirement, string>>();
        }

        /// <summary>
        /// Passed requirements
        /// </summary>
        public List<TestResultCommentary> Passed;
        /// <summary>
        /// Failed requirements
        /// </summary>
        public List<TestResultCommentary> Failed;
        /// <summary>
        /// Errors encountered evaluating each requirement
        /// </summary>
        public List<Tuple<TestRequirement, string>> Errors;
    }


    /// <summary>
    /// Results of a test run being compared against its requirements
    /// </summary>
    public class TRACE_TEST_RESULTS
    {
        /// <summary>
        /// Results of process requirements
        /// </summary>
        public REQUIREMENT_TEST_RESULTS ProcessResults = new REQUIREMENT_TEST_RESULTS();

        /// <summary>
        /// Results of thread requirements
        /// </summary>
        public Dictionary<REQUIREMENTS_LIST, Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS>> ThreadResults =
            new Dictionary<REQUIREMENTS_LIST, Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS>>();

        /// <summary>
        /// Results of child trace requirements
        /// </summary>
        public Dictionary<TraceRequirements, Dictionary<TraceRecord, TRACE_TEST_RESULTS>> ChildResults =
            new Dictionary<TraceRequirements, Dictionary<TraceRecord, TRACE_TEST_RESULTS>>();
    }


    /// <summary>
    /// A list of test requirements
    /// </summary>
    public struct REQUIREMENTS_LIST
    {
        /// <summary>
        /// list of requirements
        /// </summary>
        public List<TestRequirement> value;
    }


    /// <summary>
    /// A requirement to apply to a process or thread
    /// </summary>
    public class TestRequirement
    {
        /// <summary>
        /// The name of the requirement
        /// </summary>
        public string? Name { get; private set; }
        /// <summary>
        /// A comment about the requirement
        /// </summary>
        public string? Comment { get; private set; }
        /// <summary>
        /// The expected value of the requirement to evaluate to
        /// </summary>
        public JToken? ExpectedValue { get; private set; }
        /// <summary>
        /// A string representation of the expected value
        /// </summary>
        public string? ExpectedValueString { get; private set; }
        /// <summary>
        /// How to compare the test result to the expected value
        /// </summary>
        public RequirementCondition? Condition { get; private set; }

        /// <summary>
        /// A requirement for the test to pass
        /// </summary>
        /// <param name="name">Name of the requirement</param>
        /// <param name="value">Value being compared</param>
        /// <param name="condition">The comparison to perform</param>

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
                    JArray? items = ExpectedValue.ToObject<JArray>();
                    for (int i = 0; items is not null && i < items.Count; i++)
                    {
                        if (i > 0)
                        {
                            ExpectedValueString += ",";
                        }

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


        /// <summary>
        /// Compare an integer value
        /// </summary>
        /// <param name="value">An integer value</param>
        /// <param name="error">An error describing why it failed</param>
        /// <returns>true if pass, false if fail</returns>
        public bool Compare(int value, out string? error)
        {
            error = "";
            if (ExpectedValue is null)
            {
                error = "Null expected value";
                return false;
            }

            if (Condition == RequirementCondition.OneOf)
            {
                if (ExpectedValue.Type != JTokenType.Array)
                {
                    error = $"int 'OneOf' comparison requires array token, but token was of type {ExpectedValue.Type}";
                    return false;
                }

                JArray? expectedArr = ExpectedValue.ToObject<JArray>();
                if (expectedArr is not null)
                {
                    foreach (JToken arrayItem in expectedArr)
                    {
                        if (arrayItem.Type == JTokenType.Integer && arrayItem.ToObject<int>() == value)
                        {
                            return true;
                        }
                    }
                }
                error = $"No member was equal to {value}";
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


        /// <summary>
        /// Compare a long value
        /// </summary>
        /// <param name="value">An long value</param>
        /// <param name="error">An error describing why it failed</param>
        /// <returns>true if pass, false if fail</returns>
        public bool Compare(long value, out string? error)
        {
            if (ExpectedValue is null)
            {
                error = "Null expected value";
                return false;
            }
            error = "";
            if (Condition == RequirementCondition.OneOf)
            {
                if (ExpectedValue.Type != JTokenType.Array)
                {
                    error = $"long 'OneOf' comparison requires array token, but token was of type {ExpectedValue.Type}";
                    return false;
                }
                JArray? expectedArr = ExpectedValue.ToObject<JArray>();
                if (expectedArr is not null)
                {
                    foreach (JToken arrayItem in expectedArr)
                    {
                        if (arrayItem.Type == JTokenType.Integer && arrayItem.ToObject<long>() == value)
                        {
                            return true;
                        }
                    }
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



        /// <summary>
        /// Compare a ulong value
        /// </summary>
        /// <param name="value">A ulong value</param>
        /// <param name="error">An error describing why it failed</param>
        /// <returns>true if pass, false if fail</returns>
        public bool Compare(ulong value, out string? error)
        {
            if (ExpectedValue is null)
            {
                error = "Null expected value";
                return false;
            }
            error = "";
            if (Condition == RequirementCondition.OneOf)
            {
                if (ExpectedValue is null || ExpectedValue.Type != JTokenType.Array)
                {
                    error = $"long 'OneOf' comparison requires array token, but token was of type {ExpectedValue?.Type}";
                    return false;
                }
                JArray? expectedArr = ExpectedValue.ToObject<JArray>();
                if (expectedArr is not null)
                {
                    foreach (JToken? arrayItem in expectedArr)
                    {
                        if (arrayItem.Type == JTokenType.Integer && arrayItem.ToObject<ulong>() == value)
                        {
                            return true;
                        }
                    }
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

        /// <summary>
        /// Set the requirement comment
        /// </summary>
        /// <param name="value"></param>
        public void SetComment(string value) { Comment = "Comment: " + value; }

    }

    /// <summary>
    /// A set of requirements for a test process, threads and child processes
    /// </summary>
    public class TraceRequirements
    {
        /// <summary>
        /// list of requirements the process (ie: TraceRecord) must meet
        /// </summary>
        public List<TestRequirement> ProcessRequirements = new List<TestRequirement>();

        /// <summary>
        /// list of requirements the process threads (ie: ProtoGraphs) must meet
        /// </summary>
        public List<REQUIREMENTS_LIST> ThreadRequirements = new List<REQUIREMENTS_LIST>();

        /// <summary>
        /// list of requirements for descendant processes
        /// </summary>
        public List<TraceRequirements> ChildProcessRequirements = new List<TraceRequirements>();
    }


    /// <summary>
    /// A basic state for a test run
    /// </summary>
    public enum eTestState
    {
        /// <summary>
        /// Not executed yet
        /// </summary>
        NotRun,
        /// <summary>
        /// All requirements passed
        /// </summary>
        Passed,
        /// <summary>
        /// At least one requirement was not met
        /// </summary>
        Failed
    };


    /// <summary>
    /// A test consisting of a set of requirements and an associated binary to apply them to
    /// </summary>
    public class TestCase
    {

        private bool _loadingError = false;

        /// <summary>
        /// Errors encountered loading the test case from JSON
        /// </summary>
        public List<string> LoadingErrors = new List<string>();
        /// <summary>
        /// If the test was sucessfully loaded
        /// </summary>
        public bool Loaded { get; private set; }


        /// <summary>
        /// The lastest result from running this test
        /// </summary>
        public eTestState LatestResultState = eTestState.NotRun;
        /// <summary>
        /// The latest run object for this test
        /// </summary>
        public TestCaseRun? LatestTestRun { get; private set; }
        /// <summary>
        /// The latest error from this test
        /// </summary>
        public string? LatestErrorReason { get; private set; }
        /// <summary>
        /// File path of the test description
        /// </summary>
        public string JSONPath { get; private set; }

        /// <summary>
        /// File path of the test binary
        /// </summary>
        public string BinaryPath { get; private set; } = "";
        /// <summary>
        /// Directory of the test binary
        /// </summary>
        public string? BinaryDirectory { get; private set; }
        /// <summary>
        /// Category of the test
        /// </summary>
        public string? CategoryName { get; private set; }
        /// <summary>
        /// Name of the test
        /// </summary>
        public string? TestName { get; private set; }
        /// <summary>
        /// The test is starred on the UI
        /// </summary>
        public bool Starred;
        /// <summary>
        /// The test writers comment for the test
        /// </summary>
        public string? Comment { get; private set; }
        /// <summary>
        /// Is the test binary 32 or 64 bits
        /// </summary>
        public int TestBits { get; private set; }
        /// <summary>
        /// What OS the test runs on
        /// </summary>
        public string? TestOS { get; private set; }
        /// <summary>
        /// Is the test currently running
        /// </summary>
        public int Running { get; private set; }

        private readonly Dictionary<int, int> _passed = new Dictionary<int, int>();
        private readonly Dictionary<int, int> _failed = new Dictionary<int, int>();

        /// <summary>
        /// A list of conditions met by the entire test itself
        /// </summary>
        private readonly List<TestRequirement> _TestRunRequirements = new List<TestRequirement>();

        /// <summary>
        /// A nested list of requirements for each thread
        /// vague pseudo-json example [{C:6, [C:1, C:3]},{C:1, [C:7,C:12]}]
        ///     This expects two processes, each producing 2 thread graphs
        ///     One process must meet condtion C6 has threads meeting condition C1, the other meeting condition C3. 
        ///     Ditto for the other process needing to meet condtion C1 with threads meeting conditions 7, 12
        /// </summary>
        private TraceRequirements _TraceRequirements = new TraceRequirements();

        public readonly Dictionary<string, bool> ConfigToggles = new();


        /// <summary>
        /// Load a test case from a json file
        /// </summary>
        /// <param name="jsonpath">Path of a JSON test description file to load</param>
        /// <param name="category">The category of the test</param>
        public TestCase(string jsonpath)
        {
            JSONPath = jsonpath;
            TestName = Path.GetFileName(jsonpath).Split(CONSTANTS.TESTS.testextension)[0];
            try
            {
                BinaryDirectory = Directory.GetParent(jsonpath)?.FullName;
                if (BinaryDirectory == null || BinaryDirectory == "")
                {
                    DeclareLoadingError($"Unable to get directory of test {jsonpath}");
                    return;
                }
            }
            catch (Exception e)
            {
                DeclareLoadingError($"Exception {e.Message} getting directory of test {jsonpath}");
                return;
            }

            lock (_lock)
            {
                JObject? jsonObj;
                try
                {
                    if (!ParseTestSpec(jsonpath, out jsonObj) || jsonObj is null)
                    {
                        return;
                    }
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

        readonly List<string> ConfigurableOptionsBoolean = new List<string>()
        {
            "DiscardTraceData",
            "HideAPIThunks"
        };

        public ProcessLaunchSettings CreateSettings()
        {
            ProcessLaunchSettings result = new ProcessLaunchSettings(BinaryPath);

            result.DiscardReplayData = true;
            result.TraceChoices.InitDefaultExclusions();


            foreach (string settingName in ConfigurableOptionsBoolean)
            {
                if (ConfigToggles.TryGetValue(settingName, out bool settingVal))
                {
                    switch (settingName)
                    {
                        case "DiscardTraceData":
                            result.DiscardReplayData = settingVal;
                            break;
                        case "HideAPIThunks":
                            result.HideAPIThunks = settingVal;
                            break;
                    }
                }
            }

            return result;
        }

        private bool ParseTestSpec(string jsonpath, out Newtonsoft.Json.Linq.JObject? jsnobj)
        {
            jsnobj = null;
            string jsnfile;
            try
            {
                StreamReader file = File.OpenText(jsonpath);
                jsnfile = file.ReadToEnd();
                file.Close();
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

        private bool LoadTestCase(JObject testSpec)
        {
            //mandatory for test cases to have metadata
            if (!testSpec.TryGetValue("Meta", out JToken? metaTok) ||
                metaTok is null ||
                metaTok.Type is not JTokenType.Object)
            {
                DeclareLoadingError($"No test metadata in test specification");
                return false;
            }

            JObject? metadata = metaTok.ToObject<JObject>();
            if (metadata is null || !LoadSpecMetadata(metadata))
            {
                return false;
            }

            //optional: settings that will be applied before for the trace starts
            if (testSpec.TryGetValue("Configuration", out JToken? configTok) && configTok.Type == JTokenType.Object)
            {
                JObject? confObj = configTok.ToObject<JObject>();
                if (confObj is null || !LoadConfiguration(confObj))
                {
                    DeclareLoadingError($"Configuration were present in spec but failed to load");
                    return false;
                }
            }

            //optional: requirements for the trace state when the test execution has finished
            if (testSpec.TryGetValue("FinalRequirements", out JToken? finalReqTok) && finalReqTok.Type == JTokenType.Object)
            {
                JObject? finalReqObj = finalReqTok.ToObject<JObject>();
                if (finalReqObj is null || !LoadFinalRequirements(finalReqObj))
                {
                    DeclareLoadingError($"FinalRequirements were present in spec but failed to load");
                    return false;
                }
            }

            return _loadingError == false;
        }

        private bool LoadSpecMetadata(JObject metaObj)
        {
            //mandatory fields

            if (!metaObj.TryGetValue("BinaryName", out JToken? binNameTok) || binNameTok.Type != JTokenType.String)
            {
                DeclareLoadingError($"No binary name in metadata");
                return false;
            }

            string? binname = binNameTok.ToObject<string>();
            if (binname is null || BinaryDirectory is null)
            {
                DeclareLoadingError($"Failed to load binary name from metadata");
                return false;
            }

            string candidatePath = Path.Combine(BinaryDirectory, binname);
            if (File.Exists(candidatePath))
            {
                BinaryPath = candidatePath;
            }
            else
            {
                DeclareLoadingError($"Test binary not found at '{candidatePath}'");
                return false;
            }

            if (metaObj.TryGetValue("Bits", out JToken? bitsTok) && bitsTok.Type == JTokenType.Integer)
            {
                TestBits = bitsTok.ToObject<int>();
            }
            else
            {
                DeclareLoadingError($"No test bitwidth in metadata");
                return false;
            }

            if (metaObj.TryGetValue("OS", out JToken? OSTok) && OSTok.Type == JTokenType.String)
            {
                TestOS = OSTok.ToObject<string>();
            }

            if (TestOS is null)
            {
                DeclareLoadingError($"No test OS in metadata");
                return false;
            }  
            
            if (metaObj.TryGetValue("Category", out JToken? catTok) && catTok != null && catTok.Type == JTokenType.String )
            {
                CategoryName = catTok.ToObject<string>();
            }

            if(CategoryName is null)
            {
                DeclareLoadingError($"No valid test category in metadata");
                return false;
            }

            //optional fields
            if (metaObj.TryGetValue("Comment", out JToken? descTok) && descTok.Type == JTokenType.String)
            {
                Comment = descTok.ToObject<string>();
            }
            return true;
        }


        private bool LoadConfiguration(JObject confObj)
        {
            foreach (string settingName in ConfigurableOptionsBoolean)
            {
                if (confObj.TryGetValue(settingName, out JToken? settingBool) &&
                    settingBool is not null && 
                    settingBool.Type == JTokenType.Boolean)
                {
                    ConfigToggles[settingName] = settingBool.ToObject<bool>();
                }
            }

            return true;
        }


        /// <summary>
        /// Load the test passing conditions
        /// </summary>
        /// <param name="reqsObj">JObject of the unserialised conditions</param>
        /// <returns>Whether loading succeeded</returns>
        private bool LoadFinalRequirements(JObject reqsObj)
        {

            // Optional requirements that the entire test must satisfy at completion (eg: time it took to run, total processes spawned)
            if (reqsObj.TryGetValue("Test", out JToken? tok) && tok.Type == JTokenType.Object)
            {
                JObject? items = tok.ToObject<JObject>();
                if (items is null)
                {
                    DeclareLoadingError($"Failed to load final overall test requirements");
                    return false;
                }
                foreach (var req in items)
                {
                    if (req.Key == "Comment" || req.Value is null)
                    {
                        continue;
                    }

                    if (LoadTestRequirement(req.Key, req.Value, out TestRequirement? requirement) && requirement is not null)
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
                JObject? items = tok.ToObject<JObject>();
                if (items is not null && LoadProcessRequirements(items, out TraceRequirements requirement))
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
        private bool LoadTestRequirement(string name, JToken tok, out TestRequirement? testRequirement)
        {
            testRequirement = null;
            if (tok.Type != JTokenType.Object)
            {
                return false;
            }

            JObject? requirement = tok.ToObject<JObject>();
            if (requirement is null ||
                !requirement.TryGetValue("Value", out JToken? resultValue) ||
                !requirement.TryGetValue("Condition", out JToken? condTok) ||
                condTok is null ||
                condTok.Type != JTokenType.String)
            {
                _loadingError = true;
                DeclareLoadingError($"Requirement {name} had bad format");
                return false;
            }

            string? conditionText = condTok.ToObject<string>();
            if (conditionText is not null)
            {
                testRequirement = new TestRequirement(name, resultValue, conditionText);
            }

            if (testRequirement is null || testRequirement.Condition == RequirementCondition.INVALID)
            {
                DeclareLoadingError($"Invalid condition {conditionText} in requirement {name}");
                _loadingError = true;
                return false;
            }

            if (requirement.TryGetValue("Comment", out JToken? commentTok) && commentTok.Type == JTokenType.String)
            {
                testRequirement.SetComment(commentTok.ToString());
            }


            return true;
        }

        private bool LoadProcessRequirements(JToken procObj, out TraceRequirements ptr)
        {
            ptr = new TraceRequirements();
            if (procObj is null || procObj.Type != JTokenType.Object)
            {
                DeclareLoadingError($"JSON has invalid token type {procObj?.Type} for a process object");
                return false;
            }

            //iterate through list of process+graph requirements
            JObject? processReqsObj = procObj.ToObject<JObject>();
            if (processReqsObj is null)
            {
                DeclareLoadingError($"JSON has invalid token type {procObj.Type} for a process object");
                return false;
            }

            foreach (var processTok in processReqsObj)
            {
                if (processTok.Value is null)
                {
                    continue;
                }

                switch (processTok.Key)
                {
                    case "Comment":
                        break;

                    case "ThreadRequirements":
                        {
                            if (processTok.Value.Type is not JTokenType.Array)
                            {
                                DeclareLoadingError($"JSON has invalid GraphRequirements list");
                                return false;
                            }
                            JArray? graphToks = processTok.Value.ToObject<JArray>();
                            if (graphToks is null)
                            {

                                DeclareLoadingError($"JSON has invalid GraphRequirements list");
                                return false;
                            }
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
                        {
                            if (processTok.Value.Type is not JTokenType.Object)
                            {
                                DeclareLoadingError($"JSON has invalid ProcessRequirements list");
                                return false;
                            }
                            JObject? processToks = processTok.Value.ToObject<JObject>();
                            if (processToks is null)
                            {

                                DeclareLoadingError($"JSON has invalid ProcessRequirements list");
                                return false;
                            }

                            foreach (var req in processToks)
                            {
                                if (req.Value is not null &&
                                    LoadTestRequirement(req.Key, req.Value, out TestRequirement? processReq)
                                    && processReq is not null)
                                {
                                    ptr.ProcessRequirements.Add(processReq);
                                }
                            }

                        }
                        break;

                    case "ChildProcessRequirements":
                        {
                            if (processTok.Value.Type is not JTokenType.Array)
                            {
                                DeclareLoadingError($"JSON has invalid ChildProcessRequirements list");
                                return false;
                            }
                            JArray? childPropReqs = processTok.Value.ToObject<JArray>();
                            if (childPropReqs is null)
                            {

                                DeclareLoadingError($"JSON has invalid ChildProcessRequirements list");
                                return false;
                            }

                            foreach (var childProcessReq in childPropReqs)
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
                        break;

                    default:
                        DeclareLoadingError($"JSON has invalid ProcessRequirement {processTok.Key}");
                        return false;
                }
            }
            return true;
        }

        private bool LoadGraphRequirementsObject(JToken threadReqsObj, out REQUIREMENTS_LIST graphRequirements)
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

            JObject? threadGraphReqs = threadReqsObj.ToObject<JObject>();
            if (threadGraphReqs is null)
            {
                return false;
            }

            foreach (var reqKVP in threadGraphReqs)
            {
                if (reqKVP.Key == "Comment" || reqKVP.Value is null)
                {
                    continue;
                }

                if (LoadTestRequirement(reqKVP.Key, reqKVP.Value, out TestRequirement? graphReq) && graphReq is not null)
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

        private void DeclareLoadingError(string error)
        {
            string log = $"Failed Loading TestCase '{JSONPath}': {error}";
            Logging.RecordLogEvent(log);
            LoadingErrors.Add(error);
            _loadingError = true;
        }


        /// <summary>
        /// Fetch test run requirements. Thread safe for GUi rendering
        /// </summary>
        /// <returns>Array of test run requirements</returns>
        public TestRequirement[] TestRunRequirements()
        {
            lock (_lock)
            {
                return _TestRunRequirements.ToArray();
            }
        }


        /// <summary>
        /// Fetch trace (whole process) requirements. Thread safe for GUi rendering
        /// </summary>
        /// <returns>Array of process requirements</returns>
        public TraceRequirements TraceRequirements()
        {
            lock (_lock)
            {
                return _TraceRequirements;
            }
        }

        private readonly object _lock = new object();

        /// <summary>
        /// Increase the count of running tests
        /// </summary>
        public void RecordRunning() { lock (_lock) { Running++; } }

        /// <summary>
        /// Decrease the count of running tests
        /// </summary>
        public void RecordFinished() { lock (_lock) { Running--; } }

        /// <summary>
        /// Record a test where all requirements were met
        /// </summary>
        /// <param name="sessionID">Session ID of the test</param>
        /// <param name="testrun">The sucedssful test run</param>
        public void RecordPassed(int sessionID, TestCaseRun testrun)
        {
            lock (_lock)
            {
                _passed.TryGetValue(sessionID, out int val);
                _passed[sessionID] = val + 1;

                LatestResultState = eTestState.Passed;
                testrun.ResultCommentary.Verdict = eTestState.Passed;
                LatestTestRun = testrun;
            }
        }

        /// <summary>
        /// Get the number of passed tests in the session
        /// </summary>
        /// <param name="sessionID">Session ID to check</param>
        /// <returns>number of passed tests</returns>
        public int CountPassed(int sessionID) { lock (_lock) { _passed.TryGetValue(sessionID, out int val); return val; } }


        /// <summary>
        /// Record a test where one or more requirements were not met
        /// </summary>
        /// <param name="sessionID">Session ID of the test</param>
        /// <param name="testrun">The sucedssful test run</param>
        /// <param name="reason">Explaination for why the test failed</param>
        public void RecordFailed(int sessionID, TestCaseRun testrun, string reason)
        {
            lock (_lock)
            {
                _failed.TryGetValue(sessionID, out int val);
                _failed[sessionID] = val + 1;
                LatestResultState = eTestState.Failed;
                testrun.ResultCommentary.Verdict = eTestState.Failed;
                LatestTestRun = testrun;
                LatestErrorReason = reason;
            }
        }

        /// <summary>
        /// Get the number of failed tests in the session
        /// </summary>
        /// <param name="sessionID">Session ID to check</param>
        /// <returns>number of failed tests</returns>
        public int CountFailed(int sessionID) { lock (_lock) { _failed.TryGetValue(sessionID, out int val); return val; } }

    }
}
