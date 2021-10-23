using ImGuiNET;
using rgat.Testing;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;

namespace rgat.Widgets
{
    internal class TestCategory
    {
        public List<TestCase> Tests = new List<TestCase>();
        public bool Starred;
        public string? CategoryName;
        public string? ID;
    }

    internal class TestsWindow
    {
        public TestsWindow(rgatState clientState, ImGuiController controller)
        {

            _testingThread = new TestRunner(clientState);
            _controller = controller;
            InitTestingSession();

        }

        private readonly TestRunner _testingThread;
        private readonly ImGuiController _controller;
        private readonly Dictionary<string, TestCategory> _testDirectories = new Dictionary<string, TestCategory>();
        private readonly Dictionary<string, TestCategory> _testCategories = new Dictionary<string, TestCategory>();
        private List<string> _orderedCategories = new List<string>();
        private bool _testsRunning = false;

        private enum eCatFilter { All = 0, Remaining = 1, Complete = 2, Passing = 3, Failed = 4, StarredTest = 5, StarredCat = 6 }

        private int _selectedFilter = (int)eCatFilter.All;
        private readonly string[] filters = new string[] { "Show All Tests", "Show Remaining Tests","Show Complete Tests",
            "Show Passing Tests","Show Failed Tests", "Show Starred Tests", "Show Starred Categories"};
        private readonly int treeWidth = 400;
        private readonly List<TestCase> _queuedTests = new List<TestCase>();
        private readonly List<TestCase> _allTests = new List<TestCase>();
        private Dictionary<string, float> _sessionStats = new Dictionary<string, float>();
        private readonly object _TestsLock = new object();


        public void InitTestingSession()
        {
            lock (_TestsLock)
            {
                _sessionStats = new Dictionary<string, float>
                {
                    ["Loaded"] = 0,
                    ["Passed"] = 0,
                    ["Failed"] = 0,
                    ["Executed"] = 0
                };

                _testDirectories.Clear();
                _testCategories.Clear();
                _orderedCategories.Clear();
                _allTests.Clear();
                _queuedTests.Clear();

                string testspath = GlobalConfig.GetSettingPath(CONSTANTS.PathKey.TestsDirectory);
                if (!Directory.Exists(testspath))
                {
                    return;
                }

                string[] testdirs = Directory.EnumerateDirectories(testspath, searchPattern: "*", SearchOption.AllDirectories)
                    .Where(x => Directory.GetFiles(x).Any(file => file.EndsWith(CONSTANTS.TESTS.testextension)))
                    .ToArray();

                List<Tuple<uint, string>> validDirs = new List<Tuple<uint, string>>();
                foreach (string testdir in testdirs)
                {

                    try
                    {
                        LoadTestsInDir(testdir);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Unhandled exception parsing tests in directory {testdir}: {e.Message}",
                            Logging.LogFilterType.Debug);
                        continue;
                    }
                }

                _orderedCategories = _testCategories.OrderBy(x => x.Key).Select(x => x.Key).ToList();
                _currentSession += 1;
                _testingThread.InitSession(_currentSession);
            }

            UpdateStats();
            Logging.RecordLogEvent($"Loaded {_testDirectories.Count} test directories");

        }


        private void LoadTestsInDir(string testdir)
        {

            string[] testfiles = Directory.GetFiles(testdir, searchPattern: "*" + CONSTANTS.TESTS.testextension, SearchOption.TopDirectoryOnly)
                .ToArray();

            List<TestCase> loadedTests = LoadTests(testfiles);

            foreach (TestCase testspec in loadedTests)
            {
                string categoryName = testspec.CategoryName!;
                if (_testCategories.TryGetValue(categoryName, out TestCategory? testcategory) is false || testcategory is null)
                {
                    testcategory = new TestCategory()
                    {
                        CategoryName = categoryName,
                        Tests = new(),
                        Starred = false,
                        ID = categoryName + $"{_testCategories.Count}"
                    };
                    _testCategories[categoryName] = testcategory;
                }
                testcategory.Tests.Add(testspec);
                _sessionStats["Loaded"] += 1;
            }

            foreach (var testsCategory in _testCategories)
            {
                _allTests.AddRange(testsCategory.Value.Tests);
            }

        }


        private List<TestCase> LoadTests(string[] testfiles)
        {
            List<TestCase> results = new();
            foreach (string testfile in testfiles)
            {
                try
                {
                    TestCase t = new TestCase(testfile);
                    if (t.Loaded)
                    {
                        results.Add(t);
                    }
                }
                catch (Exception e)
                {
                    Logging.RecordLogEvent($"Unhandled Exception parsing test file {testfile}: {e.Message}");
                    continue;
                }
            }
            return results;
        }

        private int _currentSession = 0;
        public void Draw(ref bool openFlag)
        {
            UpdateStats();
            if (ImGui.Begin("Run Tests", ref openFlag, ImGuiWindowFlags.None))
            {
                DrawTestsTree();
                ImGui.SameLine();
                ImGui.BeginGroup();
                DrawStatusBanner();
                float height = ImGui.GetContentRegionAvail().Y;
                float controlsHeight = 90;
                //ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourImGui(ImGuiCol.c));
                if (ImGui.BeginChild("#TestsOutputWindow", new Vector2(ImGui.GetContentRegionAvail().X, height - controlsHeight)))
                {
                    var i = 0;
                    if (testSpecsShowUntested)
                    {
                        foreach (var testcase in _allTests)
                        {
                            if (testcase.LatestResultState == eTestState.NotRun)
                            {
                                DrawTestSpecExplainTree(testcase);
                            }
                        }
                    }

                    //ImGui.PushStyleColor(ImGuiCol.TableRowBg, Themes.GetThemeColourImGui(ImGuiCol.ChildBg, 190));
                    //ImGui.PushStyleColor(ImGuiCol.TableRowBgAlt, Themes.GetThemeColourImGui(ImGuiCol.ChildBg, 230));
                    ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(0, 3));
                    ImGui.PushStyleVar(ImGuiStyleVar.ItemInnerSpacing, new Vector2(0, 0));
                    TestSession session = _testingThread.GetTestSession(this._currentSession);
                    if (session != null)
                    {
                        foreach (var testcaserun in session.tests)
                        {
                            if (!testcaserun.Complete)
                            {
                                continue;
                            }

                            if (testcaserun.ResultCommentary.Verdict == eTestState.Passed)
                            {
                                if (testSpecsShowPassed)
                                {
                                    if (ImGui.BeginTable($"#RunTree{i++}", 1, ImGuiTableFlags.RowBg))
                                    {
                                        DrawTestResultsExplainTree(testcaserun);
                                        ImGui.EndTable();
                                    }
                                }
                            }
                            else if (testcaserun.ResultCommentary.Verdict == eTestState.Failed)
                            {
                                if (testSpecsShowFailed)
                                {
                                    if (ImGui.BeginTable($"#RunTree{i++}", 1, ImGuiTableFlags.RowBg))
                                    {
                                        DrawTestResultsExplainTree(testcaserun);

                                        ImGui.EndTable();
                                    }
                                }
                            }
                            else
                            {
                                Debug.Assert(false);
                            }
                        }
                    }
                    //ImGui.PopStyleColor(2);
                    ImGui.PopStyleVar(2);

                    ImGui.EndChild();
                }
                //ImGui.PopStyleColor();
                DrawQueueControls(controlsHeight);
                ImGui.EndGroup();
                ImGui.End();
            }

            if (_testsRunning)
            {
                if (autoStopOnFailure && _sessionStats["Failed"] > 0)
                {
                    _testsRunning = false;
                }
                else if (_queuedTests.Count > 0 && _testingThread.FreeTestSlots > 0)
                {
                    lock (_TestsLock)
                    {
                        TestCase test = _queuedTests.First();
                        long testID = _testingThread.RunTest(_currentSession, test);
                        if (testID > -1)
                        {
                            _queuedTests.Remove(test);
                            if (autoRequeue)
                            {
                                AddTestToQueue(test);
                            }
                        }
                    }
                }
            }
        }

        private void DrawTestSpecExplainTree(TestCase testcase)
        {
            if (ImGui.TreeNodeEx($"{testcase.CategoryName}:{testcase.TestName} - [Not run]"))
            {
                var wholeTestReqs = testcase.TestRunRequirements();

                if (ImGui.TreeNodeEx($"{wholeTestReqs.Length} Whole Test Requirements", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
                {
                    foreach (var wholeTestReq in wholeTestReqs)
                    {
                        ImGui.Text($"Test run Requirement: {wholeTestReq.Name} {wholeTestReq.Condition} {wholeTestReq.ExpectedValueString}");
                        SmallWidgets.MouseoverText(wholeTestReq.Comment);
                    }
                    ImGui.TreePop();
                }

                var traceRequirements = testcase.TraceRequirements();
                DrawTraceSpecExplainTreeNodes(traceRequirements);


                ImGui.TreePop();
            }
            if (testcase.Comment?.Length > 0)
            {
                SmallWidgets.MouseoverText($"Description: {testcase.Comment}");
            }
        }

        private void DrawTraceSpecExplainTreeNodes(TraceRequirements traceRequirements)
        {
            var processRequirements = traceRequirements.ProcessRequirements;
            var threadRequirements = traceRequirements.ThreadRequirements;
            var childReqsList = traceRequirements.ChildProcessRequirements;

            if (processRequirements.Count is not 0 &&
                ImGui.TreeNodeEx($"{processRequirements.Count} Process Requirements", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
            {
                foreach (var req in processRequirements)
                {
                    ImGui.Text($"Process Requirement: {req.Name} {req.Condition} {req.ExpectedValueString}");
                    SmallWidgets.MouseoverText(req.Comment);
                }
                ImGui.TreePop();
            }

            if (threadRequirements.Count is not 0 &&
                ImGui.TreeNodeEx($"{threadRequirements.Count} Set{(threadRequirements.Count != 1 ? "s" : "")} of Thread Requirements", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
            {
                foreach (var threadsReqList in threadRequirements)
                {
                    if (ImGui.TreeNodeEx($"{threadsReqList.value.Count} Thread Requirements", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
                    {
                        foreach (var req in threadsReqList.value)
                        {
                            ImGui.Text($"Thread Requirement: {req.Name} {req.Condition} {req.ExpectedValueString}");
                            SmallWidgets.MouseoverText(req.Comment);
                        }

                        ImGui.TreePop();
                    }
                }
                ImGui.TreePop();
            }

            if (childReqsList.Count is not 0 &&
                ImGui.TreeNodeEx($"{childReqsList.Count} child trace requirements", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
            {
                foreach (var childTraceReqs in childReqsList)
                {
                    DrawTraceSpecExplainTreeNodes(childTraceReqs);
                }
                ImGui.TreePop();
            }
        }

        private void DrawTestResultsExplainTree(TestCaseRun testcaserun)
        {

            //todo - list of test results, not latest

            /*
            eTestState activeState;
            if (autoStopOnFailure && testcase.CountFailed(_currentSession) > 0)
            {
                activeState = eTestState.Failed;
            }
            else
            {
                activeState = testcase.LatestResultState;
            }


            switch (activeState)
            {
                case eTestState.Failed:
                    stateString = "Failed";
                    headerflags = ImGuiTreeNodeFlags.DefaultOpen;
                    break;
                case eTestState.Passed:
                    stateString = "Passed";
                    headerflags = ImGuiTreeNodeFlags.None;
                    break;
                case eTestState.NotRun:
                    stateString = "Not Run";
                    headerflags = ImGuiTreeNodeFlags.None;
                    break;
                default:
                    headerflags = ImGuiTreeNodeFlags.None;
                    stateString = "Bad state";
                    break;
            }*/



            TraceTestResultCommentary resultsCommentary = testcaserun.ResultCommentary;
            TestCase testcase = testcaserun.GetTestCase;
            string stateString = resultsCommentary.Verdict == eTestState.Passed ? "Passed" : "Failed";
            ImGuiTreeNodeFlags headerflags = resultsCommentary.Verdict == eTestState.Passed ? ImGuiTreeNodeFlags.None : ImGuiTreeNodeFlags.DefaultOpen;


            uint passHighlight = Themes.GetThemeColourWRF(Themes.eThemeColour.GoodStateColour).ToUint(0x10);
            uint failHighlight = Themes.GetThemeColourWRF(Themes.eThemeColour.BadStateColour).ToUint(0x30);

            ImGui.TableNextRow();
            if (resultsCommentary.Verdict is eTestState.Failed)
            {
                ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, failHighlight);
            }
            else
            {

                ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, passHighlight);
            }

            ImGui.TableNextColumn();

            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 4);
            ResultIconSameLine(pass: resultsCommentary.Verdict is eTestState.Passed);
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() - 4);
            if (ImGui.TreeNodeEx($"{testcase.CategoryName}:{testcase.TestName} - [{stateString} after {testcaserun.TestDurationString}]"))
            {
                ImGui.Indent(12);
                var wholeTestReqs = testcase.TestRunRequirements();

                ImGui.TableNextRow();
                //ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, 0);
                ImGui.TableNextColumn();
                if (ImGui.TreeNodeEx($"{wholeTestReqs.Length} General Test Requirements", headerflags)) //toto plural/singular
                {
                    foreach (var wholeTestReq in wholeTestReqs)
                    {
                        TestResultCommentary results = resultsCommentary.generalTests[wholeTestReq];

                        ImGui.TableNextRow();
                        if (results.result is eTestState.Failed)
                        {
                            ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, passHighlight);
                        }
                        ImGui.TableNextColumn();
                        ResultIconSameLine(pass: results.result == eTestState.Passed);
                        ImGui.Text($"Test run Requirement: {wholeTestReq.Name} [Result: {results.comparedValueString}] {wholeTestReq.Condition} [Expected: {wholeTestReq.ExpectedValueString}]");
                        SmallWidgets.MouseoverText(wholeTestReq.Comment);
                    }

                    ImGui.TreePop();
                }

                var traceRequirements = testcase.TraceRequirements();
                DrawTraceResultsExplainTreeNodes(traceRequirements, resultsCommentary, 0);


                ImGui.Indent(-12);
                ImGui.TreePop();
            }
        }

        private static void ResultIconSameLine(bool pass)
        {
            uint colour = pass ? Themes.GetThemeColourUINT(Themes.eThemeColour.GoodStateColour) : Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour);
            ImGui.PushStyleColor(ImGuiCol.Text, colour);
            ImGui.Text($"{(pass ? ImGuiController.FA_ICON_TICK : ImGuiController.FA_ICON_CROSS)}");
            ImGui.PopStyleColor();
            ImGui.SameLine();
        }

        private void DrawTraceResultsExplainTreeNodes(TraceRequirements traceRequirements, TraceTestResultCommentary commentary, int depth)
        {
            var processRequirements = traceRequirements.ProcessRequirements;
            var threadRequirements = traceRequirements.ThreadRequirements;
            var childReqsList = traceRequirements.ChildProcessRequirements;

            uint failHighlight = Themes.GetThemeColourWRF(Themes.eThemeColour.BadStateColour).ToUint(0x30);

            TRACE_TEST_RESULTS comments = commentary.traceResults;

            ImGui.TableNextRow();
            //ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, 0);
            ImGui.TableNextColumn();
            if (ImGui.TreeNodeEx($"{processRequirements.Count} Process Requirements", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
            {
                foreach (var comm in comments.ProcessResults.Passed)
                {
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    TestRequirement req = comm.requirement;
                    ResultIconSameLine(pass: true);
                    ImGui.Text($"Process Requirement: {req.Name} ({comm.comparedValueString}) {req.Condition} {req.ExpectedValueString}");
                    SmallWidgets.MouseoverText(req.Comment);
                }
                foreach (var comm in comments.ProcessResults.Failed)
                {
                    ImGui.TableNextRow();
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, failHighlight);
                    ImGui.TableNextColumn();
                    TestRequirement req = comm.requirement;
                    ResultIconSameLine(pass: false);
                    ImGui.Text($"Process Requirement: {req.Name} ({comm.comparedValueString}) {req.Condition} {req.ExpectedValueString}");
                    SmallWidgets.MouseoverText(req.Comment);
                }

                ImGui.TreePop();
            }

            ImGui.TableNextRow();
            //ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, 0);
            ImGui.TableNextColumn();
            int reqCount = threadRequirements.Count;
            if (ImGui.TreeNodeEx($"{reqCount} set{(reqCount is 0 ? "" : "s")} of Thread Requirements", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
            {
                int setID = 0;
                foreach (var threadsReqListKVP in comments.ThreadResults)
                {
                    REQUIREMENTS_LIST threadsReqList = threadsReqListKVP.Key;
                    Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS> commentsDict = threadsReqListKVP.Value;
                    int successThreads = commentsDict.Count(x => (x.Value.Failed.Count == 0 && x.Value.Passed.Count > 0));
                    ImGui.TableNextRow();
                    if (successThreads is 0)
                    {
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, failHighlight);
                    }
                    ImGui.TableNextColumn();

                    if (ImGui.TreeNodeEx($"Requirement Set {setID}: {threadsReqList.value.Count} conditions [met by {successThreads} threads]", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
                    {
                        foreach (ProtoGraph graph in commentsDict.Keys)
                        {
                            REQUIREMENT_TEST_RESULTS graphScores = commentsDict[graph];
                            ImGui.TableNextRow();
                            if (graphScores.Failed.Count is not 0)
                            {
                                ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, failHighlight);
                            }
                            ImGui.TableNextColumn();
                            bool hasFailed = graphScores.Failed.Any();
                            ImGuiTreeNodeFlags flags = hasFailed ? ImGuiTreeNodeFlags.DefaultOpen : ImGuiTreeNodeFlags.None;
                            string treeLabel = $"Graph TID {graph.ThreadID}: {graphScores.Passed.Count}/{graphScores.Passed.Count + graphScores.Failed.Count}";

                            if (ImGui.TreeNodeEx(treeLabel, flags))
                            {
                                foreach (var comm in graphScores.Passed)
                                {
                                    ImGui.TableNextRow();
                                    ImGui.TableNextColumn();
                                    TestRequirement req = comm.requirement;

                                    ResultIconSameLine(pass: true);
                                    string testtext = $"Thread Requirement: {req.Name} ({comm.comparedValueString})";
                                    if (req.ExpectedValueString != null)
                                    {
                                        testtext += $" {req.Condition} {req.ExpectedValueString}";
                                    }
                                    ImGui.Text(testtext);
                                    SmallWidgets.MouseoverText(req.Comment);
                                }
                                foreach (var comm in graphScores.Failed)
                                {
                                    ImGui.TableNextRow();
                                    ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, failHighlight);
                                    ImGui.TableNextColumn();
                                    TestRequirement req = comm.requirement;
                                    string testtext = $"Thread Requirement: {req.Name} ({comm.comparedValueString})";
                                    if (req.ExpectedValueString is not null)
                                    {
                                        testtext += $" {req.Condition} {req.ExpectedValueString}";
                                    }
                                    ImGui.Text(testtext);
                                    SmallWidgets.MouseoverText(req.Comment);
                                }
                                ImGui.TreePop();
                            }
                        }

                        ImGui.TreePop();
                    }
                    setID++;
                }
                ImGui.TreePop();
            }

            ImGui.TableNextRow();
            //ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, 0);
            ImGui.TableNextColumn();
            if (childReqsList.Count is not 0 && ImGui.TreeNodeEx($"{childReqsList.Count} child trace requirements", ImGuiTreeNodeFlags.DefaultOpen)) //toto plural/singular
            {
                foreach (var childTraceReqs in childReqsList)
                {
                    DrawTraceSpecExplainTreeNodes(childTraceReqs);
                }
                ImGui.TreePop();
            }
        }

        private void UpdateStats()
        {
            lock (_TestsLock)
            {
                _sessionStats["Passed"] = _allTests.Where(x => x.LatestResultState == eTestState.Passed).Count();
                _sessionStats["Failed"] = _allTests.Where(x => x.LatestResultState == eTestState.Failed).Count();
                _sessionStats["Remaining"] = _allTests.Where(x => x.LatestResultState == eTestState.NotRun).Count();
                _sessionStats["Executed"] = _allTests.Count - _sessionStats["Remaining"];
            }
        }

        private void DrawStatusBanner()
        {
            //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff000000);
            if (ImGui.BeginChild("#TestsStatusBar", new Vector2(ImGui.GetContentRegionAvail().X, 28)))
            {
                float loadedCount = 0;
                float execCount = 0;
                float failedCount = 0;
                float passedCount = 0;

                lock (_TestsLock)
                {
                    execCount = _sessionStats["Executed"];
                    loadedCount = _sessionStats["Loaded"];
                    failedCount = _sessionStats["Failed"];
                    passedCount = _sessionStats["Passed"];
                }

                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 8);
                if (loadedCount is 0)
                {
                    ImGui.Text("No tests loaded. Ensure the test path is defined in settings and contains tests (see [URL - TODO])");
                }
                else
                {
                    if (execCount is 0)
                    {
                        ImGui.TextWrapped("No tests perfomed in this session. Queue tests using the list to the left or controls below and press \"Start Testing\"");
                    }
                    else
                    {
                        float exec_pct = (execCount / _allTests.Count);
                        float pass_pct = (passedCount / execCount);

                        string label = "";
                        if (execCount is 1)
                        {
                            label = $"1 unique test case executed ({exec_pct:P0}%)";
                        }
                        else
                        {
                            label = $"{execCount} of {_allTests.Count} unique test cases executed ({exec_pct:P0}%)";
                        }
                        label += $" with {failedCount} failed tests ({pass_pct:P0}% pass rate for most recent run of each test).";
                        ImGui.Text(label);
                    }
                }

                ImGui.SameLine(ImGui.GetContentRegionAvail().X - 85);
                if (ImGui.Button("Reset Session", new Vector2(80, 25)))
                {
                    ResetSession();
                }
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip("Clear test results and reload tests from test directory.");
                }

                ImGui.EndChild();
            }
            //ImGui.PopStyleColor();
        }

        private static bool testSpecsShowUntested = true;
        private static bool testSpecsShowFailed = true;
        private static bool testSpecsShowPassed = true;
        private static bool autoRequeue = false;
        private static bool autoStopOnFailure = false;

        private void DrawQueueControls(float height)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.WindowBackground));
            if (ImGui.BeginChild("#TestsControls", new Vector2(ImGui.GetContentRegionAvail().X, height)))
            {
                ImGui.SetCursorPos(ImGui.GetCursorPos() + new Vector2(6, 4));
                ImGui.BeginGroup();
                ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 3f);
                if (ImGui.BeginChild("#QueueControlsFrame", new Vector2(300, 80), true, ImGuiWindowFlags.MenuBar))
                {
                    if (ImGui.BeginMenuBar())
                    {
                        ImGui.PushStyleColor(ImGuiCol.TextDisabled, Themes.GetThemeColourUINT(Themes.eThemeColour.Dull1));
                        ImGui.MenuItem("Queue Shortcuts", false);
                        ImGui.PopStyleColor();
                        ImGui.EndMenuBar();
                    }

                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.ControlText));
                    if (ImGui.Button("+All"))
                    {
                        AddTestsToQueue(eCatFilter.All);
                    }
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetTooltip("Add every unqueued test to the queue");
                    }

                    ImGui.SameLine();
                    if (ImGui.Button("+Remaining"))
                    {
                        AddTestsToQueue(eCatFilter.Remaining);
                    }

                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetTooltip("Add all tests to the queue which have not yet been executed in this session");
                    }

                    ImGui.SameLine();
                    if (ImGui.Button("+Starred"))
                    {
                        AddTestsToQueue(eCatFilter.StarredTest);
                        AddTestsToQueue(eCatFilter.StarredCat);
                    }
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetTooltip("Add starred tests to the queue and tests from starred categories");
                    }

                    ImGui.SameLine();
                    if (ImGui.Button("+Failed"))
                    {
                        AddTestsToQueue(eCatFilter.Failed);
                    }

                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetTooltip("Add failed tests to the queue");
                    }

                    ImGui.SameLine();
                    if (_queuedTests.Any())
                    {
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour));
                        if (this._queuedTests.Any() is true && ImGui.Button("-All"))
                        {
                            EmptyQueue();
                        }
                        if (ImGui.IsItemHovered())
                        {
                            ImGui.SetTooltip("Empty the test queue");
                        }
                        ImGui.PopStyleColor();
                    }
                    ImGui.EndGroup();
                    ImGui.PopStyleColor();
                    ImGui.EndChild();
                }

                ImGui.SameLine();
                if (ImGui.BeginChild("FilterChecks", new Vector2(250, 80), true, ImGuiWindowFlags.MenuBar))
                {
                    if (ImGui.BeginMenuBar())
                    {
                        ImGui.PushStyleColor(ImGuiCol.TextDisabled, Themes.GetThemeColourUINT(Themes.eThemeColour.Dull1));
                        ImGui.MenuItem("Test Filters", false);
                        ImGui.PopStyleColor();
                        ImGui.EndMenuBar();
                    }
                    ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(4, 1));
                    ImGui.Checkbox("Untested", ref testSpecsShowUntested);
                    ImGui.SameLine();
                    ImGui.Checkbox("Passed", ref testSpecsShowPassed);
                    ImGui.SameLine();
                    ImGui.Checkbox("Failed", ref testSpecsShowFailed);
                    ImGui.PopStyleVar();
                    ImGui.EndChild();
                }

                ImGui.SameLine();
                ImGui.BeginGroup();
                float buttonSize = 32;
                float buttonYStart = ImGui.GetCursorPosY() + (height / 2) - (buttonSize);
                ImGui.SetCursorPosY(buttonYStart);
                if (_testsRunning)
                {
                    if (ImGui.Button($"Stop Testing {ImGuiController.FA_ICON_NOENTRY}", new Vector2(125, buttonSize)))
                    {
                        StopTests();
                    }
                    if (ImGui.IsItemHovered())
                    {
                        ImGui.SetTooltip("Stop execution of tests from the queue. Any active test will be cancelled and remain in the queue.");
                    }
                }
                else
                {
                    if (autoStopOnFailure && _sessionStats["Failed"] > 0)
                    {
                        ImGui.Button("Testing Stopped", new Vector2(125, buttonSize));

                        SmallWidgets.MouseoverText("A test has failed. Begin a new session or disable stop on failure");
                    }
                    else
                    {
                        if (ImGui.Button("Start Testing", new Vector2(125, buttonSize)))
                        {
                            StartTests();
                        }
                        SmallWidgets.MouseoverText("Begin executing tests from the queue");
                    }
                }


                ImGui.EndGroup();
                ImGui.SameLine();
                ImGui.BeginGroup();
                ImGui.InvisibleButton("#paddingBy3", new Vector2(4, 12));
                ImGui.Checkbox("Loop tests", ref autoRequeue);
                SmallWidgets.MouseoverText("Immediately requeue tests after execution for continuous repeated tests");

                ImGui.Checkbox("Stop on Failure", ref autoStopOnFailure);
                SmallWidgets.MouseoverText("Stop executing new tests if a test fails");
                ImGui.EndGroup();
            }
            ImGui.PopStyleColor();
        }

        private void StartTests()
        {
            if (_testsRunning)
            {
                return;
            }

            _testsRunning = true;
        }

        private void StopTests()
        {
            if (!_testsRunning)
            {
                return;
            }

            _testsRunning = false;
        }

        private void ResetSession()
        {
            StopTests();
            EmptyQueue();
            InitTestingSession();
        }

        private void EmptyQueue()
        {
            lock (_TestsLock)
            {
                _queuedTests.Clear();
            }
        }

        private void AddTestToQueue(TestCase test)
        {
            lock (_TestsLock)
            {
                _queuedTests.Add(test);
            }
        }

        private void AddTestsToQueue(eCatFilter filter)
        {
            lock (_TestsLock)
            {
                var unQueuedTests = _allTests.Where(test => !_queuedTests.Contains(test)).ToArray();
                foreach (TestCase test in unQueuedTests)
                {
                    switch (filter)
                    {
                        case eCatFilter.All:
                            AddTestToQueue(test);
                            break;
                        case eCatFilter.Failed:
                            if (test.LatestResultState == eTestState.Failed)
                            {
                                AddTestToQueue(test);
                            }

                            break;
                        case eCatFilter.Passing:
                            if (test.LatestResultState == eTestState.Passed)
                            {
                                AddTestToQueue(test);
                            }

                            break;
                        case eCatFilter.Remaining:
                            if (test.LatestResultState == eTestState.NotRun)
                            {
                                AddTestToQueue(test);
                            }

                            break;
                        case eCatFilter.StarredTest:
                            if (test.Starred)
                            {
                                AddTestToQueue(test);
                            }

                            break;
                        case eCatFilter.StarredCat:
                            if (test.CategoryName is not null &&
                                _testCategories.TryGetValue(test.CategoryName, out TestCategory? testcat)
                                && testcat is not null && testcat.Starred)
                            {
                                AddTestToQueue(test);
                            }

                            break;
                        default:
                            Logging.RecordLogEvent("AddTestsToQueue has no handler for filter " + filter.ToString(), Logging.LogFilterType.Error);
                            break;
                    }
                }
            }
        }


        private static void DrawValidTestcaseTooltip(TestCase testcase)
        {
            ImGui.BeginTooltip();

            ImGui.Text(testcase.JSONPath);
            ImGui.Text(testcase.BinaryPath);

            ImGui.Indent(5);
            ImGui.Text("OS: " + testcase.TestOS);
            ImGui.Text("Bits: " + testcase.TestBits.ToString());

            if (testcase.Comment != null)
            {
                ImGui.Text("Description: " + testcase.Comment);
            }
            else
            {
                ImGui.Text("No Description");
            }

            ImGui.Text($"Has {testcase.TestRunRequirements().Length} general test requirements");
            TraceRequirements proReq = testcase.TraceRequirements();
            if (proReq.ProcessRequirements.Count is not 0)
                ImGui.Text($"Has requirements for {proReq.ProcessRequirements.Count} initial processes");

            if (proReq.ThreadRequirements.Count is not 0)
                ImGui.Text($"Has requirements for {proReq.ThreadRequirements.Count} initial threads");

            if (proReq.ChildProcessRequirements.Count is not 0)
                ImGui.Text($"Has requirements for {proReq.ChildProcessRequirements.Count} second level child processes");

            ImGui.EndTooltip();
        }

        private static void DrawFailedTestTooltip(TestCase testcase)
        {
            ImGui.BeginTooltip();

            ImGui.Text(testcase.JSONPath);
            ImGui.Text(testcase.BinaryPath);

            TestCaseRun? failedTest = testcase.LatestTestRun;
            if (failedTest is not null)
            {
                //todo flesh this out?
                ImGui.Text("Test ID:" + failedTest.TestID);
            }

            ImGui.Indent(5);

            //_testingThread.GetTestCaseRun(te)

            ImGui.EndTooltip();
        }


        private static void DrawInvalidTestcaseTooltip(TestCase testcase)
        {
            ImGui.BeginTooltip();
            ImGui.Text("Failed to load " + testcase.JSONPath);
            ImGui.Indent(5);
            for (var i = testcase.LoadingErrors.Count - 1; i >= 0; i--)
            {
                ImGui.Text(testcase.LoadingErrors[i]);
            }
            ImGui.EndTooltip();
        }


        private void DrawTestsTree()
        {
            ImGui.SetNextItemWidth(treeWidth);
            if (ImGui.BeginChild("##TestsTreeFrame", new Vector2(treeWidth, ImGui.GetContentRegionAvail().Y), false, ImGuiWindowFlags.NoScrollbar))
            {
                uint starYellow = WritableRgbaFloat.ToUint(System.Drawing.Color.Yellow);

                if (ImGui.Combo("", ref _selectedFilter, filters, filters.Length))
                {
                    Logging.WriteConsole("Apply tests tree filter " + filters[_selectedFilter]);
                }
                ImGui.InvisibleButton("#MoveDownTree1", new Vector2(treeWidth, 4));
                //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff222222);
                ImGui.PushStyleColor(ImGuiCol.Button, 0xff222222);
                float sizeMultiplier = 0.6f;
                float height = ImGui.GetContentRegionAvail().Y;
                if (ImGui.BeginChild("#SelectionTree", new Vector2(ImGui.GetContentRegionAvail().X, height * sizeMultiplier)))
                {
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 4);
                    ImGui.TextWrapped($"Loaded {_sessionStats["Loaded"]} Tests in {_orderedCategories.Count} Categories");
                    ImGui.Separator();
                    ImGui.Indent(10);
                    {
                        foreach (string testDir in _orderedCategories)
                        {


                            if (!_testCategories.TryGetValue(testDir, out TestCategory? category) || !category.Tests.Any())
                            {
                                continue;
                            }

                            if (((eCatFilter)_selectedFilter) == eCatFilter.StarredCat && !category.Starred)
                            {
                                continue;
                            }

                            List<TestCase> shownTests = new List<TestCase>();

                            foreach (TestCase testcase in category.Tests)
                            {
                                bool failFilter = false;
                                switch ((eCatFilter)_selectedFilter)
                                {
                                    case eCatFilter.StarredTest:
                                        if (!testcase.Starred)
                                        {
                                            failFilter = true;
                                        }

                                        break;
                                    case eCatFilter.Passing:
                                        if (testcase.LatestResultState != eTestState.Passed)
                                        {
                                            failFilter = true;
                                        }

                                        break;
                                    case eCatFilter.Failed:
                                        if (testcase.LatestResultState != eTestState.Failed)
                                        {
                                            failFilter = true;
                                        }

                                        break;
                                    case eCatFilter.Remaining:
                                        if (testcase.LatestResultState != eTestState.NotRun)
                                        {
                                            failFilter = true;
                                        }

                                        break;
                                    case eCatFilter.Complete:
                                        if (testcase.LatestResultState == eTestState.NotRun)
                                        {
                                            failFilter = true;
                                        }

                                        break;

                                }
                                if (!failFilter)
                                {
                                    shownTests.Add(testcase);
                                }
                            }

                            if (!shownTests.Any())
                            {
                                continue;
                            }

                            bool starredCategory = category.Starred;
                            if (ImGui.TreeNodeEx(testDir, ImGuiTreeNodeFlags.DefaultOpen, category.CategoryName))
                            {
                                ImGui.SameLine(ImGui.GetContentRegionAvail().X - 2);
                                ImGui.PushStyleColor(ImGuiCol.Text, starredCategory ? starYellow : Themes.GetThemeColourUINT(Themes.eThemeColour.Dull1));
                                if (ImGui.Button($"{ImGuiController.FA_ICON_STAR}", new Vector2(30, 30)))
                                {
                                    category.Starred = !category.Starred;
                                }

                                SmallWidgets.MouseoverText($"Click to {((starredCategory) ? "unstar" : "star")} every test in this category");
                                ImGui.PopStyleColor();

                                if (ImGui.BeginPopupContextItem())
                                {
                                    ImGui.Checkbox("Starred Category", ref category.Starred);
                                    ImGui.EndPopup();
                                }
                                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, Vector2.Zero);
                                if (ImGui.BeginTable("#CatTable" + category.ID, 6, ImGuiTableFlags.BordersInner | ImGuiTableFlags.SizingStretchProp | ImGuiTableFlags.NoHostExtendX))
                                {
                                    ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.None, 40);
                                    ImGui.TableSetupColumn("Starred", ImGuiTableColumnFlags.WidthFixed, 30);
                                    ImGui.TableSetupColumn("Passed", ImGuiTableColumnFlags.None, 9);
                                    ImGui.TableSetupColumn("Failed", ImGuiTableColumnFlags.None, 9);
                                    ImGui.TableSetupColumn("Running", ImGuiTableColumnFlags.None, 7);
                                    ImGui.TableSetupColumn("Add", ImGuiTableColumnFlags.None, 7);


                                    for (var testi = 0; testi < shownTests.Count; testi++)
                                    {
                                        TestCase testcase = shownTests[testi];
                                        if (!testcase.Loaded)
                                        {
                                            ImGui.TableNextRow();
                                            ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, 0xff000088);

                                            ImGui.TableNextColumn();
                                            ImGui.Text(testcase.TestName + " [Error]");
                                            if (ImGui.IsItemHovered())
                                            {
                                                DrawInvalidTestcaseTooltip(testcase);
                                            }
                                            continue;
                                        }

                                        ImGui.TableNextRow();

                                        //test name
                                        ImGui.TableNextColumn();

                                        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 7);
                                        ImGui.Text(testcase.TestName);
                                        if (ImGui.IsItemHovered())
                                        {
                                            DrawValidTestcaseTooltip(testcase);
                                        }

                                        //starred
                                        //ImGui.PushStyleColor(ImGuiCol.)
                                        ImGui.TableNextColumn();
                                        bool starred = (testcase.Starred || starredCategory);
                                        ImGui.PushID($"BtnStar{testi}");
                                        if (!starredCategory)
                                        {
                                            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, Themes.GetThemeColourUINT(Themes.eThemeColour.Control));
                                            ImGui.PushStyleColor(ImGuiCol.Text, starred ?
                                                starYellow :
                                                Themes.GetThemeColourUINT(Themes.eThemeColour.Dull1));
                                            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);
                                            if (ImGui.Button($"{ImGuiController.FA_ICON_STAR}##{testi}", new Vector2(30, 30))) //todo valign
                                            {
                                                testcase.Starred = !testcase.Starred;
                                            }
                                            ImGui.PopStyleVar();
                                            ImGui.PopStyleColor(2);

                                            SmallWidgets.MouseoverText($"Click to {((testcase.Starred) ? "unstar" : "star")} this test");
                                        }
                                        else
                                        {
                                            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);
                                            ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.Emphasis1));
                                            ImGui.Button($"{ImGuiController.FA_ICON_STAR}##{testi}", new Vector2(30, 30));
                                            ImGui.PopStyleColor();
                                            ImGui.PopStyleVar();
                                            SmallWidgets.MouseoverText($"This category is starred");
                                        }
                                        ImGui.PopID();

                                        //pass/fail
                                        ImGui.TableNextColumn();
                                        if (testcase.LatestResultState != eTestState.NotRun)
                                        {
                                            int count = testcase.CountPassed(_currentSession);
                                            if (count > 0)
                                            {
                                                uint tickColour = Themes.GetThemeColourUINT(Themes.eThemeColour.GoodStateColour);
                                                SmallWidgets.DrawIcon($"{ImGuiController.FA_ICON_TICK}", colour: tickColour, countCaption: count);
                                            }
                                        }

                                        ImGui.TableNextColumn();
                                        if (testcase.LatestResultState != eTestState.NotRun)
                                        {
                                            int count = testcase.CountFailed(_currentSession);
                                            if (count > 0)
                                            {
                                                uint crossColour = Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour);
                                                SmallWidgets.DrawIcon($"{ImGuiController.FA_ICON_CROSS}", colour: crossColour, countCaption: count);
                                                if (ImGui.IsItemHovered())
                                                {
                                                    DrawFailedTestTooltip(testcase);
                                                }
                                            }
                                        }

                                        //running
                                        ImGui.TableNextColumn();
                                        int runningCount = testcase.Running;
                                        if (runningCount > 0)
                                        {
                                            SmallWidgets.DrawSpinner(_controller, runningCount, Themes.GetThemeColourUINT(Themes.eThemeColour.Dull1));
                                            if (ImGui.IsItemHovered())
                                            {
                                                ImGui.SetTooltip($"{runningCount} instance{(runningCount != 1 ? "s" : "")} of this test currently executing");
                                            }
                                        }

                                        ImGui.TableNextColumn();
                                        ImGui.PushID($"BtnAdd{testi}");
                                        ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.Emphasis1));
                                        if (ImGui.Button($"{ImGuiController.FA_ICON_PLUS}", new Vector2(30, 30)))
                                        {
                                            AddTestToQueue(testcase);
                                        }
                                        ImGui.PopStyleColor();
                                        SmallWidgets.MouseoverText("Queue this test");

                                        ImGui.PopID();

                                        /*
                                        switch (testcase.state)
                                        {
                                            case eTestState.Passed:
                                                ImGui.PushStyleColor(ImGuiCol.Text, 0xff00ff00);
                                                label += " [Passed]";
                                                coloured = true;
                                                break;
                                            case eTestState.Failed:
                                                ImGui.PushStyleColor(ImGuiCol.Text, 0xffff0000);
                                                label += " [Failed]";
                                                coloured = true;
                                                break;
                                            default:
                                                break;
                                        }

                                        if (ImGui.Selectable(label, testcase.Queued))
                                        {
                                            ToggleQueued(testcase);
                                        }

                                        if (coloured) ImGui.PopStyleColor();
                                        */
                                    }
                                    ImGui.EndTable();
                                    ImGui.PopStyleVar(); //cellpadding
                                }
                                ImGui.TreePop();
                            }
                        }
                    }
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                //ImGui.PopStyleColor();

                ImGui.InvisibleButton("#MoveDownTree1", new Vector2(treeWidth, 8));
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 4);
                ImGui.Text($"{_queuedTests.Count} test{((_queuedTests.Count != 1) ? "s" : "")} in queue");
                if (_testsRunning)
                {
                    ImGui.SameLine(ImGui.GetContentRegionAvail().X - 125, 0);
                    ImGui.Text("Test Workers Active");
                    ImGui.SameLine();
                    ImGui.PushStyleColor(ImGuiCol.Text, WritableRgbaFloat.ToUint(System.Drawing.Color.Yellow));
                    ImGui.Text($"{ImGuiController.FA_ICON_LIGHTNING}");
                    ImGui.PopStyleColor();
                }
                else
                {
                    ImGui.SameLine(ImGui.GetContentRegionAvail().X - 115, 0);
                    ImGui.Text("Test Workers Inactive");
                }

                ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.Frame));
                if (ImGui.BeginChild("##TestsQueueFrame", new Vector2(treeWidth, height - height * sizeMultiplier - 40), true))
                {
                    ImGui.Indent(10);
                    lock (_TestsLock)
                    {
                        for (var i = _queuedTests.Count - 1; i >= 0; i--)
                        {
                            TestCase testcase = _queuedTests[i];
                            if (ImGui.Selectable($"{testcase.CategoryName}:{testcase.TestName}"))
                            {
                                lock (_TestsLock)
                                {
                                    _queuedTests.RemoveAt(i);
                                }
                            }
                            SmallWidgets.MouseoverText($"{ImGuiController.FA_ICON_TRASHCAN} Click to remove from the queue");
                        }
                    }
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();


                ImGui.EndChild();
            }
        }
    }
}

