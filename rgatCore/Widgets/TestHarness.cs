using ImGuiNET;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace rgatCore.Widgets
{
    enum eTestState { NotRun, Passed, Failed };
    class TestCase
    {
        public eTestState state = eTestState.NotRun;
        public string Path;
        public string CategoryName;
        public string TestName;
        public bool Starred;
        public bool Queued;
        public bool Running;
        public string Description;
    }
    class TestCategory
    {
        public List<TestCase> Tests = new List<TestCase>();
        public string Path;
        public bool Starred;
        public string CategoryName;

    }


    class TestHarness
    {
        public TestHarness()
        {
            RefreshTestFiles();
        }

        Dictionary<string, TestCategory> _testDirectories = new Dictionary<string, TestCategory>();
        Dictionary<string, TestCategory> _testCategories = new Dictionary<string, TestCategory>();
        List<string> _orderedTestDirs = new List<string>();
        bool _testsRunning = false;

        public void RefreshTestFiles()
        {
            lock (_TestsLock)
            {
                _foundTestsCount = 0;
                _testDirectories.Clear();
                _testCategories.Clear();
                _orderedTestDirs.Clear();
                _allTests.Clear();
                _queuedTests.Clear();

                string testspath = GlobalConfig.TestsDirectory;
                if (!Directory.Exists(testspath)) return;
                string[] dirs = Directory.GetDirectories(testspath)
                    .Select(x => Path.GetFileName(x))
                    .Where(x => x.Contains("_"))
                    .ToArray();

                List<Tuple<uint, string>> validDirs = new List<Tuple<uint, string>>();
                foreach (string testdir in dirs)
                {
                    string[] splitted = testdir.Split("_");
                    if (splitted.Length < 2) continue;
                    try
                    {
                        if (uint.TryParse(splitted[0], out uint num))
                        {
                            string categoryName = splitted[1];
                            validDirs.Add(new Tuple<uint, string>(num, Path.Combine(testspath, testdir)));
                            string fullpath = Path.Combine(testspath, testdir);
                            TestCategory tests = new TestCategory();
                            tests.Tests = FindTests(fullpath, categoryName);
                            tests.CategoryName = categoryName;
                            tests.Path = fullpath;
                            _testDirectories[fullpath] = tests;
                            _testCategories[categoryName] = tests;
                            _allTests.AddRange(tests.Tests);
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Ignoring badly formatted test directory {testdir}",
                            Logging.LogFilterType.TextDebug);
                        continue;
                    }
                }

                _orderedTestDirs = validDirs.OrderBy(x => x.Item1).Select(x => x.Item2).ToList();
            }
            Logging.RecordLogEvent($"Loaded {_testDirectories.Count} test directories");
        }

        void ToggleQueued(TestCase test, bool? state = null)
        {
            if (state.HasValue && test.Queued == state.Value) return;
            lock (_TestsLock)
            {
                if (test.Queued)
                {
                    _queuedTests.Remove(test);
                }
                else
                {
                    _queuedTests.Add(test);
                }
            }
            test.Queued = !test.Queued;
        }


        static readonly string testextension = ".test.json";
        List<TestCase> FindTests(string dirpath, string category)
        {
            List<TestCase> results = new List<TestCase>();
            string[] tests = Directory.GetFiles(dirpath).Where(x => x.EndsWith(testextension)).ToArray();
            foreach (string testfile in tests)
            {
                TestCase t = new TestCase();
                t.TestName = Path.GetFileName(testfile).Split(testextension)[0];
                t.Path = testfile;
                t.CategoryName = category;
                results.Add(t);
                _foundTestsCount += 1;
            }
            return results;
        }


        int _foundTestsCount = 0;
        enum eCatFilter { All = 0, Remaining = 1, Complete = 2, Passing = 3, Failed = 4, StarredTest = 5, StarredCat = 6 }
        int _selectedFilter = (int)eCatFilter.All;
        string[] filters = new string[] { "Show All Tests", "Show Remaining Tests","Show Complete Tests",
            "Show Passing Tests","Show Failed Tests",
            "Show Starred Tests", "Show Starred Categories"};
        readonly int treeWidth = 200;
        List<TestCase> _queuedTests = new List<TestCase>();
        List<TestCase> _allTests = new List<TestCase>();

        struct OutputText
        {
            string text;
        }
        List<OutputText> _outputText = new List<OutputText>();

        public void Draw(ref bool openFlag)
        {
            if (ImGui.Begin("Run Tests", ref openFlag, ImGuiWindowFlags.None))
            {
                DrawTestsTree();
                ImGui.SameLine();
                ImGui.BeginGroup();
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff000000);
                if (ImGui.BeginChild("#TestsStatusBar", new Vector2(ImGui.GetContentRegionAvail().X, 28)))
                {
                    ImGui.SameLine(ImGui.GetContentRegionAvail().X - 85);

                    if (ImGui.Button("Reset Session", new Vector2(80, 25)))
                    {
                        ResetSession();
                    }
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Clear test results and reload tests from test directory.");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                float height = ImGui.GetContentRegionAvail().Y;
                float controlsHeight = 75;
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff887766);
                if (ImGui.BeginChild("#TestsOutputWindow", new Vector2(ImGui.GetContentRegionAvail().X, height - controlsHeight)))
                {
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                DrawQueueControls(controlsHeight);
                ImGui.EndGroup();
                ImGui.End();
            }
        }

        void DrawQueueControls(float height)
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff333333);

            if (ImGui.BeginChild("#TestsControls", new Vector2(ImGui.GetContentRegionAvail().X, height)))
            {
                ImGui.Indent(10);
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff222222);
                ImGui.PushStyleVar(ImGuiStyleVar.ChildRounding, 3f);
                if (ImGui.BeginChild("#QueueControlsFrame", new Vector2(340, 70), true, ImGuiWindowFlags.MenuBar))
                {
                    if (ImGui.BeginMenuBar())
                    {
                        ImGui.PushStyleColor(ImGuiCol.TextDisabled, 0xffffffff);
                        ImGui.MenuItem("Queue Controls", false);
                        ImGui.PopStyleColor();
                        ImGui.EndMenuBar();
                    }
                    if (ImGui.Button("+All"))
                    {
                        AddTestsToQueue(eCatFilter.All);
                    }
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Add every unqueued test to the queue");

                    ImGui.SameLine();
                    if (ImGui.Button("+Remaining")) AddTestsToQueue(eCatFilter.Remaining);
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Add all tests to the queue which have not yet been executed in this session");
                    ImGui.SameLine();
                    if (ImGui.Button("+Starred"))
                    {
                        AddTestsToQueue(eCatFilter.StarredTest);
                        AddTestsToQueue(eCatFilter.StarredCat);
                    }
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Add starred tests to the queue and tests from starred categories");
                    ImGui.SameLine();
                    if (ImGui.Button("+Failed")) AddTestsToQueue(eCatFilter.Failed);
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Add failed tests to the queue");
                    ImGui.SameLine();
                    if (!_queuedTests.Any())
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.TextDisabled));
                    else
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                    if (ImGui.Button("-All"))
                    {
                        EmptyQueue();
                    }
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Empty the test queue");
                    ImGui.PopStyleColor();
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                ImGui.SameLine();
                ImGui.BeginGroup();
                float buttonSize = 40;
                float buttonYStart = ImGui.GetCursorPosY() + (height / 2) - (buttonSize / 2);
                ImGui.SetCursorPosY(buttonYStart);
                if (_testsRunning)
                {
                    ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                    if (ImGui.Button("Stop Testing", new Vector2(80, buttonSize)))
                    {
                        StopTests();
                    }
                    ImGui.PopStyleColor();
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Stop execution of tests from the queue. Any active test will be cancelled and remain in the queue.");
                }
                else
                {

                    if (!_queuedTests.Any())
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourImGui(ImGuiCol.TextDisabled));
                    else
                        ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.eGoodStateColour));
                    if (ImGui.Button("Start Testing", new Vector2(80, buttonSize)))
                    {
                        StartTests();
                    }
                    ImGui.PopStyleColor();
                    if (ImGui.IsItemHovered())
                        ImGui.SetTooltip("Begin executing tests from the queue");
                }
                ImGui.EndGroup();
            }
            ImGui.PopStyleColor();
        }

        void StartTests()
        {
            if (_testsRunning) return;
            _testsRunning = true;
        }

        void StopTests()
        {
            if (!_testsRunning) return;
            _testsRunning = false;
        }

        void ResetSession()
        {
            StopTests();
            EmptyQueue();
            RefreshTestFiles();
        }

        readonly object _TestsLock = new object();

        void EmptyQueue()
        {
            lock (_TestsLock)
            {
                _queuedTests.Where(test => !test.Running).ToList().ForEach(test => ToggleQueued(test));
            }
        }
        void AddTestsToQueue(eCatFilter filter)
        {
            lock (_TestsLock)
            {
                var unQueuedTests = _allTests.Where(test => !test.Queued).ToArray();
                foreach (TestCase test in unQueuedTests)
                {
                    switch (filter)
                    {
                        case eCatFilter.All:
                            ToggleQueued(test, true);
                            break;
                        case eCatFilter.Failed:
                            if (test.state == eTestState.Failed) ToggleQueued(test, true);
                            break;
                        case eCatFilter.Passing:
                            if (test.state == eTestState.Passed) ToggleQueued(test, true);
                            break;
                        case eCatFilter.Remaining:
                            if (test.state == eTestState.NotRun) ToggleQueued(test, true);
                            break;
                        case eCatFilter.StarredTest:
                            if (test.Starred) ToggleQueued(test, true);
                            break;
                        case eCatFilter.StarredCat:
                            if (_testCategories[test.CategoryName].Starred) ToggleQueued(test, true);
                            break;
                        default:
                            Logging.RecordLogEvent("AddTestsToQueue has no handler for filter " + filter.ToString(), Logging.LogFilterType.TextError);
                            break;
                    }
                }
            }
        }

        void DrawTestsTree()
        {
            ImGui.SetNextItemWidth(treeWidth);
            if (ImGui.BeginChild("##TestsTreeFrame", new Vector2(treeWidth, ImGui.GetContentRegionAvail().Y), false, ImGuiWindowFlags.NoScrollbar))
            {
                if (ImGui.Combo("", ref _selectedFilter, filters, filters.Length))
                {
                    Console.WriteLine("Apply tests tree filter " + filters[_selectedFilter]);
                }
                ImGui.InvisibleButton("#MoveDownTree1", new Vector2(treeWidth, 4));
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff222222);
                float sizeMultiplier = 0.6f;
                float height = ImGui.GetContentRegionAvail().Y;
                if (ImGui.BeginChild("#SelectionTree", new Vector2(ImGui.GetContentRegionAvail().X, height * sizeMultiplier)))
                {
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 4);
                    ImGui.TextWrapped($"Loaded {_foundTestsCount} Tests in {_orderedTestDirs.Count} Categories");
                    ImGui.Separator();
                    ImGui.Indent(10);
                    {
                        foreach (string testDir in _orderedTestDirs)
                        {

                            if (!_testDirectories.TryGetValue(testDir, out TestCategory category) || !category.Tests.Any()) continue;
                            if (((eCatFilter)_selectedFilter) == eCatFilter.StarredCat && !category.Starred) continue;

                            List<TestCase> shownTests = new List<TestCase>();

                            foreach (TestCase testcase in category.Tests)
                            {
                                bool failFilter = false;
                                switch ((eCatFilter)_selectedFilter)
                                {
                                    case eCatFilter.StarredTest:
                                        if (!testcase.Starred) failFilter = true;
                                        break;
                                    case eCatFilter.Passing:
                                        if (testcase.state != eTestState.Passed) failFilter = true;
                                        break;
                                    case eCatFilter.Failed:
                                        if (testcase.state != eTestState.Failed) failFilter = true;
                                        break;
                                    case eCatFilter.Remaining:
                                        if (testcase.state != eTestState.NotRun) failFilter = true;
                                        break;
                                    case eCatFilter.Complete:
                                        if (testcase.state == eTestState.NotRun) failFilter = true;
                                        break;

                                }
                                if (!failFilter) shownTests.Add(testcase);
                            }

                            if (!shownTests.Any()) continue;


                            if (ImGui.TreeNodeEx(testDir, ImGuiTreeNodeFlags.DefaultOpen, category.CategoryName))
                            {
                                if (ImGui.BeginPopupContextItem())
                                {
                                    ImGui.Checkbox("Starred Category", ref category.Starred);
                                    ImGui.EndPopup();
                                }
                                foreach (TestCase testcase in shownTests)
                                {
                                    string label = testcase.TestName;
                                    bool coloured = false;

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

                                    bool starred = (testcase.Starred || _testCategories[testcase.CategoryName].Starred);
                                    if (starred) label = $"**{label}**";
                                    if (ImGui.Selectable(label, testcase.Queued))
                                    {
                                        ToggleQueued(testcase);
                                    }
                                    if (ImGui.BeginPopupContextItem())
                                    {
                                        ImGui.TextWrapped("Description: " + testcase.Description);
                                        ImGui.Checkbox("Starred Test", ref testcase.Starred);
                                        ImGui.EndPopup();
                                    }

                                    if (coloured) ImGui.PopStyleColor();
                                }
                                ImGui.TreePop();
                            }
                        }
                    }
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();

                ImGui.InvisibleButton("#MoveDownTree1", new Vector2(treeWidth, 8));
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 4);
                ImGui.Text($"{_queuedTests.Count} test{((_queuedTests.Count != 1) ? "s" : "")} in queue");
                ImGui.Separator();

                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff080808);
                if (ImGui.BeginChild("##TestsQueueFrame", new Vector2(treeWidth, height - height * sizeMultiplier)))
                {
                    ImGui.Indent(10);
                    lock (_TestsLock)
                    {
                        for (var i = _queuedTests.Count - 1; i >= 0; i--)
                        {
                            TestCase testcase = _queuedTests[i];
                            if (ImGui.Selectable($"{testcase.CategoryName}:{testcase.TestName}"))
                            {
                                ToggleQueued(testcase);
                            }
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

