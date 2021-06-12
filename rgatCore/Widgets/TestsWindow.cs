using ImGuiNET;
using rgatCore.Testing;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace rgatCore.Widgets
{

    class TestCategory
    {
        public List<TestCase> Tests = new List<TestCase>();
        public string Path;
        public bool Starred;
        public string CategoryName;
        public string ID;
    }

    class TestsWindow
    {
        public TestsWindow(rgatState clientState, ImGuiController controller)
        {
            
            _testingThread = new TestHarnessThread(clientState);
            _controller = controller;
            InitTestingSession();

        }

        TestHarnessThread _testingThread;
        ImGuiController _controller;
        Dictionary<string, TestCategory> _testDirectories = new Dictionary<string, TestCategory>();
        Dictionary<string, TestCategory> _testCategories = new Dictionary<string, TestCategory>();
        List<string> _orderedTestDirs = new List<string>();
        bool _testsRunning = false;
        enum eCatFilter { All = 0, Remaining = 1, Complete = 2, Passing = 3, Failed = 4, StarredTest = 5, StarredCat = 6 }
        int _selectedFilter = (int)eCatFilter.All;
        string[] filters = new string[] { "Show All Tests", "Show Remaining Tests","Show Complete Tests",
            "Show Passing Tests","Show Failed Tests",
            "Show Starred Tests", "Show Starred Categories"};
        readonly int treeWidth = 400;
        List<TestCase> _queuedTests = new List<TestCase>();
        List<TestCase> _allTests = new List<TestCase>();
        Dictionary<string, float> _sessionStats = new Dictionary<string, float>();

        List<Testing.TestOutput> _outputText = new List<Testing.TestOutput>();

        readonly object _TestsLock = new object();


        public void InitTestingSession()
        {
            lock (_TestsLock)
            {
                _sessionStats = new Dictionary<string, float>();
                _sessionStats["Loaded"] = 0;
                _sessionStats["Passed"] = 0;
                _sessionStats["Failed"] = 0;
                _sessionStats["Executed"] = 0;

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
                            tests.ID = categoryName+$"{_testCategories.Count}";
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
                _currentSession += 1;
                _testingThread.InitSession(_currentSession);
            }
            UpdateStats();
            Logging.RecordLogEvent($"Loaded {_testDirectories.Count} test directories");
            
        }

        List<TestCase> FindTests(string dirpath, string category)
        {
            List<TestCase> results = new List<TestCase>();
            string[] tests = Directory.GetFiles(dirpath).Where(x => x.EndsWith(TEST_CONSTANTS.testextension)).ToArray();
            foreach (string testfile in tests)
            {
                TestCase t = new TestCase(testfile, category);

                results.Add(t);
                _sessionStats["Loaded"] += 1;
            }
            return results;
        }

        int _currentSession = 0;
        public void Draw(ref bool openFlag)
        {
            if (ImGui.Begin("Run Tests", ref openFlag, ImGuiWindowFlags.None))
            {
                DrawTestsTree();
                ImGui.SameLine();
                ImGui.BeginGroup();
                DrawStatusBanner();
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

            if(_testsRunning)
            {
                if (_queuedTests.Count > 0 && _testingThread.FreeTestSlots > 0)
                {
                    lock (_TestsLock)
                    {
                        TestCase test = _queuedTests.First();
                        long testID = _testingThread.RunTest(_currentSession, test);
                        if (testID > -1)
                        {
                            _queuedTests.Remove(test);
                        }
                    }
                }
            }
        }

        void UpdateStats()
        {
            lock (_TestsLock)
            {
                _sessionStats["Passed"] = _allTests.Where(x => x.LatestResult == eTestState.Passed).Count();
                _sessionStats["Failed"] = _allTests.Where(x => x.LatestResult == eTestState.Failed).Count();
                _sessionStats["Remaining"] = _allTests.Where(x => x.LatestResult == eTestState.NotRun).Count();
                _sessionStats["Executed"] = _allTests.Count - _sessionStats["Remaining"];
            }
        }

        void DrawStatusBanner()
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff000000);
            if (ImGui.BeginChild("#TestsStatusBar", new Vector2(ImGui.GetContentRegionAvail().X, 28)))
            {
                if (_sessionStats["Loaded"] == 0)
                {
                    ImGui.Text("No tests loaded. Ensure the test path is defined in settings and contains tests (see [URL - TODO])");
                }
                else
                {
                    if (_sessionStats["Executed"] == 0)
                    {
                        ImGui.TextWrapped("No tests perfomed in this session. Queue tests using the list to the left or controls below and press \"Start Testing\"");
                    }
                    else
                    {
                        float exec_pct = (_sessionStats["Executed"] / _allTests.Count)*100f;
                        float pass_pct = (_sessionStats["Passed"] / _sessionStats["Executed"]) *100f;
                        string label = $"{_sessionStats["Executed"]}/{_allTests.Count} tests executed ({exec_pct}%)). {_sessionStats["Failed"]} failed tests ({pass_pct}% pass rate).";
                        ImGui.Text(label);
                    }

                }

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
            InitTestingSession();
        }


        void EmptyQueue()
        {
            lock (_TestsLock)
            {
                _queuedTests.Clear();
            }
        }

        void AddTestToQueue(TestCase test)
        {
            lock (_TestsLock)
            {
                _queuedTests.Add(test);
            }
        }

        void AddTestsToQueue(eCatFilter filter)
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
                            if (test.LatestResult == eTestState.Failed) AddTestToQueue(test);
                            break;
                        case eCatFilter.Passing:
                            if (test.LatestResult == eTestState.Passed) AddTestToQueue(test);
                            break;
                        case eCatFilter.Remaining:
                            if (test.LatestResult == eTestState.NotRun) AddTestToQueue(test);
                            break;
                        case eCatFilter.StarredTest:
                            if (test.Starred) AddTestToQueue(test);
                            break;
                        case eCatFilter.StarredCat:
                            if (_testCategories[test.CategoryName].Starred) AddTestToQueue(test);
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
                ImGui.PushStyleColor(ImGuiCol.Button, 0xff222222);
                float sizeMultiplier = 0.6f;
                float height = ImGui.GetContentRegionAvail().Y;
                if (ImGui.BeginChild("#SelectionTree", new Vector2(ImGui.GetContentRegionAvail().X, height * sizeMultiplier)))
                {
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 4);
                    ImGui.TextWrapped($"Loaded {_sessionStats["Loaded"]} Tests in {_orderedTestDirs.Count} Categories");
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
                                        if (testcase.LatestResult != eTestState.Passed) failFilter = true;
                                        break;
                                    case eCatFilter.Failed:
                                        if (testcase.LatestResult != eTestState.Failed) failFilter = true;
                                        break;
                                    case eCatFilter.Remaining:
                                        if (testcase.LatestResult != eTestState.NotRun) failFilter = true;
                                        break;
                                    case eCatFilter.Complete:
                                        if (testcase.LatestResult == eTestState.NotRun) failFilter = true;
                                        break;

                                }
                                if (!failFilter) shownTests.Add(testcase);
                            }

                            if (!shownTests.Any()) continue;


                            Veldrid.ResourceFactory rf = _controller.graphicsDevice.ResourceFactory;
                            IntPtr starFullIcon = _controller.GetOrCreateImGuiBinding(rf, _controller.GetImage("StarFull"));
                            IntPtr starEmptyIcon = _controller.GetOrCreateImGuiBinding(rf, _controller.GetImage("StarEmpty"));
                            IntPtr addIcon = _controller.GetOrCreateImGuiBinding(rf, _controller.GetImage("GreenPlus"));

                            bool starredCategory = category.Starred;
                            if (ImGui.TreeNodeEx(testDir, ImGuiTreeNodeFlags.DefaultOpen, category.CategoryName))
                            {
                                ImGui.SameLine(ImGui.GetContentRegionAvail().X + 5 );
                                IntPtr catstarTexture = starredCategory ? starFullIcon : starEmptyIcon;
                                if (ImGui.ImageButton(catstarTexture, new Vector2(18, 18))){
                                    category.Starred = !category.Starred;
                                }

                                if (ImGui.BeginPopupContextItem())
                                {
                                    ImGui.Checkbox("Starred Category", ref category.Starred);
                                    ImGui.EndPopup();
                                }
                                if (ImGui.BeginTable("#CatTable" + category.ID, 7, ImGuiTableFlags.BordersInner))
                                {
                                    ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.None, 40);
                                    ImGui.TableSetupColumn("Starred", ImGuiTableColumnFlags.None, 7);
                                    ImGui.TableSetupColumn("Passed", ImGuiTableColumnFlags.None, 7);
                                    ImGui.TableSetupColumn("Failed", ImGuiTableColumnFlags.None, 7);
                                    ImGui.TableSetupColumn("Running", ImGuiTableColumnFlags.None, 7);
                                    ImGui.TableSetupColumn("Add", ImGuiTableColumnFlags.None, 7);

                                    
                                    for(var testi = 0; testi < shownTests.Count; testi++)
                                    {
                                        TestCase testcase = shownTests[testi];
                                    
                                        ImGui.TableNextRow();

                                        //test name
                                        ImGui.TableNextColumn();
                                        ImGui.Text(testcase.TestName);
                                        if (ImGui.BeginPopupContextItem($"#TIDx{testi}"))
                                        {
                                            ImGui.TextWrapped("Description: " + testcase.Description);
                                            ImGui.Checkbox("Starred Test", ref testcase.Starred);
                                            ImGui.EndPopup();
                                        }

                                        //starred
                                        //ImGui.PushStyleColor(ImGuiCol.)
                                        ImGui.TableNextColumn();
                                        bool starred = (testcase.Starred || starredCategory);
                                        ImGui.PushID($"BtnStar{testi}");
                                        IntPtr starTexture = starred ? starFullIcon : starEmptyIcon;
                                        if (!starredCategory)
                                        {
                                            if (ImGui.ImageButton(starTexture, new Vector2(23, 23), Vector2.Zero, Vector2.One, 0))
                                                testcase.Starred = !testcase.Starred;
                                            if (ImGui.IsItemHovered())
                                            {
                                                ImGui.SetTooltip($"Click to {((testcase.Starred) ? "unstar" : "star")} this test");
                                            }
                                        }
                                        else
                                        {
                                            SmallWidgets.DrawIcon(_controller, "StarFull");
                                            ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, 0xff666600);
                                        }
                                        ImGui.PopID();

                                        //pass/fail
                                        ImGui.TableNextColumn();
                                        if (testcase.LatestResult != eTestState.NotRun) 
                                        {
                                            int count = testcase.CountPassed(_currentSession);
                                            if (count > 0)
                                            {
                                                ImGui.SetCursorScreenPos(ImGui.GetCursorScreenPos() + new Vector2(0, 2));
                                                SmallWidgets.DrawIcon(_controller, "Check", count); 
                                            }
                                        }

                                        ImGui.TableNextColumn();
                                        if (testcase.LatestResult != eTestState.NotRun)
                                        {
                                            int count = testcase.CountFailed(_currentSession);
                                            if (count > 0)
                                            {
                                                ImGui.SetCursorScreenPos(ImGui.GetCursorScreenPos() + new Vector2(0, 2));
                                                SmallWidgets.DrawIcon(_controller, "Cross", count);
                                            }
                                        }

                                        //running
                                        ImGui.TableNextColumn();
                                        if (testcase.Running > 0)
                                        {
                                            SmallWidgets.DrawSpinner(_controller, testcase.Running);
                                            if (ImGui.IsItemHovered())
                                            {
                                                int count = testcase.Running;
                                                ImGui.SetTooltip($"{count} instance{(count != 1 ? "s" : "")} of this test currently executing");
                                            }
                                        }

                                        ImGui.TableNextColumn();
                                        ImGui.PushID($"BtnAdd{testi}");
                                        if (ImGui.ImageButton(addIcon, new Vector2(23,23))) 
                                            AddTestToQueue(testcase);
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
                                }
                                ImGui.TreePop();
                            }
                        }
                    }
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
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
                                lock (_TestsLock)
                                {
                                    _queuedTests.RemoveAt(i);
                                }
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

