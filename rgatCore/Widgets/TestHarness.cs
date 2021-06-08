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
    enum eTestState { NotRun, Passed, Failed};
    class TestCase
    {
        public eTestState state = eTestState.NotRun;
        public string Folder;
        public string Path;
        public string Category;
        public string TestName;
    }


    class TestHarness
    {
        public TestHarness()
        {
            RefreshTestFiles();
        }

        Dictionary<string, string> _testDirCategories = new Dictionary<string, string>();
        Dictionary<string, List<TestCase>> _testDirectories = new Dictionary<string, List<TestCase>>();
        List<string> _orderedTestDirs = new List<string>();

        public void RefreshTestFiles()
        {
            _foundTestsCount = 0;
            _testDirCategories.Clear();
            _testDirectories.Clear();
            _orderedTestDirs.Clear();

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
                        validDirs.Add(new Tuple<uint, string>(num, testdir));
                        _testDirCategories[testdir] = categoryName;
                        _testDirectories[testdir] = FindTests(Path.Combine(testspath,testdir));
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
            Logging.RecordLogEvent($"Loaded {_testDirectories.Count} test directories");
        }


        static readonly string testextension = ".test.json";
        List<TestCase> FindTests(string testfolder)
        {
            List<TestCase> results = new List<TestCase>();
            string[] tests = Directory.GetFiles(testfolder).Where(x => x.EndsWith(testextension)).ToArray();
            foreach (string testfile in tests)
            {
                TestCase t = new TestCase();
                t.TestName = Path.GetFileName(testfile).Split(testextension)[0];
                t.Path = testfile;
                t.Folder = testfolder;
                t.Category = _testDirCategories[testfolder];
                results.Add(t);
                _foundTestsCount += 1;
            }
            return results;
        }


        int _foundTestsCount = 0;
        enum eCatFilter { All = 0, Remaining = 1, Passing = 2, Failed = 3, StarredTest = 4, StarredCat = 5 }
        int _selectedFilter = (int)eCatFilter.All;
        string[] filters = new string[] { "Show All Tests", "Show Remaining Tests", "Show Passing Tests",
                    "Show Failed Tests", "Show Starred Tests", "Show Starred Categories"};
        readonly int treeWidth = 200;
        List<string> _starredCategories = new List<string>(); 
        List<string> _starredTests = new List<string>(); 
        public void Draw(ref bool openFlag)
        {
            if (ImGui.Begin("Run Tests", ref openFlag, ImGuiWindowFlags.None))
            {

                ImGui.SetNextItemWidth(treeWidth);
                if (ImGui.Combo("", ref _selectedFilter, filters, filters.Length))
                {
                    Console.WriteLine("Apply tests tree filter " + filters[_selectedFilter]);
                }
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff222222);
                if (ImGui.BeginChild("##TestsTreeFrame", new Vector2(treeWidth, ImGui.GetContentRegionAvail().Y)))
                {
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 4);
                    ImGui.TextWrapped($"Loaded {_foundTestsCount} Tests in {_orderedTestDirs.Count} Categories");
                    ImGui.Separator();
                    ImGui.Indent(10);
                    {
                        foreach (string testDir in _orderedTestDirs)
                        {
                            
                            if (!_testDirectories.TryGetValue(testDir, out List<TestCase> tests) || !tests.Any()) continue;
                            if(((eCatFilter)_selectedFilter) == eCatFilter.StarredCat && 
                                !_starredCategories.Contains(_testDirCategories[testDir])) continue;

                            if (ImGui.TreeNodeEx(testDir, ImGuiTreeNodeFlags.DefaultOpen, _testDirCategories[testDir]))
                            {
                                foreach(TestCase testcase in tests)
                                {
                                    if (((eCatFilter)_selectedFilter) == eCatFilter.StarredTest &&
                                        !_starredTests.Contains(testcase.Path)) continue;

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
                                    ImGui.Selectable(label, false);
                                    if (coloured) ImGui.PopStyleColor();
                                }
                                ImGui.TreePop();
                            }
                        }
                        ImGui.TreePop();
                    }
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                ImGui.End();
            }
        }
    }
}
