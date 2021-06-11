using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgatCore.Testing
{
    public enum eTestState { NotRun, Passed, Failed };

    //metadata for a loaded test
    public class TestCase
    {
        //the lastest test result
        public eTestState LatestResult = eTestState.NotRun; 
        public string Path;
        public string CategoryName;
        public string TestName;
        public bool Starred;
        public string Description;

        public int Running { get; private set; }
        Dictionary<int, int> _passed = new Dictionary<int, int>();
        Dictionary<int, int> _failed = new Dictionary<int, int>();
        readonly object _lock = new object();

        public void RecordRunning() { lock (_lock) { Running++; } }
        public void RecordFinished() { lock (_lock) { Running--; } }
        public void RecordPassed(int sessionID) { 
            lock (_lock) {
                _passed.TryGetValue(sessionID, out int val);
                _passed[sessionID] = val + 1;
                LatestResult = eTestState.Passed;
            } }
        public int CountPassed(int sessionID) { lock (_lock) { _passed.TryGetValue(sessionID, out int val); return val; } }

        public void RecordFailed(int sessionID) { 
            lock (_lock) {
                _failed.TryGetValue(sessionID, out int val);
                _failed[sessionID] = val + 1;
                LatestResult = eTestState.Failed;
            } }
        public int CountFailed(int sessionID) { lock (_lock) { _failed.TryGetValue(sessionID, out int val); return val; } }

    }

    //object associated with one execution of a testcase
    public class TestCaseRun
    {
        public TestCaseRun(TestCase testc, int session, long testID)
        {
            Session = session;
            TestID = testID;
            _test = testc;
        }
        public bool Complete { get; private set; }
        public int Session;
        public long TestID;
        TestCase _test = null;
        public TestCase GetTestCase => _test;
        List<TestOutput> outputs = new List<TestOutput>();
        List<TestResult> results = new List<TestResult>();

        readonly object _lock = new object();

        public TestOutput[] Outputs() { lock (_lock) { return outputs.ToArray(); } }


       public void MarkFinished(ProtoGraph graph)
        {
            EvaluateResults(graph);
            Complete = true;
        }

        public void AddOutput(TestOutput item)
        {
            lock (_lock) { outputs.Add(item); }
        }

        void EvaluateResults(ProtoGraph graph)
        {
            _test.RecordPassed(Session);
            _test.RecordFailed(Session);
        }

        public TestResult[] Results()
        {
            if (!Complete) return null;
            lock (_lock)
            {
                return results.ToArray();
            }
        }
    }

    //a collection of testcases run in a session
    public class TestSession
    {
        public List<TestCaseRun> tests = new List<TestCaseRun>();
    }

    public class TestOutput
    {
        public string text;
    }
    public class TestResult
    {
        public string text;
    }



    class TestHarnessThread
    {

        Thread thisThread = null;
        List<TestOutput> _newResults = new List<TestOutput>();
        readonly object _lock = new object();
        rgatState _rgatState;
        Dictionary<int, TestSession> _testSessions = new Dictionary<int, TestSession>();
        Dictionary<long, TestCaseRun> _testRuns = new Dictionary<long, TestCaseRun>();
        long _currentTestID = -1;
        Dictionary<long, TestRunThread> _runningTests = new Dictionary<long, TestRunThread>();
        int _maxRunningTests = 5;
        public int FreeTestSlots => _maxRunningTests - _runningTests.Count;
        Queue<long> _testsQueue = new Queue<long>();

        public TestHarnessThread(rgatState clientState)
        {
            _rgatState = clientState;
        }

        public void Begin(string _)
        {
            thisThread = new Thread(new ParameterizedThreadStart(Listener));
            thisThread.Name = "TestHarness";
            thisThread.Start(null);
        }

        public void InitSession(int session)
        {
            _testSessions.Add(session, new TestSession());
        }


        public long RunTest(int session, TestCase test)
        {
            lock (_lock)
            {
                if (_runningTests.Count >= _maxRunningTests) return -1;
                _currentTestID += 1;
                TestCaseRun testRun = new TestCaseRun(test, session, _currentTestID);
                _testRuns[_currentTestID] = testRun;
                _testSessions[session].tests.Add(testRun);
                TestRunThread newThread = new TestRunThread(testRun, _rgatState, this);
                newThread.Begin("");
                _runningTests.Add(_currentTestID, newThread);
                return _currentTestID;
            }
        }



        public bool GetLatestResults(int max, out TestOutput[] results)
        {
            if (_newResults.Count == 0)
            {
                results = null;
                return false;
            }

            lock (_lock)
            {
                results = _newResults.Take(Math.Min(max, _newResults.Count)).ToArray();
                _newResults.Clear();
                return true;
            }
        }

        public void NotifyComplete(long testID)
        {
            lock (_lock)
            {
                TestCaseRun tcr = _testRuns[testID];
                TestRunThread testThread = _runningTests[testID];
                Debug.Assert(testThread.Finished);
                
                if (testThread.Finished)
                {
                    _runningTests.Remove(testID);
                }
                tcr.MarkFinished(null);
            }
        }

        void Listener(Object pipenameO)
        {
            while (!_rgatState.rgatIsExiting)
            {
                Thread.Sleep(1000);
                lock (_lock)
                {
                    if (_testsQueue.Any())
                    {
                    }
                }
            }
        }

    }
}
