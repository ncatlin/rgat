using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace rgat.Testing
{


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
        readonly object _lock = new object();
        readonly rgatState _rgatState;
        readonly Dictionary<int, TestSession> _testSessions = new Dictionary<int, TestSession>();
        readonly Dictionary<long, TestCaseRun> _testRuns = new Dictionary<long, TestCaseRun>();
        long _currentTestID = -1;
        readonly Dictionary<long, TestRunThread> _runningTests = new Dictionary<long, TestRunThread>();
        readonly int _maxRunningTests = 5;
        public int FreeTestSlots => _maxRunningTests - _runningTests.Count;

        readonly Queue<long> _testsQueue = new Queue<long>();

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
                if (_runningTests.Count >= _maxRunningTests)
                    return -1;

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


        public TestCaseRun GetTestCaseRun(long ID)
        {
            lock (_lock)
            {
                return _testRuns[ID];
            }
        }

        public TestSession GetTestSession(int ID)
        {
            lock (_lock)
            {
                return _testSessions[ID];
            }
        }


        public void NotifyComplete(long testID)
        {
            lock (_lock)
            {
                TestCaseRun tcr = _testRuns[testID];
                TestRunThread testThread = _runningTests[testID];
                Debug.Assert(testThread.Finished || rgatState.rgatIsExiting);

                _runningTests.Remove(testID);

                //_newResults.Add(tcr.MarkFinished());
                tcr.MarkFinished();
            }
        }


        void Listener(Object pipenameO)
        {
            while (!rgatState.rgatIsExiting)
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
