using System.Collections.Generic;
using System.Diagnostics;

namespace rgat.Testing
{

    /// <summary>
    /// a collection of testcases run in a session of tests
    /// </summary>
    public class TestSession
    {
        /// <summary>
        /// a collection of testcases run in a session of tests
        /// </summary>
        public List<TestCaseRun> tests = new List<TestCaseRun>();
    }

    /// <summary>
    /// A result of a test
    /// </summary>
    public class TestResult
    {
        /// <summary>
        /// Result text
        /// </summary>
        public string? text;
    }

    class TestHarnessThread
    {
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


        public void InitSession(int session)
        {
            _testSessions.Add(session, new TestSession());
        }


        public long RunTest(int session, TestCase test)
        {
            lock (_lock)
            {
                if (_runningTests.Count >= _maxRunningTests)
                {
                    return -1;
                }

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


        /// <summary>
        /// Mark a test as complete
        /// </summary>
        /// <param name="testID">The test ID</param>
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

    }
}
