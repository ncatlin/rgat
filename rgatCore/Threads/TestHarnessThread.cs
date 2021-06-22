﻿using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgatCore.Testing
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


        public TestCaseRun GetTestCaseRun (long ID)
        {
            lock (_lock)
            {
                if (_testRuns.TryGetValue(ID, out TestCaseRun testrun)) return testrun;
                return null;
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

                _runningTests.Remove(testID);

                //_newResults.Add(tcr.MarkFinished());
                tcr.MarkFinished();
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