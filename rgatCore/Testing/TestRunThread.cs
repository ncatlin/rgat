﻿/*
 * A worker for a single execution of a test case
 */
using Humanizer;
using System;
using System.IO;
using System.Threading;

namespace rgat.Testing
{
    internal class TestRunThread
    {
        private readonly TestCase _testCase;
        private readonly TestCaseRun _thisTest;
        private Thread? thisThread;
        private readonly rgatState _rgatState;
        public bool Running { get; private set; } = false;
        public bool Finished { get; private set; } = false;

        private readonly TestRunner _harness;

        public TestRunThread(TestCaseRun testrun, rgatState rgatState, TestRunner harness)
        {
            _testCase = testrun.GetTestCase;
            _thisTest = testrun;
            _rgatState = rgatState;
            _harness = harness;
        }


        public void Begin(string _)
        {
            thisThread = new Thread(new ParameterizedThreadStart(TestMain))
            {
                Name = $"Test_{_thisTest.Session}_{_thisTest.TestID}_{_testCase.TestName.Truncate(20)}"
            };
            thisThread.Start(null);
        }

        private void TestMain(object? _)
        {
            if (!File.Exists(_testCase.BinaryPath))
            {
                Logging.RecordLogEvent($"Test {_testCase.CategoryName}{_testCase.TestName} started with missing binary {_testCase.BinaryPath}");
                Finished = true;
                return;
            }
            Running = true;
            _testCase.RecordRunning();
            Logging.WriteConsole($"Started test Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}");
            Logging.WriteConsole($"Starting test process {_testCase.BinaryPath} test id {_thisTest.TestID}");

            ProcessLaunchSettings settings = _testCase.CreateSettings();

            System.Diagnostics.Process? testProcess = ProcessLaunching.StartLocalTrace(_testCase.TestBits, settings, testID: _thisTest.TestID);
            if (testProcess != null)
            {
                //GetTestTrace
                while (!rgatState.rgatIsExiting && !Finished)
                {
                    Logging.WriteConsole($"\tWaiting for test {_thisTest.TestID} to start...");
                    if (_rgatState.GetTestTrace(_thisTest.TestID, out TraceRecord? testTrace) && testTrace is not null)
                    {
                        _thisTest.SetFirstTrace(testTrace);
                        Logging.WriteConsole($"\tGot first trace of test {_thisTest.TestID}");

                        while (!rgatState.rgatIsExiting && !Finished)
                        {
                            /*
                             * This is quite awkward - main concern is something that does CreateProces() => ExitProcess()
                             * and we exit thinking the job is done just before another child process connects.
                             * A 100 ms delay isn't foolproof but without actually instrumenting all the process creation
                             * APIs it's difficult to come up with something to wait on.
                             * Re-evaluate when multi-process tests are written
                             */
                            Thread.Sleep(100);
                            if (!testTrace.IsRunning && !testTrace.ProcessingRemaining_All)
                            {
                                Finished = true;
                                _thisTest.SetFinishTime(DateTime.Now);
                            }
                        }
                    }
                    else { Thread.Sleep(100); }
                }
            }


            Running = false;
            _testCase.RecordFinished();

            Logging.WriteConsole($"Finished test [Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}]");

            _harness.NotifyComplete(_thisTest.TestID);
        }

    }
}
