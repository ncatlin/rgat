using Humanizer;
using System;
using System.IO;
using System.Threading;

namespace rgat.Testing
{
    class TestRunThread
    {
        readonly TestCase _testCase;
        readonly TestCaseRun _thisTest;
        Thread? thisThread;
        readonly rgatState _rgatState;
        public bool Running { get; private set; } = false;
        public bool Finished { get; private set; } = false;

        readonly TestHarnessThread _harness;

        public TestRunThread(TestCaseRun testrun, rgatState rgatState, TestHarnessThread harness)
        {
            _testCase = testrun.GetTestCase;
            _thisTest = testrun;
            _rgatState = rgatState;
            _harness = harness;
        }


        public void Begin(string _)
        {
            thisThread = new Thread(new ParameterizedThreadStart(TestMain));
            thisThread.Name = $"Test_{_thisTest.Session}_{_thisTest.TestID}_{_testCase.TestName.Truncate(20)}";
            thisThread.Start(null);
        }

        void TestMain(Object? _)
        {
            if (!File.Exists(_testCase.BinaryPath))
            {
                Logging.RecordLogEvent($"Test {_testCase.CategoryName}{_testCase.TestName} started with missing binary {_testCase.BinaryPath}");
                Finished = true;
                return;
            }
            Running = true;
            _testCase.RecordRunning();
            Console.WriteLine($"Started test Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}");
            Console.WriteLine($"Starting test process {_testCase.BinaryPath} test id {_thisTest.TestID}");

            string pintool = _testCase.TestBits == 32 ? GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath32) :
                GlobalConfig.GetSettingPath(CONSTANTS.PathKey.PinToolPath64);
            System.Diagnostics.Process? testProcess = ProcessLaunching.StartLocalTrace(pintool, _testCase.BinaryPath, testID: _thisTest.TestID);
            if (testProcess != null)
            {
                //GetTestTrace
                while (!rgatState.rgatIsExiting && !Finished)
                {
                    Console.WriteLine($"\tWaiting for test {_thisTest.TestID} to start...");
                    if (_rgatState.GetTestTrace(_thisTest.TestID, out TraceRecord testTrace))
                    {
                        _thisTest.SetFirstTrace(testTrace);
                        Console.WriteLine($"\tGot first trace of test {_thisTest.TestID}");

                        while (!rgatState.rgatIsExiting && !Finished)
                        {
                            Thread.Sleep(100);
                            if (!testTrace.IsRunning && !testTrace.ProcessingRemaining)
                                Finished = true;
                        }
                    }
                    else { Thread.Sleep(100); }
                }
            }


            Console.WriteLine($"Finished test [Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}]");

            Running = false;

            _testCase.RecordFinished();
            _harness.NotifyComplete(_thisTest.TestID);
        }

    }
}
