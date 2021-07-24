using Humanizer;
using System;
using System.IO;
using System.Threading;

namespace rgatCore.Testing
{
    class TestRunThread
    {
        TestCase _testCase = null;
        TestCaseRun _thisTest;
        Thread thisThread;
        rgatState _rgatState;
        public bool Running { get; private set; } = false;
        public bool Finished { get; private set; } = false;
        TestHarnessThread _harness;

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

        void TestMain(Object _)
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
            int countDown = 2;

            string pintoolpath = GlobalConfig.PinToolPath32;//_rgatstate.ActiveTarget.BitWidth == 32 ? GlobalConfig.PinToolPath32 : GlobalConfig.PinToolPath64;
            Console.WriteLine($"Starting test process {_testCase.BinaryPath} test id {_thisTest.TestID}");
            ProcessLaunching.StartTracedProcess(pintoolpath, _testCase.BinaryPath, testID: _thisTest.TestID);

            //GetTestTrace
            while (!_rgatState.rgatIsExiting && !Finished)
            {
                Console.WriteLine($"\tWaiting for test {_thisTest.TestID} to start...");
                if (_rgatState.GetTestTrace(_thisTest.TestID, out TraceRecord testTrace))
                {
                    _thisTest.SetFirstTrace(testTrace);
                    Console.WriteLine($"\tGot first trace of test {_thisTest.TestID}");

                    while (!_rgatState.rgatIsExiting && !Finished)
                    {
                        Thread.Sleep(100);
                        if (!testTrace.ProcessingRemaining)
                            Finished = true;
                    }
                }
                else { Thread.Sleep(100); }
            }



            Console.WriteLine($"Finished test [Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}]");

            Running = false;


            _testCase.RecordFinished();
            _harness.NotifyComplete(_thisTest.TestID);
        }

    }
}
