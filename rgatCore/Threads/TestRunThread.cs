using Humanizer;
using System;
using System.Collections.Generic;
using System.Text;
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
            Running = true;
            _testCase.RecordRunning();
            Console.WriteLine($"Started test Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}");
            int countDown = 2;
            
            while (!_rgatState.rgatIsExiting)
            {
                Console.WriteLine($"Output {2-countDown}/2 from test Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}");
                Thread.Sleep(1700);
                countDown -= 1;
                if (countDown <= 0) break;
            }


            Console.WriteLine($"Finished test [Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}]");
            Finished = true;
            Running = false;
            _testCase.RecordFinished();
            _harness.NotifyComplete(_thisTest.TestID);
        }

    }
}
