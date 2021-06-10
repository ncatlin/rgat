using Humanizer;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace rgatCore.Testing
{
    class TestRunThread
    {
        TestCase _testCase;
        TestCaseRun _thisTest;
        Thread thisThread;
        rgatState _rgatState;

        public TestRunThread(TestCaseRun testrun, rgatState rgatState)
        {
            _testCase = testrun.TestCase;
            _thisTest = testrun;
            _rgatState = rgatState;
        }


        public void Begin(string _)
        {
            thisThread = new Thread(new ParameterizedThreadStart(TestMain));
            thisThread.Name = $"Test_{_thisTest.Session}_{_thisTest.TestID}_{_testCase.TestName.Truncate(20)}";
            thisThread.Start(null);
        }

        void TestMain(Object _)
        {
            Console.WriteLine($"Starting test Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}");
            int countDown = 6;
            
            while (!_rgatState.rgatIsExiting)
            {
                Console.WriteLine($"Output {6-countDown}/6 from test Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}");
                Thread.Sleep(1700);
                countDown -= 1;
                if (countDown <= 0) break;
            }


            Console.WriteLine($"Finished test Session{_thisTest.Session}/ID{_thisTest.TestID}/{_testCase.TestName}");
        }

    }
}
