using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore.Testing
{
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
        public TraceRecord FirstTrace { get; private set; }
        public void SetFirstTrace(TraceRecord trace) => FirstTrace = trace;

        TestCase _test = null;
        public TestCase GetTestCase => _test;
        List<TestOutput> outputs = new List<TestOutput>();
        List<TestResult> results = new List<TestResult>();

        readonly object _lock = new object();

        public TestOutput[] Outputs() { lock (_lock) { return outputs.ToArray(); } }


        public void MarkFinished()
        {
            EvaluateResults();
            Complete = true;
        }

        public void AddOutput(TestOutput item)
        {
            lock (_lock) { outputs.Add(item); }
        }

        void EvaluateResults()
        {
            TestRequirement[] wholerunRequirements = _test.TestRunRequirements();
            foreach (TestRequirement req in wholerunRequirements)
            {
                Console.WriteLine($"Evaluating test requirement {req.Name} {req.Condition} [val] ");

            }

            ProcessTestRequirements[] processThreadReqs = _test.ProcessRequirements();
            foreach (ProcessTestRequirements processTests in processThreadReqs)
            {
                List<TestRequirement> processRequirementsList = processTests.ProcessRequirements;
                foreach (TestRequirement req in processRequirementsList)
                {
                    Console.WriteLine($"Evaluating process requirement {req.Name} {req.Condition} [val] ");

                }

                foreach (List<TestRequirement> threadRequirementsList in processTests.ThreadRequirements)
                {
                    foreach (TestRequirement req in threadRequirementsList)
                    {
                        Console.WriteLine($"Evaluating thread requirement {req.Name} {req.Condition} [val] ");
                    }
                }

            }


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
}
