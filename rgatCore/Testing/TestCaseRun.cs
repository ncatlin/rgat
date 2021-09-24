using System;
using System.Collections.Generic;
using System.Linq;

namespace rgat.Testing
{
    /// <summary>
    /// Explanations for why a test requirement passed/failed
    /// </summary>
    public class TestResultCommentary
    {
        /// <summary>
        /// Create a test result commentary
        /// </summary>
        /// <param name="req">The requirement being explained</param>
        public TestResultCommentary(TestRequirement req)
        {
            requirement = req;
        }

        /// <summary>
        /// The requirement object
        /// </summary>
        public TestRequirement requirement;

        /// <summary>
        /// The result of the comparison
        /// </summary>
        public eTestState result;
        /// <summary>
        /// Graphs that match a graph requirement
        /// </summary>
        public List<ProtoGraph> matchingGraphs = new List<ProtoGraph>();
        /// <summary>
        /// Traces that match a trace requirement
        /// </summary>
        public List<TraceRecord> matchingTraces = new List<TraceRecord>();
        /// <summary>
        /// The value that was compared
        /// </summary>
        public string comparedValueString = "";

    }

    /// <summary>
    /// Information about test results
    /// </summary>
    public class TraceTestResultCommentary
    {
        /// <summary>
        /// Whole test run requirement results
        /// </summary>
        public Dictionary<TestRequirement, TestResultCommentary> generalTests = new Dictionary<TestRequirement, TestResultCommentary>();

        //trace tests have a set of process results, each must match up to a process
        //public Dictionary<TraceRecord, TRACE_TEST_RESULTS> processTests = new Dictionary<TraceRecord, TRACE_TEST_RESULTS>();
        /// <summary>
        /// Process trace requirement results
        /// </summary>
        public TRACE_TEST_RESULTS traceResults = new TRACE_TEST_RESULTS();
        /// <summary>
        /// Thread requirement results
        /// </summary>
        public Dictionary<REQUIREMENTS_LIST, Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS>> threadTests = new();
        /// <summary>
        /// The final overall test result
        /// </summary>
        public eTestState Verdict;
        //public string Note;

    }

    internal class TestCommentaryObj
    {
        public List<Tuple<TestRequirement, TestResultCommentary>> generalTests = new List<Tuple<TestRequirement, TestResultCommentary>>();

        public List<Tuple<TraceRequirements, TestResultCommentary>> traceTests = new List<Tuple<TraceRequirements, TestResultCommentary>>();

    }


    /// <summary>
    /// object associated with one execution of a testcase
    /// </summary>
    public class TestCaseRun
    {
        /// <summary>
        /// Create a testcase run
        /// </summary>
        /// <param name="testc">Testcase</param>
        /// <param name="session">Session this test was run in</param>
        /// <param name="testID">ID of the test</param>
        public TestCaseRun(TestCase testc, int session, long testID)
        {
            Session = session;
            TestID = testID;
            _test = testc;
        }

        /// <summary>
        /// Get information about the test results
        /// </summary>
        public TraceTestResultCommentary ResultCommentary = new TraceTestResultCommentary();

        /// <summary>
        /// Run is complete
        /// </summary>
        public bool Complete { get; private set; }
        /// <summary>
        /// Test session ID
        /// </summary>
        public int Session;
        /// <summary>
        /// Test ID
        /// </summary>
        public long TestID;
        /// <summary>
        /// The first trace of the test
        /// </summary>
        public TraceRecord? FirstTrace { get; private set; }
        /// <summary>
        /// Set the initial trace
        /// </summary>
        /// <param name="trace"></param>
        public void SetFirstTrace(TraceRecord trace) => FirstTrace = trace;

        private readonly TestCase _test;
        /// <summary>
        /// Get the testcase for this test run
        /// </summary>
        public TestCase GetTestCase => _test;

        /// <summary>
        /// Mark the run as complete
        /// </summary>
        public void MarkFinished()
        {
            EvaluateResults();
            Complete = true;
        }

        private readonly Dictionary<TestRequirement, string?> FailedTestRequirements = new Dictionary<TestRequirement, string?>();

        private void EvaluateResults()
        {
            if (FirstTrace == null)
            {
                _test.RecordFailed(Session, this, "Didn't run");
                return;
            }

            EvaluateGeneralTestResults();
            if (FailedTestRequirements.Count > 0)
            {
                _test.RecordFailed(Session, this, $"{FailedTestRequirements.Count} general test requirements were not met");
            }

            TraceRequirements processThreadReqs = _test.TraceRequirements();

            TRACE_TEST_RESULTS processThreadResults = FirstTrace.EvaluateProcessTestRequirement(processThreadReqs, ref ResultCommentary);
            if (EvaluateProcessTestResults(processThreadReqs, processThreadResults, 0))
            {
                _test.RecordPassed(Session, this);
            }
            else
            {
                _test.RecordFailed(Session, this, $"Failed tests. Process:{processThreadResults.ProcessResults.Failed} Thread: ? Children: ?");
            }
        }

        private void EvaluateGeneralTestResults()
        {
            //evaluate requirements that apply to the entire trace tree
            foreach (TestRequirement req in _test.TestRunRequirements())
            {
                string compareValueString;
                bool passed;
                string? error = "";
                switch (req.Name)
                {
                    case "TotalProcesses":
                        int processCount = FirstTrace!.CountDescendantTraces();
                        passed = req.Compare(processCount, out error);
                        compareValueString = $"{processCount}";
                        break;

                    case "TotalGraphs":
                        int graphCount = FirstTrace!.CountDescendantGraphs();
                        passed = req.Compare(graphCount, out error);
                        compareValueString = $"{graphCount}";
                        break;

                    default:
                        passed = false;
                        compareValueString = "[?]";
                        error = "Unknown general test requirement: " + req.Name;
                        Logging.RecordLogEvent(error, Logging.LogFilterType.TextError);
                        break;
                }
                if (!passed)
                {
                    FailedTestRequirements.Add(req, error!);
                }
                ResultCommentary.generalTests[req] = new TestResultCommentary(req)
                {
                    comparedValueString = compareValueString,
                    result = passed ? eTestState.Passed : eTestState.Failed
                };

                /*
                testComments.generalTests.Add(new TestResultCommentary()
                {
                    comparisonTest = $"{req.Name} ({compareValueString}) {req.Condition} {req.ExpectedValue}",
                    requirement = req,
                    result = passed ? eTestState.Passed : eTestState.Failed
                });
                */
            }
        }

        private static bool EvaluateProcessTestResults(TraceRequirements requirements, TRACE_TEST_RESULTS results, int depth)
        {
            //need to ensure each set of thread requirements can be satisfied by at least one unique thread

            Dictionary<REQUIREMENTS_LIST, List<ProtoGraph>> reqSatisfyGraphs = new Dictionary<REQUIREMENTS_LIST, List<ProtoGraph>>();
            foreach (REQUIREMENTS_LIST reqlist in requirements.ThreadRequirements)
            {
                reqSatisfyGraphs[reqlist] = new List<ProtoGraph>();
            }

            foreach (var threadReqList in requirements.ThreadRequirements)
            {
                Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS> allThreadResults = results.ThreadResults[threadReqList];
                foreach (var graph_results in allThreadResults)
                {
                    ProtoGraph graph = graph_results.Key;
                    if (graph_results.Value.Failed.Count == 0)
                    {
                        reqSatisfyGraphs[threadReqList].Add(graph);
                    }
                }
            }
            bool threadsVerified = VerifyAllThreadRequirements(reqSatisfyGraphs, out string? threadVerifyError);
            bool processesVerified = results.ProcessResults.Failed.Count == 0;

            //if(!threadsVerified) FailedTestRequirements.Add(null, $"Thread traces didn't satisfy conditions list: "+threadVerifyError);
            //if(!processesVerified) FailedTestRequirements.Add(null, $"{results.ProcessResults.Failed.Count} requirements failed");

            return threadsVerified && processesVerified;

            //todo - multi process tests
            /*
            foreach(var x in results.ChildResults)
            {
                TRACE_TEST_RESULTS processThreadResults = childtrace.EvaluateProcessTestRequirement(processThreadReqs);
                EvaluateProcessTestResults(processThreadReqs, processThreadResults);
            }
            */

        }

        private static bool VerifyAllThreadRequirements(Dictionary<REQUIREMENTS_LIST, List<ProtoGraph>> reqSatisfyGraphs, out string? error)
        {
            error = "";
            int reqListCount = reqSatisfyGraphs.Count;
            List<REQUIREMENTS_LIST> unsatisfied = new List<REQUIREMENTS_LIST>();

            List<Tuple<REQUIREMENTS_LIST, ProtoGraph>> candidates = new List<Tuple<REQUIREMENTS_LIST, ProtoGraph>>();
            List<ProtoGraph> uniqueGraphs = new List<ProtoGraph>();

            //now we have a list of graphs that satisfy each set of requirements
            //list any requirements that no graphs satisfy
            foreach (var req_graplist in reqSatisfyGraphs)
            {
                REQUIREMENTS_LIST reqs = req_graplist.Key;
                if (req_graplist.Value.Count == 0)
                {
                    unsatisfied.Add(reqs);
                }
                foreach (var validGraph in req_graplist.Value)
                {
                    candidates.Add(new Tuple<REQUIREMENTS_LIST, ProtoGraph>(reqs, validGraph));
                    if (!uniqueGraphs.Contains(validGraph))
                    {
                        uniqueGraphs.Add(validGraph);
                    }
                }
            }
            if (unsatisfied.Count > 0)
            {

                return false;
            }


            //now pair each requirementlist up to a single graph
            //this might be better solved with a theorem prover, but for now just terribly brute force it
            //might stipulate that each set of requirements needs to be sufficiently specific it will only match 1 graph
            List<Tuple<REQUIREMENTS_LIST, ProtoGraph>> bestList = new List<Tuple<REQUIREMENTS_LIST, ProtoGraph>>();


            List<Tuple<REQUIREMENTS_LIST, ProtoGraph>> currentList = new List<Tuple<REQUIREMENTS_LIST, ProtoGraph>>();

            List<REQUIREMENTS_LIST> usedReqs = new List<REQUIREMENTS_LIST>();
            List<ProtoGraph> usedGraphs = new List<ProtoGraph>();

            foreach (var permutation in GetPermutationsWithRept<Tuple<REQUIREMENTS_LIST, ProtoGraph>>(candidates, candidates.Count))
            {
                usedGraphs.Clear();
                usedReqs.Clear();
                currentList.Clear();
                foreach (var req_graph in permutation)
                {
                    ProtoGraph graph = req_graph.Item2;
                    REQUIREMENTS_LIST reqs = req_graph.Item1;
                    if (usedReqs.Contains(reqs))
                    {
                        continue;
                    }

                    if (usedGraphs.Contains(graph))
                    {
                        continue;
                    }

                    currentList.Add(req_graph);
                    usedGraphs.Add(graph);
                    usedReqs.Add(reqs);
                    if (usedReqs.Count == reqListCount)
                    {
                        return true;
                    }
                }
                if (currentList.Count > bestList.Count)
                {
                    bestList = currentList;
                }
            }

            error = $"Failed to satisfy all thread requirements, best attempt was {bestList.Count}/{reqListCount}";
            return false;
        }

        private static IEnumerable<IEnumerable<T>> GetPermutationsWithRept<T>(IEnumerable<T> list, int length)
        {
            if (length < 2)
            {
                return list.Select(t => new T[] { t });
            }

            return GetPermutationsWithRept(list, length - 1).SelectMany(t => list, (t1, t2) => t1.Concat(new T[] { t2 }));
        }
    }
}
