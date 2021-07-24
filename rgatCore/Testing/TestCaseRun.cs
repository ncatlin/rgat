using System;
using System.Collections.Generic;
using System.Linq;

namespace rgatCore.Testing
{
    public class TestResultCommentary
    {
        public TestRequirement requirement;
        public string comparisonTest;
        public eTestState result;
        public List<ProtoGraph> matchingGraphs = new List<ProtoGraph>();
        public List<TraceRecord> matchingTraces = new List<TraceRecord>();
        public string comparisonNote;
        public string comparedValueString;

    }

    public class TraceTestResultCommentary
    {

        public Dictionary<TestRequirement, TestResultCommentary> generalTests = new Dictionary<TestRequirement, TestResultCommentary>();

        //trace tests have a set of process results, each must match up to a process
        //public Dictionary<TraceRecord, TRACE_TEST_RESULTS> processTests = new Dictionary<TraceRecord, TRACE_TEST_RESULTS>();
        public Dictionary<TraceRecord, TRACE_TEST_RESULTS> processTests = new Dictionary<TraceRecord, TRACE_TEST_RESULTS>();
        public TRACE_TEST_RESULTS traceResultsB = new TRACE_TEST_RESULTS();
        //public Dictionary<REQUIREMENTS_LIST, TestResultCommentary> threadTests = new Dictionary<REQUIREMENTS_LIST, TestResultCommentary>();

        public Dictionary<REQUIREMENTS_LIST, Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS>> threadTests =
    new Dictionary<REQUIREMENTS_LIST, Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS>>();


        /*

        public List<
            List<Tuple<TestRequirement, TestResultCommentary>>
            > threadTests = new List<List<Tuple<TestRequirement, TestResultCommentary>>>();
        */

        public TraceRequirements traceRequirements;
        public TestRequirement singleRequirement;
        public eTestState result;
        public string Note;
        public List<ProtoGraph> matchingGraphs = new List<ProtoGraph>();
        public List<TraceRecord> matchingTraces = new List<TraceRecord>();

    }

    class TestCommentaryObj
    {
        public List<Tuple<TestRequirement, TestResultCommentary>> generalTests = new List<Tuple<TestRequirement, TestResultCommentary>>();

        public List<Tuple<TraceRequirements, TestResultCommentary>> traceTests = new List<Tuple<TraceRequirements, TestResultCommentary>>();

    }

    //object associated with one execution of a testcase
    public class TestCaseRun
    {

        public TestCaseRun(TestCase testc, int session, long testID)
        {
            Session = session;
            TestID = testID;
            _test = testc;
        }

        public TraceTestResultCommentary ResultCommentary = new TraceTestResultCommentary();

        public bool Complete { get; private set; }
        public int Session;
        public long TestID;
        public TraceRecord FirstTrace { get; private set; }
        public void SetFirstTrace(TraceRecord trace) => FirstTrace = trace;

        TestCase _test = null;
        public TestCase GetTestCase => _test;
        List<TestResult> results = new List<TestResult>();

        readonly object _lock = new object();

        public void MarkFinished()
        {
            EvaluateResults();
            Complete = true;
        }

        Dictionary<TestRequirement, string> FailedTestRequirements = new Dictionary<TestRequirement, string>();

        void EvaluateResults()
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
                _test.RecordFailed(Session, this, "ff");
            }
        }


        void EvaluateGeneralTestResults()
        {
            //evaluate requirements that apply to the entire trace tree
            foreach (TestRequirement req in _test.TestRunRequirements())
            {
                string compareValueString;
                bool passed;
                string error = "";
                switch (req.Name)
                {
                    case "TotalProcesses":
                        int processCount = FirstTrace.CountDescendantTraces();
                        passed = req.Compare(processCount, out error);
                        compareValueString = $"{processCount}";
                        break;

                    case "TotalGraphs":
                        int graphCount = FirstTrace.CountDescendantGraphs();
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
                    FailedTestRequirements.Add(req, error);
                }
                ResultCommentary.generalTests[req] = new TestResultCommentary()
                {
                    comparedValueString = compareValueString,
                    result = passed ? eTestState.Passed : eTestState.Failed,
                    requirement = req
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


        bool EvaluateProcessTestResults(TraceRequirements requirements, TRACE_TEST_RESULTS results, int depth)
        {
            //need to ensure each set of thread requirements can be satisfied by at least one unique thread

            Dictionary<REQUIREMENTS_LIST, List<ProtoGraph>> reqSatisfyGraphs = new Dictionary<REQUIREMENTS_LIST, List<ProtoGraph>>();
            foreach (REQUIREMENTS_LIST reqlist in requirements.ThreadRequirements)
                reqSatisfyGraphs[reqlist] = new List<ProtoGraph>();

            foreach (var threadReqList in requirements.ThreadRequirements)
            {
                Dictionary<ProtoGraph, REQUIREMENT_TEST_RESULTS> allThreadResults = results.ThreadResults[threadReqList];
                foreach (var graph_results in allThreadResults)
                {
                    ProtoGraph graph = graph_results.Key;
                    if (graph_results.Value.Failed.Count == 0) reqSatisfyGraphs[threadReqList].Add(graph);
                }
            }
            bool threadsVerified = VerifyAllThreadRequirements(reqSatisfyGraphs, out string threadVerifyError);
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

        bool VerifyAllThreadRequirements(Dictionary<REQUIREMENTS_LIST, List<ProtoGraph>> reqSatisfyGraphs, out string error)
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
                    if (!uniqueGraphs.Contains(validGraph)) uniqueGraphs.Add(validGraph);
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
                    if (usedReqs.Contains(reqs)) continue;
                    if (usedGraphs.Contains(graph)) continue;
                    currentList.Add(req_graph);
                    usedGraphs.Add(graph);
                    usedReqs.Add(reqs);
                    if (usedReqs.Count == reqListCount) return true;
                }
                if (currentList.Count > bestList.Count) bestList = currentList;
            }

            error = $"Failed to satisfy all thread requirements, best attempt was {bestList.Count}/{reqListCount}";
            return false;
        }

        static IEnumerable<IEnumerable<T>> GetPermutationsWithRept<T>(IEnumerable<T> list, int length)
        {
            if (length < 2) return list.Select(t => new T[] { t });
            return GetPermutationsWithRept(list, length - 1).SelectMany(t => list, (t1, t2) => t1.Concat(new T[] { t2 }));
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
