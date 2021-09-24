using System.Linq;
using System.Threading;

namespace rgat.Threads
{
    /// <summary>
    /// Iterates over all the instructions in a thread ranking them by execution count
    /// </summary>
    public class HeatRankingThread : TraceProcessorWorker
    {
        /// <summary>
        /// Begin work
        /// </summary>
        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc);
            WorkerThread.Name = $"HeakRankingWorker";


            //WorkerThread.Start();//temporarily disable in lieu of marking ranking complete for a thread


        }

        static void PerformEdgeHeatRanking(ProtoGraph graph)
        {
            if (graph.EdgeCount < 10) return;

            var edgeList = graph.GetEdgeObjListCopy();

            var allEdgeExecutions = edgeList.Select(e => e.ExecutionCount).Distinct().ToList();
            allEdgeExecutions.Sort();

            float decile = (float)allEdgeExecutions.Count / 10f;
            float current = decile;


            System.Collections.Generic.List<ulong> EdgeHeatThresholds = Enumerable.Repeat((ulong)0, 9).ToList();
            for (var i = 0; i < 9; i++)
            {
                EdgeHeatThresholds[i] = allEdgeExecutions.ElementAt((int)current);
                current += decile;
            }

            foreach (EdgeData e in edgeList)
            {
                ulong execCount = e.ExecutionCount;
                int threshold = 0;
                while (threshold < EdgeHeatThresholds.Count && execCount > EdgeHeatThresholds[threshold])
                {
                    threshold++;
                }
                e.heatRank = threshold;
            }


        }

        static void PerformNodeHeatRanking(ProtoGraph graph)
        {
            if (graph.NodeList.Count < 10) return;

            var nodeList = graph.GetNodeObjlistCopy();
            var allNodeExecutions = nodeList.Select(n => n.executionCount).ToList();
            allNodeExecutions.Sort();


            System.Collections.Generic.List<ulong> NodeHeatThresholds = Enumerable.Repeat((ulong)0, 9).ToList();
            int decile = allNodeExecutions.Count / 10;
            int current = decile;
            for (var i = 0; i < 9; i++)
            {
                NodeHeatThresholds[i] = allNodeExecutions.ElementAt(current);
                current += decile;
            }

            foreach (NodeData n in nodeList)
            {
                ulong execCount = n.executionCount;
                int threshold = 0;
                while (threshold < NodeHeatThresholds.Count && execCount > NodeHeatThresholds[threshold])
                {
                    threshold++;
                }
                n.heatRank = threshold;
            }
        }


        /// <summary>
        /// Ranking thread function
        /// </summary>
        public void ThreadProc()
        {

            while (!rgatState.rgatIsExiting)
            {

                PlottedGraph? graph = _clientState!.ActiveGraph;
                if (graph == null)
                {
                    Thread.Sleep(200);
                    continue;
                }

                if (!graph.InternalProtoGraph.HeatSolvingComplete)
                {
                    PerformEdgeHeatRanking(graph.InternalProtoGraph);
                    PerformNodeHeatRanking(graph.InternalProtoGraph);
                }


                TraceRecord? activeTrace = _clientState.ActiveTrace;
                if (activeTrace == null)
                {
                    Thread.Sleep(200);
                }

            }
            Finished();
        }
    }
}
