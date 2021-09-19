using System.Linq;
using System.Threading;

namespace rgat.Threads
{
    public class HeatRankingThread : TraceProcessorWorker
    {
        public HeatRankingThread()
        {
        }

        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc);
            WorkerThread.Name = $"HeakRankingWorker";
            WorkerThread.Start();
        }

        static void PerformEdgeHeatRanking(ProtoGraph graph)
        {
            if (graph.EdgeList.Count < 10) return;

            var edgeList = graph.GetEdgeObjListCopy();

            var allEdgeExecutions = edgeList.Select(e => e.executionCount).Distinct().ToList();
            allEdgeExecutions.Sort();

            float decile = (float)allEdgeExecutions.Count / 10f;
            float current = decile;
            
            for (var i = 0; i < 9; i++)
            {
                graph._edgeHeatThresholds[i] = allEdgeExecutions.ElementAt((int)current);
                current += decile;
            }

            foreach (EdgeData e in edgeList)
            {
                ulong execCount = e.executionCount;
                int threshold = 0;
                while (threshold < graph._edgeHeatThresholds.Count && execCount > graph._edgeHeatThresholds[threshold])
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

            int decile = allNodeExecutions.Count / 10;
            int current = decile;
            for (var i = 0; i < 9; i++)
            {
                graph._nodeHeatThresholds[i] = allNodeExecutions.ElementAt(current);
                current += decile;
            }

            foreach (NodeData n in nodeList)
            {
                ulong execCount = n.executionCount;
                int threshold = 0;
                while (threshold < graph._nodeHeatThresholds.Count && execCount > graph._nodeHeatThresholds[threshold])
                {
                    threshold++;
                }
                n.heatRank = threshold;
            }
        }

        public void ThreadProc()
        {
            return; //temporarily disable in lieu of marking ranking complete for a thread




            while (!rgatState.rgatIsExiting)
            {

                PlottedGraph graph = _clientState.ActiveGraph;
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


                TraceRecord activeTrace = _clientState.ActiveTrace;

                if (activeTrace == null)
                {
                    Thread.Sleep(200);
                }

            }
            Finished();
        }
    }
}
