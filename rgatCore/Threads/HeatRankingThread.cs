using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgatCore.Threads
{
    public class HeatRankingThread
    {
        bool running = false;
        public rgatState rgatState = null;
        private Thread runningThread = null;

        public HeatRankingThread(rgatState _clientState)
        {
            rgatState = _clientState;
            runningThread = new Thread(ThreadProc);
            runningThread.Name = "HeakRanking";
            runningThread.Start();
        }


        static void PerformEdgeHeatRanking(ProtoGraph graph)
        {
            if (graph.EdgeList.Count < 10) return;

            var edgeList = graph.GetEdgeObjListCopy();

            var allEdgeExecutions = edgeList.Select(e => e.executionCount).ToList();
            allEdgeExecutions.Sort();

            int decile = allEdgeExecutions.Count / 10;
            int current = decile;
            for (var i = 0; i < 9; i++)
            {
                graph._edgeHeatThresholds[i] = allEdgeExecutions.ElementAt(current);
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
            running = true;
            List<PlottedGraph> graphlist;
            int StopTimer = -1;
            bool moreRenderingNeeded = false;

            while (!rgatState.rgatIsExiting)
            {

                PlottedGraph graph = rgatState.ActiveGraph;
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


                TraceRecord activeTrace = rgatState.ActiveTrace;

                if (activeTrace == null)
                {
                    Thread.Sleep(200);
                }

            }
            running = false;
        }
    }
}
