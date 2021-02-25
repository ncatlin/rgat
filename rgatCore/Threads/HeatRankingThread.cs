using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace rgatCore.Threads
{
    class HeatRankingThread
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

        //problem: the instruction trace doesn't tell us how many times each edge executes
        //work it out from how many times each node has executed
        void PerformHeatRanking(ProtoGraph graph)
        {
            if (graph.edgeList.Count < 10) return;
            
            var edgeList = graph.GetEdgePtrlistCopy();

            var allExecutions = edgeList.Select(e => e.executionCount).ToList();
            allExecutions.Sort();

            int decile = allExecutions.Count / 10;
            int current = decile;
            for (var i = 0; i < 9; i++)
            {
                graph.heatThresholds[i] = allExecutions.ElementAt(current);
                current += decile;
            }

            foreach(EdgeData e in edgeList)
            {
                ulong execCount = e.executionCount;
                int threshold = 0;
                while (threshold < graph.heatThresholds.Count && execCount > graph.heatThresholds[threshold])
                {
                    threshold++;
                }
                e.heatRank = threshold;
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
                if (!graph.internalProtoGraph.HeatSolvingComplete)
                { 
                    PerformHeatRanking(graph.internalProtoGraph); 
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
