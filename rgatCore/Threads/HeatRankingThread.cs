﻿using System.Linq;
using System.Threading;

namespace rgat.Threads
{
    /// <summary>
    /// Iterates over all the instructions in a thread ranking them by execution count
    /// Only operates on the graph active in the visualiser pane
    /// </summary>
    public class HeatRankingThread : TraceProcessorWorker
    {
        /// <summary>
        /// Begin work
        /// </summary>
        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc)
            {
                Name = $"HeakRankingWorker"
            };
            WorkerThread.Start();
        }


        private static void PerformEdgeHeatRanking(ProtoGraph graph)
        {
            if (graph.EdgeCount < 10)
            {
                return;
            }

            var edgeList = graph.GetEdgeObjListCopy();

            var allEdgeExecutions = edgeList.Select(e => e.ExecutionCount).Distinct().ToList();
            allEdgeExecutions.Sort();

            float decile = allEdgeExecutions.Count / 10f;
            float current = decile;


            ulong[] EdgeHeatThresholds = new ulong[9];
            for (var i = 0; i < 9; i++)
            {
                EdgeHeatThresholds[i] = allEdgeExecutions.ElementAt((int)current);
                current += decile;
            }

            foreach (EdgeData e in edgeList)
            {
                ulong execCount = e.ExecutionCount;
                int threshold = 0;
                while (threshold < EdgeHeatThresholds.Length && execCount > EdgeHeatThresholds[threshold])
                {
                    threshold++;
                }
                e.heatRank = threshold;
            }


        }

        private static void PerformNodeHeatRanking(ProtoGraph graph)
        {
            if (graph.NodeList.Count < 10)
            {
                return;
            }

            var nodeSpan = graph.GetNodeObjlistSpan();
            
            var allNodeExecutions = nodeSpan.ToArray().Select(n => n.ExecutionCount).ToList();
            allNodeExecutions.Sort();


            System.Collections.Generic.List<ulong> NodeHeatThresholds = Enumerable.Repeat((ulong)0, 9).ToList();
            int decile = allNodeExecutions.Count / 10;
            int current = decile;
            for (var i = 0; i < 9; i++)
            {
                NodeHeatThresholds[i] = allNodeExecutions.ElementAt(current);
                current += decile;
            }

            foreach (NodeData n in nodeSpan)
            {
                ulong execCount = n.ExecutionCount;
                int threshold = 0;
                while (threshold < NodeHeatThresholds.Count && execCount > NodeHeatThresholds[threshold])
                {
                    threshold++;
                }
                n.HeatRank = threshold;
            }
        }


        /// <summary>
        /// Ranking thread function
        /// </summary>
        public void ThreadProc()
        {

            while (!rgatState.rgatIsExiting)
            {
                Thread.Sleep(1000);

                PlottedGraph? graph = rgatState.ActiveGraph;
                if (graph == null || graph.InternalProtoGraph.HeatSolvingComplete)
                {
                    continue;
                }

                if (graph.InternalProtoGraph.HeatSolvingComplete is false)
                {
                    ulong instructionTotal = graph.InternalProtoGraph.TotalInstructions;

                    PerformEdgeHeatRanking(graph.InternalProtoGraph);
                    PerformNodeHeatRanking(graph.InternalProtoGraph);
                    if ((graph.InternalProtoGraph.TraceProcessor is null || graph.InternalProtoGraph.TraceProcessor.Running is false) && 
                        instructionTotal == graph.InternalProtoGraph.TotalInstructions)
                    {
                        graph.InternalProtoGraph.MarkHeatSolvingComplete();
                    }
                    if (graph.RenderingMode == CONSTANTS.eRenderingMode.eHeatmap)
                        graph.ResetCachedRender();
                }
            }
            Finished();
        }
    }
}
