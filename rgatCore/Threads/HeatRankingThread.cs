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
            var edgeList = graph.edgePtrList;
            var edgeNodesList = graph.edgeList;
            int edgeCount = edgeList.Count;
            var nodeList = graph.NodeList;
            int nodeListCount = nodeList.Count;

            //temporary stage - clear all related variables
            for (var i = 0; i < edgeCount; i++)
            {
                EdgeData edge = edgeList[i];
                //edge.executionCount = 0;
                edge.heatComplete = false;
            }
            for (var i = 0; i < nodeListCount; i++)
            {
                NodeData node = nodeList[i];
                node.heat_ExecutionsRemainingIn = 0;
                node.heat_ExecutionsRemainingOut = 0;
                node.UnsolvedInNeighbours.Clear();
                node.UnsolvedOutNeighbours.Clear();
            }


            for (var i = 0; i < edgeCount; i++)
            {
                EdgeData edge = edgeList[i];
                //edge.executionCount = 0;
                edge.heatComplete = false;
            }

            int remainingEdges = edgeList.Count;
            //first note execution count for all the trivial cases (non-flow instructions)
            List<Tuple<uint, uint>> unsolvedEdges = new List<Tuple<uint, uint>>();
            for (var i = 0; i < edgeCount; i++)
            {
                EdgeData edge = edgeList[i];
                Tuple<uint, uint> edgeNodes = edgeNodesList[i];
                NodeData sourceNode = graph.safe_get_node(edgeNodes.Item1);
                NodeData targetNode = graph.safe_get_node(edgeNodes.Item2);
                if (sourceNode.OutgoingNeighboursSet.Count == 1)
                {
                    edge.heatComplete = true;
                    targetNode.heat_ExecutionsRemainingIn -= edge.executionCount;
                    sourceNode.heat_ExecutionsRemainingOut -= edge.executionCount;
                    remainingEdges -= 1;
                    continue;
                }

                if (targetNode.IncomingNeighboursSet.Count == 1)
                {
                    edge.heatComplete = true;
                    targetNode.heat_ExecutionsRemainingIn -= edge.executionCount;
                    sourceNode.heat_ExecutionsRemainingOut -= edge.executionCount;
                    remainingEdges -= 1;
                    continue;
                }

                sourceNode.UnsolvedOutNeighbours.AddRange(sourceNode.OutgoingNeighboursSet);
                targetNode.UnsolvedInNeighbours.AddRange(targetNode.IncomingNeighboursSet);
                unsolvedEdges.Add(edgeNodes);
            }

            for(var unsolvedIndex = unsolvedEdges.Count-1; unsolvedIndex >= 0; unsolvedIndex --)
            {
                var edgeNodes = unsolvedEdges[unsolvedIndex];
                var edgeSourceIndex = edgeNodes.Item1;
                var edgeTargIndex = edgeNodes.Item2;
                var src = graph.safe_get_node(edgeSourceIndex);
                var targ = graph.safe_get_node(edgeTargIndex);
                var edge = graph.edgeDict[edgeNodes];
                for (int nidx = targ.UnsolvedInNeighbours.Count -1; nidx >= 0; nidx--)
                {
                    var targ_src_idx = targ.UnsolvedInNeighbours[nidx];
                    if (targ_src_idx != edgeSourceIndex)
                    {
                        NodeData targ_src = graph.safe_get_node((uint)targ_src_idx);
                        if (targ_src.UnsolvedOutNeighbours.Count == 0)
                        {
                            targ.UnsolvedInNeighbours.RemoveAt(nidx);
                        }
                    }
                }

                if (targ.UnsolvedInNeighbours.Count == 1 && targ.UnsolvedInNeighbours[0] == edgeSourceIndex)
                {
                    //edge.executionCount = targ.heat_ExecutionsRemainingIn;
                    src.heat_ExecutionsRemainingOut -= edge.executionCount;
                    targ.heat_ExecutionsRemainingIn = 0;
                    targ.UnsolvedInNeighbours.Clear();
                    edge.heatComplete = true;
                    src.UnsolvedOutNeighbours.Remove(edgeTargIndex);
                    unsolvedEdges.Remove(edgeNodes);
                }
            }

            if (unsolvedEdges.Count == 0)
                graph.HeatSolvingComplete = true;
            Console.WriteLine($"Done edge heat calculations {unsolvedEdges.Count} remaining out of {edgeList.Count}");
            //now assign a rank to each node

        }

        public void ThreadProc()
        {
            return;



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
