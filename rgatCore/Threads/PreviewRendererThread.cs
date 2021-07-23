﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using Veldrid;

namespace rgatCore.Threads
{
    public class PreviewRendererThread : TraceProcessorWorker
    {
        TraceRecord RenderedTrace;
        PreviewGraphsWidget _graphWidget;

        public PreviewRendererThread(TraceRecord _renderedTrace)
        {
            RenderedTrace = _renderedTrace;
            _graphWidget = _clientState.PreviewWidget;
        }

        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc);
            WorkerThread.Name = $"PreviewWrk_{RenderedTrace.PID}_{RenderedTrace.binaryTarg.TracesCount}";
            WorkerThread.Start();
        }

        public void ThreadProc()
        {
            Logging.RecordLogEvent($"PreviewRenderThread ThreadProc START", Logging.LogFilterType.BulkDebugLogFile);

            Veldrid.CommandList cl = _clientState._GraphicsDevice.ResourceFactory.CreateCommandList();
            List<PlottedGraph> graphlist;
            int StopTimer = -1;
            bool moreRenderingNeeded;

            while (!_clientState.rgatIsExiting)
            {
                //only write we are protecting against happens while creating new threads
                //so not important to release this quickly
                graphlist = RenderedTrace.GetPlottedGraphs(eRenderingMode.eStandardControlFlow);

                moreRenderingNeeded = false;
                foreach (PlottedGraph graph in graphlist)
                {
                    if (graph == null) continue;

                    if (graph != _clientState.ActiveGraph)
                    {
                        //check for trace data that hasn't been rendered yet
                        ProtoGraph protoGraph = graph.InternalProtoGraph;

                        //Console.WriteLine($"Rendering new preview verts for thread {graph.tid}");
                        graph.render_graph();
                        if (!graph.RenderingComplete())
                            moreRenderingNeeded = true;
                    }

                    if (graph.DrawnEdgesCount > 0)
                    {
                        _graphWidget.GeneratePreviewGraph(cl, graph);
                    }

                    if (_clientState.rgatIsExiting) break;
                    Thread.Sleep((int)GlobalConfig.Preview_PerThreadLoopSleepMS); //sleep removed for debug
                }

                graphlist.Clear();

                int waitForNextIt = 0;
                while (waitForNextIt < GlobalConfig.Preview_PerProcessLoopSleepMS && !_clientState.rgatIsExiting)
                {


                    Thread.Sleep(50); //sleep removed for debug


                    waitForNextIt += 50;
                }

                if (StopTimer < 0 && !moreRenderingNeeded && !RenderedTrace.IsRunning)
                    StopTimer = 60;
                else if (StopTimer > 0)
                    StopTimer--;

            }
            Finished();
        }

    }
}
