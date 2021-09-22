using System.Collections.Generic;
using System.Threading;

namespace rgat.Threads
{
    /// <summary>
    /// A worker for rendering the preview graphs of all threads in a trace record
    /// </summary>
    public class PreviewRendererThread : TraceProcessorWorker
    {
        readonly TraceRecord RenderedTrace;

        /// <summary>
        /// Set by the GUI loading thread when the widget has been created
        /// </summary>
        /// <param name="widget"></param>
        public static void SetPreviewWidget(PreviewGraphsWidget widget) => _graphWidget = widget;

        static PreviewGraphsWidget? _graphWidget;

        /// <summary>
        /// Create a preview renderer
        /// </summary>
        /// <param name="_renderedTrace">The trace with graphs to be rendered</param>
        public PreviewRendererThread(TraceRecord _renderedTrace)
        {
            RenderedTrace = _renderedTrace;
        }

        /// <summary>
        /// Start this worker
        /// </summary>
        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc);
            WorkerThread.Name = $"PreviewWrk_{RenderedTrace.PID}_{RenderedTrace.Target.TracesCount}";
            WorkerThread.Start();
        }

        /// <summary>
        /// The worker thread entry point
        /// </summary>
        public void ThreadProc()
        {
            Logging.RecordLogEvent($"PreviewRenderThread ThreadProc START", Logging.LogFilterType.BulkDebugLogFile);

            Veldrid.CommandList cl = _clientState._GraphicsDevice.ResourceFactory.CreateCommandList();
            List<PlottedGraph> graphlist;
            int StopTimer = -1;
            bool moreRenderingNeeded;

            while (!rgatState.rgatIsExiting && _graphWidget == null)
            {
                Thread.Sleep(50);
            }

            while (!rgatState.rgatIsExiting)
            {
                //only write we are protecting against happens while creating new threads
                //so not important to release this quickly
                graphlist = RenderedTrace.GetPlottedGraphs();

                moreRenderingNeeded = false;
                foreach (PlottedGraph graph in graphlist)
                {
                    if (graph == null) continue;

                    if (graph != _clientState.ActiveGraph)
                    {
                        //check for trace data that hasn't been rendered yet
                        ProtoGraph protoGraph = graph.InternalProtoGraph;

                        //Console.WriteLine($"Rendering new preview verts for thread {graph.tid}");
                        graph.RenderGraph();
                        if (!graph.RenderingComplete)
                            moreRenderingNeeded = true;
                    }

                    if (graph.DrawnEdgesCount > 0)
                    {
                        _graphWidget!.GeneratePreviewGraph(cl, graph);
                    }

                    if (rgatState.rgatIsExiting) break;
                    Thread.Sleep((int)GlobalConfig.Preview_PerThreadLoopSleepMS); //sleep removed for debug
                }

                graphlist.Clear();

                int waitForNextIt = 0;
                while (waitForNextIt < GlobalConfig.Preview_PerProcessLoopSleepMS && !rgatState.rgatIsExiting)
                {
                    Thread.Sleep(5); //sleep removed for debug
                    waitForNextIt += 5;
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
