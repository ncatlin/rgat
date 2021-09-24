using System;
using System.Collections.Generic;
using System.Threading;

namespace rgat.Threads
{
    /// <summary>
    /// A worker for rendering the preview graphs of all threads in a trace record
    /// </summary>
    public class PreviewRendererThread : TraceProcessorWorker
    {
        private readonly PreviewGraphsWidget _graphWidget;

        private readonly static Queue<PlottedGraph> renderQueue = new Queue<PlottedGraph>();
        private readonly static Queue<PlottedGraph> priorityQueue = new Queue<PlottedGraph>();

        private readonly static object _lock = new();
        private readonly static ManualResetEventSlim _waitEvent = new();
        private readonly int _idNum;
        private readonly bool _background;


        /// <summary>
        /// Fetch the next graph to render
        /// It will first fetch priority graphs (ie: those in the active trace) 
        /// unless the background flag is set
        /// </summary>
        /// <param name="graph"></param>
        public static void AddGraphToPreviewRenderQueue(PlottedGraph graph)
        {
            lock (_lock)
            {
                if (graph.InternalProtoGraph.TraceData == _clientState!.ActiveTrace)
                {
                    priorityQueue.Enqueue(graph);
                }
                else
                {
                    renderQueue.Enqueue(graph);
                }

                if (_waitEvent.IsSet is false)
                    _waitEvent.Set();
            }
        }

        /// <summary>
        /// Fetch the next graph to render
        /// </summary>
        /// <returns></returns>
        public static PlottedGraph? FetchRenderTask(bool background)
        {
            try
            {
                lock (_lock)
                {
                    if (background is false)
                    {
                        if (priorityQueue.Count > 0)
                            return priorityQueue.Dequeue();
                    }

                    if (renderQueue.Count > 0)
                    {
                        return renderQueue.Dequeue();
                    }

                    if (background is true)
                    {
                        if (priorityQueue.Count > 0)
                            return priorityQueue.Dequeue();
                    }
                }
                _waitEvent.Wait(rgatState.ExitToken);

                lock (_lock)
                {
                    if (_waitEvent.IsSet)
                        _waitEvent.Reset();
                }
            }
            catch (Exception e)
            {
                if (rgatState.rgatIsExiting is false)
                    Logging.RecordError($"Preview renderer encountered error fetching new task: {e.Message}");
            }
            return null;
        }


        /// <summary>
        /// Create a preview renderer
        /// </summary>
        public PreviewRendererThread(int workerID, PreviewGraphsWidget widget, bool background)
        {
            _idNum = workerID;
            _graphWidget = widget;
            _background = background;
        }

        /// <summary>
        /// Start this worker
        /// </summary>
        public override void Begin()
        {
            base.Begin();
            WorkerThread = new Thread(ThreadProc);
            WorkerThread.Name = $"PreviewWrk_{_idNum}_{(_background ? "BG" : "FG")}";
            WorkerThread.Start();
        }

        bool _stopFlag = false;

        /// <summary>
        /// Exit. This is a placeholder for if/when worker counts 
        /// are changed at runtime
        /// </summary>
        public void Stop()
        {
            lock (_lock)
            {
                _stopFlag = true;
                if (_waitEvent.IsSet is false)
                    _waitEvent.Set();
            }
        }

        /// <summary>
        /// The worker thread entry point
        /// </summary>
        public void ThreadProc()
        {
            Logging.RecordLogEvent($"PreviewRenderThread ThreadProc START", Logging.LogFilterType.BulkDebugLogFile);

            Veldrid.CommandList cl = _clientState!._GraphicsDevice!.ResourceFactory.CreateCommandList();

            while (!rgatState.rgatIsExiting && _graphWidget == null)
            {
                Thread.Sleep(50);
            }

            while (!rgatState.rgatIsExiting && _stopFlag is false)
            {
                PlottedGraph? graph = FetchRenderTask(_background);
                if (graph is null) continue;


                if (graph != _clientState.ActiveGraph)
                {
                    graph.RenderGraph();
                }

                if (graph.DrawnEdgesCount > 0)
                {
                    _graphWidget!.GeneratePreviewGraph(cl, graph);
                }

                AddGraphToPreviewRenderQueue(graph);
            }
            Finished();
        }

    }
}
