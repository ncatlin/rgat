using GraphShape.Algorithms.Layout;
using ImGuiNET;
using QuikGraph;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace rgatCore.Widgets
{
    class SandboxChart
    {
        public class ItemNode
        {
            public ItemNode(string caption, Logging.eTimelineEvent eventType, object item)
            {
                label = caption;
                TLtype = eventType;
                reference = item;
            }
            public string label;
            public Logging.eTimelineEvent TLtype;
            public object reference;
        }
        //todo lock access to this
        QuikGraph.BidirectionalGraph<ItemNode, Edge<ItemNode>> sbgraph = new BidirectionalGraph<ItemNode, Edge<ItemNode>>();
        GraphShape.Algorithms.Layout.KKLayoutAlgorithm<ItemNode, Edge<ItemNode>, QuikGraph.BidirectionalGraph<ItemNode, Edge<ItemNode>>> layout;
        Vector2 chartSize;
        float padding = 15;
        double _scaleX = 1;

        float nodeSize = 8;

        public SandboxChart()
        {
            chartSize = ImGui.GetContentRegionAvail();

            KKLayoutParameters layoutParams = new KKLayoutParameters()
            {
                Height = chartSize.Y - (2 * padding),
                Width = chartSize.X - (2 * padding),
                LengthFactor = 1,
                DisconnectedMultiplier = 2,
                ExchangeVertices = true
            };

            layout = new GraphShape.Algorithms.Layout.KKLayoutAlgorithm<ItemNode, Edge<ItemNode>, BidirectionalGraph<ItemNode, Edge<ItemNode>>>(sbgraph, parameters: layoutParams);
            layout.Compute();
        }

        TraceRecord _rootTrace = null;
        int timelineItemsOnChartDraw = 0;
        public void InitChartFromTrace(TraceRecord trace)
        {
            if (trace != _rootTrace)
            {
                sbgraph.Clear();
                layout.VerticesPositions.Clear();
                _rootTrace = trace;
                addedNodes.Clear();
            }

            if (trace.TimelineItemsCount != timelineItemsOnChartDraw)
            {

                Logging.TIMELINE_EVENT[] entries = trace.GetTimeLineEntries();
                timelineItemsOnChartDraw = entries.Length;
                StopLayout();
                AddThreadItems(null, trace);

                KKLayoutParameters layoutParams = new KKLayoutParameters()
                {
                    Height = chartSize.Y - (2 * padding),
                    Width = chartSize.X - (2 * padding),
                    LengthFactor = 1,
                    DisconnectedMultiplier = 2,
                    ExchangeVertices = true
                };
                //layout = new GraphShape.Algorithms.Layout.KKLayoutAlgorithm<itemNode, Edge<itemNode>, BidirectionalGraph<itemNode, Edge<itemNode>>>(sbgraph, parameters: layoutParams);

                Task.Run(() => { layout.Compute(); }); //todo - still a thread safety issue here if its open
            }
        }

        Dictionary<string, ItemNode> addedNodes = new Dictionary<string, ItemNode>();

        void AddThreadItems(ItemNode parentProcess, TraceRecord trace)
        {

            string nodeName = $"PID_{trace.PID}_PATH...";
            ItemNode startProcess = null;
            if (!addedNodes.TryGetValue(nodeName, out startProcess))
            {
                startProcess = new ItemNode(nodeName, Logging.eTimelineEvent.ProcessStart, trace);
                sbgraph.AddVertex(startProcess);
                addedNodes[nodeName] = startProcess;
                if (parentProcess != null)
                {
                    sbgraph.AddEdge(new Edge<ItemNode>(parentProcess, startProcess));
                }
            }


            var threads = trace.GetProtoGraphs();
            foreach (var thread in threads)
            {
                string threadName = $"TID_{thread.ThreadID}_StartModule...";
                if (!addedNodes.ContainsKey(threadName))
                {
                    ItemNode threadNode = new ItemNode(threadName, Logging.eTimelineEvent.ThreadStart, thread);
                    sbgraph.AddVertex(threadNode);
                    sbgraph.AddEdge(new Edge<ItemNode>(startProcess, threadNode));
                    addedNodes[threadName] = threadNode;
                }
            }
            foreach (var child in trace.GetChildren())
            {
                AddThreadItems(startProcess, child);
            }

        }

        public ItemNode GetSelectedNode => _selectedNode;

        Vector2 Point2Vec(GraphShape.Point point) => new Vector2((float)point.X, (float)point.Y);
        Vector2 chartOffset = Vector2.Zero;
        public void Draw()
        {
            Vector2 availArea = ImGui.GetContentRegionAvail();
            Vector2 targetSize = availArea - new Vector2(0, 6);
            if (targetSize != chartSize && targetSize.X > 50 && targetSize.Y > 50)
            {
                StopLayout();
                chartSize = targetSize;
                layout.Parameters.Width = targetSize.X;
                layout.Parameters.Height = targetSize.Y;
                FitNodesToChart();
            }
            if (_fittingActive)
            {
                DoLayoutFittingCycle();
            }

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xffffffff);


            Vector2 cursorPos = ImGui.GetCursorScreenPos();
            Vector2 chartPos = cursorPos + chartOffset + new Vector2(padding, padding);
            if (ImGui.BeginChild("ChartFrame", chartSize, false, ImGuiWindowFlags.NoScrollbar))
            {
                MouseOverWidget = ImGui.IsMouseHoveringRect(cursorPos, cursorPos + chartSize);
                if (MouseOverWidget)
                {
                    HandleMouseInput();
                }

                var edges = sbgraph.Edges;

                var positions = new Dictionary<ItemNode, GraphShape.Point>(layout.VerticesPositions);
                foreach (var edge in edges)
                {
                    if (positions.TryGetValue(edge.Source, out GraphShape.Point srcPoint) &&
                    positions.TryGetValue(edge.Target, out GraphShape.Point targPoint))
                    {
                        ImGui.GetWindowDrawList().AddLine(chartPos + Point2Vec(srcPoint), chartPos + Point2Vec(targPoint), 0xffff00ff);
                    }
                }


                foreach (var node in positions)
                {
                    Vector2 nCenter = chartPos + Point2Vec(node.Value);
                    DrawNode(node.Key, nCenter);
                }


                ImGui.SetCursorScreenPos(cursorPos + chartSize - new Vector2(30, 30));

                if (!_fittingActive)
                {
                    if (ImGui.Button("[C]"))
                    {
                        FitNodesToChart();
                    }
                    SmallWidgets.MouseoverText("Center graph");
                }
                ImGui.SetCursorScreenPos(cursorPos);
                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
        }


        ItemNode _selectedNode = null;
        void DrawNode(ItemNode node, Vector2 position)
        {
            Vector2 cursor = ImGui.GetCursorScreenPos();
            if (!InFrame(position - cursor)) return;

            var DrawList = ImGui.GetWindowDrawList();

            switch (node.TLtype)
            {
                case Logging.eTimelineEvent.ProcessStart:
                case Logging.eTimelineEvent.ProcessEnd:
                    {
                        TraceRecord rec = (TraceRecord)node.reference;
                        if (rec.TraceState == TraceRecord.eTraceState.eTerminated)
                        {
                            DrawList.AddCircleFilled(position, nodeSize, 0xff0000ff);
                        }
                        else if (rec.TraceState == TraceRecord.eTraceState.eRunning)
                        {
                            DrawList.AddCircleFilled(position, nodeSize, 0xff00ff00);
                        }
                        else if (rec.TraceState == TraceRecord.eTraceState.eSuspended)
                        {
                            DrawList.AddCircleFilled(position, nodeSize, 0xff00ffff);
                        }
                        else
                        {
                            Debug.Assert(false, "Bad trace state");
                        }
                    }
                    break;
                case Logging.eTimelineEvent.ThreadStart:
                case Logging.eTimelineEvent.ThreadEnd:
                    {
                        ProtoGraph graph = (ProtoGraph)node.reference;
                        if (graph.Terminated)
                        {
                            DrawList.AddCircleFilled(position, nodeSize, 0xff0000ff);
                        }
                        else
                        {
                            DrawList.AddCircleFilled(position, nodeSize, 0xff00ff00);
                        }
                    }
                    break;
                default:
                    DrawList.AddCircleFilled(position, nodeSize, 0xff000000);
                    break;

            }


            if (node == _selectedNode)
            {
                DrawList.AddCircle(position, 12, 0xff000000);
            }
            ImGui.SetCursorScreenPos(position - new Vector2(12, 12));
            ImGui.InvisibleButton($"##{position.X}-{position.Y}", new Vector2(25, 25));
            if (ImGui.IsItemClicked())
            {
                _selectedNode = node;
            }

            DrawList.AddRectFilled(position, position + new Vector2(20, 8), 0xddffffff);
            DrawList.AddText(position + new Vector2(2, -2), 0xff000000, (string)node.label);
            ImGui.SetCursorScreenPos(cursor);
        }


        bool InFrame(Vector2 ScreenPosition)
        {
            return (ScreenPosition.X > 5 &&
                ScreenPosition.X < (chartSize.X + nodeSize) &&
                ScreenPosition.Y > 5 &&
                ScreenPosition.Y < (chartSize.Y + nodeSize));
        }


        public void SelectEventNode(Logging.TIMELINE_EVENT evt)
        {
            if (_rootTrace == null) return;

            switch (evt.TimelineEventType)
            {
                case Logging.eTimelineEvent.ProcessStart:
                case Logging.eTimelineEvent.ProcessEnd:
                    TraceRecord trace = _rootTrace.GetTraceByID(evt.ID);
                    if (trace == null) return;
                    foreach (var node in sbgraph.Vertices)
                    {
                        if (node.reference == trace)
                        {
                            _selectedNode = node;
                        }
                    }
                    break;
                case Logging.eTimelineEvent.ThreadStart:
                case Logging.eTimelineEvent.ThreadEnd:
                    ProtoGraph graph = _rootTrace.GetProtoGraphByID(evt.ID);
                    if (graph == null) return;
                    foreach (var node in sbgraph.Vertices)
                    {
                        if (node.reference == graph)
                        {
                            _selectedNode = node;
                        }
                    }
                    break;

                case Logging.eTimelineEvent.APICall:

                    //_selectedNode = node;
                    Console.WriteLine($"Api selection not supported yet");// {node.reference}");
                    break;
            }
        }


        void HandleMouseInput()
        {
            /*
            Vector2 pos = ImGui.GetCursorScreenPos() + chartOffset;
            if (ImGui.IsMouseClicked(ImGuiMouseButton.Right))
            {

            }
            */
            if (ImGui.IsMouseClicked(ImGuiMouseButton.Middle))
            {
                if (_rootTrace != null)
                {
                    InitChartFromTrace(_rootTrace);//, force: true);
                }
            }
        }


        void StopLayout()
        {
            if (layout.State == QuikGraph.Algorithms.ComputationState.Running)
            {
                layout.Abort();
            }
            while (LayoutRunning)
            {
                System.Threading.Thread.Sleep(5);
            }
        }

        public void ApplyZoom(float delta)
        {
            if (!MouseOverWidget) return;
            double newScaleX = _scaleX + (delta / 25);

            if (newScaleX != _scaleX && newScaleX > 0)
            {
                _scaleX += (delta / 25);

                StopLayout();
                layout.Parameters.LengthFactor = _scaleX;
                Task.Run(() => { layout.Compute(); });
            }
        }

        bool _fittingActive = false;
        int fittingAttempts = 0;
        public void FitNodesToChart()
        {
            fittingAttempts = 0;
            if (!_fittingActive) _fittingActive = true;
        }


        void DoLayoutFittingCycle()
        {

            if (LayoutRunning || !_fittingActive) return;

            var positions = layout.VerticesPositions;
            if (positions.Count == 0 || layout.Parameters.Width == 0 || layout.Parameters.Height == 0) return;

            //find the most extreme node positions, relative to the edges
            Vector2 firstNodePos = Point2Vec(positions[sbgraph.Vertices.First()]) + chartOffset;
            double Xleft = firstNodePos.X, Xright = Xleft, yTop = firstNodePos.Y, yBase = yTop;
            foreach (var node in positions)
            {
                Vector2 nCenter = Point2Vec(node.Value) + chartOffset;
                if (nCenter.X < Xleft) Xleft = nCenter.X;
                if (nCenter.X > Xright) Xright = nCenter.X;
                if (nCenter.Y < yTop) yTop = nCenter.Y;
                if (nCenter.Y > yBase) yBase = nCenter.Y;
            }

            //find how far we need to move them to fit - ideal is to make these all zero
            double leftDifference = Xleft;
            double rightDifference = layout.Parameters.Width - (Xright + padding * 2);
            double topDifference = yTop;
            double baseDifference = layout.Parameters.Height - (yBase + padding * 2);

            //first center the chart
            double XAdder = (rightDifference - leftDifference) / 2;
            double YAdder = (baseDifference - topDifference) / 2;

            chartOffset = chartOffset + new Vector2((float)XAdder, (float)YAdder);

            Xleft += XAdder;
            yTop += YAdder;

            //now zoom to fit
            leftDifference = Xleft;
            topDifference = yTop;

            double minvalue = Math.Min(leftDifference, topDifference);
            double zoomSizeRatio = minvalue / ((leftDifference < topDifference) ? layout.Parameters.Width : layout.Parameters.Height);

            if (Math.Abs(zoomSizeRatio) > 1)
            {
                //zoom/pan is way off, reset to sensible scale
                _scaleX = 1;
                layout.Parameters.LengthFactor = _scaleX;
                layout.Compute();
            }
            else if (minvalue < 50)
            {
                //zoom out by shrinking edges
                _scaleX = _scaleX - ((Math.Abs(zoomSizeRatio) > 0.1) ? 0.2 : 0.02);
                if (_scaleX < 0)
                    _scaleX = 0.01;
                layout.Parameters.LengthFactor = _scaleX;
                layout.Compute();
            }
            else if (minvalue > 75)
            {
                //zoom in by growing edges
                _scaleX = _scaleX + ((Math.Abs(zoomSizeRatio) > 0.1) ? 0.1 : 0.01);
                layout.Parameters.LengthFactor = _scaleX;
                layout.Compute();
            }
            else
            {
                _fittingActive = false;
            }

            if (_fittingActive)
            {
                fittingAttempts += 1;
                if (fittingAttempts > 50)
                {
                    _fittingActive = false;
                    Logging.RecordLogEvent($"Ending chart zoom to frame after {fittingAttempts} cycles. XDifference: {Xleft}, YDifference: {yTop}", Logging.LogFilterType.TextDebug);
                }
            }
        }

        bool LayoutRunning => layout.State == QuikGraph.Algorithms.ComputationState.Running ||
                layout.State == QuikGraph.Algorithms.ComputationState.PendingAbortion;

        bool MouseOverWidget = false;
        public void ApplyMouseDrag(Vector2 delta)
        {
            if (MouseOverWidget)
                chartOffset -= delta;
        }


        public void AlertKeybindPressed(Tuple<Veldrid.Key, Veldrid.ModifierKeys> keyPressed, eKeybind boundAction)
        {

            float shiftModifier = ImGui.GetIO().KeyShift ? 1 : 0;
            switch (boundAction)
            {
                case eKeybind.CenterFrame:
                    //ResetLayout();
                    FitNodesToChart();
                    break;
                default:
                    break;
            }
        }


    }
}
