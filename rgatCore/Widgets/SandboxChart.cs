using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using GraphShape.Algorithms.Layout;
using ImGuiNET;
/*
using Microsoft.Msagl;
using Microsoft.Msagl.Core;
using Microsoft.Msagl.Core.Geometry;
using Microsoft.Msagl.Core.Geometry.Curves;
using Microsoft.Msagl.Core.Layout;
using Microsoft.Msagl.Layout.Incremental;
using Microsoft.Msagl.Layout.Initial;
using Microsoft.Msagl.Layout.MDS;
using Microsoft.Msagl.Miscellaneous;
using Microsoft.Msagl.Prototype.Ranking;
*/
using QuikGraph;

namespace rgatCore.Widgets
{
    class SandboxChart
    {

        struct itemNode
        {
            public string label;
        }
        QuikGraph.BidirectionalGraph<itemNode, Edge<itemNode>> sbgraph = new BidirectionalGraph<itemNode, Edge<itemNode>>();
        GraphShape.Algorithms.Layout.KKLayoutAlgorithm<itemNode, Edge<itemNode>, QuikGraph.BidirectionalGraph<itemNode, Edge<itemNode>>> layout;
        Vector2 chartSize;
        float padding = 15;
        double _scaleX = 1;

        public SandboxChart()
        {
            chartSize = ImGui.GetContentRegionAvail();

            itemNode n1 = new itemNode() { label = "Node1" };
            sbgraph.AddVertex(n1);
            sbgraph.AddVertex(new itemNode() { label = "Node2" });
            sbgraph.AddVertex(new itemNode() { label = "Node3" });

            sbgraph.AddEdge(new Edge<itemNode>(sbgraph.Vertices.ToList()[0], sbgraph.Vertices.ToList()[1]));
            sbgraph.AddEdge(new Edge<itemNode>(sbgraph.Vertices.ToList()[1], sbgraph.Vertices.ToList()[2]));

            KKLayoutParameters layoutParams = new KKLayoutParameters()
            {
                Height = chartSize.Y - (2 * padding),
                Width = chartSize.X - (2 * padding),
                LengthFactor = 1,
                DisconnectedMultiplier = 2
            };

            layout = new GraphShape.Algorithms.Layout.KKLayoutAlgorithm<itemNode, Edge<itemNode>, BidirectionalGraph<itemNode, Edge<itemNode>>>(sbgraph, parameters: layoutParams);

            layout.VerticesPositions[n1] = new GraphShape.Point(89, 177);

            layout.Compute();

        }

        Vector2 Point2Vec(GraphShape.Point point) => new Vector2((float)point.X, (float)point.Y);
        Vector2 chartOffset = Vector2.Zero;
        public void Draw()
        {
            Vector2 size = ImGui.GetContentRegionAvail();
            if (size != chartSize && chartSize.X > 50 && chartSize.Y > 50)
            {
                StopLayout();
                chartSize = size;
                layout.Parameters.Width = chartSize.X;
                layout.Parameters.Height = chartSize.Y;
                FitNodesToChart();
            }
            if (_fittingActive)
            {
                DoLayoutFittingCycle();
            }

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xffffffff);


            Vector2 pos = ImGui.GetCursorScreenPos() + chartOffset + new Vector2(padding, padding);
            if (ImGui.BeginChild("ChartFrame", chartSize))
            {
                if (ImGui.IsMouseHoveringRect(pos, pos + chartSize))
                {
                    HandleInput();
                }

                if (_fittingActive)
                {
                    ImGui.GetWindowDrawList().AddText(ImGui.GetCursorScreenPos() + new Vector2(chartSize.X/2 + 8, 20), 0xff000000, "Centering...");
                }

                var edges = sbgraph.Edges;

                var positions = new Dictionary<itemNode, GraphShape.Point>(layout.VerticesPositions);
                foreach (var edge in edges)
                {
                    if (positions.TryGetValue(edge.Source, out GraphShape.Point srcPoint) &&
                    positions.TryGetValue(edge.Target, out GraphShape.Point targPoint))
                    {
                        ImGui.GetWindowDrawList().AddLine(pos + Point2Vec(srcPoint), pos + Point2Vec(targPoint), 0xffff00ff);
                    }
                }

                foreach (var node in positions)
                {

                    Vector2 nCenter = pos + Point2Vec(node.Value);
                    DrawNode(node.Key, nCenter);

                }

                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
        }

        void DrawNode(itemNode node, Vector2 position)
        {
            var DrawList = ImGui.GetWindowDrawList();
            DrawList.AddCircleFilled(position, 8, 0xff0000ff);
            DrawList.AddRectFilled(position, position + new Vector2(20, 8), 0xddffffff);
            DrawList.AddText(position + new Vector2(2, -2), 0xff000000, (string)node.label);
        }


        void HandleInput()
        {
            Vector2 pos = ImGui.GetCursorScreenPos() + chartOffset;
            if (ImGui.IsMouseClicked(ImGuiMouseButton.Right))
            {

                StopLayout();
                Vector2 mousepos = ImGui.GetMousePos() - pos;
                Console.WriteLine($"Mouseclink: {mousepos.X},{mousepos.Y}");

                itemNode nn = new itemNode() { label = $"node{sbgraph.VertexCount}" };
                sbgraph.AddVertex(nn);
                Edge<itemNode> vedge = new Edge<itemNode>(nn, sbgraph.Vertices.ToList()[1]);
                sbgraph.AddEdge(vedge);


                Task.Run(() => { layout.Compute(); });
            }
            if (ImGui.IsMouseClicked(ImGuiMouseButton.Middle))
            {
                StopLayout();
                Vector2 mousepos = ImGui.GetMousePos() - pos;
                Console.WriteLine($"Mouseclink: {mousepos.X},{mousepos.Y}");

                itemNode nn = new itemNode() { label = $"node{sbgraph.VertexCount}" };
                sbgraph.AddVertex(nn);
                Edge<itemNode> vedge = new Edge<itemNode>(nn, sbgraph.Vertices.ToList()[4]);
                sbgraph.AddEdge(vedge);

                Task.Run(() => { layout.Compute(); });
            }



            if (ImGui.IsMouseDragging(ImGuiMouseButton.Left))
            {
                chartOffset += ImGui.GetMouseDragDelta() * 0.01f;
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
            double newScaleX = _scaleX + (delta / 25);

            if (newScaleX == _scaleX || newScaleX <= 0)
                return;

            Console.WriteLine($"Changing scale from {_scaleX} to {newScaleX}");
            _scaleX += (delta / 25);


            StopLayout();
            layout.Parameters.LengthFactor = _scaleX;
            layout.Compute();

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
            double rightDifference = layout.Parameters.Width - (Xright + padding*2);
            double topDifference = yTop;
            double baseDifference = layout.Parameters.Height - (yBase + padding*2);

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
            else if (minvalue < 5)
            {
                //zoom out by shrinking edges
                _scaleX = _scaleX - ((Math.Abs(zoomSizeRatio) > 0.1) ? 0.2 : 0.02);
                layout.Parameters.LengthFactor = _scaleX;
                layout.Compute();
            }
            else if (minvalue > 15)
            { 
                //zoom in by growing edges
                _scaleX = _scaleX + ((Math.Abs(zoomSizeRatio) > 0.1) ? 0.1 : 0.01);
                layout.Parameters.LengthFactor = _scaleX;
                layout.Compute();
            }
            else
            {
                _fittingActive = false;
                return;
            }

            fittingAttempts += 1;
            if (fittingAttempts > 50)
            {
                _fittingActive = false;
                Logging.RecordLogEvent($"Ending chart zoom to frame after {fittingAttempts} cycles. XDifference: {Xleft}, YDifference: {yTop}", Logging.LogFilterType.TextDebug);
            }
        }

        bool LayoutRunning => layout.State == QuikGraph.Algorithms.ComputationState.Running ||
                layout.State == QuikGraph.Algorithms.ComputationState.PendingAbortion;


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
