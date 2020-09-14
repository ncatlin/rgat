using GraphShape;
using GraphShape.Algorithms.Layout;
using QuikGraph;
using rgatCore.Threads;
using SharpDX.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;

namespace rgatCore.Plots
{
    class ForceDirected3DGraph : PlottedGraph
    {
        HierarchicalGraph<NodeData, TypedEdge<NodeData>> _GraphShapeGraph;

        public ForceDirected3DGraph(ProtoGraph baseProtoGraph, List<WritableRgbaFloat> colourslist) : base(baseProtoGraph, colourslist)
        {
            layout = graphLayouts.eForceDirected3D;
            graphColours = colourslist;
            if (graphColours.Count == 0)
            {
                Console.WriteLine("Warning: bad colour array. Assigning default");
                graphColours = GlobalConfig.defaultGraphColours;
            }

            //var nodes = new
            _GraphShapeGraph = new GraphShape.HierarchicalGraph<NodeData, TypedEdge<NodeData>>();


        }


        public override void draw_highlight_lines()
        {
        }


        Vector3 NodeScreenPosition(Vector3 absPos, GRAPH_SCALE dimensions, GraphicsMaths.SCREENINFO scrn)
        {
            Vector3 result = new Vector3(absPos.X, absPos.Y, 0);
            Vector3 pos2 = GraphicsMaths.Project(result, projection, view, Matrix4x4.Multiply(Matrix4x4.Identity, rotation), scrn);

            //pos2.Z = (pos2.Z - scrn.CamZoom) - dimensions.plotSize;
            //pos2.Z -= dimensions.plotSize;


            pos2.Z += scrn.CamZoom;


            return pos2;
        }


        public override List<TEXTITEM> GetOnScreenTexts(GraphicsMaths.SCREENINFO scrn)
        {
            texts.Clear();

            //return texts;

            const int hackyBCoordLeeway = 5; //screen => b coord conversion is inexact
            float highestY = scrn.Y;
            float lowestY = scrn.Y - scrn.Height;



            List<NodeData> nodes;
            lock (internalProtoGraph.nodeLock)
            {
                nodes = internalProtoGraph.NodeList.ToList<NodeData>();
            }

            /*
            performance todo - want to update position of displayed texts every frame but 
            choosing which nodes to display can be an irregular action
            */
            float ZMidPoint = scrn.CamZoom + (scalefactors.plotSize / 2);

            List<Tuple<NodeData, Vector3>> visibleNodes = new List<Tuple<NodeData, Vector3>>();
            foreach (NodeData node in nodes)
            {
                if (node.index >= NodesDisplayData.NodeCount) break;

                NodesDisplayData.get_node_coord((int)node.index, out Vector3 abspos);
                if (abspos.Y <= highestY)
                {
                    Vector3 pos = NodeScreenPosition(abspos, scalefactors, scrn);
                    if ((pos.X - scrn.X) > scrn.Width || (pos.X - scrn.X) < 0) continue;
                    if ((pos.Y - scrn.Y) > scrn.Height || (pos.Y - scrn.Y) < 0) continue;
                    //if (pos.Z > ZMidPoint) continue; //don't show text further back than half way around the cylinder

                    if (!node.IsExternal && pos.Z > GlobalConfig.FurthestInstructionText) continue;
                    if (node.IsExternal && pos.Z > GlobalConfig.FurthestSymbol) continue;

                    visibleNodes.Add(new Tuple<NodeData, Vector3>(node, pos));
                }
            }

            //if lots of nodes, get the ones nearest to the middle of the graph widget
            if (visibleNodes.Count > GlobalConfig.OnScreenNodeTextCountLimit)
            {
                Vector2 screenMiddle = new Vector2(scrn.Width / 2, scrn.Height / 2);
                visibleNodes = visibleNodes.OrderBy(n1 => Vector2.Distance(new Vector2(n1.Item2.X, n1.Item2.Y), screenMiddle))
                                           .Take(GlobalConfig.OnScreenNodeTextCountLimit)
                                           .ToList();
            }

            foreach (var node_pos in visibleNodes)
            {
                NodeData node = node_pos.Item1;
                Vector3 pos = node_pos.Item2;

                TEXTITEM itm;
                if (pos.Z < 500) itm.fontSize = 20;
                else if (pos.Z < 800) itm.fontSize = 19;
                else if (pos.Z < 1100) itm.fontSize = 18;
                else if (pos.Z < 1400) itm.fontSize = 17;
                else if (pos.Z < 1700) itm.fontSize = 16;
                else itm.fontSize = 15;

                if (node.IsExternal)
                {
                    if (node.label != null)
                        itm.contents = node.label;
                    else
                        itm.contents = "[NULL]";
                    itm.color = Color.SpringGreen;
                }
                else
                {
                    float dist = Vector2.Distance(new Vector2(pos.X, pos.Y), new Vector2(scrn.Width / 2, scrn.Height / 2));

                    Vector3 nodecoord;
                    NodesDisplayData.get_node_coord((int)node.index, out nodecoord);
                    //itm.contents = $"N<{node.index}>  X:{cylcoord.a} Y:{cylcoord.b}";
                    //itm.contents = $"N<{node.index}>  X:{pos.X} Y:{pos.Y} z:{pos.Z} Dist:{dist}";
                    itm.contents = $"{node.index} 0x{node.address:X}: {node.ins.ins_text}";
                    if (node.ins.BlockBoundary)
                    {
                        itm.contents += " <BBTOP>";
                        itm.color = Color.Blue;
                    }
                    else
                    {
                        itm.color = Color.White;
                    }
                }


                itm.screenXY.X = pos.X;
                itm.screenXY.Y = pos.Y;

                texts.Add(itm);
                if (texts.Count > GlobalConfig.OnScreenNodeTextCountLimit) break;
            }
            //Console.WriteLine(texts.Count);


            return texts;

        }


        public override void initialiseCustomDimensions(GRAPH_SCALE scale)
        {
        }

        public override void InitialiseDefaultDimensions()
        {
            wireframeSupported = false;
            wireframeActive = false;

            scalefactors.plotSize = 300;
            scalefactors.basePlotSize = 300f;
            scalefactors.userSizeModifier = 1;
            CameraClippingFar = 4000f;
            CameraZoom = 2000f;
            CameraXOffset = 0;
            CameraYOffset = -100;
            PlotRotation = 0f;
        }

        public override void InitialisePreviewDimensions()
        {
        }



        void positionVert(NodeData n, out Vector3 newPosition)
        {
            GraphDisplayData.PLOT_TRACK lastNode = NodesDisplayData.LastRenderedNode;
            if (!NodesDisplayData.get_node_coord<Vector3>((int)lastNode.lastVertID, out Vector3 oldPosition))
            {
                Console.WriteLine("[rgat]Warning: Positionvert() Waiting for node " + lastNode.lastVertID);
                int waitPeriod = 5;
                int iterations = 1;
                bool found = false;
                do
                {
                    if (waitPeriod > 1000)
                    {
                        Console.WriteLine($"Warning! Very long wait for vert ID {lastNode.lastVertID}, something has gone wrong");
                        Debug.Assert(waitPeriod < 5000);
                    }
                    System.Threading.Thread.Sleep(waitPeriod);
                    waitPeriod += (150 * iterations++);
                    found = NodesDisplayData.get_node_coord<Vector3>((int)lastNode.lastVertID, out oldPosition);

                } while (!found);
            }

            newPosition.X = oldPosition.X;
            newPosition.Y = oldPosition.Y - 50;
            newPosition.Z = 0;// oldPosition.Z - 200;

            while (NodesDisplayData.usedCoords.ContainsKey(new Tuple<float, float>(newPosition.X, newPosition.Y)))
            {
                newPosition.X += 5;
                newPosition.Y += 5;
                newPosition.Z -= 50;
            }
        }


        public override void render_node(NodeData n)
        {
            Vector3 coord;
            if (n.index >= NodesDisplayData.NodeCount)
            {
                //Console.WriteLine($"Node {n.index} {n.ins.ins_text} not plotted yet, plotting");
                if (NodesDisplayData.NodeCount == 0)
                {
                    Debug.Assert(n.index == 0);
                    Vector3 tempPos;
                    tempPos.X = 0; tempPos.Y = 0; tempPos.Z = 0;
                    coord = tempPos;


                    lock (internalProtoGraph.nodeLock)
                    {
                        NodesDisplayData.add_node_coord(tempPos);
                    }
                }
                else
                {
                    positionVert(n, out Vector3 newPos);
                    coord = newPos;
                    NodesDisplayData.add_node_coord(newPos);
                    Console.WriteLine($"Thread {internalProtoGraph.ThreadID} added vert {n.index}");
                    Debug.Assert(NodesDisplayData.NodeCount == n.index + 1);

                }

                updateStats(coord.X, coord.Y, coord.Z);
                NodesDisplayData.usedCoords.Add(new Tuple<float, float>(coord.X, coord.Y), true);

                if (!n.IsExternal)
                {
                    if (n.ins.hasSymbol && n.label == null)
                    {
                        ulong nodeoffset = n.address - internalProtoGraph.moduleBase;
                        n.label = $"[InternalFunc_{internalProtoGraph.InternalPlaceholderFuncNames.Count + 1}]";
                        n.placeholder = true;


                        internalProtoGraph.InternalPlaceholderFuncNames[nodeoffset] = n.index;

                    }
                }
                else
                {
                    if (internalProtoGraph.ProcessData.GetSymbol(n.GlobalModuleID, n.address, out string symbol))
                    {
                        n.label = symbol;
                    }
                    else
                    {
                        string module = internalProtoGraph.ProcessData.LoadedModulePaths[n.GlobalModuleID];

                        n.label = $"{module}: 0x{n.address}";
                    }
                }

            }
            else
            {
                NodesDisplayData.get_node_coord<Vector3>((int)n.index, out coord);
                Console.WriteLine($"Node {n.index} already plotted, retrieved to coord {coord.X} {coord.Y}");
            }


            //cylinderCoord(coord, out Vector3 screenc, scalefactors);

            WritableRgbaFloat active_col;
            if (n.IsExternal)
                NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeExternal;
            else
            {
                switch (n.ins.itype)
                {
                    case eNodeType.eInsUndefined:
                        //if (n.IsConditional()) Console.WriteLine($"render_node jump because n {n.index} is conditional undef");
                        NodesDisplayData.LastRenderedNode.lastVertType = n.IsConditional() ?
                            eEdgeNodeType.eNodeJump :
                            eEdgeNodeType.eNodeNonFlow;
                        break;

                    case eNodeType.eInsJump:
                        //Console.WriteLine($"render_node jump because n {n.index} is jump");

                        NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeJump;
                        break;

                    case eNodeType.eInsReturn:
                        NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeReturn;
                        break;

                    case eNodeType.eInsCall:
                        {
                            NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeCall;
                            //if code arrives to next instruction after a return then arrange as a function
                            ulong nextAddress = n.ins.address + (ulong)n.ins.numbytes;
                            Add_to_callstack(nextAddress, NodesDisplayData.LastRenderedNode.lastVertID);
                            break;
                        }
                    default:
                        Console.WriteLine("[rgat]Error: render_node unknown itype " + n.ins.itype);
                        Debug.Assert(false);
                        break;
                }
            }

            active_col = graphColours[(int)NodesDisplayData.LastRenderedNode.lastVertType];
            NodesDisplayData.LastRenderedNode.lastVertID = n.index;
            //Console.WriteLine($"Thread {internalProtoGraph.ThreadID} setting last vert to {n.index}");

            WritableRgbaFloat nodeColor = new WritableRgbaFloat()
            { A = 255f, G = active_col.G, B = active_col.B, R = active_col.R };

            VertexPositionColor colorEntry = new VertexPositionColor(coord, nodeColor, GlobalConfig.AnimatedFadeMinimumAlpha);

            NodesDisplayData.safe_add_vert(colorEntry);

        }

        protected override void PlotRerender()
        {
            _GraphShapeGraph.Clear();
        }

        public override void render_graph()
        {
            render_new_blocks();



            Dictionary<NodeData, GraphShape.Size> vertSzies = new Dictionary<NodeData, GraphShape.Size>();
            Dictionary<NodeData, Thickness> vertBordThicks = new Dictionary<NodeData, Thickness>();
            Dictionary<NodeData, CompoundVertexInnerLayoutType> cvilt = new Dictionary<NodeData, CompoundVertexInnerLayoutType>();
            Dictionary<NodeData, GraphShape.Point> positions = new Dictionary<NodeData, GraphShape.Point>();
            int szd = 1000;

            Random rnd = new Random(DateTime.Now.Millisecond);
            foreach (NodeData n in _GraphShapeGraph.Vertices)
            {
                if (!_GraphShapeGraph.ContainsVertex(n)) continue;

                GraphShape.Size sz = new GraphShape.Size(20, 80);
                vertSzies.Add(n, sz);
                vertBordThicks.Add(n, new Thickness(1, 1, 1, 1));
                cvilt.Add(n, CompoundVertexInnerLayoutType.Fixed);
                NodesDisplayData.get_node_coord((int)n.index, out Vector3 npos);
                positions.Add(n, new GraphShape.Point(Math.Max(double.Epsilon, rnd.NextDouble() * szd), Math.Max(double.Epsilon, rnd.NextDouble() * szd)));
                szd += 1000;
            
        }

            

            Stopwatch st = new Stopwatch(); st.Start();



            /*
            
            
            
            Algorithms ruled out as unusable for being slow


             */
            // LINLOG
            //not fast, too messy on larger
            //var algo = new GraphShape.Algorithms.Layout.LinLogLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph);


            //horrendous slow mess
            
            KKLayoutParameters parmsk = new KKLayoutParameters();
            parmsk.Width = 18000;
            parmsk.ExchangeVertices = true;
            parmsk.Height = 18000;
            //var algo = new GraphShape.Algorithms.Layout.KKLayoutAlgorithm<NodeData, TypedEdge<NodeData>,
            //BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph, parmsk);
            


            //CompoundFDP
            //pretty but random stuff, doubtful it is useful
            //glacially slow?
            //var algo = new GraphShape.Algorithms.Layout.CompoundFDPLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph, vertSzies, vertBordThicks, cvilt)            //useless mess with 1382 verts 



            /*
             * 
             * 
             * Algorithms which are either too messy or unevaluated due to the NaN problem
             * These might be fixable and useabled
            *
            *
            *
            *
            */

            //very fast but birdsnest messy
            //var algo = new GraphShape.Algorithms.Layout.ISOMLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph);

            //BALLOON TREE
            //doesnt work - only 1 vert
            //BalloonTreeLayoutParameters p;

            /*
            var algo = new GraphShape.Algorithms.Layout.BalloonTreeLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph, _GraphShapeGraph.Vertices.Last());
            */


            //FRLayoutAlgorithm
            //Messy because it's bounded size, can fix that
            //still - quite slow

            /*
            FreeFRLayoutParameters fp = new FreeFRLayoutParameters();
            fp.IdealEdgeLength = 200;
            fp.RepulsiveMultiplier = 36;
            fp.AttractionMultiplier = 40;
            fp.Lambda = 0.95;
            fp.MaxIterations = 16;

            BoundedFRLayoutParameters bp = new BoundedFRLayoutParameters();
            bp.Height = 10000;
            bp.Width = 10000;

            var algo = new FRLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph, positions, fp);
            */





            /*
             * 
             * Good looking layouts with at least passable speed
            *
            */


            //SUGIYAMA
            //nice looking but quite slow
            SugiyamaLayoutParameters parms = new SugiyamaLayoutParameters();
            parms.EdgeRouting = SugiyamaEdgeRouting.Orthogonal;
            parms.MinimizeEdgeLength = false;
            parms.OptimizeWidth = true;

            var algo = new GraphShape.Algorithms.Layout.SugiyamaLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph, parms);


            //SIMPLE TREE
            //not bad looking, very fast
            //var algo = new GraphShape.Algorithms.Layout.SimpleTreeLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph, vertSzies );

            //CIRCULAR
            //super fast and iconic, has to go in
            //var algo = new GraphShape.Algorithms.Layout.CircularLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>(_GraphShapeGraph, vertSzies);




            algo.Aborted += (sender, smush) => { Console.WriteLine("Compute aborted"); };
            algo.Finished += (sender, smush) => { 
                Console.WriteLine("Compute Finished"); 
            };
            
            algo.IterationEnded += (sender, smush) => {
                //FRLayoutAlgorithm<string, TypedEdge<string>, BidirectionalGraph<string, TypedEdge<string>>> alg = (FRLayoutAlgorithm<string, TypedEdge<string>, BidirectionalGraph<string, TypedEdge<string>>>) sender;
                //FRLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>> alg = (FRLayoutAlgorithm<NodeData, TypedEdge<NodeData>, BidirectionalGraph<NodeData, TypedEdge<NodeData>>>)sender;
                //Console.WriteLine($"iter done {alg.VerticesPositions[_GraphShapeGraph.Vertices.First()].X}, {alg.VerticesPositions[_GraphShapeGraph.Vertices.First()].Y}");
            };
            

            algo.Started += (sender, smush) => { Console.WriteLine("Compute Started"); };
            algo.ProgressChanged += (sender, smush) => { Console.WriteLine("Compute ProgressChanged"); };
            algo.Compute();


            st.Stop();
            double rate = (double)(_GraphShapeGraph.VertexCount / (double)st.Elapsed.TotalMilliseconds);
            Console.WriteLine($"Graph computed {_GraphShapeGraph.VertexCount} nodes in {st.Elapsed.TotalSeconds} seconds ({rate * 1000.0} nodes/second)");

            if (algo.VerticesPositions.Count == 0)
            {
                Console.WriteLine("Warning - render_graph(): No positions generated");
                return;
            }


            Debug.Assert(!double.IsNaN(algo.VerticesPositions[_GraphShapeGraph.Vertices.First()].X));
            foreach (NodeData n in _GraphShapeGraph.Vertices)
            {
                if (n.index >= NodesDisplayData.NodeCount) break;
                GraphShape.Point nodepos = algo.VerticesPositions[n];
                Vector3 pos = new Vector3((float)nodepos.X * 10, -1 * (float)nodepos.Y * 10, 0);
                NodesDisplayData.SetNodeCoord(n.index, pos, pos);
                if (n.ins.BlockBoundary)
                    Console.WriteLine($"\tNode {n.index} at {pos.X},{pos.Y} <<--- BlockTop");
                else
                    Console.WriteLine($"\tNode {n.index} at {pos.X},{pos.Y}");

                if (n.ins.ContainingBlockIDs != null)
                {
                    bool working = false;
                    uint bid = n.ins.ContainingBlockIDs[^1];
                    List<InstructionData> blk = internalProtoGraph.ProcessData.getDisassemblyBlock(bid);
                    foreach (InstructionData ins in blk)
                    {

                        if (!working)
                        {
                            if (ins.address == n.ins.address)
                                working = true;
                            continue;
                        }
                        if (ins.BlockBoundary) break;
                        pos.Y -= 15;

                        if (ins.threadvertIdx.ContainsKey(internalProtoGraph.ThreadID))
                        {
                            uint nidx = ins.threadvertIdx[internalProtoGraph.ThreadID];
                            if (NodesDisplayData.NodeCount > nidx)
                            { 
                                NodesDisplayData.SetNodeCoord(nidx, pos, pos);
                                Console.WriteLine($"\t\tNode {nidx} at {pos.X},{pos.Y}");
                            }
                        }
                    }
                    
                }
            }
            


            
            int edgesDrawn = 0;
            uint endIndex = EdgesDisplayData.CountRenderedEdges;
            EdgesDisplayData.Clear();
            for (uint edgeIdx = 0; edgeIdx < endIndex; edgeIdx++)
            {
                if (edgeIdx >= internalProtoGraph.edgeList.Count)
                {
                    Console.WriteLine("Possible error: trying to render more edges than in protograph"); //error or just catching up?
                    break;
                }    
                var edgeNodes = internalProtoGraph.edgeList[(int)edgeIdx];
                if (!render_edge(edgeNodes, null))
                {
                    Console.WriteLine("Error: rendering edge");
                    break;
                }
                edgesDrawn++;
            }
            

        }

        Vector3 nodeIndexToXYZ(int index)
        {
            bool success = NodesDisplayData.get_node_coord<Vector3>(index, out Vector3 nodeCoord);
            Debug.Assert(success);
            return nodeCoord;
        }

        static int drawCurve(GraphDisplayData linedata, Vector3 startC, Vector3 endC, GRAPH_SCALE scalefactors,
    WritableRgbaFloat colour, eEdgeNodeType edgeType, out int arraypos, bool shiftedMidPoint = false)
        {
            //describe the normal
            GraphicsMaths.midpoint(startC, endC, out Vector3 middleC);
            if (shiftedMidPoint)
            {
                middleC.X -= 1f;
                middleC.Z -= 1f;
            }

            float eLen = GraphicsMaths.linedist(startC, endC);

            Vector3 bezierC = middleC;
            int curvePoints;

            switch (edgeType)
            {
                case eEdgeNodeType.eEdgeNew:
                    {
                        //todo: make this number much smaller for previews
                        curvePoints = eLen < 50 ? 1 : GL_Constants.LONGCURVEPTS;
                        bezierC = middleC;
                        break;
                    }

                case eEdgeNodeType.eEdgeOld:
                case eEdgeNodeType.eEdgeReturn:
                    {
                        curvePoints = GL_Constants.LONGCURVEPTS;
                        if (eLen > 2)
                        {
                            //calculate the AB coords of the midpoint of the cylinder
                            //getCylinderCoordAB(middleC, scalefactors, out float oldMidA, out float oldMidB);
                            float curveMagnitude = Math.Min(eLen / 2, (float)(scalefactors.plotSize / 2));
                            //recalculate the midpoint coord as if it was inside the cylinder
                            //cylinderCoord(oldMidA, oldMidB, -curveMagnitude, out bezierC, scalefactors);

                            //i dont know why this problem happens or why this fixes it
                            //todo: is this still an issue?
                            if ((bezierC.X > 0) && (startC.X < 0 && endC.X < 0))
                                bezierC.X = -bezierC.X;
                        }
                        break;
                    }

                case eEdgeNodeType.eEdgeCall:
                case eEdgeNodeType.eEdgeLib:
                case eEdgeNodeType.eEdgeException:
                    {
                        curvePoints = GL_Constants.LONGCURVEPTS;
                        bezierC = middleC;
                        break;
                    }

                default:
                    Console.WriteLine("[rgat]Error: Drawcurve unknown edgeType " + edgeType);
                    Debug.Assert(false);
                    arraypos = -1;
                    return 0;
            }

            switch (curvePoints)
            {
                case GL_Constants.LONGCURVEPTS:

                    int vertsdrawn = linedata.drawLongCurvePoints(bezierC, startC, endC, colour, edgeType, out arraypos);
                    return vertsdrawn;

                case 1:
                    linedata.drawShortLinePoints(startC, endC, colour, GlobalConfig.AnimatedFadeMinimumAlpha, out arraypos);
                    return 2;

                default:
                    Console.WriteLine("[rgat]Error: Drawcurve unknown curvePoints " + curvePoints);
                    arraypos = 0;
                    return curvePoints;
            }
        }

        protected override bool render_edge(Tuple<uint, uint> nodePair, WritableRgbaFloat? forceColour)
        {
            ulong nodeCoordQty = (ulong)NodesDisplayData.NodeCount;
            if (nodePair.Item1 >= nodeCoordQty || nodePair.Item2 >= nodeCoordQty)
                return false;

            
            NodeData n1 = internalProtoGraph.safe_get_node(nodePair.Item1);
            NodeData n2 = internalProtoGraph.safe_get_node(nodePair.Item2);

            if (n1.ins.BlockBoundary) //plot only the top of basic blocks
            {
                if (!_GraphShapeGraph.AddVerticesAndEdge(new TypedEdge<NodeData>(n1, n2, EdgeTypes.General)))
                    Console.WriteLine("Edge add failed");
            }

            EdgeData e = internalProtoGraph.edgeDict[nodePair];

            Vector3 srcc = nodeIndexToXYZ((int)nodePair.Item1);
            Vector3 targc = nodeIndexToXYZ((int)nodePair.Item2);
            WritableRgbaFloat edgeColourPtr = forceColour != null ? (WritableRgbaFloat)forceColour : graphColours[(int)e.edgeClass];

            bool shiftedMiddle = e.edgeClass == eEdgeNodeType.eEdgeOld;
            int vertsDrawn = drawCurve(EdgesDisplayData, srcc, targc, scalefactors, edgeColourPtr, e.edgeClass, out int arraypos, shiftedMiddle);

            uint EdgeIndex = e.EdgeIndex;
            //Debug.Assert();
            if (EdgeIndex > EdgesDisplayData.Edges_VertSizes_ArrayPositions.Count) {
                Console.WriteLine($"Warning: Tried to render edge index exceeding EdgeDisplaydata count");
                return false; 
            }

            if (EdgeIndex == EdgesDisplayData.Edges_VertSizes_ArrayPositions.Count)
                EdgesDisplayData.Edges_VertSizes_ArrayPositions.Add(new Tuple<int, int>(vertsDrawn, arraypos));
            else
            {
                EdgesDisplayData.Edges_VertSizes_ArrayPositions[(int)EdgeIndex] = new Tuple<int, int>(vertsDrawn, arraypos);
            }

            EdgesDisplayData.inc_edgesRendered();


            /*
            foreach (NodeData n in _GraphShapeGraph.Vertices)
            {
                GraphShape.Point nodepos = algo.VerticesPositions[n];
                Console.WriteLine($"Node {n.index} at {nodepos.X},{nodepos.Y}");
            }
            */


            return true;
        }

        //how much to move the camera on the y axis per mouse movement
        static private float CamBoomFactor()
        {
            return 30f; //todo adjust to zoom, plot size
        }


        public override void ApplyMouseDelta(Vector2 mousedelta)
        {
            CameraYOffset -= mousedelta.Y * CamBoomFactor();
            CameraXOffset += mousedelta.X * CamBoomFactor();
        }
    }
}
