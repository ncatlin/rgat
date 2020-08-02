﻿using ImGuiNET;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Reflection.Metadata.Ecma335;
using System.Runtime;
using System.Text;
using System.Threading;
using Veldrid;
using Veldrid.OpenGLBinding;

namespace rgatCore
{
    struct CYLINDERCOORD
    {
        public float a; //across/latitude
        public float b; //down/longitude
        public float diamMod; //position protrude/intrude from the wireframe
    };

    class CylinderGraph : PlottedGraph
    {
        const float DEFAULT_A_SEP = 80f; //was 80
        const float DEFAULT_B_SEP = 120f; //was 120
        const float PREVIEW_A_SEP = 0.8f;
        const float PREVIEW_B_SEP = 1.2f;
        const float B_PX_OFFSET_FROM_TOP = 0.01f;

        const float CYLINDER_SEP_PER_ROW = 15;
        const float JUMPA = -3;
        const float JUMPB = 3;
        const float JUMPA_CLASH = 1.5f;

        const float CALLA = 5;
        const float CALLB = 3;

        const float B_BETWEEN_BLOCKNODES = 0.25f; //vertical separation between non-flow instructions
        const float B_AFTER_COND_DROP = 0.35f;    //vertical separation after a conditional that didnt execute

        //how to adjust placement if it jumps to a prexisting node (eg: if caller has called multiple)
        const int CALLA_CLASH = 0;
        const int CALLB_CLASH = 12;

        //placement of external nodes, relative to the first caller
        const float EXTERNA = -0.5f;
        const float EXTERNB = 0.5f;

        //controls placement of the node after a return
        const int RETURNA_OFFSET = 0;
        const int RETURNB_OFFSET = 3;

        const int WIREFRAME_POINTSPERLINE = 64;

        public CylinderGraph(ProtoGraph baseProtoGraph, List<WritableRgbaFloat> colourslist) : base(baseProtoGraph, colourslist)
        {
            layout = graphLayouts.eCylinderLayout;
            graphColours = colourslist;
            if (graphColours.Count == 0)
            {
                Console.WriteLine("Warning: bad colour array. Assigning default");
                graphColours = GlobalConfig.defaultGraphColours;
            }

            wireframelines = new GraphDisplayData();
        }

        /*
        void ScreenPositionToAB(Vector3 screenpos, GRAPH_SCALE dimensions, GraphicsMaths.SCREENINFO scrn, out float a, out float b)
        {
            //screenpos.Y -= (scrn.Height);
            //screenpos.X -= (scrn.Width / 2);

            Vector3 pos2 = GraphicsMaths.Unproject(screenpos, projection, view, Matrix4x4.Multiply(Matrix4x4.Identity, rotation), scrn);
            Console.WriteLine($"Unprojected {pos2.X},{pos2.Y},{pos2.Z}");

            pos2.Z = (pos2.Z - scrn.CamZoom) - dimensions.plotSize;
            getCylinderCoordAB(pos2, dimensions, out a, out b);           
        }

        Vector3 NodeScreenPosition(uint index, GRAPH_SCALE dimensions, GraphicsMaths.SCREENINFO scrn)
        {
            bool success = get_node_coord((int)index, out CYLINDERCOORD nodeCoordCyl);
            Debug.Assert(success);

            cylinderCoord(nodeCoordCyl.a, nodeCoordCyl.b, nodeCoordCyl.diamMod, out Vector3 NodeCoord, dimensions);
            Vector3 pos2 = GraphicsMaths.Project(NodeCoord, projection, view, Matrix4x4.Multiply(Matrix4x4.Identity, rotation), scrn);

            pos2.Z = (pos2.Z - scrn.CamZoom) - dimensions.plotSize;

            return pos2;
        }
        */

        Vector3 NodeScreenPosition(CYLINDERCOORD nodeCoordCyl, GRAPH_SCALE dimensions, GraphicsMaths.SCREENINFO scrn)
        {
            cylinderCoord(nodeCoordCyl.a, nodeCoordCyl.b, nodeCoordCyl.diamMod, out Vector3 NodeCoord, dimensions);
            Vector3 pos2 = GraphicsMaths.Project(NodeCoord, projection, view, Matrix4x4.Multiply(Matrix4x4.Identity, rotation), scrn);

            //pos2.Z = (pos2.Z - scrn.CamZoom) - dimensions.plotSize;
            //pos2.Z -= dimensions.plotSize;
            pos2.Z += scrn.CamZoom;
            return pos2;
        }


        public float ConvertScreenYtoBCoord(float YCoord, GraphicsMaths.SCREENINFO scrn)
        {
            cylinderCoord(0, 0, 0, out Vector3 CylXYZCoordBeforeProject, scalefactors);
            Vector3 ScreenPosAfterProject = GraphicsMaths.Project(CylXYZCoordBeforeProject, projection, view, Matrix4x4.Multiply(Matrix4x4.Identity, rotation), scrn);
            Vector3 RawGraphicPos = GraphicsMaths.Unproject(new Vector3(0, YCoord, ScreenPosAfterProject.Z), projection, view, Matrix4x4.Multiply(Matrix4x4.Identity, rotation), scrn);
            return (float)(RawGraphicPos.Y / (-1 * scalefactors.pix_per_B));
        }

        public override List<TEXTITEM> GetOnScreenTexts(GraphicsMaths.SCREENINFO scrn)
        {
            texts.Clear();

            const int hackyBCoordLeeway = 5; //screen => b coord conversion is inexact
            float highestVisibleNodeB = ConvertScreenYtoBCoord(0, scrn) - hackyBCoordLeeway;
            float lowestVisibleNodeB = ConvertScreenYtoBCoord(scrn.Height, scrn) + hackyBCoordLeeway;



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

                NodesDisplayData.get_node_coord((int)node.index, out CYLINDERCOORD nodeCoordCyl);
                if (nodeCoordCyl.b >= highestVisibleNodeB && nodeCoordCyl.b <= lowestVisibleNodeB)
                {
                    Vector3 pos = NodeScreenPosition(nodeCoordCyl, scalefactors, scrn);
                    if ((pos.X - scrn.X) > scrn.Width || (pos.X - scrn.X) < 0) continue;
                    if ((pos.Y - scrn.Y) > scrn.Height || (pos.Y - scrn.Y) < 0) continue;
                    if (pos.Z > ZMidPoint) continue; //don't show text further back than half way around the cylinder

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

                    CYLINDERCOORD cylcoord;
                    NodesDisplayData.get_node_coord((int)node.index, out cylcoord);
                    //itm.contents = $"N<{node.index}>  X:{cylcoord.a} Y:{cylcoord.b}";
                    //itm.contents = $"N<{node.index}>  X:{pos.X} Y:{pos.Y} z:{pos.Z} Dist:{dist}";
                    itm.contents = $"{node.index} 0x{node.address:X}: {node.ins.ins_text}";
                    itm.color = Color.White;
                }


                itm.screenXY.X = pos.X;
                itm.screenXY.Y = pos.Y;

                texts.Add(itm);
                if (texts.Count > GlobalConfig.OnScreenNodeTextCountLimit) break;
            }
            //Console.WriteLine(texts.Count);


            return texts;

        }

        public override void render_static_graph()
        {
            render_new_edges();
            regenerate_wireframe_if_needed();
        }


        protected override bool render_edge(Tuple<uint, uint> ePair, WritableRgbaFloat? colourOverride)
        {
            ulong nodeCoordQty = (ulong)NodesDisplayData.NodeCount;
            if (ePair.Item1 >= nodeCoordQty || ePair.Item2 >= nodeCoordQty)
                return false;


            EdgeData e = internalProtoGraph.edgeDict[ePair];

            Vector3 srcc = nodeIndexToXYZ((int)ePair.Item1);
            Vector3 targc = nodeIndexToXYZ((int)ePair.Item2);
            WritableRgbaFloat edgeColourPtr = colourOverride != null ? (WritableRgbaFloat)colourOverride : graphColours[(int)e.edgeClass];

            bool shiftedMiddle = e.edgeClass == eEdgeNodeType.eEdgeOld;
            int vertsDrawn = drawCurve(EdgesDisplayData, srcc, targc, scalefactors, edgeColourPtr, e.edgeClass, out int arraypos, shiftedMiddle);

            uint EdgeIndex = e.EdgeIndex;
            //Debug.Assert();
            if(EdgeIndex == EdgesDisplayData.Edges_VertSizes_ArrayPositions.Count)
                EdgesDisplayData.Edges_VertSizes_ArrayPositions.Add(new Tuple<int, int>(vertsDrawn, arraypos));
            else
            {
                EdgesDisplayData.Edges_VertSizes_ArrayPositions[(int)EdgeIndex] = new Tuple<int, int>(vertsDrawn, arraypos);
            }

            EdgesDisplayData.inc_edgesRendered();
            return true;
        }

        /*
		void drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE* scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget);
		void drawHighlight(GENERIC_COORD& graphCoord, GRAPH_SCALE* scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget);

		bool get_visible_node_pos(NODEINDEX nidx, DCOORD* screenPos, SCREEN_QUERY_PTRS* screenInfo, graphGLWidget &gltarget);

		pair<void*, float> get_diffgraph_nodes() { return make_pair(&node_coords, maxB); }
		void set_diffgraph_nodes(pair<void*, float> diffData) { node_coords = (vector<CYLINDERCOORD>*)diffData.first; maxB = diffData.second; }
		uint get_graph_size() { return main_scalefactors.plotSize; };

		void orient_to_user_view();
		*/

        override public void InitialisePreviewDimensions()
        {
            wireframeSupported = false;
            wireframeActive = false;

            scalefactors.plotSize = 50;
            scalefactors.basePlotSize = 50;
            scalefactors.pix_per_A = PREVIEW_A_SEP;
            scalefactors.pix_per_B = PREVIEW_B_SEP;
            scalefactors.original_pix_per_A = PREVIEW_A_SEP;
            scalefactors.original_pix_per_B = PREVIEW_B_SEP;
            scalefactors.userSizeModifier = 1;

        }

        override public void InitialiseDefaultDimensions()
        {
            wireframeSupported = true;
            wireframeActive = true;

            scalefactors.plotSize = 20000;
            scalefactors.basePlotSize = 20000;
            scalefactors.userSizeModifier = 1;
            scalefactors.pix_per_A = DEFAULT_A_SEP;
            scalefactors.original_pix_per_A = DEFAULT_A_SEP;
            scalefactors.pix_per_B = DEFAULT_B_SEP;
            scalefactors.original_pix_per_B = DEFAULT_B_SEP;

            CameraZoom = 2000f;
            CameraXOffset = 0;
            CameraYOffset = 0;
        }

        override public void initialiseCustomDimensions(GRAPH_SCALE scale)
        {
            InitialiseDefaultDimensions();
            scale.plotSize = (long)(scale.basePlotSize * scale.userSizeModifier);
            scalefactors = scale;
        }


        /*
		void setWireframeActive(int mode);

		float previewZoom() { return -2550; }
		int prevScrollYPosition() { return -250; }

		int getNearestNode(QPoint screenPos, graphGLWidget &gltarget, node_data** node);
		*/

        override public void render_node(NodeData n)
        {
            CYLINDERCOORD coord;
            if (n.index >= NodesDisplayData.NodeCount)
            {
                //Console.WriteLine($"Node {n.index} {n.ins.ins_text} not plotted yet, plotting");
                if (NodesDisplayData.NodeCount == 0)
                {
                    Debug.Assert(n.index == 0);
                    CYLINDERCOORD tempPos;
                    tempPos.a = 0; tempPos.b = 0; tempPos.diamMod = 0;
                    coord = tempPos;


                    lock (internalProtoGraph.nodeLock)
                    {
                        NodesDisplayData.add_node_coord(tempPos);
                    }
                }
                else
                {
                    positionVert(n, out CYLINDERCOORD newPos);
                    coord = newPos;
                    NodesDisplayData.add_node_coord(newPos);
                    //Console.WriteLine($"Thread {internalProtoGraph.ThreadID} added vert {n.index}");
                    Debug.Assert(NodesDisplayData.NodeCount == n.index + 1);

                }

                updateStats(coord.a, coord.b, 0);
                NodesDisplayData.usedCoords.Add(new Tuple<float, float>(coord.a, coord.b), true);

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
                NodesDisplayData.get_node_coord<CYLINDERCOORD>((int)n.index, out coord);
                Console.WriteLine($"Node {n.index} already plotted, retrieved to coord {coord.a} {coord.b}");
            }


            cylinderCoord(coord, out Vector3 screenc, scalefactors);

            WritableRgbaFloat active_col;
            if (n.IsExternal)
                NodesDisplayData.LastRenderedNode.lastVertType = eEdgeNodeType.eNodeExternal;
            else
            {
                switch (n.ins.itype)
                {
                    case eNodeType.eInsUndefined:
                        if (n.IsConditional()) Console.WriteLine($"render_node jump because n {n.index} is conditional undef");
                        NodesDisplayData.LastRenderedNode.lastVertType = n.IsConditional() ?
                            eEdgeNodeType.eNodeJump :
                            eEdgeNodeType.eNodeNonFlow;
                        break;

                    case eNodeType.eInsJump:
                        Console.WriteLine($"render_node jump because n {n.index} is jump");

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

            VertexPositionColor colorEntry = new VertexPositionColor(screenc, nodeColor, GlobalConfig.AnimatedFadeMinimumAlpha);

            NodesDisplayData.safe_add_vert(colorEntry);
        }


        //take the a/b/bmod coords, convert to opengl coordinates based on supplied cylinder multipliers/size
        Vector3 nodeIndexToXYZ(int index)
        {
            bool success = NodesDisplayData.get_node_coord<CYLINDERCOORD>(index, out CYLINDERCOORD nodeCoordCyl);
            Debug.Assert(success);
            cylinderCoord(nodeCoordCyl.a, nodeCoordCyl.b, nodeCoordCyl.diamMod, out Vector3 result, scalefactors);
            return result;
        }

        Vector2 nodeIndexToXYZ_Text(int index)
        {
            bool success = NodesDisplayData.get_node_coord<CYLINDERCOORD>(index, out CYLINDERCOORD nodeCoordCyl);
            Debug.Assert(success);
            cylinderCoord_Text(nodeCoordCyl.a, nodeCoordCyl.b, 1, out Vector2 result);
            return result;
        }


        int needed_wireframe_loops()
        {
            return (int)Math.Ceiling((maxB * scalefactors.pix_per_B) / (CYLINDER_SEP_PER_ROW * scalefactors.pix_per_B)) + 2;
        }


        void regenerate_wireframe_if_needed()
        {
            int requiredLoops = needed_wireframe_loops();
            Console.WriteLine($"Neededloops {requiredLoops} vs haveloops {wireframe_loop_count}");
            if (requiredLoops > wireframe_loop_count || wireframelines.CountVerts() == 0)
            {
                wireframe_loop_count = requiredLoops;
                wireframelines.VertList.Clear();
                plot_wireframe();
            }
        }


        void plot_wireframe()
        {
            float diam = scalefactors.plotSize;
            List<VertexPositionColor> vertsList = wireframelines.acquire_vert_write();

            //horizontal circles
            List<Vector3> pointPositions = new List<Vector3>();
            for (int circlePoint = 0; circlePoint < WIREFRAME_POINTSPERLINE + 1; ++circlePoint)
            {
                float angle = (float)(2 * Math.PI * circlePoint) / WIREFRAME_POINTSPERLINE;
                Vector3 vertPosition = new Vector3(diam * (float)Math.Cos(angle), 0, diam * (float)Math.Sin(angle));
                pointPositions.Add(vertPosition);
            }

            float Loop_vert_sep = (maxB * scalefactors.pix_per_B) / (wireframe_loop_count - 2);

            VertexPositionColor wfVert = new VertexPositionColor();
            wfVert.Color = GlobalConfig.mainColours.wireframe;
            wfVert.ActiveAnimAlpha = GlobalConfig.WireframeAnimatedAlpha;
            for (int rowY = 0; rowY < wireframe_loop_count; rowY++)
            {
                float rowYcoord = -rowY * Loop_vert_sep;// (CYLINDER_SEP_PER_ROW + Math.Max(0, main_scalefactors.pix_per_B));
                for (int circlePoint = 0; circlePoint < WIREFRAME_POINTSPERLINE + 1; ++circlePoint)
                {
                    wfVert.Position = pointPositions[circlePoint];
                    wfVert.Position.Y = rowYcoord;
                    vertsList.Add(wfVert);

                    wfVert.Position = (circlePoint < WIREFRAME_POINTSPERLINE) ? pointPositions[circlePoint + 1] : pointPositions[0];
                    wfVert.Position.Y = rowYcoord;
                    vertsList.Add(wfVert);
                }
            }
            Console.WriteLine($"Drew {vertsList.Count} wireframe verts");
            wireframelines.release_vert_write();
        }



        /*
        
        void display_graph(GraphicsMaths.PROJECTDATA pd, graphGLWidget &gltarget)
        {
            if (!trySetGraphBusy()) return;

            labelPositions.Clear();
            
            if (IsAnimated)
                display_active(gltarget);
            else
                display_static(gltarget);

            float zmul = GraphicsMaths.zoomFactor(cameraZoomlevel, main_scalefactors.plotSize);
            if (clientState.should_show_instructions(zmul) && internalProtoGraph.get_num_nodes() > 2)
                draw_instructions_text(zmul, pd, gltarget);

            if (!IsAnimated || replayState ==  REPLAY_STATE.ePaused)
            {
                if (clientState.should_show_external_symbols(zmul))
                    show_external_symbol_labels(pd, gltarget);


                if (clientState.should_show_internal_symbols(zmul))
                {
                    bool placeholders = clientState.should_show_placeholder_labels(zmul);
                    show_internal_symbol_labels(pd, gltarget, placeholders);
                }
            }
            else
                if (GlobalConfig.showRisingAnimated && internalProtoGraph.IsActive)
            {   //show label of extern we are blocked on
                //called in main thread

                NodeData n = internalProtoGraph.safe_get_node(lastMainNode.lastVertID);
                if (n != null && n.IsExternal)
                {
                    DCOORD screenCoord;
                    if (!get_screen_pos(lastMainNode.lastVertID, get_mainnodes(), pd, &screenCoord))
                    {
                        setGraphBusy(false, 82);
                        return;
                    }

                    if (is_on_screen(screenCoord, gltarget.width(), gltarget.height()))
                    {
                        QPainter painter(&gltarget);
                        painter.setFont(clientState.instructionFont);
                        const QFontMetrics fm(clientState.instructionFont);

                        TEXTRECT mouseoverNode;
                        bool hasMouseover;
                        hasMouseover = gltarget.getMouseoverNode(&mouseoverNode);

                        if (hasMouseover && mouseoverNode.index == n.index)
                            painter.setPen(Color.Orange);
                        else
                            painter.setPen(Color.Red);

                        draw_func_args(&painter, screenCoord, n, gltarget, &fm);
                        painter.end();
                    }
                }
            }

            setGraphBusy(false, 82);

        }
        */

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

            Vector3 bezierC;
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

                        if (eLen < 2)
                            bezierC = middleC;
                        else
                        {
                            bezierC = middleC;
                            //calculate the AB coords of the midpoint of the cylinder
                            getCylinderCoordAB(middleC, scalefactors, out float oldMidA, out float oldMidB);
                            float curveMagnitude = Math.Min(eLen / 2, (float)(scalefactors.plotSize / 2));
                            //recalculate the midpoint coord as if it was inside the cylinder
                            cylinderCoord(oldMidA, oldMidB, -curveMagnitude, out Vector3 bezierC2, scalefactors);
                            bezierC = bezierC2;

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
                    linedata.drawShortLinePoints(startC, endC, colour, GlobalConfig.AnimatedFadeMinimumAlpha,  out arraypos);
                    return 2;

                default:
                    Console.WriteLine("[rgat]Error: Drawcurve unknown curvePoints " + curvePoints);
                    arraypos = 0;
                    return curvePoints;
            }
        }

        /*
        void write_rising_externs(GraphicsMaths.PROJECTDATA pd, graphGLWidget &gltarget)
        {
            Vector3 nodepos;

            List<Tuple<uint, EXTTEXT>> displayNodeList;

            //make labels rise up screen, delete those that reach top
            //internalProtoGraph.externCallsLock.lock();
            map<NODEINDEX, EXTTEXT>::iterator activeExternIt = activeExternTimes.begin();
            for (; activeExternIt != activeExternTimes.end(); ++activeExternIt)
            {
                EXTTEXT extxt = activeExternIt.second;

                if (extxt.framesRemaining != (int)Anim_Constants.eKB.KEEP_BRIGHT)
                {
                    extxt.yOffset += Anim_Constants.EXTERN_FLOAT_RATE;

                    if (extxt.framesRemaining-- == 0)
                    {
                        activeExternIt = activeExternTimes.erase(activeExternIt);
                        if (activeExternIt == activeExternTimes.end())
                            break;
                        else
                            continue;
                    }
                }
                displayNodeList.Add(make_pair(activeExternIt.first, activeExternIt.second)); ;
            }
            internalProtoGraph.externCallsLock.unlock();

            if (displayNodeList.Count == 0) return;

            QPainter painter(&gltarget);
            painter.setPen(GlobalConfig.mainColours.symbolTextExternalRising);
            painter.setFont(clientState.instructionFont);
            int windowHeight = gltarget.height();



            vector<pair<NODEINDEX, EXTTEXT>>::iterator displayNodeListIt = displayNodeList.begin();
            for (; displayNodeListIt != displayNodeList.end(); ++displayNodeListIt)
            {
                //internalProtoGraph.getNodeReadLock();
                CYLINDERCOORD coord = get_node_coord(displayNodeListIt.first);
                //internalProtoGraph.dropNodeReadLock();

                EXTTEXT extxt = displayNodeListIt.second;

                if (clientState.showNearSide && !a_coord_on_screen(coord.a, 1))
                    continue;

                if (!get_screen_pos(displayNodeListIt.first, mainnodesdata, pd, &nodepos))
                    continue;

                painter.drawText(nodepos.x, windowHeight - nodepos.y - extxt.yOffset, extxt.displayString.c_str());
            }

            painter.end();
        }
        */

       
     
       

        /*
         * This positions the node in the format of the graph, with abstract layout specific coordinates
         * Translating these abstract coordinates into real x/y/z coords is the job of CylinderCoord()
         */
        void positionVert(NodeData n, out CYLINDERCOORD newPosition)
        {
            GraphDisplayData.PLOT_TRACK lastNode = NodesDisplayData.LastRenderedNode;
            if (!NodesDisplayData.get_node_coord<CYLINDERCOORD>((int)lastNode.lastVertID, out CYLINDERCOORD oldPosition))
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
                    found = NodesDisplayData.get_node_coord<CYLINDERCOORD>((int)lastNode.lastVertID, out oldPosition);

                } while (!found);
            }

            float a = oldPosition.a;
            float b = oldPosition.b;
            float diamMod = 0;
            int clash = 0;

            if (n.IsExternal)
            {
                NodeData lastNodeData = internalProtoGraph.safe_get_node(lastNode.lastVertID);
                newPosition.a = a + EXTERNA - 1 * lastNodeData.childexterns;
                newPosition.b = b + EXTERNB + 0.7f * lastNodeData.childexterns;
                newPosition.diamMod = 6;

                while (NodesDisplayData.usedCoords.ContainsKey(new Tuple<float, float>(newPosition.a, newPosition.b)))
                {
                    newPosition.a += 0.5f;
                    ++clash;
                }
                return;
            }

            switch (lastNode.lastVertType)
            {

                //small vertical distance between instructions in a basic block	
                case eEdgeNodeType.eNodeNonFlow:
                    {
                        if (n.index < 10)
                            Console.WriteLine($"Thread {internalProtoGraph.ThreadID} positionVert Vert idx {n.index} after vert {lastNode.lastVertID} type {lastNode.lastVertType} nonflow");

                        b += B_BETWEEN_BLOCKNODES;
                        while (NodesDisplayData.usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
                        {
                            b += B_BETWEEN_BLOCKNODES;
                            a += 0.2f;
                            ++clash;
                        }
                        break;
                    }

                case eEdgeNodeType.eNodeJump://long diagonal separation to show distinct basic blocks
                    {
                        if (n.index < 10)
                            Console.WriteLine($"Thread {internalProtoGraph.ThreadID} positionVert Vert idx {n.index} after vert {lastNode.lastVertID} type {lastNode.lastVertType} jump");

                        //check if this is a conditional which fell through (ie: sequential)
                        NodeData lastNodeData = internalProtoGraph.safe_get_node(lastNode.lastVertID);
                        if (lastNodeData.IsConditional() && n.address == lastNodeData.ins.condDropAddress)
                        {
                            b += B_AFTER_COND_DROP;
                            break;
                        }

                        a += JUMPA;
                        b += JUMPB;

                        while (NodesDisplayData.usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
                        {
                            a += JUMPA_CLASH;
                            ++clash;
                        }
                        break;
                    }

                case eEdgeNodeType.eNodeException:
                    {
                        a += JUMPA;
                        b += JUMPB;
                        diamMod = 8f;

                        while (NodesDisplayData.usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
                        {
                            a += JUMPA_CLASH;
                            ++clash;
                        }

                        //if (clash > 15)
                        //	cerr << "[rgat]WARNING: Dense Graph Clash (jump) - " << clash << " attempts" << endl;
                        break;
                    }

                //long purple line to show possible distinct functional blocks of the program
                case eEdgeNodeType.eNodeCall:
                    {
                        if (n.index < 10)
                            Console.WriteLine($"Thread {internalProtoGraph.ThreadID} positionVert Vert idx {n.index} after vert {lastNode.lastVertID} type {lastNode.lastVertType} call");

                        //note: b sometimes huge after this?
                        a -= CALLA;
                        b += CALLB;

                        while (NodesDisplayData.usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
                        {
                            a -= CALLA_CLASH;
                            b += CALLB_CLASH;
                            ++clash;
                        }

                        if (clash != 0)
                        {
                            a += CALLA_CLASH;
                            //if (clash > 15)
                            //	cerr << "[rgat]WARNING: Dense Graph Clash (call) - " << clash <<" attempts"<<endl;
                        }
                        break;
                    }

                case eEdgeNodeType.eNodeReturn:
                //previous externs handled same as previous returns
                case eEdgeNodeType.eNodeExternal:
                    {
                        //returning to address in call stack?

                        var found = ThreadCallStack.Where(item => item.Item1 == n.address);
                        Tuple<ulong, uint>? foundFrame = found.Any() ? found.First<Tuple<ulong, uint>>() : null;

                        //if so, position next node near caller
                        if (foundFrame != null)
                        {
                            if (!NodesDisplayData.get_node_coord((int)foundFrame.Item2, out CYLINDERCOORD caller))
                            {
                                Debug.Assert(false, "Error: Failed to find node for entry on the callstack");
                            }
                            a = caller.a + RETURNA_OFFSET;
                            b = caller.b + RETURNB_OFFSET;

                            //may not have returned to the last item in the callstack
                            //delete everything inbetween
                            var topFrame = ThreadCallStack.Pop();
                            while (topFrame.Item1 != foundFrame.Item1)
                                topFrame = ThreadCallStack.Pop();

                            Console.WriteLine($"Thread {internalProtoGraph.ThreadID} positionVert Vert idx {n.index} after vert {foundFrame.Item2} found on callstack");
                        }
                        else
                        {
                            a += RETURNA_OFFSET;
                            b += RETURNB_OFFSET;
                        }


                        while (NodesDisplayData.usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
                        {
                            a += JUMPA_CLASH;
                            b += 1;
                            ++clash;
                        }

                        //if (clash > 15)
                        //	cerr << "[rgat]WARNING: Dense Graph Clash (extern) - " << clash << " attempts" << endl;
                        break;
                    }

                default:
                    if (lastNode.lastVertType != eEdgeNodeType.eFIRST_IN_THREAD)
                        Console.WriteLine("[rgat]ERROR: Unknown Last instruction type " + lastNode.lastVertType);
                    break;
            }

            newPosition.a = a;
            newPosition.b = b;
            newPosition.diamMod = diamMod;
        }

        private void DrawHighlightLine(Vector3 start, Vector3 end, WritableRgbaFloat colour)
        {
            HighlightsDisplayData.drawShortLinePoints(start, end, colour ,1f, out int arraypos);

        }

        public override void draw_highlight_lines()
        {
            if (!HighlightsChanged && !NodesDisplayData.LastAnimatedNode.changed) return;
            uint lastAnimNodeIdx = NodesDisplayData.LastAnimatedNode.lastVertID;
            NodesDisplayData.LastAnimatedNode.ResetChanged();
            int vertscount = NodesDisplayData.CountVerts();
            if (vertscount == 0) return;
            if (lastAnimNodeIdx >= vertscount)
                lastAnimNodeIdx = NodesDisplayData.LastRenderedNode.lastVertID;


            Vector3 srcc = new Vector3(0, 0, 0);
            Vector3 targc = nodeIndexToXYZ((int)lastAnimNodeIdx);

            HighlightsDisplayData.Clear();
            DrawHighlightLine(srcc, targc, new WritableRgbaFloat(Color.Red));

            uint[] highlightNodes = null;
            lock (textLock)
            {
                HighlightsChanged = false;
                highlightNodes = HighlightedSymbolNodes.Concat(HighlightedAddressNodes).Concat(HighlightedExceptionNodes).ToArray();
            }
            foreach (uint srcnode in highlightNodes)
            {
                targc = nodeIndexToXYZ((int)srcnode);
                DrawHighlightLine(srcc, targc, new WritableRgbaFloat(Color.Cyan));
            }
        }



        /*
		bool get_screen_pos(NODEINDEX nodeIndex, GraphDisplayData* vdata, GraphicsMaths.PROJECTDATA pd, DCOORD* screenPos);
		bool a_coord_on_screen(int a, float hedgesep);
		*/


        static void cylinderCoord(CYLINDERCOORD sc, out Vector3 c, GRAPH_SCALE dimensions)
        {

            cylinderCoord(sc.a, sc.b, sc.diamMod, out c, dimensions);
        }

        static void cylinderCoord(float a, float b, float diamModifier, out Vector3 c, GRAPH_SCALE dimensions)
        {
            double r = (dimensions.plotSize + diamModifier);// +0.1 to make sure we are above lines

            a *= dimensions.pix_per_A;
            c.X = (float)(r * Math.Cos((a * Math.PI) / r));
            c.Z = (float)(r * Math.Sin((a * Math.PI) / r));

            float fb = 0;
            fb += -1 * B_PX_OFFSET_FROM_TOP; //offset start down on cylinder
            fb += -1 * b * dimensions.pix_per_B;
            c.Y = fb;
        }

        static void cylinderCoord_Text(float a, float b, float diamModifier, out Vector2 c)
        {
            c.X = (float)(diamModifier * Math.Cos((a * Math.PI) / diamModifier));
            c.Y = -1 * B_PX_OFFSET_FROM_TOP; //offset start down on cylinder
        }

        static void getCylinderCoordAB(Vector3 c, GRAPH_SCALE dimensions, out float aOut, out float bOut)
        {
            double r = dimensions.plotSize;

            float rdiv = (float)Math.Acos(r / c.X);
            rdiv = rdiv < 1 ? rdiv : 0;
            float g2 = (float)(Math.Acos(rdiv) * r);
            float g3 = (float)((Math.Acos(rdiv) * r) / Math.PI);

            aOut = (float)((Math.Acos(rdiv) * r) / Math.PI) / dimensions.pix_per_A;

            double tb = c.Y;
            tb -= B_PX_OFFSET_FROM_TOP;
            bOut = (float)(tb / (-1 * dimensions.pix_per_B));
        }

        void Add_to_callstack(ulong address, uint idx)
        {
            ThreadCallStack.Push(new Tuple<ulong, uint>(address, idx));
        }

        int wireframe_loop_count = 0;

        //List<CYLINDERCOORD> node_coords_storage;
        //List<CYLINDERCOORD> node_coords = new List<CYLINDERCOORD>();

        //these are the edges/nodes that are brightend in the animation
        //map<NODEPAIR, edge_data*> activeEdgeMap;
        //<index, final (still active) node>
        //Dictionary<uint, bool> activeNodeMap;

    }
}