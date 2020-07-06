﻿using ImGuiNET;
using rgatCore.Threads;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Text;
using Veldrid.OpenGLBinding;

namespace rgatCore
{
    struct CYLINDERCOORD
    {
        public float a; //across/latitude
        public float b; //down/longitude
        public int bMod; //small modifications to longitude
    };

    class CylinderGraph : PlottedGraph
    {
        const float DEFAULT_A_SEP = 0.8f; //was 80
        const float DEFAULT_B_SEP = 1.2f; //was 120
        const int PREVIEW_PIX_PER_A_COORD = 3;
        const int PREVIEW_PIX_PER_B_COORD = 4;
        const float B_PX_OFFSET_FROM_TOP = 0.01f;

        const int CYLINDER_PIXELS_PER_ROW = 3000;
        const float JUMPA = -3;
        const float JUMPB = 3;
        const float JUMPA_CLASH = 1.5f;

        const float CALLA = 5;
        const float CALLB = 3;

        const float B_BETWEEN_BLOCKNODES = 0.25f;

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
        }

        /*
		void maintain_draw_wireframe(graphGLWidget &gltarget);
		void plot_wireframe(graphGLWidget &gltarget);

		void performMainGraphDrawing(graphGLWidget &gltarget);
		*/
        public override void render_static_graph()
        {
            int drawCount = render_new_edges();
            if (drawCount > 0)
                needVBOReload_main = true;

            redraw_anim_edges();
            regenerate_wireframe_if_needed();
        }


        protected override bool render_edge(Tuple<uint, uint> ePair, GraphDisplayData edgedata, WritableRgbaFloat? colourOverride, bool preview, bool noUpdate)
        {
            ulong nodeCoordQty = (ulong)node_coords.Count;
            if (ePair.Item1 >= nodeCoordQty || ePair.Item2 >= nodeCoordQty)
                return false;

            EdgeData e = internalProtoGraph.edgeDict[ePair];

            GRAPH_SCALE scaling = preview ? preview_scalefactors : main_scalefactors;

            Vector3 srcc = nodeIndexToXYZ((int)ePair.Item1, scaling, 0);
            Vector3 targc = nodeIndexToXYZ((int)ePair.Item2, scaling, 0);

            WritableRgbaFloat edgeColourPtr = colourOverride != null ? (WritableRgbaFloat)colourOverride : graphColours[(int)e.edgeClass];

            int vertsDrawn = drawCurve(edgedata, srcc, targc, edgeColourPtr, e.edgeClass, scaling, out int arraypos);

            //previews, diffs, etc where we don't want to affect the original edges
            if (!noUpdate && !preview)
            {
                e.vertSize = vertsDrawn;
                e.arraypos = arraypos;
            }
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
        override public void InitialiseDefaultDimensions()
        {
            wireframeSupported = true;
            wireframeActive = true;

            preview_scalefactors.plotSize = 500;
            preview_scalefactors.basePlotSize = 500;
            preview_scalefactors.pix_per_A = PREVIEW_PIX_PER_A_COORD;
            preview_scalefactors.pix_per_B = PREVIEW_PIX_PER_B_COORD;

            main_scalefactors.plotSize = 50;// 20000;
            main_scalefactors.basePlotSize = 50;// 20000;
            main_scalefactors.userSizeModifier = 1;
            main_scalefactors.pix_per_A = DEFAULT_A_SEP;
            main_scalefactors.original_pix_per_A = DEFAULT_A_SEP;
            main_scalefactors.pix_per_B = DEFAULT_B_SEP;
            main_scalefactors.original_pix_per_B = DEFAULT_B_SEP;

            view_shift_x = 96;
            view_shift_y = 65;
            cameraZoomlevel = 60000;
        }

        override public void initialiseCustomDimensions(GRAPH_SCALE scale)
        {
            InitialiseDefaultDimensions();
            scale.plotSize = (long)(scale.basePlotSize * scale.userSizeModifier);
            main_scalefactors = scale;
        }


        /*
		void setWireframeActive(int mode);

		float previewZoom() { return -2550; }
		int prevScrollYPosition() { return -250; }

		int getNearestNode(QPoint screenPos, graphGLWidget &gltarget, node_data** node);
		*/
        override public void render_node(NodeData n, ref PLOT_TRACK lastNode, GraphDisplayData vertdata, GraphDisplayData animvertdata,
            GRAPH_SCALE dimensions)
        {
            CYLINDERCOORD coord;
            if (n.index >= node_coords.Count)
            {

                if (node_coords.Count == 0)
                {
                    Debug.Assert(n.index == 0);
                    CYLINDERCOORD tempPos;
                    tempPos.a = 0; tempPos.b = 0; tempPos.bMod = 0;
                    coord = tempPos;

                    //acquire_nodecoord_write();
                    node_coords.Add(tempPos);
                    //release_nodecoord_write();
                }
                else
                {
                    positionVert(n, lastNode, out CYLINDERCOORD newPos);
                    coord = newPos;

                    //acquire_nodecoord_write();
                    node_coords.Add(newPos);
                    //release_nodecoord_write();
                }

                updateStats(coord.a, coord.b, 0);
                usedCoords.Add(new Tuple<float, float>(coord.a, coord.b), true);
            }
            else
                get_node_coord((int)n.index, out coord);


            cylinderCoord(coord, out Vector3 screenc, dimensions, 0);


            List<VertexPositionColor> vertsList = vertdata.acquire_vert_write();

            WritableRgbaFloat active_col;
            if (n.IsExternal)
                lastNode.lastVertType = eEdgeNodeType.eNodeExternal;
            else
            {
                switch (n.ins.itype)
                {
                    case eNodeType.eInsUndefined:
                        lastNode.lastVertType = !n.IsConditional() ?
                            eEdgeNodeType.eNodeJump :
                            eEdgeNodeType.eNodeNonFlow;
                        break;

                    case eNodeType.eInsJump:
                        lastNode.lastVertType = eEdgeNodeType.eNodeJump;
                        break;

                    case eNodeType.eInsReturn:
                        lastNode.lastVertType = eEdgeNodeType.eNodeReturn;
                        break;

                    case eNodeType.eInsCall:
                        {
                            lastNode.lastVertType = eEdgeNodeType.eNodeCall;
                            //if code arrives to next instruction after a return then arrange as a function
                            ulong nextAddress = n.ins.address + (ulong)n.ins.numbytes;
                            Add_to_callstack(vertdata.IsPreview, nextAddress, lastNode.lastVertID);
                            break;
                        }
                    default:
                        Console.WriteLine("[rgat]Error: render_node unknown itype " + n.ins.itype);
                        Debug.Assert(false);
                        break;
                }
            }

            active_col = graphColours[(int)lastNode.lastVertType];
            lastNode.lastVertID = n.index;

            WritableRgbaFloat nodeColor = new WritableRgbaFloat()
                {A = 255f, G = active_col.G, B = active_col.B, R = active_col.R };

            VertexPositionColor colorEntry = new VertexPositionColor(screenc, nodeColor);
            mainnodesdata.VertList.Add(colorEntry);
            
            //vertdata.release_col_write();
            //vertdata.release_pos_write();

            //place node on the animated version of the graph
            if (animvertdata != null)
            {
                List<VertexPositionColor> animNcol = animvertdata.acquire_vert_write();
                animNcol.Add(colorEntry);
                //animvertdata.release_col_write();
            }
        }


        //take the a/b/bmod coords, convert to opengl coordinates based on supplied cylinder multipliers/size
        Vector3 nodeIndexToXYZ(int index, GRAPH_SCALE dimensions, float diamModifier)
        {
            bool success = get_node_coord(index, out CYLINDERCOORD nodeCoordCyl);
            Debug.Assert(success);
            cylinderCoord(nodeCoordCyl.a, nodeCoordCyl.b, out Vector3 result, dimensions, diamModifier);
            return result;
        }



        void initialise()
        {
            layout = graphLayouts.eCylinderLayout;
        }

        int needed_wireframe_loops()
        {
            return (int)((maxB * main_scalefactors.pix_per_B) / CYLINDER_PIXELS_PER_ROW) + 2;
        }
        /*
        void draw_wireframe(graphGLWidget &gltarget)
        {
            gltarget.glBindBuffer(GL_ARRAY_BUFFER, wireframeVBOs[VBO_CYLINDER_POS]);
            glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

            gltarget.glBindBuffer(GL_ARRAY_BUFFER, wireframeVBOs[VBO_CYLINDER_COL]);
            glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

            gltarget.glMultiDrawArrays(GL_LINE_LOOP, &wireframeStarts.at(0), &wireframeSizes.at(0), wireframe_loop_count);
            gltarget.glBindBuffer(GL_ARRAY_BUFFER, 0);
        }
        */

        void regenerate_wireframe_if_needed()
        {
            if (needed_wireframe_loops() > wireframe_loop_count)
                staleWireframe = true;
        }

        /*
        void regen_wireframe_buffers(graphGLWidget &gltarget)
        {
            if (wireframeBuffersCreated)
            {
                gltarget.glDeleteBuffers(2, wireframeVBOs);
            }
            gltarget.glGenBuffers(2, wireframeVBOs);


            //wireframe drawn using glMultiDrawArrays which takes a list of vert starts/sizes

            for (int i = 0; i < wireframe_loop_count; ++i)
            {
                wireframeStarts.Add(i * WIREFRAME_POINTSPERLINE);
                wireframeSizes.Add(WIREFRAME_POINTSPERLINE);
            }

            wireframeBuffersCreated = true;
        }
        

        
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

        int drawCurve(GraphDisplayData linedata, Vector3 startC, Vector3 endC,
            WritableRgbaFloat colour, eEdgeNodeType edgeType, GRAPH_SCALE dimensions, out int arraypos)
        {
            //describe the normal
            GraphicsMaths.midpoint(startC, endC, out Vector3 middleC);
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
                            getCylinderCoordAB(middleC, dimensions, out float oldMidA, out float oldMidB);
                            float curveMagnitude = Math.Min(eLen / 2, (float)(dimensions.plotSize / 2));
                            //recalculate the midpoint coord as if it was inside the cylinder
                            cylinderCoord(oldMidA, oldMidB, out Vector3 bezierC2, dimensions, -curveMagnitude);
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
                    linedata.drawShortLinePoints(startC, endC, colour, out arraypos);
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

        void positionVert(NodeData n, PLOT_TRACK lastNode, out CYLINDERCOORD newPosition)
        {
            if (!get_node_coord((int)lastNode.lastVertID, out CYLINDERCOORD oldPosition))
            {
                Console.WriteLine("[rgat]Warning: Positionvert() Waiting for node " + lastNode.lastVertID);
                int waitPeriod = 5;
                int iterations = 1;
                bool found = false;
                do
                {
                    System.Threading.Thread.Sleep(waitPeriod);
                    waitPeriod += (150 * iterations++);
                    found = get_node_coord((int)lastNode.lastVertID, out oldPosition);
                } while (!found);
            }

            float a = oldPosition.a;
            float b = oldPosition.b;
            int clash = 0;

            if (n.IsExternal)
            {
                NodeData lastNodeData = internalProtoGraph.safe_get_node(lastNode.lastVertID);
                newPosition.a = a + EXTERNA - 1 * lastNodeData.childexterns;
                newPosition.b = b + EXTERNB + 0.7f * lastNodeData.childexterns;
                newPosition.bMod = 0;
                return;
            }

            switch (lastNode.lastVertType)
            {

                //small vertical distance between instructions in a basic block	
                case eEdgeNodeType.eNodeNonFlow:
                    {
                        b += B_BETWEEN_BLOCKNODES;
                        break;
                    }

                case eEdgeNodeType.eNodeJump://long diagonal separation to show distinct basic blocks
                    {
                        //check if this is a conditional which fell through (ie: sequential)
                        NodeData lastNodeData = internalProtoGraph.safe_get_node(lastNode.lastVertID);
                        if (lastNodeData.IsConditional() && n.address == lastNodeData.ins.condDropAddress)
                        {
                            b += B_BETWEEN_BLOCKNODES;
                            break;
                        }

                        a += JUMPA;
                        b += JUMPB;

                        while (usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
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

                        while (usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
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
                        if (!n.IsExternal)
                        {
                            if (!n.ins.hasSymbol && n.label.Length == 0)
                            {
                                ulong nodeoffset = n.address - internalProtoGraph.moduleBase;
                                n.label = "[InternalFunc_" + (internalProtoGraph.InternalPlaceholderFuncNames.Count + 1).ToString() + "]";
                                n.placeholder = true;

                                //callStackLock.lock () ;
                                internalProtoGraph.InternalPlaceholderFuncNames[nodeoffset] = n.index;
                                //callStackLock.unlock();
                            }
                        }

                        //note: b sometimes huge after this?
                        a -= CALLA;
                        b += CALLB;

                        while (usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
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
                        long result = -1;

                        List<Tuple<ulong, uint>> callStack = mainnodesdata.IsPreview ? PreviewCallStack : MainCallStack;

                        //callStackLock.lock () ;

                        var found = callStack.Where(item => item.Item1 == n.address);
                        result = found.Any() ? (long)found.First<Tuple<ulong, uint>>().Item2 : (long)-1;

                        //testing
                        //result = -1;

                        //if so, position next node near caller
                        if (result != -1)
                        {
                            if (!get_node_coord((int)result, out CYLINDERCOORD caller))
                            {
                                Debug.Assert(false);
                            }
                            a = caller.a + RETURNA_OFFSET;
                            b = caller.b + RETURNB_OFFSET;

                            //may not have returned to the last item in the callstack
                            //delete everything inbetween
                            Console.WriteLine("Todo, resize callstack down");
                            //callStack.resize(stackIt - callStack.begin());
                        }
                        else
                        {
                            a += RETURNA_OFFSET;
                            b += RETURNB_OFFSET;
                        }
                        //callStackLock.unlock();

                        while (usedCoords.ContainsKey(new Tuple<float, float>(a, b)))
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
            newPosition.bMod = oldPosition.bMod;
        }

        bool get_node_coord(int nodeidx, out CYLINDERCOORD result)
        {

            if (nodeidx < node_coords.Count)
            {

                //acquire_nodecoord_read();
                result = node_coords[nodeidx];
                //release_nodecoord_read();
                return true;
            }
            Debug.Assert(false);
            result = new CYLINDERCOORD();
            return false;
        }
        /*
		bool get_screen_pos(NODEINDEX nodeIndex, GraphDisplayData* vdata, GraphicsMaths.PROJECTDATA pd, DCOORD* screenPos);
		bool a_coord_on_screen(int a, float hedgesep);
		*/

        void cylinderCoord(CYLINDERCOORD sc, out Vector3 c, GRAPH_SCALE dimensions, float diamModifier = 0)
        {
            cylinderCoord(sc.a, sc.b, out c, dimensions, diamModifier);
        }
        void cylinderCoord(float a, float b, out Vector3 c, GRAPH_SCALE dimensions, float diamModifier)
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


        void getCylinderCoordAB(Vector3 c, GRAPH_SCALE dimensions, out float aOut, out float bOut)
        {
            double r = dimensions.plotSize;
            aOut = (float)((Math.Asin(c.Z / r) * r) / Math.PI) / dimensions.pix_per_A;

            double tb = c.Y;
            tb -= B_PX_OFFSET_FROM_TOP;
            bOut = (float)(tb / (-1 * dimensions.pix_per_B));
        }

        void Add_to_callstack(bool isPreview, ulong address, uint idx)
        {
            //callStackLock.lock ();
            if (isPreview)
                PreviewCallStack.Add(new Tuple<ulong, uint>(address, idx));
            else
                MainCallStack.Add(new Tuple<ulong, uint>(address, idx));
            //callStackLock.unlock();
        }

        int wireframe_loop_count = 0;
        //GraphDisplayData* wireframe_data = NULL;
        //GLuint wireframeVBOs[2];
        bool staleWireframe = false;
        bool wireframeBuffersCreated = false;
        List<int> wireframeStarts, wireframeSizes;

        //List<CYLINDERCOORD> node_coords_storage;
        List<CYLINDERCOORD> node_coords = new List<CYLINDERCOORD>();

        //these are the edges/nodes that are brightend in the animation
        //map<NODEPAIR, edge_data*> activeEdgeMap;
        //<index, final (still active) node>
        //Dictionary<uint, bool> activeNodeMap;

    }
}
