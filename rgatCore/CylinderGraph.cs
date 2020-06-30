using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class CylinderGraph : PlottedGraph
    {
		const int DEFAULT_PIX_PER_A_COORD = 80;
		const int DEFAULT_PIX_PER_B_COORD = 120;
		const int PREVIEW_PIX_PER_A_COORD = 3;
		const int PREVIEW_PIX_PER_B_COORD = 4;

		public CylinderGraph(ProtoGraph baseProtoGraph) : base(baseProtoGraph)//, vector<QColor>* coloursPtr)
		{
			layout = graphLayouts.eCylinderLayout;
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

		/*
		bool render_edge(NODEPAIR ePair, GraphDisplayData* edgedata, QColor* colourOverride, bool preview, bool noUpdate);

		void drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE* scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget);
		void drawHighlight(GENERIC_COORD& graphCoord, GRAPH_SCALE* scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget);

		bool get_visible_node_pos(NODEINDEX nidx, DCOORD* screenPos, SCREEN_QUERY_PTRS* screenInfo, graphGLWidget &gltarget);

		pair<void*, float> get_diffgraph_nodes() { return make_pair(&node_coords, maxB); }
		void set_diffgraph_nodes(pair<void*, float> diffData) { node_coords = (vector<CYLINDERCOORD>*)diffData.first; maxB = diffData.second; }
		uint get_graph_size() { return main_scalefactors.plotSize; };

		void orient_to_user_view();
		*/
		public void InitialiseDefaultDimensions()
        {
			wireframeSupported = true;
			wireframeActive = true;

			preview_scalefactors.plotSize = 600;
			preview_scalefactors.basePlotSize = 600;
			preview_scalefactors.pix_per_A = PREVIEW_PIX_PER_A_COORD;
			preview_scalefactors.pix_per_B = PREVIEW_PIX_PER_B_COORD;

			main_scalefactors.plotSize = 20000;
			main_scalefactors.basePlotSize = 20000;
			main_scalefactors.userSizeModifier = 1;
			main_scalefactors.pix_per_A = DEFAULT_PIX_PER_A_COORD;
			main_scalefactors.original_pix_per_A = DEFAULT_PIX_PER_A_COORD;
			main_scalefactors.pix_per_B = DEFAULT_PIX_PER_B_COORD;
			main_scalefactors.original_pix_per_B = DEFAULT_PIX_PER_B_COORD;

			view_shift_x = 96;
			view_shift_y = 65;
			cameraZoomlevel = 60000;
		}
		/*
		void initialiseCustomDimensions(GRAPH_SCALE scale);

		void setWireframeActive(int mode);

		float previewZoom() { return -2550; }
		int prevScrollYPosition() { return -250; }

		int getNearestNode(QPoint screenPos, graphGLWidget &gltarget, node_data** node);
		*/
		override public void render_node(NodeData n, PLOT_TRACK lastNode, GraphDisplayData vertdata, GraphDisplayData animvertdata,
			GRAPH_SCALE dimensions)
        {
			CYLINDERCOORD* coord;
			if (n->index >= node_coords->size())
			{
				CYLINDERCOORD tempPos;
				if (node_coords->empty())
				{
					assert(n->index == 0);
					tempPos = { 0,0,0 };
					coord = &tempPos;

					acquire_nodecoord_write();
					node_coords->push_back(tempPos);
					release_nodecoord_write();
				}
				else
				{
					positionVert(&tempPos, n, lastNode);
					coord = &tempPos;

					acquire_nodecoord_write();
					node_coords->push_back(tempPos);
					release_nodecoord_write();
				}

				updateStats(tempPos.a, tempPos.b, 0);
				usedCoords.emplace(make_pair(make_pair(tempPos.a, tempPos.b), true));
			}
			else
				coord = get_node_coord(n->index);

			FCOORD screenc;

			cylinderCoord(coord, &screenc, dimensions, 0);

			vector<GLfloat>* mainNpos = vertdata->acquire_pos_write(677);
			vector<GLfloat>* mainNcol = vertdata->acquire_col_write();

			mainNpos->push_back(screenc.x);
			mainNpos->push_back(screenc.y);
			mainNpos->push_back(screenc.z);

			QColor* active_col = 0;
			if (n->external)
				lastNode->lastVertType = eNodeExternal;
			else
			{
				switch (n->ins->itype)
				{
					case eInsUndefined:
						lastNode->lastVertType = n->conditional ? eNodeJump : eNodeNonFlow;
						break;

					case eInsJump:
						lastNode->lastVertType = eNodeJump;
						break;

					case eInsReturn:
						lastNode->lastVertType = eNodeReturn;
						break;

					case eInsCall:
						{
							lastNode->lastVertType = eNodeCall;
							//if code arrives to next instruction after a return then arrange as a function
							MEM_ADDRESS nextAddress = n->ins->address + n->ins->numbytes;
							add_to_callstack(vertdata->isPreview(), nextAddress, lastNode->lastVertID);
							break;
						}
					default:
						cerr << "[rgat]Error: render_node unknown itype " << n->ins->itype << endl;
						assert(0);
				}
			}

			active_col = &graphColours->at(lastNode->lastVertType);
			lastNode->lastVertID = n->index;

			mainNcol->push_back(active_col->redF());
			mainNcol->push_back(active_col->greenF());
			mainNcol->push_back(active_col->blueF());
			mainNcol->push_back(1.0f);

			vertdata->set_numVerts(vertdata->get_numVerts() + 1);

			vertdata->release_col_write();
			vertdata->release_pos_write();

			//place node on the animated version of the graph
			if (animvertdata)
			{
				vector<GLfloat>* animNcol = animvertdata->acquire_col_write();

				animNcol->push_back(active_col->redF());
				animNcol->push_back(active_col->greenF());
				animNcol->push_back(active_col->blueF());
				animNcol->push_back(0);

				animvertdata->set_numVerts(vertdata->get_numVerts() + 1);
				animvertdata->release_col_write();
			}
		}
		/*
		FCOORD nodeIndexToXYZ(NODEINDEX index, GRAPH_SCALE* dimensions, float diamModifier);
		*/
	
		void initialise()
        {
			layout = eCylinderLayout;
		}

		int needed_wireframe_loops()
        {
			return ((maxB * main_scalefactors->pix_per_B) / CYLINDER_PIXELS_PER_ROW) + 2;
		}

		void draw_wireframe(graphGLWidget &gltarget)
        {
			gltarget.glBindBuffer(GL_ARRAY_BUFFER, wireframeVBOs[VBO_CYLINDER_POS]);
			glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

			gltarget.glBindBuffer(GL_ARRAY_BUFFER, wireframeVBOs[VBO_CYLINDER_COL]);
			glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

			gltarget.glMultiDrawArrays(GL_LINE_LOOP, &wireframeStarts.at(0), &wireframeSizes.at(0), wireframe_loop_count);
			gltarget.glBindBuffer(GL_ARRAY_BUFFER, 0);
		}
		
		void regenerate_wireframe_if_needed()
        {
			if (needed_wireframe_loops() > wireframe_loop_count)
				staleWireframe = true;
		}
		
		void regen_wireframe_buffers(graphGLWidget &gltarget);

		void display_graph(PROJECTDATA* pd, graphGLWidget &gltarget)
        {
			if (!trySetGraphBusy()) return;

			labelPositions.clear();
			if (isAnimated())
				display_active(gltarget);
			else
				display_static(gltarget);

			float zmul = zoomFactor(cameraZoomlevel, main_scalefactors->plotSize);
			if (clientState->should_show_instructions(zmul) && internalProtoGraph->get_num_nodes() > 2)
				draw_instructions_text(zmul, pd, gltarget);

			if (!isAnimated() || replayState == ePaused)
			{
				if (clientState->should_show_external_symbols(zmul))
					show_external_symbol_labels(pd, gltarget);


				if (clientState->should_show_internal_symbols(zmul))
				{
					bool placeholders = clientState->should_show_placeholder_labels(zmul);
					show_internal_symbol_labels(pd, gltarget, placeholders);
				}
			}
			else
				if (clientState->config.showRisingAnimated && internalProtoGraph->active)
			{   //show label of extern we are blocked on
				//called in main thread

				node_data* n = internalProtoGraph->safe_get_node(lastMainNode.lastVertID);
				if (n && n->external)
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
						painter.setFont(clientState->instructionFont);
						const QFontMetrics fm(clientState->instructionFont);

						TEXTRECT mouseoverNode;
						bool hasMouseover;
						hasMouseover = gltarget.getMouseoverNode(&mouseoverNode);

						if (hasMouseover && mouseoverNode.index == n->index)
							painter.setPen(al_col_orange);
						else
							painter.setPen(al_col_red);

						draw_func_args(&painter, screenCoord, n, gltarget, &fm);
						painter.end();
					}
				}
			}

			setGraphBusy(false, 82);
		}


		int drawCurve(GraphDisplayData* linedata, FCOORD &startC, FCOORD &endC,
			QColor &colour, int edgeType, GRAPH_SCALE* dimensions, long* arraypos)
        {
			//describe the normal
			FCOORD middleC;
			midpoint(startC, endC, &middleC);
			float eLen = linedist(startC, endC);

			FCOORD bezierC;
			int curvePoints;

			switch (edgeType)
			{
				case eEdgeNew:
					{
						//todo: make this number much smaller for previews
						curvePoints = eLen < 50 ? 1 : LONGCURVEPTS;
						bezierC = middleC;
						break;
					}

				case eEdgeOld:
				case eEdgeReturn:
					{
						curvePoints = LONGCURVEPTS;

						if (eLen < 2)
							bezierC = middleC;
						else
						{
							float oldMidA, oldMidB;
							bezierC = middleC;

							//calculate the AB coords of the midpoint of the cylinder
							getCylinderCoordAB(middleC, dimensions, &oldMidA, &oldMidB);
							float curveMagnitude = min(eLen / 2, (float)(dimensions->plotSize / 2));
							//recalculate the midpoint coord as if it was inside the cylinder
							cylinderCoord(oldMidA, oldMidB, &bezierC, dimensions, -curveMagnitude);

							//i dont know why this problem happens or why this fixes it
							//todo: is this still an issue?
							if ((bezierC.x > 0) && (startC.x < 0 && endC.x < 0))
								bezierC.x = -bezierC.x;
						}
						break;
					}

				case eEdgeCall:
				case eEdgeLib:
				case eEdgeException:
					{
						curvePoints = LONGCURVEPTS;
						bezierC = middleC;
						break;
					}

				default:
					cerr << "[rgat]Error: Drawcurve unknown edgeType " << edgeType << endl;
					return 0;
			}

			switch (curvePoints)
			{
				case LONGCURVEPTS:
					{
						int vertsdrawn = linedata->drawLongCurvePoints(bezierC, startC, endC, colour, edgeType, arraypos);
						return vertsdrawn;
					}

				case 1:
					linedata->drawShortLinePoints(startC, endC, colour, arraypos);
					return 2;

				default:
					cerr << "[rgat]Error: Drawcurve unknown curvePoints " << curvePoints << endl;
			}

			return curvePoints;
		}

		/*
		void write_rising_externs(PROJECTDATA* pd, graphGLWidget &gltarget)
		{
			DCOORD nodepos;

	vector <pair<NODEINDEX, EXTTEXT>> displayNodeList;

	//make labels rise up screen, delete those that reach top
	internalProtoGraph->externCallsLock.lock();
	map <NODEINDEX, EXTTEXT>::iterator activeExternIt = activeExternTimes.begin();
	for (; activeExternIt != activeExternTimes.end(); ++activeExternIt)
	{
		EXTTEXT *extxt = &activeExternIt->second;

		if (extxt->framesRemaining != KEEP_BRIGHT)
		{
			extxt->yOffset += (float)EXTERN_FLOAT_RATE;

			if (extxt->framesRemaining-- == 0)
			{
				activeExternIt = activeExternTimes.erase(activeExternIt);
				if (activeExternIt == activeExternTimes.end())
					break;
				else
					continue;
			}
		}
		displayNodeList.push_back(make_pair(activeExternIt->first, activeExternIt->second));;
	}
	internalProtoGraph->externCallsLock.unlock();

	if (displayNodeList.empty()) return;

	QPainter painter(&gltarget);
	painter.setPen(clientState->config.mainColours.symbolTextExternalRising);
	painter.setFont(clientState->instructionFont);
	int windowHeight = gltarget.height();



	vector <pair<NODEINDEX, EXTTEXT>>::iterator displayNodeListIt = displayNodeList.begin();
	for (; displayNodeListIt != displayNodeList.end(); ++displayNodeListIt)
	{
		internalProtoGraph->getNodeReadLock();
		CYLINDERCOORD *coord = get_node_coord(displayNodeListIt->first);
		internalProtoGraph->dropNodeReadLock();

		EXTTEXT *extxt = &displayNodeListIt->second;

		if (clientState->showNearSide && !a_coord_on_screen(coord->a, 1))
			continue;

		if (!get_screen_pos(displayNodeListIt->first, mainnodesdata, pd, &nodepos))
			continue;

		painter.drawText(nodepos.x, windowHeight - nodepos.y - extxt->yOffset, extxt->displayString.c_str());
	}

	painter.end();
		}
		
		void positionVert(void* positionStruct, node_data* n, PLOT_TRACK* lastNode);
		CYLINDERCOORD* get_node_coord(NODEINDEX idx);
		bool get_screen_pos(NODEINDEX nodeIndex, GraphDisplayData* vdata, PROJECTDATA* pd, DCOORD* screenPos);
		bool a_coord_on_screen(int a, float hedgesep);
		void cylinderCoord(CYLINDERCOORD* sc, FCOORD* c, GRAPH_SCALE* dimensions, float diamModifier = 0);
		void cylinderCoord(float a, float b, FCOORD* c, GRAPH_SCALE* dimensions, float diamModifier);
		void getCylinderCoordAB(FCOORD &c, GRAPH_SCALE* dimensions, float* a, float* b);
		void getCylinderCoordAB(DCOORD &c, GRAPH_SCALE* dimensions, float* a, float* b);

		void add_to_callstack(bool isPreview, MEM_ADDRESS address, NODEINDEX idx);

		private:
	int wireframe_loop_count = 0;
		GraphDisplayData* wireframe_data = NULL;
		GLuint wireframeVBOs[2];
		bool staleWireframe = false;
		bool wireframeBuffersCreated = false;
		vector<GLint> wireframeStarts, wireframeSizes;

		vector<CYLINDERCOORD> node_coords_storage;
		vector<CYLINDERCOORD>* node_coords = &node_coords_storage;

		//these are the edges/nodes that are brightend in the animation
		map<NODEPAIR, edge_data*> activeEdgeMap;
		//<index, final (still active) node>
		map<NODEINDEX, bool> activeNodeMap;
		*/
	}
}
