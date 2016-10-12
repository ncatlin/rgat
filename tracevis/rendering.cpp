/*
Copyright 2016 Nia Catlin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Miscellaneous graphics routines that don't fit into the graph class
*/

#include "stdafx.h"
#include "rendering.h"
#include "OSspecific.h"

//plot wireframe/colpick sphere in memory if they dont exist
//+draw wireframe
void maintain_draw_wireframe(VISSTATE *clientState, GLint *wireframeStarts, GLint *wireframeSizes)
{
	if (clientState->remakeWireframe)
	{
		delete clientState->wireframe_sphere;
		clientState->wireframe_sphere = 0;
		clientState->remakeWireframe = false;
	}

	if (!clientState->wireframe_sphere)
	{
		plot_wireframe(clientState);
		plot_colourpick_sphere(clientState);
	}

	draw_wireframe(clientState, wireframeStarts, wireframeSizes);
}

//must be called by main opengl context thread
void plot_wireframe(VISSTATE *clientState)
{
	clientState->wireframe_sphere = new GRAPH_DISPLAY_DATA(WFCOLBUFSIZE * 2);
	ALLEGRO_COLOR *wireframe_col = &clientState->config->wireframe.edgeColor;
	float cols[4] = { wireframe_col->r , wireframe_col->g, wireframe_col->b, wireframe_col->a };

	int ii, pp;
	long diam = clientState->activeGraph->m_scalefactors->radius;
	const int points = WF_POINTSPERLINE;

	int lineDivisions = (int)(360 / WIREFRAMELOOPS);
	GRAPH_DISPLAY_DATA *wireframe_data = clientState->wireframe_sphere;
	
	vector <float> *vpos = wireframe_data->acquire_pos_write(234);
	vector <float> *vcol = wireframe_data->acquire_col_write();
	for (ii = 0; ii < 180; ii += lineDivisions) {

		float ringSize = diam * sin((ii*M_PI) / 180);
		for (pp = 0; pp < WF_POINTSPERLINE; ++pp) {

			float angle = (2 * M_PI * pp) / WF_POINTSPERLINE;
			vpos->push_back(ringSize * cos(angle)); //x
			vpos->push_back(diam * cos((ii*M_PI) / 180)); //y
			vpos->push_back(ringSize * sin(angle)); //z

			vcol->insert(vcol->end(), cols, end(cols));
		}
	}

	for (ii = 0; ii < 180; ii += lineDivisions) {

		float degs2 = (ii*M_PI) / 180;
		for (pp = 0; pp < points; ++pp) {

			float angle = (2 * M_PI * pp) / points;
			float cosangle = cos(angle);
			vpos->push_back(diam * cosangle * cos(degs2));
			vpos->push_back(diam * sin(angle));
			vpos->push_back(diam * cosangle * sin(degs2));

			vcol->insert(vcol->end(), cols, end(cols));
		}
	}

	load_VBO(VBO_SPHERE_POS, clientState->wireframeVBOs, WFPOSBUFSIZE, &vpos->at(0));
	load_VBO(VBO_SPHERE_COL, clientState->wireframeVBOs, WFCOLBUFSIZE, &vcol->at(0));
	wireframe_data->release_pos_write();
	wireframe_data->release_col_write();
}

//draw basic opengl line between 2 points
void drawShortLinePoints(FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour, GRAPH_DISPLAY_DATA *vertdata, int *arraypos)
{
	vector <float> *vpos = vertdata->acquire_pos_write(52);
	vector <float> *vcol = vertdata->acquire_col_write();

	int numverts = vertdata->get_numVerts();
	*arraypos = vcol->size();

	vpos->push_back(startC->x);
	vpos->push_back(startC->y);
	vpos->push_back(startC->z);
	vcol->push_back(colour->r);
	vcol->push_back(colour->g);
	vcol->push_back(colour->b);
	vcol->push_back(colour->a);

	vpos->push_back(endC->x);
	vpos->push_back(endC->y);
	vpos->push_back(endC->z);
	vcol->push_back(colour->r);
	vcol->push_back(colour->g);
	vcol->push_back(colour->b);
	vcol->push_back(colour->a);

	vertdata->set_numVerts(numverts + 2);
	vertdata->release_pos_write();
	vertdata->release_col_write();

}

//draws a long curve with multiple vertices
int drawLongCurvePoints(FCOORD *bezierC, FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour,
	int edgeType, GRAPH_DISPLAY_DATA *vertdata, int curvePoints, int *colarraypos) {
	float fadeArray[] = { 1,0.9,0.8,0.7,0.5,0.3,0.3,0.3,0.2,0.2,0.2,
		0.3, 0.3, 0.5, 0.7, 0.9, 1 };

	int vsadded = 0;
	curvePoints += 2; 
	vector<GLfloat> *vertpos = vertdata->acquire_pos_write(63);
	vector<GLfloat> *vertcol = vertdata->acquire_col_write();

	if (!vertpos || !vertcol)
	{
		assert(0);
		return 0;
	}
	*colarraypos = vertcol->size();
	int ci = 0;
	int pi = 0;

	float cols[4] = { colour->r , colour->g, colour->b, 1 };

	vertpos->push_back(startC->x);
	vertpos->push_back(startC->y);
	vertpos->push_back(startC->z);
	
	vertcol->insert(vertcol->end(), cols, end(cols));
	++vsadded;
	// > for smoother lines, less performance
	int dt;
	float fadeA = 0.9;
	FCOORD resultC;

	int segments = float(curvePoints) / 2;
	for (dt = 1; dt < segments + 1; ++dt)
	{

		if ((edgeType == IOLD) || (edgeType == IRET)) {
			fadeA = fadeArray[dt - 1];
			if (fadeA > 1) fadeA = 1;
		}
		else
			fadeA = 0.9;
		cols[3] = fadeA;

		bezierPT(startC, bezierC, endC, dt, segments, &resultC);

		//end last line
		vertpos->push_back(resultC.x);
		vertpos->push_back(resultC.y);
		vertpos->push_back(resultC.z);
		vertcol->insert(vertcol->end(), cols, end(cols));
		++vsadded;

		//start new line at same point 
		//todo: this is waste of memory but far too much effort to fix for minimal gain
		vertpos->push_back(resultC.x);
		vertpos->push_back(resultC.y);
		vertpos->push_back(resultC.z);
		vertcol->insert(vertcol->end(), cols, end(cols));
		++vsadded;
	}

	vertpos->push_back(endC->x);
	vertpos->push_back(endC->y);
	vertpos->push_back(endC->z);
	++vsadded;
	cols[3] = 1;
	vertcol->insert(vertcol->end(), cols, end(cols));

	int numverts = vertdata->get_numVerts();

	vertdata->set_numVerts(numverts + curvePoints + 2);
	vertdata->release_col_write();
	vertdata->release_pos_write();

	return curvePoints + 2;
}

//connect two nodes with an edge of automatic number of vertices
int drawCurve(GRAPH_DISPLAY_DATA *linedata, FCOORD *startC, FCOORD *endC, 
	ALLEGRO_COLOR *colour, int edgeType, MULTIPLIERS *dimensions, int *arraypos)
{
	float r, b, g, a;
	r = colour->r;
	b = colour->b;
	g = colour->g;
	a = 1;

	//describe the normal
	FCOORD middleC;
	midpoint(startC, endC, &middleC);
	float eLen = linedist(startC, endC);

	FCOORD bezierC;
	int curvePoints;

	switch (edgeType)
	{
		case INEW:
		{
			//todo: make this number much smaller for previews
			curvePoints = eLen < 80 ? 1 : LONGCURVEPTS;
			bezierC = middleC;
			break;
		}

		case IRET:
		case IOLD:
		{
			curvePoints = LONGCURVEPTS;

			if (eLen < 2) 
				bezierC = middleC;
			else
			{
				float oldMidA, oldMidB;
				FCOORD bezierC2;
				sphereAB(&middleC, &oldMidA, &oldMidB, dimensions);
				sphereCoord(oldMidA, oldMidB, &bezierC, dimensions, -(eLen / 2));

				//i dont know why this problem happens or why this fixes it
				if ((bezierC.x > 0) && (startC->x < 0 && endC->x < 0))
					bezierC.x = -bezierC.x;
			}
			break;
		}

		case ICALL:
		case ILIB: 
		case IEXCEPT:
		{
			curvePoints = LONGCURVEPTS;
			bezierC = middleC;
			break;
		}

		default:
			cerr << "[rgat]Error: Drawcurve unknown edgeType " << edgeType << endl;
			return 0;
	}

	switch(curvePoints)
	{
		case LONGCURVEPTS:
		{
			int vertsdrawn = drawLongCurvePoints(&bezierC, startC, endC, colour, edgeType, linedata, curvePoints, arraypos);
			return vertsdrawn;
		}

		case 1:
			drawShortLinePoints(startC, endC, colour, linedata, arraypos);
			return 2;

		default:
			cerr << "[rgat]Error: Drawcurve unknown curvePoints " << curvePoints << endl;
	}

	return curvePoints;
}

//converts a single node into node vertex data
int add_node(node_data *n, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata, 
	MULTIPLIERS *dimensions, map<int, ALLEGRO_COLOR> *nodeColours)
{
	ALLEGRO_COLOR *active_col = 0;

	float adjustedB = n->vcoord.b + float(n->vcoord.bMod * BMODMAG);
	FCOORD screenc;
	sphereCoord(n->vcoord.a, adjustedB, &screenc, dimensions, 0);
	
	vector<GLfloat> *mainNpos = vertdata->acquire_pos_write(677);
	vector<GLfloat> *mainNcol = vertdata->acquire_col_write();

	mainNpos->push_back(screenc.x);
	mainNpos->push_back(screenc.y);
	mainNpos->push_back(screenc.z);

	if (n->external)
		active_col = &nodeColours->at(EXTERNAL);
	else {
		switch (n->ins->itype) 
		{
			case OPUNDEF:
				if (n->conditional)
					active_col = &nodeColours->at(JUMP);
				else 
					active_col = &nodeColours->at(NONFLOW);
				break;
			case OPJMP:
				active_col = &nodeColours->at(JUMP);
				break;
			case OPRET:
				active_col = &nodeColours->at(RETURN);
				break;
			case OPCALL:
				active_col = &nodeColours->at(CALL);
				break;
			//case ISYS: //todo: never used - intended for syscalls
			//	active_col = &al_col_grey;
			//	break;

			default:
				cerr << "[rgat]Error: add_node unknown itype " << n->ins->itype << endl;
				assert(0);
		}
	}

	mainNcol->push_back(active_col->r);
	mainNcol->push_back(active_col->g);
	mainNcol->push_back(active_col->b);
	mainNcol->push_back(1);

	vertdata->set_numVerts(vertdata->get_numVerts()+1);

	vertdata->release_col_write();
	vertdata->release_pos_write();

	//place node on the animated version of the graph
	if (!vertdata->isPreview())
	{

		vector<GLfloat> *animNcol = animvertdata->acquire_col_write();

		animNcol->push_back(active_col->r);
		animNcol->push_back(active_col->g);
		animNcol->push_back(active_col->b);
		animNcol->push_back(0);

		animvertdata->set_numVerts(vertdata->get_numVerts() + 1);
		animvertdata->release_col_write();
	}

	return 1;
}

void performMainGraphDrawing(VISSTATE *clientState, map <PID_TID, vector<EXTTEXT>> *externFloatingText)
{
	thread_graph_data *graph = clientState->activeGraph;
	assert(graph->pid == clientState->activePid->PID);

	//add any new logged calls to the call log window
	if (clientState->textlog && clientState->logSize < graph->loggedCalls.size())
		clientState->logSize = graph->fill_extern_log(clientState->textlog, clientState->logSize);

	//red line indicating last instruction
	if (!graph->basic)
		drawHighlight(graph->get_active_node_coord(), graph->m_scalefactors, &clientState->config->activityLineColour, 0);

	//green highlight lines
	if (clientState->highlightData.highlightState)
		graph->display_highlight_lines(&clientState->highlightData.highlightNodes,
			&clientState->config->highlightColour, clientState->config->highlightProtrusion);

	if (clientState->modes.heatmap)
	{
		display_big_heatmap(clientState);
		return;
	}

	if (clientState->modes.conditional)
	{
		display_big_conditional(clientState);
		return;
	}

	PROJECTDATA pd;
	gather_projection_data(&pd);
	display_graph(clientState, graph, &pd);
	graph->draw_externTexts(clientState->standardFont, clientState->modes.nearSide,
		clientState->leftcolumn, clientState->rightcolumn, clientState->mainFrameSize.height, &pd);
}

//takes node data generated from trace, converts to opengl point locations/colours placed in vertsdata
int draw_new_nodes(thread_graph_data *graph, GRAPH_DISPLAY_DATA *vertsdata, map<int, ALLEGRO_COLOR> *nodeColours) {
	
	MULTIPLIERS *scalefactors = vertsdata->isPreview() ? graph->p_scalefactors : graph->m_scalefactors;

	int nodeIdx = 0;
	int nodeEnd = graph->get_num_nodes();
	if (nodeIdx == nodeEnd) return 0;
	nodeIdx += vertsdata->get_numVerts();

	if (nodeIdx == nodeEnd) return 0;
	int maxVerts = 50;
	for (; nodeIdx != nodeEnd; ++nodeIdx)
	{
		int retries = 0;
		while (!add_node(graph->get_node(nodeIdx), vertsdata, graph->animnodesdata, scalefactors, nodeColours))
			{
					//think mutexes fixes have made this irrelevant
					Sleep(50);
					if (retries++ > 25)
						cerr<< "[rgat]MUTEX BLOCKAGE?" << endl;
			}
			if (!maxVerts--)break;
	}
	return 1;
}


//rescale all drawn verts to sphere of new diameter by altering the vertex data
void rescale_nodes(thread_graph_data *graph, bool isPreview) {

	MULTIPLIERS *scalefactors = isPreview ? graph->p_scalefactors : graph->m_scalefactors;

	GRAPH_DISPLAY_DATA *vertsdata;
	unsigned long targetIdx, nodeIdx;

	if (isPreview)
	{
		nodeIdx = 0;
		vertsdata = graph->get_previewnodes();
		targetIdx = vertsdata->get_numVerts();
	}
	else
	{
		//only resize 250 nodes per call to stop it hanging
		nodeIdx = graph->vertResizeIndex;
		graph->vertResizeIndex += 250;
		vertsdata = graph->get_mainnodes();
		targetIdx = min(graph->vertResizeIndex, vertsdata->get_numVerts());
		if (targetIdx == vertsdata->get_numVerts()) graph->vertResizeIndex = 0;		
	}
	
	if (!targetIdx) return;
	
	GLfloat *vpos = &vertsdata->acquire_pos_write(152)->at(0);

	for (; nodeIdx != targetIdx; ++nodeIdx)
	{
		node_data *n = graph->locked_get_node(nodeIdx);
		FCOORD newCoord = n->sphereCoordB(scalefactors, 0);
		assert(nodeIdx == n->index);

		const int arrayIndex = nodeIdx * POSELEMS;
		vpos[arrayIndex + XOFF] = newCoord.x;
		vpos[arrayIndex + YOFF] = newCoord.y;
		vpos[arrayIndex + ZOFF] = newCoord.z;
	}

	vertsdata->release_pos_write();
}

//reads the list of nodes/edges, creates opengl vertex/colour data
//resizes when it wraps too far around the sphere (lower than lowB, farther than farA)
void render_static_graph(thread_graph_data *graph, VISSTATE *clientState)
{

	if (!graph) return;
	bool doResize = false;
	if (clientState->rescale)
	{
		recalculate_scale(graph->m_scalefactors);
		recalculate_scale(graph->p_scalefactors);
		clientState->rescale = false;
		doResize = true;
	}

	if (clientState->autoscale)
	{
		//doesn't take bmod into account
		//keeps graph away from the south pole
		int lowestPoint = graph->maxB * graph->m_scalefactors->VEDGESEP;
		if (lowestPoint > clientState->config->lowB)
		{
			float startB = lowestPoint;
			while (lowestPoint > clientState->config->lowB)
			{
				graph->m_scalefactors->userVEDGESEP *= 0.98;
				graph->p_scalefactors->userVEDGESEP *= 0.98;
				recalculate_scale(graph->m_scalefactors);
				lowestPoint = graph->maxB * graph->m_scalefactors->VEDGESEP;
			}
			//cout << "[rgat]Max B coord too high, shrinking graph vertically from "<< startB <<" to "<< lowestPoint << endl;

			recalculate_scale(graph->p_scalefactors);
			doResize = true;
			graph->vertResizeIndex = 0;
		}

		//more straightforward, stops graph from wrapping around the globe
		int widestPoint = graph->maxA * graph->m_scalefactors->HEDGESEP;
		if (widestPoint > clientState->config->farA)
		{
			float startA = widestPoint;
			while (widestPoint > clientState->config->farA)
			{
				graph->m_scalefactors->userHEDGESEP *= 0.99;
				graph->p_scalefactors->userHEDGESEP *= 0.99;
				recalculate_scale(graph->m_scalefactors);
				widestPoint = graph->maxB * graph->m_scalefactors->HEDGESEP;
			}
			//cout << "[rgat]Max A coord too wide, shrinking graph horizontally from " << startA << " to " << widestPoint << endl;
			recalculate_scale(graph->p_scalefactors);
			doResize = true;
			graph->vertResizeIndex = 0;
		}
	}

	if (doResize) graph->previewNeedsResize = true;

	if (doResize || graph->vertResizeIndex > 0)
	{
		rescale_nodes(graph, false);
		
		
		graph->zoomLevel = graph->m_scalefactors->radius;
		graph->needVBOReload_main = true;

		if (clientState->wireframe_sphere)
			clientState->remakeWireframe = true;
	}

	int drawCount = draw_new_nodes(graph, graph->get_mainnodes(), &clientState->config->graphColours.nodeColours);
	if (drawCount < 0)
	{
		cerr << "[rgat]Error: render_main_graph failed drawing nodes" << endl;
		return;
	}
	if (drawCount)
		graph->needVBOReload_main = true;

	graph->render_new_edges(doResize, &clientState->config->graphColours.lineColours);
	graph->redraw_anim_edges();
}

//renders edgePerRender edges of graph onto the preview data
int draw_new_preview_edges(VISSTATE* clientState, thread_graph_data *graph)
{
	//draw edges
	EDGELIST::iterator edgeIt, edgeEnd;
	//todo, this should be done without the mutex using indexing instead of iteration
	graph->start_edgeL_iteration(&edgeIt, &edgeEnd);

	std::advance(edgeIt, graph->previewlines->get_renderedEdges());
	if (edgeIt != edgeEnd)
		graph->needVBOReload_preview = true;

	int remainingEdges = clientState->config->preview.edgesPerRender;
	map<int, ALLEGRO_COLOR> *lineColours = &clientState->config->graphColours.lineColours;
	
	for (; edgeIt != edgeEnd; ++edgeIt)
	{
		graph->render_edge(*edgeIt, graph->previewlines, lineColours, 0, true);
		graph->previewlines->inc_edgesRendered();
		if (!remainingEdges--)break;
	}
	graph->stop_edgeL_iteration();
	return 1;
}

//should be same as rendering for main graph but - the animation + more pauses instead of all at once
int render_preview_graph(thread_graph_data *previewGraph, VISSTATE *clientState)
{
	bool doResize = false;
	previewGraph->needVBOReload_preview = true;

	if (previewGraph->previewNeedsResize)
	{
		rescale_nodes(previewGraph, true);
		previewGraph->previewlines->reset();
		previewGraph->previewNeedsResize = false;

	}

	int vresult = draw_new_nodes(previewGraph, previewGraph->previewnodes, &clientState->config->graphColours.nodeColours);
	if (vresult == -1)
	{
		cerr << "ERROR: Failed drawing new nodes in render_preview_graph! returned: "<< vresult << endl;
		assert(0);
	}

	if (!draw_new_preview_edges(clientState, previewGraph))
	{
		cerr << "ERROR: Failed drawing new edges in render_preview_graph! returned: " << vresult << endl;
		assert(0);
	}

	return 1;
}

//uninstrumented library calls
//draw text for quantity + symbol + argument indicator
void draw_func_args(VISSTATE *clientState, ALLEGRO_FONT *font, DCOORD screenCoord, node_data *n)
{
	if (clientState->activeGraph->externList.empty()) return;

	string modPath;
	clientState->activePid->get_modpath(n->nodeMod, &modPath);

	stringstream argstring;
	if (clientState->show_extern_text == EXTERNTEXT_ALL)
		argstring << modPath << ":";

	int numCalls = n->calls;
	string symString;
	clientState->activePid->get_sym(n->nodeMod,n->address,&symString);

	//todo: might be better to find the first symbol in the DLL that has a lower address
	if (symString.empty())
		argstring << basename(modPath) << ":0x" << std::hex << n->address;

	if (numCalls > 1)
		argstring << symString;
	else
		argstring << n->calls << "x " << symString;

	obtainMutex(clientState->activeGraph->funcQueueMutex,3521);
	if (n->funcargs.empty()) 
		argstring << " ()";
	else
		{
			//TODO: crash here with argIt->second or first == <NULL>. 
			//not sure why because funcargs accesses seem to be guarded
			try 
			{

					argstring << " (";
					vector<ARGIDXDATA> *args = &n->funcargs.at(0);
					vector<ARGIDXDATA>::iterator argIt = args->begin();

					while (argIt != args->end())
					{
							argstring << argIt->first << ": " << argIt->second;
							++argIt;
					}
			}
			catch (std::exception const & e) {
				cerr << "[rgat]Warning: Known argument handling race encountered. Ignoring." << endl;
			}

			int remainingCalls = n->funcargs.size() - 1;
			if (remainingCalls)
				argstring << ") +" << remainingCalls << "saved";
			else
				argstring << ")";
		}
	dropMutex(clientState->activeGraph->funcQueueMutex);
	
	al_draw_text(font, al_col_white, screenCoord.x + INS_X_OFF,
		clientState->mainFrameSize.height - screenCoord.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
		argstring.str().c_str());

}

//show functions/args for externs in active graph
void show_extern_labels(VISSTATE *clientState, PROJECTDATA *pd, thread_graph_data *graph)
{
	GRAPH_DISPLAY_DATA *mainverts = graph->get_mainnodes();

	//todo: maintain local copy, update on size change?
	obtainMutex(graph->highlightsMutex, 1052);
	vector<unsigned int> externListCopy = graph->externList;
	dropMutex(graph->highlightsMutex);

	vector<unsigned int>::iterator externCallIt = externListCopy.begin();
	for (; externCallIt != externListCopy.end(); ++externCallIt)
	{
		node_data *n = graph->get_node(*externCallIt);
		assert(n->external);

		DCOORD screenCoord;
		if (!n->get_screen_pos(mainverts, pd, &screenCoord)) continue;

		if (clientState->modes.nearSide)
		{
			if(!a_coord_on_screen(n->vcoord.a, clientState->leftcolumn,
				clientState->rightcolumn, graph->m_scalefactors->HEDGESEP))
				continue;
		}

		if (is_on_screen(&screenCoord, clientState))
			draw_func_args(clientState, clientState->standardFont, screenCoord, n);
	}
}


//iterate through all the nodes, draw instruction text for the ones in view
void draw_instruction_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd, thread_graph_data *graph)
{

	//iterate through nodes looking for ones that map to screen coords
	glBindBuffer(GL_ARRAY_BUFFER, 0);

	bool show_all_always = (clientState->show_ins_text == INSTEXT_ALL_ALWAYS);
	unsigned int numVerts = graph->get_num_nodes();
	GRAPH_DISPLAY_DATA *mainverts = graph->get_mainnodes();
	stringstream ss;
	DCOORD screenCoord;
	string itext("?");
	for (unsigned int i = 0; i < numVerts; ++i)
	{
		node_data *n = graph->get_node(i);
		if (n->external) continue;

		//this check removes the bulk of the instructions at a low performance cost, including those
		//on screen but on the other side of the sphere
		//implementation is tainted by a horribly derived constant that sometimes rules out nodes on screen
		//bypass by turning instruction display always on
		if (!show_all_always && !a_coord_on_screen(n->vcoord.a, clientState->leftcolumn,
			clientState->rightcolumn, graph->m_scalefactors->HEDGESEP))
			continue;

		if (!n->get_screen_pos(mainverts, pd, &screenCoord)) continue; //in graph but not rendered
		if (screenCoord.x > clientState->mainFrameSize.width || screenCoord.x < -100) continue;
		if (screenCoord.y > clientState->mainFrameSize.height || screenCoord.y < -100) continue;

		if (!show_all_always) 
		{
			if (zdist < 5 && clientState->show_ins_text == INSTEXT_AUTO)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}

		ss << std::dec << n->index << "-0x" << std::hex << n->ins->address << ":" << itext;
		al_draw_text(clientState->standardFont, al_col_white, screenCoord.x + INS_X_OFF,
			clientState->mainFrameSize.height - screenCoord.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
			ss.str().c_str());
		ss.str("");
	}
}

//only draws text for instructions with unsatisfied conditions
void draw_condition_ins_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata)
{
	thread_graph_data *graph = (thread_graph_data *)clientState->activeGraph;
	//iterate through nodes looking for ones that map to screen coords
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	bool show_all_always = (clientState->show_ins_text == INSTEXT_ALL_ALWAYS);
	unsigned int numVerts = vertsdata->get_numVerts();
	GLfloat *vcol = vertsdata->readonly_col();
	for (unsigned int i = 0; i < numVerts; ++i)
	{
		node_data *n = graph->get_node(i);
		if (n->external || !n->ins->conditional) continue;

		if (!a_coord_on_screen(n->vcoord.a, clientState->leftcolumn, clientState->rightcolumn,
			graph->m_scalefactors->HEDGESEP)) continue;

		//todo: experiment with performance re:how much of these checks to include
		DCOORD screenCoord;
		if (!n->get_screen_pos(vertsdata, pd, &screenCoord)) continue;
		if (screenCoord.x > clientState->mainFrameSize.width || screenCoord.x < -100) continue;
		if (screenCoord.y > clientState->mainFrameSize.height || screenCoord.y < -100) continue;

		const int vectNodePos = n->index*COLELEMS;
		ALLEGRO_COLOR textcol;
		textcol.r = vcol[vectNodePos + ROFF];
		textcol.g = vcol[vectNodePos + GOFF];
		textcol.b = vcol[vectNodePos + BOFF];
		textcol.a = 1;

		string itext;
		if (!show_all_always) {
			float nB = n->vcoord.b + n->vcoord.bMod*BMODMAG;

			if (zdist < 5 && clientState->show_ins_text == INSTEXT_AUTO)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}
		else itext = "?";

		stringstream ss;
		ss << "0x" << std::hex << n->ins->address << ": " << itext;
		al_draw_text(clientState->standardFont, textcol, screenCoord.x + INS_X_OFF,
			clientState->mainFrameSize.height - screenCoord.y + 12, ALLEGRO_ALIGN_LEFT,
			ss.str().c_str());
	}
}

//draw number of times each edge has been executed in middle of edge
void draw_edge_heat_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd)
{
	thread_graph_data *graph = (thread_graph_data *)clientState->activeGraph;
	
	glBindBuffer(GL_ARRAY_BUFFER, 0);//need this to make text work
	GRAPH_DISPLAY_DATA *vertsdata = graph->get_mainnodes();

	//iterate through nodes looking for ones that map to screen coords
	int edgelistIdx = 0;
	int edgelistEnd = graph->heatmaplines->get_renderedEdges();

	set <node_data *> displayNodes;

	EDGELIST *edgelist = graph->edgeLptr();
	for (; edgelistIdx < edgelistEnd; ++edgelistIdx)
	{
		NODEPAIR *ePair = &edgelist->at(edgelistIdx);
		node_data *firstNode = graph->get_node(ePair->first);

		//should these checks should be done on the midpoint rather than the first node?
		if (firstNode->external) continue; //don't care about instruction in library call
		if (!a_coord_on_screen(firstNode->vcoord.a, clientState->leftcolumn,
			clientState->rightcolumn, graph->m_scalefactors->HEDGESEP))
			continue;

		edge_data *e = graph->get_edge(*ePair);
		if (!e) {
			cerr<< "[rgat]WARNING: Heatmap edge skip"<<endl; 
			continue;
		}

		DCOORD screenCoordA;
		if(!firstNode->get_screen_pos(vertsdata, pd, &screenCoordA)) continue;

		if (ePair->second >= graph->get_num_nodes()) continue;
		DCOORD screenCoordB;
		if(!graph->get_node(ePair->second)->get_screen_pos(vertsdata, pd, &screenCoordB)) continue;

		DCOORD screenCoordMid;
		midpoint(&screenCoordA, &screenCoordB, &screenCoordMid);

		if (screenCoordMid.x > clientState->mainFrameSize.width || screenCoordMid.x < -100) continue;
		if (screenCoordMid.y > clientState->mainFrameSize.height || screenCoordMid.y < -100) continue;

		displayNodes.insert(firstNode);
		displayNodes.insert(graph->get_node(ePair->second));

		//int edgeWeight = e->weight;
		unsigned long edgeWeight = e->chainedWeight;
		if (edgeWeight < 2) continue;

		string weightString = to_string(edgeWeight);
		al_draw_text(clientState->standardFont, clientState->config->heatmap.lineTextCol, screenCoordMid.x + INS_X_OFF,
			clientState->mainFrameSize.height - screenCoordMid.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
			weightString.c_str());
	}

	set <node_data *>::iterator nodesIt = displayNodes.begin();
	for (; nodesIt != displayNodes.end(); ++nodesIt)
	{
		node_data *nd = *nodesIt;
		DCOORD screenCoordN;
		if (!nd->get_screen_pos(vertsdata, pd, &screenCoordN)) continue; //in graph but not rendered

		al_draw_text(clientState->standardFont, al_col_white, screenCoordN.x + INS_X_OFF,
			clientState->mainFrameSize.height - screenCoordN.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
			to_string(nd->executionCount).c_str());

	}


}


//standard animated or static display of the active graph
void display_graph(VISSTATE *clientState, thread_graph_data *graph, PROJECTDATA *pd)
{
	if (clientState->modes.animation && !graph->basic)
		graph->display_active(clientState->modes.nodes, clientState->modes.edges);
	else
		graph->display_static(clientState->modes.nodes, clientState->modes.edges);

	float zmul = zoomFactor(clientState->cameraZoomlevel, graph->m_scalefactors->radius);
	
	if (clientState->show_ins_text && zmul < INSTEXT_VISIBLE_ZOOMFACTOR && graph->get_num_nodes() > 2)
		draw_instruction_text(clientState, zmul, pd, graph);
	
	//if zoomed in, show all extern labels
	if (zmul < EXTERN_VISIBLE_ZOOM_FACTOR && clientState->show_extern_text != EXTERNTEXT_NONE)
		show_extern_labels(clientState, pd, graph);
	else
	{	//show label of extern we are blocked on
		node_data *n = graph->get_node(graph->latest_active_node_idx);
		if (n && n->external)
		{
			DCOORD screenCoord;
			if (!n->get_screen_pos(graph->get_mainnodes(), pd, &screenCoord)) return;
			if (is_on_screen(&screenCoord, clientState))
				draw_func_args(clientState, clientState->standardFont, screenCoord, n);
		}
	}
}

//displays the divergence of two selected graphs, defined in differenderer
void display_graph_diff(VISSTATE *clientState, diff_plotter *diffRenderer) {
	thread_graph_data *graph1 = diffRenderer->get_graph(1);
	thread_graph_data *diffgraph = diffRenderer->get_diff_graph();
	GRAPH_DISPLAY_DATA *vertsdata = graph1->get_mainnodes();
	GRAPH_DISPLAY_DATA *linedata = graph1->get_mainlines();

	if (graph1->needVBOReload_main)
	{
		loadVBOs(graph1->graphVBOs, vertsdata, linedata);
		graph1->needVBOReload_main = false;
	}

	if (diffgraph->needVBOReload_main)
	{
		load_edge_VBOS(diffgraph->graphVBOs, diffgraph->get_mainlines());
		diffgraph->needVBOReload_main = false;
	}

	if (clientState->modes.nodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graph1->graphVBOs, vertsdata->get_numVerts());

	if (clientState->modes.edges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, diffgraph->graphVBOs, linedata->get_numVerts());

	float zmul = zoomFactor(clientState->cameraZoomlevel, graph1->m_scalefactors->radius);

	PROJECTDATA pd;
	bool pdgathered = false;
	if (zmul < EXTERN_VISIBLE_ZOOM_FACTOR)
	{
		gather_projection_data(&pd);
		pdgathered = true;
		show_extern_labels(clientState, &pd, graph1);
	}

	if (clientState->show_ins_text && zmul < INSTEXT_VISIBLE_ZOOMFACTOR && graph1->get_num_nodes() > 2)
	{
		if (!pdgathered) 
			gather_projection_data(&pd);
		draw_instruction_text(clientState, zmul, &pd, graph1);
	}
}

void draw_heatmap_key_blocks(VISSTATE *clientState, int x, int y)
{
	for (int i = 0; i < 10; ++i)
	{
		int qx = x + i*HEATMAP_KEY_SQUARESIZE;
		ALLEGRO_COLOR *c = &clientState->config->heatmap.edgeFrequencyCol[i];
		glBegin(GL_QUADS);
		glColor4f(c->r, c->g, c->b, c->a);
		glVertex3f(qx, y, 0);
		glVertex3f(qx + HEATMAP_KEY_SQUARESIZE, y, 0);
		glVertex3f(qx + HEATMAP_KEY_SQUARESIZE, y + HEATMAP_KEY_SQUARESIZE, 0);
		glVertex3f(qx, y + HEATMAP_KEY_SQUARESIZE, 0);
		glVertex3f(qx, y, 0);
		glEnd();
	}
}

#define HEATKEY_POS_Y 40
void draw_heatmap_key(VISSTATE *clientState)
{
	if (!clientState->activeGraph) return; 
	int keyx = clientState->mainFrameSize.width - (10 * HEATMAP_KEY_SQUARESIZE + 70);
	

	stringstream keytext;
	keytext << "Frequency:  " << clientState->activeGraph->heatExtremes.second;
	const std::string& ks = keytext.str();
	int ksWidth = al_get_text_width(clientState->standardFont, ks.c_str()) + 8;
	al_draw_text(clientState->standardFont, al_col_white, keyx - ksWidth, HEATKEY_POS_Y, 0, ks.c_str());

	draw_heatmap_key_blocks(clientState, keyx, HEATKEY_POS_Y-8);

	string keyend = to_string(clientState->activeGraph->heatExtremes.first);
	al_draw_text(clientState->standardFont, al_col_white, keyx + 10 * HEATMAP_KEY_SQUARESIZE + 8, HEATKEY_POS_Y, 0, keyend.c_str());
}

void draw_conditional_key(VISSTATE *clientState)
{
	if (!clientState->activeGraph) return;
	ALLEGRO_FONT *font = clientState->standardFont;
	stringstream keytextA, keytextN;
	keytextA << "Always Taken (" << clientState->activeGraph->condCounts.first << ")";
	keytextN << "Never Taken (" << clientState->activeGraph->condCounts.second << ")";
	int width1 = al_get_text_width(font, keytextA.str().c_str());
	int width2 = al_get_text_width(font, keytextN.str().c_str());

	int drawX = clientState->mainFrameSize.width - (max(width1, width2) + 8);
	int drawY = MAIN_FRAME_Y;
	al_draw_text(font, clientState->config->conditional.cond_succeed, drawX, drawY, 0, keytextA.str().c_str());
	drawY += al_get_font_line_height(font);
	al_draw_text(font, clientState->config->conditional.cond_fail, drawX, drawY, 0, keytextN.str().c_str());
	
}

//displays heatmap of the active graph
void display_big_heatmap(VISSTATE *clientState)
{
	thread_graph_data *graph = (thread_graph_data *)clientState->activeGraph;
	if (!graph->heatmaplines) return;

	if (graph->needVBOReload_heatmap)
	{
		if (!graph->heatmaplines->get_numVerts()) return;
		load_VBO(0, graph->heatmapEdgeVBO,
			graph->heatmaplines->col_size(), graph->heatmaplines->readonly_col());
		graph->needVBOReload_heatmap = false;
	}

	GRAPH_DISPLAY_DATA *vertsdata = graph->get_mainnodes();
	GRAPH_DISPLAY_DATA *linedata = graph->get_mainlines();
	if (graph->needVBOReload_main)
	{
		loadVBOs(graph->graphVBOs, vertsdata, linedata);
		graph->needVBOReload_main = false;
	}

	if (clientState->modes.nodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graph->graphVBOs, vertsdata->get_numVerts());

	if (clientState->modes.edges)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_LINE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->heatmapEdgeVBO[0]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

		glDrawArrays(GL_LINES, 0, graph->heatmaplines->get_numVerts());
	}

	float zmul = zoomFactor(clientState->cameraZoomlevel, graph->m_scalefactors->radius);

	PROJECTDATA pd;
	gather_projection_data(&pd);

	if (zmul < EXTERN_VISIBLE_ZOOM_FACTOR)
		show_extern_labels(clientState, &pd, graph);

	if (clientState->show_ins_text && zmul < INSTEXT_VISIBLE_ZOOMFACTOR && graph->get_num_nodes() > 2)
		draw_edge_heat_text(clientState, zmul, &pd);


}

#define VBO_COND_NODE_COLOUR 0
#define VBO_COND_LINE_COLOUR 1
//displays the conditionals of the active graph
void display_big_conditional(VISSTATE *clientState)
{
	thread_graph_data *graph = (thread_graph_data *)clientState->activeGraph;
	if (!graph->conditionallines || !graph->conditionalnodes) return;

	if (graph->needVBOReload_conditional)
	{
		if (!graph->conditionalnodes->get_numVerts() || !graph->conditionallines->get_numVerts()) return;

		load_VBO(VBO_COND_NODE_COLOUR, graph->conditionalVBOs, 
			graph->conditionalnodes->col_size(), graph->conditionalnodes->readonly_col());
		load_VBO(VBO_COND_LINE_COLOUR, graph->conditionalVBOs, 
			graph->conditionallines->col_size(), graph->conditionallines->readonly_col());

		graph->needVBOReload_conditional = false;
	}

	if (graph->needVBOReload_main)
	{
		loadVBOs(graph->graphVBOs, graph->get_mainnodes(), graph->get_mainlines());
		graph->needVBOReload_main = false;
	}

	if (clientState->modes.nodes)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_NODE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[VBO_COND_NODE_COLOUR]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		glDrawArrays(GL_POINTS, 0, graph->conditionalnodes->get_numVerts());
	}

	if (clientState->modes.edges)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_LINE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[VBO_COND_LINE_COLOUR]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		glDrawArrays(GL_LINES, 0, graph->conditionallines->get_numVerts());

	}

	PROJECTDATA pd;
	gather_projection_data(&pd);
	float zoomDiffMult = (clientState->cameraZoomlevel - graph->zoomLevel) / 1000 - 1;

	if (clientState->show_ins_text && zoomDiffMult < 10 && graph->get_num_nodes() > 2)
		draw_condition_ins_text(clientState, zoomDiffMult, &pd, graph->get_mainnodes());

}

//draws a line from the center of the sphere to nodepos. adds lengthModifier to the end
void drawHighlight(VCOORD *nodepos, MULTIPLIERS *scale, ALLEGRO_COLOR *colour, int lengthModifier)
{
	FCOORD nodeCoord;
	float adjB = nodepos->b + float(nodepos->bMod * BMODMAG);
	sphereCoord(nodepos->a, adjB, &nodeCoord, scale, lengthModifier);
	drawHighlightLine(nodeCoord, colour);
}