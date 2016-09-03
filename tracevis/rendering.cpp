#include "stdafx.h"
#include "rendering.h"


//draw an outline sphere of size diam
//we could just memset the colours array but leaving it here for the sake of adapatbility
void plot_wireframe(VISSTATE *clientstate)
{
	ALLEGRO_COLOR *wireframe_col = &clientstate->config->wireframe.edgeColor;
	const int r = wireframe_col->r;
	const int g = wireframe_col->g;
	const int b = wireframe_col->b;
	const int a = wireframe_col->a;

	int ii, pp, index;
	long diam = clientstate->activeGraph->m_scalefactors->radius;
	const int points = WF_POINTSPERLINE;
	int numSphereCurves = 0;
	int lineDivisions = (int)(360 / WIREFRAMELOOPS);
	GRAPH_DISPLAY_DATA *wireframe_data = clientstate->wireframe_sphere;

	vector <float> *vpos = wireframe_data->acquire_pos("1c");
	vector <float> *vcol = wireframe_data->acquire_col("1c");
	for (ii = 0; ii < 180; ii += lineDivisions) {

		float ringSize = diam * sin((ii*M_PI) / 180);
		for (pp = 0; pp < WF_POINTSPERLINE; ++pp) {

			float angle = (2 * M_PI * pp) / WF_POINTSPERLINE;

			index = numSphereCurves * WF_POINTSPERLINE * POSELEMS + pp * POSELEMS;
			vpos->push_back(ringSize * cos(angle)); //x
			vpos->push_back(diam * cos((ii*M_PI) / 180)); //y
			vpos->push_back(ringSize * sin(angle)); //z

			index = numSphereCurves * WF_POINTSPERLINE * COLELEMS + pp * COLELEMS;
			vcol->push_back(r);
			vcol->push_back(g);
			vcol->push_back(b);
			vcol->push_back(a);
		}
		numSphereCurves += 1;
	}

	for (ii = 0; ii < 180; ii += lineDivisions) {

		float degs2 = (ii*M_PI) / 180;
		for (pp = 0; pp < points; ++pp) {

			float angle = (2 * M_PI * pp) / points;
			float cosangle = cos(angle);

			index = numSphereCurves * WF_POINTSPERLINE * POSELEMS + pp * POSELEMS;
			vpos->push_back(diam * cosangle * cos(degs2));
			vpos->push_back(diam * sin(angle));
			vpos->push_back(diam * cosangle * sin(degs2));

			index = numSphereCurves * WF_POINTSPERLINE * COLELEMS + pp * COLELEMS;
			vcol->push_back(r);
			vcol->push_back(g);
			vcol->push_back(b);
			vcol->push_back(a);
		}
		numSphereCurves += 1;
	}

	load_VBO(VBO_SPHERE_POS, clientstate->wireframeVBOs, WFPOSBUFSIZE, &vpos->at(0));
	load_VBO(VBO_SPHERE_COL, clientstate->wireframeVBOs, WFCOLBUFSIZE, &vcol->at(0));
	wireframe_data->release_pos();
	wireframe_data->release_col();
}

//draw basic opengl line between 2 points
void drawShortLinePoints(FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour, GRAPH_DISPLAY_DATA *vertdata, int *arraypos)
{

	vector <float> *vpos = vertdata->acquire_pos("1c");
	vector <float> *vcol = vertdata->acquire_col("1c");

	int numverts = vertdata->get_numVerts();

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
	vertdata->release_pos();
	vertdata->release_col();

}

int drawLongCurvePoints(FCOORD *bezierC, FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour,
	int edgeType, GRAPH_DISPLAY_DATA *vertdata, int curvePoints, int *colarraypos) {
	float fadeArray[] = { 1,0.9,0.8,0.7,0.5,0.3,0.3,0.3,0.2,0.2,0.2,
		0.3, 0.3, 0.5, 0.7, 0.9, 1 };

	int vsadded = 0;
	curvePoints += 2;
	vector<GLfloat> *vertpos = vertdata->acquire_pos("1b");
	vector<GLfloat> *vertcol = vertdata->acquire_col("1b");
	if (!vertpos || !vertcol) return 0;
	*colarraypos = vertcol->size();
	int ci = 0;
	int pi = 0;

	float cols[4] = { colour->r , colour->g, colour->b, 1 };

	vertpos->push_back(startC->x);
	vertpos->push_back(startC->y);
	vertpos->push_back(startC->z);
	
	vertcol->insert(vertcol->end(), cols, end(cols));
	vsadded++;
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
		vsadded++;
		//start new line at same point todo: this is waste of memory
		vertpos->push_back(resultC.x);
		vertpos->push_back(resultC.y);
		vertpos->push_back(resultC.z);
		vertcol->insert(vertcol->end(), cols, end(cols));
		vsadded++;
	}

	vertpos->push_back(endC->x);
	vertpos->push_back(endC->y);
	vertpos->push_back(endC->z);
	vsadded++;
	cols[3] = 1;
	vertcol->insert(vertcol->end(), cols, end(cols));

	int numverts = vertdata->get_numVerts();

	vertdata->set_numVerts(numverts + curvePoints + 2);
	vertdata->release_col();
	vertdata->release_pos();

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

	// describe the normal
	FCOORD middleC;
	midpoint(startC, endC, &middleC);
	float eLen = linedist(startC, endC);

	FCOORD bezierC;
	int curvePoints;

	switch (edgeType)
	{
		case INEW:
		{
			//todo: this number depends on the scale!
			curvePoints = eLen < 80 ? 1 : LONGCURVEPTS;
			bezierC = middleC;
			break;
		}
		case ICALL:
		{
			curvePoints = LONGCURVEPTS;
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

				// i dont know why this maths problem happens or why this fixes it
				// but at this point i'm too afraid to ask.
				if ((bezierC.x > 0) && (startC->x < 0 && endC->x < 0))
					bezierC.x = -bezierC.x;
			}
			break;
		}

		case ILIB: 
		{
			curvePoints = LONGCURVEPTS;
			bezierC = middleC;
			break;
		}

		default:
			printf("\t\t!!!unknown colour\n");
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
			printf("ERROR: unknown curvepoints %d\n", curvePoints);
	}

	return curvePoints;
}

int add_node(node_data *n, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata, MULTIPLIERS *dimensions)
{
	ALLEGRO_COLOR *active_col;

	float adjB = n->vcoord.b + float(n->vcoord.bMod * BMODMAG);
	FCOORD screenc;
	sphereCoord(n->vcoord.a, adjB, &screenc, dimensions, 0);

	vector<GLfloat> *mainNpos = vertdata->acquire_pos("334");
	vector<GLfloat> *mainNcol = vertdata->acquire_col("33f");
	vector<GLfloat> *animNcol = animvertdata->acquire_col("1e");
	if (!mainNpos || !mainNcol || !animNcol)
	{
		vertdata->release_pos();
		vertdata->release_col();
		animvertdata->release_col();
		return 0;
	}

	mainNpos->push_back(screenc.x);
	mainNpos->push_back(screenc.y);
	mainNpos->push_back(screenc.z);

	if (n->external)
		active_col = &al_col_green;
	else {
		switch (n->ins->itype) 
		{
			case OPUNDEF:
				if (n->conditional == NOTCONDITIONAL)
					active_col = &al_col_yellow;
				else 
					active_col = &al_col_red;
				break;
			case OPJMP:
				active_col = &al_col_red;
				break;
			case OPRET:
				active_col = &al_col_orange;
				break;
			case OPCALL:
				active_col = &al_col_purple;
				break;

			case ISYS: //todo: never used - intended for syscalls
				active_col = &al_col_grey;
				break;

			default:
				printf("ERROR: Unhandled add_Vert color: %c\n", n->ins->itype);
				return 0;
		}
	}

	mainNcol->push_back(active_col->r);
	mainNcol->push_back(active_col->g);
	mainNcol->push_back(active_col->b);
	mainNcol->push_back(1);

	vertdata->set_numVerts(vertdata->get_numVerts()+1);

	vertdata->release_col();
	vertdata->release_pos();

	animNcol->push_back(active_col->r);
	animNcol->push_back(active_col->g);
	animNcol->push_back(active_col->b);
	animNcol->push_back(0);

	animvertdata->set_numVerts(vertdata->get_numVerts()+1);
	animvertdata->release_col();

	return 1;
}

int draw_new_verts(thread_graph_data *graph, GRAPH_DISPLAY_DATA *vertsdata) {
	
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
	 while (!add_node(graph->get_node(nodeIdx), vertsdata, graph->animnodesdata, scalefactors))
		{
			Sleep(50);
			if (retries++ > 25)
				printf("MUTEX BLOCKAGE?\n");
		}
	 if (retries > 25)
		 printf("BLOCKAGE CLEARED\n");
	 if (!maxVerts--)break;
	}
	return 1;
}

//resize all drawn verts to new diameter
void resize_verts(thread_graph_data *graph, GRAPH_DISPLAY_DATA *vertsdata) {

	MULTIPLIERS *scalefactors = vertsdata->isPreview() ? graph->p_scalefactors : graph->m_scalefactors;

	int targetIdx = vertsdata->get_numVerts();
	printf("starting resize\n");
	GLfloat *vpos = &vertsdata->acquire_pos("334")->at(0);
	for (int nodeIdx = 0; nodeIdx != targetIdx; ++nodeIdx)
	{
		node_data *n = graph->get_node(nodeIdx);
		FCOORD c = n->sphereCoordB(scalefactors, 0);
		assert(nodeIdx == n->index);
		//todo get rid of equiv multiply
		const int arrayIndex = nodeIdx * POSELEMS;
		vpos[arrayIndex + XOFF] = c.x;
		vpos[arrayIndex + YOFF] = c.y;
		vpos[arrayIndex + ZOFF] = c.z;
	}
	
	vertsdata->release_pos();
}

int render_main_graph(VISSTATE *clientState)
{
	bool doResize = false;

	thread_graph_data *graph = (thread_graph_data*)clientState->activeGraph;

	if (clientState->rescale)
	{
		recalculate_scale(graph->m_scalefactors);
		clientState->rescale = false;
		doResize = true;
	}

	//doesn't take bmod into account
	//keeps graph away from the south pole
	int lowestPoint = graph->maxB * graph->m_scalefactors->VEDGESEP;
	if (lowestPoint > clientState->config->lowB)
	{
		while (lowestPoint > clientState->config->lowB)
		{
			graph->m_scalefactors->userVEDGESEP *= 0.99;
			recalculate_scale(graph->m_scalefactors);
			lowestPoint = graph->maxB * graph->m_scalefactors->VEDGESEP;
		}
		doResize = true;
	}

	//more straightforward, stops graph from wrapping around the globe
	unsigned int widestPoint = graph->maxA * graph->m_scalefactors->HEDGESEP;
	if (widestPoint > clientState->config->farA)
	{
		while (widestPoint > clientState->config->farA)
		{
			graph->m_scalefactors->userHEDGESEP *= 0.99;
			recalculate_scale(graph->m_scalefactors);
			widestPoint = graph->maxB * graph->m_scalefactors->HEDGESEP;
		}
		doResize = true;
	}

	if (doResize)
	{
		resize_verts(graph, graph->get_mainnodes());
		graph->zoomLevel = graph->m_scalefactors->radius;
		graph->needVBOReload_main = true;
	}

	int drawCount = draw_new_verts(graph, graph->get_mainnodes());
	if (drawCount < 0)
	{
		printf("\n\nFATAL 5: Failed drawing verts!\n\n");
		return 0;
	}
	if (drawCount)
		graph->needVBOReload_main = true;

	graph->render_new_edges(doResize, &clientState->config->graphColours.lineColours);
	return 1;
}

int draw_new_preview_edges(VISSTATE* clientState, thread_graph_data *graph)
{
	//draw edges
	EDGELIST::iterator edgeIt;
	EDGELIST::iterator edgeEnd;
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

int render_preview_graph(thread_graph_data *previewGraph, bool *rescale, VISSTATE *clientState)
{
	bool doResize = false;
		previewGraph->needVBOReload_preview = true;

	int vresult = draw_new_verts(previewGraph, previewGraph->previewnodes);
	if (vresult == -1)
	{
		printf("\n\nFATAL 5: Failed drawing new verts! returned:%d\n\n", vresult);
		return 0;
	}
	Sleep(10);

	vresult = draw_new_preview_edges(clientState, previewGraph);
	if (!vresult)
	{
		printf("\n\nFATAL 6: Failed drawing new edges! returned:%d\n\n", vresult);
		return 0;
	}
	return 1;
}

//uninstrumented library calls
//draw text for quantity + symbol + argument indicator
void draw_func_args(VISSTATE *clientstate, ALLEGRO_FONT *font, DCOORD screenCoord, node_data *n)
{
	stringstream argstring;
	int numCalls = n->calls;
	string symString = clientstate->activePid->modsyms[n->nodeMod][n->address];
	if (numCalls == 1)
		argstring << symString;
	else
		argstring << n->calls << "x " << symString;
	
	//if trace recorded some arguments
	if (n->funcargs.size()) 
		argstring << "(...)";
	else
		argstring << "()";
	
	al_draw_text(font, al_col_white, screenCoord.x + INS_X_OFF,
		clientstate->size.height - screenCoord.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
		argstring.str().c_str());

}

void show_extern_labels(VISSTATE *clientstate, PROJECTDATA *pd, thread_graph_data *graph)
{
	GRAPH_DISPLAY_DATA *mainverts = graph->get_mainnodes();

	//todo: maintain local copy, update on size change?
	obtainMutex(graph->funcQueueMutex, "Display externlist", 1200);
	vector<int> externListCopy = graph->externList;
	dropMutex(graph->funcQueueMutex, "Display externlist");

	vector<int>::iterator externCallIt = externListCopy.begin();
	for (; externCallIt != externListCopy.end(); ++externCallIt)
	{
		node_data *n = graph->get_node(*externCallIt);
		assert(n->external);

		DCOORD screenCoord;
		if (!n->get_screen_pos(mainverts, pd, &screenCoord)) continue;
		if (is_on_screen(&screenCoord, clientstate))
			draw_func_args(clientstate, clientstate->standardFont, screenCoord, n);
	}
}


//iterate through all the nodes, draw instruction text for the ones in view
void draw_instruction_text(VISSTATE *clientstate, int zdist, PROJECTDATA *pd, thread_graph_data *graph)
{

	//iterate through nodes looking for ones that map to screen coords
	unsigned int i, drawn = 0;
	glBindBuffer(GL_ARRAY_BUFFER, 0);

	bool show_all_always = (clientstate->show_ins_text == INSTEXT_ALL_ALWAYS);
	unsigned int numVerts = graph->get_num_nodes();
	GRAPH_DISPLAY_DATA *mainverts = graph->get_mainnodes();
	for (i = 0; i < numVerts; ++i)
	{

		node_data *n = graph->get_node(i);
		if (n->external) continue;
		
		if (!a_coord_on_screen(n->vcoord.a, clientstate->leftcolumn,
			clientstate->rightcolumn, graph->m_scalefactors->HEDGESEP))
			continue;

		//todo: experiment with performance re:how much of these checks to include
			
		DCOORD screenCoord;
		if (!n->get_screen_pos(mainverts, pd, &screenCoord)) continue; //in graph but not rendered
		if (screenCoord.x > clientstate->size.width || screenCoord.x < -100) continue;
		if (screenCoord.y > clientstate->size.height || screenCoord.y < -100) continue;

		string itext("?");
		if (!show_all_always) {
			//float nB = n->vcoord.b + n->vcoord.bMod*BMODMAG;

			if (zdist < 5 && clientstate->show_ins_text == INSTEXT_AUTO)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}

		stringstream ss;
		ss << std::dec << n->index << "-0x" << std::hex << n->ins->address <<":" << itext;
		al_draw_text(clientstate->standardFont, al_col_white, screenCoord.x + INS_X_OFF,
			clientstate->size.height - screenCoord.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
			ss.str().c_str());
		drawn++;

	}
}

//only draws text for instructions with unsatisfied conditions
void draw_condition_ins_text(VISSTATE *clientstate, int zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata)
{
	thread_graph_data *graph = (thread_graph_data *)clientstate->activeGraph;
	//iterate through nodes looking for ones that map to screen coords
	unsigned int i, drawn = 0;
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	bool show_all_always = (clientstate->show_ins_text == INSTEXT_ALL_ALWAYS);
	unsigned int numVerts = vertsdata->get_numVerts();
	GLfloat *vcol = vertsdata->readonly_col();
	for (i = 0; i < numVerts; ++i)
	{
		node_data *n = graph->get_node(i);
		if (n->external || !n->ins->conditional) continue;

		if (!a_coord_on_screen(n->vcoord.a, clientstate->leftcolumn, clientstate->rightcolumn,
			graph->m_scalefactors->HEDGESEP)) continue;

		//todo: experiment with performance re:how much of these checks to include
		DCOORD screenCoord;
		if (!n->get_screen_pos(vertsdata, pd, &screenCoord)) continue;
		if (screenCoord.x > clientstate->size.width || screenCoord.x < -100) continue;
		if (screenCoord.y > clientstate->size.height || screenCoord.y < -100) continue;

		const int vectNodePos = n->index*COLELEMS;
		ALLEGRO_COLOR textcol;
		textcol.r = vcol[vectNodePos + ROFF];
		textcol.g = vcol[vectNodePos + GOFF];
		textcol.b = vcol[vectNodePos + BOFF];
		textcol.a = 1;

		string itext;
		if (!show_all_always) {
			float nB = n->vcoord.b + n->vcoord.bMod*BMODMAG;

			if (zdist < 5 && clientstate->show_ins_text == INSTEXT_AUTO)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}
		else itext = "?";

		stringstream ss;
		ss << "0x" << std::hex << n->ins->address << ": " << itext;
		al_draw_text(clientstate->standardFont, textcol, screenCoord.x + INS_X_OFF,
			clientstate->size.height - screenCoord.y + 12, ALLEGRO_ALIGN_LEFT,
			ss.str().c_str());
		drawn++;
	}
}

//draw number of times an edge has been executed
void draw_edge_heat_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd)
{
	thread_graph_data *graph = (thread_graph_data *)clientState->activeGraph;
	
	glBindBuffer(GL_ARRAY_BUFFER, 0);//need this to make text work
	GRAPH_DISPLAY_DATA *vertsdata = graph->get_mainnodes();

	//iterate through nodes looking for ones that map to screen coords
	int edgelistIdx = 0;
	int edgelistEnd = graph->heatmaplines->get_renderedEdges();

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
		int edgeWeight = e->weight;
		if (edgeWeight <= 1) continue;

		DCOORD screenCoordA, screenCoordB;
		if(!firstNode->get_screen_pos(vertsdata, pd, &screenCoordA)) continue;
		if(!graph->get_node(ePair->second)->get_screen_pos(vertsdata, pd, &screenCoordB)) continue;

		DCOORD screenCoordMid;
		midpoint(&screenCoordA, &screenCoordB, &screenCoordMid);

		if (screenCoordMid.x > clientState->size.width || screenCoordMid.x < -100) continue;
		if (screenCoordMid.y > clientState->size.height || screenCoordMid.y < -100) continue;

		string weightString = to_string(edgeWeight);
		al_draw_text(clientState->standardFont, clientState->config->heatmap.lineTextCol, screenCoordMid.x + INS_X_OFF,
			clientState->size.height - screenCoordMid.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
			weightString.c_str());
	}
}


void display_graph(VISSTATE *clientstate, thread_graph_data *graph, PROJECTDATA *pd)
{
	
	if (clientstate->modes.animation)
		graph->display_active(clientstate->modes.nodes, clientstate->modes.edges);
	else
		graph->display_static(clientstate->modes.nodes, clientstate->modes.edges);

	long sphereSize = graph->m_scalefactors->radius;
	float zmul = (clientstate->zoomlevel - sphereSize) / 1000 - 1;
	
	if (zmul < 25)
		show_extern_labels(clientstate, pd, graph);

	if (clientstate->show_ins_text && zmul < 7 && graph->get_num_nodes() > 2)
		draw_instruction_text(clientstate, zmul, pd, graph);
}

void display_graph_diff(VISSTATE *clientstate, diff_plotter *diffRenderer) {
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

	if (clientstate->modes.nodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graph1->graphVBOs, vertsdata->get_numVerts());

	if (clientstate->modes.edges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, diffgraph->graphVBOs, linedata->get_numVerts());

	long sphereSize = graph1->m_scalefactors->radius;
	float zmul = (clientstate->zoomlevel - sphereSize) / 1000 - 1;

	PROJECTDATA pd;
	bool pdgathered = false;
	if (zmul < 25)
	{
		gather_projection_data(&pd);
		pdgathered = true;
		show_extern_labels(clientstate, &pd, graph1);
	}

	if (clientstate->show_ins_text && zmul < 10 && graph1->get_num_nodes() > 2)
	{
		if (!pdgathered) 
			gather_projection_data(&pd);
		draw_instruction_text(clientstate, zmul, &pd, graph1);
	}
}

void display_big_heatmap(VISSTATE *clientstate)
{
	thread_graph_data *graph = (thread_graph_data *)clientstate->activeGraph;
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

	if (clientstate->modes.nodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graph->graphVBOs, vertsdata->get_numVerts());

	if (clientstate->modes.edges)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_LINE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->heatmapEdgeVBO[0]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

		glDrawArrays(GL_LINES, 0, graph->heatmaplines->get_numVerts());
	}

	float zmul = (clientstate->zoomlevel - graph->zoomLevel) / 1000 - 1;

	PROJECTDATA pd;
	gather_projection_data(&pd);
	if (zmul < 25)
		show_extern_labels(clientstate, &pd, graph);

	if (clientstate->show_ins_text && zmul < 10 && graph->get_num_nodes() > 2)
		draw_edge_heat_text(clientstate, zmul, &pd);
}

#define VBO_COND_NODE_COLOUR 0
#define VBO_COND_LINE_COLOUR 1
void display_big_conditional(VISSTATE *clientstate)
{
	thread_graph_data *graph = (thread_graph_data *)clientstate->activeGraph;
	if (!graph->conditionallines || !graph->conditionalnodes) return;

	if (graph->needVBOReload_conditional)
	{
		if (!graph->conditionalnodes->get_numVerts() || !graph->conditionallines->get_numVerts()) return;

		load_VBO(VBO_COND_NODE_COLOUR, graph->conditionalVBOs, 
			graph->conditionalnodes->col_size(), graph->conditionalnodes->readonly_col());
		load_VBO(VBO_COND_LINE_COLOUR, graph->conditionalVBOs, 
			graph->conditionallines->col_size(), graph->conditionallines->readonly_col());
		printf("Loading %d bytes from condcol to vbo\n", graph->conditionallines->col_size());
		graph->needVBOReload_conditional = false;
	}

	if (graph->needVBOReload_main)
	{
		loadVBOs(graph->graphVBOs, graph->get_mainnodes(), graph->get_mainlines());
		graph->needVBOReload_main = false;
	}

	if (clientstate->modes.nodes)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_NODE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[VBO_COND_NODE_COLOUR]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		glDrawArrays(GL_POINTS, 0, graph->conditionalnodes->get_numVerts());
	}

	if (clientstate->modes.edges)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_LINE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[VBO_COND_LINE_COLOUR]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		glDrawArrays(GL_LINES, 0, graph->conditionallines->get_numVerts());

	}

	float zoomDiffMult = (clientstate->zoomlevel - graph->zoomLevel) / 1000 - 1;

	PROJECTDATA pd;
	gather_projection_data(&pd);
	if (clientstate->show_ins_text && zoomDiffMult < 10 && graph->get_num_nodes() > 2)
		draw_condition_ins_text(clientstate, zoomDiffMult, &pd, graph->get_mainnodes());

}

void drawHighlight(node_data *node, MULTIPLIERS *scale, ALLEGRO_COLOR *colour, int lengthModifier)
{
	if (!node) return;

	FCOORD center;
	center.x = 0;
	center.y = 0;
	center.z = 0;

	FCOORD nodeCoord;
	VCOORD *npos = &node->vcoord;
	float adjB = npos->b + float(npos->bMod * BMODMAG);
	sphereCoord(npos->a, adjB, &nodeCoord, scale, lengthModifier);
	drawHighlightLine(center, nodeCoord, colour);
}