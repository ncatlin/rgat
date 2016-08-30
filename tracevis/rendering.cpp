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
	int points = WF_POINTSPERLINE;
	int numSphereCurves = 0;
	int lineDivisions = (int)(360 / WIREFRAMELOOPS);
	GRAPH_DISPLAY_DATA *wireframe_data = clientstate->wireframe_sphere;

	GLfloat *vpos = wireframe_data->acquire_pos("1c");
	GLfloat *vcol = wireframe_data->acquire_col("1c");
	for (ii = 0; ii < 180; ii += lineDivisions) {

		float ringSize = diam * sin((ii*M_PI) / 180);
		for (pp = 0; pp < WF_POINTSPERLINE; ++pp) {

			float angle = (2 * M_PI * pp) / WF_POINTSPERLINE;

			index = numSphereCurves * WF_POINTSPERLINE * POSELEMS + pp * POSELEMS;
			vpos[index + XOFF] = ringSize * cos(angle);
			vpos[index + YOFF] = diam * cos((ii*M_PI) / 180);
			vpos[index + ZOFF] = ringSize * sin(angle);

			index = numSphereCurves * WF_POINTSPERLINE * COLELEMS + pp * COLELEMS;
			vcol[index + ROFF] = r;
			vcol[index + GOFF] = g;
			vcol[index + BOFF] = b;
			vcol[index + AOFF] = a;
		}
		numSphereCurves += 1;
	}

	for (ii = 0; ii < 180; ii += lineDivisions) {

		float degs2 = (ii*M_PI) / 180;  
		for (pp = 0; pp < points; ++pp) {

			float angle = (2 * M_PI * pp) / points;
			float cosangle = cos(angle);
			
			index = numSphereCurves * WF_POINTSPERLINE * POSELEMS + pp * POSELEMS;
			vpos[index + XOFF] = diam * cosangle * cos(degs2);
			vpos[index + YOFF] = diam * sin(angle);
			vpos[index + ZOFF] = diam * cosangle * sin(degs2);

			index = numSphereCurves * WF_POINTSPERLINE * COLELEMS + pp * COLELEMS;
			vcol[index + ROFF] = r;
			vcol[index + GOFF] = g;
			vcol[index + BOFF] = b;
			vcol[index + AOFF] = a;
		}
		numSphereCurves += 1;
	}

	glGenBuffers(2, clientstate->wireframeVBOs);
	load_VBO(VBO_SPHERE_POS, clientstate->wireframeVBOs, WFPOSBUFSIZE, vpos);
	load_VBO(VBO_SPHERE_COL, clientstate->wireframeVBOs, WFCOLBUFSIZE, vcol);
	wireframe_data->release_pos();
	wireframe_data->release_col();
}

void drawShortLinePoints(FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour, GRAPH_DISPLAY_DATA *vertdata, int *arraypos)
{

	GLfloat* vertpos = vertdata->acquire_pos("1b");
	GLfloat* vertcol = vertdata->acquire_col("1b");

	int numverts = vertdata->get_numVerts();
	int posi = numverts * POSELEMS;
	int coli = numverts * COLELEMS;
	*arraypos = coli;
	//printf("small curve at arraypos %d size:%d -> %d\n", *arraypos, 8, * arraypos+ 8);

	memcpy(vertpos + posi, startC, POSELEMS * sizeof(float));
	posi += POSELEMS;
	memcpy(vertpos + posi, endC, POSELEMS * sizeof(float));

	memcpy(vertcol + coli, colour, COLELEMS * sizeof(float));
	coli += COLELEMS;
	memcpy(vertcol + coli, colour, COLELEMS * sizeof(float));

	vertdata->set_numVerts(numverts + 2);
	vertdata->release_pos();
	vertdata->release_col();

}

int drawLongCurvePoints(FCOORD *bezierC, FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour, 
	int edgeType, GRAPH_DISPLAY_DATA *vertdata, int curvePoints, int *arraypos) {
	float fadeArray[] = { 1,0.9,0.8,0.7,0.5,0.3,0.3,0.3,0.2,0.2,0.2,
		0.3, 0.3, 0.5, 0.7, 0.9, 1 };
	
	curvePoints += 2;
	float *posdata = (float *)malloc((curvePoints + 2) * POSELEMS * sizeof(float));
	float *coldata = (float *)malloc((curvePoints + 2) * COLELEMS * sizeof(float));
	if (!posdata || !coldata) return 0;
	int ci = 0;
	int pi = 0;

	float r = colour->r;
	float g = colour->g;
	float b = colour->b;

	posdata[pi++] = startC->x;
	posdata[pi++] = startC->y;
	posdata[pi++] = startC->z;
	coldata[ci++] = r;
	coldata[ci++] = g;
	coldata[ci++] = b;
	coldata[ci++] = 1;

	// > for smoother lines, less performance
	int dt;
	float fadeA = 0.9;
	FCOORD resultC;

	int segments = float(curvePoints) / 2;
	for (dt = 1; dt < segments + 1; ++dt)
	{

		bezierPT(startC, bezierC, endC, dt, segments, &resultC);

		//end last line
		posdata[pi++] = resultC.x;
		posdata[pi++] = resultC.y;
		posdata[pi++] = resultC.z;
		//start new line at same point todo: this is waste of memory
		posdata[pi++] = resultC.x;
		posdata[pi++] = resultC.y;
		posdata[pi++] = resultC.z;

		if ((edgeType == IOLD) || (edgeType == IRET)) {
			fadeA = fadeArray[dt - 1];
			if (fadeA > 1) fadeA = 1;
		}
		else
			fadeA = 0.9;

		coldata[ci++] = r;
		coldata[ci++] = g;
		coldata[ci++] = b;
		coldata[ci++] = fadeA;
		coldata[ci++] = r;
		coldata[ci++] = g;
		coldata[ci++] = b;
		coldata[ci++] = fadeA;
	}

	posdata[pi++] = endC->x;
	posdata[pi++] = endC->y;
	posdata[pi++] = endC->z;

	coldata[ci++] = r;
	coldata[ci++] = g;
	coldata[ci++] = b;
	coldata[ci++] = 1;

	int numverts = vertdata->get_numVerts();
	float *vpos = vertdata->acquire_pos("1d") + numverts * POSELEMS;
	float *vcol = vertdata->acquire_col("1d") + numverts * COLELEMS;
	*arraypos = numverts * COLELEMS;
	//printf("Big curve at arraypos %d size:%d -> %d\n", *arraypos, 
	//	COLELEMS * (curvePoints+2), *arraypos+ COLELEMS * (curvePoints + 2));

	//printf("memcpy bigline from 0x%lx to 0x%lx\n", vcol, vcol + COLELEMS * curvePoints *sizeof(float));
	memcpy(vpos, posdata, POSELEMS * curvePoints * sizeof(float));
	memcpy(vcol, coldata, COLELEMS * curvePoints * sizeof(float));

	free(posdata);
	free(coldata);

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

	int vertIdx = n->index;

	GLfloat *vpos = vertdata->acquire_pos("334");
	GLfloat *vcol = vertdata->acquire_col("33f");
	GLfloat *vcol2 = animvertdata->acquire_col("1e");
	if (!vpos || !vcol || !vcol2)
	{
		vertdata->release_pos();
		vertdata->release_col();
		animvertdata->release_col();
		return 0;
	}

	vpos[(vertIdx * POSELEMS) + XOFF] = screenc.x;
	vpos[(vertIdx * POSELEMS) + YOFF] = screenc.y;
	vpos[(vertIdx * POSELEMS) + ZOFF] = screenc.z;

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

	
	vcol[(vertIdx * COLELEMS) + ROFF] = active_col->r;
	vcol[(vertIdx * COLELEMS) + GOFF] = active_col->g;
	vcol[(vertIdx * COLELEMS) + BOFF] = active_col->b;
	vcol[(vertIdx * COLELEMS) + AOFF] = 1;

	vertdata->set_numVerts(vertdata->get_numVerts()+1);

	vertdata->release_col();
	vertdata->release_pos();

	vcol2[(vertIdx * COLELEMS) + ROFF] = active_col->r;
	vcol2[(vertIdx * COLELEMS) + GOFF] = active_col->g;
	vcol2[(vertIdx * COLELEMS) + BOFF] = active_col->b;
	vcol2[(vertIdx * COLELEMS) + AOFF] = 0;

	animvertdata->set_numVerts(vertdata->get_numVerts() + 1);

	animvertdata->release_col();

	return 1;
}

int draw_new_verts(thread_graph_data *graph, GRAPH_DISPLAY_DATA *vertsdata) {
	
	MULTIPLIERS *scalefactors = vertsdata->isPreview() ? graph->p_scalefactors : graph->m_scalefactors;

	map<unsigned int, node_data>::iterator vertit = graph->get_nodeStart();
	map<unsigned int, node_data>::iterator vertEnd = graph->get_nodeEnd();
	if (vertit == vertEnd) return 0;
	std::advance(vertit, vertsdata->get_numVerts());

	if (vertit == vertEnd) return 0;
	int maxVerts = 50;
	for (; vertit != vertEnd; ++vertit)
	{
		int retries = 0;
	 while (!add_node(&vertit->second, vertsdata, graph->animnodesdata, scalefactors))
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

	map<unsigned int, node_data>::iterator vertit = graph->get_nodeStart();
	map<unsigned int, node_data>::iterator target = graph->get_nodeStart();
	printf("starting resize\n");
	GLfloat *vpos = vertsdata->acquire_pos("1i");
	for (std::advance(target, vertsdata->get_numVerts()); vertit != target; ++vertit)
	{
		FCOORD c = vertit->second.sphereCoordB(scalefactors, 0);
		int vertIdx = vertit->second.index;
		vpos[(vertIdx * POSELEMS) + XOFF] = c.x;
		vpos[(vertIdx * POSELEMS) + YOFF] = c.y;
		vpos[(vertIdx * POSELEMS) + ZOFF] = c.z;
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
	unsigned int lowestPoint = graph->maxB * graph->m_scalefactors->VEDGESEP;
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
		int externVertIdx = *externCallIt;
		node_data *n = graph->get_node(externVertIdx);
		assert(n->external);

		DCOORD screenCoord = n->get_screen_pos(mainverts, pd);
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

		string itext("?");
		if (!show_all_always) {
			float nB = n->vcoord.b + n->vcoord.bMod*BMODMAG;

			if (zdist < 5 && clientstate->show_ins_text == INSTEXT_AUTO)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}

		//todo: experiment with performance re:how much of this check to include
			
		DCOORD screenCoord = n->get_screen_pos(mainverts, pd);

		if (screenCoord.x > clientstate->size.width || screenCoord.x < -100) continue;
		if (screenCoord.y > clientstate->size.height || screenCoord.y < -100) continue;

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

		string itext;
		if (!show_all_always) {
			float nB = n->vcoord.b + n->vcoord.bMod*BMODMAG;

			if (zdist < 5 && clientstate->show_ins_text == INSTEXT_AUTO)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}
		else itext = "?";

		//todo: experiment with performance re:how much of this check to include
		DCOORD screenCoord = n->get_screen_pos(vertsdata, pd);

		if (screenCoord.x > clientstate->size.width || screenCoord.x < -100) continue;
		if (screenCoord.y > clientstate->size.height || screenCoord.y < -100) continue;

		ALLEGRO_COLOR textcol;
		textcol.r = vcol[n->index*COLELEMS + ROFF];
		textcol.g = vcol[n->index*COLELEMS + GOFF];
		textcol.b = vcol[n->index*COLELEMS + BOFF];
		textcol.a = 1;

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
	
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	GRAPH_DISPLAY_DATA *vertsdata = graph->get_mainnodes();

	//iterate through nodes looking for ones that map to screen coords
	EDGELIST::iterator edgeIt;
	EDGELIST::iterator edgeEnd;
	graph->start_edgeL_iteration(&edgeIt, &edgeEnd);

	for (; edgeIt != edgeEnd; ++edgeIt)
	{
		node_data *n = graph->get_node(edgeIt->first);

		//should these checks should be done on the midpoint rather than the first node?
		if (n->external) continue; //don't care about instruction in library call
		if (!a_coord_on_screen(n->vcoord.a, clientState->leftcolumn,
			clientState->rightcolumn, graph->m_scalefactors->HEDGESEP))
			continue;
		if (graph->get_edge(*edgeIt)->weight <= 1) continue;

		DCOORD screenCoordA = n->get_screen_pos(vertsdata, pd);
		DCOORD screenCoordB = graph->get_node(edgeIt->second)->get_screen_pos(vertsdata, pd);
		DCOORD screenCoordMid;
		midpoint(&screenCoordA, &screenCoordB, &screenCoordMid);

		if (screenCoordMid.x > clientState->size.width || screenCoordMid.x < -100) continue;
		if (screenCoordMid.y > clientState->size.height || screenCoordMid.y < -100) continue;

		stringstream ss;
		ss << graph->get_edge(*edgeIt)->weight;
		al_draw_text(clientState->standardFont, clientState->config->heatmap.lineTextCol, screenCoordMid.x + INS_X_OFF,
			clientState->size.height - screenCoordMid.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
			ss.str().c_str());
	}
	graph->stop_edgeL_iteration();
}


void display_graph(VISSTATE *clientstate, thread_graph_data *graph, PROJECTDATA *pd)
{
	if (clientstate->modes.animation)
		graph->display_active(clientstate->modes.nodes, clientstate->modes.edges);
	else
		graph->display_static(clientstate->modes.nodes, clientstate->modes.edges);

	long graphSize = graph->m_scalefactors->radius;
	float zdiff = clientstate->zoomlevel - graphSize;
	float zmul = (clientstate->zoomlevel - graphSize) / 1000 - 1;
	
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

	long graphSize = graph1->m_scalefactors->radius;
	float zdiff = clientstate->zoomlevel - graphSize;
	float zmul = (clientstate->zoomlevel - graphSize) / 1000 - 1;

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
		glGenBuffers(1, graph->heatmapEdgeVBO);
		glBindBuffer(GL_ARRAY_BUFFER, graph->heatmapEdgeVBO[0]);
		glBufferData(GL_ARRAY_BUFFER, graph->heatmaplines->col_size(), graph->heatmaplines->readonly_col(), GL_STATIC_DRAW);
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

	float zdiff = clientstate->zoomlevel - graph->zoomLevel;
	float zmul = (clientstate->zoomlevel - graph->zoomLevel) / 1000 - 1;

	PROJECTDATA pd;
	gather_projection_data(&pd);
	if (zmul < 25)
		show_extern_labels(clientstate, &pd, graph);

	if (clientstate->show_ins_text && zmul < 10 && graph->get_num_nodes() > 2)
		draw_edge_heat_text(clientstate, zmul, &pd);
}

void display_big_conditional(VISSTATE *clientstate)
{
	thread_graph_data *graph = (thread_graph_data *)clientstate->activeGraph;
	if (!graph->conditionallines || !graph->conditionalnodes) return;

	if (graph->needVBOReload_conditional)
	{
		glGenBuffers(2, graph->conditionalVBOs);
		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[0]);

		glBufferData(GL_ARRAY_BUFFER, graph->conditionalnodes->col_size(), graph->conditionalnodes->readonly_col(), GL_STATIC_DRAW);

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[1]);
		glBufferData(GL_ARRAY_BUFFER, graph->conditionallines->col_size(), graph->conditionallines->readonly_col(), GL_STATIC_DRAW);

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

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[0]);
		glColorPointer(COLELEMS, GL_FLOAT, 0, 0);
		glDrawArrays(GL_POINTS, 0, graph->conditionalnodes->get_numVerts());
	}

	if (clientstate->modes.edges)
	{
		glBindBuffer(GL_ARRAY_BUFFER, graph->graphVBOs[VBO_LINE_POS]);
		glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

		glBindBuffer(GL_ARRAY_BUFFER, graph->conditionalVBOs[1]);
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