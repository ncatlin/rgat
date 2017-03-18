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
Creates a sphere layout for a plotted graph
*/

#include "stdafx.h"
#include "sphere_graph.h"
#include "rendering.h"

//A: Longitude. How many units along the side of the sphere a node is placed
//B: Latitude. How many units up or down the side of the sphere a node is placed
#define BMULT 2

#define JUMPA -6
#define JUMPB 6
#define JUMPA_CLASH -15
#define CALLB 20

//how to adjust placement if it jumps to a prexisting node (eg: if caller has called multiple)
#define CALLA_CLASH -40
#define CALLB_CLASH -30

//placement of external nodes, relative to the first caller
#define EXTERNA -3
#define EXTERNB 3

//controls placement of the node after a return
#define RETURNA_OFFSET -4
#define RETURNB_OFFSET 3

void sphere_graph::initialiseDefaultDimensions()
{
	wireframeSupported = true;
	preview_scalefactors->AEDGESEP = 0.15;
	preview_scalefactors->BEDGESEP = 0.11;
	preview_scalefactors->size = 200;
	preview_scalefactors->baseSize = 200;

	defaultViewShift = make_pair(135, -25);
	defaultZoom = 80000;
}

//performs an action (call,jump,etc) from lastNode, places new position in positionStruct
//this is the function that determines how the graph is laid out
void sphere_graph::positionVert(void *positionStruct, node_data *n, PLOT_TRACK *lastNode)
{
	
	SPHERECOORD *oldPosition = get_node_coord(lastNode->lastVertID);
	if (!oldPosition)
	{
		cerr << "Waiting for node " << lastNode->lastVertID;
		int waitPeriod = 5;
		int iterations = 1;
		do
		{
			Sleep(waitPeriod);
			waitPeriod += (150 * iterations++);
			oldPosition = get_node_coord(lastNode->lastVertID);
		} while (!oldPosition);
	}

	int a = oldPosition->a;
	int b = oldPosition->b;
	int bMod = oldPosition->bMod;
	int clash = 0;

	SPHERECOORD *position = (SPHERECOORD *)positionStruct;
	if (n->external)
	{
		node_data *lastNodeData = internalProtoGraph->safe_get_node(lastNode->lastVertID);
		position->a = a + 2 * lastNodeData->childexterns + 5;
		position->b = b + lastNodeData->childexterns + 5;
		position->bMod = bMod;
		return;
	}

	switch (lastNode->lastVertType)
	{

		//small vertical distance between instructions in a basic block	
		case eNodeNonFlow: 
		{
			bMod += 1 * BMULT;
			break;
		}

		case eNodeJump://long diagonal separation to show distinct basic blocks
		{
			//check if this is a conditional which fell through (ie: sequential)
			node_data *lastNodeData = internalProtoGraph->safe_get_node(lastNode->lastVertID);
			if (lastNodeData->conditional && n->address == lastNodeData->ins->condDropAddress)
			{
				bMod += 1 * BMULT;
				break;
			}
			//notice lack of break
		} 
	
		case eNodeException: 
		{
			a += JUMPA;
			b += JUMPB * BMULT;

			while (usedCoords.find(make_pair(a, b)) != usedCoords.end())
			{
				a += JUMPA_CLASH;
				++clash;
			}

			//if (clash > 15)
			//	cerr << "[rgat]WARNING: Dense Graph Clash (jump) - " << clash << " attempts" << endl;
			break;
		}

		//long purple line to show possible distinct functional blocks of the program
		case eNodeCall:
		{
			//note: b sometimes huge after this?
			b += CALLB * BMULT;

			while (usedCoords.find(make_pair(a,b)) != usedCoords.end())
			{
				a += CALLA_CLASH;
				b += CALLB_CLASH * BMULT;
				++clash;
			}

			if (clash)
			{
				a += CALLA_CLASH;
				//if (clash > 15)
				//	cerr << "[rgat]WARNING: Dense Graph Clash (call) - " << clash <<" attempts"<<endl;
			}

			//if code arrives to next instruction after a return then arrange as a function
			MEM_ADDRESS nextAddress = n->ins->address + n->ins->numbytes;
			callStack.push_back(make_pair(nextAddress, lastNode->lastVertID));
			cout << "placed addresss after call (" << hex << nextAddress << " in callstack" << endl;
			break;
		}

		case eNodeReturn:
			//previous externs handled same as previous returns
		case eNodeExternal:
		{
			//returning to address in call stack?
			int result = -1;

			vector<pair<MEM_ADDRESS, unsigned int>>::iterator stackIt;
			cout << "last node was ret/ext, searching for subsequent addresss (" << hex << n->address << " in callstack" << endl;
			for (stackIt = callStack.begin(); stackIt != callStack.end(); ++stackIt)
				if (stackIt->first == n->address)
				{
					result = stackIt->second;
					break;
				}

			//if so, position next node near caller
			if (result != -1)
			{
				cout << "Found a return for node " << n->index << ". caller was " << result << endl;
				SPHERECOORD *caller = get_node_coord(result);
				assert(caller);
				a = caller->a + RETURNA_OFFSET;
				b = caller->b + RETURNB_OFFSET;
				bMod = caller->bMod;

				//may not have returned to the last item in the callstack
				//delete everything inbetween
				callStack.resize(stackIt - callStack.begin());
			}
			else
			{
				a += EXTERNA;
				b += EXTERNB * BMULT;
			}

			while (usedCoords.find(make_pair(a, b)) != usedCoords.end())
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
			if (lastNode->lastVertType != eFIRST_IN_THREAD)
				cerr << "[rgat]ERROR: Unknown Last instruction type " << lastNode->lastVertType << endl;
			break;
	}

	position->a = a;
	position->b = b;
	position->bMod = bMod;
}

SPHERECOORD * sphere_graph::get_node_coord(NODEINDEX idx)
{
	if (idx < node_coords.size())
	{
		SPHERECOORD *result;
		acquire_nodecoord_read();
		result = &node_coords.at(idx);
		release_nodecoord_read();
		return result;
	}
	return 0;
}

/*
input: an 'a' coordinate, left and right columns of screen, horiz separation
return: if coord is within those columns
only as accurate as the inaccurate mystery constant

TODO: come up with a way of deriving row 'b' from a given coordinate
then we can improve performance even more by looking at the top and bottom rows
instead of getting everything in the column

Graph tends to not have much per column though so this isn't a desperate requirement
*/
bool sphere_graph::a_coord_on_screen(int a, int leftcol, int rightcol, float hedgesep)
{
	/* the idea here is to calculate the column of the given coordinate
	dunno how though!
	FIX ME - to fix text display
	*/
	//bad bad bad bad bad bad bad... but close. gets worse the wider the graph is
	int coordcolumn = floor(-a / (COLOUR_PICKING_MYSTERY_CONSTANTA / hedgesep));
	coordcolumn = coordcolumn % ADIVISIONS;

	if (leftcol > rightcol)
	{
		int shifter = ADIVISIONS - leftcol;
		leftcol = 0;
		rightcol += shifter;
		coordcolumn += shifter;
	}

	//this code is horrendous and doesn't fix it and ugh
	int stupidHack = 1;
	if ((coordcolumn >= leftcol) && (coordcolumn <= (rightcol + stupidHack))) return true;
	else return false;
}

//take longitude a, latitude b, output coord in space
//diamModifier allows specifying different sphere sizes
void sphere_graph::sphereCoord(int ia, float b, FCOORD *c, GRAPH_SCALE *dimensions, float diamModifier) 
{

	float a = ia*dimensions->AEDGESEP;
	b *= dimensions->BEDGESEP;
	b += BAdj; //offset start down on sphere

	float sinb = sin((b*M_PI) / 180);
	float r = (dimensions->size + diamModifier);// +0.1 to make sure we are above lines

	c->x = r * sinb * cos((a*M_PI) / 180);
	c->y = r * cos((b*M_PI) / 180);
	c->z = r * sinb * sin((a*M_PI) / 180);
}

//take coord in space, convert back to a/b
void sphere_graph::sphereAB(FCOORD *c, float *a, float *b, GRAPH_SCALE *mults)
{
	float acosb = acos(c->y / (mults->size + 0.099));
	float tb = DEGREESMUL*acosb;  //acos is a bit imprecise / wrong...

	float ta = DEGREESMUL * (asin((c->z / (mults->size + 0.1)) / sin(acosb)));
	tb -= BAdj;
	*a = ta / mults->AEDGESEP;
	*b = tb / mults->BEDGESEP;
}

//double version
void sphere_graph::sphereAB(DCOORD *c, float *a, float *b, GRAPH_SCALE *mults)
{
	FCOORD FFF;
	FFF.x = c->x;
	FFF.y = c->y;
	FFF.z = c->z;
	sphereAB(&FFF, a, b, mults);
}

//connect two nodes with an edge of automatic number of vertices
int sphere_graph::drawCurve(GRAPH_DISPLAY_DATA *linedata, FCOORD *startC, FCOORD *endC,
	ALLEGRO_COLOR *colour, int edgeType, GRAPH_SCALE *dimensions, int *arraypos)
{
	float r, b, g, a;
	r = colour->r;
	b = colour->b;
	g = colour->g;
	a = colour->a;

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
		curvePoints = eLen < 80 ? 1 : LONGCURVEPTS;
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
			FCOORD bezierC2;
			sphereAB(&middleC, &oldMidA, &oldMidB, dimensions);
			sphereCoord(oldMidA, oldMidB, &bezierC, dimensions, -(eLen / 2));

			//i dont know why this problem happens or why this fixes it
			if ((bezierC.x > 0) && (startC->x < 0 && endC->x < 0))
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

void sphere_graph::orient_to_user_view(int xshift, int yshift, long zoom)
{
	glTranslatef(0, 0, -zoom);
	glRotatef(-yshift, 1, 0, 0);
	glRotatef(-xshift, 0, 1, 0);
}

//function names as they are executed
void sphere_graph::write_rising_externs(ALLEGRO_FONT *font, bool nearOnly, int left, int right, int height, PROJECTDATA *pd)
{
	DCOORD nodepos;

	vector <pair<NODEINDEX, EXTTEXT>> displayNodeList;

	//make labels rise up screen, delete those that reach top
	obtainMutex(internalProtoGraph->externGuardMutex, 7676);
	map <NODEINDEX, EXTTEXT>::iterator activeExternIt = activeExternTimes.begin();
	for (; activeExternIt != activeExternTimes.end(); ++activeExternIt)
	{
		EXTTEXT *extxt = &activeExternIt->second;

		if (extxt->framesRemaining != KEEP_BRIGHT)
		{
			extxt->yOffset += EXTERN_FLOAT_RATE;

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
	dropMutex(internalProtoGraph->externGuardMutex);

	vector <pair<NODEINDEX, EXTTEXT>>::iterator displayNodeListIt = displayNodeList.begin();

	for (; displayNodeListIt != displayNodeList.end(); ++displayNodeListIt)
	{
		internalProtoGraph->getNodeReadLock();
		SPHERECOORD *coord = get_node_coord(displayNodeListIt->first);
		internalProtoGraph->dropNodeReadLock();

		EXTTEXT *extxt = &displayNodeListIt->second;

		if (nearOnly && !a_coord_on_screen(coord->a, left, right, main_scalefactors->AEDGESEP))
			continue;

		if (!get_screen_pos(displayNodeListIt->first, mainnodesdata, pd, &nodepos))
			continue;

		al_draw_text(font, al_col_green, nodepos.x, height - nodepos.y - extxt->yOffset,
			0, extxt->displayString.c_str());
	}

}


//reads the list of nodes/edges, creates opengl vertex/colour data
//resizes when it wraps too far around the sphere (lower than lowB, farther than farA)
void sphere_graph::render_static_graph(VISSTATE *clientState)
{
	bool doResize = false;
	if (clientState->rescale)
	{
		recalculate_sphere_scale(main_scalefactors);
		recalculate_sphere_scale(preview_scalefactors);
		clientState->rescale = false;
		doResize = true;
	}

	if (clientState->autoscale)
	{
		//doesn't take bmod into account
		//keeps graph away from the south pole
		int lowestPoint = maxB * main_scalefactors->BEDGESEP;
		if (lowestPoint > clientState->config->lowB)
		{
			float startB = lowestPoint;
			while (lowestPoint > clientState->config->lowB)
			{
				main_scalefactors->userBEDGESEP *= 0.98;
				preview_scalefactors->userBEDGESEP *= 0.98;
				recalculate_sphere_scale(main_scalefactors);
				lowestPoint = maxB * main_scalefactors->BEDGESEP;
			}
			//cout << "[rgat]Max B coord too high, shrinking graph vertically from "<< startB <<" to "<< lowestPoint << endl;

			recalculate_sphere_scale(preview_scalefactors);
			doResize = true;
			vertResizeIndex = 0;
		}

		//more straightforward, stops graph from wrapping around the globe
		int widestPoint = maxA * main_scalefactors->AEDGESEP;
		if (widestPoint > clientState->config->farA)
		{
			float startA = widestPoint;
			while (widestPoint > clientState->config->farA)
			{
				main_scalefactors->userAEDGESEP *= 0.99;
				preview_scalefactors->userAEDGESEP *= 0.99;
				recalculate_sphere_scale(main_scalefactors);
				widestPoint = maxB * main_scalefactors->AEDGESEP;
			}
			//cout << "[rgat]Max A coord too wide, shrinking graph horizontally from " << startA << " to " << widestPoint << endl;
			recalculate_sphere_scale(preview_scalefactors);
			doResize = true;
			vertResizeIndex = 0;
		}
	}

	if (doResize) previewNeedsResize = true;

	if (doResize || vertResizeIndex > 0)
	{
		rescale_nodes(false);


		zoomLevel = main_scalefactors->size;
		needVBOReload_main = true;

		if (clientState->wireframe_sphere)
			clientState->remakeWireframe = true;
	}

	int drawCount = render_new_edges(doResize);
	if (drawCount)
		needVBOReload_main = true;

	redraw_anim_edges();
}

void sphere_graph::maintain_draw_wireframe(VISSTATE *clientState, GLint *wireframeStarts, GLint *wireframeSizes)
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
void sphere_graph::plot_wireframe(VISSTATE *clientState)
{
	clientState->wireframe_sphere = new GRAPH_DISPLAY_DATA(WFCOLBUFSIZE * 2);
	ALLEGRO_COLOR *wireframe_col = &clientState->config->wireframe.edgeColor;
	float cols[4] = { wireframe_col->r , wireframe_col->g, wireframe_col->b, wireframe_col->a };

	int ii, pp;
	long diam = main_scalefactors->size;
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

//draws a line from the center of the sphere to nodepos. adds lengthModifier to the end
void sphere_graph::drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE *scale, ALLEGRO_COLOR *colour, int lengthModifier)
{
	FCOORD nodeCoordxyz;
	SPHERECOORD *nodeCoordSphere = get_node_coord(nodeIndex);
	if (!nodeCoordSphere) return;

	float adjB = nodeCoordSphere->b + float(nodeCoordSphere->bMod * BMODMAG);
	sphereCoord(nodeCoordSphere->a, adjB, &nodeCoordxyz, scale, lengthModifier);
	drawHighlightLine(nodeCoordxyz, colour);
}

//draws a line from the center of the sphere to nodepos. adds lengthModifier to the end
void sphere_graph::drawHighlight(void * nodeCoord, GRAPH_SCALE *scale, ALLEGRO_COLOR *colour, int lengthModifier)
{
	FCOORD nodeCoordxyz;
	if (!nodeCoord) return;

	SPHERECOORD *sphereNodeCoord = (SPHERECOORD *)nodeCoord;
	float adjB = sphereNodeCoord->b + float(sphereNodeCoord->bMod * BMODMAG);
	sphereCoord(sphereNodeCoord->a, adjB, &nodeCoordxyz, scale, lengthModifier);
	drawHighlightLine(nodeCoordxyz, colour);
}

//take the a/b/bmod coords, convert to opengl coordinates based on supplied sphere multipliers/size
FCOORD sphere_graph::nodeIndexToXYZ(NODEINDEX index, GRAPH_SCALE *dimensions, float diamModifier)
{
	SPHERECOORD *nodeCoordSphere = get_node_coord(index);
	float adjB = nodeCoordSphere->b + float(nodeCoordSphere->bMod * BMODMAG);

	FCOORD result;
	sphereCoord(nodeCoordSphere->a, adjB, &result, dimensions, diamModifier);
	return result;
}


//IMPORTANT: Must have edge reader lock to call this
bool sphere_graph::render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata,
	ALLEGRO_COLOR *forceColour, bool preview, bool noUpdate)
{

	unsigned long nodeCoordQty = node_coords.size();
	if (ePair.second >= nodeCoordQty || ePair.first >= nodeCoordQty) 
		return false;

	edge_data *e = &internalProtoGraph->edgeDict.at(ePair);
	
	GRAPH_SCALE *scaling;
	if (preview)
		scaling = preview_scalefactors;
	else
		scaling = main_scalefactors;

	FCOORD srcc = nodeIndexToXYZ(ePair.first, scaling, 0);
	FCOORD targc = nodeIndexToXYZ(ePair.second, scaling, 0);

	int arraypos = 0;
	ALLEGRO_COLOR *edgeColour;
	if (forceColour) edgeColour = forceColour;
	else
		edgeColour = &graphColours->at(e->edgeClass);

	int vertsDrawn = drawCurve(edgedata, &srcc, &targc,
		edgeColour, e->edgeClass, scaling, &arraypos);

	//previews, diffs, etc where we don't want to affect the original edges
	if (!noUpdate && !preview)
	{
		e->vertSize = vertsDrawn;
		e->arraypos = arraypos;
	}
	return true;
}


//converts a single node into node vertex data
int sphere_graph::add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
	GRAPH_SCALE *dimensions)
{
	//printf("in add node! node %d\n", n->index);
	SPHERECOORD * spherecoord;
	if (n->index >= node_coords.size())
	{

		SPHERECOORD tempPos;
		if (node_coords.empty())
		{
			assert(n->index == 0);
			tempPos = { 0,0,0 };
			spherecoord = &tempPos;

			acquire_nodecoord_write();
			node_coords.push_back(tempPos);
			release_nodecoord_write();
		}
		else
		{
			positionVert(&tempPos, n, lastNode);
			spherecoord = &tempPos;

			acquire_nodecoord_write();
			node_coords.push_back(tempPos);
			release_nodecoord_write();
		}


		updateStats(tempPos.a, tempPos.b, tempPos.bMod);
		usedCoords.emplace(make_pair(make_pair(tempPos.a, tempPos.b), true));
	}
	else
		spherecoord = get_node_coord(n->index);

	float adjustedB = spherecoord->b + float(spherecoord->bMod * BMODMAG);
	FCOORD screenc;

	sphereCoord(spherecoord->a, adjustedB, &screenc, dimensions, 0);

	vector<GLfloat> *mainNpos = vertdata->acquire_pos_write(677);
	vector<GLfloat> *mainNcol = vertdata->acquire_col_write();

	mainNpos->push_back(screenc.x);
	mainNpos->push_back(screenc.y);
	mainNpos->push_back(screenc.z);

	ALLEGRO_COLOR *active_col = 0;
	if (n->external)
		lastNode->lastVertType = eNodeExternal;
	else 
	{
		switch (n->ins->itype)
		{
		case OPUNDEF:
		{
			lastNode->lastVertType = n->conditional ? eNodeJump : eNodeNonFlow;
			break;
		}
		case OPJMP:
		{
			lastNode->lastVertType = eNodeJump;
			break; 
		}
		case OPRET: 
		{
			lastNode->lastVertType = eNodeReturn;
			break; 
		}
		case OPCALL:
		{
			lastNode->lastVertType = eNodeCall;
			break;
		}
			//case ISYS: //todo: never used - intended for syscalls
			//	active_col = &al_col_grey;
			//	break;
		default:
			cerr << "[rgat]Error: add_node unknown itype " << n->ins->itype << endl;
			assert(0);
		}
	}

	active_col = &graphColours->at(lastNode->lastVertType);
	lastNode->lastVertID = n->index;

	mainNcol->push_back(active_col->r);
	mainNcol->push_back(active_col->g);
	mainNcol->push_back(active_col->b);
	mainNcol->push_back(1);

	vertdata->set_numVerts(vertdata->get_numVerts() + 1);

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

void sphere_graph::performMainGraphDrawing(VISSTATE *clientState)
{
	if (get_pid() != clientState->activePid->PID) return;

	//add any new logged calls to the call log window
	if (clientState->textlog && clientState->logSize < internalProtoGraph->loggedCalls.size())
		clientState->logSize = internalProtoGraph->fill_extern_log(clientState->textlog, clientState->logSize);

	//line marking last instruction
	//<there may be a need to do something different depending on currentUnchainedBlocks.empty() or not>
	drawHighlight(lastAnimatedNode, main_scalefactors, &clientState->config->activityLineColour, 0);

	//highlight lines
	if (highlightData.highlightState)
		display_highlight_lines(&highlightData.highlightNodes,
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
	display_graph(clientState, &pd);
	write_rising_externs(clientState->standardFont, clientState->modes.nearSide,
		clientState->leftcolumn, clientState->rightcolumn, clientState->mainFrameSize.height, &pd);
}

//standard animated or static display of the active graph
void sphere_graph::display_graph(VISSTATE *clientState, PROJECTDATA *pd)
{
	if (clientState->modes.animation)
		display_active(clientState->modes.nodes, clientState->modes.edges);
	else
		display_static(clientState->modes.nodes, clientState->modes.edges);

	float zmul = zoomFactor(clientState->cameraZoomlevel, main_scalefactors->size);

	if (zmul < INSTEXT_VISIBLE_ZOOMFACTOR && internalProtoGraph->get_num_nodes() > 2)
		draw_instruction_text(clientState, zmul, pd);

	//if zoomed in, show all extern/internal labels
	if (zmul < EXTERN_VISIBLE_ZOOM_FACTOR)
		show_symbol_labels(clientState, pd);
	else
	{	//show label of extern we are blocked on
		node_data *n = internalProtoGraph->safe_get_node(lastMainNode.lastVertID);
		if (n && n->external)
		{
			DCOORD screenCoord;
			if (!get_screen_pos(lastMainNode.lastVertID, get_mainnodes(), pd, &screenCoord)) return;
			if (is_on_screen(&screenCoord, clientState->mainFrameSize.width, clientState->mainFrameSize.height))
				draw_func_args(clientState, clientState->standardFont, screenCoord, n);
		}
	}
}

//iterate through all the nodes, draw instruction text for the ones in view
//TODO: in animation mode don't show text for inactive nodes
void sphere_graph::draw_instruction_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd)
{
	if (clientState->modes.show_ins_text == eInsTextOff) return;

	//iterate through nodes looking for ones that map to screen coords
	glBindBuffer(GL_ARRAY_BUFFER, 0);

	bool show_all_always = (clientState->modes.show_ins_text == eInsTextForced);
	NODEINDEX numVerts = internalProtoGraph->get_num_nodes();
	GRAPH_DISPLAY_DATA *mainverts = get_mainnodes();
	stringstream ss;
	DCOORD screenCoord;
	string itext("?");
	for (NODEINDEX i = 0; i < numVerts; ++i)
	{
		node_data *n = internalProtoGraph->safe_get_node(i);
		if (n->external) continue;

		SPHERECOORD *nodeCoord = get_node_coord(i);
		if (!nodeCoord) continue; //usually happens with block interrupted by exception

		//this check removes the bulk of the instructions at a low performance cost, including those
		//on screen but on the other side of the sphere
		//implementation is tainted by a horribly derived constant that sometimes rules out nodes on screen
		//bypass by turning instruction display always on
		if (!show_all_always && !a_coord_on_screen(nodeCoord->a, clientState->leftcolumn,
			clientState->rightcolumn, main_scalefactors->AEDGESEP))
			continue;


		if (!get_screen_pos(i, mainverts, pd, &screenCoord)) continue; //in graph but not rendered
		if (screenCoord.x > clientState->mainFrameSize.width || screenCoord.x < -100) continue;
		if (screenCoord.y > clientState->mainFrameSize.height || screenCoord.y < -100) continue;

		if (show_all_always)
			itext = n->ins->ins_text;
		else
		{
			if (zdist < 5 && clientState->modes.show_ins_text == eInsTextAuto)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}
			

		ss << std::dec << i << "-0x" << std::hex << n->ins->address << ":" << itext;

		al_draw_text(clientState->instructionFont, al_col_white, screenCoord.x + INS_X_OFF,
			clientState->mainFrameSize.height - screenCoord.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
			ss.str().c_str());
		ss.str("");
	}
}

//show functions/args for externs in active graph
void sphere_graph::show_symbol_labels(VISSTATE *clientState, PROJECTDATA *pd)
{
	if (clientState->modes.show_symbol_verbosity == eSymboltextOff) return;

	GRAPH_DISPLAY_DATA *mainverts = get_mainnodes();
	
	vector<NODEINDEX> externListCopy;
	vector<NODEINDEX> internListCopy;

	if (clientState->modes.show_symbol_location != eSymboltextInternal )
	{
		obtainMutex(internalProtoGraph->highlightsMutex, 1052);
		externListCopy = internalProtoGraph->externalSymbolList;
		dropMutex(internalProtoGraph->highlightsMutex);

		vector<NODEINDEX>::iterator externCallIt = externListCopy.begin();
		for (; externCallIt != externListCopy.end(); ++externCallIt)
		{
			node_data *n = internalProtoGraph->safe_get_node(*externCallIt);
			assert(n->external);

			DCOORD screenCoord;
			if (!get_screen_pos(*externCallIt, mainverts, pd, &screenCoord)) continue;

			if (clientState->modes.nearSide)
			{
				SPHERECOORD *nodeCoord = get_node_coord(*externCallIt);
				assert(nodeCoord);
				if (!a_coord_on_screen(nodeCoord->a, clientState->leftcolumn,
					clientState->rightcolumn, main_scalefactors->AEDGESEP))
					continue;
			}

			if (is_on_screen(&screenCoord, clientState->mainFrameSize.width, clientState->mainFrameSize.height))
				draw_func_args(clientState, clientState->standardFont, screenCoord, n);
		}
	}

	if (clientState->modes.show_symbol_location != eSymboltextExternal)
	{
		obtainMutex(internalProtoGraph->highlightsMutex, 1053);
		internListCopy = internalProtoGraph->internalSymbolList;
		dropMutex(internalProtoGraph->highlightsMutex);

		vector<NODEINDEX>::iterator internSymIt = internListCopy.begin();
		for (; internSymIt != internListCopy.end(); ++internSymIt)
		{
			node_data *n = internalProtoGraph->safe_get_node(*internSymIt);
			assert(!n->external);

			DCOORD screenCoord;
			if (!get_screen_pos(*internSymIt, mainverts, pd, &screenCoord)) continue;

			if (clientState->modes.nearSide)
			{
				SPHERECOORD *nodeCoord = get_node_coord(*internSymIt);
				assert(nodeCoord);
				if (!a_coord_on_screen(nodeCoord->a, clientState->leftcolumn,
					clientState->rightcolumn, main_scalefactors->AEDGESEP))
					continue;
			}

			if (is_on_screen(&screenCoord, clientState->mainFrameSize.width, clientState->mainFrameSize.height))
				draw_internal_symbol(clientState, clientState->standardFont, screenCoord, n);
		}
	}
}

//only draws text for instructions with unsatisfied conditions
void sphere_graph::draw_condition_ins_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata)
{
	if (clientState->modes.show_ins_text == eInsTextOff) return;

	//iterate through nodes looking for ones that map to screen coords
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	bool show_all_always = (clientState->modes.show_ins_text == eInsTextForced);
	NODEINDEX numVerts = vertsdata->get_numVerts();
	GLfloat *vcol = vertsdata->readonly_col();
	for (NODEINDEX i = 0; i < numVerts; ++i)
	{
		node_data *n = internalProtoGraph->safe_get_node(i);
		
		if (n->external || !n->ins->conditional) continue;

		SPHERECOORD *nodeCoord = get_node_coord(i);
		if (!nodeCoord) continue;
		if (!a_coord_on_screen(nodeCoord->a, clientState->leftcolumn, clientState->rightcolumn,
			main_scalefactors->AEDGESEP)) continue;

		//todo: experiment with performance re:how much of these checks to include
		DCOORD screenCoord;
		if (!get_screen_pos(n->index, vertsdata, pd, &screenCoord)) continue;
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
			if (zdist < 5 && clientState->modes.show_ins_text == eInsTextAuto)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}
		else itext = "?";

		stringstream ss;
		ss << "0x" << std::hex << n->ins->address << ": " << itext;
		al_draw_text(clientState->instructionFont, textcol, screenCoord.x + INS_X_OFF,
			clientState->mainFrameSize.height - screenCoord.y + COND_INSTEXT_Y_OFF, ALLEGRO_ALIGN_LEFT,
			ss.str().c_str());
	}
}

//draw number of times each edge has been executed in middle of edge
void sphere_graph::draw_edge_heat_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd)
{
	if (clientState->modes.show_heat_location == eHeatNone) return;

	plotted_graph *graph = (plotted_graph *)clientState->activeGraph;

	glBindBuffer(GL_ARRAY_BUFFER, 0);//need this to make text work
	GRAPH_DISPLAY_DATA *vertsdata = get_mainnodes();

	//iterate through nodes looking for ones that map to screen coords
	int edgelistIdx = 0;
	int edgelistEnd = graph->heatmaplines->get_renderedEdges();

	set <node_data *> displayNodes;

	EDGELIST *edgelist = internalProtoGraph->edgeLptr();
	//assert(edgelistEnd <= edgelist->size());
	for (; edgelistIdx < edgelistEnd; ++edgelistIdx)
	{
		NODEPAIR *ePair = &edgelist->at(edgelistIdx);
		node_data *firstNode = internalProtoGraph->safe_get_node(ePair->first);
		
		//should these checks should be done on the midpoint rather than the first node?
		if (firstNode->external) continue; //don't care about instruction in library call

		SPHERECOORD *firstNodeCoord = get_node_coord(ePair->first);
		if (!firstNodeCoord) continue;
		if (!a_coord_on_screen(firstNodeCoord->a, clientState->leftcolumn,
			clientState->rightcolumn, graph->main_scalefactors->AEDGESEP))
			continue;

		edge_data *e = internalProtoGraph->get_edge(*ePair);
		if (!e) {
			cerr << "[rgat]WARNING: Heatmap edge skip" << endl;
			continue;
		}

		DCOORD screenCoordA;
		if (!get_screen_pos(ePair->first, vertsdata, pd, &screenCoordA)) continue;

		if (ePair->second >= internalProtoGraph->get_num_nodes()) continue;
		DCOORD screenCoordB;

		if (!get_screen_pos(ePair->second, vertsdata, pd, &screenCoordB)) continue;

		DCOORD screenCoordMid;
		midpoint(&screenCoordA, &screenCoordB, &screenCoordMid);

		if (screenCoordMid.x > clientState->mainFrameSize.width || screenCoordMid.x < -100) continue;
		if (screenCoordMid.y > clientState->mainFrameSize.height || screenCoordMid.y < -100) continue;


		if (clientState->modes.show_heat_location == eHeatEdges)
		{
			unsigned long edgeWeight = e->chainedWeight;
			if (edgeWeight < 2) continue;

			string weightString = to_string(edgeWeight);
			al_draw_text(clientState->instructionFont, clientState->config->heatmap.lineTextCol, screenCoordMid.x + INS_X_OFF,
				clientState->mainFrameSize.height - screenCoordMid.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
				weightString.c_str());
		}
		else
		{
			displayNodes.insert(firstNode);
			displayNodes.insert(internalProtoGraph->safe_get_node(ePair->second));
		}
		
	}

	if (clientState->modes.show_heat_location == eHeatNodes)
	{
		set <node_data *>::iterator nodesIt = displayNodes.begin();
		for (; nodesIt != displayNodes.end(); ++nodesIt)
		{
			node_data *n = *nodesIt;
			if (n->executionCount == 1) continue;

			DCOORD screenCoordN;
			if (!get_screen_pos(n->index, vertsdata, pd, &screenCoordN)) continue; //in graph but not rendered

			ALLEGRO_COLOR *textcol;
			if (!n->unreliableCount)
				textcol = &al_col_white;
			else
				textcol = &al_col_cyan;

			al_draw_text(clientState->instructionFont, *textcol, screenCoordN.x + INS_X_OFF,
				clientState->mainFrameSize.height - screenCoordN.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
				to_string(n->executionCount).c_str());
		}
	}
}

//this fails if we are drawing a node that has been recorded on the graph but not rendered graphically
//takes a node index and returns the x/y on the screen
bool sphere_graph::get_screen_pos(NODEINDEX nodeIndex, GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos)
{
	FCOORD graphPos;
	if (!vdata->get_coord(nodeIndex, &graphPos)) return false;

	gluProject(graphPos.x, graphPos.y, graphPos.z,
		pd->model_view, pd->projection, pd->viewport,
		&screenPos->x, &screenPos->y, &screenPos->z);
	return true;
}

