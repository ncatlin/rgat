/*
Copyright 2016-2017 Nia Catlin

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
Creates a tree layout for a plotted graph
*/

#include "stdafx.h"
#include "tree_graph.h"

#include <gl/GLU.h>
#include "widgets\GraphPlotGLWidget.h"

//A: Horizontal separation 
//B: Vertical separation
#define PREVIEW_PIX_PER_A_COORD 3
#define PREVIEW_PIX_PER_B_COORD 4


#define DEFAULT_PIX_PER_A_COORD 80
#define DEFAULT_PIX_PER_B_COORD 50

#define AMULT 1
#define BMULT 1

#define CALLA 18
#define CALLB 12

#define JUMPA 16
#define JUMPB 3

//placement of external nodes, relative to the first caller
#define EXTERNA -4
#define EXTERNB 8

//controls placement of the node after a return
#define RETURNA_OFFSET 0
#define RETURNB_OFFSET 2


//how to adjust placement if node would be place on prexisting node
#define JUMPA_CLASH 1
#define JUMPB_CLASH -1
#define CALLA_CLASH 3
#define CALLB_CLASH 3

void tree_graph::initialiseDefaultDimensions()
{
	wireframeSupported = false;
	//preview_scalefactors->AEDGESEP = 0.15;
	//preview_scalefactors->BEDGESEP = 0.15;
	//preview_scalefactors->size = 20;
	//preview_scalefactors->baseSize = 20;

	defaultViewShift = make_pair(0, 0);
	//defaultZoom = 1600;

	preview_scalefactors->plotSize = 600;
	preview_scalefactors->basePlotSize = 600;
	preview_scalefactors->pix_per_A = PREVIEW_PIX_PER_A_COORD;
	preview_scalefactors->pix_per_B = PREVIEW_PIX_PER_B_COORD;

	main_scalefactors->plotSize = 2000;
	main_scalefactors->basePlotSize = 2000;
	main_scalefactors->pix_per_A = DEFAULT_PIX_PER_A_COORD;
	main_scalefactors->pix_per_B = DEFAULT_PIX_PER_B_COORD;

	view_shift_x = 0;
	view_shift_y = 0;
	cameraZoomlevel = 10000;
}

void tree_graph::initialise()
{
	layout = eTreeLayout;
}


tree_graph::~tree_graph()
{
}

/*performs an action (call,jump,etc) from lastNode, places new position in positionStruct
this is the function that determines how the graph is laid out

for this tree the depth is added down in y axis
spacing is done by spreading out in x/z axes
*/
void tree_graph::positionVert(void *positionStruct, node_data *n, PLOT_TRACK *lastNode)
{
	TREECOORD *newPosition = (TREECOORD *)positionStruct;

	TREECOORD *oldPosition = get_node_coord(lastNode->lastVertID);
	if (!oldPosition)
	{
		cerr << "Waiting for node " << lastNode->lastVertID;
		int waitPeriod = 5;
		int iterations = 1;
		do
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(waitPeriod));
			waitPeriod += (150 * iterations++);
			oldPosition = get_node_coord(lastNode->lastVertID);
		} while (!oldPosition);
	}

	long x = oldPosition->x;
	long y = oldPosition->y;
	long z = oldPosition->z;
	int clash = 0;

	//long oldy = oldPosition->y;
	//long extraB = oldb - (-1*lastNode->lastVertID);

	//TREECOORD *position = (TREECOORD *)positionStruct;
	if (n->external)
	{
		node_data *lastNodeData = internalProtoGraph->safe_get_node(lastNode->lastVertID);

		y = y + lastNodeData->childexterns + EXTERNB * -1;

		newPosition->x = x + 2 * lastNodeData->childexterns + EXTERNA;
		newPosition->y = y;
		newPosition->z = z;

		std::cout << "Extern node " << n->index << " x: " << newPosition->x << " y: " << newPosition->y << " z: " << newPosition->z << std::endl;
		return;
	}

	switch (lastNode->lastVertType)
	{

	//small vertical distance between instructions in a basic block	
	case eNodeNonFlow:
	{
		//std::cout << "noflow...";
		y = y + -1 * BMULT;
		break;
	}

	case eNodeJump://long diagonal separation to show distinct basic blocks
	{
		//check if this is a conditional which fell through (ie: sequential)
		node_data *lastNodeData = internalProtoGraph->safe_get_node(lastNode->lastVertID);
		if (lastNodeData->conditional && n->address == lastNodeData->ins->condDropAddress)
		{
			//std::cout << "noflowcond...";
			y= y + -1 * BMULT;
			break;
		}
		//notice lack of break
	}

	case eNodeException:
	{
		x += JUMPA * AMULT;
		y = y + (JUMPB * BMULT * -1);
		break;
	}

	//long purple line to show possible distinct functional blocks of the program
	case eNodeCall:
	{
		//std::cout << "call...";
		if (!n->external)
		{
			if (!n->ins->hasSymbol && n->label.isEmpty())
			{
				ADDRESS_OFFSET nodeoffset = n->address - internalProtoGraph->moduleBase;
				n->label = "[InternalFunc_" + QString::number(internalProtoGraph->internalPlaceholderFuncNames.size() + 1) + "]";
				n->placeholder = true;

				callStackLock.lock();
				internalProtoGraph->internalPlaceholderFuncNames[nodeoffset] = n->index;
				callStackLock.unlock();
			}
		}
		//note: b sometimes huge after this?
		//a += CALLA * AMULT;
		x += CALLA * AMULT;
		y += CALLB * BMULT * -1;
		break;
	}

	case eNodeReturn:
		//previous externs handled same as previous returns
		//std::cout << "ret...";
		//b += EXTERNB * BMULT * -10;
	case eNodeExternal:
	{
		//a += EXTERNA * AMULT * -1;
		//b += EXTERNB * BMULT * -1;

		
		//std::cout << "ext...";
		//returning to address in call stack?
		NODEINDEX resultNodeIDX = -1;
		vector<pair<MEM_ADDRESS, NODEINDEX>> *callStack;
		if (mainnodesdata->isPreview())
			callStack = &previewCallStack;
		else
			callStack = &mainCallStack;
		vector<pair<MEM_ADDRESS, NODEINDEX>>::iterator stackIt;

		callStackLock.lock();
		bool foundCallerOnStack = false;
		for (stackIt = callStack->begin(); stackIt != callStack->end(); ++stackIt)
			if (stackIt->first == n->address)
			{
				resultNodeIDX = stackIt->second;
				foundCallerOnStack = true;
				break;
			}
		

		//if so, position next node near caller
		if (foundCallerOnStack)
		{
			TREECOORD *caller = get_node_coord(resultNodeIDX);
			assert(caller);
			x = caller->x + RETURNA_OFFSET;
			y = caller->y;// -(-1 * resultNodeIDX);
			y = caller->y + RETURNB_OFFSET * -1;
			//extraB += RETURNB_OFFSET * -1;

			//may not have returned to the last item in the callstack
			//delete everything inbetween
			callStack->resize(stackIt - callStack->begin());
		}
		else
		{
			x += EXTERNA * AMULT;
			y += EXTERNB * BMULT;
		}
		callStackLock.unlock();
		
		break;
	}

	default:
		if (lastNode->lastVertType != eFIRST_IN_THREAD)
			cerr << "[rgat]ERROR: Unknown Last instruction type " << lastNode->lastVertType << endl;
		break;
	}

	while (usedCoords.find(make_pair(x, y)) != usedCoords.end())
	{
		x += 4;
		y -= 3;
		++clash;
	}

	newPosition->x = x;
	newPosition->y = y;// -1 * n->index + extraB;
	newPosition->z = z;
	//std::cout << "node " << n->index << " a: " << position->a << " b: " << position->b << " c: " <<position->c << " addr: 0x" << n->address << std::endl;
	//cout << "Position of node " << n->index << " = " << a << " , " << b << "," << c << endl;
}

TREECOORD * tree_graph::get_node_coord(NODEINDEX idx)
{
	if (idx < node_coords->size())
	{
		TREECOORD *result;
		acquire_nodecoord_read();
		result = &node_coords->at(idx);
		release_nodecoord_read();
		return result;
	}
	return 0;
}

//function names as they are executed
void tree_graph::write_rising_externs(PROJECTDATA *pd, graphGLWidget &gltarget)
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

	vector <pair<NODEINDEX, EXTTEXT>>::iterator displayNodeListIt = displayNodeList.begin();

	for (; displayNodeListIt != displayNodeList.end(); ++displayNodeListIt)
	{
		internalProtoGraph->getNodeReadLock();
		//TREECOORD *coord = get_node_coord(displayNodeListIt->first);
		internalProtoGraph->dropNodeReadLock();

		//EXTTEXT *extxt = &displayNodeListIt->second;


		if (!get_screen_pos(displayNodeListIt->first, mainnodesdata, pd, &nodepos))
			continue;

		if (!is_on_screen(nodepos, gltarget.width(), gltarget.height()))
			continue;

		//todo - write rising extern!

		//al_draw_text(font, al_col_green, nodepos.x, height - nodepos.y - extxt->yOffset,
		//	0, extxt->displayString.c_str());
		//painter.drawText(nodepos.x, windowHeight - nodepos.y - extxt->yOffset, extxt->displayString.c_str());
	}

}

//take longitude a, latitude b, output coord in space
void tree_graph::treeCoord(long ix, long y, long z, FCOORD *coord, GRAPH_SCALE *dimensions)
{
	float x = ix*dimensions->pix_per_A;
	y *= dimensions->pix_per_B;

	coord->x = x;
	coord->y = y;
	//coord->z = c;
}

//take coord in space, convert back to a/b/c
void tree_graph::treeAB(FCOORD &coord, GRAPH_SCALE *mults, long *a, long *b, long *c)
{
	*a = coord.x;
	*b = coord.y;
	//*c = coord->z;
}

//reads the list of nodes/edges, creates opengl vertex/colour data
void tree_graph::render_static_graph()
{
	int drawCount = render_new_edges();
	if (drawCount)
		needVBOReload_main = true;

	redraw_anim_edges();
}

//draws a line from the center of the layout to nodepos. adds lengthModifier to the end
void tree_graph::drawHighlight(NODEINDEX nodeIndex, GRAPH_SCALE *scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget)
{
	FCOORD nodeCoordxyz;
	TREECOORD *nodeCoordTree = get_node_coord(nodeIndex);
	if (!nodeCoordTree) return;

	float adjY = nodeCoordTree->y;
	treeCoord(nodeCoordTree->x, adjY, 1, &nodeCoordxyz, scale);
	//todo implement
	//drawHighlightLine(plotwindow, nodeCoordxyz, colour);
}

//draws a line from the center of the layout to nodepos. adds lengthModifier to the end
void tree_graph::drawHighlight(GENERIC_COORD& nodeCoord, GRAPH_SCALE *scale, QColor &colour, int lengthModifier, graphGLWidget &gltarget)
{
	FCOORD nodeCoordxyz;
//	TREECOORD *treeNodeCoord = (TREECOORD *)nodeCoord;
	//float adjB = treeNodeCoord->b + float(sphereNodeCoord->bMod * BMODMAG);
	//sphereCoord(sphereNodeCoord->a, adjB, &nodeCoordxyz, scale, lengthModifier);
	//drawHighlightLine(nodeCoordxyz, colour);
}


//take the a/b/bmod coords, convert to opengl coordinates based on supplied sphere multipliers/size
FCOORD tree_graph::nodeIndexToXYZ(NODEINDEX index, GRAPH_SCALE *dimensions, float diamModifier)
{
	TREECOORD *nodeCoord = get_node_coord(index);

	FCOORD result;
	treeCoord(nodeCoord->x, nodeCoord->y, nodeCoord->z, &result, dimensions);
	return result;
}


//IMPORTANT: Must have edge reader lock to call this
bool tree_graph::render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata,QColor *colourOverride, bool preview, bool noUpdate)
{
	size_t nodeCoordQty = node_coords->size();
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

	long arraypos = 0;
	QColor &edgeColour = colourOverride ? *colourOverride : graphColours->at(e->edgeClass);


	int vertsDrawn = drawCurve(edgedata, srcc, targc, edgeColour, e->edgeClass, scaling, &arraypos);

	//previews, diffs, etc where we don't want to affect the original edges
	if (!noUpdate && !preview)
	{
		e->vertSize = vertsDrawn;
		e->arraypos = arraypos;
	}
	return true;
}

//connect two nodes with an edge of automatic number of vertices
int tree_graph::drawCurve(GRAPH_DISPLAY_DATA *linedata, FCOORD &startC, FCOORD &endC,
	QColor &colour, int edgeType, GRAPH_SCALE *dimensions, long *arraypos)
{

	float edgeLen = linedist(startC, endC);

	int curvePoints;

	switch (edgeType)
	{
	case eEdgeNew:
	{
		//todo: make this number much smaller for previews
		curvePoints = edgeLen < 80 ? 1 : LONGCURVEPTS;
		break;
	}

	case eEdgeOld:
	case eEdgeReturn:
	{
		curvePoints = edgeLen < 80 ? 1 : LONGCURVEPTS;
		break;
	}

	case eEdgeCall:
	case eEdgeLib:
	case eEdgeException:
	{
		curvePoints = LONGCURVEPTS;
		break;
	}

	default:
		cerr << "[rgat]Error: Drawcurve unknown edgeType " << edgeType << endl;
		return 0;
	}

	if (curvePoints == LONGCURVEPTS)
	{

		FCOORD bezierC;
		midpoint(startC, endC, &bezierC);
		float lineMiddleShift = edgeLen / 10;
		bezierC.x -= lineMiddleShift;
		bezierC.y += lineMiddleShift;
		bezierC.z -= lineMiddleShift;
		int vertsdrawn = linedata->drawLongCurvePoints(bezierC, startC, endC, colour, edgeType, arraypos);
		return vertsdrawn;
	}
	else
	{
		linedata->drawShortLinePoints(startC, endC, colour, arraypos);
		return 2;
	}
}


//converts a single node into node vertex data
void tree_graph::add_node(node_data *n, PLOT_TRACK *lastNode, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
	GRAPH_SCALE *dimensions)
{
	TREECOORD * nodeCoord;
	if (n->index >= node_coords->size())
	{
		TREECOORD tempPos;
		if (node_coords->empty())
		{
			assert(n->index == 0);
			tempPos = { 0,0,1 };
			nodeCoord = &tempPos;

			acquire_nodecoord_write();
			node_coords->push_back(tempPos);
			release_nodecoord_write();
		}
		else
		{
			positionVert(&tempPos, n, lastNode);
			nodeCoord = &tempPos;

			acquire_nodecoord_write();
			node_coords->push_back(tempPos);
			release_nodecoord_write();
		}

		updateStats(tempPos.x, tempPos.y, tempPos.z);
		usedCoords.emplace(make_pair(make_pair(tempPos.x, tempPos.y), true));
	}
	else
		nodeCoord = &node_coords->at(n->index);

	FCOORD screenc;

	treeCoord(nodeCoord->x, nodeCoord->y, nodeCoord->z, &screenc, dimensions);

	vector<GLfloat> *staticNodePosition = vertdata->acquire_pos_write(677);
	vector<GLfloat> *staticNodeColour = vertdata->acquire_col_write();

	staticNodePosition->push_back(screenc.x);
	staticNodePosition->push_back(screenc.y);
	staticNodePosition->push_back(screenc.z);

	*lastNode = setLastNode(n->index);

	QColor &active_col = graphColours->at(lastNode->lastVertType);
	staticNodeColour->push_back(active_col.redF());
	staticNodeColour->push_back(active_col.greenF());
	staticNodeColour->push_back(active_col.blueF());
	staticNodeColour->push_back(1);

	vertdata->set_numVerts(vertdata->get_numVerts() + 1);

	vertdata->release_col_write();
	vertdata->release_pos_write();

	//place node on the animated version of the graph
	if (!vertdata->isPreview())
	{
		vector<GLfloat> *animNodeColour = animvertdata->acquire_col_write();

		animNodeColour->push_back(active_col.redF());
		animNodeColour->push_back(active_col.greenF());
		animNodeColour->push_back(active_col.blueF());
		animNodeColour->push_back(0);

		animvertdata->set_numVerts(vertdata->get_numVerts() + 1);
		animvertdata->release_col_write();
	}
}

void tree_graph::orient_to_user_view()
{
	glTranslatef(0, 0, -cameraZoomlevel);
	glTranslatef(0, view_shift_y * 160, 0); //todo: make this depend on zoom level
	glTranslatef(-view_shift_x * 1000, 0, 0);
}

void tree_graph::performMainGraphDrawing(graphGLWidget &gltarget)
{
	//if (get_pid() != clientState->activePid->PID) return;

	//add any new logged calls to the call log window
	//if (clientState->textlog && clientState->logSize < internalProtoGraph->loggedCalls.size())
	//	clientState->logSize = internalProtoGraph->fill_extern_log(clientState->textlog, clientState->logSize);

	//line marking last instruction
	//<there may be a need to do something different depending on currentUnchainedBlocks.empty() or not>
	drawHighlight(lastAnimatedNode, main_scalefactors, clientState->config.mainColours.activityLine, 0, gltarget);

	//highlight lines
	if (highlightData.highlightState)
	{
		display_highlight_lines(&highlightData.highlightNodes,
			clientState->config.mainColours.highlightLine, clientState->config.highlightProtrusion, gltarget);
	}


	labelPositions.clear();
	if (clientState->heatmapMode)
	{
		display_big_heatmap(gltarget);
	}
	else if (clientState->conditionalsMode)
	{
		display_big_conditional(gltarget);
	}
	else
	{
		PROJECTDATA pd;
		gltarget.gather_projection_data(&pd);
		display_graph(&pd, gltarget);
		write_rising_externs(&pd, gltarget);
	}
}

//standard animated or static display of the active graph
void tree_graph::display_graph(PROJECTDATA *pd, graphGLWidget &gltarget)
{
	if (!trySetGraphBusy()) return;

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
		if (clientState->config.showRisingAnimated)
		{	//show label of extern we are blocked on
			//called in main thread

			node_data *n = internalProtoGraph->safe_get_node(lastMainNode.lastVertID);
			if (n && n->external)
			{
				DCOORD screenCoord;
				if (!get_screen_pos(lastMainNode.lastVertID, get_mainnodes(), pd, &screenCoord)) {
					setGraphBusy(false, 83);
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

/*
//iterate through all the nodes, draw instruction text for the ones in view
void tree_graph::draw_instruction_text(int zdist, PROJECTDATA *pd, graphGLWidget &gltarget)
{
	//iterate through nodes looking for ones that map to screen coords
	gltarget->glBindBuffer(GL_ARRAY_BUFFER, 0);

	bool show_all_always = (clientState->show_ins_text == eInsTextForced);
	NODEINDEX numVerts = node_coords->size();
	GRAPH_DISPLAY_DATA *mainverts = get_mainnodes();
	stringstream ss;
	DCOORD screenCoord;
	string itext("?");

	int textcount = 0;
	for (NODEINDEX i = 0; i < numVerts; ++i)
	{
		node_data *n = internalProtoGraph->safe_get_node(i);
		if (n->external) continue;

		TREECOORD *nodeCoord = get_node_coord(i);

		if (!nodeCoord) continue; //usually happens with block interrupted by exception
		if (!get_screen_pos(i, mainverts, pd, &screenCoord)) continue; //in graph but not rendered
		if (!is_on_screen(&screenCoord, gltarget->width(), gltarget->height())) continue;

		if (show_all_always)
			itext = n->ins->ins_text;
		else
		{
			if (cameraZoomlevel < 2000 && clientState->show_ins_text == eInsTextAuto)
				itext = n->ins->ins_text;
			else
				itext = n->ins->mnemonic;
		}
			
		textcount++;
		ss << std::dec << n->index << "-0x" << std::hex << n->ins->address << ":" << itext;
		//al_draw_text(clientState->standardFont, al_col_white, screenCoord.x + INS_X_OFF,
		//	window->height() - screenCoord.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
		//	ss.str().c_str());
		cout << " text6262 ";
		ss.str("");
	}
}

//TODO, merge with proto graph
//show functions/args for externs in active graph
void tree_graph::show_symbol_labels(PROJECTDATA *pd, graphGLWidget &gltarget)
{
	cout << " symbtodo ";
	return;

	GRAPH_DISPLAY_DATA *mainverts = get_mainnodes();

	bool showExterns = (clientState->show_symbol_location != eSymboltextOff);
	bool showDbgSymbols = false;//clientState->modes.show_dbg_symbol_text;

	if (!showExterns && !showDbgSymbols) return;

	vector<NODEINDEX> externListCopy;

	if (showExterns)
	{
		QPainter painter(gltarget);
		painter.setPen(clientState->config.mainColours.symbolTextExternal);
		painter.setFont(clientState->instructionFont);

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
			if (is_on_screen(&screenCoord, gltarget->width(), gltarget->height()))
				draw_func_args(&painter, screenCoord, n, gltarget);
		}
		painter.end();
	}

	vector<NODEINDEX> internListCopy;

	if (showDbgSymbols)
	{
		obtainMutex(internalProtoGraph->highlightsMutex, 1053);
		if (showDbgSymbols)
			internListCopy = internalProtoGraph->internalSymbolList;
		dropMutex(internalProtoGraph->highlightsMutex);

		vector<NODEINDEX>::iterator internSymIt = internListCopy.begin();
		for (; internSymIt != internListCopy.end(); ++internSymIt)
		{
			node_data *n = internalProtoGraph->safe_get_node(*internSymIt);
			assert(!n->external);

			DCOORD screenCoord;
			if (!get_screen_pos(*internSymIt, mainverts, pd, &screenCoord)) continue;

			cout << " todosyttt ";
			//if (is_on_screen(&screenCoord, clientState->mainFrameSize.width, clientState->mainFrameSize.height))
			//	draw_internal_symbol(clientState, clientState->standardFont, screenCoord, n);
		}
	}
}
*/
/*
//only draws text for instructions with unsatisfied conditions
void tree_graph::draw_condition_ins_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata)
{
	//iterate through nodes looking for ones that map to screen coords
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	bool show_all_always = (clientState->modes.show_ins_text == eInsTextForced);
	NODEINDEX numVerts = vertsdata->get_numVerts();
	GLfloat *vcol = vertsdata->readonly_col();
	for (NODEINDEX i = 0; i < numVerts; ++i)
	{
		node_data *n = internalProtoGraph->safe_get_node(i);

		if (n->external || !n->ins->conditional) continue;

		TREECOORD *nodeCoord = get_node_coord(i);
		if (!nodeCoord) continue;
		//if (!a_coord_on_screen(nodeCoord->a, clientState->leftcolumn, clientState->rightcolumn,
		//	main_scalefactors->AEDGESEP)) continue;

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
		al_draw_text(clientState->standardFont, textcol, screenCoord.x + INS_X_OFF,
			clientState->mainFrameSize.height - screenCoord.y + COND_INSTEXT_Y_OFF, ALLEGRO_ALIGN_LEFT,
			ss.str().c_str());
	}
}
*/

/*
//draw number of times each edge has been executed in middle of edge
void tree_graph::draw_edge_heat_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd)
{
	plotted_graph *graph = (plotted_graph *)clientState->activeGraph;

	glBindBuffer(GL_ARRAY_BUFFER, 0);//need this to make text work
	GRAPH_DISPLAY_DATA *vertsdata = get_mainnodes();

	//iterate through nodes looking for ones that map to screen coords
	int edgelistIdx = 0;
	int edgelistEnd = graph->heatmaplines->get_renderedEdges();

	set <node_data *> displayNodes;

	EDGELIST *edgelist = internalProtoGraph->edgeLptr();
	for (; edgelistIdx < edgelistEnd; ++edgelistIdx)
	{
		NODEPAIR *ePair = &edgelist->at(edgelistIdx);
		node_data *firstNode = internalProtoGraph->safe_get_node(ePair->first);

		//should these checks should be done on the midpoint rather than the first node?
		if (firstNode->external) continue; //don't care about instruction in library call

		TREECOORD *firstNodeCoord = get_node_coord(ePair->first);
		if (!firstNodeCoord) continue;
		//if (!a_coord_on_screen(firstNodeCoord->a, clientState->leftcolumn,
		//	clientState->rightcolumn, graph->main_scalefactors->AEDGESEP))
		//	continue;

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

		displayNodes.insert(firstNode);
		displayNodes.insert(internalProtoGraph->safe_get_node(ePair->second));

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
		node_data *n = *nodesIt;
		DCOORD screenCoordN;
		if (n->executionCount == 1) continue;
		if (!get_screen_pos(n->index, vertsdata, pd, &screenCoordN)) continue; //in graph but not rendered

		al_draw_text(clientState->standardFont, al_col_white, screenCoordN.x + INS_X_OFF,
			clientState->mainFrameSize.height - screenCoordN.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
			to_string(n->executionCount).c_str());
	}
}
*/

//this fails if we are drawing a node that has been recorded on the graph but not rendered graphically
//takes a node index and returns the x/y on the screen
bool tree_graph::get_screen_pos(NODEINDEX nodeIndex, GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos)
{
	FCOORD graphPos;
	if (!vdata->get_coord(nodeIndex, &graphPos)) return false;

	gluProject(graphPos.x, graphPos.y, graphPos.z,
		pd->model_view, pd->projection, pd->viewport,
		&screenPos->x, &screenPos->y, &screenPos->z);
	return true;
}

//returns the screen coordinate of a node if it is on the screen
bool tree_graph::get_visible_node_pos(NODEINDEX nidx, DCOORD *screenPos, SCREEN_QUERY_PTRS *screenInfo, graphGLWidget &gltarget)
{
	TREECOORD *nodeCoord = get_node_coord(nidx);
	if (!nodeCoord)
		return false; //usually happens with block interrupted by exception

	//todo: needs a quick hereustic

	DCOORD screenCoord;
	if (!get_screen_pos(nidx, screenInfo->mainverts, screenInfo->pd, &screenCoord)) return false; //in graph but not rendered

																								  //not visible if not within bounds of opengl widget rectangle
	if (screenCoord.x > gltarget.width() || screenCoord.x < -100) return false;
	if (screenCoord.y > gltarget.height() || screenCoord.y < -100) return false;

	*screenPos = screenCoord;
	return true;
}
