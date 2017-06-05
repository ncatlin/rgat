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
#include "tree_graph.h"
#include "sphere_graph.h"

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
int drawLongCurvePoints(FCOORD *bezierC, FCOORD *startC, FCOORD *endC, ALLEGRO_COLOR *colour, int edgeType, GRAPH_DISPLAY_DATA *vertdata, int *colarraypos)
{

	//bold start, faded end (convey direction)
	float fadeArray[] = { 1, 1, 1, 0.7, 0.9, 0.9, 0.9, 0.7, 0.8, 0.8, 0.6, 0.7, 0.7, 0.5, 0.5, 0.4, 0.4 };

	int vsadded = 0;
	int curvePoints = LONGCURVEPTS + 2;
	vector<GLfloat> *vertpos = vertdata->acquire_pos_write(63);
	vector<GLfloat> *vertcol = vertdata->acquire_col_write();

	if (!vertpos || !vertcol)
	{
		assert(0);
		return 0;
	}
	*colarraypos = vertcol->size();

	float cols[4] = { colour->r , colour->g, colour->b, colour->a };

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
		fadeA = fadeArray[dt - 1];
		if (fadeA > 1) fadeA = 1;

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



//uninstrumented library calls
//draw text for quantity + symbol + argument indicator
void draw_func_args(VISSTATE *clientState, ALLEGRO_FONT *font, DCOORD screenCoord, node_data *n)
{
	proto_graph * protoGraph = ((plotted_graph *)clientState->activeGraph)->get_protoGraph();
	if (protoGraph->externalSymbolList.empty()) return;


	string modPath;
	clientState->activePid->get_modpath(n->nodeMod, &modPath);

	stringstream argstring;
	argstring << "(" << n->index << ")";
	if (clientState->modes.show_symbol_verbosity == eSymboltextPaths)
		argstring << modPath << ":";

	int numCalls = n->calls;
	string symString;

	if (clientState->modes.show_symbol_verbosity != eSymboltextAddresses)
		clientState->activePid->get_sym(n->nodeMod,n->address,&symString);


	//todo: might be better to find the first symbol in the DLL that has a lower address
	if (symString.empty())
		argstring << basename(modPath) << ":0x" << std::hex << n->address;

	if (numCalls > 1)
		argstring << symString;
	else
		argstring << n->calls << "x " << symString;

	obtainMutex(protoGraph->externGuardMutex,3521);
	if (n->funcargs.empty()) 
		argstring << " ()";
	else
		{
			//(fixed?)TODO: crash here with argIt->second or first == <NULL>. 
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
	dropMutex(protoGraph->externGuardMutex);
	
	al_draw_text(font, al_col_light_green, screenCoord.x + INS_X_OFF + 10,
		clientState->mainFrameSize.height - screenCoord.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
		argstring.str().c_str());

}

void draw_internal_symbol(VISSTATE *clientState, ALLEGRO_FONT *font, DCOORD screenCoord, node_data *n)
{

	string symString;
	clientState->activePid->get_sym(n->nodeMod, n->address, &symString);

	int textLength = al_get_text_width(font, symString.c_str());
	al_draw_text(font, al_col_white, screenCoord.x - textLength,
		clientState->mainFrameSize.height - screenCoord.y + INS_Y_OFF, ALLEGRO_ALIGN_LEFT,
		symString.c_str());

}

//displays the divergence of two selected graphs, defined in diffrenderer
void display_graph_diff(VISSTATE *clientState, diff_plotter *diffRenderer, node_data *divergeNode)
{
	plotted_graph *graph1 = diffRenderer->get_graph(1);
	plotted_graph *diffgraph = diffRenderer->get_diff_graph();
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

	if (clientState->modes.wireframe)
		diffgraph->maintain_draw_wireframe(clientState);

	if (clientState->modes.nodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graph1->graphVBOs, vertsdata->get_numVerts());

	if (clientState->modes.edges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, diffgraph->graphVBOs, diffgraph->get_mainlines()->get_numVerts());

	if (divergeNode)
	{
		void *nodePos = diffRenderer->get_graph(1)->get_node_coord_ptr(divergeNode->index);
		diffgraph->drawHighlight(nodePos, diffgraph->main_scalefactors, &al_col_orange, 10);
	}
	
	float zmul = zoomFactor(clientState->cameraZoomlevel, graph1->main_scalefactors->size);
	
	PROJECTDATA pd;
	bool pdgathered = false;
	if (zmul < EXTERN_VISIBLE_ZOOM_FACTOR)
	{
		gather_projection_data(&pd);
		pdgathered = true;
		diffgraph->show_symbol_labels(clientState, &pd);
	}

	if (clientState->modes.show_ins_text && 
		zmul < INSTEXT_VISIBLE_ZOOMFACTOR && 
		graph1->get_protoGraph()->get_num_nodes() > 2)
	{
		if (!pdgathered)
			gather_projection_data(&pd);
		diffgraph->draw_instruction_text(clientState, zmul, &pd);
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

	pair<unsigned long, unsigned long> heatExtremes = ((plotted_graph *)clientState->activeGraph)->heatExtremes;

	stringstream keytext;
	keytext << "Frequency:  " << heatExtremes.second;
	const std::string& ks = keytext.str();
	int ksWidth = al_get_text_width(clientState->standardFont, ks.c_str()) + 8;
	al_draw_text(clientState->standardFont, al_col_white, keyx - ksWidth, HEATKEY_POS_Y, 0, ks.c_str());

	draw_heatmap_key_blocks(clientState, keyx, HEATKEY_POS_Y-8);

	string keyend = to_string(heatExtremes.first);
	al_draw_text(clientState->standardFont, al_col_white, keyx + 10 * HEATMAP_KEY_SQUARESIZE + 8, HEATKEY_POS_Y, 0, keyend.c_str());
}

//todo: looks awful. draw a dark background behind this
void draw_conditional_key(VISSTATE *clientState)
{
	if (!clientState->activeGraph) return;

	ALLEGRO_FONT *font = clientState->standardFont;
	pair<unsigned long, unsigned long> condCounts = ((plotted_graph *)clientState->activeGraph)->condCounts;
	stringstream keytextA, keytextN;
	keytextA << "Always Taken (" << condCounts.first << ")";
	keytextN << "Never Taken (" << condCounts.second << ")";
	int width1 = al_get_text_width(font, keytextA.str().c_str());
	int width2 = al_get_text_width(font, keytextN.str().c_str());

	int drawX = clientState->mainFrameSize.width - (max(width1, width2) + 8);
	int drawY = MAIN_FRAME_Y;
	al_draw_text(font, clientState->config->conditional.cond_succeed, drawX, drawY, 0, keytextA.str().c_str());
	drawY += al_get_font_line_height(font);
	al_draw_text(font, clientState->config->conditional.cond_fail, drawX, drawY, 0, keytextN.str().c_str());
	
}



