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
Monsterous class that handles the bulk of graph management 
*/

#pragma once
#include "stdafx.h"
#include "node_data.h"
#include "edge_data.h"
#include "graph_display_data.h"
#include "plotted_graph.h"
#include "traceMisc.h"
#include "OSspecific.h"

//max length to display in diff summary
#define MAX_DIFF_PATH_LENGTH 50
#define ANIMATION_ENDED -1
#define ANIMATION_WIDTH 8



#define ANIM_EXEC_TAG 0
#define ANIM_LOOP 1
#define ANIM_LOOP_LAST 2
#define ANIM_UNCHAINED 3
#define ANIM_UNCHAINED_RESULTS 4
#define ANIM_UNCHAINED_DONE 5
#define ANIM_EXEC_EXCEPTION 6

#define KEEP_BRIGHT -1

struct VERTREMAINING {
	unsigned int vertIdx;
	unsigned int timeRemaining;
};

class sphere_node_data
{
public:
	sphere_node_data() {};

	VCOORD vcoord;
	bool get_screen_pos(unsigned int nodeIndex, GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos);
	FCOORD sphereCoordB(MULTIPLIERS *dimensions, float diamModifier);
};

class sphere_graph : public plotted_graph
{

public:
	sphere_graph(PROCESS_DATA* processdata, unsigned int threadID): plotted_graph(processdata, threadID) {};
	~sphere_graph() {};

	void draw_externTexts(ALLEGRO_FONT *font, bool nearOnly, int left, int right, int height, PROJECTDATA *pd);
	void maintain_draw_wireframe(VISSTATE *clientState, GLint *wireframeStarts, GLint *wireframeSizes);
	void plot_wireframe(VISSTATE *clientState);
	int add_node(node_data *n, GRAPH_DISPLAY_DATA *vertdata, GRAPH_DISPLAY_DATA *animvertdata,
		MULTIPLIERS *dimensions, map<int, ALLEGRO_COLOR> *nodeColours);
	void performMainGraphDrawing(VISSTATE *clientState, map <PID_TID, vector<EXTTEXT>> *externFloatingText);
	void display_graph(VISSTATE *clientState, PROJECTDATA *pd);
	void draw_instruction_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd);
	void show_symbol_labels(VISSTATE *clientState, PROJECTDATA *pd);
	void draw_edge_heat_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd);
	void draw_condition_ins_text(VISSTATE *clientState, int zdist, PROJECTDATA *pd, GRAPH_DISPLAY_DATA *vertsdata);

	void positionVert(int *pa, int *pb, int *pbMod, MEM_ADDRESS address, char lastInstructionType);
	void render_static_graph(VISSTATE *clientState);

	void render_edge(NODEPAIR ePair, GRAPH_DISPLAY_DATA *edgedata, map<int, ALLEGRO_COLOR> *lineColours,
		ALLEGRO_COLOR *forceColour, bool preview, bool noUpdate);

	FCOORD nodeCoordB(MULTIPLIERS *dimensions, float diamModifier, unsigned int index);
	void drawHighlight(unsigned int nodeIndex, MULTIPLIERS *scale, ALLEGRO_COLOR *colour, int lengthModifier);

	VCOORD latest_active_node_coord;

	vector <sphere_node_data> nodeGraphicDataList;
	sphere_node_data* get_node_graphicdata(int index)
	{
		//todo mutex, existance check;
		return &nodeGraphicDataList.at(index);
	}
private:
	vector<VCOORD> node_coords;

	bool afterReturn = false;
	char lastRIPType = FIRST_IN_THREAD;

	vector<pair<MEM_ADDRESS, int>> callStack;

	//these are the edges/nodes that are brightend in the animation
	map <NODEPAIR, edge_data *> activeEdgeMap;
	//<index, final (still active) node>
	map <unsigned int, bool> activeNodeMap;

	VCOORD *get_node_coord(unsigned int idx) {
		return &node_coords.at(idx); //mutex?
	}
	VCOORD *get_active_node_coord();
};

