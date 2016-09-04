#pragma once
#include "stdafx.h"
#include "graph_display_data.h"
#include "traceStructs.h"
#include "traceConstants.h"
#include "mathStructs.h"

class node_data
{
public:
	node_data() {};
	~node_data() {};
	bool serialise(ofstream *file);
	bool get_screen_pos(GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd, DCOORD *screenPos);
	FCOORD sphereCoordB(MULTIPLIERS *dimensions, float diamModifier);

	unsigned int index = 0;
	VCOORD vcoord;
	int conditional = NOTCONDITIONAL;
	INS_DATA* ins = NULL;
	bool external = false;
	int nodeMod;
	int mutation;
	//list of lists of arg number, contents
	vector<ARGLIST> funcargs;
	unsigned long calls = 1;
	//number of external functions called
	unsigned childexterns = 0;
	unsigned long address = 0; //todo: this is only used in externs. bit big?
	unsigned int parentIdx = 0;
};

