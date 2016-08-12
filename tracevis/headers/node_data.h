#pragma once
#include "stdafx.h"
#include "graph_display_data.h"
#include "traceStructs.h"
#include "traceConstants.h"
#include "mathStructs.h"

class node_data
{
public:
	node_data();
	~node_data();
	bool serialise(ofstream *file);
	DCOORD get_screen_pos(GRAPH_DISPLAY_DATA *vdata, PROJECTDATA *pd);
	FCOORD sphereCoordB(MULTIPLIERS *dimensions, float diamModifier);

	unsigned int index = 0;
	VCOORD vcoord;
	int conditional = NOTCONDITIONAL;
	INS_DATA* ins = NULL;
	bool external = false;
	string nodeSym;
	int nodeMod;
	//arg number, contents
	vector<pair<int, string>> funcargs;
	//number of external functions called
	unsigned childexterns = 0;
	unsigned long address = 0; //todo: this is only used in externs. bit big?
};

