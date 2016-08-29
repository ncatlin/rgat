#include "stdafx.h"
#include "clientConfig.h"
#include "configdefaults.h"
#include "GUIConstants.h"
#include "traceConstants.h"

clientConfig::clientConfig(string filepath)
{
	configFilePath = filepath;
	
	if (al_filename_exists(filepath.c_str()))
	{
		printf("Attempting to load config file %s\n", filepath.c_str());
		loadFromFile();
	}
	else
	{
		printf("Config file %s not found, loading from defaults...\n", filepath.c_str());
		loadDefaults();
	}
}


clientConfig::~clientConfig()
{
}

void clientConfig::loadFromFile()
{
	ALLEGRO_CONFIG *alConfig = al_load_config_file(configFilePath.c_str());
	al_destroy_config(alConfig);
}

void clientConfig::loadDefaults()
{
	wireframe.edgeColor = WIREFRAME_COLOUR;

	preview.edgesPerRender = PREVIEW_EDGES_PER_RENDER;
	preview.processDelay = PREVIEW_UPDATE_DELAY_MS;
	preview.threadDelay = PREVIEW_DELAY_PER_GRAPH;
	preview.spinPerFrame = PREVIEW_SPIN_PER_FRAME;
	preview.FPS = PREVIEW_RENDER_FPS;
	preview.activeHighlight = PREVIEW_ACTIVE_HIGHLIGHT;
	preview.inactiveHighlight = PREVIEW_INACTIVE_HIGHLIGHT;
	preview.background = PREVIEW_BACKGROUND;

	conditional.delay = CONDITIONAL_DELAY_MS;
	conditional.edgeColor = CONDITIONAL_edgeColor;
	conditional.background = CONDITIONAL_background;
	conditional.cond_fail = CONDITIONAL_cond_fail;
	conditional.cond_succeed = CONDITIONAL_cond_succeed;
	conditional.cond_both = CONDITIONAL_cond_both;

	heatmap.delay = HEATMAP_DELAY_MS;
	heatmap.lineTextCol = HEAT_EDGE_TEXT_COL;

	mainBackground = MAIN_BACKGROUND_COLOUR;
	highlightColour = HIGHLIGHT_LINE_COLOUR;
	highlightProtrusion = HIGHLIGHT_LINE_PROTRUSION;
	activityLineColour = ACTIVITY_LINE_COLOUR;

	lowB = GRAPH_LOW_B;
	farA = GRAPH_FAR_A;

	graphColours.lineColours[ICALL] = DEFAULT_EDGE_CALL;
	graphColours.lineColours[IOLD] = DEFAULT_EDGE_OLD;
	graphColours.lineColours[IRET] = DEFAULT_EDGE_RET;
	graphColours.lineColours[ILIB] = DEFAULT_EDGE_LIB;
	graphColours.lineColours[INEW] = DEFAULT_EDGE_NEW;

	graphColours.nodeColours[NONFLOW] = DEFAULT_NODE_STD;
	graphColours.nodeColours[JUMP] = DEFAULT_NODE_JUMP;
	graphColours.nodeColours[CALL] = DEFAULT_NODE_CALL;
	graphColours.nodeColours[RETURN] = DEFAULT_NODE_RET;
	graphColours.nodeColours[EXTERNAL] = DEFAULT_NODE_EXT;

}