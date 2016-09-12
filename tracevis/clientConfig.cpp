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
		saveToFile();
	}
}


clientConfig::~clientConfig()
{
}

void clientConfig::loadFromFile()
{
	alConfig = al_load_config_file(configFilePath.c_str());
	al_destroy_config(alConfig);
}

void clientConfig::cleanup()
{
	vector<string *>::iterator cleanIt = cleanupList.begin();
	for (; cleanIt != cleanupList.end(); ++cleanIt)
	{
		delete *cleanIt;
	}
}

const char* clientConfig::col_to_charstring(ALLEGRO_COLOR col)
{
	stringstream colstream;
	colstream << col.r*255 << "," << col.g*255 << "," << col.b*255 << "," << col.a*255;
	string *result_s = new string(colstream.str());
	cleanupList.push_back(result_s);
	const char *result = result_s->c_str();
	return result;
}

void clientConfig::savePreview()
{
	al_add_config_section(alConfig, "Preview");
	al_set_config_value(alConfig, "Preview", "EDGES_PER_FRAME", to_string(preview.edgesPerRender).c_str());
	al_set_config_value(alConfig, "Preview", "MS_BETWEEN_UPDATES", to_string(preview.processDelay).c_str());
	al_set_config_value(alConfig, "Preview", "MS_BETWEEN_GRAPHS", to_string(preview.threadDelay).c_str());
	al_set_config_value(alConfig, "Preview", "SPIN_PER_FRAME", to_string(preview.spinPerFrame).c_str());
	al_set_config_value(alConfig, "Preview", "FPS", to_string(preview.FPS).c_str());
	al_set_config_value(alConfig, "Preview", "HIGHLIGHT_ACTIVE_RGBA", col_to_charstring(preview.activeHighlight));
	al_set_config_value(alConfig, "Preview", "HIGHLIGHT_INACTIVE_RGBA", col_to_charstring(preview.inactiveHighlight));
	al_set_config_value(alConfig, "Preview", "BACKGROUND_RGBA", col_to_charstring(preview.background));
}

void clientConfig::loadPreviewDefaults()
{
	preview.edgesPerRender = PREVIEW_EDGES_PER_RENDER;
	preview.processDelay = PREVIEW_UPDATE_DELAY_MS;
	preview.threadDelay = PREVIEW_DELAY_PER_GRAPH;
	preview.spinPerFrame = PREVIEW_SPIN_PER_FRAME;
	preview.FPS = PREVIEW_RENDER_FPS;
	preview.activeHighlight = PREVIEW_ACTIVE_HIGHLIGHT;
	preview.inactiveHighlight = PREVIEW_INACTIVE_HIGHLIGHT;
	preview.background = PREVIEW_BACKGROUND;
}

void clientConfig::saveConditionals()
{
	al_add_config_section(alConfig, "Conditionals");
	al_set_config_value(alConfig, "Conditionals", "MS_BETWEEN_UPDATES", to_string(conditional.delay).c_str());
	al_set_config_value(alConfig, "Conditionals", "EDGE_COLOUR_RGBA", col_to_charstring(conditional.edgeColor));
	al_set_config_value(alConfig, "Conditionals", "EDGE_COLOUR_RGBA", col_to_charstring(conditional.background));
	al_set_config_value(alConfig, "Conditionals", "NODE_FALLTHROUGH_RGBA", col_to_charstring(conditional.cond_fail));
	al_set_config_value(alConfig, "Conditionals", "NODE_TAKEN_RGBA", col_to_charstring(conditional.cond_succeed));
	al_set_config_value(alConfig, "Conditionals", "NODE_BOTH_RGBA", col_to_charstring(conditional.cond_both));
}

void clientConfig::loadConditionalDefaults()
{
	conditional.delay = CONDITIONAL_DELAY_MS;
	conditional.edgeColor = CONDITIONAL_edgeColor;
	conditional.background = CONDITIONAL_background;
	conditional.cond_fail = CONDITIONAL_cond_fail;
	conditional.cond_succeed = CONDITIONAL_cond_succeed;
	conditional.cond_both = CONDITIONAL_cond_both;
}

void clientConfig::saveHeatmap()
{
	al_add_config_section(alConfig, "Heatmap");
	al_set_config_value(alConfig, "Heatmap", "DELAY_MS", to_string(heatmap.delay).c_str());
	al_set_config_value(alConfig, "Heatmap", "EDGE_TEXT_RGBA", col_to_charstring(heatmap.lineTextCol));
}

void clientConfig::loadHeatmapDefaults()
{

	heatmap.delay = HEATMAP_DELAY_MS;
	heatmap.lineTextCol = HEAT_EDGE_TEXT_COL;

	//todo: gradients
}

void clientConfig::saveColours()
{
	al_add_config_section(alConfig, "MainGraph");
	al_set_config_value(alConfig, "MainGraph", "EDGE_CALL_RGBA", col_to_charstring(graphColours.lineColours[ICALL]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_OLD_RGBA", col_to_charstring(graphColours.lineColours[IOLD]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_RET_RGBA", col_to_charstring(graphColours.lineColours[IRET]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_LIB_RGBA", col_to_charstring(graphColours.lineColours[ILIB]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_NEW_RGBA", col_to_charstring(graphColours.lineColours[INEW]));

	al_set_config_value(alConfig, "MainGraph", "NODE_NONFLOW_RGBA", col_to_charstring(graphColours.nodeColours[NONFLOW]));
	al_set_config_value(alConfig, "MainGraph", "NODE_JUMP_RGBA", col_to_charstring(graphColours.nodeColours[JUMP]));
	al_set_config_value(alConfig, "MainGraph", "NODE_CALL_RGBA", col_to_charstring(graphColours.nodeColours[CALL]));
	al_set_config_value(alConfig, "MainGraph", "NODE_RET_RGBA", col_to_charstring(graphColours.nodeColours[RETURN]));
	al_set_config_value(alConfig, "MainGraph", "NODE_EXTERNAL_RGBA", col_to_charstring(graphColours.nodeColours[EXTERNAL]));
}

void clientConfig::loadDefaultColours()
{

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

void clientConfig::saveToFile()
{
	const char *cval = col_to_charstring(wireframe.edgeColor);
	al_set_config_value(alConfig, "Wireframe", "COL_RGBA", col_to_charstring(wireframe.edgeColor));

	savePreview();
	saveConditionals();
	saveHeatmap();

	al_set_config_value(alConfig, "Dimensions", "FAR_A_LIMIT", to_string(farA).c_str());
	al_set_config_value(alConfig, "Dimensions", "LOW_B_LIMIT", to_string(lowB).c_str());

	al_set_config_value(alConfig, "Misc", "MAIN_BACKGROUND_RGBA", col_to_charstring(mainBackground));
	al_set_config_value(alConfig, "Misc", "HIGHLIGHT_RGBA", col_to_charstring(highlightColour));
	al_set_config_value(alConfig, "Misc", "HIGHLIGHT_PROTRUSION", to_string(highlightProtrusion).c_str());
	al_set_config_value(alConfig, "Misc", "ACTIVITY_MARKER_RGBA", col_to_charstring(activityLineColour));
	al_set_config_value(alConfig, "Misc", "ANIMATION_FADE_RATE", to_string(animationFadeRate).c_str());

	saveColours();
	cleanup();

	if (al_save_config_file(configFilePath.c_str(), alConfig))
		printf("Created config file %s\n", configFilePath.c_str());
	else
		printf("Failed to create config file %s: Error %d\n", configFilePath.c_str(), al_get_errno());
}

void clientConfig::loadDefaults()
{
	alConfig = al_create_config();

	wireframe.edgeColor = WIREFRAME_COLOUR;
	
	loadPreviewDefaults();
	loadConditionalDefaults();
	loadHeatmapDefaults();

	lowB = GRAPH_LOW_B;
	farA = GRAPH_FAR_A;

	mainBackground = MAIN_BACKGROUND_COLOUR;
	highlightColour = HIGHLIGHT_LINE_COLOUR;
	highlightProtrusion = HIGHLIGHT_LINE_PROTRUSION;
	activityLineColour = ACTIVITY_LINE_COLOUR;
	animationFadeRate = ANIMATION_FADE_RATE;

	loadDefaultColours();
}