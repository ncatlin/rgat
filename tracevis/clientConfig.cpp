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
Class that holds the configuration data read from and written to the config file
*/
#include "stdafx.h"
#include "clientConfig.h"
#include "configdefaults.h"
#include "GUIConstants.h"
#include "traceConstants.h"
#include "OSspecific.h"

clientConfig::clientConfig(string filepath)
{
	configFilePath = filepath;
	
	if (fileExists(filepath))
	{
		cout << "[rgat]Loading config file " << filepath << "...";
		if (loadFromFile())
		{
			cout << "complete" << endl;
			return;
		}
		else
		{
			cout << "failed! [old version?], loading from defaults..." << endl;
			string backupFilePath = filepath + ".obsolete";
			renameFile(filepath, backupFilePath);
			loadDefaults();
			saveToFile();
		}
	}
	else
	{
		cout << "[rgat]WARNING: Config file " << filepath << " not found, loading from defaults...\n" << endl;
		loadDefaults();
		saveToFile();
	}
}

clientConfig::~clientConfig()
{
}

//can this be cleaned up?
void argtouni(const char* charstr, unsigned int *result, int *errorCount)
{
	if (!charstr) {
		(*errorCount)++; return;
	}
	*result = atoi(charstr);
}

void argtounl(const char* charstr, unsigned long  *result, int *errorCount)
{
	if (!charstr) {
		(*errorCount)++; return;
	}
	*result = atol(charstr);
}

void argtoi(const char* charstr, int *result, int *errorCount)
{
	if (!charstr) {
		(*errorCount)++; return;
	}
	*result = atoi(charstr);
}

void argtof(const char* charstr, float *result, int *errorCount)
{
	if (!charstr) {
		(*errorCount)++; return;
	}
	*result = atof(charstr);
}

const char* clientConfig::col_to_charstr(ALLEGRO_COLOR col)
{
	stringstream colstream;
	colstream << col.r * 255 << "," << col.g * 255 << "," << col.b * 255 << "," << col.a * 255;
	string *result_s = new string(colstream.str());
	cleanupList.push_back(result_s);
	const char *result = result_s->c_str();
	return result;
}

void clientConfig::charstr_to_col(const char* charstr, ALLEGRO_COLOR* destination, int *errorCount)
{
	if (!charstr) {
		(*errorCount)++; return;
	}

	stringstream colstream(charstr);
	
	colstream >> destination->r;
	destination->r /= 255;
	colstream.ignore();

	colstream >> destination->g;
	destination->g /= 255;
	colstream.ignore();

	colstream >> destination->b;
	destination->b /= 255;
	colstream.ignore();

	colstream >> destination->a;
	destination->a /= 255;
}

bool clientConfig::loadPreview()
{
	int errorCount = 0;
	argtoi(al_get_config_value(alConfig, "Preview", "EDGES_PER_FRAME"), &preview.edgesPerRender, &errorCount);
	argtoi(al_get_config_value(alConfig, "Preview", "MS_BETWEEN_UPDATES"), &preview.processDelay, &errorCount);
	argtoi(al_get_config_value(alConfig, "Preview", "MS_BETWEEN_GRAPHS"), &preview.threadDelay, &errorCount);
	argtof(al_get_config_value(alConfig, "Preview", "SPIN_PER_FRAME"), &preview.spinPerFrame, &errorCount);
	argtoi(al_get_config_value(alConfig, "Preview", "FPS"), &preview.FPS, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Preview", "HIGHLIGHT_ACTIVE_RGBA"), &preview.activeHighlight, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Preview", "HIGHLIGHT_INACTIVE_RGBA"), &preview.inactiveHighlight, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Preview", "BACKGROUND_RGBA"), &preview.background, &errorCount);
	return (errorCount == 0);
}

bool clientConfig::loadPaths()
{
	const char *savepath = al_get_config_value(alConfig, "Paths", "SAVE_PATH");
	if (!savepath) return false;
	saveDir = string(savepath);

	savepath = al_get_config_value(alConfig, "Paths", "DYNAMORIO_PATH");
	if (!savepath) return false;
	DRDir = string(savepath);

	savepath = al_get_config_value(alConfig, "Paths", "CLIENT_PATH");
	if (!savepath) return false;
	clientPath = string(savepath);

	savepath = al_get_config_value(alConfig, "Paths", "LAST_PATH");
	if (!savepath) return false;
	lastPath = string(savepath);
	return true;
}

bool clientConfig::loadConditionals()
{
	int errorCount = 0;
	argtoi(al_get_config_value(alConfig, "Conditionals", "MS_BETWEEN_UPDATES"), &conditional.delay, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Conditionals", "EDGE_COLOUR_RGBA"), &conditional.edgeColor, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Conditionals", "BG_COLOUR_RGBA"), &conditional.background, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Conditionals", "NODE_FALLTHROUGH_RGBA") , &conditional.cond_fail, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Conditionals", "NODE_TAKEN_RGBA") , &conditional.cond_succeed, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Conditionals", "NODE_BOTH_RGBA"), &conditional.cond_both, &errorCount);
	return (errorCount == 0);
}

bool clientConfig::loadHeatmap()
{
	int errorCount = 0;
	argtoi(al_get_config_value(alConfig, "Heatmap", "MS_BETWEEN_UPDATES"), &heatmap.delay, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_TEXT_RGBA"), &heatmap.lineTextCol, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ0_COL"), &heatmap.edgeFrequencyCol[0], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ1_COL"), &heatmap.edgeFrequencyCol[1], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ2_COL"), &heatmap.edgeFrequencyCol[2], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ3_COL"), &heatmap.edgeFrequencyCol[3], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ4_COL"), &heatmap.edgeFrequencyCol[4], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ5_COL"), &heatmap.edgeFrequencyCol[5], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ6_COL"), &heatmap.edgeFrequencyCol[6], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ7_COL"), &heatmap.edgeFrequencyCol[7], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ8_COL"), &heatmap.edgeFrequencyCol[8], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Heatmap", "EDGE_FREQ9_COL"), &heatmap.edgeFrequencyCol[9], &errorCount);
	return (errorCount == 0);
}

bool clientConfig::loadColours()
{
	int errorCount = 0;
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "EDGE_CALL_RGBA"), &graphColours.lineColours[ICALL], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "EDGE_OLD_RGBA"), &graphColours.lineColours[IOLD], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "EDGE_RET_RGBA"), &graphColours.lineColours[IRET], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "EDGE_LIB_RGBA"), &graphColours.lineColours[ILIB], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "EDGE_NEW_RGBA"), &graphColours.lineColours[INEW], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "EDGE_EXCEPT_RGBA"), &graphColours.lineColours[IEXCEPT], &errorCount);

	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "NODE_NONFLOW_RGBA"), &graphColours.nodeColours[NONFLOW], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "NODE_JUMP_RGBA"), &graphColours.nodeColours[JUMP], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "NODE_CALL_RGBA"), &graphColours.nodeColours[CALL], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "NODE_RET_RGBA"), &graphColours.nodeColours[RETURN], &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "MainGraph", "NODE_EXTERNAL_RGBA"), &graphColours.nodeColours[EXTERNAL], &errorCount);
	return (errorCount == 0);
}


bool clientConfig::loadFromFile()
{
	int errorCount = 0;
	string cstrpath(configFilePath.begin(), configFilePath.end());
	alConfig = al_load_config_file(cstrpath.c_str());
	if (!alConfig) 
		return false;

	charstr_to_col(al_get_config_value(alConfig, "Wireframe", "COL_RGBA"), &wireframe.edgeColor, &errorCount);

	if (!loadPreview()) 
		return false;
	if (!loadConditionals()) 
		return false;
	if (!loadHeatmap()) 
		return false;


	argtoi(al_get_config_value(alConfig, "Dimensions", "FAR_A_LIMIT"), &farA, &errorCount);
	argtoi(al_get_config_value(alConfig, "Dimensions", "LOW_B_LIMIT"), &lowB, &errorCount);

	charstr_to_col(al_get_config_value(alConfig, "Misc", "MAIN_BACKGROUND_RGBA"), &mainBackground, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Misc", "HIGHLIGHT_RGBA"), &highlightColour, &errorCount);
	argtoi(al_get_config_value(alConfig, "Misc", "HIGHLIGHT_PROTRUSION"), &highlightProtrusion, &errorCount);
	charstr_to_col(al_get_config_value(alConfig, "Misc", "ACTIVITY_MARKER_RGBA"), &activityLineColour, &errorCount);
	argtof(al_get_config_value(alConfig, "Misc", "ANIMATION_FADE_RATE"), &animationFadeRate, &errorCount);
	argtouni(al_get_config_value(alConfig, "Misc", "MAINGRAPH_UPDATE_FREQUENCY_MS"), &renderFrequency, &errorCount);
	argtounl(al_get_config_value(alConfig, "Misc", "TRACE_BUFFER_MAX"), &traceBufMax, &errorCount);
	argtouni(al_get_config_value(alConfig, "Misc", "DEFAULT_MAX_ARG_STORAGE"), &maxArgStorage, &errorCount);
	argtouni(al_get_config_value(alConfig, "Misc", "DEFAULT_MAX_WAIT_FRAMES"), &maxWaitFrames, &errorCount);

	if (!loadColours()) 
		return false;
	if (!loadPaths()) 
		return false;

	al_destroy_config(alConfig);

	if (errorCount) 
		return false;
	initialised = true;
	return true;
}

void clientConfig::cleanup()
{
	vector<string *>::iterator cleanIt = cleanupList.begin();
	for (; cleanIt != cleanupList.end(); ++cleanIt)
		delete *cleanIt;
	cleanupList.clear();
}

void clientConfig::savePreview()
{
	al_add_config_section(alConfig, "Preview");
	al_set_config_value(alConfig, "Preview", "EDGES_PER_FRAME", to_string(preview.edgesPerRender).c_str());
	al_set_config_value(alConfig, "Preview", "MS_BETWEEN_UPDATES", to_string(preview.processDelay).c_str());
	al_set_config_value(alConfig, "Preview", "MS_BETWEEN_GRAPHS", to_string(preview.threadDelay).c_str());
	al_set_config_value(alConfig, "Preview", "SPIN_PER_FRAME", to_string(preview.spinPerFrame).c_str());
	al_set_config_value(alConfig, "Preview", "FPS", to_string(preview.FPS).c_str());
	al_set_config_value(alConfig, "Preview", "HIGHLIGHT_ACTIVE_RGBA", col_to_charstr(preview.activeHighlight));
	al_set_config_value(alConfig, "Preview", "HIGHLIGHT_INACTIVE_RGBA", col_to_charstr(preview.inactiveHighlight));
	al_set_config_value(alConfig, "Preview", "BACKGROUND_RGBA", col_to_charstr(preview.background));
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
	al_set_config_value(alConfig, "Conditionals", "EDGE_COLOUR_RGBA", col_to_charstr(conditional.edgeColor));
	al_set_config_value(alConfig, "Conditionals", "BG_COLOUR_RGBA", col_to_charstr(conditional.background));
	al_set_config_value(alConfig, "Conditionals", "NODE_FALLTHROUGH_RGBA", col_to_charstr(conditional.cond_fail));
	al_set_config_value(alConfig, "Conditionals", "NODE_TAKEN_RGBA", col_to_charstr(conditional.cond_succeed));
	al_set_config_value(alConfig, "Conditionals", "NODE_BOTH_RGBA", col_to_charstr(conditional.cond_both));
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
	al_set_config_value(alConfig, "Heatmap", "MS_BETWEEN_UPDATES", to_string(heatmap.delay).c_str());
	al_set_config_value(alConfig, "Heatmap", "EDGE_TEXT_RGBA", col_to_charstr(heatmap.lineTextCol));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ0_COL", col_to_charstr(heatmap.edgeFrequencyCol[0]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ1_COL", col_to_charstr(heatmap.edgeFrequencyCol[1]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ2_COL", col_to_charstr(heatmap.edgeFrequencyCol[2]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ3_COL", col_to_charstr(heatmap.edgeFrequencyCol[3]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ4_COL", col_to_charstr(heatmap.edgeFrequencyCol[4]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ5_COL", col_to_charstr(heatmap.edgeFrequencyCol[5]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ6_COL", col_to_charstr(heatmap.edgeFrequencyCol[6]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ7_COL", col_to_charstr(heatmap.edgeFrequencyCol[7]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ8_COL", col_to_charstr(heatmap.edgeFrequencyCol[8]));
	al_set_config_value(alConfig, "Heatmap", "EDGE_FREQ9_COL", col_to_charstr(heatmap.edgeFrequencyCol[9]));
}

void clientConfig::loadHeatmapDefaults()
{

	heatmap.delay = HEATMAP_DELAY_MS;
	heatmap.lineTextCol = HEAT_EDGE_TEXT_COL;

	heatmap.edgeFrequencyCol[0] = HEAT_EDGE_COL_FREQ0;
	heatmap.edgeFrequencyCol[1] = HEAT_EDGE_COL_FREQ1;
	heatmap.edgeFrequencyCol[2] = HEAT_EDGE_COL_FREQ2;
	heatmap.edgeFrequencyCol[3] = HEAT_EDGE_COL_FREQ3;
	heatmap.edgeFrequencyCol[4] = HEAT_EDGE_COL_FREQ4;
	heatmap.edgeFrequencyCol[5] = HEAT_EDGE_COL_FREQ5;
	heatmap.edgeFrequencyCol[6] = HEAT_EDGE_COL_FREQ6;
	heatmap.edgeFrequencyCol[7] = HEAT_EDGE_COL_FREQ7;
	heatmap.edgeFrequencyCol[8] = HEAT_EDGE_COL_FREQ8;
	heatmap.edgeFrequencyCol[9] = HEAT_EDGE_COL_FREQ9;
}

void clientConfig::saveColours()
{
	al_add_config_section(alConfig, "MainGraph");
	al_set_config_value(alConfig, "MainGraph", "EDGE_CALL_RGBA", col_to_charstr(graphColours.lineColours[ICALL]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_OLD_RGBA", col_to_charstr(graphColours.lineColours[IOLD]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_RET_RGBA", col_to_charstr(graphColours.lineColours[IRET]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_LIB_RGBA", col_to_charstr(graphColours.lineColours[ILIB]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_NEW_RGBA", col_to_charstr(graphColours.lineColours[INEW]));
	al_set_config_value(alConfig, "MainGraph", "EDGE_EXCEPT_RGBA", col_to_charstr(graphColours.lineColours[IEXCEPT]));

	al_set_config_value(alConfig, "MainGraph", "NODE_NONFLOW_RGBA", col_to_charstr(graphColours.nodeColours[NONFLOW]));
	al_set_config_value(alConfig, "MainGraph", "NODE_JUMP_RGBA", col_to_charstr(graphColours.nodeColours[JUMP]));
	al_set_config_value(alConfig, "MainGraph", "NODE_CALL_RGBA", col_to_charstr(graphColours.nodeColours[CALL]));
	al_set_config_value(alConfig, "MainGraph", "NODE_RET_RGBA", col_to_charstr(graphColours.nodeColours[RETURN]));
	al_set_config_value(alConfig, "MainGraph", "NODE_EXTERNAL_RGBA", col_to_charstr(graphColours.nodeColours[EXTERNAL]));
}

void clientConfig::loadDefaultColours()
{

	graphColours.lineColours[ICALL] = DEFAULT_EDGE_CALL;
	graphColours.lineColours[IOLD] = DEFAULT_EDGE_OLD;
	graphColours.lineColours[IRET] = DEFAULT_EDGE_RET;
	graphColours.lineColours[ILIB] = DEFAULT_EDGE_LIB;
	graphColours.lineColours[INEW] = DEFAULT_EDGE_NEW;
	graphColours.lineColours[IEXCEPT] = DEFAULT_EDGE_EXCEPT;

	graphColours.nodeColours[NONFLOW] = DEFAULT_NODE_STD;
	graphColours.nodeColours[JUMP] = DEFAULT_NODE_JUMP;
	graphColours.nodeColours[CALL] = DEFAULT_NODE_CALL;
	graphColours.nodeColours[RETURN] = DEFAULT_NODE_RET;
	graphColours.nodeColours[EXTERNAL] = DEFAULT_NODE_EXT;
}

void clientConfig::saveToFile()
{
	if (!initialised)
	{
		cerr << "[rgat]ERROR:Attempt to save uninitialised config" << endl;
		assert(0);
	}

	al_set_config_value(alConfig, "Wireframe", "COL_RGBA", col_to_charstr(wireframe.edgeColor));

	savePreview();
	saveConditionals();
	saveHeatmap();

	al_set_config_value(alConfig, "Dimensions", "FAR_A_LIMIT", to_string(farA).c_str());
	al_set_config_value(alConfig, "Dimensions", "LOW_B_LIMIT", to_string(lowB).c_str());

	al_set_config_value(alConfig, "Misc", "MAIN_BACKGROUND_RGBA", col_to_charstr(mainBackground));
	al_set_config_value(alConfig, "Misc", "HIGHLIGHT_RGBA", col_to_charstr(highlightColour));
	al_set_config_value(alConfig, "Misc", "HIGHLIGHT_PROTRUSION", to_string(highlightProtrusion).c_str());
	al_set_config_value(alConfig, "Misc", "ACTIVITY_MARKER_RGBA", col_to_charstr(activityLineColour));
	al_set_config_value(alConfig, "Misc", "ANIMATION_FADE_RATE", to_string(animationFadeRate).c_str());
	al_set_config_value(alConfig, "Misc", "MAINGRAPH_UPDATE_FREQUENCY_MS", to_string(renderFrequency).c_str());
	al_set_config_value(alConfig, "Misc", "TRACE_BUFFER_MAX", to_string(traceBufMax).c_str());
	al_set_config_value(alConfig, "Misc", "DEFAULT_MAX_ARG_STORAGE", to_string(maxArgStorage).c_str());
	al_set_config_value(alConfig, "Misc", "DEFAULT_MAX_WAIT_FRAMES", to_string(maxWaitFrames).c_str());

	al_set_config_value(alConfig, "Paths", "SAVE_PATH", saveDir.c_str());
	al_set_config_value(alConfig, "Paths", "DYNAMORIO_PATH", DRDir.c_str());
	al_set_config_value(alConfig, "Paths", "CLIENT_PATH", clientPath.c_str());
	al_set_config_value(alConfig, "Paths", "LAST_PATH", lastPath.c_str());

	saveColours();
	cleanup();

	if (al_save_config_file(configFilePath.c_str(), alConfig))
		cout << "[rgat]Saved config file " << configFilePath <<endl;
	else
		cerr << "[rgat]Failed to create config file " << configFilePath <<", Allegro error: " << al_get_errno() << endl;
}

void clientConfig::reSaveToFile()
{
	string cstrpath(configFilePath.begin(), configFilePath.end());
	alConfig = al_load_config_file(cstrpath.c_str());
	if (!alConfig) return;

	saveToFile();

	al_destroy_config(alConfig);
}

void clientConfig::updateSavePath(string path)
{
	saveDir = path;
	reSaveToFile();
}

void clientConfig::updateLastPath(string path)
{
	lastPath = path;
	reSaveToFile();
}

void clientConfig::loadDefaultPaths()
{
	saveDir = getModulePath();
	DRDir = getModulePath();
	clientPath = getModulePath();

#ifdef WINDOWS
	saveDir.append("\\saves\\");
	DRDir.append("\\DynamoRIO\\");
	clientPath.append("\\drgat\\");
#elif LINUX
	assert(0);
#endif
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
	renderFrequency = MAINGRAPH_DEFAULT_RENDER_FREQUENCY;
	traceBufMax = DEFAULT_MAX_TRACE_BUFSIZE;
	maxArgStorage = DEFAULT_MAX_ARG_STORAGE;
	maxWaitFrames = DEFAULT_MAX_WAIT_FRAMES;

	loadDefaultColours();

	loadDefaultPaths();
	initialised = true;
}