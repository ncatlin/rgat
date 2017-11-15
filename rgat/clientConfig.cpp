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
Class that holds the configuration data read from and written to the config file
*/
#include "stdafx.h"
#include "clientConfig.h"
#include "configdefaults.h"
#include "GUIConstants.h"
#include "traceConstants.h"
#include "OSspecific.h"

clientConfig::clientConfig()
{
	QSettingsObj = new QSettings("rgat", "rgat");
	//QSettingsObj->clear();
	loadSettings();

	//save any default values used
	saveConfig(); 
}

clientConfig::~clientConfig()
{
}

void clientConfig::loadPreview()
{

	preview.edgesPerRender = QSettingsObj->value("Preview/EDGES_PER_FRAME", PREVIEW_EDGES_PER_RENDER).toInt();
	preview.processDelay = QSettingsObj->value("Preview/MS_BETWEEN_UPDATES", PREVIEW_UPDATE_DELAY_MS).toInt();
	preview.threadDelay = QSettingsObj->value("Preview/MS_BETWEEN_GRAPHS", PREVIEW_DELAY_PER_GRAPH).toInt();
	preview.spinPerFrame = QSettingsObj->value("Preview/SPIN_PER_FRAME", PREVIEW_SPIN_PER_FRAME).toInt();
	preview.FPS = QSettingsObj->value("Preview/FPS", PREVIEW_RENDER_FPS).toInt();

	QVariant colourVariant = QSettingsObj->value("Preview/HIGHLIGHT_ACTIVE_RGBA", PREVIEW_ACTIVE_HIGHLIGHT);
	preview.activeHighlight = colourVariant.value<QColor>();
	
	colourVariant = QSettingsObj->value("Preview/HIGHLIGHT_INACTIVE_RGBA", PREVIEW_INACTIVE_HIGHLIGHT);
	preview.inactiveHighlight = colourVariant.value<QColor>();

	colourVariant = QSettingsObj->value("Preview/BACKGROUND_RGBA", PREVIEW_BACKGROUND);
	preview.background = colourVariant.value<QColor>();

}

void clientConfig::loadPaths()
{
	saveDir = QSettingsObj->value("Paths/SAVE_PATH").toString().toStdString();
	if (saveDir.empty() || !boost::filesystem::is_directory(saveDir))
		setDefaultSavePath();

	DRDir = QSettingsObj->value("Paths/DYNAMORIO_PATH").toString().toStdString();
	if (DRDir.empty() || !boost::filesystem::is_directory(DRDir))
		setDefaultDRPath();

	PinDir = QSettingsObj->value("Paths/PIN_PATH").toString().toStdString();
	if (PinDir.empty() || !boost::filesystem::is_directory(PinDir))
		setDefaultPinPath();

	clientPath = QSettingsObj->value("Paths/CLIENT_PATH").toString().toStdString();
	if (clientPath.empty() || !boost::filesystem::is_directory(clientPath))
		setDefaultClientPath();

	lastPath = QSettingsObj->value("Paths/LAST_PATH").toString().toStdString();
}

void clientConfig::loadHeatmap()
{

	heatmap.delay = QSettingsObj->value("Heatmap/MS_BETWEEN_UPDATES", HEATMAP_DELAY_MS).toInt();

	QVariant colourVariant = QSettingsObj->value("Heatmap/EDGE_TEXT_RGBA", HEAT_EDGE_TEXT_COL);
	heatmap.lineTextCol = colourVariant.value<QColor>();

	if (!QSettingsObj->contains("Heatmap/EDGE_FREQ0_COL"))
	{
		setHeatmapDefaults();
		return;
	}

	heatmap.edgeFrequencyCol.resize(10);
	for (int i = 0; i < 10; i++)
	{
		string key = "Heatmap/EDGE_FREQ" + to_string(i) + "_COL";
		colourVariant = QSettingsObj->value(QString::fromStdString(key));
		heatmap.edgeFrequencyCol.at(i) = colourVariant.value<QColor>();
	}

	colourVariant = QSettingsObj->value("Heatmap/BG_COLOUR_RGBA", HEATMAP_background);
	heatmap.background = colourVariant.value<QColor>();

	colourVariant = QSettingsObj->value("Heatmap/HIGHLIGHT", HEATMAP_highlight);
	heatmap.highlight = colourVariant.value<QColor>();
}

void clientConfig::loadConditionals()
{
	conditional.delay = QSettingsObj->value("Conditionals/MS_BETWEEN_UPDATES", CONDITIONAL_DELAY_MS).toInt();

	QVariant colourVariant = QSettingsObj->value("Conditionals/EDGE_COLOUR_RGBA", CONDITIONAL_edgeColor);
	conditional.edgeColor = colourVariant.value<QColor>();

	colourVariant = QSettingsObj->value("Conditionals/BG_COLOUR_RGBA", CONDITIONAL_background);
	conditional.background = colourVariant.value<QColor>();

	colourVariant = QSettingsObj->value("Conditionals/NODE_FALLTHROUGH_RGBA", CONDITIONAL_cond_fail);
	conditional.cond_fail = colourVariant.value<QColor>();

	colourVariant = QSettingsObj->value("Conditionals/NODE_TAKEN_RGBA", CONDITIONAL_cond_succeed);
	conditional.cond_succeed = colourVariant.value<QColor>();

	colourVariant = QSettingsObj->value("Conditionals/NODE_BOTH_RGBA", CONDITIONAL_cond_both);
	conditional.cond_both = colourVariant.value<QColor>();

	colourVariant = QSettingsObj->value("Conditionals/HIGHLIGHT", CONDITIONAL_highlight);
	conditional.highlight = colourVariant.value<QColor>();
}



void clientConfig::loadMaingraphColours()
{

	if (!QSettingsObj->contains("MainGraph/EDGE_CALL_RGBA"))
	{
		setDefaultColours();
		return;
	}

	graphColours.resize(eENLAST);

	graphColours.at(eEdgeNodeType::eEdgeCall) = QSettingsObj->value("MainGraph/EDGE_CALL_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eEdgeOld) = QSettingsObj->value("MainGraph/EDGE_CALL_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eEdgeReturn) = QSettingsObj->value("MainGraph/EDGE_RET_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eEdgeLib) = QSettingsObj->value("MainGraph/EDGE_LIB_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eEdgeNew) = QSettingsObj->value("MainGraph/EDGE_NEW_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eEdgeException) = QSettingsObj->value("MainGraph/EDGE_EXCEPT_RGBA").value<QColor>();

	graphColours.at(eEdgeNodeType::eNodeNonFlow) = QSettingsObj->value("MainGraph/NODE_NONFLOW_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eNodeJump) = QSettingsObj->value("MainGraph/NODE_JUMP_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eNodeCall) = QSettingsObj->value("MainGraph/NODE_CALL_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eNodeReturn) = QSettingsObj->value("MainGraph/NODE_RET_RGBA").value<QColor>();
	graphColours.at(eEdgeNodeType::eNodeExternal) = QSettingsObj->value("MainGraph/NODE_EXTERNAL_RGBA").value<QColor>();
}

void clientConfig::loadColours()
{
	if (QSettingsObj->contains("MainGraph/MAIN_BACKGROUND_RGBA"))
		mainColours.background = QSettingsObj->value("MainGraph/MAIN_BACKGROUND_RGBA").value<QColor>();
	else
		mainColours.background = MAIN_BACKGROUND_COLOUR;

	if (QSettingsObj->contains("MainGraph/HIGHLIGHT_RGBA"))
		mainColours.highlightLine = QSettingsObj->value("MainGraph/HIGHLIGHT_RGBA").value<QColor>();
	else
		mainColours.highlightLine = HIGHLIGHT_LINE_COLOUR;


	if (QSettingsObj->contains("MainGraph/ACTIVITY_MARKER_RGBA"))
		mainColours.activityLine = QSettingsObj->value("MainGraph/ACTIVITY_MARKER_RGBA").value<QColor>();
	else
		mainColours.activityLine = ACTIVITY_LINE_COLOUR;

	if (QSettingsObj->contains("MainGraph/INSTRUCTION_TEXT_RGBA"))
		mainColours.instructionText = QSettingsObj->value("MainGraph/INSTRUCTION_TEXT_RGBA").value<QColor>();
	else
		mainColours.instructionText = INSTRUCTION_TEXT_COLOUR;

	if (QSettingsObj->contains("MainGraph/EXTERNAL_SYM_TEXT_RGBA"))
		mainColours.symbolTextExternal = QSettingsObj->value("MainGraph/EXTERNAL_SYM_TEXT_RGBA").value<QColor>();
	else
		mainColours.symbolTextExternal = EXTERNAL_SYM_TEXT_COLOUR;

	if (QSettingsObj->contains("MainGraph/RISING_EXTERNAL_SYM_TEXT_RGBA"))
		mainColours.symbolTextExternalRising = QSettingsObj->value("MainGraph/RISING_EXTERNAL_SYM_TEXT_RGBA").value<QColor>();
	else
		mainColours.symbolTextExternalRising = RISING_EXTERNAL_SYM_TEXT_COLOUR;

	if (QSettingsObj->contains("MainGraph/INTERNAL_SYM_TEXT_RGBA"))
		mainColours.symbolTextInternal = QSettingsObj->value("MainGraph/INTERNAL_SYM_TEXT_RGBA").value<QColor>();
	else
		mainColours.symbolTextInternal = INTERNAL_SYM_TEXT_COLOUR;

	if (QSettingsObj->contains("MainGraph/RISING_INTERNAL_SYM_TEXT_RGBA"))
		mainColours.symbolTextInternal = QSettingsObj->value("MainGraph/RISING_INTERNAL_SYM_TEXT_RGBA").value<QColor>();
	else
		mainColours.symbolTextInternal = RISING_INTERNAL_SYM_TEXT_COLOUR;

	loadMaingraphColours();
}

void clientConfig::loadTextSettings()
{
	vector<pair<SYMS_VISIBILITY *, QString>> displayAreas;
	displayAreas.push_back(make_pair(&externalSymbolVisibility, "LabelDisplay/ExternalSymbol/"));
	displayAreas.push_back(make_pair(&internalSymbolVisibility, "LabelDisplay/InternalSymbol/"));
	displayAreas.push_back(make_pair(&instructionTextVisibility, "LabelDisplay/Instructions/"));

	pair<SYMS_VISIBILITY *, QString> area;
	foreach(area, displayAreas)
	{
		if (!QSettingsObj->contains(area.second + "Addresses"))
		{
			setDefaultTextSettings();
			return;
		}
		area.first->addresses = QSettingsObj->value(area.second + "Addresses").value<bool>();
		area.first->extraDetail = QSettingsObj->value(area.second + "Arguments").value<bool>();
		area.first->autoVisibleZoom = QSettingsObj->value(area.second + "AutoVisibleZoom").value<float>();
		area.first->duringAnimationFaded = QSettingsObj->value(area.second + "AnimationFaded").value<bool>();
		area.first->duringAnimationHighlighted = QSettingsObj->value(area.second + "AnimationActive").value<bool>();
		area.first->enabled = QSettingsObj->value(area.second + "Enabled").value<bool>();
		area.first->fullPaths = QSettingsObj->value(area.second + "FullPaths").value<bool>();
		area.first->notAnimated = QSettingsObj->value(area.second + "NotAnimated").value<bool>();
		area.first->offsets = QSettingsObj->value(area.second + "Offsets").value<bool>();
	}

	showRisingAnimated = QSettingsObj->value("LabelDisplay/ShowRisingAnimated").value<bool>();
	showNodeIndex = QSettingsObj->value("LabelDisplay/ShowNodeIndex").value<bool>();
	insTextCompactThreshold = QSettingsObj->value("LabelDisplay/InstextCompactThreshold").value<float>();
}

void clientConfig::loadSettings()
{
	if (QSettingsObj->contains("Wireframe/COL_RGBA"))
		wireframe.edgeColor = QSettingsObj->value("Wireframe/COL_RGBA").value<QColor>();
	else
		wireframe.edgeColor = WIREFRAME_COLOUR;

	loadPreview();
	loadConditionals();
	loadHeatmap();

	//argtoi(al_get_config_value(alConfig, "Dimensions", "FAR_A_LIMIT"), &farA, &errorCount);
	//argtoi(al_get_config_value(alConfig, "Dimensions", "LOW_B_LIMIT"), &lowB, &errorCount);

	highlightProtrusion = QSettingsObj->value("MainGraph/HIGHLIGHT_PROTRUSION", HIGHLIGHT_LINE_PROTRUSION).toInt();
	animationFadeRate = QSettingsObj->value("Misc/ANIMATION_FADE_RATE", ANIMATION_FADE_RATE).toFloat();
	animationUpdateRate = QSettingsObj->value("Misc/ANIMATION_UPDATES_PER_FRAME", ANIMATION_UPDATES_PER_FRAME).toUInt();
	renderFrequency = QSettingsObj->value("Misc/MAINGRAPH_UPDATE_FREQUENCY_MS", MAINGRAPH_DEFAULT_RENDER_FREQUENCY).toInt();
	traceBufMax = QSettingsObj->value("Misc/TRACE_BUFFER_MAX", DEFAULT_MAX_TRACE_BUFSIZE).toUInt();
	maxArgStorage = QSettingsObj->value("Misc/DEFAULT_MAX_ARG_STORAGE", DEFAULT_MAX_ARG_STORAGE).toUInt();
	maxWaitFrames = QSettingsObj->value("Misc/DEFAULT_MAX_WAIT_FRAMES", DEFAULT_MAX_WAIT_FRAMES).toUInt();

	loadColours(); 
	loadPaths();
	loadTextSettings();

	initialised = true;
}

void clientConfig::savePreview()
{
	QSettingsObj->setValue("Preview/EDGES_PER_FRAME", preview.edgesPerRender);
	QSettingsObj->setValue("Preview/MS_BETWEEN_UPDATES", preview.processDelay);
	QSettingsObj->setValue("Preview/MS_BETWEEN_GRAPHS", preview.threadDelay);
	QSettingsObj->setValue("Preview/SPIN_PER_FRAME", preview.spinPerFrame);
	QSettingsObj->setValue("Preview/FPS", preview.FPS);
	QSettingsObj->setValue("Preview/HIGHLIGHT_ACTIVE_RGBA", preview.activeHighlight);
	QSettingsObj->setValue("Preview/HIGHLIGHT_INACTIVE_RGBA", preview.inactiveHighlight);
	QSettingsObj->setValue("Preview/BACKGROUND_RGBA", preview.background);
}


void clientConfig::saveConditionals()
{
	QSettingsObj->setValue("Conditionals/MS_BETWEEN_UPDATES", conditional.delay);
	QSettingsObj->setValue("Conditionals/EDGE_COLOUR_RGBA", conditional.edgeColor);
	QSettingsObj->setValue("Conditionals/BG_COLOUR_RGBA", conditional.background);
	QSettingsObj->setValue("Conditionals/NODE_FALLTHROUGH_RGBA", conditional.cond_fail);
	QSettingsObj->setValue("Conditionals/NODE_TAKEN_RGBA", conditional.cond_succeed);
	QSettingsObj->setValue("Conditionals/NODE_BOTH_RGBA", conditional.cond_both);
}

void clientConfig::saveHeatmap()
{
	QSettingsObj->setValue("Heatmap/MS_BETWEEN_UPDATES", heatmap.delay);
	QSettingsObj->setValue("Heatmap/EDGE_TEXT_RGBA", heatmap.lineTextCol);
	QSettingsObj->setValue("Heatmap/BG_COLOUR_RGBA", heatmap.background);

	for (int i = 0; i < 10; i++)
	{
		string key = "Heatmap/EDGE_FREQ" + to_string(i) + "_COL";
		QSettingsObj->setValue(QString::fromStdString(key), heatmap.edgeFrequencyCol.at(i));
	}
}

void clientConfig::setHeatmapDefaults()
{
	heatmap.edgeFrequencyCol.resize(10);
	heatmap.edgeFrequencyCol.at(0) = HEAT_EDGE_COL_FREQ0;
	heatmap.edgeFrequencyCol.at(1) = HEAT_EDGE_COL_FREQ1;
	heatmap.edgeFrequencyCol.at(2) = HEAT_EDGE_COL_FREQ2;
	heatmap.edgeFrequencyCol.at(3) = HEAT_EDGE_COL_FREQ3;
	heatmap.edgeFrequencyCol.at(4) = HEAT_EDGE_COL_FREQ4;
	heatmap.edgeFrequencyCol.at(5) = HEAT_EDGE_COL_FREQ5;
	heatmap.edgeFrequencyCol.at(6) = HEAT_EDGE_COL_FREQ6;
	heatmap.edgeFrequencyCol.at(7) = HEAT_EDGE_COL_FREQ7;
	heatmap.edgeFrequencyCol.at(8) = HEAT_EDGE_COL_FREQ8;
	heatmap.edgeFrequencyCol.at(9) = HEAT_EDGE_COL_FREQ9;
}

void clientConfig::saveColours()
{

	QSettingsObj->setValue("MainGraph/EDGE_CALL_RGBA", graphColours.at(eEdgeCall));
	QSettingsObj->setValue("MainGraph/EDGE_OLD_RGBA", graphColours.at(eEdgeOld));
	QSettingsObj->setValue("MainGraph/EDGE_RET_RGBA", graphColours.at(eEdgeReturn));
	QSettingsObj->setValue("MainGraph/EDGE_LIB_RGBA", graphColours.at(eEdgeLib));
	QSettingsObj->setValue("MainGraph/EDGE_NEW_RGBA", graphColours.at(eEdgeNew));
	QSettingsObj->setValue("MainGraph/EDGE_EXCEPT_RGBA", graphColours.at(eEdgeException));

	QSettingsObj->setValue("MainGraph/NODE_NONFLOW_RGBA", graphColours.at(eNodeNonFlow));
	QSettingsObj->setValue("MainGraph/NODE_JUMP_RGBA", graphColours.at(eNodeJump));
	QSettingsObj->setValue("MainGraph/NODE_CALL_RGBA", graphColours.at(eNodeCall));
	QSettingsObj->setValue("MainGraph/NODE_RET_RGBA", graphColours.at(eNodeReturn));
	QSettingsObj->setValue("MainGraph/NODE_EXTERNAL_RGBA", graphColours.at(eNodeExternal));

	QSettingsObj->setValue("MainGraph/INSTRUCTION_TEXT_RGBA", mainColours.instructionText);
	QSettingsObj->setValue("MainGraph/SYMBOL_TEXT_RGBA", mainColours.symbolTextExternal);
	QSettingsObj->setValue("MainGraph/INTERNAL_SYM_TEXT_RGBA", mainColours.symbolTextInternal);
	QSettingsObj->setValue("MainGraph/MAIN_BACKGROUND_RGBA", mainColours.background);
	QSettingsObj->setValue("MainGraph/HIGHLIGHT_RGBA", mainColours.highlightLine);
	QSettingsObj->setValue("MainGraph/ACTIVITY_MARKER_RGBA", mainColours.activityLine);
}

void clientConfig::saveTextSettings()
{
	vector<pair<SYMS_VISIBILITY *, QString>> displayAreas;
	displayAreas.push_back(make_pair(&externalSymbolVisibility, "LabelDisplay/ExternalSymbol/"));
	displayAreas.push_back(make_pair(&internalSymbolVisibility, "LabelDisplay/InternalSymbol/"));
	displayAreas.push_back(make_pair(&instructionTextVisibility, "LabelDisplay/Instructions/"));

	pair<SYMS_VISIBILITY *, QString> area;
	foreach(area, displayAreas)
	{
		QSettingsObj->setValue(area.second + "Addresses", area.first->addresses);
		QSettingsObj->setValue(area.second + "Arguments", area.first->extraDetail);
		QSettingsObj->setValue(area.second + "AutoVisibleZoom", area.first->autoVisibleZoom);
		QSettingsObj->setValue(area.second + "AnimationFaded", area.first->duringAnimationFaded);
		QSettingsObj->setValue(area.second + "AnimationActive", area.first->duringAnimationHighlighted);
		QSettingsObj->setValue(area.second + "Enabled", area.first->enabled);
		QSettingsObj->setValue(area.second + "FullPaths", area.first->fullPaths);
		QSettingsObj->setValue(area.second + "NotAnimated", area.first->notAnimated);
		QSettingsObj->setValue(area.second + "Offsets", area.first->offsets);
	}

	QSettingsObj->setValue("LabelDisplay/ShowRisingAnimated", showRisingAnimated);
	QSettingsObj->setValue("LabelDisplay/ShowNodeIndex", showNodeIndex);
	QSettingsObj->setValue("LabelDisplay/InstextCompactThreshold", insTextCompactThreshold);
}


void clientConfig::setDefaultColours()
{
	graphColours.resize(eENLAST);
	graphColours.at(eEdgeCall) = DEFAULT_EDGE_CALL;
	graphColours.at(eEdgeOld) = DEFAULT_EDGE_OLD;
	graphColours.at(eEdgeReturn) = DEFAULT_EDGE_RET;
	graphColours.at(eEdgeLib) = DEFAULT_EDGE_LIB;
	graphColours.at(eEdgeNew) = DEFAULT_EDGE_NEW;
	graphColours.at(eEdgeException) = DEFAULT_EDGE_EXCEPT;

	graphColours.at(eNodeNonFlow) = DEFAULT_NODE_STD;
	graphColours.at(eNodeJump) = DEFAULT_NODE_JUMP;
	graphColours.at(eNodeCall) = DEFAULT_NODE_CALL;
	graphColours.at(eNodeReturn) = DEFAULT_NODE_RET;
	graphColours.at(eNodeExternal) = DEFAULT_NODE_EXT;
}

void clientConfig::saveConfig()
{
	assert(QSettingsObj != NULL);

	QSettingsObj->setValue("wireframe/COL_RGBA", wireframe.edgeColor);

	savePreview();
	saveConditionals();
	saveHeatmap();

	//al_set_config_value(alConfig, "Dimensions", "FAR_A_LIMIT", to_string(farA).c_str());
	//al_set_config_value(alConfig, "Dimensions", "LOW_B_LIMIT", to_string(lowB).c_str());

	QSettingsObj->setValue("MainGraph/HIGHLIGHT_PROTRUSION", highlightProtrusion);


	QSettingsObj->setValue("Misc/ANIMATION_FADE_RATE", animationFadeRate);
	QSettingsObj->setValue("Misc/ANIMATION_UPDATES_PER_FRAME", animationUpdateRate);
	QSettingsObj->setValue("Misc/MAINGRAPH_UPDATE_FREQUENCY_MS", renderFrequency);
	QSettingsObj->setValue("Misc/TRACE_BUFFER_MAX", traceBufMax);
	QSettingsObj->setValue("Misc/DEFAULT_MAX_ARG_STORAGE", maxArgStorage);
	QSettingsObj->setValue("Misc/DEFAULT_MAX_WAIT_FRAMES", maxWaitFrames);


	QSettingsObj->setValue("Paths/SAVE_PATH", QString::fromStdString(saveDir.string()));
	QSettingsObj->setValue("Paths/DYNAMORIO_PATH", QString::fromStdString(DRDir.string()));
	QSettingsObj->setValue("Paths/CLIENT_PATH", QString::fromStdString(clientPath.string()));
	QSettingsObj->setValue("Paths/LAST_PATH", QString::fromStdString(lastPath.string()));
	QSettingsObj->setValue("Paths/PIN_PATH", QString::fromStdString(PinDir.string()));


	saveColours();
	saveTextSettings();

	QSettingsObj->sync();
}

void clientConfig::updateSavePath(boost::filesystem::path savePath)
{
	saveDir = savePath.parent_path();
	QSettingsObj->setValue("Paths/SAVE_PATH", QString::fromStdString(saveDir.string()));
	QSettingsObj->sync();
}

void clientConfig::updateLastPath(boost::filesystem::path binarypath)
{
	lastPath = binarypath.parent_path();
	QSettingsObj->setValue("Paths/LAST_PATH", QString::fromStdString(lastPath.string()));
	QSettingsObj->sync();
}

//returns path string if exists on disk, empty string if not
QString clientConfig::getLastPathString()
{
	if (boost::filesystem::is_directory(lastPath))
		return QString::fromStdString(lastPath.string());

	return "";
}

QString clientConfig::getSaveDirString()
{
	if (boost::filesystem::is_directory(saveDir))
		return QString::fromStdString(saveDir.string());

	return "";
}

void clientConfig::setDefaultSavePath()
{
	saveDir = getModulePath();
	saveDir.append("\\saves\\");
}

void clientConfig::setDefaultDRPath()
{
	DRDir = getModulePath();
	DRDir.append("\\DynamoRIO\\");
}

void clientConfig::setDefaultPinPath()
{
	PinDir = getModulePath();
	PinDir.append("\\Pin\\");
}

void clientConfig::setDefaultClientPath()
{
	clientPath = getModulePath();
	clientPath.append("\\");
}

void clientConfig::setDefaultPaths()
{
	setDefaultDRPath();
	setDefaultSavePath();
	setDefaultClientPath();
}


void clientConfig::setDefaultTextSettings()
{
	//auto display of symbols from a far distance
	//show symbol and arguments, but not address or path
	//hide during animation unless highlighted active areas
	externalSymbolVisibility.enabled = true;
	externalSymbolVisibility.autoVisibleZoom = EXTERN_VISIBLE_ZOOM_FACTOR;
	externalSymbolVisibility.offsets = true;
	externalSymbolVisibility.addresses = false;
	externalSymbolVisibility.fullPaths = false;
	externalSymbolVisibility.extraDetail = true;
	externalSymbolVisibility.duringAnimationFaded = false;
	externalSymbolVisibility.duringAnimationHighlighted = true;
	externalSymbolVisibility.notAnimated = true;

	//auto display of internal symbols is similar
	internalSymbolVisibility.enabled = true;
	internalSymbolVisibility.autoVisibleZoom = EXTERN_VISIBLE_ZOOM_FACTOR;
	internalSymbolVisibility.addresses = false;
	internalSymbolVisibility.fullPaths = false;
	internalSymbolVisibility.extraDetail = true;
	internalSymbolVisibility.duringAnimationFaded = false;
	internalSymbolVisibility.duringAnimationHighlighted = true;
	internalSymbolVisibility.notAnimated = true;

	instructionTextVisibility.enabled = true;
	instructionTextVisibility.autoVisibleZoom = INSTEXT_VISIBLE_ZOOMFACTOR;
	instructionTextVisibility.addresses = true;
	instructionTextVisibility.offsets = true;
	instructionTextVisibility.fullPaths = true; //label for targets of calls/jmps
	instructionTextVisibility.extraDetail = true; //only show control flow

	//if we are zoomed in this far we will probably always want to see the text
	instructionTextVisibility.duringAnimationFaded = true;
	instructionTextVisibility.duringAnimationHighlighted = true;
	instructionTextVisibility.notAnimated = true;

	showRisingAnimated = true;
	showNodeIndex = false;
	insTextCompactThreshold = INSTEXT_COMPACT_THRESHOLD;
}
