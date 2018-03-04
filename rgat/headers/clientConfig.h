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
#pragma once
#include "stdafx.h"

#include <boost/filesystem.hpp>

enum PreviewScrollDir { ePrevscrollDown, ePrevscrollUp, ePrevscrollLeft, ePrevscrollRight, ePrevscrollDisabled };
enum heatTextDisplayState { eHeatNodes, eHeatEdges, eHeatNone };

struct SYMS_VISIBILITY
{
	bool enabled = true;
	bool showWhenZoomed = true;
	float autoVisibleZoom;

	bool duringAnimationFaded;
	bool duringAnimationHighlighted;
	bool notAnimated;
	bool fullPaths;
	bool addresses;
	bool offsets;
	bool extraDetail;
};

struct LAUNCHOPTIONS {
	bool removeSleeps = false;
	bool pause = false;
	bool debugLogging = false;
	string args;

	//not implemented
	bool basic = false;
	//bool debugMode = false;
};

class clientConfig
{

public:
	clientConfig();
	//save config from memory into file
	void saveConfig();

	~clientConfig();

	struct {
		QColor edgeColor;
	} wireframe;

	struct {
		int delay;
		QColor edgeColor;
		QColor background;
		QColor cond_fail;
		QColor cond_succeed;
		QColor cond_both;
		QColor highlight;
	} conditional;

	struct {
		int delay;
		QColor background;
		QColor lineTextCol;
		vector<QColor> edgeFrequencyCol;
		QColor highlight;
	} heatmap;

	struct {
		int FPS;
		int processDelay;
		int threadDelay;
		float spinPerFrame;
		int edgesPerRender;
		QColor background;
		QColor inactiveHighlight;
		QColor activeHighlight;
		bool rotationEnabled;
	} preview;

	vector <QColor> graphColours;

	struct {
		QColor background;
		QColor highlightLine;
		QColor instructionText;
		QColor symbolTextExternal;
		QColor symbolTextExternalRising;
		QColor symbolTextInternal;
		QColor symbolTextInternalRising;
		QColor symbolTextPlaceholder;
		QColor conditionalInstructionText;
		QColor activityLine;
	} mainColours;

	SYMS_VISIBILITY externalSymbolVisibility;
	SYMS_VISIBILITY internalSymbolVisibility;
	SYMS_VISIBILITY placeholderLabelVisibility;
	SYMS_VISIBILITY instructionTextVisibility;

	bool showRisingAnimated;

	bool show_ins_text = true;
	heatTextDisplayState show_heat_location = eHeatNodes;
	bool showNodeIndex = false;
	float insTextCompactThreshold;

	int highlightProtrusion;
	bool showActiveMarker = true; 

	//int lowB;
	//int farA;
	unsigned int renderFrequency; //ms between render thread frames
	unsigned long long traceBufMax;
	unsigned int maxWaitFrames;

	boost::filesystem::path saveDir;	//where traces get saved
	boost::filesystem::path DRDir, PinDir; //instrumentation tools
	boost::filesystem::path clientPath; //the drgat client
	boost::filesystem::path lastPath; //last folder navigated to

	float animationFadeRate;
	int animationUpdateRate;
	unsigned int maxArgStorage;

	//these are not saved in the config file but toggled at runtime
	void updateSavePath(boost::filesystem::path savePath);
	void updateLastPath(boost::filesystem::path binarypath);
	QString getLastPathString();
	QString getSaveDirString();

private:
	QSettings *QSettingsObj;

	bool initialised = false;
	vector<string *> cleanupList;

	boost::filesystem::path configFilePath;

	//read config file at configFilePath into memory
	void loadSettings();

	//save individual sections of memory config to file
	void savePreview();
	void saveConditionals();
	void saveHeatmap();
	void saveColours();
	void saveTextSettings();

	//retrieve from stored config
	void loadPreview();
	void loadConditionals();
	void loadHeatmap();
	void loadMaingraphColours();
	void loadPaths();
	void loadColours();
	void loadTextSettings();

	//initialise with default settings if not in stored config
	void setHeatmapDefaults();
	void setDefaultColours();
	void setDefaultPaths();
	void setDefaultSavePath();
	void setDefaultDRPath();
	void setDefaultPinPath();
	void setDefaultClientPath();
	void setDefaultTextSettings();
};

