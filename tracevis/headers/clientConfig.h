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
#pragma once

class clientConfig
{

public:
	clientConfig(string filepath);
	//save config from memory into file
	void saveToFile();

	~clientConfig();

	struct {
		ALLEGRO_COLOR edgeColor;
	} wireframe;

	struct {
		int delay;
		ALLEGRO_COLOR edgeColor;
		ALLEGRO_COLOR background;
		ALLEGRO_COLOR cond_fail;
		ALLEGRO_COLOR cond_succeed;
		ALLEGRO_COLOR cond_both;
	} conditional;

	struct {
		int delay;
		ALLEGRO_COLOR lineTextCol;
		ALLEGRO_COLOR edgeFrequencyCol[10];
	} heatmap;

	struct {
		int FPS;
		int processDelay;
		int threadDelay;
		float spinPerFrame;
		int edgesPerRender;
		ALLEGRO_COLOR background;
		ALLEGRO_COLOR inactiveHighlight;
		ALLEGRO_COLOR activeHighlight;
	} preview;

	struct {
		map<int, ALLEGRO_COLOR> lineColours;
		map<int, ALLEGRO_COLOR> nodeColours;
	} graphColours;

	ALLEGRO_CONFIG *alConfig;
	ALLEGRO_COLOR mainBackground;
	ALLEGRO_COLOR highlightColour;
	int highlightProtrusion;
	ALLEGRO_COLOR activityLineColour;
	int lowB;
	int farA;
	unsigned int renderFrequency;
	unsigned long traceBufMax;

	string saveDir;
	string DRDir;
	string clientPath;
	string lastPath;

	float animationFadeRate;
	unsigned int maxArgStorage;

	//these are not saved in the config file but toggled at runtime
	void updateSavePath(string path);
	void updateLastPath(string path);

private:
	bool initialised = false;
	vector<string *> cleanupList;

	//when we save the file we create a bunch of colours on the heap
	//this deletes them
	void cleanup();

	//convert col to a user friendly comma seperated list for saving
	const char* col_to_charstr(ALLEGRO_COLOR col);
	void charstr_to_col(const char *charstring, ALLEGRO_COLOR *destination, int *errorCount);

	string configFilePath;

	//read config file at configFilePath into memory
	bool loadFromFile();
	void reSaveToFile();

	//save individual sections of memory config to file
	void savePreview();
	void saveConditionals();
	void saveHeatmap();
	void saveColours();

	//retrieve from config file
	bool loadPreview();
	bool loadConditionals();
	bool loadHeatmap();
	bool loadColours();
	bool loadPaths();

	//place default settings in memory
	void loadDefaults();
	void loadPreviewDefaults();
	void loadConditionalDefaults();
	void loadHeatmapDefaults();
	void loadDefaultColours();
	void loadDefaultPaths();
};

