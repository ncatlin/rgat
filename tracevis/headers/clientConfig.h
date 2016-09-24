#pragma once

class clientConfig
{

public:
	clientConfig(string filepath);
	
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

	//these are not saved in the config file but toggled at runtime
	bool showExternText = false;
	void updateLastPath(string path);

private:
	bool initialised = false;
	vector<string *> cleanupList;

	//when we save the file we create a bunch of colours on the heap
	//this deletes them
	void cleanup();

	//convert col to a user friendly comma seperated list for saving
	const char* col_to_charstr(ALLEGRO_COLOR col);
	void charstr_to_col(const char *charstring, ALLEGRO_COLOR *destination);

	string configFilePath;

	//read config file at configFilePath into memory
	bool loadFromFile();

	//save config from memory into file
	void saveToFile();

	//save individual sections of memory config to file
	void savePreview();
	void saveConditionals();
	void saveHeatmap();
	void saveColours();

	//place default settings in memory
	void loadDefaults();
	void loadPreview();
	void loadConditionals();
	void loadHeatmap();
	void loadColours();
	void loadPaths();

	//load individual default config sections into memory
	void loadPreviewDefaults();
	void loadConditionalDefaults();
	void loadHeatmapDefaults();
	void loadDefaultColours();
	void loadDefaultPaths();
};

