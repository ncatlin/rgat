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
	} heatmap;

	struct {
		int FPS;
		int processDelay;
		int threadDelay;
		int spinPerFrame;
		int edgesPerRender;
	} preview;

	struct {
		map<int, ALLEGRO_COLOR> lineColours;
		map<int, ALLEGRO_COLOR> nodeColours;
	} graphColours;

	ALLEGRO_COLOR mainBackground;
	ALLEGRO_COLOR highlightColour;
	int highlightProtrusion;
	ALLEGRO_COLOR activityLineColour;
	int lowB;
	int farA;

private:
	string configFilePath;
	void loadFromFile();
	void loadDefaults();
	void saveToFile();

};

