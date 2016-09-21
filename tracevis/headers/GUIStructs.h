#pragma once
#include "stdafx.h"
#include "graph_display_data.h"
#include "GUIConstants.h"
#include "traceStructs.h"
#include "thread_graph_data.h"
#include "timeline.h"
#include "clientConfig.h"
#define XOFF 0
#define YOFF 1
#define ZOFF 2
#define ROFF 0
#define GOFF 1
#define BOFF 2
#define AOFF 3

struct DIFFIDS {
	int pid1 = -1;
	int pid2 = -1;
	int tid1 = -1;
	int tid2 = -1;
};

struct TITLE {
	char zoom[25] = { 0 };
	char MPos[25] = { 0 };
	char title[255] = { 0 };
	char FPS[25] = { 0 };
	char Primitives[55] = { 0 };
	char dbg[200] = { 0 };
};

struct DISPLAYMODES {
	bool wireframe = true;
	bool nodes = true;
	bool edges = true;
	bool preview = true;
	bool animation = false;
	bool heatmap = false;
	bool conditional = false;
	int diff = 0;
};

struct HEIGHTWIDTH {
	int height;
	int width;
};

struct HIGHLIGHT_DATA {
	int highlightState = 0;
	string highlight_s;
	unsigned long highlightAddr;
	int highlightModule = 0;
	vector<node_data *> highlightNodes;
};

struct LAUNCHOPTIONS {
	bool caffine = false;
	bool antidote = false;
	bool pause = false;
	bool basic = false;
};

class VISSTATE {
public:
	VISSTATE() {
		glGenBuffers(2, colSphereVBOs);
		glGenBuffers(2, wireframeVBOs);
	};
	~VISSTATE() {};
	ALLEGRO_DISPLAY *maindisplay = 0;
	ALLEGRO_BITMAP *mainGraphBMP = 0;
	ALLEGRO_BITMAP *previewPaneBMP = 0;
	ALLEGRO_BITMAP *GUIBMP = 0;
	ALLEGRO_FONT *standardFont;
	ALLEGRO_EVENT_QUEUE *event_queue = 0;

	LAUNCHOPTIONS launchopts;

	TITLE *title;
	long zoomlevel = 0; //INITIALZOOM;
	float xturn = 135;
	float yturn = -25;
	HEIGHTWIDTH displaySize;
	HEIGHTWIDTH mainFrameSize;
	bool rescale = false;
	int show_ins_text = INSTEXT_AUTO;
	int leftcolumn = 0;
	int rightcolumn = 0;

	void *widgets;
	int animationUpdate = 0;
	bool animFinished = false;
	bool skipLoop = false;

	bool saveInProgress = false;
	bool mouse_dragging = false;
	thread_graph_data *mouse_drag_graph = NULL;
	map <int, NODEPAIR> graphPositions;

	//for future random pipe names
	//char pipeprefix[20];

	float previewYAngle = -30;
	bool previewSpin = true;

	DISPLAYMODES modes;
	thread_graph_data *activeGraph = NULL;
	void *newActiveGraph = NULL;
	int newPID = -1;
	PROCESS_DATA *activePid = NULL;

	GRAPH_DISPLAY_DATA *col_pick_sphere = NULL;
	GLuint colSphereVBOs[2];
	
	GRAPH_DISPLAY_DATA *wireframe_sphere = NULL;
	GLuint wireframeVBOs[2];
	bool remakeWireframe = false;
	
	std::map<int, PROCESS_DATA *> glob_piddata_map;
	HANDLE pidMapMutex = CreateMutex(NULL, false, NULL);

	timeline *timelineBuilder;
	ALLEGRO_TEXTLOG *textlog = 0;
	unsigned int logSize = 0;

	HIGHLIGHT_DATA highlightData;
	clientConfig *config;
};

//screen top bottom red green
//for edge picking
struct SCREEN_EDGE_PIX {
	double leftgreen = 0;
	double rightgreen = 0;
	double topred = 0;
	double bottomred = 0;
};

