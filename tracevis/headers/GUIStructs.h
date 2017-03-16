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
A messy collection of state structures, generally targeted to the visualiser state
*/

#pragma once
#include "stdafx.h"
#include "GUIConstants.h"
#include "timeline.h"
#include "clientConfig.h"
#include "traceStructs.h"
#include "graph_display_data.h"

enum graphLayouts { eSphereLayout, eTreeLayout, eLayoutInvalid};
enum instructionTextDisplayState { eInsTextOff, eInsTextAuto, eInsTextForced };
enum symbolTextDisplayState { eSymboltextOff, eSymboltextSymbols, eSymboltextPaths, eSymboltextInternal, eSymboltextExternal, eSymboltextAll };
enum heatTextDisplayState { eHeatNodes, eHeatEdges, eHeatNone };

#define XOFF 0
#define YOFF 1
#define ZOFF 2
#define ROFF 0
#define GOFF 1
#define BOFF 2
#define AOFF 3

#define DEFAULT_INSTRUCTION_FONT_SIZE 12

struct DIFFIDS {
	PID_TID pid1 = -1;
	PID_TID pid2 = -1;
	PID_TID tid1 = -1;
	PID_TID tid2 = -1;
};

#define TITLE_STRING_MAX 300
#define PRIMITIVES_STRING_MAX 200
#define FPS_STRING_MAX 200

struct TITLE {
	char zoom[25] = { 0 };
	char MPos[25] = { 0 };
	char title[TITLE_STRING_MAX] = { 0 };
	char FPS[25] = { 0 };
	char Primitives[PRIMITIVES_STRING_MAX] = { 0 };
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
	bool nearSide = false;
	
	instructionTextDisplayState show_ins_text = eInsTextAuto;
	symbolTextDisplayState show_symbol_verbosity = eSymboltextSymbols;
	symbolTextDisplayState show_symbol_location = eSymboltextAll;
	heatTextDisplayState show_heat_location = eHeatNodes;
	int diff = 0;
};

struct HEIGHTWIDTH {
	int height;
	int width;
};


struct LAUNCHOPTIONS {
	bool caffine = false;
	bool pause = false;
	bool basic = false;
	bool debugMode = false;
	bool debugLogging = false;
};

class VISSTATE {
public:
	VISSTATE() {};
	~VISSTATE() {};

	void gen_wireframe_buffers()
	{
		glGenBuffers(2, colSphereVBOs);
		glGenBuffers(2, wireframeVBOs);
		initWireframeBufs();
	}

#ifdef XP_COMPATIBLE
	HANDLE graphPtrMutex = CreateMutex(NULL, FALSE, NULL);
#else
	SRWLOCK graphPtrLock = SRWLOCK_INIT;
#endif

	void set_activeGraph(void *graph);
	void displayActiveGraph();
	void performIrregularActions();
	void change_mode(eUIEventCode mode);
	void draw_display_diff(ALLEGRO_FONT *font, void **diffRenderer);
	void initWireframeBufs();
	void setFontPath(string path) { instructionFontpath = path; }
	void setInstructionFontSize(int ptSize);
	int getInstructionFontSize() { return instructionFontSize; }
	bool mouseInDialog(int mousex, int mousey);
	void closeFrame(agui::Frame *);
	void openFrame(agui::Frame *);

	//cache to avoid lock every time we move mouse
	long get_activegraph_size() { return activeGraphSize; }
	void set_activegraph_size(long size) {
		activeGraphSize = size;
	}
	long activeGraphSize = 0;

	ALLEGRO_DISPLAY *maindisplay = 0;
	ALLEGRO_BITMAP *mainGraphBMP = 0;
	ALLEGRO_BITMAP *previewPaneBMP = 0;
	ALLEGRO_BITMAP *GUIBMP = 0;

	ALLEGRO_FONT *instructionFont = 0;
	ALLEGRO_FONT *standardFont = 0;
	ALLEGRO_FONT *messageFont = 0;
	ALLEGRO_FONT *PIDFont = 0;

	ALLEGRO_COLOR backgroundColour;

	ALLEGRO_EVENT_QUEUE *event_queue = 0;
	ALLEGRO_EVENT_QUEUE *low_frequency_timer_queue = 0;

	LAUNCHOPTIONS launchopts;


	TITLE *title;
	long cameraZoomlevel = 0;
	float view_shift_x = 0;
	float view_shift_y = 0;
	HEIGHTWIDTH displaySize;
	HEIGHTWIDTH mainFrameSize;
	bool rescale = false;
	bool autoscale = true;

	int leftcolumn = 0;
	int rightcolumn = 0;

	graphLayouts currentLayout = eSphereLayout;

	void *widgets = 0;
	int animationUpdate = 0;

	int userSelectedAnimPos = 0;
	bool animFinished = false;

	bool mouse_dragging = false;

	void *mouse_drag_graph = NULL; 
	void *activeGraph = NULL;
	void *maingraphRenderThreadPtr;

	//for rendering graph diff
	void *diffRenderer;

	map <PID_TID, NODEPAIR> graphPositions;

	string commandlineLaunchPath;
	string commandlineLaunchArgs;
	//for future random pipe names
	//char pipeprefix[20];

	float previewYAngle = -30;
	//bool previewSpin = true;

	DISPLAYMODES modes;
	vector <agui::Frame *> openFrames;
	
	void *newActiveGraph = NULL;
	bool switchProcess = true;
	int selectedPID = -1;

	PROCESS_DATA *activePid = NULL;
	PROCESS_DATA* spawnedProcess = NULL;

	GRAPH_DISPLAY_DATA *col_pick_sphere = NULL;
	GLuint colSphereVBOs[2];
	
	GRAPH_DISPLAY_DATA *wireframe_sphere = NULL;
	GLuint wireframeVBOs[2];
	bool remakeWireframe = false;
	
	map<PID_TID, PROCESS_DATA *> glob_piddata_map;
	HANDLE pidMapMutex = CreateMutex(NULL, false, NULL);

	timeline *timelineBuilder;
	ALLEGRO_TEXTLOG *textlog = 0;
	unsigned int logSize = 0;

	//new sym/arg strings currently being displayed on the graph
	map <PID_TID, vector<EXTTEXT>> externFloatingText;

	clientConfig *config;

	bool die = false;
	bool saving = false;

	int previewRenderFrame = 0;

	GLint *wireframeStarts;
	GLint *wireframeSizes;

private:
	string instructionFontpath;
	int instructionFontSize = DEFAULT_INSTRUCTION_FONT_SIZE;
};

//screen top bottom red green
//for edge picking
struct SCREEN_EDGE_PIX {
	double leftgreen = 0;
	double rightgreen = 0;
	double topred = 0;
	double bottomred = 0;
};

