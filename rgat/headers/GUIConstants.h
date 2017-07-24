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
Lots of GUI related constants
*/

#pragma once

//more divisions = smoother curves
#define ADIVISIONS 32
#define BDIVISIONS 16

#define al_col_red QColor(255, 0, 0, 255)
#define al_col_dull_red QColor(136, 0, 0, 255)
#define al_col_dull_green QColor(79, 100, 12, 255)
#define al_col_light_green QColor(180, 255, 190, 255)
#define al_col_green QColor(0, 255, 0, 255)
#define al_col_white QColor(255, 255, 255, 255)
#define al_col_purple QColor(139, 0, 139, 255)
#define al_col_orange QColor(255, 126, 0, 255)
#define al_col_yellow QColor(255, 255, 0, 255)
#define al_col_grey QColor(77, 77, 77, 255)
#define al_col_black QColor(0, 0, 0, 255)
#define al_col_cyan QColor(0, 255, 255, 255)

#define PREVIEW_GRAPH_PADDING_X 6
#define PREVIEW_GRAPH_PADDING_Y 6
#define PREVIEW_GRAPH_HEIGHT 200
#define PREVIEW_GRAPH_WIDTH 280
#define PREVIEW_PANE_WIDTH (PREVIEW_GRAPH_WIDTH + PREVIEW_GRAPH_PADDING_X*2)


#define WF_POINTSPERLINE 64


#define VERTSPERQUAD 4

//#define M_PI acos(-1.0)
#define DEGREESMUL float(180 / M_PI)

/*
enum eUIEventCode { EV_NONE = 0, EV_MOUSE, EV_KEYBOARD, EV_EXIT, EV_BTN_STEPPING,	EV_BTN_RUN, EV_BTN_QUIT,
	EV_BTN_WIREFRAME, EV_BTN_HEATMAP, EV_BTN_CONDITION, EV_BTN_PREVIEW, EV_BTN_LOAD, EV_BTN_SAVE, EV_BTN_EXTERNLOG,
	EV_RESIZE, EV_BTN_DIFF, EV_BTN_NODES, EV_BTN_EDGES, EV_BTN_HIGHLIGHT,	EV_BTN_AUTOSCALE, 
	EV_BTN_RESETSCALE,	EV_BTN_ABOUT, EV_BTN_DBGSYM, EV_BTN_NEARSIDE, EV_BTN_EXT_TEXT_MENU
}; 
&*/

#define STARTWWIDTH 1600
#define STARTWHEIGHT 800

//number of divisions of long curve. More = smoother, worse(?) performance
#define LONGCURVEPTS 32

#define DEFAULTPOINTSIZE 5
#define PREVIEW_POINT_SIZE 5



#define FORCE_NEARSIDE_ZOOMFACTOR 15

//how far floating text rises per frame. can be negative. todo: add to config
#define EXTERN_FLOAT_RATE 0.3
//how many frames to display it
#define EXTERN_LIFETIME_FRAMES 40

//initial
#define VERTBUFFERSIZE 1100

#define VBO_CYLINDER_POS 0
#define VBO_CYLINDER_COL 1

#define VBO_NODE_POS 0
#define VBO_NODE_COL 1
#define VBO_LINE_POS 2
#define VBO_LINE_COL 3

//beyond this add a '+[NUMEXTERNS-MAXEXTERNS]box'
#define MAXEXTERNS 5

//offset the instruction text on the drawn node
#define INS_X_OFF 5
#define INS_Y_OFF 1

#define COND_INSTEXT_Y_OFF 6

#define MAX_LIVE_ANIMATION_NODES_PER_FRAME 100

#define HEATMAP_KEY_SQUARESIZE 25

#define MAIN_FRAME_Y 50

#define BACKLOG_TEXT_COLOUR_LOW agui::Color(255, 255, 255)
#define BACKLOG_TEXT_COLOUR_HIGH agui::Color(255, 255, 0)
#define BACKLOG_TEXT_COLOUR_FULL agui::Color(255, 0, 0)

#define ANIM_INACTIVE_NODE_ALPHA 0.00
#define ANIM_INACTIVE_EDGE_ALPHA 0.00

#define HIGHLIGHT_REFRESH_DELAY_MS 700

#define TARGET_FPS 20 //todo: increase in release

//max length to display in diff summary
#define MAX_DIFF_PATH_LENGTH 50

#define NODES_PER_RESCALE_ITERATION 250

#define LAYOUT_ICONS_W 48
#define LAYOUT_ICONS_H 48
#define LAYOUT_ICONS_X1 15
#define LAYOUT_ICONS_X_SEP (LAYOUT_ICONS_W + 8)
#define LAYOUT_ICONS_X2 (LAYOUT_ICONS_X1 + LAYOUT_ICONS_X_SEP)
#define LAYOUT_ICONS_X3 (LAYOUT_ICONS_X1 + (LAYOUT_ICONS_X_SEP*2))
#define LAYOUT_ICONS_Y 32

#define XOFF 0
#define YOFF 1
#define ZOFF 2
#define ROFF 0
#define GOFF 1
#define BOFF 2
#define AOFF 3