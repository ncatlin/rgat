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
Lots of GUI related constants
*/

#pragma once

//more divisions = smoother curves
#define ADIVISIONS 32
#define BDIVISIONS 16

/*
don't know, please figure out how to derive properly.
I derived this by making the colpick sphere permenant and 
looking at the column of example verts at given h_edge_seps
eg: 
coord -8a is between col 0 and 1 at h_edge_sep ~1.39. 1.39*8 = 11.12
coord -14a is between col 0 and 1 at h_edge_sep ~0.8. 0.8*14 = 11.2
*/
#define COLOUR_PICKING_MYSTERY_CONSTANTA 11.16

#define al_col_red al_map_rgba(255, 0, 0, 255)
#define al_col_light_green al_map_rgba(180, 255, 190, 255)
#define al_col_green al_map_rgba(0, 255, 0, 255)
#define al_col_white al_map_rgba(255, 255, 255, 255)
#define al_col_purple al_map_rgba(139, 0, 139, 255)
#define al_col_orange al_map_rgba(255, 126, 0, 255)
#define al_col_yellow al_map_rgba(255, 255, 0, 255)
#define al_col_grey al_map_rgba(77, 77, 77, 255)
#define al_col_black al_map_rgba(0, 0, 0, 255)
#define al_col_cyan al_map_rgba(0, 255, 255, 255)


//#define ISYS 6


#define PREV_SCROLLBAR_WIDTH 15
#define PREV_GRAPH_PADDING 10
#define PREVIEW_GRAPH_HEIGHT 200
#define PREVIEW_PANE_WIDTH 300
#define PREVIEW_GRAPH_WIDTH (PREVIEW_PANE_WIDTH - PREV_GRAPH_PADDING*2)

#define BASE_CONTROLS_HEIGHT 80
#define TOP_SUMMARY_HEIGHT 40

#define INSTEXT_FIRST 0
//show no instruction text
#define INSTEXT_NONE INSTEXT_FIRST
//show instruction text selected by distance
#define INSTEXT_AUTO 1
//show all instruction text
#define INSTEXT_ALL_ALWAYS 2
#define INSTEXT_LAST INSTEXT_ALL_ALWAYS

#define EXTERNTEXT_FIRST 0
//show no external labels
#define EXTERNTEXT_NONE EXTERNTEXT_FIRST
//show symbols
#define EXTERNTEXT_SYMS 1
//show path and symbols
#define EXTERNTEXT_ALL 2
#define EXTERNTEXT_LAST EXTERNTEXT_ALL



#define WF_POINTSPERLINE 64
#define WIREFRAMELOOPS 18 //meant to be alterable but stuff breaks if you change this. don't.
#define WFPOSBUFSIZE WIREFRAMELOOPS * WF_POINTSPERLINE * POSELEMS * sizeof(GLfloat)
#define WFCOLBUFSIZE WIREFRAMELOOPS * WF_POINTSPERLINE * COLELEMS * sizeof(GLfloat)

#define VERTSPERQUAD 4
#define COL_SPHERE_VERTS ((180 / BDIVISIONS)-2)*(WF_POINTSPERLINE/2)*VERTSPERQUAD
#define COL_SPHERE_BUFSIZE COL_SPHERE_VERTS*POSELEMS*sizeof(float)

#define M_PI acos(-1.0)
#define DEGREESMUL float(180 / M_PI)

enum eUIEventCode { EV_NONE = 0, EV_MOUSE, EV_KEYBOARD, EV_EXIT, EV_BTN_STEPPING,	EV_BTN_RUN, EV_BTN_QUIT,
	EV_BTN_WIREFRAME, EV_BTN_HEATMAP, EV_BTN_CONDITION, EV_BTN_PREVIEW, EV_BTN_LOAD, EV_BTN_SAVE, EV_BTN_EXTERNLOG,
	EV_RESIZE, EV_BTN_DIFF, EV_BTN_NODES, EV_BTN_EDGES, EV_BTN_HIGHLIGHT, EV_BTN_EXT_TEXT_NONE, EV_BTN_EXT_TEXT_SYMS,
	EV_BTN_EXT_TEXT_PATH, EV_BTN_INS_TEXT_NONE, EV_BTN_INS_TEXT_AUTO, EV_BTN_INS_TEXT_ALWA, EV_BTN_AUTOSCALE,
	EV_BTN_ABOUT, EV_BTN_DBGSYM, EV_BTN_NEARSIDE
}; 

#define DIFF_SELECTED 1
#define DIFF_STARTED 2

#define STARTWWIDTH 1600
#define STARTWHEIGHT 800

//number of divisions of long curve. More = smoother, worse(?) performance
#define LONGCURVEPTS 32

#define DEFAULTPOINTSIZE 5
#define PREVIEW_POINT_SIZE 5

#define BMODMAG  0.55
#define BAdj 35

#define EXTERN_VISIBLE_ZOOM_FACTOR 25
#define INSTEXT_VISIBLE_ZOOMFACTOR 7

//how far floating text rises per frame. can be negative. todo: add to config
#define EXTERN_FLOAT_RATE 0.3
//how many frames to display it
#define EXTERN_LIFETIME_FRAMES 40

//initial
#define VERTBUFFERSIZE 1100

#define VBO_SPHERE_POS 0
#define VBO_SPHERE_COL 1

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

#define TARGET_FPS 60

//max length to display in diff summary
#define MAX_DIFF_PATH_LENGTH 50

#define NODES_PER_RESCALE_ITERATION 250

#define LAYOUT_ICONS_W 48
#define LAYOUT_ICONS_H 48
#define LAYOUT_ICONS_X_SEP 8
#define LAYOUT_ICONS_X1 15
#define LAYOUT_ICONS_X2 LAYOUT_ICONS_X1 + LAYOUT_ICONS_W + LAYOUT_ICONS_X_SEP
#define LAYOUT_ICONS_Y 32
