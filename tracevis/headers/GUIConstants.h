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

#define al_col_red al_map_rgb(255, 0, 0)
#define al_col_green al_map_rgb(0, 255, 0)
#define al_col_white al_map_rgb(255, 255, 255)
#define al_col_purple al_map_rgb(139, 0, 139)
#define al_col_orange al_map_rgb(255, 126, 0)
#define al_col_yellow al_map_rgb(255, 255, 0)
#define al_col_grey al_map_rgb(0.3 * 255, 0.3 * 255, 0.3 * 255)
#define al_col_black al_map_rgb(0, 0, 0)

#define ICALL 0
#define IOLD 1
#define IRET 2
#define ILIB 3
#define INEW 4
#define ISTD 5
#define IFLOW 6
#define ISYS 7

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

#define EV_NONE 0
#define EV_MOUSE 1
#define EV_KEYBOARD 2
#define EV_EXIT EV_KEYBOARD+1

#define EV_BTN_STEPPING EV_EXIT+1

#define EV_BTN_RUN EV_BTN_STEPPING+1
#define EV_BTN_QUIT EV_BTN_RUN+1 
#define EV_BTN_WIREFRAME EV_BTN_QUIT+1 
#define EV_BTN_HEATMAP EV_BTN_WIREFRAME+1 
#define EV_BTN_CONDITION EV_BTN_HEATMAP+1
#define EV_BTN_PREVIEW EV_BTN_CONDITION+1
#define EV_BTN_LOAD EV_BTN_PREVIEW+1
#define EV_BTN_SAVE EV_BTN_LOAD+1
#define EV_BTN_EXTERNLOG EV_BTN_SAVE+1
#define EV_RESIZE EV_BTN_EXTERNLOG+1
#define EV_BTN_DIFF EV_RESIZE+1
#define EV_BTN_NODES EV_BTN_DIFF+1
#define EV_BTN_EDGES EV_BTN_NODES+1
#define EV_BTN_HIGHLIGHT EV_BTN_EDGES+1

#define EV_BTN_EXT_TEXT_NONE EV_BTN_HIGHLIGHT+1
#define EV_BTN_EXT_TEXT_SYMS EV_BTN_EXT_TEXT_NONE+1
#define EV_BTN_EXT_TEXT_PATH EV_BTN_EXT_TEXT_SYMS+1

#define EV_BTN_INS_TEXT_NONE EV_BTN_EXT_TEXT_PATH+1
#define EV_BTN_INS_TEXT_AUTO EV_BTN_INS_TEXT_NONE+1
#define EV_BTN_INS_TEXT_ALWA EV_BTN_INS_TEXT_AUTO+1

#define EV_BTN_AUTOSCALE EV_BTN_INS_TEXT_ALWA+1

#define EV_BTN_ABOUT EV_BTN_AUTOSCALE+1

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

#define INITIALZOOM 80000
#define EXTERN_VISIBLE_ZOOM_FACTOR 25
#define INSTEXT_VISIBLE_ZOOMFACTOR 7

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
#define INS_Y_OFF 3

#define MAX_LIVE_ANIMATION_NODES_PER_FRAME 100

#define HEATMAP_KEY_SQUARESIZE 25

#define MAIN_FRAME_Y 50

#define BACKLOG_TEXT_COLOUR_LOW agui::Color(255, 255, 255)
#define BACKLOG_TEXT_COLOUR_HIGH agui::Color(255, 255, 0)
#define BACKLOG_TEXT_COLOUR_FULL agui::Color(255, 0, 0)

#define ANIM_INACTIVE_NODE_ALPHA 0.00
#define ANIM_INACTIVE_EDGE_ALPHA 0.00
