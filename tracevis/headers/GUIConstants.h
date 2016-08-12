#pragma once

//more divisions = smoother curves
#define ADIVISIONS 32
#define BDIVISIONS 16

//don't know, please figure out how to derive properly. 
//this is good for a couple of wraps around the sphere, which is prob too many
//change it by whatever factor you change ADIVISIONS
#define COLOUR_PICKING_MYSTERY_CONSTANTA 11.115

#define al_col_red al_map_rgb(255, 0, 0)
#define al_col_green al_map_rgb(0, 255, 0)
#define al_col_white al_map_rgb(255, 255, 255)
#define al_col_purple al_map_rgb(139, 0, 139)
#define al_col_orange al_map_rgb(255, 126, 0)
#define al_col_yellow al_map_rgb(255, 255, 0)
#define al_col_grey al_map_rgb(0.3 * 255, 0.3 * 255, 0.3 * 255)


#define ICALL 0
#define IOLD 1
#define IRET 2
#define ILIB 3
#define INEW 4
#define ISTD 5
#define IFLOW 6
#define ISYS 7

#define PREV_THREAD_X_PAD 15
#define PREV_SCROLLBAR_WIDTH 30
#define PREVIEW_GRAPH_HEIGHT 200
#define PREVIEW_GRAPH_WIDTH 280
#define PREVIEW_PANE_WIDTH 300
#define PREVIEW_RENDER_FPS 10
#define PREVIEW_UPDATE_DELAY_MS 800
#define PREVIEW_SPIN_PER_FRAME 0.6

#define HEATMAP_DELAY_MS 1000
#define CONDITIONAL_DELAY_MS 1000

#define wireframe_col al_map_rgba(255, 255, 255, 255)
#define INSTEXT_FIRST 0
#define INSTEXT_NONE INSTEXT_FIRST
#define INSTEXT_AUTO 1
#define INSTEXT_ALL_ALWAYS 2
#define INSTEXT_LAST INSTEXT_ALL_ALWAYS

#define POINTSPERLINE 32
#define WIREFRAMELOOPS 18 //meant to be alterable but stuff breaks if you change this. don't.
#define WFPOSBUFSIZE WIREFRAMELOOPS * POINTSPERLINE * POSELEMS * sizeof(GLfloat)
#define WFCOLBUFSIZE WIREFRAMELOOPS * POINTSPERLINE * COLELEMS * sizeof(GLfloat)

#define VERTSPERQUAD 4
#define COL_SPHERE_VERTS ((180 / BDIVISIONS)-2)*POINTSPERLINE*VERTSPERQUAD
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
#define EV_RESIZE EV_BTN_SAVE+1
#define EV_BTN_DIFF EV_RESIZE+1

#define DIFF_SELECTED 1
#define DIFF_STARTED 2

#define STARTWWIDTH 1200
#define STARTWHEIGHT 800

//number of divisions of long curve. More = smoother, worse(?) performance
#define LONGCURVEPTS 32

#define DEFAULTPOINTSIZE 5

#define BACKVERTA 0.5
#define BMODMAG  0.55
#define BAdj 35

#define INITIALZOOM 200000

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
#define INS_Y_OFF -6