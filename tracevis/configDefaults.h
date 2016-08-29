#pragma once
#define HEATMAP_DELAY_MS 1000

#define CONDITIONAL_DELAY_MS 1000
#define CONDITIONAL_edgeColor al_map_rgba(25, 25, 25, 150)
#define CONDITIONAL_background al_map_rgba(180, 180, 180, 150)
#define CONDITIONAL_cond_fail al_map_rgba(255, 0, 0, 255)
#define CONDITIONAL_cond_succeed al_map_rgba(0, 255, 0, 255)
#define CONDITIONAL_cond_both al_map_rgba(0, 0, 0, 0)

#define WIREFRAME_COLOUR al_map_rgba(255, 255, 255, 255)

#define PREVIEW_RENDER_FPS 10
#define PREVIEW_UPDATE_DELAY_MS 400
#define PREVIEW_DELAY_PER_GRAPH 80
#define PREVIEW_SPIN_PER_FRAME 0.6
#define PREVIEW_EDGES_PER_RENDER 60

#define MAIN_BACKGROUND_COLOUR al_map_rgba(0, 0, 0, 255)
#define GRAPH_LOW_B 70
#define GRAPH_FAR_A 300