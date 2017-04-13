#include "plotted_graph_layouts.h"

#define LAYOUT_ICONS_X_END LAYOUT_ICONS_X3 + LAYOUT_ICONS_W
#define LAYOUT_ICONS_Y_END LAYOUT_ICONS_Y + LAYOUT_ICONS_H

graphLayouts layout_selection_click(int mousex, int mousey)
{
	if (mousey > LAYOUT_ICONS_Y_END || mousex > LAYOUT_ICONS_X_END || mousex < LAYOUT_ICONS_X1 || mousey < LAYOUT_ICONS_Y)
		return eLayoutInvalid;

	if (mousex >= LAYOUT_ICONS_X1 && mousex <= (LAYOUT_ICONS_X1 + LAYOUT_ICONS_W))
		return eCylinderLayout;

	if (mousex >= LAYOUT_ICONS_X2 && mousex <= (LAYOUT_ICONS_X2 + LAYOUT_ICONS_W))
		return eSphereLayout;

	if (mousex >= LAYOUT_ICONS_X3 && mousex <= (LAYOUT_ICONS_X3 + LAYOUT_ICONS_W))
		return eTreeLayout;

	return eLayoutInvalid;
}