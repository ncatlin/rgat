#pragma once
#include "stdafx.h"
#include "GUIStructs.h"
#include "diffWindow.h"
#include "highlightWindow.h"
#include "animControls.h"
#include "exeWindow.h"

#include <Agui/Agui.hpp>
#include <Agui/Backends/Allegro5/Allegro5.hpp>
#include "Agui\Widgets\DropDown\DropDown.hpp"
#include "Agui\Widgets\Label\Label.hpp"
#include "Agui\Widgets\RadioButton\RadioButton.hpp"
#include "Agui\Widgets\Frame\Frame.hpp"
#include "Agui\FlowLayout.hpp"
#include "Agui\Widgets\TextField\TextField.hpp"
#include "Agui\Widgets\ToolTip\ToolTip.hpp"
#include "Agui\Widgets\ScrollBar\VScrollBar.hpp"

#define WIDGET_UPDATE_GAP 10
class TraceVisGUI {

public:
	TraceVisGUI(VISSTATE *cstate) { clientState = cstate; }
	void widgetSetup(string fontpath);
	agui::Allegro5Input *inputHandler() { return widgetInputHandler; }
	agui::DropDown *dropdown() { return dropDownWidget; }
	void updateWidgets(thread_graph_data *graph);
	void paintWidgets();
	void setScrollbarVisible(bool enabled) { controlWindow->setScrollbarVisible(enabled); }
	void doScroll(int z) { controlWindow->doScroll(z); }
	int getScroll() { return controlWindow->getScroll(); }
	void setScrollbarMax(int val) { controlWindow->setScrollbarMax(val); }
	void doLogic() { widgets->logic(); }
	void setActivePID(int PID);
	void addPID(int PID);
	void showHideDiffFrame();
	void showHideHighlightFrame();
	void processEvent(ALLEGRO_EVENT *ev)
		{ widgetInputHandler->processEvent(*ev); widgets->logic();	}
	bool dropdownDropped() { return dropDownWidget->isDropDownShowing(); }
	void showGraphToolTip(thread_graph_data *graph, PROCESS_DATA *piddata, int x, int y);

	DiffSelectionFrame *diffWindow = NULL;
	HighlightSelectionFrame *highlightWindow = NULL;
	AnimControls *controlWindow = NULL;
	exeWindow *exeSelector = NULL;
	void fitToResize();

	//redrawing every widget is awfully slow
	//activating this makes it happen every frame
	void toggleSmoothDrawing(bool activated) { 
		if (activated && dropdownDropped()) return;
		smoothDrawing = activated; 
	}
	bool isSmoothDrawing() { return smoothDrawing; }
	bool isHighlightVisible() { return highlightWindow->highlightFrame->isVisible(); }

private:
	agui::ToolTip *tippy;
	agui::Gui *widgets;
	VISSTATE *clientState;
	agui::Allegro5Graphics *widgetGraphicsHandler;
	agui::Label *pidDropLabel;
	agui::DropDown *dropDownWidget;
	agui::Allegro5Input *widgetInputHandler;
	int widgetsUpdateCooldown = 1;
	bool smoothDrawing = false;
	vector<string> pidEntryQueue;
};

class PIDDropdownListener : public agui::ActionListener
{
public:
	PIDDropdownListener(VISSTATE *state) { clientState = state; }
	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		int PID = std::stoi(evt.getSource()->getText());
		if (PID != clientState->activePid->PID)
			clientState->newPID = PID;
	}
private:
	VISSTATE *clientState;
};

ALLEGRO_DISPLAY* displaySetup();
void updateTitle(ALLEGRO_DISPLAY *display, TITLE *title);
void updateTitle_Mouse(ALLEGRO_DISPLAY *display, TITLE *title, int x, int y);
void updateTitle_Zoom(ALLEGRO_DISPLAY *display, TITLE *title, float zoom);
void updateTitle_FPS(ALLEGRO_DISPLAY *display, TITLE *title, int FPS, double FPSMax);
void updateTitle_NumPrimitives(ALLEGRO_DISPLAY *display, VISSTATE *clientState, int verts, int edges);
void updateTitle_dbg(ALLEGRO_DISPLAY *display, TITLE *title, char *msg);
void display_activeGraph_summary(int x, int y, ALLEGRO_FONT *font, VISSTATE *clientState);

int controlSetup();
ALLEGRO_EVENT_SOURCE * create_menu(ALLEGRO_DISPLAY *display);
void cleanup_for_exit(ALLEGRO_DISPLAY *display);
