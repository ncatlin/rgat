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
The class describing the agui components of the GUI, the menu bar and
misc other UI elements
*/

#pragma once
#include "stdafx.h"
#include "GUIStructs.h"
#include "diffWindow.h"
#include "highlightWindow.h"
#include "animControls.h"
#include "exeWindow.h"
#include "plotted_graph.h"

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
#include "Agui\Widgets\ImageWidget\ImageWidget.hpp"

#define WIDGET_UPDATE_GAP 10
class TraceVisGUI {

public:
	TraceVisGUI(VISSTATE *cstate) { clientState = cstate; }
	void widgetSetup(string resourcepath, string fontfile);
	agui::Allegro5Input *inputHandler() { return widgetInputHandler; }
	agui::DropDown *dropdown() { return dropDownWidget; }
	void updateWidgets(plotted_graph *graph);
	void paintWidgets();
	void setScrollbarVisible(bool enabled) { controlWindow->setScrollbarVisible(enabled); }
	void doScroll(int z) { controlWindow->doScroll(z); }
	int getScroll() { return controlWindow->getScroll(); }
	void setScrollbarMax(int val) { controlWindow->setScrollbarMax(val); }
	void doLogic() { widgets->logic(); }
	void setActivePID(PID_TID PID);
	void addPID(PID_TID PID);
	void showHideDiffFrame();
	void showHideHighlightFrame();
	void processEvent(ALLEGRO_EVENT *ev)
		{ widgetInputHandler->processEvent(*ev); widgets->logic();	}
	bool dropdownDropped() { return dropDownWidget->isDropDownShowing(); }
	void showGraphToolTip(proto_graph *graph, PROCESS_DATA *piddata, int x, int y);
	void setLayoutIcon();

	DiffSelectionFrame *diffWindow = NULL;
	HighlightSelectionFrame *highlightWindow = NULL;
	AnimControls *controlWindow = NULL;
	exeWindow *exeSelector = NULL;
	agui::Frame *aboutBox = NULL;
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
	unsigned int processCount = 0;
	agui::ToolTip *tippy;
	agui::Gui *widgets;
	VISSTATE *clientState;
	agui::Allegro5Graphics *widgetGraphicsHandler;
	agui::Label *pidDropLabel;
	agui::Label *pidCountLabel;
	agui::DropDown *dropDownWidget;
	agui::Allegro5Input *widgetInputHandler;

	ALLEGRO_BITMAP *sphereIcon, *sphereIconBase, *treeIcon, *treeIconBase;

	int widgetsUpdateCooldown = 1;
	bool smoothDrawing = false;

	//agui is not thread safe. when a new process appears, we add it to this queue
	//our main gui handlign thread will pop it out and handle it
	vector<string> pidEntryQueue;
};

class PIDDropdownListener : public agui::ActionListener
{
public:
	PIDDropdownListener(VISSTATE *state) { clientState = state; }
	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		PID_TID PID = std::stoi(evt.getSource()->getText());
		if (!clientState->activePid || (PID != clientState->activePid->PID))
			clientState->selectedPID = PID;
	}
private:
	VISSTATE *clientState;
};

//todo: find out how to make keyboard copy and paste work with agui
class aboutListener : public agui::KeyboardListener
{
public:
	virtual void keyDownCB(const agui::KeyEvent &evt)
	{
		//if (evt.control && evt.getKey() == ALLEGRO_KEY_C)
		printf("copy %d, %d\n", evt.control(), evt.getKey());
	}
};

class aboutBtnListener : public agui::ActionListener
{
public:
	aboutBtnListener(TraceVisGUI *guiptr) { gui = guiptr; }
	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		gui->aboutBox->setVisibility(false);
	}
private:
	TraceVisGUI *gui;
};


ALLEGRO_DISPLAY* displaySetup();
void updateTitle(ALLEGRO_DISPLAY *display, TITLE *title);
void updateTitle_Mouse(ALLEGRO_DISPLAY *display, TITLE *title, int x, int y);
void updateTitle_Zoom(ALLEGRO_DISPLAY *display, TITLE *title, float zoom);
void updateTitle_FPS(ALLEGRO_DISPLAY *display, TITLE *title, int FPS, double FPSMax);
void updateTitle_NumPrimitives(ALLEGRO_DISPLAY *display, VISSTATE *clientState, int verts, int edges);
void updateTitle_dbg(ALLEGRO_DISPLAY *display, TITLE *title, char *msg);
void display_activeGraph_summary(int x, int y, ALLEGRO_FONT *font, VISSTATE *clientState);
bool GUI_init(ALLEGRO_EVENT_QUEUE ** evq, ALLEGRO_DISPLAY **newDisplay);
void handle_resize(VISSTATE *clientState);
void display_only_status_message(string msg, VISSTATE *clientState);
bool controlSetup();
ALLEGRO_EVENT_SOURCE * create_menu(ALLEGRO_DISPLAY *display);
void cleanup_for_exit(ALLEGRO_DISPLAY *display);
graphLayouts layout_selection_click(int mousex, int mousey);
void resize_display(VISSTATE *clientState, int w, int h);
void toggle_externtext_mode(VISSTATE *clientState);
void toggle_instext_mode(VISSTATE *clientState);
void closeTextLog(VISSTATE *clientState);
void toggleExternLog(VISSTATE *clientState);
