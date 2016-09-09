#include "stdafx.h"
#include "GUIConstants.h"
#include "GUIManagement.h"

RadioButtonListener::RadioButtonListener(VISSTATE *state, agui::RadioButton *s1, agui::RadioButton *s2)
{
	source1 = s1;
	source2 = s2;
	clientState = state; 
}

void TraceVisGUI::showHideHighlightFrame() 
{
	highlightWindow->highlightFrame->setVisibility(!highlightWindow->highlightFrame->isVisible());
	if (highlightWindow->highlightFrame->isVisible())
		highlightWindow->refreshDropdowns();
}

void TraceVisGUI::addPID(int PID) 
{
	string pidstring = " "+std::to_string(PID);
	//crash here if we add it while the mouse is
	//in the dropdown. queue it to do at the end of the frame
	pidEntryQueue.push_back(pidstring);
}

void TraceVisGUI::setActivePID(int PID) 
{
	string pidstring = " "+std::to_string(PID);
	dropDownWidget->setText(pidstring);
}

void TraceVisGUI::showHideDiffFrame() 
{
	diffWindow->diffFrame->setVisibility(!diffWindow->diffFrame->isVisible());
}

void TraceVisGUI::updateWidgets(thread_graph_data *graph) 
{
	
	if (!clientState->activeGraph || !widgetsUpdateCooldown--)
	{
		al_set_target_backbuffer(al_get_current_display());
		al_clear_to_color(al_col_black);
		if (graph)
			controlWindow->update(graph);
 	}
}

void TraceVisGUI::paintWidgets()
{
	if (widgetsUpdateCooldown < 0 && !smoothDrawing) return;

	while (!pidEntryQueue.empty())
	{
		dropDownWidget->addItem(pidEntryQueue.back());
		pidEntryQueue.pop_back();
	}
	widgetsUpdateCooldown = WIDGET_UPDATE_GAP;
	widgets->render();
}

void TraceVisGUI::showGraphToolTip(thread_graph_data *graph, PROCESS_DATA *piddata, int x, int y) {
	if (!graph)
	{
		tippy->hide(); 
		return;
	}

	if (graph->modPath.empty())	graph->assign_modpath(piddata);

	stringstream tipText;
	tipText << "Path: " << graph->modPath << endl;
	tipText << "Nodes: " << graph->get_num_nodes() << endl;
	tipText << "Edges: " << graph->get_num_edges() << endl;
	tipText << "Instructions: " << graph->totalInstructions << endl;

	//diff frame is at 0,0 so paint it relative to that
	agui::Widget *widget = this->diffWindow->diffFrame;
	tippy->showToolTip(tipText.str(),200,x,y,widget);
}

void TraceVisGUI::fitToResize()
{
	int framex = clientState->mainFrameSize.width;
	pidDropLabel->setLocation(framex, 12);
	dropDownWidget->setLocation(framex + pidDropLabel->getSize().getWidth(), 12 - 4);
	controlWindow->fitToResize();	
	widgets->resizeToDisplay();
}
void TraceVisGUI::widgetSetup(string fontpath) {

	//agui::Image::setImageLoader(new agui::Allegro5ImageLoader);
	agui::Font::setFontLoader(new agui::Allegro5FontLoader);
	//Instance the input handler
	widgetInputHandler = new agui::Allegro5Input();
	widgetGraphicsHandler = new agui::Allegro5Graphics();
	widgets = new agui::Gui();

	agui::Font *defaultFont = agui::Font::load(fontpath.c_str(), 14);

	agui::Widget::setGlobalFont(defaultFont);
	widgets->setGraphics(widgetGraphicsHandler);
	widgets->setInput(widgetInputHandler);

	tippy = new agui::ToolTip();
	tippy->setFont(defaultFont);
	tippy->setSize(80, 20);
	widgets->add(tippy);
	widgets->setToolTip(tippy);
	widgets->setHoverInterval(0.1);

	int framex = clientState->mainFrameSize.width + 15;
	int framey = 12;

	pidDropLabel = new agui::Label;
	widgets->add(pidDropLabel);
	pidDropLabel->setLocation(framex, framey);
	pidDropLabel->setText("Process: ");
	pidDropLabel->resizeToContents();
	pidDropLabel->setFontColor(agui::Color(255, 255, 255));

	dropDownWidget = new agui::DropDown;
	widgets->add(dropDownWidget);
	//todo: generic way of working out height. font height, padding, margins, blah blah blah
	dropDownWidget->setLocation(framex + pidDropLabel->getSize().getWidth(), framey - 4); 
	dropDownWidget->setSize(110, 25);
	dropDownWidget->setText(" Select PID");
	PIDDropdownListener *dropListen = new PIDDropdownListener(clientState);
	dropDownWidget->addActionListener(dropListen);

	//cache glyphs
	dropDownWidget->addItem("0123456789 ");
	dropDownWidget->removeItemAt(0);

	diffWindow = new DiffSelectionFrame(widgets, clientState, defaultFont);
	controlWindow = new AnimControls(widgets, clientState, defaultFont);
	highlightWindow = new HighlightSelectionFrame(widgets, clientState, defaultFont);
	exeSelector = new exeWindow(widgets, clientState, defaultFont);
}

ALLEGRO_DISPLAY* displaySetup() {

	al_set_new_window_position(100, 100);
	al_set_new_display_flags(ALLEGRO_OPENGL | ALLEGRO_WINDOWED | ALLEGRO_RESIZABLE);
	al_set_new_display_option(ALLEGRO_DEPTH_SIZE, 16, ALLEGRO_SUGGEST);

	ALLEGRO_DISPLAY *display = al_create_display(STARTWWIDTH, STARTWHEIGHT);
	if (!display) {
		if (!display)
		{
			fprintf(stderr, "Failed to create display! error: %d\n", al_get_errno());
			printf("Running this on VirtualBox?\n");
			printf("\tVB Manual:\"3D acceleration with Windows guests requires Windows 2000, Windows XP, Vista or Windows 7\"");
			return NULL;
		}
	}

	return display;
}

void updateTitle(ALLEGRO_DISPLAY *display, TITLE *title) {
	if (!title) return;
	stringstream newTitle;
	newTitle << "TraceVis. Mouse:(" << title->MPos
		<< ") Zoom:(" << title->zoom << ") "
		<< title->Primitives
		<< " FPS: " << title->FPS;
	al_set_window_title(display, newTitle.str().c_str());
}

void updateTitle_Mouse(ALLEGRO_DISPLAY *display, TITLE *title, int x, int y) {
	if (!title->MPos) return;
	snprintf(title->MPos, 25, "x:%d, y:%d", x, y);
	updateTitle(display, title);

}

void updateTitle_Zoom(ALLEGRO_DISPLAY *display, TITLE *title, float zoom) {
	if (!title->zoom) return;
	snprintf(title->zoom, 25, "%0.1f", zoom);
	updateTitle(display, title);

}

void updateTitle_dbg(ALLEGRO_DISPLAY *display, TITLE *title, char *msg) {
	if (!title->zoom) return;
	snprintf(title->dbg, 200, "%s", msg);
	updateTitle(display, title);

}


void updateTitle_NumPrimitives(ALLEGRO_DISPLAY *display, VISSTATE *clientstate, int verts, int edges){
	if (!clientstate->title->zoom) return;
	thread_graph_data *graph = (thread_graph_data *)clientstate->activeGraph;
	int mbRemaining = (int) graph->traceBufferSize / 1024;
	snprintf(clientstate->title->Primitives, 55, "[TID:%d V:%d/E:%d] Pending:%d MB", graph->tid, verts,edges, mbRemaining);
	updateTitle(display, clientstate->title);

}

void updateTitle_FPS(ALLEGRO_DISPLAY *display, TITLE *title, int FPS, double FPSMax) {
	if (!title->FPS) return;

	//get rid of annoying flicker
	if (FPSMax > 10000) FPSMax = 10000;
	if (FPS >= 59) FPS = 60;

	snprintf(title->FPS, 25, "%d (%.0f)\n", FPS, FPSMax);
	updateTitle(display, title);

}

void display_activeGraph_summary(int x, int y, ALLEGRO_FONT *font, VISSTATE *clientState)
{
	if (!clientState->activeGraph->get_num_nodes())
	{
		printf("ERROR NO VERTS in summary activegraph\n"); return;
	}
	stringstream infotxt;
	ALLEGRO_COLOR textcol;

	PROCESS_DATA *piddata = clientState->activePid;
	if (piddata->active)
		textcol = al_col_white;
	else
		textcol = al_col_red;

	int activeModule = clientState->activeGraph->get_node(0)->nodeMod;
	infotxt << piddata->modpaths[activeModule];
	infotxt << " (PID: " << piddata->PID << ")" << " (TID: " << clientState->activeGraph->tid << ")";

	al_draw_filled_rectangle(0, 0, clientState->mainFrameSize.width, 32, al_map_rgba(0, 0, 0, 235));
	al_draw_text(font, textcol, x, y, ALLEGRO_ALIGN_LEFT, infotxt.str().c_str());
}

int controlSetup() {
	if (!al_install_mouse()) {
		printf("Error installing mouse.\n");
		return 0;
	}
	if (!al_install_keyboard()) {
		printf("Error installing keyboard.\n");
		return 0;
	}
	return 1;
}

void cleanup_for_exit(ALLEGRO_DISPLAY *display) {
	al_destroy_display(display);
	printf("Done cleanup!\n");
}

ALLEGRO_EVENT_SOURCE * create_menu(ALLEGRO_DISPLAY *display) {
	ALLEGRO_MENU_INFO menu_info[] = {

		ALLEGRO_START_OF_MENU("&File", 1),
		{ "&Run", EV_BTN_RUN, 0, NULL },
		{ "&Save", EV_BTN_SAVE, 0, NULL },
		{ "&Load", EV_BTN_LOAD, 0, NULL },

		ALLEGRO_START_OF_MENU("Open &Recent...", 3),
		{ "Recent 1", 4, 0, NULL },
		{ "Recent 2", 5, 0, NULL },
		ALLEGRO_END_OF_MENU,
		ALLEGRO_MENU_SEPARATOR,
		{ "E&xit", EV_BTN_QUIT, 0, NULL },
		ALLEGRO_END_OF_MENU,

		{ "&Wireframe [y]", EV_BTN_WIREFRAME, 0, NULL },

		ALLEGRO_START_OF_MENU("Views", 3),
		{ "&Heatmap [k]", EV_BTN_HEATMAP, 0, NULL },
		{ "&Conditionals [j]", EV_BTN_CONDITION, 0, NULL },
		{ "&Preview", EV_BTN_PREVIEW, 0, NULL },
		{ "&Diff", EV_BTN_DIFF, 0, NULL },
		ALLEGRO_END_OF_MENU,

		{ "&Call Log", EV_BTN_EXTERNLOG, 0, NULL },
		{ "&Highlight", EV_BTN_HIGHLIGHT, 0, NULL },

		ALLEGRO_START_OF_MENU("Settings", 3),
		{ "Show Nodes", EV_BTN_NODES, 0, NULL },
		{ "Show Edges", EV_BTN_EDGES, 0, NULL },
		ALLEGRO_END_OF_MENU,

		ALLEGRO_START_OF_MENU("&Help", 7),
		{ "&About", 8, 0, NULL },
		ALLEGRO_END_OF_MENU,
		ALLEGRO_END_OF_MENU
	};

	ALLEGRO_MENU *menu_file = al_build_menu(menu_info);
	al_set_display_menu(display, menu_file);
	ALLEGRO_EVENT_SOURCE *menuEvents = al_enable_menu_event_source(menu_file);
	return menuEvents;
}