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
#include "stdafx.h"
#include "GUIConstants.h"
#include "GUIManagement.h"
#include "OSspecific.h"
#include "plotted_graph.h"

RadioButtonListener::RadioButtonListener(VISSTATE *state, agui::RadioButton *s1, agui::RadioButton *s2)
{
	source1 = s1;
	source2 = s2;
	clientState = state; 
}



void TraceVisGUI::showHideHighlightFrame() 
{
	bool frameIsVisible = highlightWindow->highlightFrame->isVisible();
	if (frameIsVisible)
		clientState->closeFrame(highlightWindow->highlightFrame);
	else
		clientState->openFrame(highlightWindow->highlightFrame);
	frameIsVisible = !frameIsVisible;

	if (frameIsVisible)
		highlightWindow->refreshData();
}

void TraceVisGUI::addPID(PID_TID PID)
{
	string pidstring = " "+std::to_string(PID);
	//crash here if we add it while the mouse is
	//in the dropdown. queue it to do at the end of the frame
	pidEntryQueue.push_back(pidstring);
}

void TraceVisGUI::setActivePID(PID_TID PID)
{
	string pidstring = " "+std::to_string(PID);
	dropDownWidget->setText(pidstring);
}

void TraceVisGUI::showHideDiffFrame() 
{
	if (diffWindow->diffFrame->isVisible())
		clientState->closeFrame(diffWindow->diffFrame);
	else
		clientState->openFrame(diffWindow->diffFrame);
}

void TraceVisGUI::updateWidgets(plotted_graph *graph)
{
	const int ticksRemaining = --widgetsUpdateCooldown;
	if (!graph) return;
	if (ticksRemaining == 0)
		controlWindow->update(graph);

	if (highlightWindow->highlightFrame->isVisible() && highlightWindow->staleData())
		highlightWindow->refreshData();
}

//widgets->render() is a monster on the CPU
//try not to do it more than needed
void TraceVisGUI::paintWidgets()
{
	if (widgetsUpdateCooldown > 0 && !smoothDrawing) return;
	
	while (!pidEntryQueue.empty())
	{
		dropDownWidget->addItem(pidEntryQueue.back());
		pidCountLabel->setText("(of " + to_string(++processCount) + ")");
		pidCountLabel->resizeToContents();
		pidEntryQueue.pop_back();
	}
	widgetsUpdateCooldown = WIDGET_UPDATE_GAP;

	al_set_target_bitmap(clientState->GUIBMP);
	al_clear_to_color(al_map_rgba(0, 0, 0, 0));
	widgets->render();

	al_draw_tinted_bitmap(cylinderIcon, al_map_rgba(255, 255, 255, 255), LAYOUT_ICONS_X1, LAYOUT_ICONS_Y, 0);
	al_draw_tinted_bitmap(sphereIcon, al_map_rgba(255, 255, 255, 255),  LAYOUT_ICONS_X2, LAYOUT_ICONS_Y, 0);
	al_draw_tinted_bitmap(treeIcon, al_map_rgba(255, 255, 255, 255), LAYOUT_ICONS_X3, LAYOUT_ICONS_Y, 0);
}

void TraceVisGUI::setLayoutIcon()
{
	ALLEGRO_BITMAP *oldbmp = al_get_target_bitmap();

	al_set_target_bitmap(cylinderIcon);
	al_clear_to_color(al_map_rgba(0, 0, 0, 0));
	if (clientState->currentLayout == eCylinderLayout)
	{
		al_draw_tinted_bitmap(cylinderIconBase, al_map_rgba(255, 255, 255, 255), 0, 0, 0);
		al_draw_rectangle(1, 1, 47, 47, al_col_white, 2);
		al_draw_rectangle(3, 3, 45, 45, al_col_black, 2);
	}
	else
	{
		al_draw_tinted_bitmap(cylinderIconBase, al_map_rgba(255, 255, 255, 100), 0, 0, 0);
	}


	al_set_target_bitmap(sphereIcon);
	al_clear_to_color(al_map_rgba(0, 0, 0, 0));
	if (clientState->currentLayout == eSphereLayout)
	{
		al_draw_tinted_bitmap(sphereIconBase, al_map_rgba(255, 255, 255, 255), 0, 0, 0);
		al_draw_rectangle(1, 1, 47, 47, al_col_white, 2);
		al_draw_rectangle(3, 3, 45, 45, al_col_black, 2);
	}
	else
	{
		al_draw_tinted_bitmap(sphereIconBase, al_map_rgba(255, 255, 255, 100), 0, 0, 0);
	}

	al_set_target_bitmap(treeIcon);
	al_clear_to_color(al_map_rgba(0, 0, 0, 0));
	if (clientState->currentLayout == eTreeLayout)
	{
		al_draw_tinted_bitmap(treeIconBase, al_map_rgba(255, 255, 255, 255), 0, 0, 0);
		al_draw_rectangle(1, 1, 47, 47, al_col_white, 2);
		al_draw_rectangle(3, 3, 45, 45, al_col_black, 2);
	}
	else
	{
		al_draw_tinted_bitmap(treeIconBase, al_map_rgba(255, 255, 255, 100), 0, 0, 0);
	}



	al_set_target_bitmap(oldbmp);
}

void TraceVisGUI::showGraphToolTip(proto_graph *graph, PROCESS_DATA *piddata, int x, int y) {
	if (!graph)
	{
		tippy->hide(); 
		return;
	}

	if (graph->modulePath.empty())	graph->assign_modpath(piddata);

	stringstream tipText;
	tipText << "Path: " << graph->modulePath << endl;
	tipText << "Nodes: " << graph->get_num_nodes() << endl;
	tipText << "Edges: " << graph->get_num_edges() << endl;
	tipText << "Instructions: " << graph->totalInstructions << endl;

	//diff frame is at 0,0 so paint it relative to that
	agui::Widget *widget = this->diffWindow->diffFrame;
	tippy->showToolTip(tipText.str(),200,x,y,widget);
}

void TraceVisGUI::initialiseIcons(string resourcepath)
{
	stringstream iconsPath;
	iconsPath << resourcepath << "\\layoutIcons.png";
	ALLEGRO_BITMAP *iconsBmp = al_load_bitmap(iconsPath.str().c_str());

	sphereIconBase = al_create_bitmap(48, 48);
	sphereIcon = al_create_bitmap(48, 48);
	treeIconBase = al_create_bitmap(48, 48);
	treeIcon = al_create_bitmap(48, 48);
	cylinderIcon = al_create_bitmap(48, 48);
	cylinderIconBase = al_create_bitmap(48, 48);

	if (iconsBmp)
	{
		al_set_target_bitmap(cylinderIconBase);
		al_draw_bitmap_region(iconsBmp, 0, 0, 48, 48, 0, 0, 0);
		al_set_target_bitmap(sphereIconBase);
		al_draw_bitmap_region(iconsBmp, 48, 0, 48, 48, 0, 0, 0);
		al_set_target_bitmap(treeIconBase);
		al_draw_bitmap_region(iconsBmp, 96, 0, 48, 48, 0, 0, 0);

	}
	else
	{
		ALLEGRO_FONT *ifont = al_load_ttf_font(resourcepath.c_str(), 14, 0);

		if (ifont)
		{
			al_set_target_bitmap(sphereIconBase);
			al_draw_text(ifont, al_col_white, 20, 20, 0, "S");

			al_set_target_bitmap(treeIconBase);
			al_draw_text(ifont, al_col_white, 20, 20, 0, "T");

			al_set_target_bitmap(cylinderIconBase);
			al_draw_text(ifont, al_col_white, 20, 20, 0, "C");
		}
		else
		{
			al_set_target_bitmap(sphereIconBase);
			al_clear_to_color(al_col_red);

			al_set_target_bitmap(treeIconBase);
			al_clear_to_color(al_col_green);

			al_set_target_bitmap(cylinderIconBase);
			al_clear_to_color(al_col_purple);
		}
	}
	setLayoutIcon();
}

void TraceVisGUI::fitToResize()
{
	int framex = clientState->mainFrameSize.width;
	pidDropLabel->setLocation(framex, 12);
	dropDownWidget->setLocation(framex + pidDropLabel->getSize().getWidth(), 12 - 4);
	controlWindow->fitToResize();	
	widgets->resizeToDisplay();
}

void TraceVisGUI::widgetSetup(string resourcepath, string fontfile) {

	agui::Font::setFontLoader(new agui::Allegro5FontLoader);
	//Instance the input handler
	widgetInputHandler = new agui::Allegro5Input();
	widgetGraphicsHandler = new agui::Allegro5Graphics();
	widgets = new agui::Gui();

	string fontPath = string(resourcepath) + "\\" + fontfile;
	agui::Font *defaultFont = agui::Font::load(fontPath.c_str(), 14);

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
	dropDownWidget->setSize(105, 25);
	dropDownWidget->setText(" Select PID");
	PIDDropdownListener *dropListen = new PIDDropdownListener(clientState);
	dropDownWidget->addActionListener(dropListen);

	//cache glyphs
	dropDownWidget->addItem("0123456789 ");
	dropDownWidget->removeItemAt(0);

	pidCountLabel = new agui::Label;
	pidCountLabel->setLocation(dropDownWidget->getLocation().getX()+dropDownWidget->getWidth(), framey);
	pidCountLabel->setFontColor(agui::Color(255, 255, 255));
	widgets->add(pidCountLabel);

	diffWindow = new DiffSelectionFrame(widgets, clientState, defaultFont);
	controlWindow = new AnimControls(widgets, clientState, defaultFont);
	highlightWindow = new HighlightSelectionFrame(widgets, clientState, defaultFont);
	exeSelector = new exeWindow(widgets, clientState, defaultFont);

	aboutBox = new agui::Frame();
	aboutBox->setSize(300, 110);
	aboutBox->setVisibility(false);
	agui::FlowLayout *aboutLayout = new agui::FlowLayout;
	aboutLayout->setMargins(5, 10, 5, 10);
	aboutLayout->setMaxOnRow(1);
	aboutLayout->setHorizontallyCentered(true);
	aboutBox->add(aboutLayout);
	
	stringstream versionSS;
	versionSS << "rgat Version " << RGAT_VERSION_MAJ << ".";
	versionSS << RGAT_VERSION_MIN << "." << RGAT_VERSION_FEATURE;
	versionSS << " (" << RGAT_VERSION_DESCRIPTION << ")";

	agui::Label *versionLabel = new agui::Label;
	versionLabel->setText(versionSS.str());
	versionLabel->resizeToContents();
	aboutLayout->add(versionLabel);

	aboutBtnListener *abtBtnListen = new aboutBtnListener(this);

	//this was a textfield but the keyboardevent handler wasnt seeing ctrl-c
	//could add a 'Copy' button but that looks crap
	//instead ill just leave it as a label until I can summon the will to diagnose the keyboard issue
	agui::Label *seeElseWhereUrl = new agui::Label;
	seeElseWhereUrl->setText("https://github.com/ncatlin/rgat/");
	seeElseWhereUrl->resizeToContents();
	seeElseWhereUrl->setBackColor(aboutBox->getContentPane()->getBackColor());
	//seeElseWhereUrl->setReadOnly(true);
	//seeElseWhereUrl->setWantHotkeys(true);
	aboutLayout->add(seeElseWhereUrl);

	agui::Button *closeBtn = new agui::Button;

	closeBtn->setText("Close");
	closeBtn->resizeToContents();
	closeBtn->setLocation(60, closeBtn->getLocation().getY());
	closeBtn->addActionListener(abtBtnListen);
	aboutLayout->add(closeBtn);

	aboutLayout->resizeToContents();
	aboutBox->resizeToContents();
	widgets->add(aboutBox);

	textConfigBox = new textDialog(widgets, clientState, defaultFont);

	al_init_image_addon();

	initialiseIcons(resourcepath);
	

}



ALLEGRO_DISPLAY* displaySetup() 
{

	al_set_new_window_position(100, 100);
	al_set_new_display_flags(ALLEGRO_OPENGL | ALLEGRO_WINDOWED | ALLEGRO_RESIZABLE);
	al_set_new_display_option(ALLEGRO_DEPTH_SIZE, 16, ALLEGRO_SUGGEST);

	ALLEGRO_DISPLAY *display = al_create_display(STARTWWIDTH, STARTWHEIGHT);
	if (!display) 
	{
		cerr << "[rgat]Failed to create display! Allegro error: "<< al_get_errno() << endl;
		cerr << "[rgat]Running this on VirtualBox?" << endl;
		cerr << "[rgat]VirtualBox Manual:" << endl;
		cerr << "\t\"3D acceleration with Windows guests requires Windows 2000, Windows XP, Vista or Windows 7\"" << endl;
		cerr << "[rgat]It is safer to record the trace in nongraphical mode [-e from the command line]" << endl;
		cerr << "[rgat]Replay the trace in an environment with 3D support." << endl;
		return NULL;
	}

	return display;
}

void updateTitle(ALLEGRO_DISPLAY *display, TITLE *title) {
	if (!title) return;
	stringstream newTitle;
	newTitle << "rgat " 
		<< RGAT_VERSION_MAJ << "." << RGAT_VERSION_MIN << "." << RGAT_VERSION_FEATURE << " " 
		<<title->Primitives;
		//<< " FPS: " << title->FPS;
	al_set_window_title(display, newTitle.str().c_str());
}

void updateTitle_Mouse(ALLEGRO_DISPLAY *display, TITLE *title, int x, int y) {
	if (!title->MPos) return;
	snprintf(title->MPos, 25, "x:%d, y:%d", x, y);
	updateTitle(display, title);

}

void updateTitle_Zoom(ALLEGRO_DISPLAY *display, TITLE *title, float zoom) 
{
	if (!title->zoom) return;
	snprintf(title->zoom, 25, "%0.1f", zoom);
	updateTitle(display, title);
}

void updateTitle_dbg(ALLEGRO_DISPLAY *display, TITLE *title, char *msg) 
{
	if (!title->zoom) return;
	snprintf(title->dbg, 200, "%s", msg);
	updateTitle(display, title);
}

void updateTitle_NumPrimitives(ALLEGRO_DISPLAY *display, VISSTATE *clientState, int nodes, int edges)
{
	if (!clientState->title->zoom) return;
	if (!clientState->activeGraph) return;
	proto_graph * graph = ((plotted_graph*)clientState->activeGraph)->get_protoGraph();
	if (!graph) return;

	
	snprintf(clientState->title->Primitives, PRIMITIVES_STRING_MAX, "[target:%s TID:%d %d Nodes / %d Edges]", basename(graph->modulePath).c_str(), graph->get_TID(), nodes, edges);
	updateTitle(display, clientState->title);
}

void updateTitle_FPS(ALLEGRO_DISPLAY *display, TITLE *title, int FPS, double FPSMax) {
	if (!title->FPS) return;

	if (FPS >= 59) FPS = 60;
	//get rid of annoying flicker
	if (FPSMax > 10000) FPSMax = 10000;
	

	snprintf(title->FPS, 25, "%d (%.0f)\n", FPS, FPSMax);
	updateTitle(display, title);
}

void display_activeGraph_summary(int x, int y, ALLEGRO_FONT *font, VISSTATE *clientState)
{
	proto_graph * graph = ((plotted_graph*)clientState->activeGraph)->get_protoGraph();
	if (!graph->get_num_nodes())
		return;

	stringstream infotxt;
	ALLEGRO_COLOR textColour;

	PROCESS_DATA *piddata = clientState->activePid;
	if (piddata->is_running())
		textColour = al_col_white;
	else
		textColour = al_col_red;

	int activeModule = graph->safe_get_node(0)->nodeMod;
	string modPath;
	piddata->get_modpath(activeModule, &modPath);
	infotxt << modPath <<" (PID: " << piddata->PID << ")" << " (TID: " << graph->get_TID() << ")";

	al_draw_filled_rectangle(0, 0, clientState->mainFrameSize.width, 32, al_map_rgba(0, 0, 0, 235));
	al_draw_text(font, textColour, x, y, ALLEGRO_ALIGN_LEFT, infotxt.str().c_str());
}

bool GUI_init(ALLEGRO_EVENT_QUEUE ** evq, ALLEGRO_DISPLAY **newDisplay) 
{

	*newDisplay = displaySetup();
	if (!*newDisplay) {
		cerr << "[rgat]Display creation failed, returned: " << (int)newDisplay << endl;
		return false;
	}

	if (!controlSetup()) {
		cerr << "[rgat]Control setup failed" << endl;
		return false;
	}

	if (!al_init_font_addon() || !al_init_ttf_addon())
	{
		cerr << "[rgat]ERROR: Failed to init allegro font addon. Exiting..." << endl;
		return -1;
	}

	*evq = al_create_event_queue();
	al_register_event_source(*evq, (ALLEGRO_EVENT_SOURCE*)al_get_mouse_event_source());
	al_register_event_source(*evq, (ALLEGRO_EVENT_SOURCE*)al_get_keyboard_event_source());
	al_register_event_source(*evq, create_menu(*newDisplay));
	al_register_event_source(*evq, al_get_display_event_source(*newDisplay));
	return true;
}

void handle_resize(VISSTATE *clientState)
{
	glViewport(0, 0, clientState->mainFrameSize.width, clientState->mainFrameSize.height);

	al_destroy_bitmap(clientState->GUIBMP);
	clientState->GUIBMP = al_create_bitmap(clientState->displaySize.width, clientState->displaySize.height);
	TraceVisGUI *widgets = (TraceVisGUI *)clientState->widgets;
	widgets->fitToResize();

	al_destroy_bitmap(clientState->mainGraphBMP);
	al_destroy_bitmap(clientState->previewPaneBMP);
	clientState->mainGraphBMP = al_create_bitmap(clientState->mainFrameSize.width, clientState->mainFrameSize.height);
	clientState->previewPaneBMP = al_create_bitmap(PREVIEW_PANE_WIDTH, clientState->displaySize.height - 50);
}

bool controlSetup() {
	if (!al_install_mouse()) {
		cerr << "[rgat]Error installing mouse." << endl;
		return false;
	}
	if (!al_install_keyboard()) {
		cerr << "[rgat]Error installing keyboard." << endl;
		return false;
	}
	return true;
}

void cleanup_for_exit(VISSTATE *cstate) 
{
	free(cstate->wireframeStarts);
	free(cstate->wireframeSizes);
	al_destroy_display(cstate->maindisplay);
}

ALLEGRO_EVENT_SOURCE * create_menu(ALLEGRO_DISPLAY *display) 
{
	ALLEGRO_MENU_INFO menu_info[] = {

		ALLEGRO_START_OF_MENU("&File", 1),
		{ "&Run executable", EV_BTN_RUN, 0, NULL },
		{ "&Save process traces", EV_BTN_SAVE, 0, NULL },
		{ "&Load saved trace", EV_BTN_LOAD, 0, NULL },

		//todo?
		//ALLEGRO_START_OF_MENU("Open &Recent...", 3),
		//{ "Recent 1", 4, 0, NULL },
		//{ "Recent 2", 5, 0, NULL },
		//ALLEGRO_END_OF_MENU,

		ALLEGRO_MENU_SEPARATOR,
		{ "E&xit", EV_BTN_QUIT, 0, NULL },
		ALLEGRO_END_OF_MENU,

		ALLEGRO_START_OF_MENU("Visualisations", 3),
		{ "&Heatmap [k]", EV_BTN_HEATMAP, 0, NULL },
		{ "&Conditionals [j]", EV_BTN_CONDITION, 0, NULL },
		{ "&Previews", EV_BTN_PREVIEW, 0, NULL },
		{ "&Divergence", EV_BTN_DIFF, 0, NULL },
		//{ "&Mutation", EV_BTN_MUTATION, 0, NULL },
		ALLEGRO_END_OF_MENU,

		{ "&Call Log", EV_BTN_EXTERNLOG, 0, NULL },
		{ "&Highlight", EV_BTN_HIGHLIGHT, 0, NULL },

		ALLEGRO_START_OF_MENU("Settings", 3),
		{ "Show Nodes", EV_BTN_NODES, 0, NULL },
		{ "Show Edges [e]", EV_BTN_EDGES, 0, NULL },
		{ "Show &Wireframe [y]", EV_BTN_WIREFRAME, 0, NULL },
		{ "Toggle Autoscale", EV_BTN_AUTOSCALE, 0, NULL },
		{ "Reset Scale", EV_BTN_RESETSCALE, 0, NULL },
		{ "View sphere nearside only [n]", EV_BTN_NEARSIDE, 0, NULL },
		ALLEGRO_END_OF_MENU,

		{ "&Text [t]", EV_BTN_EXT_TEXT_MENU, 0, NULL },

		{ "&About", EV_BTN_ABOUT, 0, NULL },
		ALLEGRO_END_OF_MENU
	};

	ALLEGRO_MENU *menu_file = al_build_menu(menu_info);
	al_set_display_menu(display, menu_file);
	ALLEGRO_EVENT_SOURCE *menuEvents = al_enable_menu_event_source(menu_file);
	return menuEvents;
}

//display message in middle of the screen when doing something that locks UI
void display_only_status_message(string msg, VISSTATE *clientState)
{
	al_clear_to_color(al_col_black);
	int textw = al_get_text_width(clientState->standardFont, msg.c_str());
	int middlex = clientState->displaySize.width / 2 - textw / 2;
	al_draw_text(clientState->messageFont, al_col_white, middlex, clientState->mainFrameSize.height / 2, 0, msg.c_str());
	al_set_target_backbuffer(clientState->maindisplay);
	al_draw_bitmap(clientState->GUIBMP, 0, 0, 0);
	al_flip_display();
}

void resize_display(VISSTATE *clientState, int w, int h)
{
	ALLEGRO_DISPLAY *display = clientState->maindisplay;

	clientState->displaySize.height = h;
	clientState->displaySize.width = w;

	clientState->mainFrameSize.height = h - BASE_CONTROLS_HEIGHT;
	clientState->mainFrameSize.width = w - (PREVIEW_PANE_WIDTH + PREV_SCROLLBAR_WIDTH);

	al_acknowledge_resize(display);
	handle_resize(clientState);
}

void closeTextLog(VISSTATE *clientState)
{
	al_close_native_text_log(clientState->textlog);
	clientState->textlog = 0;
	clientState->logSize = 0;
}

void toggleExternLog(VISSTATE *clientState)
{
	if (clientState->textlog)
	{
		closeTextLog(clientState);
		return;
	}
	
	if (!clientState->activeGraph) return;

	plotted_graph *activeGraph = (plotted_graph *)clientState->activeGraph;
	stringstream windowName;
	windowName << "Extern calls [TID: " << activeGraph->get_protoGraph()->get_TID() << "]";
	clientState->textlog = al_open_native_text_log(windowName.str().c_str(), 0);
	ALLEGRO_EVENT_SOURCE* logevents = (ALLEGRO_EVENT_SOURCE*)al_get_native_text_log_event_source(clientState->textlog);
	al_register_event_source(clientState->event_queue, logevents);
	clientState->logSize = activeGraph->get_protoGraph()->fill_extern_log(clientState->textlog, clientState->logSize);
}