#include "stdafx.h"
#include "GUIConstants.h"
#include "GUIManagement.h"

class AnimButtonListener : public agui::ActionListener
{
public:
	AnimButtonListener(VISSTATE *state, agui::TextField *tfl) { clientState = state; stepq = tfl; }
	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		string btntext = evt.getSource()->getText();
		if (btntext == ">")
		{
			clientState->animationUpdate = 1;
			return;
		}
		if (btntext == "<")
		{
			clientState->animationUpdate = -1;
			return;
		}

		if (btntext == "Stop")
		{
			clientState->animationUpdate = 0;
			clientState->modes.animation = false;
			evt.getSource()->setText("Play");
			evt.getSource()->resizeToContents();
			return;
		}

		if (btntext == "Disconnect")
		{
			printf("Disconnect");
			return;
		}

		int quantity = std::stoi(stepq->getText());
		if (btntext == ">>")
		{
			clientState->animationUpdate = quantity;
			return;
		}

		if (btntext == "<<")
		{
			clientState->animationUpdate = -quantity;
			return;
		}

		if (btntext == "Play")
		{
			clientState->animationUpdate = quantity;
			clientState->modes.animation = true;
			evt.getSource()->setText("Stop");
			evt.getSource()->resizeToContents();
			return;
		}

	}
private:
	VISSTATE *clientState;
	agui::TextField *stepq;
};

void AnimControls::notifyAnimFinished()
{
	playBtn->setText("Play");
	playBtn->resizeToContents();
}

void AnimControls::update(thread_graph_data *graph)
{
	if (graph->active == enableState)
		setAnimEnabled(!graph->active);

	stringstream stepInfo;
	if (clientState->stepBBs)
		stepInfo << graph->sequenceIndex+1 << "/" << graph->bbsequence.size() << " basic blocks";
	else
		stepInfo << graph->animInstructionIndex << "/" << graph->totalInstructions-1 << " instructions";
	stepsLabel->setText(stepInfo.str());
}

void AnimControls::setAnimEnabled(bool newState)
{
	enableState = newState;
	if (enableState)
	{
		connectBtn->setVisibility(false);
		backJumpBtn->setVisibility(true);
		backStepBtn->setVisibility(true);
		forwardStepBtn->setVisibility(true);
		forwardJumpBtn->setVisibility(true);
		playBtn->setVisibility(true);
		stepText->setVisibility(true);
	}
	else
	{
		connectBtn->setVisibility(true);
		backJumpBtn->setVisibility(false);
		backStepBtn->setVisibility(false);
		forwardStepBtn->setVisibility(false);
		forwardJumpBtn->setVisibility(false);
		playBtn->setVisibility(false);
		stepText->setVisibility(false);
	}
	
}

AnimControls::AnimControls(agui::Gui *widgets, VISSTATE *cstate) {
	guiwidgets = widgets;
	clientState = cstate;
	controlsLayout = new agui::FlowLayout;

	
	btnFont = agui::Font::load("VeraSe.ttf", 22);

	connectBtn = new agui::Button();
	connectBtn->setFont(btnFont);
	connectBtn->setText("Disconnect");
	connectBtn->setMargins(0, 8, 0, 8);
	connectBtn->resizeToContents();
	connectBtn->setBackColor(agui::Color(210, 210, 210));
	controlsLayout->add(connectBtn);

	backStepBtn = new agui::Button();
	backStepBtn->setFont(btnFont);
	backStepBtn->setText("<<");
	backStepBtn->resizeToContents();
	backStepBtn->setBackColor(agui::Color(210, 210, 210));
	backStepBtn->setToolTipText("Step animation back by one");
	controlsLayout->add(backStepBtn);

	backJumpBtn = new agui::Button();
	backJumpBtn->setFont(btnFont);
	backJumpBtn->setText("<");
	backJumpBtn->resizeToContents();
	backJumpBtn->setBackColor(agui::Color(210, 210, 210));
	backJumpBtn->setToolTipText("Jump animation back by specified steps");
	controlsLayout->add(backJumpBtn);

	stepText = new agui::TextField();
	stepText->setText("1");
	stepText->setSize(70, backStepBtn->getHeight());
	stepText->setNumeric(true);
	controlsLayout->add(stepText);

	forwardStepBtn = new agui::Button();
	forwardStepBtn->setFont(btnFont);
	forwardStepBtn->setText(">");
	forwardStepBtn->resizeToContents();
	forwardStepBtn->setBackColor(agui::Color(210, 210, 210));
	forwardStepBtn->setToolTipText("Step animation forward by one");
	controlsLayout->add(forwardStepBtn);

	forwardJumpBtn = new agui::Button();
	forwardJumpBtn->setFont(btnFont);
	forwardJumpBtn->setText(">>");
	forwardJumpBtn->resizeToContents();
	forwardJumpBtn->setBackColor(agui::Color(210, 210, 210));
	forwardJumpBtn->setToolTipText("Jump animation forward by specified steps");
	controlsLayout->add(forwardJumpBtn);

	playBtn = new agui::Button();
	playBtn->setFont(btnFont);
	playBtn->setText("Play");
	playBtn->setToolTipText("Play animation at specified steps per frame");
	playBtn->setMargins(0, 8, 0, 8);
	playBtn->resizeToContents();
	playBtn->setSize(playBtn->getWidth(), forwardStepBtn->getHeight());
	playBtn->setBackColor(agui::Color(210, 210, 210));
	controlsLayout->add(playBtn);

	stepsLabel = new agui::Label();
	stepsLabel->setFont(btnFont);
	stepsLabel->setFontColor(agui::Color(210, 210, 210));
	stepsLabel->setText("x Steps total");
	stepsLabel->resizeToContents();
	stepsLabel->setBackColor(agui::Color(210, 210, 210));
	stepsLabel->setVisibility(true);
	stepsLabel->setEnabled(true);
	controlsLayout->add(stepsLabel);

	controlsLayout->resizeToContents();
	controlsLayout->setLocation(50, clientState->size.height - playBtn->getHeight()*2.2);
	controlsLayout->setHorizontalSpacing(10);
	widgets->add(controlsLayout);
	setAnimEnabled(false);

	AnimButtonListener *btnListen = new AnimButtonListener(clientState, stepText);
	connectBtn->addActionListener(btnListen);
	backStepBtn->addActionListener(btnListen);
	backJumpBtn->addActionListener(btnListen);
	forwardStepBtn->addActionListener(btnListen);
	forwardJumpBtn->addActionListener(btnListen);
	playBtn->addActionListener(btnListen);


}

RadioButtonListener::RadioButtonListener(VISSTATE *state, agui::RadioButton *s1, agui::RadioButton *s2)
{
	source1 = s1;
	source2 = s2;
	clientState = state; 
}

void TraceVisGUI::addPID(int PID) {
	string pidstring = " "+std::to_string(PID);
	dropDownWidget->addItem(pidstring);
}
void TraceVisGUI::setActivePID(int PID) {
	string pidstring = " "+std::to_string(PID);
	dropDownWidget->setText(pidstring);
}

int ComparisonBox::getSelectedDiff() {
	if (firstDiffLabel->getCheckedState()) return 0;
	if (secondDiffLabel->getCheckedState()) return 1;
	return 0;
}

thread_graph_data *ComparisonBox::get_graph(int idx)
{
	if (idx == 1) return graph1;
	if (idx == 2) return graph2;
	return 0;
}

void ComparisonBox::setDiffGraph(thread_graph_data *graph) {
	int graphIdx = getSelectedDiff();
	stringstream graphText;
	graphText << "[Thread " << std::to_string(graphIdx + 1) << "] PID:" << graph->pid << " TID:" << graph->tid;

	stringstream threadSummary;
	threadSummary << "Edges:" << graph->edgeList.size()
		<< "Verts:" << graph->get_num_verts();

	if (graphIdx == 0)
	{
		firstDiffLabel->setText(graphText.str());
		firstDiffLabel->resizeToContents();
		graph1 = graph;
		graph1Path->setText(graph->modPath);
		graph1Info->setText(threadSummary.str());
	}
	else 
	{
		secondDiffLabel->setText(graphText.str());
		secondDiffLabel->resizeToContents();
		graph2 = graph;
		graph2Path->setText(graph->modPath);
		graph2Info->setText(threadSummary.str());
	}

	if (graph1 && graph2)
		if (graph1 != graph2)
		{
			//int similarityScore = IMPLEMENT_ME(graph1, graph2);
			//set comparison label

			diffBtn->setEnabled(true); 
			diffBtn->setBackColor(agui::Color(200, 200, 200));
			return;
		}

	diffBtn->setEnabled(false);
	diffBtn->setBackColor(agui::Color(128, 128, 128)); 
	return;
}

void TraceVisGUI::showHideDiffFrame() {
	diffWindow->diffFrame->setVisibility(!diffWindow->diffFrame->isVisible());
}

ComparisonBox::ComparisonBox(agui::Gui *widgets, VISSTATE *clientState) {
	int paneHeight = 400;
	diffFrame = new agui::Frame;
	diffFrame->setSize(480, paneHeight);
	diffFrame->setLocation(200, 300);
	diffFrame->setText("Select threads to compare->");
	diffFrame->setVisibility(false);
	widgets->add(diffFrame);

	agui::Label *selectLabel = new agui::Label;
	selectLabel->setText("Click graphs from preview pane to compare");
	selectLabel->setLocation(10, 20);
	selectLabel->resizeToContents();
	diffFrame->add(selectLabel);

	diffFont = agui::Font::load("VeraSe.ttf", 22);
	firstDiffLabel = new agui::RadioButton;
	firstDiffLabel->setLocation(10, 70);
	firstDiffLabel->setFont(diffFont);
	firstDiffLabel->setText("Select Thread 1");
	firstDiffLabel->resizeToContents();
	firstDiffLabel->setChecked(true);
	diffFrame->add(firstDiffLabel);

	graph1Path = new agui::Label;
	graph1Path->setLocation(DIFF_INFOLABEL_X_OFFSET, 100);
	diffFrame->add(graph1Path);
	graph1Info = new agui::Label;
	graph1Info->setLocation(DIFF_INFOLABEL_X_OFFSET, 120);
	diffFrame->add(graph1Info);
	

	secondDiffLabel = new agui::RadioButton;
	secondDiffLabel->setLocation(10, 200);
	secondDiffLabel->setFont(diffFont);
	secondDiffLabel->setText("Select Thread 2");
	secondDiffLabel->resizeToContents();
	diffFrame->add(secondDiffLabel);

	graph2Path = new agui::Label;
	graph2Path->setLocation(DIFF_INFOLABEL_X_OFFSET, 230);
	diffFrame->add(graph2Path);
	graph2Info = new agui::Label;
	graph2Info->setLocation(DIFF_INFOLABEL_X_OFFSET, 250);
	diffFrame->add(graph2Info);


	RadioButtonListener *radiolisten = new RadioButtonListener(clientState,firstDiffLabel,secondDiffLabel);
	firstDiffLabel->addActionListener(radiolisten);
	secondDiffLabel->addActionListener(radiolisten);

	diffBtn = new agui::Button();
	diffBtn->setText("Compare");
	diffBtn->setEnabled(false);
	diffBtn->setLocation(170, paneHeight - 75);
	diffBtn->setSize(100, 40);
	diffBtn->setBackColor(agui::Color(210, 210, 210));
	
	CompareButtonListener *compareBtn = new CompareButtonListener(clientState);
	diffBtn->addActionListener(compareBtn);
	diffFrame->add(diffBtn);
}

void TraceVisGUI::updateRenderWidgets(thread_graph_data *graph) {
	controlWindow->update(graph);
	widgets->render();
}

void TraceVisGUI::widgetSetup() {

	//agui::Image::setImageLoader(new agui::Allegro5ImageLoader);
	agui::Font::setFontLoader(new agui::Allegro5FontLoader);
	//Instance the input handler
	widgetInputHandler = new agui::Allegro5Input();
	widgetGraphicsHandler = new agui::Allegro5Graphics();
	widgets = new agui::Gui();
	
	agui::Font *defaultFont = agui::Font::load("VeraSe.ttf", 14);
	agui::Widget::setGlobalFont(defaultFont);

	widgets->setGraphics(widgetGraphicsHandler);
	widgets->setInput(widgetInputHandler);

	int framex = clientState->size.width - PREVIEW_PANE_WIDTH + PREV_THREAD_X_PAD;
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
	dropDownWidget->setSize(80, 25);
	dropDownWidget->setText("Select PID");
	DropDownListener *dropListen = new DropDownListener(clientState);
	dropDownWidget->addActionListener(dropListen);

	//cache glyphs
	dropDownWidget->addItem("0123456789 ");
	dropDownWidget->removeItemAt(0);

	diffWindow = new ComparisonBox(widgets, clientState);
	controlWindow = new AnimControls(widgets, clientState);
}

ALLEGRO_DISPLAY* displaySetup() {

	if (!al_init()) {
		fprintf(stderr, "failed to initialize allegro!\n");
		return NULL;
	}

	al_set_new_window_position(100, 100);
	al_set_new_display_flags(ALLEGRO_OPENGL | ALLEGRO_WINDOWED | ALLEGRO_RESIZABLE);
	al_set_new_display_option(ALLEGRO_DEPTH_SIZE, 16, ALLEGRO_SUGGEST);

	ALLEGRO_DISPLAY *display = al_create_display(STARTWWIDTH, STARTWHEIGHT);
	if (!display) {
		fprintf(stderr, "failed to create display!\n");
		return NULL;
	}

	return display;
}

void updateTitle(ALLEGRO_DISPLAY *display, TITLE *title) {
	if (!title) return;

	snprintf(title->title, 255, "TraceVis. Mouse:(%s) Zoom:(%s) %s FPS: %s [%s]", title->MPos, title->zoom, title->Primitives, title->FPS, title->dbg);
	al_set_window_title(display, title->title);
}

GUI_DATA *init_GUI_Colours()
{
	GUI_DATA *guidata = new GUI_DATA;
	guidata->lineColoursArr.insert(guidata->lineColoursArr.begin() + ICALL, al_col_purple);
	guidata->lineColoursArr.insert(guidata->lineColoursArr.begin() + IOLD, al_col_white);
	guidata->lineColoursArr.insert(guidata->lineColoursArr.begin() + IRET, al_col_orange);
	guidata->lineColoursArr.insert(guidata->lineColoursArr.begin() + ILIB, al_col_green);
	guidata->lineColoursArr.insert(guidata->lineColoursArr.begin() + INEW, al_col_yellow);
	return guidata;
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
	snprintf(clientstate->title->Primitives, 35, "[TID:%d V:%d/E:%d]", graph->tid, verts,edges);
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
	stringstream infotxt;
	ALLEGRO_COLOR textcol;

	PID_DATA *piddata = clientState->activePid;
	if (piddata->active)
		textcol = al_col_white;
	else
		textcol = al_col_red;

	int activeModule = clientState->activeGraph->get_vert(0)->nodeMod;
	infotxt << piddata->modpaths[activeModule];
	infotxt << " (PID: " << piddata->PID << ")" << " (TID: " << clientState->activeGraph->tid << ")";

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
		{ "&Heatmap", EV_BTN_HEATMAP, 0, NULL },
		{ "&Conditionals", EV_BTN_CONDITION, 0, NULL },
		{ "&Preview", EV_BTN_PREVIEW, 0, NULL },
		{ "&Diff", EV_BTN_DIFF, 0, NULL },

		ALLEGRO_START_OF_MENU("Settings", 3),
		{ "Instruction Stepping", EV_BTN_STEPPING, 0, NULL },
		{ "Other setting", 5, 0, NULL },
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