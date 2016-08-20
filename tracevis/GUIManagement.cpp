#include "stdafx.h"
#include "GUIConstants.h"
#include "GUIManagement.h"

class AnimButtonListener : public agui::ActionListener
{
public:
	AnimButtonListener(AnimControls *mycontrols, int *stateAddress, VISSTATE *state)
	{ controls = mycontrols; animState = stateAddress; clientState = state;}

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		//dunno if there is a builtin ID value for buttons instead of doing this
		//todo: if not it's worth adding
		int currentState = *animState;

		string btntext = evt.getSource()->getText();
		if (btntext == "Stop" || btntext == "Play")
		{
			if (currentState == ANIM_LIVE || currentState == ANIM_REPLAY)
				controls->setAnimState(ANIM_INACTIVE);
			else
				controls->setAnimState(ANIM_ACTIVATED);
		}

		//one step forward
		if (btntext == ">")
		{
			if (currentState == ANIM_INACTIVE)
				clientState->animationUpdate = 1;
			return;
		}

		if (btntext == "Skip")
		{
			clientState->skipLoop = true;
			return;
		}

		//one step back
		if (btntext == "<")
		{
			if (currentState == ANIM_INACTIVE)
				clientState->animationUpdate = -1;
			return;
		}

		if (btntext == "Stop")
		{
			clientState->animationUpdate = 0;
			clientState->modes.animation = false;
			clientState->activeGraph->reset_animation();
			evt.getSource()->setText("Play");
			return;
		}

		if (btntext == "Pause")
		{
			evt.getSource()->setText("Continue");
			evt.getSource()->setSize(115, evt.getSource()->getHeight());
			clientState->modes.animation = false;
			return;
		}

		int quantity = std::stoi(controls->stepText->getText());
		if (btntext == "Continue")
		{
			clientState->animationUpdate = quantity;
			clientState->modes.animation = true;
			evt.getSource()->setText("Pause");
			evt.getSource()->setSize(90, evt.getSource()->getHeight());
			return;
		}

		if (btntext == "Disconnect")
		{
			printf("Disconnect");
			return;
		}

		
		
		if (btntext == ">>")
		{
			if (currentState == ANIM_INACTIVE)
			{
				clientState->animationUpdate = quantity;
			}
			else if (currentState == ANIM_REPLAY)
			{
				quantity++;
				controls->stepText->setText(to_string(quantity));
				clientState->animationUpdate = quantity;
			}
			return;
		}

		if (btntext == "<<")
		{
			if (currentState == ANIM_INACTIVE)
			{
				clientState->animationUpdate = -quantity;
			}
			else if (currentState == ANIM_REPLAY)
			{
				if (quantity == 0) return;
				quantity--;
				controls->stepText->setText(to_string(quantity));
				clientState->animationUpdate = quantity;
			}
			return;
		}	
	}
private:
	AnimControls *controls;
	int *animState;
	VISSTATE *clientState;
};

void AnimControls::notifyAnimFinished()
{
	setAnimState(ANIM_INACTIVE);
}

void AnimControls::setAnimState(int newAnimState)
{
	if (newAnimState == animationState) return;
	if (animationState == ANIM_INACTIVE && newAnimState == ANIM_ACTIVATED)
	{
		if (!clientState->activeGraph->active)
		{
			newAnimState = ANIM_REPLAY;
			clientState->animationUpdate = std::stoi(this->stepText->getText());
			clientState->modes.animation = true;
		}
		else
			printf("How did we get here?\n");
	}
	animationState = newAnimState;

	if (newAnimState == ANIM_LIVE)
	{
		connectBtn->setVisibility(true);
		pauseBtn->setVisibility(true);
		backJumpBtn->setVisibility(false);
		backStepBtn->setVisibility(false);
		forwardStepBtn->setVisibility(false);
		forwardJumpBtn->setVisibility(false);
		playBtn->setVisibility(false);
		stepText->setVisibility(false);

	}

	if (newAnimState == ANIM_INACTIVE)
		{
			backJumpBtn->setVisibility(true);
			backStepBtn->setVisibility(true);
			forwardStepBtn->setVisibility(true);
			forwardStepBtn->setToolTipText("Step animation forward by one");
			forwardJumpBtn->setVisibility(true);
			playBtn->setText("Play");
			
			stepText->setVisibility(true);
			
			clientState->animationUpdate = 0;
			clientState->modes.animation = false;
			connectBtn->setVisibility(false);
			pauseBtn->setVisibility(false);
			playBtn->setVisibility(true);
		}

	else if (newAnimState == ANIM_REPLAY)
	{
		backStepBtn->setVisibility(false);
		backJumpBtn->setVisibility(true);
		forwardStepBtn->setVisibility(true);
		forwardStepBtn->setToolTipText("Skip loop");
		forwardJumpBtn->setVisibility(true);
		playBtn->setVisibility(true);
		playBtn->setText("Stop");
		

		stepText->setVisibility(true);
		connectBtn->setVisibility(false);

		clientState->animationUpdate = std::stoi(this->stepText->getText());
		clientState->modes.animation = true;
		

		pauseBtn->setVisibility(true);
		pauseBtn->setText("Pause");
		pauseBtn->setSize(90,forwardStepBtn->getHeight());
	}
	
}

void AnimControls::update(thread_graph_data *graph)
{
	if (!graph->active && animationState == ANIM_LIVE)
		setAnimState(ANIM_INACTIVE);

	stringstream stepInfo;
	//if (clientState->stepBBs)
	//	stepInfo << graph->sequenceIndex+1 << "/" << graph->bbsequence.size() << " basic blocks. ";
	//else

	stepInfo << graph->animInstructionIndex << "/";
	if (graph->totalInstructions < 10000)
		stepInfo << graph->totalInstructions-1 << " instructions. ";
	else if (graph->totalInstructions < 1000000)
		stepInfo << (graph->totalInstructions - 1)/1000 << "K instructions. ";
	else
		stepInfo << (graph->totalInstructions - 1)/1000000 << "M instructions. ";

	if (graph->loopCounter)
	{
		if (graph->animLoopStartIdx)
		{
			if(!graph->active)
				skipBtn->setVisibility(true);
			stepInfo << "Iteration " << graph->loopIteration << "/" << graph->targetIterations << " of ";
		}
		else
			skipBtn->setVisibility(false);

		if (!graph->active)stepInfo << graph->loopsPlayed << "/";
		stepInfo << graph->loopCounter << " loops";
	}


	//todo: can crash here
	stepsLabel->setText(stepInfo.str());
}

AnimControls::AnimControls(agui::Gui *widgets, VISSTATE *cstate) {
	guiwidgets = widgets;
	clientState = cstate;
	btnFont = agui::Font::load("VeraSe.ttf", 22);

	labelsLayout = new agui::FlowLayout;

	stepsLabel = new agui::Label();
	stepsLabel->setFont(btnFont);
	stepsLabel->setFontColor(agui::Color(210, 210, 210));
	stepsLabel->setText("x Steps total");
	stepsLabel->resizeToContents();
	stepsLabel->setBackColor(agui::Color(0, 0, 210));
	stepsLabel->setVisibility(true);
	stepsLabel->setEnabled(true);
	labelsLayout->add(stepsLabel);

	labelsLayout->resizeToContents();
	labelsLayout->setLocation(15, clientState->size.height - (CONTROLS_Y+15));
	labelsLayout->setHorizontalSpacing(10);
	labelsLayout->setBackColor(agui::Color(0, 0, 210));
	labelsLayout->setOpacity(1);
	widgets->add(labelsLayout);



	controlsLayout = new agui::FlowLayout;
	
	

	backStepBtn = new agui::Button();
	backStepBtn->setFont(btnFont);
	backStepBtn->setText("<");
	backStepBtn->resizeToContents();
	backStepBtn->setBackColor(agui::Color(210, 210, 210));
	backStepBtn->setToolTipText("Step animation back by one");
	controlsLayout->add(backStepBtn);

	forwardStepBtn = new agui::Button();
	forwardStepBtn->setFont(btnFont);
	forwardStepBtn->setText(">");
	forwardStepBtn->resizeToContents();
	forwardStepBtn->setBackColor(agui::Color(210, 210, 210));
	forwardStepBtn->setToolTipText("Step animation forward by one");
	controlsLayout->add(forwardStepBtn);

	int btnHeight = forwardStepBtn->getHeight();

	backJumpBtn = new agui::Button();
	backJumpBtn->setFont(btnFont);
	backJumpBtn->setText("<<");
	backJumpBtn->resizeToContents();
	backJumpBtn->setBackColor(agui::Color(210, 210, 210));
	backJumpBtn->setToolTipText("Jump animation back by specified steps");
	controlsLayout->add(backJumpBtn);

	stepText = new agui::TextField();
	stepText->setText("1");
	stepText->setSize(70, btnHeight);
	stepText->setNumeric(true);
	controlsLayout->add(stepText);

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
	playBtn->setSize(80, btnHeight);
	playBtn->setBackColor(agui::Color(210, 210, 210));
	controlsLayout->add(playBtn);

	connectBtn = new agui::Button();
	connectBtn->setFont(btnFont);
	connectBtn->setText("Disconnect");
	connectBtn->setMargins(0, 8, 0, 8);
	connectBtn->setBackColor(agui::Color(210, 210, 210));
	connectBtn->resizeToContents();
	connectBtn->setSize(connectBtn->getWidth(), btnHeight);
	controlsLayout->add(connectBtn);

	pauseBtn = new agui::Button();
	pauseBtn->setFont(btnFont);
	pauseBtn->setText("Pause");
	pauseBtn->setToolTipText("Pause replay");
	pauseBtn->setMargins(0, 8, 0, 8);
	pauseBtn->setBackColor(agui::Color(210, 210, 210));
	pauseBtn->setVisibility(true);
	pauseBtn->setSize(90, btnHeight);
	controlsLayout->add(pauseBtn);


	skipBtn = new agui::Button();
	skipBtn->setFont(btnFont);
	skipBtn->setText("Skip");
	skipBtn->setToolTipText("Skip Loop");
	skipBtn->setMargins(0, 8, 0, 8);
	skipBtn->setBackColor(agui::Color(210, 210, 210));
	skipBtn->setVisibility(false);
	skipBtn->setSize(65, btnHeight);
	controlsLayout->add(skipBtn);

	controlsLayout->resizeToContents();
	controlsLayout->setLocation(15, clientState->size.height - playBtn->getHeight()*2.2);
	controlsLayout->setHorizontalSpacing(10);
	widgets->add(controlsLayout);

	animationState = -1;

	AnimButtonListener *btnListen = new AnimButtonListener(this, &animationState, clientState);
	connectBtn->addActionListener(btnListen);
	backStepBtn->addActionListener(btnListen);
	backJumpBtn->addActionListener(btnListen);
	forwardStepBtn->addActionListener(btnListen);
	forwardJumpBtn->addActionListener(btnListen);
	playBtn->addActionListener(btnListen);
	pauseBtn->addActionListener(btnListen);
	skipBtn->addActionListener(btnListen);

	scrollbar = new agui::VScrollBar;
	scrollbar->setSize(SCROLLBAR_WIDTH, clientState->size.height-20);
	scrollbar->setLocation(clientState->size.width - SCROLLBAR_WIDTH, 0);
	widgets->add(scrollbar);
}

RadioButtonListener::RadioButtonListener(VISSTATE *state, agui::RadioButton *s1, agui::RadioButton *s2)
{
	source1 = s1;
	source2 = s2;
	clientState = state; 
}

void TraceVisGUI::addPID(int PID) {
	string pidstring = " "+std::to_string(PID);
	//todo: crash here?
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

void TraceVisGUI::showToolTip(thread_graph_data *graph, int x, int y) {
	printf("show tooltip pid %d tid %d (%d,%d)\n", graph->pid, graph->tid,x,y);
	tippy->setLocation(x, y);
	tippy->show();
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

	tippy = new agui::ToolTip();
	tippy->setFont(defaultFont);
	tippy->setSize(400, 100);
	widgets->add(tippy);
	widgets->setToolTip(tippy);
	widgets->setHoverInterval(0.1);


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
	if (!clientState->activeGraph->get_num_verts())
	{
		printf("ERROR NO VERTS in summary activegraph\n"); return;
	}
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

	al_draw_filled_rectangle(0, 0, clientState->size.width, 32, al_map_rgba(0, 0, 0, 255));
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