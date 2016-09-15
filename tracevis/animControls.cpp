#include "animControls.h"

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
		printf("\t\tpause visible!\n");
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

		printf("\t\tpause invisible!\n");
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
		printf("\t\tpause visible!\n");
		pauseBtn->setText("Pause");
		pauseBtn->setSize(90, forwardStepBtn->getHeight());
	}

}

void AnimControls::update(thread_graph_data *graph)
{
	if (!graph->active && animationState == ANIM_LIVE)
		setAnimState(ANIM_INACTIVE);

	stringstream stepInfo;

	stepInfo << graph->animInstructionIndex << "/";
	if (graph->totalInstructions < 10000)
		stepInfo << graph->totalInstructions - 1 << " instructions. ";
	else if (graph->totalInstructions < 1000000)
		stepInfo << (graph->totalInstructions - 1) / 1000 << "K instructions. ";
	else
		stepInfo << (graph->totalInstructions - 1) / 1000000 << "M instructions. ";

	if (graph->loopCounter)
	{
		if (graph->animLoopStartIdx)
		{
			if (!graph->active)
				skipBtn->setVisibility(true);
			stepInfo << "Iteration " << graph->loopIteration << "/" << graph->targetIterations << " of ";
		}
		else
			skipBtn->setVisibility(false);

		if (!graph->active)stepInfo << graph->loopsPlayed << "/";
		stepInfo << graph->loopCounter << " loops";
	}

	stepsLabel->setText(stepInfo.str());
}

void AnimControls::fitToResize()
{
	scrollbar->setLocation(clientState->displaySize.width - PREV_SCROLLBAR_WIDTH, 50);
	scrollbar->setSize(PREV_SCROLLBAR_WIDTH, clientState->displaySize.height - 50);
	mouseLayout->setLocation(clientState->displaySize.width - PREVIEW_PANE_WIDTH, 30);
	controlsLayout->setLocation(15, clientState->displaySize.height - 40);
	labelsLayout->setLocation(15, clientState->displaySize.height - (CONTROLS_Y - 5));
}

AnimControls::AnimControls(agui::Gui *widgets, VISSTATE *cstate, agui::Font *font) {
	guiwidgets = widgets;
	clientState = cstate;
	btnFont = font;

	labelsLayout = new agui::FlowLayout;

	//agui seems to need a widget under the mouse to display a tooltip
	//so we put an invisible pane over the previews
	mouseLayout = new agui::FlowLayout;
	mouseLayout->setSize(PREVIEW_PANE_WIDTH, clientState->displaySize.height - 30);
	mouseLayout->setLocation(clientState->displaySize.width - PREVIEW_PANE_WIDTH, 30);
	widgets->add(mouseLayout);

	stepsLabel = new agui::Label();
	stepsLabel->setFont(btnFont);
	stepsLabel->setFontColor(agui::Color(210, 210, 210));
	stepsLabel->setText("Waiting for target");
	stepsLabel->resizeToContents();
	stepsLabel->setBackColor(agui::Color(0, 0, 210));
	stepsLabel->setVisibility(true);
	stepsLabel->setEnabled(true);
	labelsLayout->add(stepsLabel);

	labelsLayout->resizeToContents();
	labelsLayout->setLocation(15, clientState->displaySize.height - (CONTROLS_Y - 5));
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
	controlsLayout->setLocation(15, clientState->displaySize.height - playBtn->getHeight()*3);
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
	scrollbar->setSize(PREV_SCROLLBAR_WIDTH, clientState->displaySize.height - 50);
	scrollbar->setLocation(clientState->displaySize.width - PREV_SCROLLBAR_WIDTH, 50);
	widgets->add(scrollbar);
}
