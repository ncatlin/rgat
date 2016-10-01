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
Handles the animation control widgets
*/

#include "animControls.h"
#include "thread_trace_reader.h"

void AnimControls::notifyAnimFinished()
{
	setAnimState(ANIM_INACTIVE);
}

void AnimControls::setAnimState(int newAnimState)
{
	if (clientState->activePid && clientState->activePid->is_running())
		killBtn->setVisibility(true);
	else
		killBtn->setVisibility(false);

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
			cerr << "[rgat] Animation selection error"<<endl;
	}
	animationState = newAnimState;

	if (newAnimState == ANIM_LIVE)
	{
		//connectBtn->setVisibility(true);
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
		backJumpBtn->setToolTipText("Unimplemented");
		//backStepBtn->setVisibility(true); //disabled while unimplemented
		forwardStepBtn->setVisibility(true);
		forwardStepBtn->setToolTipText("Step animation forward by one");
		forwardJumpBtn->setVisibility(true);
		playBtn->setText("Play");

		stepText->setVisibility(true);

		clientState->animationUpdate = 0;
		clientState->modes.animation = false;
		//connectBtn->setVisibility(false);

		pauseBtn->setVisibility(false);
		playBtn->setVisibility(true);
	}

	else if (newAnimState == ANIM_REPLAY)
	{
		backStepBtn->setVisibility(false);
		backJumpBtn->setVisibility(true);
		backJumpBtn->setToolTipText("Decrease animation speed");
		forwardStepBtn->setVisibility(true);
		forwardStepBtn->setToolTipText("Skip loop");
		forwardJumpBtn->setVisibility(true);
		forwardJumpBtn->setToolTipText("Increase animation speed");
		playBtn->setVisibility(true);
		playBtn->setText("Stop");

		stepText->setVisibility(true);
		//connectBtn->setVisibility(false);

		clientState->animationUpdate = std::stoi(this->stepText->getText());
		clientState->modes.animation = true;

		pauseBtn->setVisibility(true);
		pauseBtn->setText("Pause");
		pauseBtn->setSize(90, forwardStepBtn->getHeight());
	}

}

void AnimControls::displayBacklog(thread_graph_data *graph)
{
	pair <unsigned long, unsigned long> sizePair;
	thread_trace_reader *reader = (thread_trace_reader*)graph->getReader();
	bool processingBuf1 = reader->getBufsState(&sizePair);
	unsigned long totalBacklog = sizePair.first + sizePair.second;

	bool showBacklog = graph->active || totalBacklog;
	backlogLayout->setVisibility(showBacklog);
	if (!showBacklog) return;

	unsigned long bufferMax = clientState->config->traceBufMax;

	double bufFullness = fmin(totalBacklog / (double)bufferMax, 1.0);
	
	int redShade = 255 - (int)(bufFullness * 255);

	backlogLabel->setFontColor(agui::Color(255, redShade, redShade));

	string readString;
	if (bufFullness == 1.0)
		readString = "Reading Paused";
	else
		readString = "Reading " + to_string(graph->getBacklogIn()) + "/s";

	string processedString = "Processing " + to_string(graph->getBacklogOut()) + "/s";

	readLabel->setText(readString);
	doneLabel->setText(processedString);
	backlogLabel->setText("Backlog: "+to_string(totalBacklog));
}

void AnimControls::update(thread_graph_data *graph)
{
	if (graph->active)
		displayBacklog(graph);

	if (graph->basic) 
	{ 
		controlsLayout->setVisibility(false);
		statusLabel->setText("Displaying basic graph");
		return; 
	}
	else
		controlsLayout->setVisibility(true);


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

	if (graph->loopCounter)//loops exist
	{
		if (graph->animLoopStartIdx) //in loop
		{
			if (!graph->active)
				skipBtn->setVisibility(true);
			stepInfo << "Iteration " << graph->loopIteration << "/" << graph->targetIterations << " of ";
		}
		else
			skipBtn->setVisibility(false);

		if (!graph->active)
			stepInfo << graph->loopsPlayed << "/";
		stepInfo << graph->loopCounter << " loops";
	}

	statusLabel->setText(stepInfo.str());

	if (graph->active)
	{
		if (clientState->modes.animation)
			pauseBtn->setText("Structure");
		else
			pauseBtn->setText("Activity");
	}
	else
	{
		backlogLayout->setVisibility(false);
		if (clientState->modes.animation)
			pauseBtn->setText("Pause");
		else
			pauseBtn->setText("Continue");
	}
}

void AnimControls::fitToResize()
{
	scrollbar->setLocation(clientState->displaySize.width - PREV_SCROLLBAR_WIDTH, 50);
	scrollbar->setSize(PREV_SCROLLBAR_WIDTH, clientState->displaySize.height - 50);
	mouseLayout->setLocation(clientState->displaySize.width - PREVIEW_PANE_WIDTH, 30);
	controlsLayout->setLocation(15, clientState->displaySize.height - 40);
	labelsLayout->setLocation(15, clientState->displaySize.height - (CONTROLS_Y - 5));
	
	backlogLayout->setLocation(clientState->mainFrameSize.width - BACKLOG_X_OFFSET,
		clientState->mainFrameSize.height - 60);

}

void AnimControls::CreateBufLayout()
{
	backlogLayout = new agui::FlowLayout();
	backlogLayout->setTopToBottom(true);
	backlogLayout->setSingleRow(false);
	backlogLayout->setMaxOnRow(1);

	readLabel = new agui::Label();
	readLabel->setFont(btnFont);
	readLabel->setSize(100, 30);
	readLabel->setBackColor(agui::Color(0, 0, 0));
	readLabel->setFontColor(agui::Color(255, 255, 255));
	backlogLayout->add(readLabel);

	backlogLabel = new agui::Label();
	backlogLabel->setFont(btnFont);
	backlogLabel->setFontColor(agui::Color(255, 255, 255));
	backlogLabel->resizeToContents();
	backlogLayout->add(backlogLabel);

	doneLabel = new agui::Label();
	doneLabel->setFont(btnFont);
	doneLabel->setFontColor(agui::Color(255, 255, 255));
	backlogLayout->add(doneLabel);

	backlogLayout->setLocation(clientState->mainFrameSize.width - BACKLOG_X_OFFSET,
		clientState->mainFrameSize.height - backlogLayout->getHeight() - 10);

	backlogLayout->resizeToContents();
	backlogLayout->setVisibility(false);
	guiwidgets->add(backlogLayout);
}

AnimControls::AnimControls(agui::Gui *widgets, VISSTATE *cstate, agui::Font *font) 
{
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

	statusLabel = new agui::Label();
	statusLabel->setFont(btnFont);
	statusLabel->setFontColor(agui::Color(210, 210, 210));
	statusLabel->setText("Waiting for target");
	statusLabel->resizeToContents();
	statusLabel->setBackColor(agui::Color(0, 0, 210));
	statusLabel->setVisibility(true);
	statusLabel->setEnabled(true);
	labelsLayout->add(statusLabel);

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

	killBtn = new agui::Button();
	killBtn->setFont(btnFont);
	killBtn->setText("Kill");
	killBtn->setMargins(0, 8, 0, 8);
	killBtn->setBackColor(agui::Color(210, 210, 210));
	killBtn->resizeToContents();
	killBtn->setSize(killBtn->getWidth(), btnHeight);
	killBtn->setVisibility(false);
	controlsLayout->add(killBtn);

	pauseBtn = new agui::Button();
	pauseBtn->setFont(btnFont);
	pauseBtn->setText("Structure");
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
	//connectBtn->addActionListener(btnListen);
	backStepBtn->addActionListener(btnListen);
	backJumpBtn->addActionListener(btnListen);
	forwardStepBtn->addActionListener(btnListen);
	forwardJumpBtn->addActionListener(btnListen);
	playBtn->addActionListener(btnListen);
	pauseBtn->addActionListener(btnListen);
	skipBtn->addActionListener(btnListen);
	killBtn->addActionListener(btnListen);

	scrollbar = new agui::VScrollBar;
	scrollbar->setSize(PREV_SCROLLBAR_WIDTH, clientState->displaySize.height - 50);
	scrollbar->setLocation(clientState->displaySize.width - PREV_SCROLLBAR_WIDTH, 50);
	scrollbar->setMaxValue(0);
	widgets->add(scrollbar);

	CreateBufLayout();

}
