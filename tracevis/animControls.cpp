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

#define ANIM_SCROLL_X 320

void AnimControls::setAnimState(int newAnimState)
{
	if (clientState->activePid && clientState->activePid->is_running())
		killBtn->setVisibility(true);
	else
		killBtn->setVisibility(false);

	if (newAnimState == animationState) return;

	if (animationState == ANIM_INACTIVE && newAnimState == ANIM_ACTIVATED)
	{
		//start replay
		if (!clientState->activeGraph->active)
		{
			newAnimState = ANIM_REPLAY;
			clientState->animationUpdate = getSpeed();
			clientState->modes.animation = true;
			stringstream logentry;
			logentry << "Replay of " << clientState->activeGraph->modPath << " PID:" <<
				clientState->activePid->PID << " TID:" << clientState->activeGraph->tid << " started." << endl;
			al_append_native_text_log(clientState->textlog, logentry.str().c_str());
		}
		else
			cerr << "[rgat] Animation selection error" << endl;
	}
	animationState = newAnimState;

	if (newAnimState == ANIM_LIVE)
	{
		pauseBtn->setVisibility(true);
		playBtn->setVisibility(false);
		animHSlide->setVisibility(false);
		speedSelect->setVisibility(false);
	}

	if (newAnimState == ANIM_INACTIVE)
	{
		playBtn->setText("Play");

		clientState->animationUpdate = 0;
		clientState->modes.animation = false;
		clientState->activeGraph->terminated = true;

		pauseBtn->setVisibility(false);
		playBtn->setVisibility(true);

		speedSelect->setVisibility(true);

		animHSlide->setVisibility(true);
		int scrollX = ANIM_SCROLL_X;
		int scrollWidth = (int)floor((clientState->mainFrameSize.width - scrollX)*(2.0 / 3.0));

		animHSlide->setSize(scrollWidth, 20);
		animHSlide->setLocation(scrollX, playBtn->getAbsolutePosition().getY() + 2);
		ignoreSliderChange = true;

		setSlider(0);
	}

	else if (newAnimState == ANIM_REPLAY)
	{
		playBtn->setVisibility(true);
		playBtn->setText("Stop");
		playBtn->setToolTipText("Reset animation");

		clientState->animationUpdate = getSpeed();
		clientState->modes.animation = true;
		

		speedSelect->setVisibility(true);

		animHSlide->setVisibility(true);
		int scrollX = ANIM_SCROLL_X;
		int scrollWidth = (int)floor((clientState->mainFrameSize.width - scrollX)*(2.0 / 3.0));
		animHSlide->setSize(scrollWidth, 20);
		animHSlide->setLocation(scrollX, playBtn->getAbsolutePosition().getY()+2);
		ignoreSliderChange = true;

		setSlider((int)((float)1000 * clientState->activeGraph->getAnimationPercent()));

		pauseBtn->setVisibility(true);
		pauseBtn->setText("Pause");
		pauseBtn->setSize(90, playBtn->getHeight());
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
		
	if (graph->vertResizeIndex)
	{
		statusLabel->setText("(Rescaling graph...)");
		return;
	}

	controlsLayout->setVisibility(true);

	if (!graph->active && animationState == ANIM_LIVE)
		setAnimState(ANIM_INACTIVE);

	stringstream stepInfo;

	if (!graph->active)
	{

		/*
		//ruined by skipping using replay slider
		//could implement by adding current instruction count to every animation update in trace
		//but not sure if worth the extra file size

		if (graph->animInstructionIndex < 10000)
			stepInfo << graph->animInstructionIndex - 1;
		else if (graph->animInstructionIndex < 1000000)
			stepInfo << (graph->animInstructionIndex - 1) / 1000 << "K";
		else
			stepInfo << (graph->animInstructionIndex - 1) / 1000000 << "M";

		stepInfo << " / ";
		*/

		float animPercent = graph->getAnimationPercent();
		if (animPercent)
		{
			ALLEGRO_MOUSE_STATE mstate;
			al_get_mouse_state(&mstate);
			if (mstate.y < clientState->mainFrameSize.height || !mstate.buttons)
			{
				int newVal = (int)(SLIDER_MAXVAL * animPercent);
				ignoreSliderChange = true;
				setSlider(newVal);
			}
		}
	}
	if (graph->totalInstructions < 10000)
		stepInfo << graph->totalInstructions - 1 << " instructions. ";
	else if (graph->totalInstructions < 1000000)
		stepInfo << (graph->totalInstructions - 1) / 1000 << "K instructions. ";
	else
		stepInfo << (graph->totalInstructions - 1) / 1000000 << "M instructions. ";

	statusLabel->setText(stepInfo.str());

	if (graph->active)
	{
		if (clientState->modes.animation)
			pauseBtn->setText("Structure");
		else
			pauseBtn->setText("Activity");
		killBtn->setVisibility(true);
	}
	else
	{
		killBtn->setVisibility(false);
		backlogLayout->setVisibility(false);
		if (clientState->modes.animation)
			pauseBtn->setText("Pause");
		else
			pauseBtn->setText("Continue");
	}
}

int AnimControls::getSpeed()
{
	return (1 << speedSelect->getSelectedIndex());
}

void AnimControls::fitToResize()
{
	previewVScroll->setLocation(clientState->displaySize.width - PREV_SCROLLBAR_WIDTH, 50);
	previewVScroll->setSize(PREV_SCROLLBAR_WIDTH, clientState->displaySize.height - 50);
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


	playBtn = new agui::Button();
	playBtn->setFont(btnFont);
	playBtn->setText("Play");
	playBtn->setToolTipText("Replay animation");
	playBtn->setMargins(0, 8, 0, 8);
	playBtn->setSize(80, 25);
	playBtn->setBackColor(agui::Color(210, 210, 210));
	controlsLayout->add(playBtn);

	int btnHeight = playBtn->getHeight();

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

	speedSelect = new agui::DropDown;
	speedSelect->setText("Replay Speed");
	speedSelect->addItem("0.5x");
	speedSelect->addItem("1x");
	speedSelect->addItem("2x");
	speedSelect->addItem("4x");
	speedSelect->addItem("8x");
	speedSelect->addItem("16x");
	speedSelect->addItem("32x");
	speedSelect->addItem("64x");
	speedSelect->addItem("128x");
	speedSelect->setSelectedIndex(0);
	speedSelect->resizeToContents();
	speedSelect->setSize(speedSelect->getWidth(), pauseBtn->getHeight());
	speedSelect->setToolTipText("Replay speed");
	speedSelect->setVisibility(false);
	controlsLayout->add(speedSelect);

	speedDropListener *dropListen = new speedDropListener(clientState, this);
	speedSelect->addActionListener(dropListen);

	controlsLayout->resizeToContents();
	controlsLayout->setLocation(15, clientState->displaySize.height - playBtn->getHeight()*3);
	controlsLayout->setHorizontalSpacing(10);
	widgets->add(controlsLayout);

	animationState = -1;

	AnimButtonListener *btnListen = new AnimButtonListener(this, &animationState, clientState);
	playBtn->addActionListener(btnListen);
	pauseBtn->addActionListener(btnListen);
	killBtn->addActionListener(btnListen);

	previewVScroll = new agui::VScrollBar;
	previewVScroll->setSize(PREV_SCROLLBAR_WIDTH, clientState->displaySize.height - 50);
	previewVScroll->setLocation(clientState->displaySize.width - PREV_SCROLLBAR_WIDTH, 50);
	previewVScroll->setMaxValue(0);
	PrevScrollBarMouseListener *sbmlPrev = new PrevScrollBarMouseListener(this, clientState, previewVScroll);
	previewVScroll->addMouseListener(sbmlPrev);
	widgets->add(previewVScroll);

	animHSlide = new agui::Slider;
	animHSlide->setMinValue(0);
	animHSlide->setMaxValue((int)SLIDER_MAXVAL);
	animHSlide->setVisibility(false);
	HSliderMouseListener *sbmlAnim = new HSliderMouseListener(this, clientState, animHSlide);
	animHSlide->addSliderListener(sbmlAnim);
	widgets->add(animHSlide);

	CreateBufLayout();

}
