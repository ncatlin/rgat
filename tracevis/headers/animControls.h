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

#pragma once
#include "stdafx.h"
#include "GUIStructs.h"
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
#include "Agui\Widgets\Slider\Slider.hpp"
#include "Agui\Widgets\Slider\SliderListener.hpp"

#define CONTROLS_Y 80
#define ANIM_INACTIVE 0
#define ANIM_LIVE 1
#define ANIM_REPLAY 2
#define ANIM_ACTIVATED 3
#define PREVIEW_GRAPH_Y_OFFSET 12
#define BACKLOG_X_OFFSET 150
#define SLIDER_MAXVAL 1000.0

class AnimControls {
public:
	AnimControls(agui::Gui *widgets, VISSTATE *cState, agui::Font *font);
	void setAnimState(int animState);
	bool isEnabled() { return enableState; }
	void update(thread_graph_data *graph);
	void notifyAnimFinished();
	void setScrollbarVisible(bool enabled) { previewVScroll->setVisibility(enabled); }
	void setScrollbarMax(int val) { previewVScroll->setMaxValue(val);}

	agui::VScrollBar getScrollbar() { return previewVScroll; }
	
	int getScroll() { return previewVScroll->getValue(); }
	int getSpeed();
	void setSlider(int val) { animHSlide->setValue(val); }

	void doScroll(int z) {
		if (z > 0) previewVScroll->scrollUp();
		else previewVScroll->scrollDown();
	}

	//call when client windows gets resized
	void fitToResize();
	void setStatusLabel(string msg) { statusLabel->setText(msg); };
	bool ignoreSliderChange = false;

private:
	agui::FlowLayout *mouseLayout = NULL;
	agui::FlowLayout *controlsLayout = NULL;
	agui::FlowLayout *labelsLayout = NULL;
	agui::Button *killBtn = NULL;
	agui::Button *playBtn = NULL;
	agui::Button *pauseBtn = NULL;
	agui::VScrollBar *previewVScroll = NULL;
	agui::DropDown *speedSelect = NULL;
	agui::Slider *animHSlide = NULL;

	agui::FlowLayout *backlogLayout = NULL;
	agui::Label *readLabel = NULL;
	agui::Label *doneLabel = NULL;
	agui::Label *backlogLabel = NULL;

	agui::Font *btnFont;
	agui::Label *statusLabel;
	bool enableState = true;
	agui::Gui *guiwidgets;
	VISSTATE *clientState;
	int animationState = -1;

	void CreateBufLayout();
	void displayBacklog(thread_graph_data *graph);
};

class AnimButtonListener : public agui::ActionListener
{
public:
	AnimButtonListener(AnimControls *mycontrols, int *stateAddress, VISSTATE *state)
	{
		controls = mycontrols; animState = stateAddress; clientState = state;
	}

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		//dunno if there is a builtin ID value for buttons instead of doing this
		//todo: if not it's worth adding
		int currentState = *animState;

		string btntext = evt.getSource()->getText();
		if (btntext == "Stop" || btntext == "Play")
		{
			if (clientState->modes.diff)
				clientState->modes.diff = false;
			if (currentState == ANIM_LIVE || currentState == ANIM_REPLAY)
				controls->setAnimState(ANIM_INACTIVE);
			else
				controls->setAnimState(ANIM_ACTIVATED);
		}

		if (btntext == "Stop")
		{
			clientState->animationUpdate = 0;
			clientState->modes.animation = false;
			clientState->activeGraph->terminated = true;
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

		if (btntext == "Structure")
		{
			evt.getSource()->setText("Animation");
			evt.getSource()->setSize(115, evt.getSource()->getHeight());
			clientState->modes.animation = false;
			return;
		}

		if (btntext == "Activity")
		{
			clientState->animationUpdate = controls->getSpeed();
			clientState->modes.animation = true;
			evt.getSource()->setText("Structure");
			evt.getSource()->setSize(90, evt.getSource()->getHeight());
			return;
		}

		if (btntext == "Continue")
		{
			clientState->animationUpdate = controls->getSpeed();
			clientState->modes.animation = true;
			evt.getSource()->setText("Pause");
			evt.getSource()->setSize(90, evt.getSource()->getHeight());
			return;
		}

		if (btntext == "Kill")
		{
			clientState->activePid->kill();
			return;
		}

	}
private:
	AnimControls *controls;
	int *animState;
	VISSTATE *clientState;
};

class PrevScrollBarMouseListener : public agui::MouseListener
{
public:
	PrevScrollBarMouseListener(AnimControls *mycontrols, VISSTATE *state, agui::VScrollBar *sb)
	{
		controls = mycontrols; clientState = state; scrollbar = sb;
	}

	void mouseClickCB(agui::MouseEvent &evt) 
	{
		int clickY = evt.getY();
		int scrollBarMidY = scrollbar->getHeight() / 2;
		if (clickY > scrollBarMidY)
			scrollbar->scrollDown();
		else
			scrollbar->scrollUp();
	}
private:
	agui::VScrollBar *scrollbar;
	AnimControls *controls;
	VISSTATE *clientState;
};

class HSliderMouseListener : public agui::SliderListener
{
public:
	HSliderMouseListener(AnimControls *mycontrols, VISSTATE *state, agui::Slider *sb)
	{
		controls = mycontrols; clientState = state; scrollbar = sb;
	}

	void valueChanged(agui::Slider* source, int value)
	{
		if (controls->ignoreSliderChange)
		{
			controls->ignoreSliderChange = false;
			return;
		}

		float newVal = source->getValue();
		float maxVal = source->getMaxValue();
		clientState->activeGraph->userSelectedAnimPosition = (unsigned long)(clientState->activeGraph->getAnimDataSize()*(newVal / maxVal));
	}

private:
	agui::Slider *scrollbar;
	AnimControls *controls;
	VISSTATE *clientState;
	int lastX =-1;
};

class speedDropListener : public agui::ActionListener
{
public:
	speedDropListener(VISSTATE *state, AnimControls *acontrols) { clientState = state; controls = acontrols; }
	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		clientState->animationUpdate = controls->getSpeed();
	}
private:
	VISSTATE *clientState;
	AnimControls *controls;
};