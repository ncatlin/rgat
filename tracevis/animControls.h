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

#define CONTROLS_Y 80
#define ANIM_INACTIVE 0
#define ANIM_LIVE 1
#define ANIM_REPLAY 2
#define ANIM_ACTIVATED 3
#define PREVIEW_GRAPH_Y_OFFSET 12

class AnimControls {
public:
	AnimControls(agui::Gui *widgets, VISSTATE *cState, agui::Font *font);
	void setAnimState(int animState);
	bool isEnabled() { return enableState; }
	void update(thread_graph_data *graph);
	void notifyAnimFinished();
	void setScrollbarVisible(bool enabled) { scrollbar->setVisibility(enabled); }
	void setScrollbarMax(int val) { scrollbar->setMaxValue(val); }
	agui::VScrollBar getScrollbar() { return scrollbar; }
	int getScroll() { return scrollbar->getValue(); }
	agui::TextField *stepText = NULL;
	void doScroll(int z) {
		if (z > 0) scrollbar->scrollUp();
		else
			scrollbar->scrollDown();
		printf("scroll val:%d / max %d\n", getScroll(), scrollbar->getMaxValue());
	}

private:
	agui::FlowLayout *controlsLayout = NULL;
	agui::FlowLayout *labelsLayout = NULL;
	agui::Button *connectBtn = NULL;
	agui::Button *backJumpBtn = NULL;
	agui::Button *backStepBtn = NULL;
	agui::Button *forwardStepBtn = NULL;
	agui::Button *forwardJumpBtn = NULL;
	agui::Button *playBtn = NULL;
	agui::Button *pauseBtn = NULL;
	agui::Button *skipBtn = NULL;
	agui::VScrollBar *scrollbar = NULL;

	agui::Font *btnFont;
	agui::Label *stepsLabel;
	bool enableState = true;
	agui::Gui *guiwidgets;
	VISSTATE *clientState;
	int animationState = -1;
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