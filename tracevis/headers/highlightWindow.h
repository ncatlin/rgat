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
The class for the highlight selection dialog
*/

#pragma once
#include "GUIStructs.h"
#include <Agui/Agui.hpp>
#include <Agui/Backends/Allegro5/Allegro5.hpp>
#include "Agui\Widgets\DropDown\DropDown.hpp"
#include "Agui\Widgets\Label\Label.hpp"
#include "Agui\Widgets\RadioButton\RadioButton.hpp"
#include "Agui\Widgets\Frame\Frame.hpp"
#include "Agui\Widgets\TextField\TextField.hpp"

class HighlightSelectionFrame {
public:
	HighlightSelectionFrame(agui::Gui *widgets, VISSTATE *state, agui::Font *font);

	void refreshDropdowns();
	void updateHighlightNodes(HIGHLIGHT_DATA *highlightData, thread_graph_data *graph, PROCESS_DATA* activePid);
	agui::Frame *highlightFrame = NULL;
	agui::DropDown *symbolDropdown;
	agui::DropDown *moduleDropdown;
	agui::TextField *addressText;

private:
	agui::Label *addressLabel;
	agui::Button *addressBtn;

	agui::Label *symbolLabel;
	agui::Button *symbolBtn;

	agui::Label *moduleLabel;
	agui::Button *moduleBtn;
	
	agui::Font *highlightFont;

	int lastModCount = 0;
	int lastSymCount = 0;
	VISSTATE *clientState;
};

#define HL_REFRESH_BTN 0
#define HL_HIGHLIGHT_ADDRESS 1
#define HL_HIGHLIGHT_SYM 2
#define HL_HIGHLIGHT_MODULE 3
class highlightButtonListener : public agui::ActionListener
{
public:
	highlightButtonListener(VISSTATE *state, int btnid, HighlightSelectionFrame *frame) { 
		clientState = state; id = btnid; hl_frame = frame; }

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		if (evt.getSource()->getText() == "Close")
		{
			hl_frame->highlightFrame->setVisibility(false);
			return;
		}

		switch (id)
		{
		case HL_REFRESH_BTN:
			{
			hl_frame->refreshDropdowns();
			break;
			}
		case HL_HIGHLIGHT_ADDRESS:
			{
				string address_s = hl_frame->addressText->getText();
				if (!caught_stoul(address_s, &clientState->highlightData.highlightAddr, 16)) break;
				hl_frame->highlightFrame->setVisibility(false);
				if (clientState->activePid->disassembly.count(clientState->highlightData.highlightAddr))
					clientState->highlightData.highlightState = HL_HIGHLIGHT_ADDRESS;
				else
					clientState->highlightData.highlightState = 0;
				break;
			}
		case HL_HIGHLIGHT_SYM:
			{
				if (hl_frame->symbolDropdown->getSelectedIndex() < 0) break;
				hl_frame->highlightFrame->setVisibility(false);
				
				clientState->highlightData.highlight_s = hl_frame->symbolDropdown->getText();
				clientState->highlightData.highlightState = HL_HIGHLIGHT_SYM;
				break; 
			}

		case HL_HIGHLIGHT_MODULE:
			{
				if (hl_frame->moduleDropdown->getSelectedIndex() < 0) break;
				hl_frame->highlightFrame->setVisibility(false);
				clientState->highlightData.highlightModule = hl_frame->moduleDropdown->getSelectedIndex();
				clientState->highlightData.highlightState = HL_HIGHLIGHT_MODULE;
				break; 
			}
		}
		hl_frame->updateHighlightNodes(&clientState->highlightData,
			clientState->activeGraph,
			clientState->activePid);
	}

private:
	VISSTATE *clientState;
	int id;
	HighlightSelectionFrame *hl_frame;
};