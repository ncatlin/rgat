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
#include "plotted_graph.h"
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

	void refreshData();
	void updateHighlightNodes(HIGHLIGHT_DATA *highlightData, proto_graph *graph, PROCESS_DATA* activePid);
	agui::Frame *highlightFrame = NULL;
	agui::DropDown *symbolDropdown;
	agui::DropDown *moduleDropdown;
	agui::TextField *addressText;
	bool staleData() { return (GetTickCount64() > (lastRefresh + HIGHLIGHT_REFRESH_DELAY_MS)); }

private:
	agui::Label *addressLabel;
	agui::Button *addressBtn;

	agui::Label *symbolLabel;
	agui::Button *symbolBtn;

	agui::Label *moduleLabel;
	agui::Button *moduleBtn;

	agui::Label *exceptionLabel;
	agui::Button *exceptionBtn;
	
	agui::Font *highlightFont;
	DWORD64 lastRefresh = 0;

	unsigned int lastSymCount = 0;
	unsigned int lastExceptionCount = 0;
	VISSTATE *clientState;
};

#define HL_REFRESH_BTN 0
#define HL_HIGHLIGHT_ADDRESS 1
#define HL_HIGHLIGHT_SYM 2
#define HL_HIGHLIGHT_MODULE 3
#define HL_HIGHLIGHT_EXCEPTIONS 4
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

		plotted_graph * graph = (plotted_graph *)clientState->activeGraph;
		HIGHLIGHT_DATA *highlightData = &graph->highlightData;
		switch (id)
		{
		case HL_HIGHLIGHT_ADDRESS:
			{
				if (!clientState->activePid) break;
				string address_s = hl_frame->addressText->getText();
				if (!caught_stoul(address_s, &highlightData->highlightAddr, 16)) break;
				hl_frame->highlightFrame->setVisibility(false);
				if (clientState->activePid->disassembly.count(highlightData->highlightAddr))
					highlightData->highlightState = HL_HIGHLIGHT_ADDRESS;
				else
					highlightData->highlightState = 0;
				break;
			}
		case HL_HIGHLIGHT_SYM:
			{
				if (hl_frame->symbolDropdown->getSelectedIndex() < 0) break;
				hl_frame->highlightFrame->setVisibility(false);
				
				highlightData->highlight_s = hl_frame->symbolDropdown->getText();
				highlightData->highlightState = HL_HIGHLIGHT_SYM;
				break; 
			}

		case HL_HIGHLIGHT_MODULE:
			{
				if (hl_frame->moduleDropdown->getSelectedIndex() < 0) break;
				hl_frame->highlightFrame->setVisibility(false);
				highlightData->highlightModule = hl_frame->moduleDropdown->getSelectedIndex();
				highlightData->highlightState = HL_HIGHLIGHT_MODULE;
				break; 
			}

		case HL_HIGHLIGHT_EXCEPTIONS:
			{
				hl_frame->highlightFrame->setVisibility(false);
				highlightData->highlightState = HL_HIGHLIGHT_EXCEPTIONS;
				break;
			}
		}

		hl_frame->updateHighlightNodes(highlightData, graph->get_protoGraph(), clientState->activePid);
	}

private:
	VISSTATE *clientState;
	int id;
	HighlightSelectionFrame *hl_frame;
};