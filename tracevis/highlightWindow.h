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
	agui::Label *addressLabel;
	agui::TextField *addressText;
	agui::Button *addressBtn;

	agui::Label *symbolLabel;
	agui::DropDown *symbolDropdown;
	agui::Button *symbolBtn;

	agui::Label *moduleLabel;
	agui::DropDown *moduleDropdown;
	agui::Button *moduleBtn;

	agui::Frame *highlightFrame = NULL;
	agui::Font *highlightFont;
	void refreshDropdowns();

private:
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
				unsigned long addr;
				if (!caught_stol(address_s, &addr, 16)) break;
				printf("initiating highlight of address %s->%lx\n", address_s.c_str(), addr);
				hl_frame->highlightFrame->setVisibility(false);
				break;
			}
		case HL_HIGHLIGHT_SYM:
			{
				if (hl_frame->symbolDropdown->getSelectedIndex() < 0) break;
				printf("initiating highlight of sym %s [%d]\n", hl_frame->symbolDropdown->getText().c_str(), hl_frame->symbolDropdown->getSelectedIndex());
				hl_frame->highlightFrame->setVisibility(false);
				break; 
			}

		case HL_HIGHLIGHT_MODULE:
			{
				if (hl_frame->moduleDropdown->getSelectedIndex() < 0) break;
				printf("initiating highlight of mod %s [%d]\n", hl_frame->moduleDropdown->getText().c_str(), hl_frame->moduleDropdown->getSelectedIndex());
				hl_frame->highlightFrame->setVisibility(false);
				break; 
			}
		}
	}
private:
	VISSTATE *clientState;
	int id;
	HighlightSelectionFrame *hl_frame;
};