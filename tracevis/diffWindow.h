#pragma once
#include "GUIStructs.h"
#include <Agui/Agui.hpp>
#include <Agui/Backends/Allegro5/Allegro5.hpp>
#include "Agui\Widgets\DropDown\DropDown.hpp"
#include "Agui\Widgets\Label\Label.hpp"
#include "Agui\Widgets\RadioButton\RadioButton.hpp"
#include "Agui\Widgets\Frame\Frame.hpp"

#define DIFF_INFOLABEL_X_OFFSET 25

class RadioButtonListener : public agui::ActionListener
{
public:
	RadioButtonListener(VISSTATE *state, agui::RadioButton *s1, agui::RadioButton *s2);
	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		if (evt.getSource() == source1)
			source2->setChecked(!source1->getRadioButtonState());
		else {
			if (evt.getSource() == source2)
				source1->setChecked(!source2->getRadioButtonState());
		}
	}
private:
	VISSTATE *clientState;
	agui::RadioButton *source1;
	agui::RadioButton *source2;
};

class CompareButtonListener : public agui::ActionListener
{
public:
	CompareButtonListener(VISSTATE *state) { clientState = state; }
	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		clientState->modes.diff = DIFF_SELECTED;
	}
private:
	VISSTATE *clientState;
};

class DiffSelectionFrame {
public:
	DiffSelectionFrame(agui::Gui *widgets, VISSTATE *clientState, agui::Font *font);
	agui::RadioButton *firstDiffLabel;
	agui::RadioButton *secondDiffLabel;
	//todo make class for this
	agui::Frame *diffFrame = NULL;
	agui::Font *diffFont;

	agui::Button *diffBtn;

	int getSelectedDiff();
	void setDiffGraph(thread_graph_data *graph);
	thread_graph_data *get_graph(int idx);

private:
	agui::Label *graph1Info = 0;
	agui::Label *graph1Path = 0;
	agui::Label *graph2Info = 0;
	agui::Label *graph2Path = 0;
	thread_graph_data *graph1 = 0;
	thread_graph_data *graph2 = 0;
};