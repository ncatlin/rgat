#pragma once

#include "GUIStructs.h"
#include <Agui/Agui.hpp>
#include <Agui/Backends/Allegro5/Allegro5.hpp>
#include "Agui\Widgets\DropDown\DropDown.hpp"
#include "Agui\Widgets\Label\Label.hpp"
#include "Agui\Widgets\RadioButton\RadioButton.hpp"
#include "Agui\Widgets\Frame\Frame.hpp"
#include "Agui\Widgets\TextField\TextField.hpp"
#include "Agui\Widgets\Slider\Slider.hpp"
#include "Agui\Widgets\Slider\SliderListener.hpp"

#define INSRADIO_NONE 1
#define INSRADIO_AUTO 2
#define INSRADIO_ALL 3
#define EXTRADIO_INTERNAL 4
#define EXTRADIO_EXTERNAL 5
#define EXTRADIO_ALL 6
#define EXTRADIO_NAMES 7
#define EXTRADIO_PATHS 8
#define EXTRADIO_NONE 9
#define HEATRADIO_NODE 10
#define HEATRADIO_EDGE 11 
#define HEATRADIO_NONE 12

class TextRadioListener : public agui::ActionListener
{
public:
	TextRadioListener(VISSTATE *state, void *txtdiag) {
		clientState = state;
		txtBoxPtr = txtdiag;
	}

	void actionPerformed(const agui::ActionEvent &evt);


private:
	VISSTATE *clientState;
	void *txtBoxPtr;
};

class textDialog
{
public:
	textDialog(agui::Gui *widgets, VISSTATE *state, agui::Font *font);
	~textDialog();

	void createInsTextRadios(agui::Font *font, int X, int Y, TextRadioListener *radiolisten);
	void createRadios_symVerbosity(agui::Font *font, int X, int Y, TextRadioListener *radiolisten);
	void createRadios_symLocation(agui::Font *font, int X, int Y, TextRadioListener *radiolisten);
	void createHeatTextRadios(agui::Font *font, int X, int Y, TextRadioListener *radiolisten);
	void createFontSlider(agui::Font *font, int X, int Y);
	void toggle() { textFrame->isVisible() ? textFrame->hide() : textFrame->show(); }

	agui::Frame *textFrame = NULL;
	VISSTATE *clientState;

	vector <agui::Label *> labelPtrs;

	agui::RadioButton *insTextRadio_Auto;
	agui::RadioButton *insTextRadio_All;
	agui::RadioButton *insTextRadio_None;
	agui::RadioButton *externTextRadio_Names;
	agui::RadioButton *externTextRadio_Paths;
	agui::RadioButton *externTextRadio_None;
	agui::RadioButton *externTextRadio_Internal;
	agui::RadioButton *externTextRadio_External;
	agui::RadioButton *externTextRadio_All;
	agui::RadioButton *heatTextRadio_Node;
	agui::RadioButton *heatTextRadio_Edge;
	agui::RadioButton *heatTextRadio_None;

	agui::Label *fontPtBox = NULL;
	agui::Slider *fontSlider = NULL;
};



class textButtonListener : public agui::ActionListener
{
public:
	textButtonListener(VISSTATE *state, textDialog *frame) {
		clientState = state; txt_frame = frame;
	}

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		if (evt.getSource()->getText() == "X")
		{
			txt_frame->textFrame->setVisibility(false);
			clientState->dialogOpen = false;
			return;
		}
	}
private:
	VISSTATE *clientState;
	textDialog *txt_frame;
};

class FontSliderMouseListener : public agui::SliderListener
{
public:
	FontSliderMouseListener(VISSTATE *state, agui::Slider *sb, agui::Label *txt)
	{
		clientState = state; scrollbar = sb; txtBox = txt;
	}

	void valueChanged(agui::Slider* source, int value)
	{

		float newVal = source->getValue();
		cout << "changed font size to " << newVal << endl;
		string newValstr = to_string(int(floor(newVal)));
		txtBox->setText(newValstr);
		float maxVal = source->getMaxValue();
	}

private:
	agui::Slider *scrollbar;
	agui::Label *txtBox;
	VISSTATE *clientState;
	int lastX = -1;
};