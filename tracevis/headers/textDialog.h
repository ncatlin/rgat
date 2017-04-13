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

enum textRadioOption { INSRADIO_NONE, INSRADIO_AUTO, INSRADIO_ALL, EXTRADIO_INTERNAL, EXTRADIO_EXTERNAL,
	EXTRADIO_ALL, EXTRADIO_NAMES, EXTRADIO_PATHS, EXTRADIO_ADDRESS, EXTRADIO_NONE, HEATRADIO_NODE, HEATRADIO_EDGE, HEATRADIO_NONE };

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
	~textDialog() {};

	void createInsTextRadios(agui::Font *font, int X, int Y, TextRadioListener *radiolisten);
	void createRadios_symVerbosity(agui::Font *font, int X, int Y, TextRadioListener *radiolisten);
	void createRadios_symLocation(agui::Font *font, int X, int Y, TextRadioListener *radiolisten);
	void createHeatTextRadios(agui::Font *font, int X, int Y, TextRadioListener *radiolisten);
	void createFontSlider(agui::Font *font, int X, int Y);
	void toggle() { textFrame->isVisible() ? clientState->closeFrame(textFrame) : clientState->openFrame(textFrame); }

	agui::Frame *textFrame = NULL;
	VISSTATE *clientState;

	vector <agui::Label *> labelPtrs;

	agui::RadioButton *insTextRadio_Auto, *insTextRadio_All, *insTextRadio_None;
	agui::RadioButton *externTextRadio_Names, *externTextRadio_Paths, *externTextRadio_Addresses, *externTextRadio_None;
	agui::RadioButton *externTextRadio_Internal, *externTextRadio_External, *externTextRadio_All;
	agui::RadioButton *heatTextRadio_Node, *heatTextRadio_Edge, *heatTextRadio_None;

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
			clientState->closeFrame(txt_frame->textFrame);
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

		int newVal = int(source->getValue());
		cout << "changed font size to " << newVal << endl;
		string newValstr = to_string(newVal);
		txtBox->setText(newValstr);
		clientState->setInstructionFontSize(newVal);
	}

private:
	agui::Slider *scrollbar;
	agui::Label *txtBox;
	VISSTATE *clientState;
	int lastX = -1;
};