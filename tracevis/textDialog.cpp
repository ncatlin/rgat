#include "stdafx.h"
#include "textDialog.h"
#include "Agui\Enumerations.hpp"

using namespace agui;

void textDialog::createInsTextRadios(agui::Font *font, int X, int Y, TextRadioListener *radiolisten)
{

	agui::Label *summaryLabel = new agui::Label;
	summaryLabel->setLocation(10, Y);
	summaryLabel->setText("Instruction text visibiity");
	summaryLabel->resizeToContents();
	textFrame->add(summaryLabel);
	labelPtrs.push_back(summaryLabel);

	int radioOffsetY = 20;
	int offsetX2 = 110;
	int offsetX3 = 2 * offsetX2;
	insTextRadio_Auto = new agui::RadioButton();
	insTextRadio_Auto->setText("Auto");
	insTextRadio_Auto->setLocation(X, Y + radioOffsetY);
	insTextRadio_Auto->setFont(font);
	insTextRadio_Auto->resizeToContents();
	insTextRadio_Auto->setWidgetID(INSRADIO_AUTO);
	insTextRadio_Auto->addActionListener(radiolisten);
	textFrame->add(insTextRadio_Auto);


	insTextRadio_All = new agui::RadioButton();
	insTextRadio_All->setText("Always");
	insTextRadio_All->setLocation(X + offsetX2, Y + radioOffsetY);
	insTextRadio_All->setFont(font);
	insTextRadio_All->resizeToContents();
	insTextRadio_All->setWidgetID(INSRADIO_ALL);
	insTextRadio_All->addActionListener(radiolisten);
	textFrame->add(insTextRadio_All);

	insTextRadio_None = new agui::RadioButton();
	insTextRadio_None->setText("None");
	insTextRadio_None->setLocation(X + offsetX3, Y + radioOffsetY);
	insTextRadio_None->setFont(font);
	insTextRadio_None->resizeToContents();
	insTextRadio_None->setWidgetID(INSRADIO_NONE);
	insTextRadio_None->addActionListener(radiolisten);
	textFrame->add(insTextRadio_None);

	switch (clientState->modes.show_ins_text)
	{
	case eInsTextAuto:
		insTextRadio_Auto->setChecked(true);
		insTextRadio_All->setChecked(false);
		insTextRadio_None->setChecked(false);
		break;

	case eInsTextForced:
		insTextRadio_Auto->setChecked(false);
		insTextRadio_All->setChecked(true);
		insTextRadio_None->setChecked(false);
		break;

	case eInsTextOff:
		insTextRadio_Auto->setChecked(false);
		insTextRadio_All->setChecked(false);
		insTextRadio_None->setChecked(true);
		break;
	}
}

void textDialog::createRadios_symVerbosity(agui::Font *font, int X, int Y, TextRadioListener *radiolisten)
{
	agui::Label *summaryLabel = new agui::Label;
	summaryLabel->setLocation(10, Y);
	summaryLabel->setText("Symbol labels");
	summaryLabel->resizeToContents();
	textFrame->add(summaryLabel);
	labelPtrs.push_back(summaryLabel);

	int radioOffsetY = 20;
	int offsetX2 = 110;
	int offsetX3 = 2 * offsetX2;

	externTextRadio_Names = new agui::RadioButton();
	externTextRadio_Names->setText("Names");
	externTextRadio_Names->setLocation(X, Y + radioOffsetY);
	externTextRadio_Names->setFont(font);
	externTextRadio_Names->resizeToContents();
	externTextRadio_Names->setWidgetID(EXTRADIO_NAMES);
	externTextRadio_Names->addActionListener(radiolisten);
	textFrame->add(externTextRadio_Names);

	externTextRadio_Paths = new agui::RadioButton();
	externTextRadio_Paths->setText("Paths");
	externTextRadio_Paths->setLocation(X + offsetX2, Y + radioOffsetY);
	externTextRadio_Paths->setFont(font);
	externTextRadio_Paths->resizeToContents();
	externTextRadio_Paths->setWidgetID(EXTRADIO_PATHS);
	externTextRadio_Paths->addActionListener(radiolisten);
	textFrame->add(externTextRadio_Paths);

	externTextRadio_None = new agui::RadioButton();
	externTextRadio_None->setText("None");
	externTextRadio_None->setLocation(X + offsetX3, Y + radioOffsetY);
	externTextRadio_None->setFont(font);
	externTextRadio_None->resizeToContents();
	externTextRadio_None->setWidgetID(EXTRADIO_NONE);
	externTextRadio_None->addActionListener(radiolisten);
	textFrame->add(externTextRadio_None);


	switch (clientState->modes.show_symbol_verbosity)
	{
	case eSymboltextSymbols:
		externTextRadio_Names->setChecked(true);
		externTextRadio_Paths->setChecked(false);
		externTextRadio_None->setChecked(false);
		break;

	case eSymboltextPaths:
		externTextRadio_Paths->setChecked(false);
		externTextRadio_Paths->setChecked(true);
		externTextRadio_None->setChecked(false);
		break;

	case eSymboltextOff: 
		externTextRadio_None->setChecked(false);
		externTextRadio_Paths->setChecked(false);
		externTextRadio_None->setChecked(true);
		break;
	}
}

void textDialog::createRadios_symLocation(agui::Font *font, int X, int Y, TextRadioListener *radiolisten)
{
	agui::Label *summaryLabel = new agui::Label;
	summaryLabel->setLocation(10, Y);
	summaryLabel->setText("Symbol sources");
	summaryLabel->resizeToContents();
	textFrame->add(summaryLabel);
	labelPtrs.push_back(summaryLabel);

	int radioOffsetY = 20;
	int offsetX2 = 110;
	int offsetX3 = 2 * offsetX2;

	externTextRadio_Internal = new agui::RadioButton();
	externTextRadio_Internal->setText("Internal");
	externTextRadio_Internal->setLocation(X, Y + radioOffsetY);
	externTextRadio_Internal->setFont(font);
	externTextRadio_Internal->resizeToContents();
	externTextRadio_Internal->setWidgetID(EXTRADIO_INTERNAL);
	externTextRadio_Internal->addActionListener(radiolisten);
	textFrame->add(externTextRadio_Internal);

	externTextRadio_External = new agui::RadioButton();
	externTextRadio_External->setText("External");
	externTextRadio_External->setLocation(X + offsetX2, Y + radioOffsetY);
	externTextRadio_External->setFont(font);
	externTextRadio_External->resizeToContents();
	externTextRadio_External->setWidgetID(EXTRADIO_EXTERNAL);
	externTextRadio_External->addActionListener(radiolisten);
	textFrame->add(externTextRadio_External);

	externTextRadio_All = new agui::RadioButton();
	externTextRadio_All->setText("All");
	externTextRadio_All->setLocation(X + offsetX3, Y + radioOffsetY);
	externTextRadio_All->setFont(font);
	externTextRadio_All->resizeToContents();
	externTextRadio_All->setWidgetID(EXTRADIO_ALL);
	externTextRadio_All->addActionListener(radiolisten);
	textFrame->add(externTextRadio_All);

	switch (clientState->modes.show_symbol_location)
	{
	case eSymboltextAll:
		externTextRadio_All->setChecked(true);
		externTextRadio_External->setChecked(false);
		externTextRadio_Internal->setChecked(false);
		break;

	case eSymboltextExternal:
		externTextRadio_All->setChecked(false);
		externTextRadio_External->setChecked(true);
		externTextRadio_Internal->setChecked(false);
		break;

	case eSymboltextInternal:
		externTextRadio_All->setChecked(false);
		externTextRadio_External->setChecked(false);
		externTextRadio_Internal->setChecked(true);
		break;
	}
}

void textDialog::createHeatTextRadios(agui::Font *font, int X, int Y, TextRadioListener *radiolisten)
{
	
	agui::Label *summaryLabel = new agui::Label;
	summaryLabel->setLocation(10, Y);
	summaryLabel->setText("Heatmap heat display");
	summaryLabel->resizeToContents();
	textFrame->add(summaryLabel);
	labelPtrs.push_back(summaryLabel);

	int radioOffsetY = 20;
	int offsetX2 = 110;
	int offsetX3 = 2 * offsetX2;

	heatTextRadio_Node = new agui::RadioButton();
	heatTextRadio_Node->setText("Node");
	heatTextRadio_Node->setLocation(X, Y + radioOffsetY);
	heatTextRadio_Node->setFont(font);
	heatTextRadio_Node->resizeToContents();
	heatTextRadio_Node->setWidgetID(HEATRADIO_NODE);
	heatTextRadio_Node->addActionListener(radiolisten);
	textFrame->add(heatTextRadio_Node);

	heatTextRadio_Edge = new agui::RadioButton();
	heatTextRadio_Edge->setText("Edge");
	heatTextRadio_Edge->setLocation(X + offsetX2, Y + radioOffsetY);
	heatTextRadio_Edge->setFont(font);
	heatTextRadio_Edge->resizeToContents();
	heatTextRadio_Edge->setWidgetID(HEATRADIO_EDGE);
	heatTextRadio_Edge->addActionListener(radiolisten);
	textFrame->add(heatTextRadio_Edge);

	heatTextRadio_None = new agui::RadioButton();
	heatTextRadio_None->setText("None");
	heatTextRadio_None->setLocation(X + offsetX3, Y + radioOffsetY);
	heatTextRadio_None->setFont(font);
	heatTextRadio_None->resizeToContents();
	heatTextRadio_None->setWidgetID(HEATRADIO_NONE);
	heatTextRadio_None->addActionListener(radiolisten);
	textFrame->add(heatTextRadio_None);

	switch (clientState->modes.show_heat_location)
	{
	case eHeatNodes:
		heatTextRadio_Node->setChecked(true);
		heatTextRadio_Edge->setChecked(false);
		heatTextRadio_None->setChecked(false);
		break;

	case eHeatEdges:
		heatTextRadio_Node->setChecked(false);
		heatTextRadio_Edge->setChecked(true);
		heatTextRadio_None->setChecked(false);
		break;

	case eHeatNone:
		heatTextRadio_Node->setChecked(false);
		heatTextRadio_Edge->setChecked(false);
		heatTextRadio_None->setChecked(true);
		break;
	}
}

void textDialog::createFontSlider(agui::Font *font, int X, int Y)
{
	agui::Label *summaryLabel = new agui::Label;
	summaryLabel->setLocation(10, Y);
	summaryLabel->setText("Font size:");
	summaryLabel->resizeToContents();
	textFrame->add(summaryLabel);
	labelPtrs.push_back(summaryLabel);

	fontSlider = new agui::Slider;
	fontSlider->setMinValue(3);
	fontSlider->setMaxValue(25);
	fontSlider->setValue(clientState->getInstructionFontSize());
	fontSlider->setLocation(X + 85, Y);
	fontSlider->setSize(160, 20);
	textFrame->add(fontSlider);

	fontPtBox = new agui::Label;
	fontPtBox->setLocation(X + 260, Y);
	fontPtBox->setSize(30, 20);
	fontPtBox->setText(to_string(fontSlider->getValue()));
	textFrame->add(fontPtBox);

	FontSliderMouseListener *fontSlideListen = new FontSliderMouseListener(clientState, fontSlider, fontPtBox);
	fontSlider->addSliderListener(fontSlideListen);


}

textDialog::textDialog(agui::Gui *widgets, VISSTATE *state, agui::Font *font)
{
	clientState = state;

	textFrame = new agui::Frame;
	textFrame->setSize(400, 350);
	textFrame->setLocation(200, 300);
	widgets->add(textFrame);
	textFrame->setVisibility(false);

	TextRadioListener *radiolisten = new TextRadioListener(clientState, this);

	int ysep = 55;
	int ypos = 15;
	createInsTextRadios(font, 18, ypos, radiolisten);
	ypos += ysep;
	createRadios_symVerbosity(font, 18, ypos, radiolisten);
	ypos += ysep;
	createRadios_symLocation(font, 18, ypos, radiolisten);
	ypos += ysep;
	createHeatTextRadios(font, 18, ypos, radiolisten);
	ypos += ysep;
	createFontSlider(font, 25, ypos);

	
	textButtonListener *textBtnListen = new textButtonListener(clientState, this);

	agui::Button *closeBtn = new agui::Button;
	closeBtn->setText("X");
	closeBtn->setMargins(2, 5, 2, 5);
	closeBtn->resizeToContents();
	closeBtn->setLocation(textFrame->getWidth() - closeBtn->getWidth() - 15, 5);
	closeBtn->addActionListener(textBtnListen);
	textFrame->add(closeBtn);

}

void TextRadioListener::actionPerformed(const agui::ActionEvent &evt)
{
	//called due to user selecting a graph, not clicking a radio button
	int sourceRadioID = evt.getSource()->getWidgetID();
	if (sourceRadioID < 0) { return; }

	textDialog *txtbox = (textDialog *)txtBoxPtr;

	switch (sourceRadioID)
	{
	case INSRADIO_NONE:
		clientState->modes.show_ins_text = eInsTextOff;
		txtbox->insTextRadio_None->setChecked(true);
		txtbox->insTextRadio_Auto->setChecked(false);
		txtbox->insTextRadio_All->setChecked(false);
		break;

	case INSRADIO_AUTO:
		clientState->modes.show_ins_text = eInsTextAuto;
		txtbox->insTextRadio_None->setChecked(false);
		txtbox->insTextRadio_Auto->setChecked(true);
		txtbox->insTextRadio_All->setChecked(false);
		break;

	case INSRADIO_ALL:
		clientState->modes.show_ins_text = eInsTextForced;
		txtbox->insTextRadio_None->setChecked(false);
		txtbox->insTextRadio_Auto->setChecked(false);
		txtbox->insTextRadio_All->setChecked(true);
		break;

	case EXTRADIO_INTERNAL:
		clientState->modes.show_symbol_location = eSymboltextInternal;
		txtbox->externTextRadio_Internal->setChecked(true);
		txtbox->externTextRadio_External->setChecked(false);
		txtbox->externTextRadio_None->setChecked(false);
		break;

	case EXTRADIO_EXTERNAL:
		clientState->modes.show_symbol_location = eSymboltextExternal;
		txtbox->externTextRadio_Internal->setChecked(false);
		txtbox->externTextRadio_External->setChecked(true);
		txtbox->externTextRadio_None->setChecked(false);
		break;

	case EXTRADIO_ALL:

		clientState->modes.show_symbol_location = eSymboltextAll;
		txtbox->externTextRadio_Internal->setChecked(false);
		txtbox->externTextRadio_External->setChecked(false);
		txtbox->externTextRadio_All->setChecked(true);
		break;

	case EXTRADIO_NAMES:
		clientState->modes.show_symbol_verbosity = eSymboltextSymbols;
		txtbox->externTextRadio_Names->setChecked(true);
		txtbox->externTextRadio_Paths->setChecked(false);
		txtbox->externTextRadio_None->setChecked(false);
		break;

	case EXTRADIO_PATHS:
		clientState->modes.show_symbol_verbosity = eSymboltextPaths;
		txtbox->externTextRadio_Names->setChecked(false);
		txtbox->externTextRadio_Paths->setChecked(true);
		txtbox->externTextRadio_None->setChecked(false);
		break;

	case EXTRADIO_NONE:
		clientState->modes.show_symbol_verbosity = eSymboltextOff;
		txtbox->externTextRadio_Names->setChecked(false);
		txtbox->externTextRadio_Paths->setChecked(false);
		txtbox->externTextRadio_None->setChecked(true);
		break;

	case HEATRADIO_NODE:
		clientState->modes.show_heat_location = eHeatNodes;
		txtbox->heatTextRadio_Node->setChecked(true);
		txtbox->heatTextRadio_Edge->setChecked(false);
		txtbox->heatTextRadio_None->setChecked(false);
		break;

	case HEATRADIO_EDGE:
		clientState->modes.show_heat_location = eHeatEdges;
		txtbox->heatTextRadio_Node->setChecked(false);
		txtbox->heatTextRadio_Edge->setChecked(true);
		txtbox->heatTextRadio_None->setChecked(false);
		break;

	case HEATRADIO_NONE:
		clientState->modes.show_heat_location = eHeatNone;
		txtbox->heatTextRadio_Node->setChecked(false);
		txtbox->heatTextRadio_Edge->setChecked(false);
		txtbox->heatTextRadio_None->setChecked(true);
		break;
	}
}
