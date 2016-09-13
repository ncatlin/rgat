#include "stdafx.h"
#include "exeWindow.h"





#define EXEFRAME_W 500
#define EXEFRAME_H 300
#define EXETEXT_W 350
#define EXETEXT_X 60
exeWindow::exeWindow(agui::Gui *widgets, VISSTATE *state, agui::Font *font)
{
	clientState = state;
	guiWidgets = widgets;

	exeFrame = new agui::Frame;
	exeFrame->setSize(EXEFRAME_W, EXEFRAME_H);
	exeFrame->setLocation(100, 100);

	widgets->add(exeFrame);
	filePathLabel = new agui::Label;
	filePathLabel->setText("Target of execution:");
	filePathLabel->resizeToContents();
	filePathLabel->setLocation(10, 40);
	exeFrame->add(filePathLabel);

	filePathTxt = new agui::TextField;
	filePathTxt->setSize(EXETEXT_W, 25);
	filePathTxt->setLocation(EXETEXT_X, 40);
	filePathTxt->setWantHotkeys(true);
	filePathTxt->setSelectable(true);
	filePathTxt->setReadOnly(false);
	filePathTxt->setBlinking(true);
	filePathTxt->setEnabled(true);
	exeFrame->add(filePathTxt);

	filePathBtn = new agui::Button;
	filePathBtn->setText("Open"); //TODO: file icon
	filePathBtn->setSize(50, 25);
	filePathBtn->setLocation(EXETEXT_X + EXETEXT_W +10, 40);
	exeFrame->add(filePathBtn);

	fileButtonListener *btnListener1 = new fileButtonListener(state, this);
	filePathBtn->addActionListener(btnListener1);
	exeFrame->setVisibility(false);

	agui::Dimension CBSize;
	CBSize.setHeight(20);
	CBSize.setWidth(20);

	nonGraphicalCB = new agui::CheckBox;
	nonGraphicalCB->setText("Disable Rendering");
	nonGraphicalCB->setCheckBoxSize(CBSize);
	nonGraphicalCB->resizeToContents();
	nonGraphicalCB->setLocation(40, 90);
	nonGraphicalCB->setToolTipText("Disable graph drawing - useful for low-spec VMs.\nSave the graph to render it elsewhere.");
	exeFrame->add(nonGraphicalCB);

	hideVMCB = new agui::CheckBox;
	hideVMCB->setText("Anti-Redpill");
	hideVMCB->setCheckBoxSize(CBSize);
	hideVMCB->resizeToContents();
	hideVMCB->setLocation(40, 130);
	hideVMCB->setToolTipText("[Experimental] Change results of VM detection instructions to hide virtualisation");
	exeFrame->add(hideVMCB);

	hideSleepCB = new agui::CheckBox;
	hideSleepCB->setText("Anti-Sleep");
	hideSleepCB->setCheckBoxSize(CBSize);
	hideSleepCB->resizeToContents();
	hideSleepCB->setLocation(40, 160);
	hideSleepCB->setToolTipText("[Experimental] Change sleep() calls and timer results to reduce pauses and hide slowdown");
	exeFrame->add(hideSleepCB);

	launchBtn = new agui::Button;
	launchBtn->setText("Launch");
	launchBtn->resizeToContents();
	launchBtn->setLocation(exeFrame->getWidth()/2 - launchBtn->getWidth()/2, 220);
	launchButtonListener *btnListener2 = new launchButtonListener(state, this);
	launchBtn->addActionListener(btnListener2);
	exeFrame->add(launchBtn);
}


exeWindow::~exeWindow()
{
}
