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
The class for the executable launching dialog
*/
#include "stdafx.h"
#include "exeWindow.h"
#include "OSspecific.h"

#define EXEFRAME_W 500
#define EXEFRAME_H 300
#define EXETEXT_W 350
#define EXETEXT_X 60
#define EXETEXT_Y 50
#define OPTS_X 40
#define FEATURES_X 220
exeWindow::exeWindow(agui::Gui *widgets, VISSTATE *state, agui::Font *font)
{
	clientState = state;
	guiWidgets = widgets;

	exeFrame = new agui::Frame;
	exeFrame->setSize(EXEFRAME_W, EXEFRAME_H);
	exeFrame->setLocation(100, 100);
	widgets->add(exeFrame);

	agui::Label *title = new agui::Label;
	title->setText("Trace target selection");
	title->resizeToContents();
	title->setLocation(10, 10);
	exeFrame->add(title);

	agui::Label *filePathLabel = new agui::Label;
	filePathLabel->setText("File:");
	filePathLabel->resizeToContents();
	filePathLabel->setLocation(10, EXETEXT_Y+4);
	exeFrame->add(filePathLabel);

	filePathTxt = new agui::TextField;
	filePathTxt->setSize(EXETEXT_W, 25);
	filePathTxt->setLocation(EXETEXT_X, EXETEXT_Y);
	filePathTxt->setWantHotkeys(true);
	filePathTxt->setSelectable(true);
	filePathTxt->setReadOnly(false);
	filePathTxt->setBlinking(true);
	filePathTxt->setEnabled(true);
	exeFrame->add(filePathTxt);

	agui::Label *fileArgLabel = new agui::Label;
	fileArgLabel->setText("Args:");
	fileArgLabel->resizeToContents();
	fileArgLabel->setLocation(10, EXETEXT_Y + 4 +27);
	exeFrame->add(fileArgLabel);

	fileArgsTxt = new agui::TextField;
	fileArgsTxt->setSize(EXETEXT_W, 25);
	fileArgsTxt->setLocation(EXETEXT_X, EXETEXT_Y +27);
	fileArgsTxt->setWantHotkeys(true);
	fileArgsTxt->setSelectable(true);
	fileArgsTxt->setReadOnly(false);
	fileArgsTxt->setBlinking(true);
	fileArgsTxt->setEnabled(true);
	exeFrame->add(fileArgsTxt);

	filePathBtn = new agui::Button;
	filePathBtn->setText("Open"); //TODO(polish): file icon
	filePathBtn->setSize(50, 25);
	filePathBtn->setLocation(EXETEXT_X + EXETEXT_W +10, EXETEXT_Y);
	exeFrame->add(filePathBtn);

	fileButtonListener *btnListener1 = new fileButtonListener(state, this);
	filePathBtn->addActionListener(btnListener1);
	exeFrame->setVisibility(false);

	agui::Label *opts = new agui::Label;
	opts->setText("Options");
	opts->resizeToContents();
	opts->setLocation(OPTS_X, 120);
	exeFrame->add(opts);

	agui::Dimension CBSize;
	CBSize.setHeight(20);
	CBSize.setWidth(20);

	CBlisten *boxlistener = new CBlisten(state, this);

	pauseCB = new agui::CheckBox;
	pauseCB->setText("Pause on start");
	pauseCB->setCheckBoxSize(CBSize);
	pauseCB->resizeToContents();
	pauseCB->setLocation(OPTS_X +15, 140);
	pauseCB->setToolTipText("Pauses execution at program start with a message box to allow debugger attaching");
	pauseCB->addCheckBoxListener(boxlistener);
	exeFrame->add(pauseCB);

	basicCB = new agui::CheckBox;
	basicCB->setText("Basic mode");
	basicCB->setCheckBoxSize(CBSize);
	basicCB->resizeToContents();
	basicCB->setLocation(OPTS_X+15, 165);
	basicCB->setToolTipText("Improve performance by not animating or saving trace history");
	basicCB->addCheckBoxListener(boxlistener);
	exeFrame->add(basicCB);

	agui::Label *features = new agui::Label;
	features->setText("Feature creep");
	features->resizeToContents();
	features->setLocation(FEATURES_X, 120);
	exeFrame->add(features);

	/*
	hideVMCB = new agui::CheckBox;
	hideVMCB->setText("VM Cloaking");
	hideVMCB->setCheckBoxSize(CBSize);
	hideVMCB->resizeToContents();
	hideVMCB->setLocation(FEATURES_X+15, 140);
	hideVMCB->setToolTipText("[Experimental] Change results of VM detection instructions to hide virtualisation");
	hideVMCB->addCheckBoxListener(boxlistener);
	exeFrame->add(hideVMCB);
	*/

	hideSleepCB = new agui::CheckBox;
	hideSleepCB->setText("Anti-Sleep");
	hideSleepCB->setCheckBoxSize(CBSize);
	hideSleepCB->resizeToContents();
	hideSleepCB->setLocation(FEATURES_X + 15, 140);
	hideSleepCB->setToolTipText("[Experimental] Change sleep() calls to reduce pauses and timer results to hide slowdown");
	hideSleepCB->addCheckBoxListener(boxlistener);
	exeFrame->add(hideSleepCB);

	launchBtn = new agui::Button;
	launchBtn->setText("Launch");
	launchBtn->setSize(60, 25);
	launchBtn->setLocation(exeFrame->getWidth() / 2 - launchBtn->getWidth() / 2, exeFrame->getHeight()-70);
	launchButtonListener *btnListener2 = new launchButtonListener(state, this);
	launchBtn->addActionListener(btnListener2);
	exeFrame->add(launchBtn);
}


exeWindow::~exeWindow()
{
}
