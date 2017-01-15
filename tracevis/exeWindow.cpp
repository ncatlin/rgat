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
#define EXEFRAME_H 330
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

	agui::Button *fileArgsBtn = new agui::Button;
	fileArgsBtn->setText("Paste"); //TODO(polish): file icon
	fileArgsBtn->setSize(50, fileArgsTxt->getHeight());
	fileArgsBtn->setLocation(EXETEXT_X + EXETEXT_W + 10, fileArgsTxt->getLocation().getY());
	exeFrame->add(fileArgsBtn);

	fileButtonListener *btnListener1 = new fileButtonListener(state, this);
	filePathBtn->addActionListener(btnListener1);
	fileArgsBtn->addActionListener(btnListener1);
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
	pauseCB->setToolTipText("Pauses execution at program start with a message box. Allows attaching a debugger to the target.");
	pauseCB->addCheckBoxListener(boxlistener);
	exeFrame->add(pauseCB);
	
	debugLogCB = new agui::CheckBox;
	debugLogCB->setText("Debug logging");
	debugLogCB->setCheckBoxSize(CBSize);
	debugLogCB->resizeToContents();
	debugLogCB->setLocation(OPTS_X + 15, 160);
	debugLogCB->setToolTipText("Generates a logfile for debugging drgat's instrumentation. Useful for reporting bugs!");
	debugLogCB->addCheckBoxListener(boxlistener);
	exeFrame->add(debugLogCB);

	/*
	debugCB = new agui::CheckBox;
	debugCB->setText("Debugger mode");
	debugCB->setCheckBoxSize(CBSize);
	debugCB->resizeToContents();
	debugCB->setLocation(OPTS_X + 15, 165);
	debugCB->setToolTipText("For manual debugger stepping.\nUpdate the visualisation at the end of every basic block. Massively degrades performance.");
	debugCB->addCheckBoxListener(boxlistener);
	exeFrame->add(debugCB);
	*/

	agui::Label *features = new agui::Label;
	features->setText("Feature creep");
	features->resizeToContents();
	features->setLocation(FEATURES_X, 120);
	exeFrame->add(features);

	hideSleepCB = new agui::CheckBox;
	hideSleepCB->setText("Anti-Sleep");
	hideSleepCB->setCheckBoxSize(CBSize);
	hideSleepCB->resizeToContents();
	hideSleepCB->setLocation(FEATURES_X + 15, 140);
	hideSleepCB->setToolTipText("[Experimental] Change sleep() calls to reduce pauses and timer results to hide slowdown");
	hideSleepCB->addCheckBoxListener(boxlistener);
	exeFrame->add(hideSleepCB);

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

	int midframeX = exeFrame->getWidth() / 2;

	agui::Label *warnLabel1 = new agui::Label;
	warnLabel1->setText("Target will execute with rgat's privileges in this environment");
	warnLabel1->resizeToContents();
	warnLabel1->setLocation(midframeX - warnLabel1->getWidth() / 2, exeFrame->getHeight() - 100);
	//warnLabel1->setMargins(0, 15, 0, 0);
	exeFrame->add(warnLabel1);

	agui::Label *warnLabel2 = new agui::Label;
	warnLabel2->setText("Do be sensible");
	warnLabel2->resizeToContents();
	warnLabel2->setLocation(midframeX - warnLabel2->getWidth() / 2, exeFrame->getHeight() - 80);
	//warnLabel2->setMargins(0, 15, 0, 0);
	exeFrame->add(warnLabel2);

	exeButtonListener *btnListener2 = new exeButtonListener(state, this);

	launchBtn = new agui::Button;
	launchBtn->setText("Launch");
	launchBtn->setSize(60, 25);
	
	launchBtn->setLocation(midframeX - launchBtn->getWidth()/2, exeFrame->getHeight()-58);
	launchBtn->addActionListener(btnListener2);
	launchBtn->setToolTipText("Visualise target execution");
	exeFrame->add(launchBtn);

	agui::Button *closeBtn = new agui::Button;
	closeBtn->setText("X");
	closeBtn->setSize(25, 25);
	int sideFrameX = exeFrame->getWidth() - closeBtn->getWidth() - 15;
	closeBtn->setLocation(sideFrameX, 5);
	closeBtn->addActionListener(btnListener2);
	closeBtn->setToolTipText("Close Dialog (or press Esc)");
	exeFrame->add(closeBtn);
}


exeWindow::~exeWindow()
{
}
