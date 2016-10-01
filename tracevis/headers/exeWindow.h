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

#pragma once
#include "OSspecific.h"
#include "GUIStructs.h"
#include <Agui/Agui.hpp>
#include <Agui/Backends/Allegro5/Allegro5.hpp>
#include "Agui/Widgets/Label\Label.hpp"
#include "Agui/Widgets\Frame\Frame.hpp"
#include "Agui/Widgets\TextField\TextField.hpp"
#include "Agui/Widgets/Button/Button.hpp"
#include "Agui\Widgets\CheckBox\CheckBox.hpp"
#include "Agui\Widgets\CheckBox\CheckBoxListener.hpp"


class exeWindow
{
private:
	agui::Frame *exeFrame;

	agui::TextField *filePathTxt;
	agui::TextField *fileArgsTxt;
	agui::Button *filePathBtn;
	agui::Button *launchBtn;

	agui::Label *attachIDLabel;
	agui::TextField *attachIDTxt;
	agui::Button *attachIDBtn;

	agui::CheckBox *pauseCB;
	agui::CheckBox *basicCB;
	agui::CheckBox *debugCB;
	agui::CheckBox *hideVMCB;
	agui::CheckBox *hideSleepCB;


	string target;
	int PID = -1;
	VISSTATE *clientState;
	agui::Gui *guiWidgets;

public:
	exeWindow(agui::Gui *widgets, VISSTATE *state, agui::Font *font);
	void show() 
	{ 
		if (exeFrame->isVisible())
			exeFrame->setVisibility(false);
		else
		{
			int frameX = clientState->displaySize.width / 2 - exeFrame->getSize().getWidth() / 2;
			int frameY = clientState->displaySize.height / 2 - exeFrame->getSize().getHeight() / 2;
			exeFrame->setLocation(frameX, frameY);
			exeFrame->setVisibility(true);
		}
	}
	void hide() { exeFrame->setVisibility(false);	}
	~exeWindow();
	void setPath(string path) { 
		target = path; 
		filePathTxt->setText(path.c_str()); 
	}
	string getPath() { return target; }
	string getArgs() {	return fileArgsTxt->getText(); }

};

class CBlisten : public agui::CheckBoxListener
{
public:
	CBlisten(VISSTATE *state, exeWindow *exeWind) {
		clientState = state; exe_wind = exeWind;
	}

	virtual void checkedStateChanged(agui::CheckBox* source,
		agui::CheckBox::CheckBoxCheckedEnum state)
	{
		//i'm sure there must be a way to add an int ID to a checkbox
		//can't find it though and haven't bothered to add it
		string thisNeedsAnIDField = source->getText().c_str();
		if (thisNeedsAnIDField == "Anti-Sleep")
			clientState->launchopts.caffine = state;
		else if (thisNeedsAnIDField == "Pause on start")
			clientState->launchopts.pause = state;
		else if (thisNeedsAnIDField == "Structure only")
			clientState->launchopts.basic = state;
		else if (thisNeedsAnIDField == "Debugger mode")
			clientState->launchopts.debugMode = state; 
		else
			cerr<< "[rgat]Checkbox text '"<< source->getText() << "' does not match an expected value! Ignoring" <<endl;
	}
private:
	VISSTATE *clientState;
	exeWindow *exe_wind;
};

class fileButtonListener : public agui::ActionListener
{
public:
	fileButtonListener(VISSTATE *state, exeWindow *exeWind) {
		clientState = state; exe_wind = exeWind;
	}

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		ALLEGRO_FILECHOOSER *fileDialog;
		string startPath = clientState->config->lastPath;
		fileDialog = al_create_native_file_dialog(startPath.c_str(), "Choose target to execute", "*.exe;*.*;",
			ALLEGRO_FILECHOOSER_FILE_MUST_EXIST | ALLEGRO_FILECHOOSER_SHOW_HIDDEN);
		al_show_native_file_dialog(clientState->maindisplay, fileDialog);

		const char* result =  al_get_native_file_dialog_path(fileDialog, 0);
		if (!result) return;

		string path(result);
		al_destroy_native_file_dialog(fileDialog);
		if (!fileExists(path)) return;

		clientState->config->updateLastPath(path);
		exe_wind->setPath(path);
	}

private:
	VISSTATE *clientState;
	exeWindow *exe_wind;
};

class exeButtonListener : public agui::ActionListener
{
public:
	exeButtonListener(VISSTATE *state, exeWindow *exeWind) {
		clientState = state; exe_wind = exeWind;
	}

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		if (evt.getSource()->getText() == "X")
		{
			exe_wind->hide();
			return;
		}
		string path = exe_wind->getPath();
		if (!fileExists(path))
		{	
			cerr << "[rgat]Executable " << path << " not found. Try again." << endl;
			return;
		}
		execute_tracer(path,exe_wind->getArgs(), clientState);
		exe_wind->hide();
	}

private:
	
	VISSTATE *clientState;
	exeWindow *exe_wind;
};