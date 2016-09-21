#pragma once
#include "GUIStructs.h"
#include <Agui/Agui.hpp>
#include <Agui/Backends/Allegro5/Allegro5.hpp>
#include "Agui/Widgets/Label\Label.hpp"
#include "Agui/Widgets\Frame\Frame.hpp"
#include "Agui/Widgets\TextField\TextField.hpp"
#include "Agui/Widgets/Button/Button.hpp"
#include "Agui\Widgets\CheckBox\CheckBox.hpp"
#include "Agui\Widgets\CheckBox\CheckBoxListener.hpp"
#include "OSspecific.h"

class exeWindow
{
private:
	agui::Frame *exeFrame;

	agui::Label *filePathLabel;
	agui::TextField *filePathTxt;
	agui::Button *filePathBtn;
	agui::Button *launchBtn;

	agui::Label *attachIDLabel;
	agui::TextField *attachIDTxt;
	agui::Button *attachIDBtn;

	agui::CheckBox *pauseCB;
	agui::CheckBox *basicCB;
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
		
		string thisNeedsAnIDField = source->getText().c_str();
		if (thisNeedsAnIDField == "Anti-Sleep")
			clientState->launchopts.caffine = state;
		else if (thisNeedsAnIDField == "Pause on start")
			clientState->launchopts.pause = state;
		else if (thisNeedsAnIDField == "Basic mode")
			clientState->launchopts.basic = state;
		else
			printf("Checkbox text %s does not match an expected value! Ignoring\n", source->getText().c_str());
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

class launchButtonListener : public agui::ActionListener
{
public:
	launchButtonListener(VISSTATE *state, exeWindow *exeWind) {
		clientState = state; exe_wind = exeWind;
	}

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		string path = exe_wind->getPath();
		if (!fileExists(path)) return;
		execute_tracer(path, clientState);
		exe_wind->hide();
	}

private:
	
	VISSTATE *clientState;
	exeWindow *exe_wind;
};