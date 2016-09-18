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
	
	agui::Label *nonGraphicalLabel;
	agui::CheckBox *nonGraphicalCB;
	agui::CheckBox *hideVMCB;
	agui::CheckBox *hideSleepCB;
	agui::Button *launchBtn;

	string target;
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
	void setPath(string path) { target = path; filePathTxt->setText(path); }
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
		if (thisNeedsAnIDField == "Anti-Redpill")
			clientState->launchopts.antidote = state;
		else if (thisNeedsAnIDField == "Anti-Sleep")
			clientState->launchopts.caffine = state;
		else if (thisNeedsAnIDField == "Disable Rendering")
			clientState->launchopts.nographics = state;
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
		lastPath = getModulePath();
	}

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		ALLEGRO_FILECHOOSER *fileDialog;
		fileDialog = al_create_native_file_dialog(lastPath.c_str(), "Choose target to execute", "*.exe;*.*;",
			ALLEGRO_FILECHOOSER_FILE_MUST_EXIST | ALLEGRO_FILECHOOSER_SHOW_HIDDEN);
		al_show_native_file_dialog(clientState->maindisplay, fileDialog);

		const char* result = al_get_native_file_dialog_path(fileDialog, 0);
		al_destroy_native_file_dialog(fileDialog);
		if (!al_filename_exists(result)) return;
		exe_wind->setPath(string(result));
	}

private:
	VISSTATE *clientState;
	exeWindow *exe_wind;
	string lastPath = getModulePath();
};

class launchButtonListener : public agui::ActionListener
{
public:
	launchButtonListener(VISSTATE *state, exeWindow *exeWind) {
		clientState = state; exe_wind = exeWind;
		lastPath = getModulePath();
	}

	virtual void actionPerformed(const agui::ActionEvent &evt)
	{
		string path =exe_wind->getPath();
		if (!al_filename_exists(path.c_str())) return;
		execute_tracer(path, clientState);
		exe_wind->hide();
	}

private:
	
	VISSTATE *clientState;
	exeWindow *exe_wind;
	string lastPath;
};