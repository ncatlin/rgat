/*
Copyright 2016-2017 Nia Catlin

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
The main QT window class
*/
#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_rgat.h"
#include "ui_processSelector.h"
#include "ui_highlightSelector.h"
#include "ui_settingsDialog.h"
#include "ui_labelMouseoverWidget.h"
#include "ui_moduleIncludeSelector.h"

#include "rgatState.h"
#include "highlightWidget.h"
#include "mouseoverFrame.h"
#include "settingsdialog.h"

//Q_IMPORT_PLUGIN(qico);

#define RELEASE_BUILD true

namespace textBtnEnum {
	enum textBtnID { eExternToggle, eExternAuto, eExternAddress, eExternOffset, eExternAddressNone, eExternPath,
		eInternalToggle, eInternalAuto, ePlaceholderToggle, eInstructionToggle, eInstructionAddress, eInstructionOffset,
		eInstructionNoAddress, eInstructionTargLabel, eControlOnlyLabel, eResolveExterns
	};
}

class rgat : public QMainWindow
{

	Q_OBJECT

public:
	rgat(QWidget *parent = Q_NULLPTR);
	~rgat();

public Q_SLOTS:
	void activateDynamicStack();
	void activateStaticStack();
	void startSaveAll ();
	void startSaveTarget();
	void startSaveTrace();
	void loadSavedTrace();
	void textBtnTriggered(int btnID);
	void closeEvent(QCloseEvent *event);
	void doUIHousekeeping();

	void dropEvent(QDropEvent *event);
	void dragEnterEvent(QDragEnterEvent *event)
	{		event->accept();	}

	void settingsMenuBtnPressed();

private:
	rgatState *rgatstate;

	Ui::rgatClass ui;
	QDialog processSelectorDialog;
	Ui::processSelector processSelectUI;
	QDialog highlightSelectorDialog;
	Ui::highlightDialog highlightSelectUI;
	QDialog blacklistSelectDialog;
	Ui::moduleIncludeSelectDialog blacklistSelectUI;
	QDialog settingsWindowDialog;
	Ui::SettingsWindow settingsDialogUI;
	
	QMenu *recentTargetsMenu = NULL;

	QLabel *tracingStatusLabel, *activityStatusLabel;
	Ui_mouseoverWidget mouseoverWidgetUI;
	mouseoverFrame mouseoverWidget;

	QTimer *UIHousekeepingTimer = NULL;

private:
	void setStatePointers();
	void setupUI();

	void addLabelBtnMenus();
	void addExternTextBtn(QMenu *labelmenu);
	void addInternalTextBtn(QMenu *labelmenu); 
	void addPlaceholderTextBtn(QMenu *labelmenu);
	void addInstructionTextBtn(QMenu *labelmenu);
	void addFileMenuBtn();
	void loadRecentTargetsMenu();
};
