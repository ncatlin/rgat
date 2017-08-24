/*
Copyright 2016-2017 Nia Catlin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
The main QT window class
*/

#include "stdafx.h"
#include "rgat.h"
#include "headers\OSspecific.h"
#include "processLaunching.h"
#include "maingraph_render_thread.h"
#include "qglobal.h"
#include "serialise.h"


//shouldn't really be needed, only here because i havent dealt with a naming scheme yet. make it pid based?
bool checkAlreadyRunning()
{
	return boost::filesystem::exists("\\\\.\\pipe\\BootstrapPipe");
}

void rgat::addExternTextBtn(QMenu *labelmenu)
{
	QMenu *externMenu = new QMenu(this);

	externMenu->setTitle("External Symbols");
	externMenu->setToolTipsVisible(true);
	externMenu->setToolTipDuration(500);
	externMenu->setStatusTip(tr("Symbols outside of instrumented code"));
	externMenu->setToolTip(tr("Symbols outside of instrumented code"));
	labelmenu->addMenu(externMenu);

	QAction *showHideAction = new QAction(tr("&Enabled"), this);
	rgatstate->textButtons.externalShowHide = showHideAction;
	externMenu->addAction(showHideAction);
	//note to future porting efforts: if this doesn't compile, use qtsignalmapper
	connect(showHideAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternToggle); });

	QAction *autoAction = new QAction(tr("&Auto"), this);
	rgatstate->textButtons.externalAuto = autoAction;
	autoAction->setCheckable(true);
	externMenu->addAction(autoAction);
	connect(autoAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternAuto); });

	QAction *address = new QAction(tr("&Addresses"), this);
	rgatstate->textButtons.externalAddress = address;
	address->setCheckable(true);
	externMenu->addAction(address);
	connect(address, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternAddress); });

	QAction *paths = new QAction(tr("&Full Paths"), this);
	rgatstate->textButtons.externalPath = paths;
	paths->setCheckable(true);
	externMenu->addAction(paths);
	connect(paths, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternPath); });
}

void rgat::addInternalTextBtn(QMenu *labelmenu)
{
	QMenu *menu = new QMenu(this);

	menu->setTitle("Internal Symbols");
	menu->setToolTipsVisible(true);
	menu->setToolTipDuration(500);
	menu->setStatusTip(tr("Symbols outside of instrumented code"));
	menu->setToolTip(tr("Symbols outside of instrumented code"));
	labelmenu->addMenu(menu);

	QAction *showAction = new QAction(tr("&Enabled"), this);
	rgatstate->textButtons.internalShowHide = showAction;
	menu->addAction(showAction);
	connect(showAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInternalToggle); });

	QAction *autoAction = new QAction(tr("&Auto"), this);
	rgatstate->textButtons.internalAuto = autoAction;
	autoAction->setCheckable(true);
	menu->addAction(autoAction);
	connect(autoAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInternalAuto); });
}

void rgat::addInstructionTextBtn(QMenu *labelmenu)
{
	QMenu *menu = new QMenu(this);

	menu->setTitle("Instructions");
	menu->setToolTipsVisible(true);
	menu->setToolTipDuration(500);
	menu->setStatusTip(tr("Instruction Text"));
	menu->setToolTip(tr("Instruction Text"));
	labelmenu->addMenu(menu);

	QAction *showAction = new QAction(tr("&Enabled"), this);
	rgatstate->textButtons.instructionShowHide = showAction;
	menu->addAction(showAction);
	connect(showAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInstructionToggle); });

	QAction *mnemonicAction = new QAction(tr("&Mnemonics"), this);
	rgatstate->textButtons.instructionMnemonic = mnemonicAction;
	mnemonicAction->setCheckable(true);
	menu->addAction(mnemonicAction);
	connect(mnemonicAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInstructionMnemonic); });
}

void rgat::textBtnTriggered(int buttonID)
{
	switch ((textBtnEnum::textBtnID)buttonID)
	{
	case textBtnEnum::eExternToggle:
		rgatstate->config.externalSymbolVisibility.enabled = !rgatstate->config.externalSymbolVisibility.enabled;
		break;

	case textBtnEnum::eExternAuto:
		rgatstate->config.externalSymbolVisibility.showWhenZoomed = !rgatstate->config.externalSymbolVisibility.showWhenZoomed;
		break;

	case textBtnEnum::eExternAddress:
		rgatstate->config.externalSymbolVisibility.addresses = !rgatstate->config.externalSymbolVisibility.addresses;
		break;

	case textBtnEnum::eExternPath:
		rgatstate->config.externalSymbolVisibility.fullPaths = !rgatstate->config.externalSymbolVisibility.fullPaths;
		break;

	case textBtnEnum::eInternalToggle:
		rgatstate->config.internalSymbolVisibility.enabled = !rgatstate->config.internalSymbolVisibility.enabled;
		break;

	case textBtnEnum::eInternalAuto:
		rgatstate->config.internalSymbolVisibility.showWhenZoomed = !rgatstate->config.internalSymbolVisibility.showWhenZoomed;
		break;

	case textBtnEnum::eInstructionToggle:
		rgatstate->config.instructionTextVisibility.enabled = !rgatstate->config.instructionTextVisibility.enabled;
		break;

	case textBtnEnum::eInstructionMnemonic:
		rgatstate->config.instructionTextVisibility.fullPaths = !rgatstate->config.instructionTextVisibility.fullPaths;
		break;

	default:
		cerr << "[rgat]bad text button. asserting." << endl;
		assert(false);
	}
	rgatstate->updateTextDisplayButtons();
}

void rgat::addLabelBtnMenu()
{
	QMenu *labelmenu = new QMenu(this);
	ui.labelSelectBtn->setMenu(labelmenu);
	ui.labelSelectBtn->setPopupMode(QToolButton::InstantPopup);
	labelmenu->setToolTipsVisible(true);

	addExternTextBtn(labelmenu);
	addInternalTextBtn(labelmenu);
	addInstructionTextBtn(labelmenu);
}

void rgat::setupUI()
{
	ui.setupUi(this);
	processSelectui.setupUi(&processSelectorDialog);
	highlightSelectui.setupUi(&highlightSelectorDialog);

	ui.previewsGLBox->setFixedWidth(PREVIEW_PANE_WIDTH);

	ui.speedComboBox->addItem("0.5x");
	ui.speedComboBox->addItem("1x");
	ui.speedComboBox->setCurrentIndex(1);
	ui.speedComboBox->addItem("2x");
	ui.speedComboBox->addItem("4x");
	ui.speedComboBox->addItem("8x");
	ui.speedComboBox->addItem("16x");
	ui.speedComboBox->addItem("32x");
	ui.speedComboBox->addItem("64x");
	ui.speedComboBox->addItem("128x");

	ui.playBtn->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
	ui.stopBtn->setIcon(style()->standardIcon(QStyle::SP_MediaStop));

	activityStatusLabel = new QLabel(this);
	ui.statusBar->addPermanentWidget(activityStatusLabel);
	activityStatusLabel->setFrameStyle(QFrame::Sunken);
	activityStatusLabel->setAlignment(Qt::AlignLeft);
	activityStatusLabel->setMinimumWidth(200);
	activityStatusLabel->setText("Saving");

	tracingStatusLabel = new QLabel(this);
	ui.statusBar->addPermanentWidget(tracingStatusLabel);
	tracingStatusLabel->setMinimumWidth(200);
	tracingStatusLabel->setText("Traces Active: 0");

	rgatstate->widgetStyle = style();
	addLabelBtnMenu();
	rgatstate->updateTextDisplayButtons();

#ifdef RELEASE
		//disable various stubs until implemented

		//disable tree option https://stackoverflow.com/questions/11439773/disable-item-in-qt-combobox
		QVariant v(0);
		ui.visLayoutSelectCombo->setItemData(eTreeLayout, v, Qt::UserRole - 1);

		//disable fuzzing tab
		ui.dynamicAnalysisContentsTab->removeTab(eFuzzTab);

		ui.menuAnalysis_Mode->menuAction()->setEnabled(false);
		ui.menuSettings->menuAction()->setEnabled(false);
		ui.pauseBreakBtn->setEnabled(false);
#endif

}

rgat::rgat(QWidget *parent)
	: QMainWindow(parent)
{

	if (checkAlreadyRunning())
	{
		std::cerr << "[rgat]Error: rgat already running [Existing BootstrapPipe found]. Exiting..." << endl;
		return;
	}

	rgatstate = new rgatState;

	setupUI();
	setStatePointers();

	rgat_create_thread(process_coordinator_thread, rgatstate);

	Ui::highlightDialog *highlightui = (Ui::highlightDialog *)rgatstate->highlightSelectUI;
	highlightui->addressLabel->setText("Address:");

	maingraph_render_thread *mainRenderThread = new maingraph_render_thread(rgatstate);
	rgatstate->maingraphRenderer = mainRenderThread;
	rgat_create_thread(mainRenderThread->ThreadEntry, mainRenderThread);

	rgatstate->emptyComparePane1();
	rgatstate->emptyComparePane2();

	rgatstate->updateActivityStatus("Open a binary target or saved trace", PERSISTANT_ACTIVITY);
}

//probably a better way of doing this
void rgat::setStatePointers()
{
	rgatstate->ui = &ui;
	rgatstate->processSelectorDialog = &processSelectorDialog;
	rgatstate->processSelectUI = &processSelectui;
	processSelectui.treeWidget->clientState = rgatstate;

	rgatstate->highlightSelectorDialog = &highlightSelectorDialog;
	rgatstate->highlightSelectUI = &highlightSelectui;
	highlightSelectui.highlightDialogWidget->clientState = rgatstate;
	
	ui.targetListCombo->setTargetsPtr(&rgatstate->targets, ui.dynamicAnalysisContentsTab);
	ui.dynamicAnalysisContentsTab->setPtrs(&rgatstate->targets, rgatstate);
	ui.traceAnalysisTree->setClientState(rgatstate);

	rgatstate->InitialiseStatusbarLabels(activityStatusLabel, tracingStatusLabel);

	base_thread::clientState = rgatstate;
	plotted_graph::clientState = rgatstate;
	graphGLWidget::clientState = rgatstate;
	ui.targetListCombo->clientState = rgatstate;
	ui.traceGatherTab->clientState = rgatstate;

	ui.previewsGLBox->setScrollBar(ui.previewScrollbar);
}

void rgat::activateDynamicStack()
{
	ui.actionDynamic->setChecked(true);
	ui.actionStatic->setChecked(false);
	ui.staticDynamicStack->setCurrentIndex(eDynamicTabs);
}

void rgat::activateStaticStack()
{
	ui.actionStatic->setChecked(true);
	ui.actionDynamic->setChecked(false);
	ui.staticDynamicStack->setCurrentIndex(eStaticTabs);
}


void rgat::startSaveAll()
{
	rgatstate->saveAll();
}

void rgat::startSaveTarget()
{
	if (rgatstate && rgatstate->activeBinary)
		rgatstate->saveTarget(rgatstate->activeBinary);
}

void rgat::startSaveTrace()
{
	if (rgatstate && rgatstate->activeTrace)
	{
		traceRecord *originalTrace = rgatstate->activeTrace;
		while (originalTrace->parentTrace)
			originalTrace = originalTrace->parentTrace;

		rgatstate->saveTrace(originalTrace);
	}
}


void launch_all_trace_threads(traceRecord *trace, rgatState *clientState)
{
	launch_saved_process_threads(trace, clientState);

	traceRecord *childTrace;
	foreach(childTrace, trace->children)
	{
		launch_all_trace_threads(childTrace, clientState);
	}
}

void rgat::loadSavedTrace()
{
	QString fileName = QFileDialog::getOpenFileName(this,
		tr("Select saved trace"), rgatstate->config.getSaveDirString(),
		tr("Trace (*.rgat);;Library (*.dll);;All Files (*.*)"));

	boost::filesystem::path filepath(fileName.toStdString());
	if (!boost::filesystem::exists(filepath)) return;

	traceRecord *trace;
	if (!rgatstate->loadTrace(filepath, &trace)) return;

	launch_all_trace_threads(trace, rgatstate);
	
	rgatstate->activeBinary = (binaryTarget *)trace->get_binaryPtr();
	rgatstate->switchTrace = trace;

	ui.dynamicAnalysisContentsTab->setCurrentIndex(eVisualiseTab);

}

void rgat::closeEvent(QCloseEvent *event)
{
	/*QMessageBox::StandardButton resBtn = QMessageBox::question(this, "rgat",
		tr("Confirm Quit?\n"),
		QMessageBox::Cancel | QMessageBox::No | QMessageBox::Yes,
		QMessageBox::Yes);
	if (resBtn != QMessageBox::Yes) {
		event->ignore();
	}
	else {
		event->accept();
	}*/

	if (highlightSelectorDialog.isVisible())
		highlightSelectorDialog.hide();
	if (processSelectorDialog.isVisible())
		processSelectorDialog.hide();
	event->accept();
}