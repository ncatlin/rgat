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

rgat::rgat(QWidget *parent)
	: QMainWindow(parent)
{

	if (checkAlreadyRunning())
	{
		std::cerr << "[rgat]Error: rgat already running [Existing BootstrapPipe found]. Exiting..." << endl;
		return;
	}
	setAcceptDrops(true);

	rgatstate = new rgatState;

	setupUI();
	setStatePointers();

	std::thread visualiserThreadLauncher(process_coordinator_thread, rgatstate);
	visualiserThreadLauncher.detach();

	Ui::highlightDialog *highlightui = (Ui::highlightDialog *)rgatstate->highlightSelectUI;
	highlightui->addressLabel->setText("Address:");

	maingraph_render_thread *mainRenderThread = new maingraph_render_thread(rgatstate);
	rgatstate->maingraphRenderer = mainRenderThread;
	std::thread renderThread(maingraph_render_thread::ThreadEntry, mainRenderThread);
	renderThread.detach();

	rgatstate->emptyComparePane1();
	rgatstate->emptyComparePane2();

	rgatstate->updateActivityStatus("Open a binary target or saved trace", PERSISTANT_ACTIVITY);
}

rgat::~rgat() 
{
	processSelectorDialog.deleteLater();
	highlightSelectorDialog.deleteLater();
	settingsWindowDialog.deleteLater();
}

void rgat::setupUI()
{
	ui.setupUi(this);
	processSelectUI.setupUi(&processSelectorDialog);
	highlightSelectUI.setupUi(&highlightSelectorDialog);
	mouseoverWidgetUI.setupUi(&mouseoverWidget);
	blacklistSelectUI.setupUi(&blacklistSelectDialog);
	settingsDialogUI.setupUi(&settingsWindowDialog);

	rgatstate->labelMouseoverWidget = &mouseoverWidget;
	rgatstate->labelMouseoverWidget->clientState = rgatstate;
	mouseoverWidget.setWindowFlags(Qt::FramelessWindowHint | Qt::WindowSystemMenuHint);


	ui.previewsGLBox->setFixedWidth(PREVIEW_PANE_WIDTH);

	vector <QString> supportedPlaybackSpeeds =
	{ "0.5x","1x", "2x", "4x", "8x", "16x", "32x", "64x", "128x" };
	for each (QString speed in supportedPlaybackSpeeds)
	{
		ui.speedComboBox->addItem(speed);
	}
	ui.speedComboBox->setCurrentIndex(1); //1x is standard

	ui.fileToolBtn->setIcon(style()->standardIcon(QStyle::SP_FileDialogNewFolder));
	ui.settingsUiBtn->setIcon(style()->standardIcon(QStyle::SP_FileDialogDetailedView));
	ui.playBtn->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
	ui.stopBtn->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
	ui.redrawButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));

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
	addLabelBtnMenus();
	rgatstate->updateTextDisplayButtons();
	addFileMenuBtn();

#ifdef RELEASE
	//disable various stubs until implemented

	//disable tree option https://stackoverflow.com/questions/11439773/disable-item-in-qt-combobox
	QVariant v(0);
	ui.visLayoutSelectCombo->setItemData(eTreeLayout, v, Qt::UserRole - 1);

	//disable fuzzing tab
	ui.dynamicAnalysisContentsTab->removeTab(eFuzzTab);

	//pausing/breaking process not supported yet
	ui.pauseBreakBtn->setEnabled(false);
#endif

}

//probably a better way of doing this
void rgat::setStatePointers()
{
	rgatstate->ui = &ui;
	rgatstate->processSelectorDialog = &processSelectorDialog;
	rgatstate->processSelectUI = &processSelectUI;
	processSelectUI.treeWidget->clientState = rgatstate;

	rgatstate->highlightSelectorDialog = &highlightSelectorDialog;
	rgatstate->highlightSelectUI = &highlightSelectUI;
	highlightSelectUI.highlightDialogWidget->clientState = rgatstate;

	rgatstate->includesSelectorDialog = &blacklistSelectDialog;
	rgatstate->includesSelectorUI = &blacklistSelectUI;
	blacklistSelectUI.blackWhiteListStack->clientState = rgatstate;

	rgatstate->settingsDialog = &settingsWindowDialog;
	rgatstate->settingsDialogUI = &settingsDialogUI;
	settingsDialogUI.mainSettingsFrame->settingsUIPtr = &settingsDialogUI;
	settingsDialogUI.mainSettingsFrame->clientState = rgatstate;
	settingsDialogUI.mainSettingsFrame->connectWidgets();

	rgatstate->labelMouseoverUI = &mouseoverWidgetUI;

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




void rgat::addExternTextBtn(QMenu *labelmenu)
{
	labelmenu->setToolTipsVisible(true);
	labelmenu->setToolTipDuration(500);
	labelmenu->setStatusTip(tr("Symbols outside of instrumented code"));
	labelmenu->setToolTip(tr("Symbols outside of instrumented code"));

	QAction *showHideAction = new QAction(tr("&External Symbols"), this);
	rgatstate->textButtons.externalShowHide = showHideAction;
	labelmenu->addAction(showHideAction);
	//note to future porting efforts: if this doesn't compile, use qtsignalmapper
	connect(showHideAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternToggle); });

	labelmenu->addSeparator();

	QAction *offset = new QAction(tr("&Offset"), this);
	offset->setStatusTip(QCoreApplication::tr("Displaying offset of symbols from module base."));
	rgatstate->textButtons.externalOffset = offset;
	offset->setCheckable(true);
	labelmenu->addAction(offset);
	connect(offset, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternOffset); });

	QAction *address = new QAction(tr("&Address"), this);
	address->setStatusTip(QCoreApplication::tr("Displaying absolute memory address of symbols."));
	rgatstate->textButtons.externalAddress = address;
	rgatstate->textButtons.externalAddress = address;
	address->setCheckable(true);
	labelmenu->addAction(address);
	connect(address, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternAddress); });

	QAction *addressOff = new QAction(tr("&None"), this);
	addressOff->setStatusTip(QCoreApplication::tr("Disable displaying of symbol location."));
	rgatstate->textButtons.externalAddressOff = addressOff;
	addressOff->setCheckable(true);
	labelmenu->addAction(addressOff);
	connect(addressOff, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternAddressNone); });

	labelmenu->addSeparator();

	QAction *paths = new QAction(tr("&Paths"), this);
	rgatstate->textButtons.externalPath = paths;
	paths->setCheckable(true);
	paths->setChecked(rgatstate->config.externalSymbolVisibility.fullPaths);
	labelmenu->addAction(paths);
	connect(paths, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eExternPath); });
	paths->setStatusTip(QCoreApplication::tr("Display the full path of the module each external symbol belongs to."));


	QAction *performResolve = new QAction(tr("&Resolve Symbols"), this);
	performResolve->setCheckable(false);
	labelmenu->addAction(performResolve);
	connect(performResolve, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eResolveExterns); });
	performResolve->setStatusTip(
		QCoreApplication::tr("Attempt to determine the symbol that unresolved externals on the screen belong to."));
}

void rgat::addInternalTextBtn(QMenu *labelmenu)
{
	QAction *showAction = new QAction(tr("&Internal Symbols"), this);
	rgatstate->textButtons.internalShowHide = showAction;
	labelmenu->addAction(showAction);
	connect(showAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInternalToggle); });
}

void rgat::addPlaceholderTextBtn(QMenu *labelmenu)
{
	QAction *showAction = new QAction(tr("&Placeholder Labels"), this);
	rgatstate->textButtons.placeholderShowHide = showAction;
	labelmenu->addAction(showAction);
	connect(showAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::ePlaceholderToggle); });
}


void rgat::addInstructionTextBtn(QMenu *labelmenu)
{
	QAction *showAction = new QAction(tr("&Enabled"), this);
	rgatstate->textButtons.instructionShowHide = showAction;
	labelmenu->addAction(showAction);
	connect(showAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInstructionToggle); });

	labelmenu->addSeparator();

	QAction *offsetAction = new QAction(tr("&Offset"), this);
	rgatstate->textButtons.instructionOffset = offsetAction;
	offsetAction->setCheckable(true);
	labelmenu->addAction(offsetAction);
	connect(offsetAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInstructionOffset); });
	offsetAction->setStatusTip(QCoreApplication::tr("Display offset of instructions from the module base."));

	QAction *addressAction = new QAction(tr("&Address"), this);
	rgatstate->textButtons.instructionAddress = addressAction;
	addressAction->setCheckable(true);
	labelmenu->addAction(addressAction);
	connect(addressAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInstructionAddress); });
	addressAction->setStatusTip(QCoreApplication::tr("Display absolute address of instructions."));

	QAction *noaddressAction = new QAction(tr("&None"), this);
	rgatstate->textButtons.instructionAddressOff = noaddressAction;
	noaddressAction->setCheckable(true);
	labelmenu->addAction(noaddressAction);
	connect(noaddressAction, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInstructionNoAddress); });
	noaddressAction->setStatusTip(QCoreApplication::tr("Disable display of instruction location."));

	labelmenu->addSeparator();

	QAction *controlonly = new QAction(tr("&Control flow only"), this);
	rgatstate->textButtons.controlOnlyLabel = controlonly;
	controlonly->setCheckable(true);
	labelmenu->addAction(controlonly);
	connect(controlonly, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eControlOnlyLabel); });
	controlonly->setStatusTip(QCoreApplication::tr("Only display control flow instructions (eg: jump, ret, call...)"));

	QAction *targlabel = new QAction(tr("&Target Label"), this);
	rgatstate->textButtons.instructionTargLabel = targlabel;
	targlabel->setCheckable(true);
	labelmenu->addAction(targlabel);
	connect(targlabel, &QAction::triggered, this, [this] {textBtnTriggered(textBtnEnum::eInstructionTargLabel); });
}

void rgat::textBtnTriggered(int buttonID)
{
	switch ((textBtnEnum::textBtnID)buttonID)
	{
	case textBtnEnum::eExternToggle:
		rgatstate->config.externalSymbolVisibility.enabled = 
			!rgatstate->config.externalSymbolVisibility.enabled;
		break;

	case textBtnEnum::eExternAuto:
		rgatstate->config.externalSymbolVisibility.showWhenZoomed = 
			!rgatstate->config.externalSymbolVisibility.showWhenZoomed;
		break;

	case textBtnEnum::eExternOffset:
		if (!rgatstate->config.externalSymbolVisibility.offsets)
		{
			rgatstate->config.externalSymbolVisibility.addresses = true;
			rgatstate->config.externalSymbolVisibility.offsets = true;
		}
		break;

	case textBtnEnum::eExternAddress:
		if ((rgatstate->config.externalSymbolVisibility.offsets == true) ||
			(rgatstate->config.externalSymbolVisibility.addresses == false))
		{
			rgatstate->config.externalSymbolVisibility.offsets = false;
			rgatstate->config.externalSymbolVisibility.addresses = true;
		}
		break;

	case textBtnEnum::eExternAddressNone:
		if (rgatstate->config.externalSymbolVisibility.addresses == true)
		{
			rgatstate->config.externalSymbolVisibility.addresses = false;
			rgatstate->config.externalSymbolVisibility.offsets = false;
		}
		break;

	case textBtnEnum::eExternPath:
		rgatstate->config.externalSymbolVisibility.fullPaths = 
			!rgatstate->config.externalSymbolVisibility.fullPaths;
		break;

	case textBtnEnum::eInternalToggle:
		rgatstate->config.internalSymbolVisibility.enabled = 
			!rgatstate->config.internalSymbolVisibility.enabled;
		break;

	case textBtnEnum::ePlaceholderToggle:
		rgatstate->config.placeholderLabelVisibility.enabled =
			!rgatstate->config.placeholderLabelVisibility.enabled;
		break;

	case textBtnEnum::eInternalAuto:
		rgatstate->config.internalSymbolVisibility.showWhenZoomed = 
			!rgatstate->config.internalSymbolVisibility.showWhenZoomed;
		break;

	case textBtnEnum::eInstructionToggle:
		rgatstate->config.instructionTextVisibility.enabled = 
			!rgatstate->config.instructionTextVisibility.enabled;
		break;

	case textBtnEnum::eInstructionOffset:
		if (!rgatstate->config.instructionTextVisibility.offsets)
		{
			rgatstate->config.instructionTextVisibility.addresses = true;
			rgatstate->config.instructionTextVisibility.offsets = true;
		}
		break;

	case textBtnEnum::eInstructionAddress:
		if ((rgatstate->config.instructionTextVisibility.offsets == true) || 
			(rgatstate->config.instructionTextVisibility.addresses == false))
		{
			rgatstate->config.instructionTextVisibility.offsets = false;
			rgatstate->config.instructionTextVisibility.addresses = true;
		}
		break;

	case textBtnEnum::eInstructionNoAddress:
		if (rgatstate->config.instructionTextVisibility.addresses == true)
		{
			rgatstate->config.instructionTextVisibility.addresses = false;
			rgatstate->config.instructionTextVisibility.offsets = false;
		}
		break;

	case textBtnEnum::eControlOnlyLabel:
		rgatstate->config.instructionTextVisibility.extraDetail = 
			!rgatstate->config.instructionTextVisibility.extraDetail;
		break;

	case textBtnEnum::eInstructionTargLabel:
		rgatstate->config.instructionTextVisibility.fullPaths = 
			!rgatstate->config.instructionTextVisibility.fullPaths;
		break;



	case textBtnEnum::eResolveExterns:
		{
			plotted_graph *activeGraph = ((plotted_graph*)rgatstate->getActiveGraph(false));
			if (activeGraph)
				activeGraph->schedule_performSymbolResolve = true; 
		}
		break;

	default:
		cerr << "[rgat]bad text button. asserting." << endl;
		assert(false);
	}
	rgatstate->updateTextDisplayButtons();
	rgatstate->config.saveConfig();
}

void rgat::addLabelBtnMenus()
{
	QMenu *symLabelMenu = new QMenu(this);
	ui.toolb_symbolSelectBtn->setMenu(symLabelMenu);
	ui.toolb_symbolSelectBtn->setPopupMode(QToolButton::InstantPopup);
	symLabelMenu->setToolTipsVisible(true);

	addExternTextBtn(symLabelMenu);
	addInternalTextBtn(symLabelMenu);
	addPlaceholderTextBtn(symLabelMenu);

	QMenu *insLabelMenu = new QMenu(this);
	ui.toolb_instructionSelectBtn->setMenu(insLabelMenu);
	ui.toolb_instructionSelectBtn->setPopupMode(QToolButton::InstantPopup);
	insLabelMenu->setToolTipsVisible(true);
	addInstructionTextBtn(insLabelMenu);
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

		originalTrace->save(&rgatstate->config);
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

	if (highlightSelectorDialog.isVisible())		highlightSelectorDialog.hide();
	if (processSelectorDialog.isVisible())		processSelectorDialog.hide();
	if (mouseoverWidget.isVisible())		mouseoverWidget.hide();
	if (highlightSelectorDialog.isVisible())		highlightSelectorDialog.hide();
	if (settingsWindowDialog.isVisible())		settingsWindowDialog.hide();

	event->accept();
}

//drag and drop support
void rgat::dropEvent(QDropEvent *event)
{
	const QMimeData *mimeData = event->mimeData();
	if (mimeData->hasUrls())
	{
		QStringList pathList;
		QList<QUrl> urlList = mimeData->urls();

		for (int i = 0; i < urlList.size(); ++i)
		{
			string filepathstr = urlList.at(i).toLocalFile().toStdString();
			boost::filesystem::path filepath;
			filepath.append(filepathstr);

			binaryTarget *target;

			bool newBinary = rgatstate->targets.getTargetByPath(filepath, &target);
			ui.targetListCombo->addTargetToInterface(target, newBinary);
			rgatstate->config.updateLastPath(filepath);
		}

	}
}

void rgat::addFileMenuBtn()
{
	QMenu *fileLabelMenu = new QMenu(this);
	ui.fileToolBtn->setMenu(fileLabelMenu);
	ui.fileToolBtn->setPopupMode(QToolButton::InstantPopup);
	fileLabelMenu->setToolTipsVisible(true);

	QAction *selectTargAction = new QAction(tr("&Select Target Executable"), this);
	fileLabelMenu->addAction(selectTargAction);
	connect(selectTargAction, SIGNAL(triggered()), ui.targetListCombo, SLOT(addNewTarget()));

	//for when attaching to a process is supported (which is not now)
	//QAction *selectTargAction = new QAction(tr("Select Target From Process"), this);
	//fileLabelMenu->addAction(selectTargAction);
	//connect(selectTargAction, SIGNAL(triggered()), ui.targetListCombo, SLOT(addNewTarget()));
	
	QAction *openSavedTraceAction = new QAction(tr("&Open Saved Trace"), this);
	fileLabelMenu->addAction(openSavedTraceAction);
	connect(openSavedTraceAction, SIGNAL(triggered()), this, SLOT(loadSavedTrace()));
	
	fileLabelMenu->addSeparator();

	QAction *saveCurrentTraceAction = new QAction(tr("&Save Current Trace"), this);
	fileLabelMenu->addAction(saveCurrentTraceAction);
	connect(saveCurrentTraceAction, SIGNAL(triggered()), this, SLOT(startSaveTrace()));

	QAction *saveTargetTraceAction = new QAction(tr("&Save Target Traces"), this);
	fileLabelMenu->addAction(saveTargetTraceAction);
	connect(saveTargetTraceAction, SIGNAL(triggered()), this, SLOT(startSaveTarget()));

	QAction *saveAllTracesAction = new QAction(tr("&Save All Traces"), this);
	fileLabelMenu->addAction(saveAllTracesAction);
	connect(saveAllTracesAction, SIGNAL(triggered()), this, SLOT(startSaveAll()));

	fileLabelMenu->addSeparator();

	QAction *settingsAction = new QAction(tr("&Settings"), this);
	fileLabelMenu->addAction(settingsAction);
	connect(settingsAction, SIGNAL(triggered()), this, SLOT(settingsMenuBtnPressed()));

	fileLabelMenu->addSeparator();

	QAction *exitAction = new QAction(tr("&Exit"), this);
	fileLabelMenu->addAction(exitAction);
	connect(exitAction, SIGNAL(triggered()), this, SLOT(close()));
}

void rgat::settingsMenuBtnPressed()
{
	if (rgatstate->settingsDialog->isVisible())
		rgatstate->settingsDialog->hide();
	else
		rgatstate->settingsDialog->show();
}