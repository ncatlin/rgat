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
The bulk of the ui functionality had to go somewhere - here it is
This contains much of the functionality for the dynamic analysis tabs
*/

#include "stdafx.h"
#include "ui_rgat.h"
#include "ui_processSelector.h"
#include "ui_highlightSelector.h"
#include "widgets\maintabbox.h"
#include "widgets\graphPlotGLWidget.h"
#include "widgets\highlightWidget.h"
#include "graphplots/plotted_graph.h"
#include "processLaunching.h"
#include "testRun.h"
#include "fuzzRun.h"
#include "ui_moduleIncludeSelector.h"
#include <iomanip>

mainTabBox::mainTabBox(QWidget *parent)
	: QTabWidget(parent)
{
	lastIndex = currentIndex();

	time(&lastUpdate);
	updateTimer = new QTimer(this);
	connect(updateTimer, &QTimer::timeout, this, &mainTabBox::updateTimerFired);
	updateTimer->start(500);

	
	wfOff_action->setCheckable(true);
	connect(wfOff_action, &QAction::triggered, this, [this] {treeWireframeBtnCheck(treeWireframeMode::eWfNone); });
	wfEdges_action->setCheckable(true);
	connect(wfEdges_action, &QAction::triggered, this, [this] {treeWireframeBtnCheck(treeWireframeMode::eWFEdges); });
	wfFaces_action->setCheckable(true);
	connect(wfFaces_action, &QAction::triggered, this, [this] {treeWireframeBtnCheck(treeWireframeMode::eWFFaces); });
	wfFull_action->setCheckable(true);
	connect(wfFull_action, &QAction::triggered, this, [this] {treeWireframeBtnCheck(treeWireframeMode::eWFFull); });
}


mainTabBox::~mainTabBox() { delete updateTimer; }


void mainTabBox::changeTarget(binaryTarget *target, dynamicTabs tabToOpen)
{
	activeTarget = target;

	lastIndex = -1; //ensure refresh of current tab contents

	setCurrentIndex(tabToOpen);

	tabChanged(tabToOpen);
}

void mainTabBox::toggleGraphAnimated(bool state)
{
	if (!state) return;
	plotted_graph *graph = (plotted_graph *)clientState->getActiveGraph(true);
	if (!graph) return;

	graph->setAnimated(true);
	graph->decrease_thread_references(33);
}

void mainTabBox::toggleGraphStatic(bool state)
{
	if (!state) return;
	plotted_graph *graph = (plotted_graph *)clientState->getActiveGraph(true);
	if (!graph) return;

	graph->setAnimated(false);
	graph->decrease_thread_references(44);
}

#ifdef DEBUG
//used to tease out crashes from bad mutex usage when redrawing trace graphs in different layouts
DWORD WINAPI stressThread(LPVOID uiarg)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)uiarg;

	int layout = 0;
	while (true)
	{
		ui->dynamicAnalysisContentsTab->graphLayoutSelected(layout);
		if (layout == 0)
			layout = 1;
		else layout = 0;
		std::this_thread::sleep_for(20ms);
	}
}
#endif 

void mainTabBox::treeWireframeBtnCheck(treeWireframeMode newmode)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	plotted_graph *graph = (plotted_graph *)clientState->getActiveGraph(true);
	if (graph)
	{
		graph->setWireframeActive(newmode);
		graph->decrease_thread_references(44);
	}

	wfOff_action->setChecked(false);
	wfEdges_action->setChecked(false);
	wfFaces_action->setChecked(false);
	wfFull_action->setChecked(false);

	switch (newmode)
	{
		case treeWireframeMode::eWfNone:
			wfOff_action->setChecked(true);
			ui->toolb_wireframeBtn->setChecked(false);
			break;
		case treeWireframeMode::eWFEdges:
			wfEdges_action->setChecked(true);
			ui->toolb_wireframeBtn->setChecked(true);
			break;
		case treeWireframeMode::eWFFaces:
			wfFaces_action->setChecked(true);
			ui->toolb_wireframeBtn->setChecked(true);
			break;
		case treeWireframeMode::eWFFull:
			wfFull_action->setChecked(true);
			ui->toolb_wireframeBtn->setChecked(true);
			break;
		default:
			std::cerr << "Error: bad treeWireframeMode " << newmode << std::endl;
	}

}

void mainTabBox::setWireframeBtnMenu(graphLayouts layout, int wireframeMode)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (currentWireframeLayout != layout)
	{
		if (layout == graphLayouts::eCylinderLayout) 
		{
			ui->toolb_wireframeBtn->setMenu(0);
		}
		else if (layout == graphLayouts::eTreeLayout)
		{
			QMenu *wfmenu = new QMenu(this);
			wfmenu->setToolTipsVisible(true);
			wfmenu->addAction(wfOff_action);
			wfmenu->addAction(wfEdges_action);
			wfmenu->addAction(wfFaces_action);
			wfmenu->addAction(wfFull_action);

			ui->toolb_wireframeBtn->setMenu(wfmenu);
			treeWireframeBtnCheck((treeWireframeMode)wireframeMode);
		}
		else {
			std::cerr << "Bad wireframe layout" << std::endl;
		}

		currentWireframeLayout = layout;
	}
}

void mainTabBox::tabChanged(int newIndex)
{
	if (newIndex == lastIndex) return;
	if (!clientState)
	{
		lastIndex = newIndex;
		return;
	}

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	if (lastIndex == eVisualiseTab)
	{	
		ui->graphPlotGLBox->tabChanged(false);
	}

	if (newIndex == eVisualiseTab)
	{
		//DWORD suppressWarningThreadID;
		//CreateThread(NULL, 0, stressThread, (LPVOID)clientState->ui, 0, &suppressWarningThreadID);

		ui->graphPlotGLBox->tabChanged(true);
		updateVisualiseStats(true);
	}

	if (newIndex == dynamicTabs::eGraphCompareTab)
	{
		if (clientState->getCompareGraph(1) == NULL)
			clientState->emptyComparePane1();

		if (clientState->getCompareGraph(2) == NULL)
			clientState->emptyComparePane2();
	}

	if (newIndex == dynamicTabs::eStartTraceTab)
	{
		((Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI)->blackWhiteListStack->SyncUIWithCurrentBinary();
		ui->traceGatherTab->fillAnalyseTab(clientState->activeBinary);
	}

	if (newIndex == dynamicTabs::eTraceAnalyseTab)
	{
		if(activeTarget)
			ui->traceAnalysisTree->updateContents(activeTarget);
	}

	lastIndex = newIndex;
}

void mainTabBox::updateVisualiserUI(bool fullRefresh = false)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (!activeTarget)
	{
		ui->animControlsStack->setCurrentIndex(controlStacks::eStackNoTrace);
		return;
	}

	//this ensures the controls update when a saved graph is loaded
	if (fullRefresh)
	{
		if (ui->animControlsStack->currentIndex() == controlStacks::eStackLive)
		{
			liveGraph = true;
			ui->animControlsStack->setCurrentIndex(controlStacks::eStackLive);
		}
		else
		{
			liveGraph = false;
			ui->animControlsStack->setCurrentIndex(controlStacks::eStackReplay);
		}
	}

	traceRecord * activeTrace = clientState->activeTrace;
	if (!activeTrace) return;

	if (liveGraph && !activeTrace->isRunning())
	{
		//trace terminated - switch to replay controls
		ui->animControlsStack->setCurrentIndex(controlStacks::eStackReplay);
		liveGraph = false;
	}
	else if (!liveGraph && activeTrace->isRunning())
	{
		liveGraph = true;
		ui->animControlsStack->setCurrentIndex(controlStacks::eStackLive);
	}
	updateVisualiseStats(fullRefresh);
}


void mainTabBox::killActiveTrace()
{
	traceRecord *trace = clientState->activeTrace;
	if (trace) 
		trace->killTraceProcess();
}


void mainTabBox::killActiveTraceAndChildren()
{
	traceRecord *trace = clientState->activeTrace;
	if(trace)
		trace->killTree();
}


void mainTabBox::playPauseClicked()
{
	plotted_graph *graph = (plotted_graph *)clientState->getActiveGraph(true);
	if (!graph) return;
	if (graph->get_protoGraph()->active) { graph->decrease_thread_references(55);  return; }

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	switch (graph->replayState)
	{
	case eStopped: //start replay
		graph->replayState = ePlaying;
		graph->setAnimated(true);
		ui->playBtn->setIcon(style()->standardIcon(QStyle::SP_MediaPause));
		ui->stopBtn->setDisabled(false);
		break;

	case ePlaying: //pause replay
		graph->replayState = ePaused;
		ui->playBtn->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
		break;

	case ePaused: //unpause replay
		graph->replayState = ePlaying;
		ui->playBtn->setIcon(style()->standardIcon(QStyle::SP_MediaPause));
		break;
	}
	graph->decrease_thread_references(56);
}

void mainTabBox::stopAnimation()
{
	plotted_graph *graph = (plotted_graph *)clientState->getActiveGraph(true);
	if (!graph) return;
	if (graph->get_protoGraph()->active) { graph->decrease_thread_references(66);  return; }

	graph->replayState = eStopped;
	graph->setAnimated(false);

	graph->decrease_thread_references(67);

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	ui->playBtn->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
	ui->stopBtn->setDisabled(true);
	ui->replaySlider->setValue(0);
}

void mainTabBox::speedComboChanged(int index)
{
	if (clientState)
		clientState->animationStepRate = (1 << index);
}

void mainTabBox::sliderChanged(int value)
{
	plotted_graph *graph = (plotted_graph *)clientState->getActiveGraph(true);
	if (!graph) return;
	if (graph->get_protoGraph()->active) { graph->decrease_thread_references(77);  return; }

	if (graph->replayState == REPLAY_STATE::eStopped)
	{
		playPauseClicked(); //pretend play was pressed
		playPauseClicked(); //now pause it
	}

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	float animationProportion = (float)value / (float)ui->replaySlider->maximum();
	long long newPos = (unsigned long)(graph->get_protoGraph()->getAnimDataSize()*animationProportion);
	graph->userSelectedAnimPosition = newPos;

	graph->decrease_thread_references(88);
}

//regular (multiple times per second)
void mainTabBox::updateTimerFired()
{
	if (!clientState) return;

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	switch (ui->dynamicAnalysisContentsTab->currentIndex())
	{
	case eVisualiseTab:
		updateVisualiserUI(false);
		break;

	case eTraceAnalyseTab:
		if(activeTarget)
			ui->traceAnalysisTree->updateContents(activeTarget);
		break;
	}


	clientState->maintainStatusbarMessage();
	clientState->updateTracingStatus(clientState->numActiveProcesses());
}


int mainTabBox::addProcessToGUILists(traceRecord * trace, QTreeWidgetItem *parentitem)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	binaryTarget *binary = (binaryTarget *)(trace->get_binaryPtr());
	string filename = binary->path().filename().string();

	int activeProcesses;
	stringstream combostring;
	combostring << trace->PID << "  (" << filename << ")";
	if (trace->is_running())
	{
		activeProcesses = 1;
		combostring << "[Active]";
	}
	else
		activeProcesses = 0;

	ui->processesCombo->addItem(QString::fromStdString(combostring.str()));
	if (trace->PID == clientState->activeTrace->getPID())
		ui->processesCombo->setCurrentIndex(ui->processesCombo->count()-1);
	processComboVec.push_back(trace);

	QString pidstring = QString::number(trace->PID);

	QTreeWidgetItem *procitem = new QTreeWidgetItem;
	procitem->setText(0, pidstring);
	procitem->setText(1, QString::fromStdString(filename));
	procitem->setData(2, Qt::UserRole, qVariantFromValue((void *)trace));

	Ui::processSelector *psui = (Ui::processSelector *)clientState->processSelectUI;
	if (parentitem)
		parentitem->addChild(procitem);
	else
		psui->treeWidget->addTopLevelItem(procitem);

	for (auto it = trace->children.begin(); it != trace->children.end(); it++)
		activeProcesses += addProcessToGUILists(*it, procitem);
	psui->treeWidget->expandAll();

	return activeProcesses;
}

void mainTabBox::refreshProcessesCombo(traceRecord *initialTrace)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	ui->processesCombo->clear();
	processComboVec.clear();

	Ui::processSelector *psui = (Ui::processSelector *)clientState->processSelectUI;
	psui->treeWidget->clear();

	int processesQty = initialTrace->countDescendants();

	int activeProcesses = addProcessToGUILists(initialTrace, NULL); //recursively add each to process combo
	if (initialTrace->UIRunningFlag && activeProcesses == 0)
		initialTrace->UIRunningFlag = false;
	else if(!initialTrace->UIRunningFlag && activeProcesses != 0)
		initialTrace->UIRunningFlag = true;

	stringstream labelStringStream;
	labelStringStream << "Processes (" << activeProcesses << "/" << processesQty << "): ";
	ui->processesLabel->setText(QString::fromStdString(labelStringStream.str()));
}

void mainTabBox::refreshTracesCombo(traceRecord *initialTrace)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	ui->tracesListCombo->clear();

	if (!clientState->activeBinary) return;

	int activeTraceCount = 0;
	//int currentIndex = ui->tracesListCombo->currentIndex();

	ui->tracesListCombo->blockSignals(true);
	list <traceRecord *> tracelist = clientState->activeBinary->getTraceList();
	for (auto traceit = tracelist.begin(); traceit != tracelist.end(); traceit++)
	{
		traceRecord *trace = *traceit;
		stringstream entrySS;
		const time_t startTime = trace->getStartedTime();

		std::stringstream timess;
		timess << std::put_time(std::localtime(&startTime), " (%H:%M:%S %d/%m/%Y)");

		entrySS << "First PID: " << trace->getPID() << timess.str();
		if (trace->UIRunningFlag) //set while iterating through the child processes if any are running
		{
			++activeTraceCount;
			entrySS << " [Active]";
		}

		QString itemText(QString::fromStdString(entrySS.str()));
		ui->tracesListCombo->addItem(itemText);

		if (trace == clientState->activeTrace)
			ui->tracesListCombo->setCurrentIndex(ui->tracesListCombo->count() - 1);
		
	}

	ui->tracesListCombo->blockSignals(false);

	stringstream labelStringStream;
	labelStringStream << "Traces (" << activeTraceCount << "/" << clientState->activeBinary->getTraceListPtr()->size() << "): ";
	ui->tracesLabel->setText(QString::fromStdString(labelStringStream.str()));
}

void mainTabBox::updateVisualiseStats(bool fullRefresh)
{
	if (!clientState || !clientState->activeTrace) return;

	proto_graph *protoGraph = (proto_graph *)clientState->getActiveProtoGraph();
	if (!protoGraph)
	{	
		return;
	}


	if (clientState->processChangeSeen() || fullRefresh)
	{

		//find the initial trace to lay them out in the process displays from the beginning
		traceRecord *traceParent = clientState->activeTrace;
		if (!traceParent)
			return;
		while (traceParent->parentTrace)
			traceParent = traceParent->parentTrace;

		refreshProcessesCombo(traceParent);
		refreshTracesCombo(traceParent);
	}

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	stringstream labelStringStream;
	labelStringStream.str("");
	labelStringStream << "Active Thread ID: " << protoGraph->get_TID();
	ui->threadInfoGroup->setTitle(QString::fromStdString(labelStringStream.str()));
	
	labelStringStream.str("");
	labelStringStream << "Edges: " << protoGraph->edgeList.size();
	ui->edgesLabel->setText(QString::fromStdString(labelStringStream.str()));

	labelStringStream.str("");
	labelStringStream << "Nodes: " << protoGraph->nodeList.size();
	ui->nodesLabel->setText(QString::fromStdString(labelStringStream.str()));

	labelStringStream.str("");
	labelStringStream << "Updates: " << protoGraph->getAnimDataSize();
	ui->updatesLabel->setText(QString::fromStdString(labelStringStream.str()));

	labelStringStream.str("");
	labelStringStream << "Backlog: " << protoGraph->get_backlog_total();
	ui->backlogLabel->setText(QString::fromStdString(labelStringStream.str()));

	plotted_graph *graph = (plotted_graph *)clientState->getActiveGraph(true);
	if (graph) {
		graphLayouts layout = graph->getLayout();
		graph->decrease_thread_references(56);
		setWireframeBtnMenu(layout, graph->wireframeMode);
	}
}

void mainTabBox::moduleIncludeSelectBtnClicked()
{
	if (clientState->includesSelectorDialog->isVisible())
	{
		clientState->includesSelectorDialog->hide();
	}
	else
	{
		Ui::moduleIncludeSelectDialog *includesDlg = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
		includesDlg->blackWhiteListStack->SyncUIWithCurrentBinary();
		clientState->includesSelectorDialog->show();
	}
}

void mainTabBox::processSelectBtnClicked()
{
	if (clientState->processSelectorDialog->isVisible())
	{
		clientState->processSelectorDialog->hide();
	}
	else
	{
		clientState->processSelectorDialog->show();
	}
}

void mainTabBox::highlightDialogBtnClicked()
{
	if (clientState->highlightSelectorDialog->isVisible())
	{
		clientState->highlightSelectorDialog->hide();
	}
	else
	{
		clientState->highlightSelectorDialog->show();
		clientState->highlightSelectorDialog->raise();
		clientState->highlightSelectorDialog->activateWindow();

		Ui::highlightDialog *highlightui = (Ui::highlightDialog *)clientState->highlightSelectUI;
		highlightui->highlightDialogWidget->setup();
	}

}

void mainTabBox::processComboIndexChange(int index)
{
	if (index >= processComboVec.size()) return;

	clientState->switchTrace = processComboVec.at(index);
	clientState->clearActiveGraph();
}


void mainTabBox::traceComboIndexChange(int index)
{
	if (!clientState->activeBinary || index < 0) return;

	list <traceRecord *> traces = clientState->activeBinary->getTraceList();
	if (index < traces.size())
	{
		list <traceRecord *>::iterator traceIt = traces.begin();
		std::advance(traceIt, index);
		clientState->switchTrace = *traceIt;
	}
}


void mainTabBox::startNewTrace()
{
	binaryTarget *activeTarget = clientState->activeBinary;
	if (!activeTarget)
	{
		cerr << " No target to execute... ignoring" << endl;
		return;
	}

	//box should be unclickable to prevent this
	if (!activeTarget->getBitWidth())
		return;

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (ui->showVisCheck->isChecked())
	{
		ui->staticDynamicStack->setCurrentIndex(eDynamicTabs);
		ui->dynamicAnalysisContentsTab->setCurrentIndex(eVisualiseTab);
	}

	clientState->activeTrace = NULL;
	clientState->clearActiveGraph();

	ui->traceGatherTab->refreshLaunchOptionsFromUI(activeTarget);
	Ui::moduleIncludeSelectDialog *moduleWidget = (Ui::moduleIncludeSelectDialog *)clientState->includesSelectorUI;
	moduleWidget->blackWhiteListStack->syncBinaryToUI();
	
	execute_tracer(activeTarget, clientState->config, clientState->getTempDir(), ui->tracePinRadio->isChecked());
	clientState->waitingForNewTrace = true;
}

void mainTabBox::startDiffCompare()
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	if (clientState->validCompareGraphsSet())
		ui->compareGLWidget->plotComparison();
}

void mainTabBox::nodeBtnPress()
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	bool newState = ui->toolb_nodesVisibleBtn->isChecked();
	clientState->setNodesShown(newState);
}

void mainTabBox::edgeBtnPress()
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	bool newState = ui->toolb_edgesVisibleBtn->isChecked();
	clientState->showEdges = newState;
}

void mainTabBox::renderModeSelected(int index)
{
	switch (index)
	{
	case eTraceComboItem:
		clientState->setNodesShown(true);
		clientState->showEdges = true;
		clientState->heatmapMode = false;
		clientState->conditionalsMode = false;
		break;

	case eHeatmapComboItem:
		if (!clientState->heatmapMode)
			clientState->toggleModeHeatmap();
		break;

	case eConditionalComboItem:
		if (!clientState->conditionalsMode)
			clientState->toggleModeConditional();
		break;

	default:
		cerr << "Bad index " << index << " in renderModeSelected" << endl;
	}
}

void mainTabBox::graphLayoutSelected(int index)
{
	if (index != clientState->newGraphLayout) 
		clientState->newGraphLayout = (graphLayouts)index;
}

void mainTabBox::startDynamorioTest()
{
	binaryTarget *activeTarget = clientState->activeBinary;
	if (!activeTarget)
	{
		cerr << " No target to test... ignoring" << endl;
		return;
	}
	if (activeTarget->getBitWidth() != 0)
		execute_dynamorio_compatibility_test(activeTarget, clientState->config);
}

void mainTabBox::startPinTest()
{
	binaryTarget *activeTarget = clientState->activeBinary;
	if (!activeTarget)
	{
		cerr << " No target to test... ignoring" << endl;
		return;
	}
	if (activeTarget->getBitWidth() != 0)
		execute_pin_compatibility_test(activeTarget, clientState->config);
}


void mainTabBox::startDrgatGeneralTests()
{
	boost::filesystem::path testPath = clientState->config.clientPath;
	testPath.append("tests");
	if (!boost::filesystem::exists(testPath)) 
	{
		string errMsg = "Directory " + testPath.string() + " not found - aborting tests";
		clientState->updateActivityStatus(QString::fromStdString(errMsg), 10);
		cerr << errMsg << endl;
		return;
	}

	testRun testingRun(testPath, clientState);
	testingRun.beginTests();
	clientState->testTargets.clear();
}

void mainTabBox::startPingatGeneralTests()
{
	boost::filesystem::path testPath = getModulePath();
	testPath.append("tests");
	if (!boost::filesystem::exists(testPath))
	{
		QString newpath = QFileDialog::getExistingDirectory(this, tr("Select directory containing test binaries"));
		testPath = newpath.toStdString();
		if (!boost::filesystem::exists(testPath))
		{
			string errMsg = "Directory " + testPath.string() + " not found - aborting tests";
			clientState->updateActivityStatus(QString::fromStdString(errMsg), 10);
			cerr << errMsg << endl;
			return;
		}
	}

	testRun testingRun(testPath, clientState);
	testingRun.beginTests();
	clientState->testTargets.clear();
}

void mainTabBox::redrawClicked()
{
	plotted_graph *activegraph = (plotted_graph *)clientState->getActiveGraph(false);
	if (activegraph)
		activegraph->scheduleRedraw();
}