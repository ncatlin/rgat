#include "stdafx.h"
#include "rgatState.h"
#include "graphplots/plotted_graph.h"
#include "ui_rgat.h"
#include "serialise.h"
#include "graphplots/plotted_graph_layouts.h"

double rgatState::getPreviewAngle() 
{
	if (config.preview.rotationEnabled)
	{
		previewAngleDegrees += config.preview.spinPerFrame;
		if (previewAngleDegrees > 360) previewAngleDegrees -= 360;
	}
	return previewAngleDegrees;
}

//activate a trace in the active binary (the target in the top dropdown)
//activates the first trace with instrumented thread activity if none passed as argument
void rgatState::selectActiveTrace(traceRecord *trace)
{
	activeGraph = NULL;

	if (!trace && activeBinary)
	{
		//waiting for a shiny new trace user just launched
		if (waitingForNewTrace)
			return;
		trace = activeBinary->getFirstTrace();
	}

	activeTrace = trace;
}

bool rgatState::validCompareGraphsSet()
{
	return (compareGraph1 && compareGraph2);
}

void rgatState::setCompareGraph(PLOTTEDGRAPH_CASTPTR graph, int index)
{
	
	Ui::rgatClass *myui = (Ui::rgatClass *)ui;
	myui->compareGLWidget->resetRenderer();

	if (index == 1)
	{
		compareGraph1 = graph;
		fillComparePane1();
		if (compareGraph2 == graph)
		{
			compareGraph2 = NULL;
			emptyComparePane2();
		}
	}
	else if (index == 2)
	{
		compareGraph2 = graph;
		fillComparePane2();
		if (compareGraph1 == graph)
		{
			compareGraph1 = NULL;
			emptyComparePane1();
		}
	}
	else
	{
		cerr << "[rgat]ERROR: Bad index [" << index << "] to setCompareGraph()" << endl;
		assert(false);
	}
}

PLOTTEDGRAPH_CASTPTR rgatState::getCompareGraph(int index)
{
	if (index == 1)
		return compareGraph1;
	else if (index == 2)
		return compareGraph2;


	cerr << "[rgat]ERROR: Bad index [" << index << "] to getCompareGraph()" << endl;
	assert(false);
	return NULL;
}



//these are kinda out of place here
void rgatState::fillComparePane1()
{
	Ui::rgatClass *myui = (Ui::rgatClass *)ui;
	plotted_graph *graph = (plotted_graph *)compareGraph1;
	if (!graph) return;

	QString graphExe = "Graph A: " + QString::fromStdWString(activeBinary->path().filename().wstring());
	myui->graph1Group->setTitle(graphExe);
	myui->graph1PathLabel->clear();
	myui->graph1PIDLabel->setText("PID: " + QString::number(graph->get_pid()));
	myui->graph1TIDLabel->setText("TID: " + QString::number(graph->get_tid()));
}

void rgatState::emptyComparePane1()
{
	Ui::rgatClass *myui = (Ui::rgatClass *)ui;
	QString graphExe = "Graph B: No target set";
	myui->graph1Group->setTitle(graphExe);
	myui->graph1PathLabel->setText("Right click in visualiser preview pane to set");
	myui->graph1PIDLabel->setText("PID: - ");
	myui->graph1TIDLabel->setText("TID: - ");
}

void rgatState::fillComparePane2()
{
	Ui::rgatClass *myui = (Ui::rgatClass *)ui;
	plotted_graph *graph = (plotted_graph *)compareGraph2;
	if (!graph) return;

	QString graphExe = "Graph 2: " + QString::fromStdWString(activeBinary->path().filename().wstring());
	myui->graph2Group->setTitle(graphExe);
	myui->graph2PIDLabel->setText("PID: " + QString::number(graph->get_pid()));
	myui->graph2TIDLabel->setText("TID: " + QString::number(graph->get_tid()));
}

void rgatState::emptyComparePane2()
{
	Ui::rgatClass *myui = (Ui::rgatClass *)ui;
	QString graphExe = "Graph 2: No target set";
	myui->graph2Group->setTitle(graphExe);
	myui->graph2PathLabel->setText("Right click in visualiser preview pane to set");
	myui->graph2PIDLabel->setText("PID: - ");
	myui->graph2TIDLabel->setText("TID: - ");
}

bool rgatState::should_show_labels(float zoomMultiplier, SYMS_VISIBILITY *labels)
{
	if (labels->enabled)
	{
		if (labels->showWhenZoomed)
			return (labels->autoVisibleZoom > zoomMultiplier);
		else
			return true;
	}
	else
		return false;
}

bool rgatState::should_show_instructions(float zoomMultiplier)
{
	return should_show_labels(zoomMultiplier, &config.instructionTextVisibility);
}

bool rgatState::should_show_external_symbols(float zoomMultiplier)
{
	return should_show_labels(zoomMultiplier, &config.externalSymbolVisibility);
}

bool rgatState::should_show_internal_symbols(float zoomMultiplier)
{
	return should_show_labels(zoomMultiplier, &config.internalSymbolVisibility);
}

bool rgatState::should_show_placeholder_labels(float zoomMultiplier)
{
	return should_show_labels(zoomMultiplier, &config.placeholderLabelVisibility);
}

void rgatState::toggleModeHeatmap()
{
	heatmapMode = !heatmapMode;
	conditionalsMode = false;

	setNodesShown(!heatmapMode);
	Ui::rgatClass *myui = (Ui::rgatClass *)ui;
	if (heatmapMode)
		myui->graphModeCombo->setCurrentIndex(eHeatmapComboItem);
	else
		myui->graphModeCombo->setCurrentIndex(eTraceComboItem);

}

void rgatState::toggleModeConditional()
{
	conditionalsMode = !conditionalsMode;
	heatmapMode = false;

	Ui::rgatClass *myui = (Ui::rgatClass *)ui;
	if (conditionalsMode == true)
	{
		setNodesShown(true);
		myui->graphModeCombo->setCurrentIndex(eConditionalComboItem);
	}
	else
	{
		myui->graphModeCombo->setCurrentIndex(eTraceComboItem);
	}

}

void rgatState::setNodesShown(bool state)
{
	showNodes = state;

	Ui::rgatClass *myui = (Ui::rgatClass *)ui;
	myui->toolb_nodesVisibleBtn->setChecked(state);
}

void rgatState::saveAll()
{
	int saveCount = 0;
	vector<binaryTarget *> targetsList = targets.getTargetsList();
	for(auto targetIt = targetsList.begin(); targetIt != targetsList.end(); targetIt++)
	{
		binaryTarget *target = *targetIt;
		updateActivityStatus("Saving Target: " + QString::fromStdString(target->path().string()), 10000);
		saveTarget(target);
		saveCount++;
	}

	QString savemsg ("Finished saving " + QString::number(saveCount) + " targets");
	updateActivityStatus(savemsg, 7000);
}


void rgatState::saveTarget(binaryTarget *target)
{
	traceRecord *trace;
	list<traceRecord *> traces = target->getTraceList();
	foreach(trace, traces)
	{
		trace->save(&config);
	}
}






bool initialiseTarget(rapidjson::Document *saveJSON, binaryTargets *targets, Ui::rgatClass *myui, binaryTarget ** targetPtr)
{
	rapidjson::Value::ConstMemberIterator pathIt = saveJSON->FindMember("BinaryPath");
	if (pathIt == saveJSON->MemberEnd())
	{
		return false;
	}
	boost::filesystem::path binaryPath = pathIt->value.GetString();

	binaryTarget * target;

	bool newBinary = targets->getTargetByPath(binaryPath, &target);
	myui->targetListCombo->addTargetToInterface(target, newBinary);
	*targetPtr = target;

	return true;
}

//return true if a new trace was created, false if failed or duplicate
//todo should have 3 returns
bool rgatState::initialiseTrace(rapidjson::Document *saveJSON, traceRecord **trace, binaryTarget *target)
{
	PID_TID tracePID;
	int tracePID_ID;
	long long timeStarted;

	rapidjson::Value::ConstMemberIterator PIDDataIt = saveJSON->FindMember("PID");
	rapidjson::Value::ConstMemberIterator PID_ID_DataIt = saveJSON->FindMember("PID_ID");
	rapidjson::Value::ConstMemberIterator timeIt = saveJSON->FindMember("StartTime");
	if ((PIDDataIt == saveJSON->MemberEnd()) ||
		(PID_ID_DataIt == saveJSON->MemberEnd()) ||
		(timeIt == saveJSON->MemberEnd()))
	{
		cout << "[rgat]Warning: Trace metadata not found. Load failed." << endl;
		return false;
	}

	if (!PIDDataIt->value.IsInt64() || !PIDDataIt->value.IsInt() || !timeIt->value.IsInt64())
	{
		cout << "[rgat]Warning: Corrupt trace metadata. Load failed." << endl;
		return false;
	}
	
	tracePID = PIDDataIt->value.GetInt64();
	tracePID_ID = PID_ID_DataIt->value.GetInt();
	timeStarted = timeIt->value.GetInt64();

	bool newTrace = target->createTraceAtTime(trace, timeStarted, tracePID, tracePID_ID);
	if (!newTrace)
	{
		updateActivityStatus("Trace already loaded", 15000);
		cout << "[rgat] Trace already loaded" << endl;
		return false;
	}
	(*trace)->setTraceType(eTracePurpose::eVisualiser);

	updateActivityStatus("Loaded saved process: " + QString::number(tracePID), 15000);
	return true;
}

void extractChildTraceFilenames(rapidjson::Document &saveJSON, vector<boost::filesystem::path> *childrenFiles)
{
	rapidjson::Value::ConstMemberIterator pathsArray = saveJSON.FindMember("Children");
	if (pathsArray != saveJSON.MemberEnd())
	{
		rapidjson::Value::ConstValueIterator pathsArrayIt = pathsArray->value.Begin();
		for (; pathsArrayIt != pathsArray->value.End(); pathsArrayIt++)
		{
			childrenFiles->push_back(pathsArrayIt->GetString());
		}
	}
}

void rgatState::loadChildTraces(vector<boost::filesystem::path> childrenFiles, traceRecord *trace)
{
	boost::filesystem::path childtraceFile;
	foreach(childtraceFile, childrenFiles)
	{
		boost::filesystem::path childFilePath = config.saveDir;
		childFilePath /= childtraceFile;

		if (!boost::filesystem::equivalent(childFilePath.parent_path(), config.saveDir))
			return;	//avoid directory traversal

		if (!boost::filesystem::exists(childFilePath))
		{
			cerr << "[rgat] Warning: Tried to load child save file '" << childtraceFile.string() << "' but it was not found at " << childFilePath.string() << endl;
			return;
		}

		traceRecord *childTrace;
		loadTrace(childFilePath, &childTrace);
		trace->children.push_back(childTrace);
		childTrace->parentTrace = trace;
	}
}

bool rgatState::loadTrace(boost::filesystem::path traceFilePath, traceRecord **traceReturnPtr)
{
	//display_only_status_message("Loading save file...", clientState);
	updateActivityStatus("Loading " + QString::fromStdString(traceFilePath.string()) + "...", 2000);

	rapidjson::Document saveJSON;
	if (!getJSON(traceFilePath, &saveJSON))
		return false;

	binaryTarget * target;
	if (!initialiseTarget(&saveJSON, &targets, (Ui::rgatClass *)ui, &target))
	{
		updateActivityStatus("Process data load failed - possibly corrupt trace file", 15000);
		return false;
	}

	traceRecord * trace = NULL;
	if (!initialiseTrace(&saveJSON, &trace, target))
	{
		if (trace) //already existed
		{
			switchTrace = trace;
		}

		return false;
	}

	if (!trace->load(saveJSON, config.graphColours))
		return false;

	if (traceReturnPtr)
		*traceReturnPtr = trace;

	vector<boost::filesystem::path> childrenFiles;
	extractChildTraceFilenames(saveJSON, &childrenFiles);
	updateActivityStatus("Loaded " + QString::fromStdString(traceFilePath.filename().string()), 15000);

	if (!childrenFiles.empty())
		loadChildTraces(childrenFiles, trace);

	return true;
}

void rgatState::updateTracingStatus(int numactiveTraces)//no need for arg
{
	tracingStatusLabel->setText("Traces Active: " + QString::number(numactiveTraces));
}

void rgatState::updateActivityStatus(QString activityText, int timeoutMS)
{
	activityStatusLabel->setText(activityText);
	if (timeoutMS == PERSISTANT_ACTIVITY || timeoutMS == 0)
		activityStatusTimeout = PERSISTANT_ACTIVITY;
	else
	{
		activityStatusTimeout = timeoutMS;
		lastUpdate = std::chrono::system_clock::now();
	}
}

/*
call with how often this is called

the statusbar message duration is very fuzzy at the sub-500ms mark
this is called every 500ms but the message might have only been set 1ms before that
to compensate we set timedout messages to LAST_GASP_ACTIVITY_DISPLAY so they last at least one full update
only messages in this state get cleared
*/
void rgatState::maintainStatusbarMessage()
{

	if (activityStatusTimeout == NO_ACTIVITY_STATUS) 
		return;
	else
	{
		std::chrono::system_clock::time_point timeNow = std::chrono::system_clock::now();
		std::chrono::system_clock::duration timeGap = timeNow - lastUpdate;

		long long timeSinceLastUpdate = std::chrono::duration_cast<std::chrono::milliseconds>(timeGap).count();
		activityStatusTimeout -= min((long long)1000, timeSinceLastUpdate);

		if (activityStatusTimeout < 1)
		{
			activityStatusTimeout = NO_ACTIVITY_STATUS;
			activityStatusLabel->clear();
		}

		lastUpdate = timeNow;
	}
}

void rgatState::newProcessSeen() 
{ 
	processChange = true; 
	++activeTraces;
}


void rgatState::processEnded()
{
	processChange = true;
	--activeTraces;
}

#include <qstyle.h>
void rgatState::updateTextDisplayButtons()
{
	//-------------------external symbols----------------
	if (config.externalSymbolVisibility.enabled)
	{
		textButtons.externalShowHide->setIcon(widgetStyle->standardIcon(QStyle::SP_DialogYesButton));
		textButtons.externalShowHide->setStatusTip(QCoreApplication::tr("External symbols being displayed when zoomed in. Click to hide."));
	}
	else
	{
		textButtons.externalShowHide->setIcon(widgetStyle->standardIcon(QStyle::SP_DialogNoButton));
		textButtons.externalShowHide->setStatusTip(QCoreApplication::tr("External symbols hidden. Click to display."));
	}

	if (config.externalSymbolVisibility.addresses)
	{
		if (config.externalSymbolVisibility.offsets)
		{
			textButtons.externalOffset->setChecked(true);
			textButtons.externalAddress->setChecked(false);
			textButtons.externalAddressOff->setChecked(false);
		}
		else
		{
			textButtons.externalOffset->setChecked(false);
			textButtons.externalAddress->setChecked(true);
			textButtons.externalAddressOff->setChecked(false);
		}
	}
	else
	{
		textButtons.externalOffset->setChecked(false);
		textButtons.externalAddress->setChecked(false);
		textButtons.externalAddressOff->setChecked(true);
	}


	//-------------------internal/debugging symbols----------------
	if (config.internalSymbolVisibility.enabled)
	{
		textButtons.internalShowHide->setIcon(widgetStyle->standardIcon(QStyle::SP_DialogYesButton));
		textButtons.internalShowHide->setStatusTip(QCoreApplication::tr("Internal symbols being displayed when zoomed in. Click to hide."));
	}
	else
	{
		textButtons.internalShowHide->setIcon(widgetStyle->standardIcon(QStyle::SP_DialogNoButton));
		textButtons.internalShowHide->setStatusTip(QCoreApplication::tr("Internal symbols not being displayed. Click to show."));
	}

	//-------------------autogenerated placeholders for functions without symbols----------------
	if (config.placeholderLabelVisibility.enabled)
	{
		textButtons.placeholderShowHide->setIcon(widgetStyle->standardIcon(QStyle::SP_DialogYesButton));
		textButtons.placeholderShowHide->setStatusTip(QCoreApplication::tr("Placeholder labels being displayed when zoomed in. Click to hide."));
	}
	else
	{
		textButtons.placeholderShowHide->setIcon(widgetStyle->standardIcon(QStyle::SP_DialogNoButton));
		textButtons.placeholderShowHide->setStatusTip(QCoreApplication::tr("Placeholder labels not being displayed. Click to show."));
	}

	//-------------------instruction text----------------
	if (config.instructionTextVisibility.enabled)
	{
		textButtons.instructionShowHide->setIcon(widgetStyle->standardIcon(QStyle::SP_DialogYesButton));
		textButtons.instructionShowHide->setStatusTip(QCoreApplication::tr("Instruction text displayed when zoomed in. Click to hide."));
	}
	else
	{
		textButtons.instructionShowHide->setIcon(widgetStyle->standardIcon(QStyle::SP_DialogNoButton));
		textButtons.instructionShowHide->setStatusTip(QCoreApplication::tr("Instruction text hidden. Click to display when zoomed in."));
	}
	textButtons.instructionShowHide->setChecked(config.instructionTextVisibility.enabled);


	if (config.instructionTextVisibility.addresses)
	{
		if (config.instructionTextVisibility.offsets)
		{

			textButtons.instructionOffset->setChecked(true);
			textButtons.instructionAddress->setChecked(false);
			textButtons.instructionAddressOff->setChecked(false);

		}
		else
		{
			textButtons.instructionOffset->setChecked(false);
			textButtons.instructionAddress->setChecked(true);
			textButtons.instructionAddressOff->setChecked(false);
		}
	}
	else
	{
		textButtons.instructionOffset->setChecked(false);
		textButtons.instructionAddress->setChecked(false);
		textButtons.instructionAddressOff->setChecked(true);
	}

	if (config.instructionTextVisibility.fullPaths)
	{
		textButtons.instructionTargLabel->setStatusTip(QCoreApplication::tr("Displaying label of jump/call targets, if available. Click to show address."));
	}
	else
	{
		textButtons.instructionTargLabel->setStatusTip(QCoreApplication::tr("Displaying address of jump/call targets. Click to show label, if available"));
	}
	textButtons.instructionTargLabel->setChecked(config.instructionTextVisibility.fullPaths);

	textButtons.controlOnlyLabel->setChecked(!config.instructionTextVisibility.extraDetail);
}

PLOTTEDGRAPH_CASTPTR rgatState::createNewPlottedGraph(PROTOGRAPH_CASTPTR protoGraphPtr)
{
	plotted_graph *newGraph = NULL;
	proto_graph * protoGraph = (proto_graph *)protoGraphPtr;
	
	switch (newGraphLayout)
	{
	case eCylinderLayout:
		{
			newGraph = new cylinder_graph(protoGraph->get_TID(), protoGraph, &config.graphColours);
			break;
		}
	case eTreeLayout:
		{
			newGraph = new tree_graph(protoGraph->get_TID(), protoGraph, &config.graphColours);
			break;
		}
	default:
		{
			cout << "Bad graph layout: " << newGraphLayout << endl;
			assert(0);
		}
	}
	return (PLOTTEDGRAPH_CASTPTR)newGraph;
}

PLOTTEDGRAPH_CASTPTR rgatState::getActiveGraph(bool increaseReferences)
{
	if (activeGraph && ((plotted_graph *)activeGraph)->needsReleasing())
		return NULL;

	activeGraphLock.lock();

	if (!activeGraph)
	{
		activeGraphLock.unlock();
		return NULL;
	}

	if (increaseReferences)
	{
		bool success = ((plotted_graph *)activeGraph)->increase_thread_references(52);
		if (!success)
		{
			activeGraphLock.unlock();
			return NULL;
		}
		//cout << "[+1: "<< ((plotted_graph *)activeGraph)->threadReferences << "]increased refs to graph " << activeGraph << endl;
	}
	PLOTTEDGRAPH_CASTPTR tmp = activeGraph;
	activeGraphLock.unlock();

	return tmp;
}

void rgatState::clearActiveGraph()
{
	activeGraphLock.lock();
	if (!activeGraph) 
	{
		activeGraphLock.unlock();
		return;
	}

	((plotted_graph *)activeGraph)->decrease_thread_references(50);
	activeGraph = NULL;
	activeGraphLock.unlock();
}

bool rgatState::setActiveGraph(PLOTTEDGRAPH_CASTPTR graph)
{

	if (activeGraph && ((plotted_graph *)activeGraph)->isBeingDeleted())
		return false;

	clearActiveGraph();

	assert(activeGraph == NULL);

	activeGraphLock.lock();
	if (((plotted_graph *)graph)->increase_thread_references(50))
	{
		activeGraph = graph;
	}
	activeGraphLock.unlock();
	return true;
}

PROTOGRAPH_CASTPTR rgatState::getActiveProtoGraph()
{
	PROTOGRAPH_CASTPTR tmp = NULL;
	activeGraphLock.lock();
	plotted_graph *activePlot = (plotted_graph *)activeGraph;
	if (activePlot && activePlot->increase_thread_references(51))
	{
		tmp = activePlot->get_protoGraph();
		activePlot->decrease_thread_references(51);
	}
	activeGraphLock.unlock();

	return tmp;
}


void rgatState::addFuzzRun(int runid, void *run)
{
	activeGraphLock.lock();
	pendingFuzzruns.emplace(make_pair(runid, run));
	activeGraphLock.unlock();
}


void rgatState::fuzztarget_connected(int runid, traceRecord *trace)
{
	activeGraphLock.lock();
	auto fuzzrunIt = pendingFuzzruns.find(runid);
	if (fuzzrunIt != pendingFuzzruns.end())
	{
		fuzzRun *pendingrun = (fuzzRun *)fuzzrunIt->second;
		pendingrun->target_connected(trace);
		pendingFuzzruns.erase(fuzzrunIt);
	}
	else
	{
		cerr << "[rgat-fuzz] ERROR: unknown fuzz session connected: " << runid << " (pending runs: "<< pendingFuzzruns.size()<<")"<< endl;
	}
	activeGraphLock.unlock();
}

void rgatState::mouseoverLabelChanged()
{
	plotted_graph *graph = (plotted_graph *)activeGraph;
	if (!graph) return;

	Ui_mouseoverWidget* tooltipwidget = (Ui_mouseoverWidget*)labelMouseoverUI;
	QString newNodeText = tooltipwidget->labelEdit->text();
	node_data *n = graph->get_protoGraph()->safe_get_node(((Ui::rgatClass *)ui)->graphPlotGLBox->mouseoverNode());

	if (newNodeText.isEmpty())
	{
		n->label = "[ ]";
		n->ins->hasSymbol = false;
	}
	else
	{
		n->label = newNodeText;
		n->placeholder = false;
		n->ins->hasSymbol = true;
	}
}

boost::filesystem::path rgatState::getTempDir()
{
	if (tempDir.empty())
	{
		if (!createTempDir(tempDir))
		{
			cerr << "[rgat] Failed to create temporary IPC directory. Error: 0x" << std::hex << GetLastError() << endl;
		}
	}
	return tempDir;
}