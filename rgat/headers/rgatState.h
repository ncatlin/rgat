#pragma once

#include "binaryTargets.h"
#include "clientConfig.h"
#include "ui_labelMouseoverWidget.h"

#define NO_ACTIVITY_STATUS -9090
#define PERSISTANT_ACTIVITY -9091

enum graphModeComboIndex {eTraceComboItem = 0, eHeatmapComboItem = 1, eConditionalComboItem = 2 };
//must correspond to the visLayoutSelectCombo item order
enum graphLayouts { eCylinderLayout = 0, eTreeLayout = 1, eLayoutInvalid };

struct TEXT_DISPLAY_BUTTONS
{
	QAction *externalShowHide, *externalPath, *externalAddress, *externalAddressOff, *externalOffset;
	QAction *internalShowHide;
	QAction *instructionShowHide, *instructionOffset, *instructionAddress, *instructionAddressOff, *instructionTargLabel,
		*controlOnlyLabel;
};

class rgatState
{
public:
	rgatState() { InitializeCriticalSection(&activeGraphCritsec); };
	~rgatState() { DeleteCriticalSection(&activeGraphCritsec); };


	bool rgatIsExiting() { return rgatExiting; }
	bool openGLWorking() { return haveOpenGL; }
	void setOpenGLFailed() { haveOpenGL = false; }
	int getPreviewAngle();

	void newProcessSeen();
	void processEnded();
	bool processChangeSeen() { bool tmp = processChange; processChange = false; return tmp; }
	void selectActiveTrace(traceRecord *trace = NULL);
	bool validCompareGraphsSet();
	void setCompareGraph(PLOTTEDGRAPH_CASTPTR graph, int index);
	PLOTTEDGRAPH_CASTPTR getCompareGraph(int index);
	void emptyComparePane1();
	void emptyComparePane2();
	void fillComparePane1();
	void fillComparePane2();
	void toggleModeHeatmap();
	void toggleModeConditional();
	void setNodesShown(bool state);
	void InitialiseStatusbarLabels(QLabel *activityLabel, QLabel *tracingLabel)
		{ activityStatusLabel = activityLabel; tracingStatusLabel = tracingLabel; }
	void updateTracingStatus(int activeTraces);
	void updateActivityStatus(QString activityText, int timeout);
	void maintainStatusbarMessage();
	PLOTTEDGRAPH_CASTPTR createNewPlottedGraph(PROTOGRAPH_CASTPTR protoGraph);

	bool should_show_instructions(float zoomMultiplier);
	bool should_show_external_symbols(float zoomMultiplier);
	bool should_show_internal_symbols(float zoomMultiplier);

	void saveTrace(traceRecord *trace);
	void saveTarget(binaryTarget *target);
	void saveAll();
	bool loadTrace(boost::filesystem::path traceFilePath, traceRecord **traceReturnPtr);
	int numActiveProcesses() { return activeTraces; }
	void updateTextDisplayButtons();

	void addFuzzRun(int runid, void *run);
	void fuzztarget_connected(int runid, traceRecord *trace);
	boost::filesystem::path getTempDir();

	binaryTargets targets;
	binaryTargets testTargets;
	clientConfig config;

public:
	//display options
	//options for all graph layouts
	bool showNodes = true;
	bool showEdges = true;
	bool heatmapMode = false;
	bool conditionalsMode = false;
	bool testsRunning = false;

	heatTextDisplayState show_heat_location = eHeatNodes;

	//display options for certain graph layouts
	bool wireframe = true;
	bool showNearSide = false;

public:

	bool waitingForNewTrace = false;

	int animationStepRate = 1;

	void *diffRenderer = NULL;
	void *maingraphRenderer = NULL;

	void *ui = NULL;
	void *processSelectUI = NULL, *highlightSelectUI = NULL, 
		*includesSelectorUI = NULL;
	QDialog *processSelectorDialog = NULL, *highlightSelectorDialog = NULL, 
		*includesSelectorDialog = NULL;

	void *labelMouseoverUI = NULL;
	mouseoverFrame *labelMouseoverWidget = NULL;

	PLOTTEDGRAPH_CASTPTR getActiveGraph(bool increaseReferences);
	void clearActiveGraph();
	bool setActiveGraph(PLOTTEDGRAPH_CASTPTR graph);
	PROTOGRAPH_CASTPTR getActiveProtoGraph();
	void mouseoverLabelChanged();

	PLOTTEDGRAPH_CASTPTR switchGraph = NULL;
	binaryTarget *activeBinary = NULL;
	traceRecord *activeTrace = NULL;
	traceRecord *switchTrace = NULL;

	graphLayouts newGraphLayout = (graphLayouts)0;
	bool savingFlag = false;

	QPixmap mainGraphBMP;
	QFont instructionFont = QFont("Helvetica", 8);
	TEXT_DISPLAY_BUTTONS textButtons;
	QStyle* widgetStyle;

private:

	PLOTTEDGRAPH_CASTPTR activeGraph = NULL;

	bool should_show_labels(float zoomMultiplier, SYMS_VISIBILITY *labels);
	void loadChildTraces(vector<boost::filesystem::path> childrenFiles, traceRecord *trace);
	bool initialiseTrace(rapidjson::Document *saveJSON, traceRecord **trace, binaryTarget *target);

	PLOTTEDGRAPH_CASTPTR compareGraph1 = NULL, compareGraph2 = NULL;
	QLabel *tracingStatusLabel = NULL, *activityStatusLabel = NULL;
	int activityStatusTimeout = NO_ACTIVITY_STATUS;
	std::chrono::system_clock::time_point lastUpdate;

	bool processChange = false;
	bool rgatExiting = false;
	bool haveOpenGL = true;
	int previewAngleDegrees = 0;
	int activeTraces = 0;

	map<int, void *> pendingFuzzruns;

	CRITICAL_SECTION activeGraphCritsec;

	boost::filesystem::path tempDir;
};