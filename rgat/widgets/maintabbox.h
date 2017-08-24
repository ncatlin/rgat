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
A parent QT widget that acts as a signal receiver and manager for much
of the GUI activity around dynamic analysis
*/
#pragma once
#include <qtabwidget>
#include "binaryTargets.h"
#include "rgatState.h"
#include "graphplots/plotted_graph.h"

#define PLAYICON ":/Resources/playico.ico"
#define PAUSEICON ":/Resources/pauseico.ico"

enum rgatTabStacks { eStaticTabs = 0, eDynamicTabs = 1};
enum staticTabs { eStaySameStaticTab = -1, eFileSummaryTab = 0, eStringsTab = 1};
enum dynamicTabs{ eStaySameDynamicTab = -1, eStartTraceTab = 0, eVisualiseTab = 1, eTraceAnalyseTab = 2, eGraphCompareTab = 3, eFuzzTab = 4};
enum controlStacks { eStackReplay = 0, eStackNoTrace = 1, eStackLive = 2 };

struct GRAPHINFO
{
	unsigned long nodes, edges;
	unsigned int processCount;
};

class mainTabBox :
	public QTabWidget
{

	Q_OBJECT

public:
	mainTabBox(QWidget *parent = 0);
	~mainTabBox();
	void updateVisualiserUI(bool fullRefresh);

public Q_SLOTS:
	void changeTarget(binaryTarget *target, dynamicTabs tabToOpen = eStaySameDynamicTab);
	void setPtrs(binaryTargets *targsPtr, rgatState *statePtr) {
		clientState = statePtr; targets = targsPtr;
	}

	void toggleGraphAnimated(bool state);
	void toggleGraphStatic(bool state);
	void tabChanged(int newIndex);
	void killActiveTrace();
	void killActiveTraceAndChildren();
	void playPauseClicked();
	void stopAnimation();
	void speedComboChanged(int index);
	void sliderChanged(int value);
	void processSelectBtnClicked();
	void processComboIndexChange(int index);
	void traceComboIndexChange(int index);
	void startNewTrace();
	void startDiffCompare();
	void nodeBtnPress();
	void edgeBtnPress();
	void renderModeSelected(int index);
	void graphLayoutSelected(int index);
	void highlightDialogBtnClicked();
	void startDynamorioTest();
	void startDrgatTest();

private:
	void updateVisualiseStats(bool fullRefresh = false);
	void refreshProcessesCombo(traceRecord *initialTrace);
	void updateTimerFired();
	int addProcessToGUILists(PROCESS_DATA *trace, QTreeWidgetItem *parentitem);
	void refreshTracesCombo(traceRecord *initialTrace);


private:
	binaryTargets * targets = NULL;
	rgatState *clientState = NULL;
	binaryTarget * activeTarget = NULL;

	//visualiser UI state
	int lastIndex;
	bool liveGraph = false;
	QTimer *updateTimer = NULL;
	time_t lastUpdate;

	GRAPHINFO activeGraphStats;
	vector<traceRecord *> processComboVec;
};

