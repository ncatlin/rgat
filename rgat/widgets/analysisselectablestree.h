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
The trace analysis tab to provide text trace data
*/

#pragma once
#include "qtreewidget.h"
#include "traceRecord.h"
#include "proto_graph.h"
#include "rgatState.h"

enum analyzeTabCategory { eAC_TraceProcess, eAC_TraceGraph, eAC_Modules, eAC_ExternalCalls, eAC_Timeline };

class analysisSelectablesTree :
	public QTreeWidget
{
	Q_OBJECT

public:
	analysisSelectablesTree(QWidget *parent = 0);
	~analysisSelectablesTree();
	void updateContents();
	void setClientState(rgatState *statePtr) { clientState = statePtr; }

public Q_SLOTS:
	void analysisItemSelected(QTreeWidgetItem*, int);

private:
	void manageTrace(traceRecord * trace, QTreeWidgetItem* parentItem);
	void addTrace(traceRecord * trace, QTreeWidgetItem* parentItem);

	void updateTraceSelectables(traceRecord * trace, QTreeWidgetItem* traceItem);
	void addTraceAnalysisSelectables(QTreeWidgetItem* threadItem, traceRecord *trace);

	void addChildProcessItems(QTreeWidgetItem* processItem, traceRecord *trace);
	void manageChildProcessListItem(QTreeWidgetItem* processItem, traceRecord *trace);

	void manageThreadsListItem(QTreeWidgetItem* processItem, traceRecord *trace);
	void addThreadItems(QTreeWidgetItem* processItem, traceRecord *trace);
	void updateThreadItem(QTreeWidgetItem* threadItem, proto_graph *graph);
	void addThreadItem(QTreeWidgetItem* threadsItem, proto_graph *graph);

	void addSelectionOptions(QTreeWidgetItem* threadItem, proto_graph *graph);

	void fillAnalysisLog_ExternCalls(proto_graph *graph, bool appendNewUpdates);
	void fillAnalysisLog_Modules(traceRecord *trace, bool appendNewUpdates);

	QTreeWidgetItem* findChildItemStartingWith(QString startString, QTreeWidgetItem* parentItem);

private:
	rgatState *clientState = NULL;

	map <proto_graph *, QTreeWidgetItem*> graphItemsList;
	map <traceRecord *, QTreeWidgetItem*> traceItemsList;
	QTreeWidgetItem* activeItem = NULL;
	unsigned long currentLogLines = 0;
};

