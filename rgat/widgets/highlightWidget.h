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
A form to allow selection of trace artifacts (address/symbol/exception/etc) to highlight
*/

#pragma once
#include "qwidget.h"
#include "rgatState.h"
#include "proto_graph.h"

struct symbolInfo {
	QString name;
	vector<NODEINDEX> threadNodes;
	MEM_ADDRESS *address;
};

struct moduleEntry {
	QTreeWidgetItem *entry;
	map <MEM_ADDRESS, symbolInfo> symbols;
};

class highlightWidget :
	public QWidget
{
	Q_OBJECT
public:
	highlightWidget(QWidget *parent = 0);
	~highlightWidget();

	rgatState *clientState = NULL;
	void setup();
	void updateColour();

public Q_SLOTS:
	void exceptionClick();
	void addressClick();
	void modSymClick();
	void closed(int val);
	void startColourSelect();
	void addressChange(QString);

private:
	void updateModSyms(proto_graph *graph);
	void addSymbolToTree(moduleEntry *moduleData, QString symname, node_data *node);
	moduleEntry * getModuleHighlightData(PROCESS_DATA *process, int moduleNumber);

	map<int, moduleEntry> displayedModules;
	QColor highlightColour;

	bool updateStarted = false;
};

