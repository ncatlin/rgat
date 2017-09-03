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

#include "stdafx.h"
#include "widgets\analysisselectablestree.h"
#include "ui_rgat.h"

#define HEADERLINE QString("------------------------------")

analysisSelectablesTree::analysisSelectablesTree(QWidget *parent):
	QTreeWidget(parent)
{
	header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
}


analysisSelectablesTree::~analysisSelectablesTree()
{
	
}

void analysisSelectablesTree::fillAnalysisLog_ExternCalls(proto_graph *graph, bool appendNewUpdates)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	QTextCursor text_cursor = QTextCursor(ui->traceAnalysisTextBox->document());

	if (!appendNewUpdates)
	{
		ui->traceAnalysisTextBox->clear();
		text_cursor.movePosition(QTextCursor::Start);
		traceRecord *trace = (traceRecord *)graph->get_piddata()->tracePtr;
		binaryTarget *targ = (binaryTarget *)trace->get_binaryPtr();

		QString header = "External calls from " + QString::fromStdString(targ->path().string()) + ", thread ID " + QString::number(graph->get_TID());
		text_cursor.insertText(header + "\n");
		text_cursor.insertText(HEADERLINE + "\n");
	}

	size_t recordsCount = graph->externCallRecords.size();
	unsigned long startPosition = appendNewUpdates ? currentLogLines : 0;
	//check if symbols in graph > previous count
	//if it is, add extras to log
	for (currentLogLines = startPosition; currentLogLines < recordsCount; currentLogLines++)
	{
		
		text_cursor.movePosition(QTextCursor::End);
		EXTERNCALLDATA *calldata = &graph->externCallRecords.at(currentLogLines);

		node_data *node = graph->safe_get_node(calldata->edgeIdx.second);
		assert(node->external);

		string symbol = graph->get_node_sym(calldata->edgeIdx.second);
		string argstring = generate_funcArg_string(symbol, &calldata->argList);

		text_cursor.insertText(QString::fromStdString(argstring) + "\n");
	}
}


void analysisSelectablesTree::fillAnalysisLog_Modules(traceRecord *trace, bool appendNewUpdates)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	if (!appendNewUpdates)
		ui->traceAnalysisTextBox->clear();

	map <int, boost::filesystem::path> modpaths = trace->get_piddata()->modpaths;

	size_t recordsCount = modpaths.size();
	unsigned long startPosition = appendNewUpdates ? currentLogLines : 0;
	//check if symbols in graph > previous count
	//if it is, add extras to log
	for (currentLogLines = startPosition; currentLogLines < recordsCount; currentLogLines++)
	{
		QTextCursor text_cursor = QTextCursor(ui->traceAnalysisTextBox->document());
		text_cursor.movePosition(QTextCursor::End);

		text_cursor.insertText(QString::fromStdString(modpaths.at(currentLogLines).string()) + "\n");
	}
}


void analysisSelectablesTree::analysisItemSelected(QTreeWidgetItem* selectedItem, int index)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	QVariant itemTypeVariant = ui->traceAnalysisTree->currentItem()->data(1, Qt::UserRole);
	analyzeTabCategory itemType = (analyzeTabCategory)itemTypeVariant.value<int>();
	QVariant supplementaryData = ui->traceAnalysisTree->currentItem()->data(2, Qt::UserRole);

	string itemName = selectedItem->text(0).toStdString();
	switch (itemType)
	{
	case eAC_ExternalCalls:
	{
		currentLogLines = 0;
		activeItem = selectedItem;
		proto_graph * graph = (proto_graph *)supplementaryData.value<void *>();
		fillAnalysisLog_ExternCalls(graph, false);
		break;
	}

	case eAC_Modules:
	{
		currentLogLines = 0;
		activeItem = selectedItem;
		traceRecord * trace = (traceRecord *)supplementaryData.value<void *>();
		fillAnalysisLog_Modules(trace, false);
		break;
	}


	case eAC_Timeline:
	{
	}
	}

}


void addSelectionOptionsInternal(QTreeWidgetItem* parentItem, void *data, vector <pair<QString, analyzeTabCategory>> *optionsList)
{
	pair<QString, analyzeTabCategory> option;
	foreach(option, *optionsList)
	{
		QTreeWidgetItem* optionItem = new QTreeWidgetItem();
		optionItem->setText(0, option.first);
		optionItem->setData(1, Qt::UserRole, qVariantFromValue((int)option.second));
		optionItem->setData(2, Qt::UserRole, qVariantFromValue((void *)data));
		parentItem->insertChild(0, optionItem);
	}
}


//add a thread and its options to a process item in the analysis selection pane
void analysisSelectablesTree::addSelectionOptions(QTreeWidgetItem* threadItem, proto_graph *graph)
{
	QTreeWidgetItem* optionItem = new QTreeWidgetItem();
	QString symCallsString = "Symbol Calls (" + QString::number(graph->externCallRecords.size()) + ")";
	optionItem->setText(0, symCallsString);
	optionItem->setData(1, Qt::UserRole, qVariantFromValue((int)eAC_ExternalCalls));
	optionItem->setData(2, Qt::UserRole, qVariantFromValue((void *)graph));
	threadItem->addChild(optionItem);
}

//add a process and its options to the analysis option selection pane
void analysisSelectablesTree::addTraceAnalysisSelectables(QTreeWidgetItem* traceItem, traceRecord *trace)
{
	QTreeWidgetItem* optionItem = new QTreeWidgetItem();
	QString symCallsString = "Loaded Modules (" + QString::number(trace->get_piddata()->modpaths.size()) + ")";
	optionItem->setText(0, symCallsString);
	optionItem->setData(1, Qt::UserRole, qVariantFromValue((int)eAC_Modules));
	optionItem->setData(2, Qt::UserRole, qVariantFromValue((void *)trace));
	traceItem->addChild(optionItem);

	optionItem = new QTreeWidgetItem();
	optionItem->setText(0, "Timeline");
	optionItem->setData(1, Qt::UserRole, qVariantFromValue((int)eAC_Timeline));
	optionItem->setData(2, Qt::UserRole, qVariantFromValue((void *)trace));
	traceItem->addChild(optionItem);
}

void analysisSelectablesTree::addThreadItem(QTreeWidgetItem* threadsItem, proto_graph *graph)
{
	QTreeWidgetItem* threadItem = new QTreeWidgetItem();
	PID_TID graphTid = graph->get_TID();
	threadItem->setText(0, "TID " + QString::number(graphTid));
	threadItem->setData(1, Qt::UserRole, qVariantFromValue((int)eAC_TraceGraph));
	threadItem->setData(2, Qt::UserRole, qVariantFromValue((void *)graph));
	threadsItem->insertChild(threadsItem->childCount(), threadItem);

	addSelectionOptions(threadItem, graph);
	graphItemsList[graph] = threadItem;
}

void analysisSelectablesTree::manageChildProcessListItem(QTreeWidgetItem* childProcessesItem, traceRecord *trace)
{
	traceRecord *childTrace;
	int numChildren = 0;
	foreach(childTrace, trace->children)
	{
		map <traceRecord *, QTreeWidgetItem*>::iterator traceItemsListIt = traceItemsList.find(trace);
		if (traceItemsListIt == traceItemsList.end())
		{
			addTrace(childTrace, childProcessesItem);
		}
		else
		{
			manageTrace(childTrace, traceItemsListIt->second);
		}
		++numChildren;
	}

	QString processesString = "Child Processes (" + QString::number(numChildren) + ")";
	childProcessesItem->setText(0, processesString);
}

void analysisSelectablesTree::addThreadItems(QTreeWidgetItem* processItem, traceRecord *trace)
{
	vector <proto_graph *> graphs;
	trace->getProtoGraphs(&graphs);

	QTreeWidgetItem* threadsItem = new QTreeWidgetItem();
	QString threadsString = "Threads (" + QString::number(graphs.size()) + ")";
	threadsItem->setText(0, threadsString);
	threadsItem->setData(1, Qt::UserRole, qVariantFromValue(0));
	threadsItem->setData(2, Qt::UserRole, qVariantFromValue(0));
	processItem->insertChild(processItem->childCount(), threadsItem);

	proto_graph *graph;
	foreach(graph, graphs)
	{
		addThreadItem(threadsItem, graph);
	}
}

QTreeWidgetItem* analysisSelectablesTree::findChildItemStartingWith(QString startString, QTreeWidgetItem* parentItem)
{
	for(int i = 0; i < parentItem->childCount(); ++i)
	{
		QTreeWidgetItem *childItem = parentItem->child(i);
		if (childItem->text(0).startsWith(startString))
			return childItem;
	}
	return NULL;
}

void analysisSelectablesTree::manageThreadsListItem(QTreeWidgetItem* threadsListItem, traceRecord *trace)
{
	vector <proto_graph *> graphs;
	trace->getProtoGraphs(&graphs);

	QString threadsString = "Threads (" + QString::number(graphs.size()) + ")";
	threadsListItem->setText(0, threadsString);

	proto_graph *graph;
	foreach(graph, graphs)
	{
		map <proto_graph *, QTreeWidgetItem*>::iterator threadItemsIt = graphItemsList.find(graph);
		if (threadItemsIt != graphItemsList.end())
			updateThreadItem(threadItemsIt->second, graph);
		else
			addThreadItem(threadsListItem, graph);
	}
}

void analysisSelectablesTree::updateThreadItem(QTreeWidgetItem* threadItem, proto_graph *graph)
{
	QTreeWidgetItem *item;
	for(int i = 0; i < threadItem->childCount(); ++i)
	{
		item = threadItem->child(i);
		QVariant itemTypeVariant = item->data(1, Qt::UserRole);
		analyzeTabCategory itemType = (analyzeTabCategory)itemTypeVariant.value<int>();

		switch(itemType)
		{
		case eAC_ExternalCalls:
			{
				size_t callQty = graph->externCallRecords.size();
				
				QString newText = "Symbol Calls (" + QString::number(callQty) + ")";
				item->setText(0, newText);

				if ((item == activeItem) && (callQty > currentLogLines))
				{
					fillAnalysisLog_ExternCalls(graph, true);
				}
				continue;
			}
		}
	}
}


void analysisSelectablesTree::addChildProcessItems(QTreeWidgetItem* processItem, traceRecord *trace)
{
	if (trace->children.empty())
		return;

	QTreeWidgetItem* childProcessItem = new QTreeWidgetItem();
	childProcessItem->setData(1, Qt::UserRole, qVariantFromValue(0));
	childProcessItem->setData(2, Qt::UserRole, qVariantFromValue(0));
	processItem->insertChild(processItem->childCount(), childProcessItem);

	traceRecord *childTrace;
	int numChildren = 0;
	foreach(childTrace, trace->children)
	{
		addTrace(childTrace, childProcessItem);
		++numChildren;
	}

	QString processesString = "Child Processes (" + QString::number(numChildren) + ")";
	childProcessItem->setText(0, processesString);
}

//adding trace from scratch
void analysisSelectablesTree::addTrace(traceRecord * trace, QTreeWidgetItem* parentTraceItem)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	QTreeWidgetItem* traceItem = new QTreeWidgetItem();
	binaryTarget *traceBinary = (binaryTarget *)trace->get_binaryPtr();
	PID_TID processPid = trace->getPID();
	QString filename = QString(traceBinary->path().filename().string().c_str());
	traceItem->setText(0, filename + " (PID " + QString::number(processPid) + ")");
	traceItem->setData(1, Qt::UserRole, qVariantFromValue((int)eAC_TraceProcess));
	traceItem->setData(2, Qt::UserRole, qVariantFromValue((void *)trace));

	addTraceAnalysisSelectables(traceItem, trace);

	if (parentTraceItem)
	{
		parentTraceItem->addChild(traceItem);
	}
	else
	{
		ui->traceAnalysisTree->insertTopLevelItem(ui->traceAnalysisTree->topLevelItemCount(), traceItem);
	}

	traceItemsList[trace] = traceItem;
	addThreadItems(traceItem, trace);
	addChildProcessItems(traceItem, trace);
}

//adding trace from scratch
void analysisSelectablesTree::updateTraceSelectables(traceRecord * trace, QTreeWidgetItem* traceItem)
{
	QTreeWidgetItem *item;
	for (int i = 0; i < traceItem->childCount(); ++i)
	{
		item = traceItem->child(i);
		QVariant itemTypeVariant = item->data(1, Qt::UserRole);
		analyzeTabCategory itemType = (analyzeTabCategory)itemTypeVariant.value<int>();

		switch (itemType)
		{
		case eAC_Modules:
			{
				size_t moduleQty = trace->get_piddata()->modpaths.size();
				QString newText = "Loaded Modules (" + QString::number(moduleQty) + ")";
				item->setText(0, newText);

				if ((item == activeItem) && (moduleQty > currentLogLines))
				{
					fillAnalysisLog_Modules(trace, true);
				}
				continue; 
			}
		}
	}
}



//if trace doesn't exist, adds it to top level (or a parent trace, if specified)
//if trace does exist, updates selectables with new data, new threads etc
void analysisSelectablesTree::manageTrace(traceRecord * trace, QTreeWidgetItem* parentItem)
{
	map <traceRecord *, QTreeWidgetItem*>::iterator traceItemListIt = traceItemsList.find(trace);
	if (traceItemListIt != traceItemsList.end())
	{
		QTreeWidgetItem* traceItem = traceItemListIt->second;

		updateTraceSelectables(trace, traceItem);

		QTreeWidgetItem* threadsListItem = findChildItemStartingWith("Threads (", traceItem);
		if (threadsListItem)
			manageThreadsListItem(threadsListItem, trace);

		QTreeWidgetItem* childrenListItem = findChildItemStartingWith("Child Processes (", traceItem);
		if (childrenListItem)
		{
			manageChildProcessListItem(childrenListItem, trace);
		}
		else 
		{
			addChildProcessItems(traceItem, trace);
		}
	}
	else
	{
		addTrace(trace, parentItem);
	}
}

void analysisSelectablesTree::updateContents(binaryTarget *binary)
{

	list <traceRecord *> traceList = binary->getTraceList();
	for (auto it = traceList.begin(); it != traceList.end(); it++)
	{
		manageTrace(*it, NULL);
	}
}
