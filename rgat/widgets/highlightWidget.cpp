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
#include "stdafx.h"
#include "widgets\highlightWidget.h"
#include "ui_rgat.h"
#include "ui_highlightSelector.h"

highlightWidget::highlightWidget(QWidget *parent)
	:QWidget(parent)
{
}


highlightWidget::~highlightWidget()
{
}

//update the colour of the colour selection button to match the current colour
void highlightWidget::updateColour()
{
	Ui::highlightDialog *highlightui = (Ui::highlightDialog *)clientState->highlightSelectUI;
	QString stylesheet;

	highlightColour = clientState->config.mainColours.highlightLine;
	stylesheet = "color: " + highlightColour.name() + "; ";

	if (clientState->heatmapMode)
		stylesheet = stylesheet + "background-color: " + clientState->config.heatmap.background.name() + ";";
	else if (clientState->conditionalsMode)
		stylesheet = stylesheet + "background-color: " + clientState->config.conditional.background.name() + ";";
	else
		stylesheet = stylesheet + "background-color: " + clientState->config.mainColours.background.name() + ";";

	//highlightui->addressLabel->setText("Address:"); 
	highlightui->colourSelectorBtn->setStyleSheet(stylesheet);
}


void highlightWidget::addSymbolToTree(moduleEntry *moduleData, QString symName, node_data *node)
{
	MEM_ADDRESS symbolAddress = node->address;
	symbolInfo thisSymInfo;
	thisSymInfo.name = symName;
	thisSymInfo.threadNodes.push_back(node->index);

	moduleData->symbols.emplace(make_pair(symbolAddress, thisSymInfo));

	QTreeWidgetItem *modsymitem = new QTreeWidgetItem;
	modsymitem->setText(0, NULL);
	modsymitem->setText(1, thisSymInfo.name);
	modsymitem->setText(2, "0x" + QString::number(symbolAddress, 16));
	modsymitem->setData(3, Qt::UserRole, qVariantFromValue((void *)&moduleData->symbols.at(symbolAddress)));

	moduleData->entry->addChild(modsymitem);
}

//returns the data for [module moduleNumber] in the item tree, adding a new one if non existant
moduleEntry *highlightWidget::getModuleHighlightData(PROCESS_DATA *process, int moduleNumber)
{
	Ui::highlightDialog *highlightui = (Ui::highlightDialog *)clientState->highlightSelectUI;

	auto activeModuleIt = displayedModules.find(moduleNumber);
	if (activeModuleIt == displayedModules.end())
	{
		boost::filesystem::path modpath;
		process->get_modpath(moduleNumber, &modpath);

		QTreeWidgetItem *moduleItem = new QTreeWidgetItem;
		moduleItem->setText(0, QString::fromStdWString(modpath.filename().wstring()));
		moduleItem->setText(1, "("+QString::fromStdWString(modpath.wstring())+")");
		moduleItem->setText(2, NULL);
		moduleItem->setData(3, Qt::UserRole, qVariantFromValue(moduleNumber));

		highlightui->modSymTree->addTopLevelItem(moduleItem);

		displayedModules[moduleNumber].entry = moduleItem;
	
		return &displayedModules.at(moduleNumber);
	}
	
	return &activeModuleIt->second;
}

void highlightWidget::updateModSyms(proto_graph *graph)
{
	if (!updateStarted)
		updateStarted = true;
	else
		return;

	PROCESS_DATA *piddata = graph->get_piddata();

	Ui::highlightDialog *highlightui = (Ui::highlightDialog *)clientState->highlightSelectUI;
	highlightui->modSymTree->clear();
	displayedModules.clear();

	NODEINDEX nodeIndex;
	vector<NODEINDEX> externalnodes = graph->copyExternalNodeList();
	foreach(nodeIndex, externalnodes)
	{
		node_data* node = graph->safe_get_node(nodeIndex);
		moduleEntry *moduleData = getModuleHighlightData(piddata, node->globalModID);

		map <MEM_ADDRESS, symbolInfo>::iterator symIt = moduleData->symbols.find(node->address);
		if (symIt == moduleData->symbols.end())
		{
			string symName;
			MEM_ADDRESS offset = node->address - piddata->modBounds.at(node->globalModID)->first;
			if(piddata->get_sym(node->globalModID, offset, symName))
				addSymbolToTree(moduleData, QString::fromStdString(symName), node);
			else
				addSymbolToTree(moduleData, "[No Symbol]", node);
		}
		else
			symIt->second.threadNodes.push_back(nodeIndex);
	}

	for (int i = 0; i < 3; i++)
		highlightui->modSymTree->resizeColumnToContents(i);

	updateStarted = false;
}

//call with the bg colour of the current gl widget
void highlightWidget::setup()
{
	updateColour();
	proto_graph *activeProto = (proto_graph *)clientState->getActiveProtoGraph();
	if (activeProto)
	{
		updateModSyms(activeProto);

		Ui::highlightDialog *highlightui = (Ui::highlightDialog *)clientState->highlightSelectUI;

		size_t exceptionQty = activeProto->exceptionSet.size();
		if (exceptionQty == 1)
			highlightui->exceptionsHighlightLabel->setText("1 Exception");
		else
			highlightui->exceptionsHighlightLabel->setText(QString::number(exceptionQty) + " Exceptions");
	}
}

void highlightWidget::addressClick()
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (ui->dynamicAnalysisContentsTab->currentIndex() == eGraphCompareTab)
	{
		//
	}
	else
	{
		ui->graphPlotGLBox->addressHighlightSelected();
	}
}

void highlightWidget::modSymClick()
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (ui->dynamicAnalysisContentsTab->currentIndex() == eGraphCompareTab)
	{
		//
	}
	else
	{
		ui->graphPlotGLBox->symbolHighlightSelected();
	}
}

void highlightWidget::exceptionClick()
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (ui->dynamicAnalysisContentsTab->currentIndex() == eGraphCompareTab)
	{
		//
	}
	else
	{
		ui->graphPlotGLBox->exceptionsHighlightSelected();
	}
}


void highlightWidget::closed(int val)
{
	Ui::highlightDialog *highlightui = (Ui::highlightDialog *)clientState->highlightSelectUI;
	if (!highlightui->clearCheckBox->isChecked()) return;

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	if (ui->dynamicAnalysisContentsTab->currentIndex() == eGraphCompareTab)
	{
		//
	}
	else
	{
		ui->graphPlotGLBox->clearHighlights();
	}
}

void highlightWidget::startColourSelect()
{
	QColor newColor = QColorDialog::getColor(highlightColour);
	highlightColour = newColor;
	clientState->config.mainColours.highlightLine = newColor;
	clientState->config.saveConfig();
	updateColour();
}


void highlightWidget::addressChange(QString addressString)
{
	Ui::highlightDialog *highlightui = (Ui::highlightDialog *)clientState->highlightSelectUI;
	MEM_ADDRESS address = addressString.toLongLong(0, 16);

	//find address in disassembly of whole process

	
	proto_graph *activeGraph = (proto_graph *)clientState->getActiveProtoGraph();
	if (!activeGraph) return;

	bool addressFound = false;
	PROCESS_DATA *processdata = activeGraph->get_piddata();
	processdata->getDisassemblyReadLock();
	auto addressIt = processdata->disassembly.find(address);
	if (addressIt != processdata->disassembly.end())
		addressFound = true;
	processdata->dropDisassemblyReadLock();

	if (!addressFound)
	{
		processdata->getExternDictReadLock();
		auto externIt = processdata->externdict.find(address);
		if (externIt != processdata->externdict.end())
			addressFound = true;
		processdata->dropExternDictReadLock();
	}

	if (addressFound)
	{
		highlightui->addressEdit->setStyleSheet({ "border: 2px solid green" });
	}
	else
	{
		highlightui->addressEdit->setStyleSheet({ "border: 2px solid red" });
	}

}