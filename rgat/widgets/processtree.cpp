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
A tree listing processes and their children to make selecting the right trace easier
*/

#include "stdafx.h"
#include "widgets\processtree.h"
#include "ui_processSelector.h"
#include "traceRecord.h"

processTree::processTree(QWidget *parent)
{
}


processTree::~processTree()
{
}

void processTree::activateClicked()
{
	Ui::processSelector *psui = (Ui::processSelector *)clientState->processSelectUI;
	auto selecteditems = psui->treeWidget->selectedItems();

	if (selecteditems.empty())
		return;

	QVariant traceValue = psui->treeWidget->currentItem()->data(2, Qt::UserRole);
	traceRecord *selectedTrace = (traceRecord *)traceValue.value<void *>();

	clientState->switchTrace = selectedTrace;
	clientState->clearActiveGraph();
}


void processTree::activateCloseClicked()
{
	activateClicked();
	clientState->processSelectorDialog->hide();
}