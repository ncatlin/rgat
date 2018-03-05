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
The targets combo box at the top of the interface.
Also handles creating new targets.
*/

#include "stdafx.h"
#include "targetcombo.h"
#include "maintabbox.h"
#include <boost\filesystem.hpp>
#include "ui_rgat.h"

targetCombo::targetCombo(QWidget *parent)
	: QComboBox(parent)
{

}


targetCombo::~targetCombo()
{
}

void targetCombo::setActiveTarget(binaryTarget * target)
{
	if (!targets->exists(target) || (target == clientState->activeBinary)) return;

	clientState->activeBinary = target;
	clientState->clearActiveGraph();
	clientState->activeTrace = NULL;
	mainTabs->changeTarget(target, eVisualiseTab);

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

	ui->traceGatherTab->fillAnalyseTab(target);
}

void targetCombo::setActiveTarget(int index)
{
	if (index == -1 || paths.size() <= index) return;

	boost::filesystem::path activePath = paths.at(index);
	if (activePath.size() == 0) return;

	binaryTarget * target;

	targets->getTargetByPath(activePath, &target);
	if (target)
		setActiveTarget(target);
}

void targetCombo::addTargetToInterface(binaryTarget *target, bool newBinary)
{
	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	boost::filesystem::path filepath = target->path();
	if (newBinary)
	{

		if (paths.empty())
		{
			//get rid of the [hey you should add a target] text
			removeItem(0);
		}

		paths.push_back(target->path());

		stringstream targetSS;
		targetSS << "[" << paths.size()-1 << "]" << "   " << filepath.string();
		QString targetDisplayString = QString::fromStdString(targetSS.str());


		addItem(targetDisplayString);
		setCurrentIndex(count() - 1);

		ui->staticDynamicStack->setCurrentIndex(eDynamicTabs);

		ui->dynamicAnalysisContentsTab->setCurrentIndex(eStartTraceTab);
	}
	else
	{
		auto vecpos = std::find(paths.begin(), paths.end(), filepath);
		assert(vecpos != paths.end());
		setCurrentIndex(vecpos - paths.begin());
		ui->dynamicAnalysisContentsTab->setCurrentIndex(eStartTraceTab);
	}

	ui->traceGatherTab->fillAnalyseTab(target);

}


void targetCombo::addNewTarget()
{
	//crash when right click in this dialog https://bugreports.qt.io/browse/QTBUG-33119?page=com.atlassian.jira.plugin.system.issuetabpanels%3Aall-tabpanel
	QString fileName = QFileDialog::getOpenFileName(this,
		tr("Select new target"), clientState->config.getLastPathString(),
		tr("Executable (*.exe);;Library (*.dll);;All Files (*.*)"));

	boost::filesystem::path filepath(fileName.toStdString());
	if (!boost::filesystem::exists(filepath))
		return;

	binaryTarget *target;

	bool newBinary = targets->getTargetByPath(filepath, &target);

	addTargetToInterface(target, newBinary);

	clientState->config.updateLastPath(filepath);


}