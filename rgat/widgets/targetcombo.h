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

#pragma once
#include "qcombobox.h"
#include "binaryTargets.h"
#include "maintabbox.h"
#include "rgatState.h"

class targetCombo :
	public QComboBox
{
	Q_OBJECT
public:
	targetCombo(QWidget *parent = 0);
	~targetCombo();
	void setTargetsPtr(binaryTargets *ptr, mainTabBox *tabs) { targets = ptr; mainTabs = tabs; }
	rgatState * clientState = NULL;
	void addTargetToInterface(binaryTarget *target, bool newBinary);
	void setActiveTarget(binaryTarget * target);


public Q_SLOTS:
	void addNewTarget();
	void setActiveTarget(int index);
	void loadRecent(QString rcnt);

private:
	void addTargetByPath(boost::filesystem::path filepath);

private:
	binaryTargets * targets = NULL;
	mainTabBox *mainTabs = NULL;
	vector<boost::filesystem::path> paths;
};

