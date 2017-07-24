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

#pragma once
#include "qtreewidget.h"
#include "rgatState.h"

class processTree :
	public QTreeWidget
{

	Q_OBJECT

public:
	processTree(QWidget *parent = 0);
	~processTree();

public Q_SLOTS:
	void activateClicked();
	void activateCloseClicked();

public:
	rgatState *clientState = NULL;
};

