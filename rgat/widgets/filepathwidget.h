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
Displays some basic static analysis and provides tracing/instrumentation options + launch control
*/
#pragma once
#include "qwidget.h"
//#include "headers\binaryTarget.h"
//#include "headers\rgatState.h"

class filePathWidget :
	public QWidget
{

	Q_OBJECT

public:
	filePathWidget(QWidget *parent = 0);
	~filePathWidget();

};

