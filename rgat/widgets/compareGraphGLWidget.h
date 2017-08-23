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
A graph display gl widget specialised to handle trace diffs
*/

#pragma once
#include "rgatState.h"
#include "graphplots/plotted_graph.h"
#include "graph_display_data.h"
#include "mathstructs.h"
#include "graphGLWidget.h"
#include "diff_plotter.h"

enum diffWidgetIndex { eDiffWidgetStackNone = 0, eDiffWidgetStackSelected = 1 };

class compareGraphGLWidget :
	public graphGLWidget
{

	Q_OBJECT

public:
	compareGraphGLWidget(QWidget *parent = 0);
	~compareGraphGLWidget();

	void plotComparison();

	void initializeGL();
	void resizeGL(int w, int h);
	void paintGL();
	void mouseDragged(int dx, int dy);
	void resetRenderer();

public Q_SLOTS:
	void frameTimerFired();
	void wheelEvent(QWheelEvent *event);

private:

	diff_plotter *plotter = NULL;
	plotted_graph *diff_graph = NULL;

	double aspect;

	QTimer *frameTimer = NULL;
};

