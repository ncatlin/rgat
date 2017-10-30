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
The primary graph display opengl widget
*/

#pragma once
#include "rgatState.h"
#include "graphplots\plotted_graph.h"
#include "graph_display_data.h"
#include "mathstructs.h"
#include "graphGLWidget.h"

class graphPlotGLWidget :
	public graphGLWidget
{

	Q_OBJECT


public:
	graphPlotGLWidget(QWidget *parent = 0);
	~graphPlotGLWidget();

	void tabChanged(bool nowActive);

	

	void initializeGL();
	void resizeGL(int w, int h);
	void paintGL();

	void display_graph_diff(void *diffRenderer, node_data* divergeNode);
	void draw_heatmap_key();
	void draw_conditional_key();

	void mouseDragged(int dx, int dy);

	void addressHighlightSelected();
	void symbolHighlightSelected();
	void exceptionsHighlightSelected();
	void clearHighlights();

public Q_SLOTS:
	void frameTimerFired();
	void irregularTimerFired();

	void wheelEvent(QWheelEvent *event);
	void keyPressEvent(QKeyEvent *event);
	void keyReleaseEvent(QKeyEvent *event);

	void wireframeButtonToggled(bool state);
	void stretchHIncrease();
	void stretchHDecrease();
	void stretchHSet();
	void stretchVIncrease();
	void stretchVDecrease();
	void stretchVSet();
	void plotSizeIncrease();
	void plotSizeDecrease();
	void plotSizeSet(); 
	bool event(QEvent * event) override;

private:

	//debugging stuff
	Qt::Key lastkey = Qt::Key_0;

private:
	
	inline void setupHUDMode();
	inline void drawHUD();
	void draw_heatmap_key_blocks(int x, int y);
	void drawBoundingBox();
	void performIrregularActions();
	void switchToGraph(plotted_graph *graph);
	void selectGraphInActiveTrace();
	bool chooseGraphToDisplay(); 
	bool setMouseoverNode(); 
	void showMouseoverNodeTooltip();

	bool performIrregulars = false;

	QTimer *frameTimer = NULL;
	QTimer *irregularActionTimer = NULL;

	plotted_graph *activeGraph = NULL;

	map <traceRecord *, plotted_graph *> lastGraphs;
};

