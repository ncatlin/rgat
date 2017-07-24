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
An opengl widget with a vertical scrollbar to display animated graph previews for selection
*/

#pragma once
#include "graphGLWidget.h"
#include "rgatState.h"
#include "plotted_graph.h"
#include "graph_display_data.h"
#include "mathstructs.h"
#include "qopenglframebufferobject.h"

#define TARGET_FPS 20//60

class previewPlotGLWidget :
	public graphGLWidget
{

	Q_OBJECT

public:
	previewPlotGLWidget(QWidget *parent = 0);
	~previewPlotGLWidget();
	void tabChanged(bool nowActive);
	void resizeGL(int w, int h);
	void paintGL();
	void setScrollBar(QScrollBar *scrollptr) { scrollbar = scrollptr; }
	void clearHighlights();

public Q_SLOTS:
	void frameTimerFired();
	void irregularTimerFired();

	void wheelEvent(QWheelEvent *event);
	void mouseMoveEvent(QMouseEvent *event);
	void mousePressEvent(QMouseEvent *event);
	void sliderMoved(int sliderPosition);
	void sliderMoved();
	void menuSetGraph1();
	void menuSetGraph2();


private:
	void gather_projection_data(PROJECTDATA *pd);
	void initializeGL();
	void drawPreviewGraphToBuffer(plotted_graph *previewgraph);
	void uploadPreviewGraph(plotted_graph *previewgraph);
	void drawPreviewNodesVerts(plotted_graph *previewgraph, int imageWidth);
	void drawPreviewOutline(plotted_graph *previewgraph, int imageWidth);
	void drawPreviewInfo(plotted_graph *graph, int imageWidth, QPainter *painter, int yPos);
	void drawGraphBuffer(int x, int y);
	void refreshPreviewGraphs(bool forceFullCheck);

private:
	QPoint mousePos;
	QTimer *frameTimer = NULL;
	QTimer *irregularTimer = NULL;

	QSplitter *splitterparent;
	QByteArray originalSplitterState;
	QOpenGLFramebufferObject *glframebuf = NULL;
	map <traceRecord *, int> previewScrolls;
	int previewScrollY = 0;
	QScrollBar *scrollbar = NULL;
	vector<plotted_graph *> previewGraphs;
	int testedGraphQty = 0;

	plotted_graph *mouseoverGraph = NULL;
	plotted_graph *contextMenuGraph = NULL;
	plotted_graph *scheduledNewGraph = NULL;

	traceRecord *activeTrace = NULL;

};




