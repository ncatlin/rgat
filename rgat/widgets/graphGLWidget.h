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
An OpenGL widget designed to display trace graphs
intended to be inherited eg: (main animated trace display, trace diffs)
*/

#pragma once
#include "qopenglwidget.h"
#include <QtGui\qopenglfunctions_3_0.h>
#include "mathstructs.h"
#include "graph_display_data.h"
#include "rgatState.h"

enum eDisplayMode { eStandardGraph, eHeatMap, eConditional, eDiffView };
enum eDiffMode { eDiffInactive, eDiffSelected, eDiffRendered };

struct TEXTRECT {
	QRect rect;
	NODEINDEX index = INT_MAX;
};


class graphGLWidget :
	public QOpenGLWidget, public QOpenGLFunctions_3_0
{

	Q_OBJECT

public:
	graphGLWidget(QWidget *parent);
	~graphGLWidget();

	double getAspect() { return aspect; }

	void load_VBO(int index, GLuint *VBOs, int bufsize, float *data);
	void loadVBOs(GLuint *VBOs, GRAPH_DISPLAY_DATA *verts, GRAPH_DISPLAY_DATA *lines);

	void gather_projection_data(PROJECTDATA *pd);
	void array_render_points(int POSVBO, int COLVBO, GLuint *buffers, GLsizei quantity);
	void array_render_lines(int POSVBO, int COLVBO, GLuint *buffers, GLsizei quantity);
	void drawBoundingBox(int thickness, QColor colour);
	void drawBox(float x, float y, float w, float h, int thickness, QColor colour);
	void drawRect(float x, float y, float w, float h, QColor colour);
	void drawHighlightLine(FCOORD lineEndPt, QColor &colour);
	bool getMouseoverNode(TEXTRECT *node) { *node = mouseoverNodeRect; return activeMouseoverNode; }
	static rgatState *clientState;
	NODEINDEX mouseoverNode() { return mouseoverNodeRect.index; }

public Q_SLOTS:
	void mouseMoveEvent(QMouseEvent *event);

protected:
	void load_edge_VBOS(GLuint *VBOs, GRAPH_DISPLAY_DATA *lines);
	void array_render(int prim, int POSVBO, int COLVBO, GLuint *buffers, GLsizei quantity);
	void updateAspect();
	virtual void mouseDragged(int dx, int dy){};

	void selectHighlightedAddressNodes(PLOTTEDGRAPH_CASTPTR graph);
	void selectHighlightedSymbolNodes(PLOTTEDGRAPH_CASTPTR graph);
	void selectHighlightedExceptionNodes(PLOTTEDGRAPH_CASTPTR graph);
	void clearHighlightNodes(PLOTTEDGRAPH_CASTPTR graphPtr);

	bool acceptsMouseDrag = false;
	QPoint mousePos;
	bool activeMouseoverNode = false;
	TEXTRECT mouseoverNodeRect = { QRect(0,0,0,0), 0 };

private:
	eDisplayMode displaymode = eStandardGraph;
	eDiffMode diffMode = eDiffInactive;

	double aspect;
};

