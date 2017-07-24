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

#include "stdafx.h"
#include "widgets\previewPlotGLWidget.h"
#include <gl/GLU.h>
#include <gl/GL.h>
#include "graphicsmaths.h"
#include "diff_plotter.h"
#include "widgets\maintabbox.h"
#include "ui_rgat.h"

previewPlotGLWidget::previewPlotGLWidget(QWidget *parent)
	: graphGLWidget(parent)
{
	frameTimer = new QTimer(this);
	connect(frameTimer, &QTimer::timeout,
		this, &previewPlotGLWidget::frameTimerFired);

	irregularTimer = new QTimer(this);
	connect(irregularTimer, &QTimer::timeout,
		this, &previewPlotGLWidget::irregularTimerFired);
	irregularTimer->start(800);

	this->setMouseTracking(true);
	setEnabled(true);

	mousePos.setX(0);
	mousePos.setY(0);

	splitterparent = (QSplitter*)parent;
	splitterparent->setStyleSheet("QSplitter::handle{background: rgb(93,93,93);}");
	originalSplitterState = splitterparent->saveState();
}


previewPlotGLWidget::~previewPlotGLWidget()
{
	if (glframebuf)	delete glframebuf;
}




//this call is a bit sensitive and will give odd results if called in the wrong place
void previewPlotGLWidget::gather_projection_data(PROJECTDATA *pd)
{
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	glGetDoublev(GL_MODELVIEW_MATRIX, pd->model_view);
	glGetDoublev(GL_PROJECTION_MATRIX, pd->projection);
	glGetIntegerv(GL_VIEWPORT, pd->viewport);
}



void previewPlotGLWidget::tabChanged(bool nowActive)
{
	previewGraphs.clear();
	mouseoverGraph = NULL;

	if (nowActive)
	{
		
		//frameTimer->start(1 / clientState->config.renderFrequency);
		frameTimer->start(1000 / TARGET_FPS);

		if (clientState->activeTrace)
		{
			auto it = previewScrolls.find(clientState->activeTrace);
			if (it != previewScrolls.end())
				previewScrollY = it->second;
		}
	}
	else
	{
		frameTimer->stop();
	}
}

void previewPlotGLWidget::initializeGL()
{
	initializeOpenGLFunctions();

	glEnable(GL_ALPHA_TEST);
	glEnable(GL_BLEND);
	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_COLOR_ARRAY);

	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_DEPTH_TEST);
	glDepthFunc(GL_ALWAYS);

	glPointSize(DEFAULTPOINTSIZE);
	glClearColor(0, 0, 0, 1.0);


	assert(glframebuf == NULL);
	if (!glframebuf)
		glframebuf = new QOpenGLFramebufferObject(PREVIEW_GRAPH_WIDTH, PREVIEW_GRAPH_HEIGHT,
			QOpenGLFramebufferObject::NoAttachment, GL_TEXTURE_2D, GL_RGBA32F);


	glframebuf->release();

	frameTimer->start(50);

	scrollbar->setPageStep(2*(PREVIEW_GRAPH_HEIGHT + PREVIEW_GRAPH_PADDING_Y));
	scrollbar->setSingleStep((PREVIEW_GRAPH_HEIGHT + PREVIEW_GRAPH_PADDING_Y));
}

void previewPlotGLWidget::mouseMoveEvent(QMouseEvent *event)
{
	event->setAccepted(true);

	if (event->buttons() == 0)
	{
		mousePos = event->pos();
		int scrolledPaneYPos = mousePos.y() + scrollbar->value();
		scrolledPaneYPos -= PREVIEW_GRAPH_PADDING_Y;

		int graphID = scrolledPaneYPos / (PREVIEW_GRAPH_HEIGHT + PREVIEW_GRAPH_PADDING_Y);
		int graphYOffset = scrolledPaneYPos % (PREVIEW_GRAPH_HEIGHT + PREVIEW_GRAPH_PADDING_Y);

		if (graphYOffset < 0 || graphYOffset > PREVIEW_GRAPH_HEIGHT)
			graphID = -1;

		if ((mousePos.x() < PREVIEW_GRAPH_PADDING_X) || (mousePos.x() > (PREVIEW_GRAPH_WIDTH + PREVIEW_GRAPH_PADDING_X)))
			graphID = -1;

		if (graphID >= 0 && graphID < previewGraphs.size())
			mouseoverGraph = previewGraphs.at(graphID);
		else
			mouseoverGraph = NULL;
	}
}


void previewPlotGLWidget::menuSetGraph1()
{
	clientState->setCompareGraph(contextMenuGraph, 1);
}

void previewPlotGLWidget::menuSetGraph2()
{
	clientState->setCompareGraph(contextMenuGraph, 2);
}

void previewPlotGLWidget::mousePressEvent(QMouseEvent *event)
{
	if (!mouseoverGraph) return;

	if (event->button() != Qt::RightButton)
	{
		clientState->switchGraph = mouseoverGraph;
		clientState->clearActiveGraph();
		return;
	}
	
	contextMenuGraph = mouseoverGraph;

	QMenu menu;
	menu.addSection("Graph Comparison");
	menu.addAction(tr("Set Comparison Target A"), this, SLOT(menuSetGraph1()));
	menu.addAction(tr("Set Comparison Target B"), this, SLOT(menuSetGraph2()));
	menu.addSeparator();
	menu.addSection("Other");
	//menu.addAction(tr("Delete"), tree, SLOT(removeOne()));
	menu.exec(QCursor::pos());
}


void previewPlotGLWidget::wheelEvent(QWheelEvent *event)
{
	scrollbar->setValue(scrollbar->value() - event->delta());
}

void previewPlotGLWidget::frameTimerFired()
{
	if (!clientState || !clientState->activeTrace || clientState->switchGraph)
		return;

	if (width() < 10) return;
	update();
}

void previewPlotGLWidget::sliderMoved(int sliderPosition)
{
	if (splitterparent->sizes().at(1) == 0)
		splitterparent->restoreState(originalSplitterState);

	if (!clientState->activeTrace || sliderPosition == -1)
		return;

	//auto it = previewScroll.find(clientState->activeTrace);
	previewScrolls.emplace(make_pair(clientState->activeTrace, sliderPosition));
	previewScrollY = sliderPosition;
}

void previewPlotGLWidget::sliderMoved()
{
	sliderMoved(-1);
}

void previewPlotGLWidget::uploadPreviewGraph(plotted_graph *previewgraph)
{
	GLuint *VBOs = previewgraph->previewVBOs;

	int nodesToLoad = previewgraph->previewnodes->get_numVerts();
	load_VBO(VBO_NODE_POS, VBOs, POSITION_VERTS_SIZE(nodesToLoad), previewgraph->previewnodes->readonly_pos());
	load_VBO(VBO_NODE_COL, VBOs, COLOUR_VERTS_SIZE(nodesToLoad), previewgraph->previewnodes->readonly_col());
	previewgraph->previewnodes->set_numLoadedVerts(nodesToLoad);

	int linesVertsToLoad = previewgraph->previewlines->get_numVerts();
	if (!linesVertsToLoad) return;

	vector<float> *lineVector = 0;

	lineVector = previewgraph->previewlines->acquire_pos_read(25);
	if (previewgraph->previewlines->get_numVerts() == 0 || lineVector->empty())
	{
		previewgraph->previewlines->release_pos_read();
		return;
	}

	load_VBO(VBO_LINE_POS, VBOs, POSITION_VERTS_SIZE(linesVertsToLoad), &lineVector->at(0));
	previewgraph->previewlines->release_pos_read();

	lineVector = previewgraph->previewlines->acquire_col_read();
	assert(!lineVector->empty());
	load_VBO(VBO_LINE_COL, VBOs, COLOUR_VERTS_SIZE(linesVertsToLoad), &lineVector->at(0));
	previewgraph->previewlines->release_col_read();

	previewgraph->previewlines->set_numLoadedVerts(linesVertsToLoad);
	previewgraph->needVBOReload_preview = false;
}

void previewPlotGLWidget::drawPreviewNodesVerts(plotted_graph *previewgraph, int imageWidth)
{
	//initialise graphics buffers for the graph if needed
	if (!previewgraph->VBOsGenned)
		previewgraph->gen_graph_VBOs(this);

	//upload any new render data to graphics buffers
	if (previewgraph->needVBOReload_preview)
		uploadPreviewGraph(previewgraph);
	
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	gluPerspective(45, imageWidth / PREVIEW_GRAPH_HEIGHT, 1, 12000);

	//glMatrixMode(GL_MODELVIEW);
	glPushMatrix();
	glTranslatef(0, 0, previewgraph->previewZoom() + 2 * width());
	glTranslatef(0, previewgraph->prevScrollYPosition(), 0);
	glRotatef(90.0 + clientState->getPreviewAngle(), 0, 1, 0);
	

	array_render_points(VBO_NODE_POS, VBO_NODE_COL, previewgraph->previewVBOs, previewgraph->previewnodes->get_numLoadedVerts());
	array_render_lines(VBO_LINE_POS, VBO_LINE_COL, previewgraph->previewVBOs, previewgraph->previewlines->get_numLoadedVerts());

	glPopMatrix();

}

void previewPlotGLWidget::drawPreviewOutline(plotted_graph *graph, int imageWidth)
{
	QColor outlineColour;
	bool threadIsRunning = graph->get_protoGraph()->active;
	bool graphNotSelected = (graph != clientState->getActiveGraph(false));
	int borderThickness;

	glMatrixMode(GL_PROJECTION);
	glPushMatrix();
	glLoadIdentity();
	glOrtho(0.0f, imageWidth, PREVIEW_GRAPH_HEIGHT, 0.0f, 0.0f, 10.0f);

	if (graphNotSelected)
	{
		borderThickness = 1;
		outlineColour = threadIsRunning ? al_col_dull_green : al_col_dull_red;
		drawBox(0, borderThickness, imageWidth - borderThickness, PREVIEW_GRAPH_HEIGHT - borderThickness, borderThickness, outlineColour);
	}
	else
	{
		borderThickness = 2;
		outlineColour = threadIsRunning ? al_col_green : al_col_red;
		drawBox(1, borderThickness, imageWidth - borderThickness -1, PREVIEW_GRAPH_HEIGHT - borderThickness, borderThickness, outlineColour);
	}

	glPopMatrix();
}

void previewPlotGLWidget::drawPreviewInfo(plotted_graph *graph, int imageWidth, QPainter *painter, int yPos)
{
	stringstream infoTxt;
	infoTxt << "TID: " << graph->get_tid();

	

	proto_graph *proto = graph->get_protoGraph();
	unsigned long newIn = proto->getBacklogIn();
	if (newIn > 5)
		infoTxt << "  in:" << newIn;

	unsigned long backlog = proto->get_backlog_total();
	if (backlog > 200)
		infoTxt << " Q:" << backlog;

	painter->drawText(10, yPos + 15, QString::fromStdString(infoTxt.str()));

	if (clientState->getCompareGraph(1) == graph)
		painter->drawText(15, yPos + PREVIEW_GRAPH_HEIGHT - 15, "Comparison A");
	else if (clientState->getCompareGraph(2) == graph)
		painter->drawText(15, yPos + PREVIEW_GRAPH_HEIGHT - 15, "Comparison B");
}


void previewPlotGLWidget::drawPreviewGraphToBuffer(plotted_graph *thisPreviewGraph)
{
	
	if (!glframebuf->isBound())
		glframebuf->bind();
	

	//draw red/green background depending on if thread is still running
	QColor previewBackgroundColour;
	if (thisPreviewGraph->get_protoGraph()->active)
		previewBackgroundColour = clientState->config.preview.activeHighlight;
	else
		previewBackgroundColour = clientState->config.preview.inactiveHighlight;
	glClearColor(previewBackgroundColour.redF(), previewBackgroundColour.greenF(), previewBackgroundColour.blueF(), previewBackgroundColour.alphaF());
	glClear(GL_COLOR_BUFFER_BIT);

	glMatrixMode(GL_PROJECTION);
	glViewport(0, 0, PREVIEW_GRAPH_WIDTH, PREVIEW_GRAPH_HEIGHT);
	glLoadIdentity();
	glOrtho(0.0f, PREVIEW_GRAPH_WIDTH, PREVIEW_GRAPH_HEIGHT, 0.0f, 0.0f, 10.0f);
	


	//draw the graph
	drawPreviewNodesVerts(thisPreviewGraph, PREVIEW_GRAPH_WIDTH);
	
	//draw white box around the preview of graph in main frame
	drawPreviewOutline(thisPreviewGraph, PREVIEW_GRAPH_WIDTH);

	//write_tid_text(clientState->standardFont, previewGraph, PREV_GRAPH_PADDING, graphy);

	if (glframebuf->isBound())
		glframebuf->release();

}

void previewPlotGLWidget::drawGraphBuffer(int x, int y)
{
	glViewport(0, 0, width(), height());
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrtho(0.0f, (double)width(), (double)height(), 0.0f, -1.0f, 10.0f);

	glMatrixMode(GL_MODELVIEW);
	glPushMatrix();
	glEnable(GL_TEXTURE_2D);

	glBindTexture(GL_TEXTURE_2D, glframebuf->texture());
	glColor4f(1.0f, 1.0f, 1.0f,1.0f);
	glBegin(GL_QUADS);
	glTexCoord2f(0, 0); glVertex3f(x, y, 0);
	glTexCoord2f(1, 0); glVertex3f(x + glframebuf->width(), y, 0);
	glTexCoord2f(1, 1); glVertex3f(x + glframebuf->width(), y + glframebuf->height(), 0);
	glTexCoord2f(0, 1); glVertex3f(x, y + glframebuf->height(), 0);
	glEnd();
	glDisable(GL_TEXTURE_2D);

	glPopMatrix();

}

void previewPlotGLWidget::irregularTimerFired()
{
	//refreshPreviewGraphs(true);
}

//force full check to ensure that graphs seen earlier with 0 nodes (but now have nodes) are re-checked
void previewPlotGLWidget::refreshPreviewGraphs(bool forceFullCheck = false)
{
	if (!clientState || !clientState->activeTrace) return;
	if (activeTrace != clientState->activeTrace)
	{
		activeTrace = clientState->activeTrace;
		testedGraphQty = 0;
		forceFullCheck = true;
	}

	//changing graph layouts ruins the list. fix that if this is a performance bottleneck.
	forceFullCheck = true;

	plotted_graph * currentGraph;
	int traceGraphQty = activeTrace->plottedGraphs.size();
	if (testedGraphQty < traceGraphQty || forceFullCheck)
	{
		previewGraphs.clear();

		activeTrace->getPlottedGraphs(&previewGraphs);
		if (previewGraphs.empty())
			return;

		sort(previewGraphs.begin(), previewGraphs.end(), constructed_before());

		int basemax = (int)previewGraphs.size()*(PREVIEW_GRAPH_HEIGHT+PREVIEW_GRAPH_PADDING_Y) - (int)height();
		basemax += PREVIEW_GRAPH_PADDING_Y;
		scrollbar->setRange(0, std::max(1, basemax));
		testedGraphQty = traceGraphQty;
	}
}

void previewPlotGLWidget::paintGL()
{
	activeTrace = clientState->activeTrace;
	if (!activeTrace || clientState->waitingForNewTrace)
		return;

	QColor bgColour = clientState->config.preview.background;
	glClearColor(bgColour.redF(), bgColour.greenF(), bgColour.blueF(), bgColour.alphaF());
	glClear(GL_COLOR_BUFFER_BIT);


	int graphPreviewStartY = PREVIEW_GRAPH_PADDING_Y - previewScrollY;
	plotted_graph * currentGraph;





	refreshPreviewGraphs(false);
	for (auto threadit = previewGraphs.begin(); threadit != previewGraphs.end(); threadit++)
	{
		currentGraph = *threadit;
		if (!currentGraph || !currentGraph->previewnodes->get_numVerts()) continue;


		//if base of graph is below top of screen, draw the preview
		if ((graphPreviewStartY + PREVIEW_GRAPH_HEIGHT) > 0)
		{

			drawPreviewGraphToBuffer(currentGraph);
			drawGraphBuffer(PREVIEW_GRAPH_PADDING_X, graphPreviewStartY);

			
			//opengl state is borked by this so have to do it in every iteraton of the loop
			//have tried restoring state (https://forum.qt.io/topic/78246/qpainter-overwrites-opengl-state-in-qopenglwidget) but no luck 
			QPainter painter(this);
			painter.setFont(clientState->instructionFont);
			painter.setPen(al_col_white);

			drawPreviewInfo(currentGraph, PREVIEW_GRAPH_WIDTH, &painter, graphPreviewStartY);

		}
		graphPreviewStartY += (PREVIEW_GRAPH_HEIGHT + PREVIEW_GRAPH_PADDING_Y);

		if (graphPreviewStartY > height())
			break; //everything else below pane, don't bother drawing
	}

	for (auto graph : previewGraphs)
	{
		graph->decrease_thread_references();
		//cout << "[-1: " << graph->threadReferences << "] after preview getplottedgraphs decreased references " << endl;
	}
}


void previewPlotGLWidget::resizeGL(int w, int h)
{
	updateAspect();
}

void previewPlotGLWidget::clearHighlights()
{
	
}