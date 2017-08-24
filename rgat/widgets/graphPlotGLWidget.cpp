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

#include "stdafx.h"
#include "widgets\graphPlotGLWidget.h"
#include <gl/GLU.h>
#include <gl/GL.h>
#include "graphicsmaths.h"
#include "diff_plotter.h"
#include "maintabbox.h"
#include "ui_rgat.h"

graphPlotGLWidget::graphPlotGLWidget(QWidget *parent)
	: graphGLWidget(parent)
{
	frameTimer = new QTimer(this);
	connect(frameTimer, &QTimer::timeout,
		this, &graphPlotGLWidget::frameTimerFired);

	irregularActionTimer = new QTimer(this);
	connect(irregularActionTimer, &QTimer::timeout,
		this, &graphPlotGLWidget::irregularTimerFired);

	acceptsMouseDrag = true;

}


graphPlotGLWidget::~graphPlotGLWidget()
{
}




//activate a graph in the active trace
//selects the last one that was active in this trace, or the first seen
void graphPlotGLWidget::selectGraphInActiveTrace()
{
	traceRecord *selectedTrace = clientState->activeTrace;
	if (!selectedTrace) return;

	auto lastGraphIt = lastGraphs.find(selectedTrace);
	if (lastGraphIt != lastGraphs.end())
	{
		//cout << "sgiat 1 calling swtich ag to lastgraph " << lastGraphIt->second << endl;
		vector <plotted_graph *> traceGraphs;
		selectedTrace->getPlottedGraphs(&traceGraphs);
		plotted_graph *tmp;
		if (std::find(traceGraphs.begin(), traceGraphs.end(), lastGraphIt->second) != traceGraphs.end())
		{
			switchToGraph(lastGraphIt->second);
			
			foreach(tmp, traceGraphs)
			{
				tmp->decrease_thread_references();
			}
			return;
		}
		foreach(tmp, traceGraphs)
		{
			tmp->decrease_thread_references();
		}
	}

	plotted_graph *tmp = (plotted_graph*)selectedTrace->get_first_graph();
	switchToGraph(tmp);
}

void graphPlotGLWidget::switchToGraph(plotted_graph *graph)
{
	clientState->clearActiveGraph();
	if (!graph) return;

	traceRecord *trace = clientState->activeTrace;

	if(clientState->setActiveGraph(graph))
	 lastGraphs.emplace(make_pair(trace, graph));

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	ui->dynamicAnalysisContentsTab->updateVisualiserUI(true);
	ui->wireframeBtn->setCheckable(graph->isWireframeSupported());
	ui->wireframeBtn->setChecked(graph->isWireframeActive());
}


void graphPlotGLWidget::tabChanged(bool nowActive)
{
	activeGraph = NULL;
	if (nowActive)
	{
		
		//frameTimer->start(1 / clientState->config.renderFrequency);
		frameTimer->start(1000 / TARGET_FPS);
		irregularActionTimer->start(600);

		if (clientState && clientState->activeTrace)
		{
			selectGraphInActiveTrace();
		}
	}
	else
	{
		frameTimer->stop();
		irregularActionTimer->stop();
	}
}

void graphPlotGLWidget::initializeGL()
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

	frameTimer->start(50);
}

void graphPlotGLWidget::keyPressEvent(QKeyEvent *event)
{
	switch (event->key())
	{
	case Qt::Key_Shift:
		lastkey = Qt::Key_Shift;
		break;

	case Qt::Key_Control:
		lastkey = Qt::Key_Control;
		break;

	case Qt::Key_K:
		clientState->toggleModeHeatmap();
		break;

	case Qt::Key_J:
		clientState->toggleModeConditional();
		break;

	default:
		lastkey = Qt::Key_0;
		break;
	}

}

void graphPlotGLWidget::keyReleaseEvent(QKeyEvent *event)
{

	lastkey = Qt::Key_0;
}



void graphPlotGLWidget::wheelEvent(QWheelEvent *event)
{
	if(activeGraph)
		activeGraph->changeZoom((double)event->delta());
}

void graphPlotGLWidget::frameTimerFired()
{
	//set to true if displaying the colour picking sphere
	if (performIrregulars)
	{
		performIrregularActions();
		if (activeGraph)
			((Ui::rgatClass *)clientState->ui)->dynamicAnalysisContentsTab->updateVisualiserUI(false);
	}
	
	update();
}

void graphPlotGLWidget::irregularTimerFired()
{
	performIrregulars = true;
}

void graphPlotGLWidget::drawBoundingBox()
{
	glLineWidth(2);
	glBegin(GL_LINES);
	glColor4f(0, 1, 0, 1.0);
	glVertex3f(0, 0, 0);
	glVertex3f(0, 0 + height(), 0);

	glVertex3f(0 + width(), 0, 0);
	glVertex3f(0 + width(), 0 + height(), 0);

	glVertex3f(0, 0, 0);
	glVertex3f(0 + width(), 0, 0);

	glVertex3f(0, 0 + height(), 0);
	glVertex3f(0 + width(), 0 + height(), 0);

	glEnd();
}

void graphPlotGLWidget::setupHUDMode()
{

}

//do 2d ui 1:1 pixel scale stuff here
void graphPlotGLWidget::drawHUD()
{
	//setup for 2d UI mode
	glLoadIdentity();
	glMatrixMode(GL_PROJECTION);

	glOrtho(0.0f, (double)width(), (double)height(), 0.0f, 0.0f, 10.0f);

	QColor bgColour;
	if (clientState->heatmapMode)
	{
		bgColour = clientState->config.heatmap.background;
		glClearColor(bgColour.redF(), bgColour.greenF(), bgColour.blueF(), bgColour.alphaF());
		draw_heatmap_key();
	}
	else if (clientState->conditionalsMode)
	{
		bgColour = clientState->config.conditional.background;
		glClearColor(bgColour.redF(), bgColour.greenF(), bgColour.blueF(), bgColour.alphaF());
		draw_conditional_key();
	}
	else
	{
		bgColour = clientState->config.mainColours.background;
		glClearColor(bgColour.redF(), bgColour.greenF(), bgColour.blueF(), bgColour.alphaF());
	}
}

bool graphPlotGLWidget::chooseGraphToDisplay()
{
	if (activeGraph)
	{
		if (activeGraph->needsReleasing() || (activeGraph != clientState->getActiveGraph(false)))
		{
			activeGraph->decrease_thread_references();
			//cout << "[-1: " << activeGraph->threadReferences << "] chooseGraphToDisplay decreased references " << endl;
			activeGraph = NULL;
			return false;
		}

		return true;
	}

	if (clientState->switchTrace)
	{
		clientState->selectActiveTrace(clientState->switchTrace);
		clientState->switchTrace = NULL;
		Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
		ui->dynamicAnalysisContentsTab->updateVisualiserUI(true);
	}

	if (clientState->switchGraph)
	{
		//cout << "cgtd switching to cs-switch " << (plotted_graph*)clientState->switchGraph << endl;
		switchToGraph((plotted_graph*)clientState->switchGraph);
		clientState->switchGraph = NULL;
	}

	activeGraph = (plotted_graph*)clientState->getActiveGraph(true);
	//cout << "set actg to " << activeGraph << endl;
	if (!activeGraph && !clientState->waitingForNewTrace)
	{
		if (!clientState->activeTrace)
			clientState->selectActiveTrace();

		
		selectGraphInActiveTrace();
		//cout << "set actg-2- to " << activeGraph << endl;
	}

	//cout << "activegraph: " << activeGraph << " cs->ag: " << clientState->getActiveGraph(false)<<endl;
	return (activeGraph != NULL);

}

void graphPlotGLWidget::paintGL()
{
	if (!activeGraph || activeGraph->needsReleasing())
		return;

	activeGraph->gl_frame_setup(this);

	activeGraph->performMainGraphDrawing(this);

	drawHUD();
}

void graphPlotGLWidget::resizeGL(int w, int h)
{
	updateAspect(); 
}



//displays the divergence of two selected graphs, defined in diffrenderer
void graphPlotGLWidget::display_graph_diff(void *diffRenderer, node_data* divergeNode)
{
	plotted_graph *graph1 = ((diff_plotter *)diffRenderer)->get_graph(1);
	plotted_graph *diffgraph = ((diff_plotter *)diffRenderer)->get_diff_graph();
	GRAPH_DISPLAY_DATA *vertsdata = graph1->get_mainnodes();
	GRAPH_DISPLAY_DATA *linedata = graph1->get_mainlines();

	if (graph1->needVBOReload_main)
	{
		loadVBOs(graph1->graphVBOs, vertsdata, linedata);
		graph1->needVBOReload_main = false;
	}

	if (diffgraph->needVBOReload_main)
	{
		load_edge_VBOS(diffgraph->graphVBOs, diffgraph->get_mainlines());
		diffgraph->needVBOReload_main = false;
	}

	if (clientState->wireframe)
		diffgraph->maintain_draw_wireframe(this);

	if (clientState->showNodes)
		array_render_points(VBO_NODE_POS, VBO_NODE_COL, graph1->graphVBOs, vertsdata->get_numVerts());

	if (clientState->showEdges)
		array_render_lines(VBO_LINE_POS, VBO_LINE_COL, diffgraph->graphVBOs, diffgraph->get_mainlines()->get_numVerts());

	if (divergeNode)
	{
		void *nodePos = graph1->get_node_coord_ptr(divergeNode->index);
		diffgraph->drawHighlight(nodePos, diffgraph->main_scalefactors, &al_col_orange, 10, this);
	}

	float zmul = zoomFactor(graph1->cameraZoomlevel, graph1->main_scalefactors->size);

	PROJECTDATA pd;
	bool pdgathered = false;
	if (clientState->should_show_external_symbols(zmul))
	{
		gather_projection_data(&pd);
		pdgathered = true;
		diffgraph->show_external_symbol_labels(&pd, this);
	}

	if (clientState->should_show_internal_symbols(zmul))
	{
		gather_projection_data(&pd);
		pdgathered = true;
		diffgraph->show_internal_symbol_labels(&pd, this);
	}

	if (clientState->should_show_instructions(zmul) &&
		graph1->get_protoGraph()->get_num_nodes() > 2)
	{
		if (!pdgathered)
			gather_projection_data(&pd);
		diffgraph->draw_instructions_text(zmul, &pd, this);
	}
}

void graphPlotGLWidget::draw_heatmap_key_blocks(int x, int y)
{
	auto it = clientState->config.heatmap.edgeFrequencyCol.begin();
	int xindex = x;
	for (; it != clientState->config.heatmap.edgeFrequencyCol.end(); it++)
	{
		glBegin(GL_QUADS);
		glColor4f(it->redF(), it->greenF(), it->blueF(), it->alphaF());
		glVertex3f(xindex, y, 0);
		glVertex3f(xindex + HEATMAP_KEY_SQUARESIZE, y, 0);
		glVertex3f(xindex + HEATMAP_KEY_SQUARESIZE, y + HEATMAP_KEY_SQUARESIZE, 0);
		glVertex3f(xindex, y + HEATMAP_KEY_SQUARESIZE, 0);
		glVertex3f(xindex, y, 0);
		glEnd();
		xindex += HEATMAP_KEY_SQUARESIZE;
	}
}

void graphPlotGLWidget::performIrregularActions()
{
	if (!chooseGraphToDisplay())
		return;

	activeGraph->irregularActions();

	if (activeGraph->replayState == ePlaying)
	{
		Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;

		ui->replaySlider->setValue(1000 * activeGraph->getAnimationPercent());

	}

	if (activeGraph->replayState == eEnded)
	{
		Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
		ui->dynamicAnalysisContentsTab->stopAnimation();
	}

	HIGHLIGHT_DATA *highlightData = &activeGraph->highlightData;
	if (highlightData->highlightState && activeGraph->get_protoGraph()->active)
	{
		//((TraceVisGUI *)widgets)->highlightWindow->updateHighlightNodes(highlightData, graph->get_protoGraph(), activePid);
	}
}

#define HEATKEY_POS_Y 25
#define HEATKEY_X_FROM_RIGHT 25
void graphPlotGLWidget::draw_heatmap_key()
{
	if (!activeGraph) return;

	const QFontMetrics fm(clientState->instructionFont);
	const pair<unsigned long, unsigned long> heatExtremes = activeGraph->heatExtremes;

	stringstream keytext;
	keytext << "Frequency:  " << heatExtremes.second;
	const std::string ksleft = keytext.str();
	int ksWidthLeft = fm.width(ksleft.c_str());

	const std::string ksright = to_string(heatExtremes.first);
	int ksWidthRight = fm.width(ksright.c_str());

	const int keyx = width() - (ksWidthLeft + (10 * HEATMAP_KEY_SQUARESIZE) + ksWidthRight);

	QPainter painter(this);
	painter.setPen(clientState->config.mainColours.instructionText);
	painter.setFont(clientState->instructionFont);

	painter.drawText(keyx - ksWidthLeft - 8, HEATKEY_POS_Y, ksleft.c_str());
	painter.drawText(keyx + 10 * HEATMAP_KEY_SQUARESIZE + 8, HEATKEY_POS_Y, ksright.c_str());
	painter.end();

	draw_heatmap_key_blocks(keyx, HEATKEY_POS_Y - 16);
}

//todo: looks awful. draw a dark background behind this
void graphPlotGLWidget::draw_conditional_key()
{
	if (!activeGraph) return;

	const pair<unsigned long, unsigned long> condCounts = activeGraph->condCounts;
	stringstream keytextA, keytextN;

	keytextA << "Always Taken (" << condCounts.first << ")";
	keytextN << "Never Taken (" << condCounts.second << ")";

	const QFontMetrics fm(clientState->instructionFont);
	int width1 = fm.width(keytextA.str().c_str());
	int width2 = fm.width(keytextN.str().c_str());
	int drawX = width() - (max(width1, width2) + 8);

	QPainter painter(this);

	int fontHeight = fm.height();

	int drawY = fontHeight + 5;
	painter.setPen(clientState->config.conditional.cond_succeed);
	painter.drawText(drawX, drawY, keytextA.str().c_str());

	drawY += fontHeight + 3;

	painter.setPen(clientState->config.conditional.cond_fail);
	painter.drawText(drawX, drawY, keytextN.str().c_str());
	painter.end();
}


void graphPlotGLWidget::mouseDragged(int dx, int dy)
{
	if (activeGraph)
	{
		activeGraph->apply_drag(dx, dy);
	}
}


void graphPlotGLWidget::wireframeButtonToggled(bool state)
{
	if (activeGraph)
		activeGraph->setWireframeActive(state);
}

void graphPlotGLWidget::addressHighlightSelected()
{
	selectHighlightedAddressNodes(activeGraph);
}

void graphPlotGLWidget::symbolHighlightSelected()
{
	selectHighlightedSymbolNodes(activeGraph);
}

void graphPlotGLWidget::exceptionsHighlightSelected()
{
	selectHighlightedExceptionNodes(activeGraph);
}

void graphPlotGLWidget::clearHighlights()
{
	clearHighlightNodes(activeGraph);
}