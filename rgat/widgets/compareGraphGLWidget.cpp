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

#include "stdafx.h"
#include "widgets\compareGraphGLWidget.h"
#include "ui_rgat.h"

compareGraphGLWidget::compareGraphGLWidget(QWidget *parent)
	: graphGLWidget(parent)
{
	frameTimer = new QTimer(this);
	connect(frameTimer, &QTimer::timeout,
		this, &compareGraphGLWidget::frameTimerFired);

	acceptsMouseDrag = true;
}


compareGraphGLWidget::~compareGraphGLWidget()
{
}

void compareGraphGLWidget::frameTimerFired()
{
	if (plotter) 
		update();
}

void compareGraphGLWidget::resetRenderer()
{
	if (diff_graph)
	{
		delete plotter;
		plotter = NULL;
		diff_graph = NULL;

		Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
		ui->diffWidgetStack->setCurrentIndex(eDiffWidgetStackNone);
	}
}

void compareGraphGLWidget::plotComparison()
{

	plotted_graph *graph1 = (plotted_graph *)clientState->getCompareGraph(1);
	traceRecord *graph1trace = graph1->get_protoGraph()->get_traceRecord();

	plotted_graph *graph2 = (plotted_graph *)clientState->getCompareGraph(2);
	if (!graph1 || !graph2) return;

	plotter = new diff_plotter(this, graph1, graph2, &clientState->instructionFont);

	plotter->render(this);
	diff_graph = plotter->get_diff_graph();

	Ui::rgatClass *ui = (Ui::rgatClass *)clientState->ui;
	ui->diffWidgetStack->setCurrentIndex(eDiffWidgetStackSelected);
	if (plotter->wasDivergenceFound())
	{
		ui->commonInsLabel->setText("Divergence found");
		//ui->commonInsLabel->setText(QString::number(plotter->get_divergence_index()) + " instructions until divergence");
		if (!plotter->get_divergence_index())
		{
			ui->lastCommonInsLabel->setText("No common instructions");
		}
		else
		{
			NODEINDEX divergeIdx = plotter->get_diff_node();
			node_data * diffNode = graph1->get_protoGraph()->safe_get_node(divergeIdx);

			QString infostring;
			if (diffNode->external)
			{
				string symString;
				MEM_ADDRESS offset = diffNode->address - graph1trace->modBounds.at(diffNode->nodeMod)->first;
				graph1->get_protoGraph()->get_piddata()->get_sym(diffNode->nodeMod, offset, symString);
				infostring = " - " + QString::fromStdString(symString) + "(*)";
				ui->lastCommonInsLabel->setText("Divergence at external address 0x" + QString::number(diffNode->address, 16) + infostring);
			}
			else
			{
				infostring = " - " + QString::fromStdString(diffNode->ins->ins_text);
				ui->lastCommonInsLabel->setText("Divergence at internal address 0x" + QString::number(diffNode->address, 16) + infostring);
			}
		}
		
	}
	else
	{
		ui->commonInsLabel->setText("No divergence found - graphs equivalent");
		ui->lastCommonInsLabel->clear();
	}


}

void compareGraphGLWidget::initializeGL()
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
	glClearColor(0.0, 0, 0, 1.0);

	frameTimer->start(50);
}

void compareGraphGLWidget::paintGL()
{
	if (!diff_graph) return;

	void *divergencePositionPtr = NULL;
	if (plotter && plotter->wasDivergenceFound())
	{
		NODEINDEX divergeNodeIdx = plotter->get_diff_node();
		divergencePositionPtr = plotter->get_graph(1)->get_node_coord_ptr(divergeNodeIdx);
	}

	diff_graph->gl_frame_setup(this);
	diff_graph->performDiffGraphDrawing(this, divergencePositionPtr);

}

void compareGraphGLWidget::resizeGL(int w, int h)
{
	updateAspect();
}

void compareGraphGLWidget::mouseDragged(int dx, int dy)
{
	if (diff_graph)
	{
		diff_graph->apply_drag(dx, dy);
	}
}

void compareGraphGLWidget::wheelEvent(QWheelEvent *event)
{
	if (diff_graph)
	{
		diff_graph->changeZoom((double)event->delta());
	}
}