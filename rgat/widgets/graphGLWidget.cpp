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

#include "stdafx.h"
#include "widgets\graphGLWidget.h"
#include "GUIconstants.h"
#include "graphicsMaths.h"
#include "graphplots/plotted_graph.h"
#include "ui_highlightSelector.h"

rgatState *graphGLWidget::clientState = NULL;

graphGLWidget::graphGLWidget(QWidget *parent = 0)
	: QOpenGLWidget(parent)
{

	setMouseTracking(true);
	mousePos.setX(0);
	mousePos.setY(0);
	setEnabled(true);
}


graphGLWidget::~graphGLWidget()
{
}

//this call is a bit sensitive and will give odd results if called in the wrong place
void graphGLWidget::gather_projection_data(PROJECTDATA *pd)
{
	glBindBuffer(GL_ARRAY_BUFFER, 0);
	glGetDoublev(GL_MODELVIEW_MATRIX, pd->model_view);
	glGetDoublev(GL_PROJECTION_MATRIX, pd->projection);
	glGetIntegerv(GL_VIEWPORT, pd->viewport);
}

void graphGLWidget::load_VBO(int index, GLuint *VBOs, int bufsize, float *data)
{
	glBindBuffer(GL_ARRAY_BUFFER, VBOs[index]);
	glBufferData(GL_ARRAY_BUFFER, bufsize, data, GL_STATIC_DRAW);
	glBindBuffer(GL_ARRAY_BUFFER, 0);
}

void graphGLWidget::load_edge_VBOS(GLuint *VBOs, GRAPH_DISPLAY_DATA *lines)
{
	GLsizei vertsqty = lines->get_numVerts();
	GLsizei posbufsize = vertsqty * POSELEMS * sizeof(GLfloat);
	load_VBO(VBO_LINE_POS, VBOs, posbufsize, lines->readonly_pos());

	GLsizei linebufsize = vertsqty * COLELEMS * sizeof(GLfloat);
	load_VBO(VBO_LINE_COL, VBOs, linebufsize, lines->readonly_col());
	lines->set_numLoadedVerts(vertsqty);
}

void graphGLWidget::loadVBOs(GLuint *VBOs, GRAPH_DISPLAY_DATA *nodes, GRAPH_DISPLAY_DATA *lines)
{
	GLsizei nodevertsqty = nodes->get_numVerts();
	load_VBO(VBO_NODE_POS, VBOs, nodevertsqty * POSELEMS * sizeof(GLfloat), nodes->readonly_pos());
	load_VBO(VBO_NODE_COL, VBOs, nodevertsqty * COLELEMS * sizeof(GLfloat), nodes->readonly_col());
	nodes->set_numLoadedVerts(nodevertsqty);

	load_edge_VBOS(VBOs, lines);
}


void graphGLWidget::array_render(int prim, int POSVBO, int COLVBO, GLuint *buffers, GLsizei quantity)
{
	glBindBuffer(GL_ARRAY_BUFFER, buffers[POSVBO]);
	glVertexPointer(POSELEMS, GL_FLOAT, 0, 0);

	glBindBuffer(GL_ARRAY_BUFFER, buffers[COLVBO]);
	glColorPointer(COLELEMS, GL_FLOAT, 0, 0);

	int err = glGetError();
	if (err)
		cerr << "GL1 error " << err << " in arr_r_pts (display active)" << endl;

	//Check VBOs have been loaded correctly if crashing here
	glDrawArrays(prim, 0, quantity);	
	err = glGetError();
	if (err)
		cerr << "GL2 error " << err << " in arr_r_pts (display active)" << endl;
	glBindBuffer(GL_ARRAY_BUFFER, 0);
}

void graphGLWidget::array_render_points(int POSVBO, int COLVBO, GLuint *buffers, GLsizei quantity)
{
	array_render(GL_POINTS, POSVBO, COLVBO, buffers, quantity);
}

void graphGLWidget::array_render_lines(int POSVBO, int COLVBO, GLuint *buffers, GLsizei quantity)
{
	array_render(GL_LINES, POSVBO, COLVBO, buffers, quantity);
}

void graphGLWidget::updateAspect()
{
	aspect = (double)width() / (double)height();
}

void graphGLWidget::drawBoundingBox(int thickness, QColor colour)
{
	drawBox(0, 0, width(), height(), thickness, colour);
}

void graphGLWidget::drawBox(float x, float y, float w, float h, int thickness, QColor colour)
{
	glLineWidth((GLfloat)thickness);
	glColor4f(colour.redF(), colour.greenF(), colour.blueF(), colour.alphaF());

	glBegin(GL_LINES);

	glVertex3f(x, y, 0);	glVertex3f(x, y + h, 0); //left
	glVertex3f(x, y, 0);	glVertex3f(x + w, y, 0); //top
	glVertex3f(x + w -1, y, 0);	glVertex3f(x + w - 1, y + h, 0); //right
	glVertex3f(x, y + h - 1, 0); glVertex3f(x + w, y + h -1, 0); //base

	glEnd();
}

void graphGLWidget::drawRect(float x, float y, float w, float h, QColor colour)
{
	glColor4f(colour.redF(), colour.greenF(), colour.blueF(), colour.alphaF());

	glBegin(GL_QUADS);

	glVertex3f(x, y, 0);
	glVertex3f(x + w, y, 0);
	glVertex3f(x + w, y + h, 0);
	glVertex3f(x, y + h, 0);
	glVertex3f(x, y, 0);

	glEnd();
}

void graphGLWidget::mouseMoveEvent(QMouseEvent *event)
{
	event->setAccepted(true);

	if (event->buttons() == 0)
	{
		//todo:  mouseover nodes
		mousePos = event->pos(); 
		return;
	}

	if (!acceptsMouseDrag)
		return;

	QPoint newPos = event->pos();
	mouseDragged(newPos.x() - mousePos.x(), newPos.y() - mousePos.y());
	mousePos = event->pos();
}

void graphGLWidget::drawHighlightLine(FCOORD lineEndPt, QColor &colour)
{
	glColor4f(colour.redF(), colour.greenF(), colour.blueF(), colour.alphaF());
	glBegin(GL_LINES);
	glVertex3f(0, 0, 0);
	glVertex3f(lineEndPt.x, lineEndPt.y, lineEndPt.z);
	glEnd();
}

void graphGLWidget::selectHighlightedAddressNodes(PLOTTEDGRAPH_CASTPTR graphPtr)
{
	if (!graphPtr)	return;
	plotted_graph *graph = (plotted_graph *)graphPtr;

	Ui::highlightDialog *ui = (Ui::highlightDialog *)clientState->highlightSelectUI;
	//todo: abstract
	QString addressString = ui->addressEdit->text();
	MEM_ADDRESS address = addressString.toLongLong(0, 16);

	vector<NODEINDEX> nodeList;

	//find address in disassembly of whole process
	proto_graph *basegraph = graph->get_protoGraph();
	PROCESS_DATA *processdata = basegraph->get_piddata();

	ReadLock disassemblyReadLock(processdata->disassemblyRWLock);
	auto addressIt = processdata->disassembly.find(address);
	if (addressIt != processdata->disassembly.end())
	{
		//find instrumented instructions from this thread in matching address
		INSLIST insList = addressIt->second;
		INSLIST::iterator insListIt = insList.begin();
		int currentTid = graph->get_tid();
		for (; insListIt != insList.end(); ++insListIt)
		{
			INS_DATA *target = *insListIt;
			unordered_map<PID_TID, NODEINDEX>::iterator threadVIt = target->threadvertIdx.find(currentTid);
			if (threadVIt == target->threadvertIdx.end()) continue;
			node_data *n = basegraph->safe_get_node(threadVIt->second);
			nodeList.push_back(n->index);
		}
		disassemblyReadLock.unlock();
		graph->setHighlightData(&nodeList, eAddress_HL);
		return;
	}
	disassemblyReadLock.unlock();


	processdata->getExternDictReadLock();
	auto externIt = processdata->externdict.find(address);
	if (externIt != processdata->externdict.end())
	{
		//find external nodes from this thread in matching address
		ROUTINE_STRUCT *block = externIt->second;
		processdata->getExternCallerReadLock();
		auto threadIt = block->thread_callers.find(graph->get_tid());
		if (threadIt == block->thread_callers.end()) 
		{
			processdata->dropExternDictReadLock();
			processdata->dropExternCallerReadLock();
			return;
		}

		processdata->dropExternCallerReadLock();

		EDGELIST edges = threadIt->second;
		NODEPAIR edge;
		foreach(edge, edges)
		{
			nodeList.push_back(edge.second);
		}
		processdata->dropExternDictReadLock();
		graph->setHighlightData(&nodeList, eAddress_HL);
		return;
	}
	processdata->dropExternDictReadLock();

}

void graphGLWidget::clearHighlightNodes(PLOTTEDGRAPH_CASTPTR graphPtr)
{
	if (!graphPtr)	return;
	plotted_graph *graph = (plotted_graph *)graphPtr;
	graph->setHighlightData(0, eNone_HL);
}


void graphGLWidget::selectHighlightedSymbolNodes(PLOTTEDGRAPH_CASTPTR graphPtr)
{
	if (!graphPtr)	return;
	plotted_graph *graph = (plotted_graph *)graphPtr;
	
	vector<NODEINDEX> nodeList;

	Ui::highlightDialog *highlightui = (Ui::highlightDialog *)clientState->highlightSelectUI;

	auto selecteditems = highlightui->modSymTree->selectedItems();
	QTreeWidgetItem *item;
	foreach(item, selecteditems)
	{
		if (item->text(2).isEmpty())
			continue; //user highlighted a module instead of a symbol

		QVariant symbolInfoValue = item->data(3, Qt::UserRole);
		symbolInfo *info = (symbolInfo *)symbolInfoValue.value<void *>();

		nodeList.reserve(nodeList.size() + info->threadNodes.size());
		nodeList.insert(nodeList.end(), info->threadNodes.begin(), info->threadNodes.end());
	}

	graph->setHighlightData(&nodeList, eSym_HL);
}


//todo: test this
void graphGLWidget::selectHighlightedExceptionNodes(PLOTTEDGRAPH_CASTPTR graphPtr)
{
	if (!graphPtr)	return;
	plotted_graph *graph = (plotted_graph *)graphPtr;
	proto_graph *protoGraph = graph->get_protoGraph();

	vector<NODEINDEX> nodeList;

	protoGraph->highlightsLock.lock();

	if (!protoGraph->exceptionSet.empty())
	{
		set<NODEINDEX>::iterator exceptIt = protoGraph->exceptionSet.begin();
		for (; exceptIt != protoGraph->exceptionSet.end(); ++exceptIt)
			nodeList.push_back(*exceptIt);
	}
	protoGraph->highlightsLock.unlock();


	graph->setHighlightData(&nodeList, eExceptions_HL);
}