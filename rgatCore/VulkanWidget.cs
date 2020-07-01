using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using static Veldrid.OpenGLBinding.OpenGLNative;

namespace rgatCore
{
    class VulkanWidget
    {
		Vector2 mousePos;
		public VulkanWidget()
		{
		}

		/*
		//this call is a bit sensitive and will give odd results if called in the wrong place
		void unsafe gather_projection_data(GraphicsMaths.PROJECTDATA pd)
		{
			
			glBindBuffer(Veldrid.OpenGLBinding.BufferTarget.ArrayBuffer, 0);
			int result;
			//veldrid doesnt have glGetDoublev??
			//glGetDoublev(GL_MODELVIEW_MATRIX, pd.model_view);
			//glGetDoublev(GL_PROJECTION_MATRIX, pd.projection);
			
			glGetIntegerv(Veldrid.OpenGLBinding.GetPName.ModelviewMatrix, &result);
			pd.model_view = result;
			glGetIntegerv(Veldrid.OpenGLBinding.GetPName.ProjectionMatrix, &result);
			glGetIntegerv(Veldrid.OpenGLBinding.GetPName.Viewport, result);
		}

		void load_VBO(int index, GLuint* VBOs, int bufsize, float* data)
		{
			glBindBuffer(GL_ARRAY_BUFFER, VBOs[index]);
			glBufferData(GL_ARRAY_BUFFER, bufsize, data, GL_STATIC_DRAW);
			glBindBuffer(GL_ARRAY_BUFFER, 0);
		}

		void load_edge_VBOS(GLuint* VBOs, GRAPH_DISPLAY_DATA* lines)
		{
			GLsizei vertsqty = lines->get_numVerts();
			GLsizei posbufsize = vertsqty * POSELEMS * sizeof(GLfloat);
			load_VBO(VBO_LINE_POS, VBOs, posbufsize, lines->readonly_pos());

			GLsizei linebufsize = vertsqty * COLELEMS * sizeof(GLfloat);
			load_VBO(VBO_LINE_COL, VBOs, linebufsize, lines->readonly_col());
			lines->set_numLoadedVerts(vertsqty);
		}

		void load_block_VBOS(GLuint* VBOs, GRAPH_DISPLAY_DATA* lines)
		{
			GLsizei vertsqty = lines->get_numVerts();
			GLsizei posbufsize = vertsqty * POSELEMS * sizeof(GLfloat);
			load_VBO(VBO_BLOCKLINE_POS, VBOs, posbufsize, lines->readonly_pos());

			GLsizei linebufsize = vertsqty * COLELEMS * sizeof(GLfloat);
			load_VBO(VBO_BLOCKLINE_COL, VBOs, linebufsize, lines->readonly_col());
			lines->set_numLoadedVerts(vertsqty);
		}

		void loadVBOs(GLuint* VBOs, GRAPH_DISPLAY_DATA* nodes, GRAPH_DISPLAY_DATA* lines, GRAPH_DISPLAY_DATA* blocklines)
		{
			GLsizei nodevertsqty = nodes->get_numVerts();
			load_VBO(VBO_NODE_POS, VBOs, nodevertsqty * POSELEMS * sizeof(GLfloat), nodes->readonly_pos());
			load_VBO(VBO_NODE_COL, VBOs, nodevertsqty * COLELEMS * sizeof(GLfloat), nodes->readonly_col());
			nodes->set_numLoadedVerts(nodevertsqty);

			load_edge_VBOS(VBOs, lines);
			if (blocklines != NULL)
				load_block_VBOS(VBOs, blocklines);
		}


		void array_render(int prim, int POSVBO, int COLVBO, GLuint* buffers, GLsizei quantity)
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

		void array_render_points(int POSVBO, int COLVBO, GLuint* buffers, GLsizei quantity)
		{
			array_render(GL_POINTS, POSVBO, COLVBO, buffers, quantity);
		}

		void array_render_lines(int POSVBO, int COLVBO, GLuint* buffers, GLsizei quantity)
		{
			array_render(GL_LINES, POSVBO, COLVBO, buffers, quantity);
		}

		void updateAspect()
		{
			aspect = (double)width() / (double)height();
		}

		void drawBoundingBox(int thickness, QColor colour)
		{
			drawBox(0, 0, width(), height(), thickness, colour);
		}

		void drawBox(float x, float y, float w, float h, int thickness, QColor colour)
		{
			glLineWidth((GLfloat)thickness);
			glColor4f(colour.redF(), colour.greenF(), colour.blueF(), colour.alphaF());

			glBegin(GL_LINES);

			glVertex3f(x, y, 0); glVertex3f(x, y + h, 0); //left
			glVertex3f(x, y, 0); glVertex3f(x + w, y, 0); //top
			glVertex3f(x + w - 1, y, 0); glVertex3f(x + w - 1, y + h, 0); //right
			glVertex3f(x, y + h - 1, 0); glVertex3f(x + w, y + h - 1, 0); //base

			glEnd();
		}

		void drawRect(float x, float y, float w, float h, QColor colour)
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

		void mouseMoveEvent(QMouseEvent*event)
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

	void drawHighlightLine(FCOORD lineEndPt, QColor &colour)
	{
		glColor4f(colour.redF(), colour.greenF(), colour.blueF(), colour.alphaF());
		glBegin(GL_LINES);
		glVertex3f(0, 0, 0);
		glVertex3f(lineEndPt.x, lineEndPt.y, lineEndPt.z);
		glEnd();
	}

	void selectHighlightedAddressNodes(PLOTTEDGRAPH_CASTPTR graphPtr)
	{
		if (!graphPtr) return;
		plotted_graph* graph = (plotted_graph*)graphPtr;

		Ui::highlightDialog* ui = (Ui::highlightDialog*)clientState->highlightSelectUI;
		//todo: abstract
		QString addressString = ui->addressEdit->text();
		MEM_ADDRESS address = addressString.toLongLong(0, 16);

		vector<NODEINDEX> nodeList;

		//find address in disassembly of whole process
		proto_graph* basegraph = graph->get_protoGraph();
		PROCESS_DATA* processdata = basegraph->get_piddata();

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
				INS_DATA* target = *insListIt;
				unordered_map<PID_TID, NODEINDEX>::iterator threadVIt = target->threadvertIdx.find(currentTid);
				if (threadVIt == target->threadvertIdx.end()) continue;
				node_data* n = basegraph->safe_get_node(threadVIt->second);
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
			ROUTINE_STRUCT* block = externIt->second;
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
			foreach (edge, edges)
		{
				nodeList.push_back(edge.second);
			}
			processdata->dropExternDictReadLock();
			graph->setHighlightData(&nodeList, eAddress_HL);
			return;
		}
		processdata->dropExternDictReadLock();

	}

	void clearHighlightNodes(PLOTTEDGRAPH_CASTPTR graphPtr)
	{
		if (!graphPtr) return;
		plotted_graph* graph = (plotted_graph*)graphPtr;
		graph->setHighlightData(0, eNone_HL);
	}


	void selectHighlightedSymbolNodes(PLOTTEDGRAPH_CASTPTR graphPtr)
	{
		if (!graphPtr) return;
		plotted_graph* graph = (plotted_graph*)graphPtr;

		vector<NODEINDEX> nodeList;

		Ui::highlightDialog* highlightui = (Ui::highlightDialog*)clientState->highlightSelectUI;

		auto selecteditems = highlightui->modSymTree->selectedItems();
		QTreeWidgetItem* item;
		foreach (item, selecteditems)
	{
			if (item->text(2).isEmpty())
				continue; //user highlighted a module instead of a symbol

			QVariant symbolInfoValue = item->data(3, Qt::UserRole);
			symbolInfo* info = (symbolInfo*)symbolInfoValue.value<void*>();

			nodeList.reserve(nodeList.size() + info->threadNodes.size());
			nodeList.insert(nodeList.end(), info->threadNodes.begin(), info->threadNodes.end());
		}

		graph->setHighlightData(&nodeList, eSym_HL);
	}


	//todo: test this
	void selectHighlightedExceptionNodes(PLOTTEDGRAPH_CASTPTR graphPtr)
	{
		if (!graphPtr) return;
		plotted_graph* graph = (plotted_graph*)graphPtr;
		proto_graph* protoGraph = graph->get_protoGraph();

		vector<NODEINDEX> nodeList;

		protoGraph->highlightsLock.lock () ;

		if (!protoGraph->exceptionSet.empty())
		{
			set<NODEINDEX>::iterator exceptIt = protoGraph->exceptionSet.begin();
			for (; exceptIt != protoGraph->exceptionSet.end(); ++exceptIt)
				nodeList.push_back(*exceptIt);
		}
		protoGraph->highlightsLock.unlock();


		graph->setHighlightData(&nodeList, eExceptions_HL);
	}

	double getKeyboardZoomModifier()
	{
		/*
		double deltaModifier = 1.0;
		bool shiftheld = QApplication::keyboardModifiers() & Qt::ShiftModifier;
		bool ctrlheld = QApplication::keyboardModifiers() & Qt::ControlModifier;

		if (shiftheld) deltaModifier *= 5;
		if (shiftheld) ctrlheld *= 50;

		return deltaModifier;
		
		return 0;
	}
	*/
	}
}
