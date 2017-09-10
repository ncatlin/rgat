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
This class holds (and provides dubiously mutex guarded access to) OpenGl vertex and colour data
*/
#pragma once
#include <stdafx.h>
#include "mathStructs.h"
#include "traceConstants.h"

class GRAPH_DISPLAY_DATA {
public:
	GRAPH_DISPLAY_DATA(bool preview = false);
	~GRAPH_DISPLAY_DATA();

	vector <float>* acquire_pos_read(int holder = 0);
	vector <float>* acquire_col_read();
	vector <float>* acquire_pos_write(int holder = 0);
	vector <float>* acquire_col_write();

	float *readonly_col() { if (!vcolarray.empty()) return &vcolarray.at(0); return 0; }
	float *readonly_pos() { if (!vposarray.empty()) return &vposarray.at(0); return 0; }

	void release_pos_write();
	void release_pos_read();
	void release_col_write();
	void release_col_read();

	void clear();
	void reset();

	size_t col_sizec() { return vcolarray.size(); }
	//this is actually quite slow? or at least is a significant % of reported cpu time
	unsigned int col_buf_capacity_floats() { return vcolarraySize; }
	GLsizei get_numVerts() { return numVerts; }
	GLsizei get_numLoadedVerts() { return loadedVerts; }
	void set_numLoadedVerts(GLsizei qty) { loadedVerts = qty; }
	void set_numVerts(GLsizei num);
	unsigned int get_renderedEdges() { return edgesRendered; }
	void inc_edgesRendered() { ++edgesRendered; }

	void drawShortLinePoints(FCOORD *startC, FCOORD *endC, QColor *colour, long *arraypos);
	int drawLongCurvePoints(FCOORD *bezierC, FCOORD *startC, FCOORD *endC, QColor *colour, int edgeType, long *colarraypos);

	bool get_coord(NODEINDEX index, FCOORD* result);

	bool isPreview() { return preview; }

private:


	SRWLOCK poslock = SRWLOCK_INIT;
	SRWLOCK collock = SRWLOCK_INIT;

	unsigned long numVerts = 0;
	unsigned long loadedVerts = 0;

	vector<GLfloat> vposarray;
	vector<GLfloat> vcolarray;
	unsigned long vcolarraySize = 0;

	//not used for nodes
	unsigned int edgesRendered = 0;
	bool preview = false;
};