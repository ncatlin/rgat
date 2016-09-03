#pragma once
#include <stdafx.h>
#include "mathStructs.h"

class GRAPH_DISPLAY_DATA {
public:
	GRAPH_DISPLAY_DATA(bool preview = false);
	~GRAPH_DISPLAY_DATA();

	//float *acquire_pos(char *location);
	//float *acquire_col(char *location);
	vector <float>* acquire_pos(char *location);
	vector <float>* acquire_col(char *location);

	float *readonly_col() { return &vcolarray.at(0); }
	float *readonly_pos() { return &vposarray.at(0); }

	void release_pos();
	void release_col();
	void clear();
	void reset();
	unsigned int col_size() { return colSize; }
	unsigned int pos_size() { return posSize; }
	unsigned int col_sizec() { return vcolarray.size(); }
	//this is actually quite slow? or at least is a significant % of reported cpu time
	unsigned int col_buf_capacity_floats() { return vcolarraySize; }
	unsigned int get_numVerts() { return numVerts; }
	void set_numVerts(unsigned int num);
	unsigned int get_renderedEdges() { return edgesRendered; }
	void inc_edgesRendered() { ++edgesRendered; }

	bool get_coord(unsigned int index, FCOORD* result);

	bool isPreview() { return preview; }

private:
	HANDLE posmutex;
	HANDLE colmutex;
	unsigned int numVerts = 0;

	vector<GLfloat> vposarray;
	vector<GLfloat> vcolarray;

	unsigned int colSize = 0;
	unsigned int posSize = 0;
	unsigned int vcolarraySize = 0;

	//not used for nodes
	unsigned int edgesRendered = 0;
	bool preview = false;
};