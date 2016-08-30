#pragma once
#include <stdafx.h>
#include "mathStructs.h"

class GRAPH_DISPLAY_DATA {
public:
	GRAPH_DISPLAY_DATA(int initialValue);
	~GRAPH_DISPLAY_DATA();

	float *acquire_pos(char *location);
	float *acquire_col(char *location);

	float *readonly_col() { return &vcolarray.at(0); }
	float *readonly_pos() { return &vposarray.at(0); }

	void release_pos();
	void release_col();
	void clear();
	unsigned int col_size() { return get_numVerts()*COLELEMS * sizeof(float); }
	unsigned int pos_size() { return get_numVerts()*POSELEMS * sizeof(float); }
	unsigned int col_buf_size_floats() { return vcolarray.size(); }
	unsigned int get_numVerts() { return numVerts; }
	void set_numVerts(unsigned int num);
	unsigned int get_renderedEdges() { return edgesRendered; }
	void inc_edgesRendered() { edgesRendered++; }

	FCOORD get_coord(unsigned int index);

	bool isPreview() { return preview; }
	void setPreview() { preview = true; }

private:
	HANDLE posmutex;
	HANDLE colmutex;
	unsigned int numVerts = 0;

	vector<GLfloat> vposarray;
	vector<GLfloat> vcolarray;


	//not used for nodes
	unsigned int edgesRendered = 0;
	bool preview = false;
};