#pragma once
#include <stdafx.h>
#include "mathStructs.h"

class GRAPH_DISPLAY_DATA {
public:
	GRAPH_DISPLAY_DATA(int initialValue);
	~GRAPH_DISPLAY_DATA();
	//todo - split these up?
	float *acquire_pos(char *location);
	float *acquire_col(char *location);
	void debg(int m);
	//need to work out if this is a problem. might be
	float *readonly_col() { return vcolarray; }
	float *readonly_pos() { return vposarray; }

	float *acquire_fcoord();
	void release_pos();
	void release_col();
	void release_fcoord();
	unsigned int col_size() { return vcsize; }
	unsigned int pos_size() { return vpsize; }
	unsigned int get_numVerts() { return numVerts; }
	void set_numVerts(unsigned int num);
	unsigned int get_renderedEdges() { return edgesRendered; }
	void inc_edgesRendered() { edgesRendered++; }
	void expand(unsigned int minsize);

	FCOORD get_coord(unsigned int index);

	bool isPreview() { return preview; }
	void setPreview() { preview = true; }

private:
	HANDLE posmutex;
	HANDLE colmutex;
	HANDLE coordmutex;
	unsigned int numVerts = 0;

	//for realloc groundskeeping
	unsigned int vpsize = 0;
	unsigned int vcsize = 0;

	float *vposarray;
	float *vcolarray;
	float *fcoordarray;
	//not used for nodes
	unsigned int edgesRendered = 0;
	bool preview = false;
};