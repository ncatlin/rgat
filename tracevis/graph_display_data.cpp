#include <graph_display_data.h>
#include <traceMisc.h>
#include "OSspecific.h"

//time to split line/node data sperate
GRAPH_DISPLAY_DATA::GRAPH_DISPLAY_DATA(bool prev)
{
	if (prev) preview = true;
	posmutex = CreateMutex(NULL, FALSE, NULL);
	colmutex = CreateMutex(NULL, FALSE, NULL);
	numVerts = 0;
	edgesRendered = 0;
}

GRAPH_DISPLAY_DATA::~GRAPH_DISPLAY_DATA()
{
	obtainMutex(colmutex, INFINITE);
	obtainMutex(posmutex, INFINITE);
}

bool GRAPH_DISPLAY_DATA::get_coord(unsigned int index, FCOORD* result)
{
	const unsigned int listIndex = index*POSELEMS;
	if (listIndex >= vposarray.size()) return false;

	obtainMutex(posmutex, 6000);
	result->x = vposarray.at(listIndex);
	result->y = vposarray.at(listIndex + 1);
	result->z = vposarray.at(listIndex + 2);
	dropMutex(posmutex);
	return true;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_pos()
{
	bool result = obtainMutex(posmutex, INFINITE);
	if (!result) return 0;
	return &vposarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_col()
{
	bool result = obtainMutex(colmutex, INFINITE);
	if (!result) {
		cerr << "[rgat]Acquire_col: Failed to obtain colmutex" << endl; return 0;
	}
	return &vcolarray;
}

void GRAPH_DISPLAY_DATA::release_pos()
{
	dropMutex(posmutex);	
}

void GRAPH_DISPLAY_DATA::release_col()
{
	dropMutex(colmutex);
}

//TODO: this is awful. need to add to vector ert by vert
//when number of verts increases also checks buffer sizes
//mutexes are bit dodgy, expect them to be held by caller
void GRAPH_DISPLAY_DATA::set_numVerts(unsigned int num)
{ 
	assert(num >= numVerts);
	numVerts = num;

	posSize = numVerts * POSELEMS * sizeof(float);
	colSize = numVerts * COLELEMS * sizeof(float);
	vcolarraySize = vcolarray.size();
}

//delete me if unused
void GRAPH_DISPLAY_DATA::clear()
{
	acquire_pos();
	acquire_col();
	edgesRendered = 0;
	release_col();
	release_pos();
}

void GRAPH_DISPLAY_DATA::reset()
{
	acquire_pos();
	acquire_col();
	//needed? try without
	vposarray.clear();
	vcolarray.clear();
	numVerts = 0;
	edgesRendered = 0;
	release_col();
	release_pos();
}