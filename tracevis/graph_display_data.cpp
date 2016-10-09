/*
Copyright 2016 Nia Catlin

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
	obtainMutex(colmutex, 9004);
	obtainMutex(posmutex, 9005);
}

bool GRAPH_DISPLAY_DATA::get_coord(unsigned int index, FCOORD* result)
{
	const unsigned int listIndex = index*POSELEMS;
	if (listIndex >= vposarray.size()) return false;

	obtainMutex(posmutex, 1006);
	result->x = vposarray.at(listIndex);
	result->y = vposarray.at(listIndex + 1);
	result->z = vposarray.at(listIndex + 2);
	dropMutex(posmutex);
	return true;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_pos(int holder)
{
	bool result = obtainMutex(posmutex, 1007);
	//printf("holder %d got 1007 --- ", holder);
	if (!result) return 0;
	return &vposarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_col()
{
	obtainMutex(colmutex, 2000);
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