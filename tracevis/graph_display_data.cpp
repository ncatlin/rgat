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

#ifdef XP_COMPATIBLE
	posmutex = CreateMutex(NULL, FALSE, NULL);
	colmutex = CreateMutex(NULL, FALSE, NULL);
#endif
	numVerts = 0;
	edgesRendered = 0;
}

GRAPH_DISPLAY_DATA::~GRAPH_DISPLAY_DATA()
{
	acquire_pos_write();
	acquire_col_write();
}

bool GRAPH_DISPLAY_DATA::get_coord(unsigned int index, FCOORD* result)
{
	const unsigned int listIndex = index*POSELEMS;
	if (listIndex >= vposarray.size()) return false;

	acquire_pos_read(12);
	//wonder if we can do this in one range call
	result->x = vposarray.at(listIndex);
	result->y = vposarray.at(listIndex + 1);
	result->z = vposarray.at(listIndex + 2);
	release_pos_read();

	return true;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_pos_read(int holder)
{
#ifdef XP_COMPATIBLE
	obtainMutex(posmutex, 1007);
#else
	AcquireSRWLockShared(&poslock);
#endif

	return &vposarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_pos_write(int holder)
{
#ifdef XP_COMPATIBLE
	obtainMutex(posmutex, 1007);
#else
	AcquireSRWLockExclusive(&poslock);
#endif
	return &vposarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_col_read()
{
#ifdef XP_COMPATIBLE
	obtainMutex(colmutex, 1007);
#else
	AcquireSRWLockShared(&collock);
#endif
	return &vcolarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_col_write()
{
#ifdef XP_COMPATIBLE
	obtainMutex(colmutex, 1007);
#else
	AcquireSRWLockExclusive(&collock);
#endif
	return &vcolarray;
}

void GRAPH_DISPLAY_DATA::release_pos_write()
{
#ifdef XP_COMPATIBLE
	dropMutex(posmutex);
#else
	ReleaseSRWLockExclusive(&poslock);
#endif
}

void GRAPH_DISPLAY_DATA::release_pos_read()
{
#ifdef XP_COMPATIBLE
	dropMutex(posmutex);
#else
	ReleaseSRWLockShared(&poslock);
#endif
}

void GRAPH_DISPLAY_DATA::release_col_write()
{
#ifdef XP_COMPATIBLE
	dropMutex(posmutex);
#else
	ReleaseSRWLockExclusive(&collock);
#endif
}

void GRAPH_DISPLAY_DATA::release_col_read()
{
#ifdef XP_COMPATIBLE
	dropMutex(posmutex);
#else
	ReleaseSRWLockShared(&collock);
#endif
}

//TODO: this is awful. need to add to vector vert by vert
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
	assert(0);
	acquire_pos_write(266);
	acquire_col_write();
	edgesRendered = 0;
	release_col_write();
	release_pos_write();
}

void GRAPH_DISPLAY_DATA::reset()
{
	acquire_pos_write(342);
	acquire_col_write();
	//needed? try without
	vposarray.clear();
	vcolarray.clear();
	numVerts = 0;
	edgesRendered = 0;
	release_col_write();
	release_pos_write();
}