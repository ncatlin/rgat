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
This class holds (and provides dubiously mutex guarded access to) OpenGL vertex and colour data
*/
#include "stdafx.h"
#include <graph_display_data.h>
#include <traceMisc.h>
#include "OSspecific.h"
#include "graphicsMaths.h"
#include "GUiconstants.h"

//time to split line/node data sperate
GRAPH_DISPLAY_DATA::GRAPH_DISPLAY_DATA(bool prev)
{
	if (prev) preview = true;

	numVerts = 0;
	edgesRendered = 0;
}

GRAPH_DISPLAY_DATA::~GRAPH_DISPLAY_DATA()
{
	acquire_pos_write();
	acquire_col_write();
}

bool GRAPH_DISPLAY_DATA::get_coord(NODEINDEX index, FCOORD* result)
{
	const unsigned long listIndex = index*POSELEMS;
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
	AcquireSRWLockShared(&poslock);
	return &vposarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_pos_write(int holder)
{

	AcquireSRWLockExclusive(&poslock);
	return &vposarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_col_read()
{
	AcquireSRWLockShared(&collock);
	return &vcolarray;
}

vector<float> *GRAPH_DISPLAY_DATA::acquire_col_write()
{
	AcquireSRWLockExclusive(&collock);
	return &vcolarray;
}

void GRAPH_DISPLAY_DATA::release_pos_write()
{
	ReleaseSRWLockExclusive(&poslock);
}

void GRAPH_DISPLAY_DATA::release_pos_read()
{
	ReleaseSRWLockShared(&poslock);
}

void GRAPH_DISPLAY_DATA::release_col_write()
{
	ReleaseSRWLockExclusive(&collock);
}

void GRAPH_DISPLAY_DATA::release_col_read()
{
	ReleaseSRWLockShared(&collock);
}

//TODO: this is awful. need to add to vector vert by vert
//when number of verts increases also checks buffer sizes
//mutexes are bit dodgy, expect them to be held by caller
void GRAPH_DISPLAY_DATA::set_numVerts(GLsizei num)
{ 
	assert(num >= (GLsizei)numVerts);
	numVerts = num;
	vcolarraySize = (unsigned long)vcolarray.size();
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

//draw basic opengl line between 2 points
void GRAPH_DISPLAY_DATA::drawShortLinePoints(FCOORD *startC, FCOORD *endC, QColor *colour, long *arraypos)
{
	vector <float> *vpos = acquire_pos_write(52);
	vector <float> *vcol = acquire_col_write();

	GLsizei numverts = get_numVerts();
	*arraypos = (long)vcol->size();

	vpos->push_back(startC->x);
	vpos->push_back(startC->y);
	vpos->push_back(startC->z);
	vcol->push_back(colour->redF());
	vcol->push_back(colour->greenF());
	vcol->push_back(colour->blueF());
	vcol->push_back(colour->alphaF());

	vpos->push_back(endC->x);
	vpos->push_back(endC->y);
	vpos->push_back(endC->z);
	vcol->push_back(colour->redF());
	vcol->push_back(colour->greenF());
	vcol->push_back(colour->blueF());
	vcol->push_back(colour->alphaF());

	set_numVerts(numverts + 2);
	release_pos_write();
	release_col_write();

}

//draws a long curve with multiple vertices
int GRAPH_DISPLAY_DATA::drawLongCurvePoints(FCOORD *bezierC, FCOORD *startC, FCOORD *endC, QColor *colour, int edgeType, long *colarraypos)
{
	//bold start, faded end (convey direction)
	//float fadeArray[] = { 1, 1, 1, (float)0.7, (float)0.9, (float)0.9, (float)0.9, (float)0.7, (float)0.8, (float)0.8,
	//	(float)0.6, (float)0.7, (float)0.7, (float)0.5, (float)0.5, (float)0.4, (float)0.4 };
	//faded start, bold end (convey direction)
	float fadeArray[] = { 0.4f, 0.4f, 0.5f, 0.5f, 0.7f, 0.7f, 0.6f, 0.8f, 0.8f, 0.7f, 0.9f, 0.9f, 0.9f, 0.7f,  1, 1, 1, };

	int vsadded = 0;
	int curvePoints = LONGCURVEPTS + 2;
	vector<GLfloat> *vertpos = acquire_pos_write(63);
	vector<GLfloat> *vertcol = acquire_col_write();

	if (!vertpos || !vertcol)
	{
		assert(0);
		return 0;
	}
	*colarraypos = (long)vertcol->size();

	vertpos->push_back(startC->x);
	vertpos->push_back(startC->y);
	vertpos->push_back(startC->z);

	float colours[4] = { (float)colour->redF() , (float)colour->greenF(), (float)colour->blueF(), (float)colour->alphaF() };
	vertcol->insert(vertcol->end(), colours, end(colours));
	++vsadded;
	// > for smoother lines, less performance
	int dt;
	float fadeA = (float)0.9;
	FCOORD resultC;

	int segments = float(curvePoints) / 2;
	for (dt = 1; dt < segments + 1; ++dt)
	{
		fadeA = fadeArray[dt - 1];
		if (fadeA > 1) fadeA = 1;

		colours[3] = fadeA;

		bezierPT(startC, bezierC, endC, dt, segments, &resultC);

		//end last line
		vertpos->push_back(resultC.x);
		vertpos->push_back(resultC.y);
		vertpos->push_back(resultC.z);
		vertcol->insert(vertcol->end(), colours, end(colours));
		++vsadded;

		//start new line at same point 
		//todo: this is waste of memory but far too much effort to fix for minimal gain
		vertpos->push_back(resultC.x);
		vertpos->push_back(resultC.y);
		vertpos->push_back(resultC.z);
		vertcol->insert(vertcol->end(), colours, end(colours));
		++vsadded;
	}

	vertpos->push_back(endC->x);
	vertpos->push_back(endC->y);
	vertpos->push_back(endC->z);
	++vsadded;
	colours[3] = 1;
	vertcol->insert(vertcol->end(), colours, end(colours));

	GLsizei numverts = get_numVerts();

	set_numVerts(numverts + curvePoints + 2);
	release_col_write();
	release_pos_write();

	return curvePoints + 2;
}