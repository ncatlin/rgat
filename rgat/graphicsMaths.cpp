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
Graph layout coordinate processing functions
*/
#include "stdafx.h"
#include "GUIConstants.h"
#include "graphicsMaths.h"
#include "traceStructs.h"

//returns number in the repeating range 0.0-1.0-0.0, oscillating with the clock
float getPulseAlpha()
{
	clock_t clockVal = clock();
	int millisecond = ((int)(clockVal / 100)) % 10;
	int countUp = ((int)(clockVal / 1000) % 10) % 2;

	float pulseAlpha;
	if (countUp)
		pulseAlpha = (float)millisecond / 10.0;
	else
		pulseAlpha = 1.0 - (millisecond / 10.0);

	return pulseAlpha;
}


//returns a small number indicating rough zoom
float zoomFactor(double cameraZoom, long plotSize)
{
	return ((abs(cameraZoom) - plotSize) / 1000) - 1;
}

//distance between two points
float linedist(FCOORD *c1, FCOORD *c2)
{
	float dist = pow((c2->x - c1->x), 2);
	dist += pow((c2->y - c1->y), 2);
	dist += pow((c2->z - c1->z), 2);
	return sqrt(dist);
}

//double version
float linedist(DCOORD *lineStart, FCOORD *lineEnd)
{
	float dist = pow((lineEnd->x - lineStart->x), 2);
	dist += pow((lineEnd->y - lineStart->y), 2);
	dist += pow((lineEnd->z - lineStart->z), 2);
	return sqrt(dist);
}

//middle of line c1->c2 placed in c3
void midpoint(FCOORD *lineStart, FCOORD *lineEnd, FCOORD *midPointCoord) 
{
	midPointCoord->x = (lineStart->x + lineEnd->x) / 2;
	midPointCoord->y = (lineStart->y + lineEnd->y) / 2;
	midPointCoord->z = (lineStart->z + lineEnd->z) / 2;
}

//double version
void midpoint(DCOORD *lineStart, DCOORD *lineEnd, DCOORD *midPointCoord) 
{
	midPointCoord->x = (lineStart->x + lineEnd->x) / 2;
	midPointCoord->y = (lineStart->y + lineEnd->y) / 2;
	midPointCoord->z = (lineStart->z + lineEnd->z) / 2;
}

//computes location of point 'pointnum' on a quadratic bezier curve divided into totalpoints segments
void bezierPT(FCOORD *startC, FCOORD *bezierC, FCOORD *endC, int pointnum, int totalpoints, FCOORD *resultC)
{
	float t = float(pointnum) / float(totalpoints);

	//quadratic bezier
	resultC->x = ((1 - t) * (1 - t) * startC->x + 2 * (1 - t) * t * bezierC->x + t * t * endC->x);
	resultC->y = ((1 - t) * (1 - t) * startC->y + 2 * (1 - t) * t * bezierC->y + t * t * endC->y);
	resultC->z = ((1 - t) * (1 - t) * startC->z + 2 * (1 - t) * t * bezierC->z + t * t * endC->z);
}



//returns if the coord is present on the screen
bool is_on_screen(DCOORD * screenCoord, int screenWidth, int screenHeight)
{
	if (screenCoord->x < screenWidth &&
		screenCoord->y < screenHeight &&
		screenCoord->x > 0 && screenCoord->y > 0 
		)
		return true;
	else
		return false;
}