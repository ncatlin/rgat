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
Sphere coordinate processing functions
*/
#include "stdafx.h"
#include "GUIStructs.h"
#include "GUIConstants.h"
#include "graphicsMaths.h"
#include "traceStructs.h"

//returns a small number indicating rough zoom
float zoomFactor(long cameraZoom, long sphereSize)
{
	return ((cameraZoom - sphereSize) / 1000) - 1;
}

//propagates changes to the sphere size to the separation between coordinates
void recalculate_scale(MULTIPLIERS *mults)
{
	mults->radius = mults->baseRadius * mults->userDiamModifier;

	float HSCALE = 3;
	float HMULTIPLIER = float(mults->radius / HSCALE);
	float HRANGE = float(360 * HSCALE);
	mults->HEDGESEP = float((360 / HRANGE) * (HMULTIPLIER / mults->radius)) + (mults->userHEDGESEP-1);

	float VSCALE = 3;
	float VMULTIPLIER = float(mults->radius / VSCALE);
	float VRANGE = float(360 * VSCALE);
	mults->VEDGESEP = float((360 / VRANGE) * (VMULTIPLIER / mults->radius)) + (mults->userVEDGESEP-1);

}

//take longitude a, latitude b, output coord in space
//diamModifier allows specifying different sphere sizes
void sphereCoord(int ia, float b, FCOORD *c, MULTIPLIERS *dimensions, float diamModifier) {

	float a = ia*dimensions->HEDGESEP;
	b *= dimensions->VEDGESEP;
	b += BAdj; //offset start down on sphere

	float sinb = sin((b*M_PI) / 180);
	float r = (dimensions->radius + diamModifier);// +0.1 to make sure we are above lines

	//think this order is right, still dont get why numbers are fucked
	c->x = r * sinb * cos((a*M_PI) / 180);
	c->y = r * cos((b*M_PI) / 180);
	c->z = r * sinb * sin((a*M_PI) / 180);
}

//take coord in space, convert back to a/b
void sphereAB(FCOORD *c, float *a, float *b, MULTIPLIERS *mults)
{
	float acosb = acos(c->y / (mults->radius + 0.099));
	float tb = DEGREESMUL*acosb;  //acos is a bit imprecise / wrong...

	float ta = DEGREESMUL * (asin((c->z / (mults->radius + 0.1)) / sin(acosb)));
	tb -= BAdj;
	*a = ta / mults->HEDGESEP;
	*b = tb / mults->VEDGESEP;
}

//double version
void sphereAB(DCOORD *c, float *a, float *b, MULTIPLIERS *mults)
{
	FCOORD FFF;
	FFF.x = c->x;
	FFF.y = c->y;
	FFF.z = c->z;
	sphereAB(&FFF, a, b, mults);
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
void midpoint(FCOORD *lineStart, FCOORD *lineEnd, FCOORD *midPointCoord) {
	midPointCoord->x = (lineStart->x + lineEnd->x) / 2;
	midPointCoord->y = (lineStart->y + lineEnd->y) / 2;
	midPointCoord->z = (lineStart->z + lineEnd->z) / 2;
}

//double version
void midpoint(DCOORD *lineStart, DCOORD *lineEnd, DCOORD *midPointCoord) {
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

/*
input: an 'a' coordinate, left and right columns of screen, horiz separation
return: if coord is within those columns
only as accurate as the inaccurate mystery constant

TODO: come up with a way of deriving row 'b' from a given coordinate
then we can improve performance even more by looking at the top and bottom rows
instead of getting everything in the column

Graph tends to not have much per column though so this isn't a desperate requirement
*/
bool a_coord_on_screen(int a, int leftcol, int rightcol, float hedgesep)
{
	/* the idea here is to calculate the column of the given coordinate
	   dunno how though!
	   FIX ME - to fix text display
	*/
									//bad bad bad bad bad bad bad... but close. gets worse the wider the graph is
	int coordcolumn = floor(-a / (COLOUR_PICKING_MYSTERY_CONSTANTA / hedgesep));
	coordcolumn = coordcolumn % ADIVISIONS;

	if (leftcol > rightcol)
	{
		int shifter = ADIVISIONS - leftcol;
		leftcol = 0;
		rightcol += shifter;
		coordcolumn += shifter;
	}

	//this code is horrendous and doesn't fix it and ugh
	int stupidHack = 1;
	if ((coordcolumn >= leftcol) && (coordcolumn <= (rightcol+stupidHack))) return true;
	else return false;
}

//returns if the coord is present on the screen
bool is_on_screen(DCOORD * screenCoord, void *clientState)
{
	VISSTATE *castclientState = (VISSTATE *) clientState; //compiler goes berserk if the header has GUIstructs
	if (screenCoord->x < castclientState->mainFrameSize.width &&
		screenCoord->y < castclientState->mainFrameSize.height &&
		screenCoord->x > 0 && screenCoord->y > 0 
		)
		return true;
	else
		return false;
}