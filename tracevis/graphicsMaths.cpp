#include "stdafx.h"
#include "GUIStructs.h"
#include "GUIConstants.h"
#include "graphicsMaths.h"
#include "traceStructs.h"

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

void sphereAB(DCOORD *c, float *a, float *b, MULTIPLIERS *mults)
{
	FCOORD FFF;
	FFF.x = c->x;
	FFF.y = c->y;
	FFF.z = c->z;
	sphereAB(&FFF, a, b, mults);
}

float linedist(FCOORD *c1, FCOORD *c2)
{
	float dist = pow((c2->x - c1->x), 2);
	dist += pow((c2->y - c1->y), 2);
	dist += pow((c2->z - c1->z), 2);
	return sqrt(dist);
}

float linedist(DCOORD *c1, FCOORD *c2)
{
	float dist = pow((c2->x - c1->x), 2);
	dist += pow((c2->y - c1->y), 2);
	dist += pow((c2->z - c1->z), 2);
	return sqrt(dist);
}

void midpoint(FCOORD *c1, FCOORD *c2, FCOORD *c3) {
	c3->x = (c1->x + c2->x) / 2;
	c3->y = (c1->y + c2->y) / 2;
	c3->z = (c1->z + c2->z) / 2;
	return;
}

void midpoint(DCOORD *c1, DCOORD *c2, DCOORD *c3) {
	c3->x = (c1->x + c2->x) / 2;
	c3->y = (c1->y + c2->y) / 2;
	c3->z = (c1->z + c2->z) / 2;
	return;
}
//computes location of point 'pointnum' on a quadratic bezier curve divided into totalpoints segments
void bezierPT(FCOORD *startC, FCOORD *bezierC, FCOORD *endC, int pointnum, int totalpoints, FCOORD *resultC)
{
	float t = float(pointnum) / float(totalpoints);
	float tSq = t*t;

	//end line
	//quadratic bezier
	resultC->x = ((1 - t) * (1 - t) * startC->x + 2 * (1 - t) * t * bezierC->x + t * t * endC->x);
	resultC->y = ((1 - t) * (1 - t) * startC->y + 2 * (1 - t) * t * bezierC->y + t * t * endC->y);
	resultC->z = ((1 - t) * (1 - t) * startC->z + 2 * (1 - t) * t * bezierC->z + t * t * endC->z);
}

//take an a coordinate, left and right columns of screen, horiz sep
//return if coord is within those columns
//only as accurate as the mystery constant
bool a_coord_on_screen(int a, int leftcol, int rightcol, float hedgesep)
{
	int coordcolumn = floor(-a / (COLOUR_PICKING_MYSTERY_CONSTANTA / hedgesep));
	coordcolumn = coordcolumn % ADIVISIONS;

	if (leftcol > rightcol)
	{
		int shifter = ADIVISIONS - leftcol;
		leftcol = 0;
		rightcol += shifter;
		coordcolumn += shifter;
	}

	if (coordcolumn >= leftcol && coordcolumn <= rightcol) return true;
	else return false;
}

bool is_on_screen(DCOORD * screenCoord, void *clientstate)
{
	VISSTATE *castclientstate = (VISSTATE *) clientstate;
	if (screenCoord->x < castclientstate->size.width &&
		screenCoord->y < castclientstate->size.height &&
		screenCoord->x > 0 &&
		screenCoord->y > 0 
		)
	{
		//printf("c %f,%f,%f\n", screenCoord->x, screenCoord->y, screenCoord->z);
		return true;
	}
	else
		return false;
}

//not used but keep in case
float sphereDist(FCOORD pt) {
	return sqrtf((pt.x - 0)*(pt.x - 0) + (pt.y - 0) *(pt.y - 0) + (pt.z - 0) *(pt.z - 0));
}

void spherePtDist(FCOORD pt, float dist) {
	float divisor = sphereDist(pt) / dist;
	FCOORD answer;
	answer.x = pt.x / divisor;
	answer.y = pt.y / divisor;
	answer.x = pt.z / divisor;
	float res = sphereDist(answer);
	if (res == dist)
		printf("Success %f == %f\n", res, dist);
	else
		printf("failure %f != %f\n", res, dist);
}
