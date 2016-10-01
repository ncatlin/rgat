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
Header for sphere coordinate processing functions
*/
#pragma once
#include <stdafx.h>
#include "mathStructs.h"

void recalculate_scale(MULTIPLIERS *mults);
//take longitude a, latitude b, output coord in space
void sphereCoord(int ia, float b, FCOORD *c, MULTIPLIERS *dimensions, float diamModifier = 0);
float linedist(FCOORD *c1, FCOORD *c2);
float linedist(DCOORD *c1, FCOORD *c2);
void midpoint(FCOORD *c1, FCOORD *c2, FCOORD *c3);
void midpoint(DCOORD *c1, DCOORD *c2, DCOORD *c3);
float zoomFactor(long cameraZoom, long sphereSize);

//computes location of point 'pointnum' on a quadratic bezier curve divided into totalpoints segments
void bezierPT(FCOORD *startC, FCOORD *bezierC, FCOORD *endC, int pointnum, int totalpoints, FCOORD *resultC);
void sphereAB(FCOORD *c, float *a, float *b, MULTIPLIERS *dimensions);
void sphereAB(DCOORD *c, float *a, float *b, MULTIPLIERS *dimensions);
bool is_on_screen(DCOORD * screenCoord, void *clientState);
bool a_coord_on_screen(int a, int leftcol, int rightcol, float hedgesep);