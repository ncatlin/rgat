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
Structures used to hold coordinate and OpenGL state information
*/
#pragma once
struct FCOORD {
	float x = 0;
	float y = 0;
	float z = 0;
};

struct DCOORD {
	double x = 0;
	double y = 0;
	double z = 0;
};

struct CYLINDERCOORD {
	float a; //across/latitude
	float b; //down/longitude
	int bMod; //small modifications to longitude
};

struct TREECOORD {
	long x; //across
	long y; //up/down
	long z; //depth (towards away from screen)
};

struct GRAPH_SCALE {
	long plotSize = 10000;
	long basePlotSize = 10000;
	float userSizeModifier = 1;
	int maxA = 360;
	int maxB = 180;
	int maxC = 1;
	int pix_per_A, pix_per_B, original_pix_per_A, original_pix_per_B;
	float stretchA = 1, stretchB = 1;
};

struct PROJECTDATA 
{
	GLdouble model_view[16];
	GLdouble projection[16];
	GLint viewport[4];
};

#define COLELEMS 4
#define POSELEMS 3