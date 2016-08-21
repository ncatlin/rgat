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

struct VCOORD {
	int a; //accross/latitude
	int b; //down/longitude
	int bMod; //small modifications to longitude
};

struct MULTIPLIERS {
	long radius = 20000;
	long baseRadius = 20000;
	float HEDGESEP = 1;
	float userHEDGESEP = 1;
	float VEDGESEP = 1;
	float userVEDGESEP = 1;
	float userDiamModifier = 1;
	int sphereMaxA = 360;
	int sphereMaxB = 180;
};

struct PROJECTDATA {
	GLdouble model_view[16];
	GLdouble projection[16];
	GLint viewport[4];
};