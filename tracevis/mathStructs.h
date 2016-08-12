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
	float radius = 0;
	float HEDGESEP = 0;
	float userHEDGESEP = 0;
	float VEDGESEP = 0;
	float userVEDGESEP = 0;
	float userDiamModifier = 1;
};

struct PROJECTDATA {
	GLdouble model_view[16];
	GLdouble projection[16];
	GLint viewport[4];
};