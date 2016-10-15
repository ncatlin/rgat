// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once
#define WINDOWS
#define X86_32

//#define XP_COMPATIBLE

//not implemented yet
//#define LINUX
//#define X86_64

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#ifdef WINDOWS
#include <shlwapi.h>
#endif

#define RGAT_VERSION_MAJ 0
#define RGAT_VERSION_MIN 3
#define RGAT_VERSION_FEATURE 0
#define RGAT_VERSION_DESCRIPTION "Preview/Unstable"

using namespace std;
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <set>
#include <map>
#include <queue>
#include <unordered_map>
#include <math.h>
#include <queue>

#include <allegro5/allegro.h>
#include <allegro5/allegro_opengl.h>
#include <allegro5/allegro_windows.h>
#include <allegro5\allegro_image.h>
#include <allegro5/allegro_font.h>
#include <allegro5/allegro_ttf.h>
#include <allegro5/allegro_native_dialog.h>

#include <capstone.h>

#include <GL/glu.h>
#include <GL/gl.h>


#define COLELEMS 4
#define POSELEMS 3