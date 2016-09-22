#pragma once
#include <stdafx.h>
#include <GUIStructs.h>

string getModulePath();
string get_dr_path();
bool fileExists(string path);
void execute_tracer(string executable, VISSTATE *clientState);
bool getSavePath(VISSTATE *clientState, string *result, int PID);
