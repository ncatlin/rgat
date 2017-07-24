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
Misc disassembly and conversion functions
*/
#include "stdafx.h"
#include "traceMisc.h"
#include "OSspecific.h"
//#include "GUIStructs.h"



//takes symbol+arguments and cats them together for display
string generate_funcArg_string(string sym, ARGLIST *args)
{
	stringstream funcArgStr;
	funcArgStr << sym << "(";

	if (args)
	{
		int numargs = args->size();
		for (int i = 0; i < numargs; ++i)
		{
			ARGIDXDATA arg = args->at(i);
			funcArgStr << arg.first << ": " << arg.second;
			if (i < numargs - 1)
				funcArgStr << ", ";
		}
	}

	funcArgStr << ")";
	return funcArgStr.str();
}


//takes "MARKERBXXXX" char buf
//if "MARKER" matches marker, converts XXXX to integer and places in pid
//returns bitwidth or 0 for failure
cs_mode extract_pid_bitwidth_path(vector <char> *char_buf, string marker, PID_TID *pid, int *PID_ID, boost::filesystem::path* binarypath)
{

	std::string pipeinput(char_buf->begin(), char_buf->end());
	if (pipeinput.substr(0, marker.length()) != marker) return (cs_mode)0;

	cs_mode bitWidth;
	char bitWidthChar = pipeinput.at(marker.length());
	if (bitWidthChar == '3')
		bitWidth = CS_MODE_32;
	else if (bitWidthChar == '6')
		bitWidth = CS_MODE_64;
	else
		return (cs_mode)NULL;

	int pos;
	//go to the PID string
	for (pos = marker.length() + 1; pos < pipeinput.length(); pos++)
	{
		if (pipeinput.at(pos) == 'r') { break; }
	}

	std::string::size_type sz = 0;
	string pidstring = pipeinput.substr(marker.length() + 1, pos);
	try {
		*pid = std::stoul(pidstring, &sz);
	}
	catch (const std::exception& e) {
		sz = 0;
	}

	if (sz == 0) return (cs_mode)0;

	//go to the random int string
	int pos2 = pos + 1;
	for (; pos2 < pipeinput.length(); pos2++)
		if (pipeinput.at(pos2) == 'p') { break; }

	string randstring = pipeinput.substr(pos + 1, pos2 - pos);
	try {
		*PID_ID = std::stoi(randstring);
	}
	catch (const std::exception& e) {
		sz = 0;
	}

	if (sz == 0) return (cs_mode)0;

	string pathstring = pipeinput.substr(pos2 + 1, pipeinput.length());
	boost::filesystem::path boostpath(pathstring);
	*binarypath = boostpath.generic_path();
	return bitWidth;
}

int extract_tid(char *char_buf, string marker, PID_TID *tid)
{
	string pipeinput(char_buf);
	if (pipeinput.substr(0, marker.length()) != marker) return 0;

	std::string::size_type sz = 0;
	string x = pipeinput.substr(marker.length(), pipeinput.length());
	try {
		*tid = std::stoul(x, &sz);
	}
	catch (const std::exception& e) {
		sz = 0;
	}

	if (sz == 0) return 0;
	else return 1;
}

int caught_stoi(string s, int *result, int base)
{
	if (s.empty()) return 0;
	try {
		*result = std::stoi(s, 0, base);
	}
	catch (std::exception const & e) {
		return 0;
	}
	return 1;
}

int caught_stoi(string s, unsigned int *result, int base)
{
	if (s.empty()) return 0;

	try {
		*result = std::stoi(s, 0, base);
	}
	catch (std::exception const & e) {
		return 0;
	}
	return 1;
}

int caught_stoul(string s, unsigned long *result, int base) {
	if (s.empty()) return 0;

	try {
		*result = std::stoul(s, 0, base);
	}
	catch (std::exception const & e) {

		return 0;
	}
	return 1;
}

int caught_stoull(string s, unsigned long long *result, int base) {
	if (s.empty()) return 0;

	try {
		*result = std::stoull(s, 0, base);
	}
	catch (std::exception const & e) {

		return 0;
	}
	return 1;
}