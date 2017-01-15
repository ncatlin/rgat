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
Misc disassembly and conversion functions
*/
#include "stdafx.h"
#include "traceMisc.h"
#include "OSspecific.h"
#include "GUIStructs.h"

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

INSLIST* getDisassemblyBlock(MEM_ADDRESS blockaddr, BLOCK_IDENTIFIER blockID,
	PROCESS_DATA *piddata, bool *dieFlag)
{
	int iterations = 0;

	map<MEM_ADDRESS, map<BLOCK_IDENTIFIER, INSLIST *>>::iterator blockIt;
	while (true)
	{
		piddata->getDisassemblyReadLock();
		blockIt = piddata->blocklist.find(blockaddr);
		piddata->dropDisassemblyReadLock();

		if (blockIt != piddata->blocklist.end()) break;

		piddata->getExternlistReadLock();
		int externCount = piddata->externdict.count(blockaddr);
		piddata->dropExternlistReadLock();

		if (externCount> 0) return 0;
	

		if (iterations++ > 20)
			cerr << "[rgat]Warning: Long wait for disassembly of address 0x" << std::hex << blockaddr << endl;

		Sleep(1);
		if (*dieFlag) return 0;
	}

	INSLIST *resultPtr;
	map<BLOCK_IDENTIFIER, INSLIST *>::iterator mutationIt;

	while (true)
	{
		piddata->getDisassemblyReadLock();
		if (blockID == 0 && !blockIt->second.empty())
		{
			resultPtr = blockIt->second.begin()->second;
			piddata->dropDisassemblyReadLock();
			break;
		}

		mutationIt = blockIt->second.find(blockID);
		piddata->dropDisassemblyReadLock();

		if (mutationIt != blockIt->second.end())
		{
			resultPtr = mutationIt->second;
			break;
		}

		if (iterations++ > 20)
			cerr << "[rgat]Warning... long wait for blockID "<< std::hex << blockID <<"of address 0x" << blockaddr << endl;
		Sleep(1);
		if (*dieFlag) return 0;
	}

	return resultPtr;
}

//takes "MARKERBXXXX" char buf
//if "MARKER" matches marker, converts XXXX to integer and places in pid
//returns bitwidth or 0 for failure
cs_mode extract_pid_bitwidth(char *char_buf, string marker, PID_TID *pid)
{
	string pipeinput(char_buf);
	if (pipeinput.substr(0, marker.length()) != marker) return (cs_mode)0;

	cs_mode bitWidth;
	char bitWidthChar = pipeinput.at(marker.length());
	if (bitWidthChar == '3')
		bitWidth = CS_MODE_32;
	else if (bitWidthChar == '6')
		bitWidth = CS_MODE_64;
	else
		return (cs_mode)NULL;

	std::string::size_type sz = 0;
	string pidstring = pipeinput.substr(marker.length()+1, pipeinput.length());
	try {
		*pid = std::stoul(pidstring, &sz);
	}
	catch (const std::exception& e) {
		sz = 0;
	}

	if (sz == 0) return (cs_mode)0;
	else return bitWidth;
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
		*result = std::stoi(s,0,base);
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
		*result = std::stoul(s,0,base);
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