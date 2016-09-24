#include "stdafx.h"
#include "traceMisc.h"
#include "OSspecific.h"
#include "GUIStructs.h"

//takes symbol+arguments and cats them together for display
string generate_funcArg_string(string sym, ARGLIST args)
{
	stringstream funcArgStr;
	cout << "drawsym (" << sym << ")"<<endl;
	funcArgStr << sym << "(";

	int numargs = args.size();
	for (int i = 0; i < numargs; ++i)
	{
		funcArgStr << args[i].first << ": " << args[i].second;
		if (i < numargs - 1)
			funcArgStr << ", ";
	}
	funcArgStr << ")";
	return funcArgStr.str();
}

//gets [mutation]'th disassembly of [address]. if absent or [getLatest] then returns the most recent 
INS_DATA* getDisassembly(unsigned long address,int mutation, HANDLE mutex, map<unsigned long, INSLIST> *disas, bool getLatest = false)
{
	obtainMutex(mutex, 4000);
	map<unsigned long, INSLIST>::iterator disasIt = disas->find(address);


	if (disasIt == disas->end() || (!getLatest && disasIt->second.size()-1 < (size_t)mutation))
	{
		int waitTime = 1;
		while (true)
		{
			dropMutex(mutex);
			Sleep(waitTime);

			obtainMutex(mutex, 4000);
			disasIt = disas->find(address);
			
			if (disasIt == disas->end())
			{
				waitTime += 5;
				if (waitTime > 600)
					cout<<"[rgat]Long wait for disassembly of " << address << ", mutation " << mutation << endl;
				continue;
			}

			if (getLatest)
			{
				mutation = disasIt->second.size() - 1;
				break;
			}
			else
				if (disasIt->second.size() - 1 >= (size_t)mutation)
					break;
				else
				{
					//Not found mutation? Give up and use the latest one
					//If display of mutating code is going bad, this might be where it happens.
					//Could also be a source of significant slowdown so wait time is reduced
					mutation = disasIt->second.size() - 1;
					/*
					waitTime += 40;
					if (waitTime > 120) {
						mutation = disasIt->second.size() - 1;
					}
					Sleep(waitTime);
					*/
				}
		}
	}

	INS_DATA *result = disasIt->second.at(mutation);
	dropMutex(mutex);
	return result;
}

//lot of stuff pushed on stack here for a common call. consider reworking
//this function is the biggest bottleneck (due to map lookups, not sleeping)
INS_DATA* getLastDisassembly(unsigned long address,unsigned int blockID, HANDLE mutex, 
	map<unsigned long, INSLIST> *disas, int *mutationIndex)
{
	obtainMutex(mutex, 4000);
	map<unsigned long, INSLIST>::iterator disasIt = disas->find(address);
	if (disasIt == disas->end())
	{
		dropMutex(mutex);
		int waitTime = 5;
		while (true)
		{
			cout << "[rgat]Waiting "<< waitTime << " ms for disassembly of addr " << std::hex << address << endl;
			Sleep(waitTime);
			obtainMutex(mutex, 4000);
			disasIt = disas->find(address);
			if (disasIt != disas->end())
				break;
			dropMutex(mutex);
			waitTime += 5;
		}
	}

	INS_DATA *result = disasIt->second.back();
	//make sure we are not looking at instruction from different block mutation
	if (std::find(result->blockIDs.begin(), result->blockIDs.end(), blockID) != result->blockIDs.end())
	{
		if (mutationIndex)
			*mutationIndex = disasIt->second.size() - 1;
	}
	else
	{
		while (true)
		{
			vector<INS_DATA *>::iterator insIt = disasIt->second.begin();
			int mut = 0;
			for (; insIt != disasIt->second.end(); ++insIt)
			{
				INS_DATA* ins = *insIt;
				if (std::find(ins->blockIDs.begin(), ins->blockIDs.end(), blockID) != ins->blockIDs.end())
				{
					if (mutationIndex)
						*mutationIndex = mut;
					result = ins;
					break;
				}
				++mut;
			}
			if (insIt != disasIt->second.end()) break;
			dropMutex(mutex);
			Sleep(2);
			obtainMutex(mutex, 4000);
			cout << "[rgat]Waiting for mutation (address " << std::hex << address << ")" << endl;
		}
	}
	
	dropMutex(mutex);
	return result;
}

//takes MARKER1234 buf, marker and target int
//if MARKER matches marker, converts 1234 to integer and places
//in target
int extract_integer(char *char_buf, string marker, int *target) {
	string pipeinput(char_buf);

	if (pipeinput.substr(0, marker.length()) == marker)
	{
		std::string::size_type sz = 0;
		string x = pipeinput.substr(marker.length(), pipeinput.length());
		try {
			*target = std::stoi(x, &sz);
		}
		catch (const std::exception& ia) {
			sz = 0;
		}

		if (sz == 0)
			return 0;
		else
			return 1;
	}
	else
		return 0;

}

int caught_stoi(string s,int *result, int base) {
	try {
		*result = std::stoi(s,0,base);
	}
	catch (std::exception const & e) {
		return 0;
	}
	return 1;
}

int caught_stoi(string s, unsigned int *result, int base) {
	try {
		*result = std::stoi(s, 0, base);
	}
	catch (std::exception const & e) {
		return 0;
	}
	return 1;
}

int caught_stol(string s, unsigned long *result, int base) {
	try {
		*result = std::stoll(s,0,base);
	}
	catch (std::exception const & e) {

		return 0;
	}
	return 1;
}
