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
Class describing each node
*/
#include "stdafx.h"
#include "node_data.h"
#include "b64.h"
#include "graphicsMaths.h"
#include "GUIConstants.h"
#include "traceMisc.h"


bool node_data::serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer)
{
	writer.StartArray();

	writer.Uint(index);
	writer.Uint(conditional);
	writer.Uint(nodeMod);
	writer.Uint64(address);
	writer.Uint64(executionCount);

	writer.StartArray();
	set<unsigned int>::iterator adjacentIt = incomingNeighbours.begin();
	for (; adjacentIt != incomingNeighbours.end(); ++adjacentIt)
		writer.Uint(*adjacentIt);
	writer.EndArray();

	writer.StartArray();
	adjacentIt = outgoingNeighbours.begin();
	for (; adjacentIt != outgoingNeighbours.end(); ++adjacentIt)
		writer.Uint(*adjacentIt);
	writer.EndArray();

	writer.Bool(external);

	if (!external)
		writer.Uint(ins->mutationIndex);
	else
	{
		writer.StartArray(); //function calls
		vector<ARGLIST>::iterator callIt = funcargs.begin();
		ARGLIST::iterator argIt;
		for (; callIt != funcargs.end(); callIt++)
		{
			writer.StartArray(); //arguments
			for (argIt = callIt->begin(); argIt != callIt->end(); argIt++)
			{
				string argstring = argIt->second;
				const unsigned char* cus_argstring = reinterpret_cast<const unsigned char*>(argstring.c_str());

				writer.StartArray(); //arg index, contents
				writer.Uint(argIt->first);
				writer.String(base64_encode(cus_argstring, argstring.size()).c_str());
				writer.EndArray();
			}
			writer.EndArray(); //end lsit of args for this call
		}
		writer.EndArray(); //end list of calls for this node
	}
	writer.EndArray(); //end node

	return true;
}


int node_data::unserialise(ifstream *file, map <MEM_ADDRESS, INSLIST> *disassembly)
{
	string value_s;

	getline(*file, value_s, '{');
	if (value_s == "}N,D") return 0;

	if (!caught_stoi(value_s, (int *)&index, 10))
		return -1;

	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, (int *)&conditional, 10))
		return -1;

	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, &nodeMod, 10))
		return -1;

	getline(*file, value_s, ',');
	if (!caught_stoull(value_s, &address, 10))
		return -1;

	getline(*file, value_s, ',');
	if (!caught_stoul(value_s, &executionCount, 10))
		return -1;

	unsigned int adjacentQty;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, &adjacentQty, 10))
		return -1;

	for (unsigned int i = 0; i < adjacentQty; ++i)
	{
		unsigned int adjacentIndex;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, &adjacentIndex, 10))
			return -1;
		incomingNeighbours.insert(adjacentIndex);
	}

	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, &adjacentQty, 10))
		return -1;

	for (unsigned int i = 0; i < adjacentQty; ++i)
	{
		unsigned int adjacentIndex;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, &adjacentIndex, 10))
			return -1;
		outgoingNeighbours.insert(adjacentIndex);
	}

	getline(*file, value_s, ',');
	if (value_s.at(0) == '0')
	{
		external = false;

		getline(*file, value_s, '}');
		if (!caught_stoi(value_s, (int *)&blockID, 10))
			return -1;

		map<MEM_ADDRESS, INSLIST>::iterator addressIt = disassembly->find(address);
		if ((addressIt == disassembly->end()) || (blockID >= addressIt->second.size()))
			return -1;

		ins = addressIt->second.at(blockID);
		return 1;
	}

	external = true;

	int numCalls;
	getline(*file, value_s, ',');
	if (!caught_stoi(value_s, &numCalls, 10))
		return -1;

	vector <ARGLIST> funcCalls;
	for (int i = 0; i < numCalls; ++i)
	{
		int argidx, numArgs = 0;
		getline(*file, value_s, ',');
		if (!caught_stoi(value_s, &numArgs, 10))
			return -1;
		ARGLIST callArgs;

		for (int i = 0; i < numArgs; ++i)
		{
			getline(*file, value_s, ',');
			if (!caught_stoi(value_s, &argidx, 10))
				return -1;
			getline(*file, value_s, ',');
			string decodedarg = base64_decode(value_s);
			callArgs.push_back(make_pair(argidx, decodedarg));
		}
		if (!callArgs.empty())
			funcCalls.push_back(callArgs);
	}
	if (!funcCalls.empty())
		funcargs = funcCalls;

	file->seekg(1, ios::cur);
	return 1;
}