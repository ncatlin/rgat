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

	writer.Bool(unreliableCount);

	return true;
}


int node_data::deserialise(const rapidjson::Value& nodeData, map <MEM_ADDRESS, INSLIST> *disassembly)
{
	using namespace rapidjson;

	index = nodeData[0].GetUint();
	conditional = nodeData[1].GetUint();
	nodeMod = nodeData[2].GetUint();
	address = nodeData[3].GetUint64();
	executionCount = nodeData[4].GetUint64();

	//execution comes from these nodes to this node
	const Value& incomingEdges = nodeData[5];
	Value::ConstValueIterator incomingIt = incomingEdges.Begin();
	for (; incomingIt != incomingEdges.End(); incomingIt++)
		incomingNeighbours.insert(incomingIt->GetUint());

	//execution goes from this node to these nodes
	const Value& outgoingEdges = nodeData[6];
	Value::ConstValueIterator outgoingIt = outgoingEdges.Begin();
	for (; outgoingIt != outgoingEdges.End(); outgoingIt++)
		outgoingNeighbours.insert(outgoingIt->GetUint());

	external = nodeData[7].GetBool();

	if (!external)
	{
		blockID = nodeData[8].GetInt(); //todo: one is blockID other is mutation index. No problems noticed but check this.
		map<MEM_ADDRESS, INSLIST>::iterator addressIt = disassembly->find(address);
		if ((addressIt == disassembly->end()) || (blockID >= addressIt->second.size()))
		{
			cerr << "[rgat] Error. Failed to find address " << address << " in disassembly for node " << index << endl;
			return false;
		}
		ins = addressIt->second.at(blockID);
	}
	else
	{
		const Value& functionCalls = nodeData[8];
		Value::ConstValueIterator funcCallsIt = functionCalls.Begin();
		for (; funcCallsIt != functionCalls.End(); funcCallsIt++)
		{
			ARGLIST callArgs;
			const Value& callArgumentsArray = *funcCallsIt;
			Value::ConstValueIterator argsIt = callArgumentsArray.Begin();
			for (; argsIt != callArgumentsArray.End(); argsIt++)
			{
				const Value& callArgumentsEntry = *argsIt;

				int argIndex = callArgumentsEntry[0].GetUint();
				string b64Arg = callArgumentsEntry[1].GetString();
				string plainArgString = base64_decode(b64Arg);

				callArgs.push_back(make_pair(argIndex, plainArgString));
			}
			funcargs.push_back(callArgs);
		}
	}

	unreliableCount = nodeData[9].GetBool();

	return true;
}