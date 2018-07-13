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
Class describing each node
*/
#include "stdafx.h"
#include "node_data.h"
#include "b64.h"
#include "graphicsMaths.h"
#include "GUIConstants.h"
#include "traceMisc.h"
#include "proto_graph.h"
#include "binaryTarget.h"


bool node_data::serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer, PROTOGRAPH_CASTPTR graphPtr)
{
	writer.StartArray();

	writer.Uint64(index); //[0]
	writer.Uint(conditional);//[1]
	writer.Uint(globalModID);//[2]
	writer.Uint64(address);//[3]
	writer.Uint64(executionCount);//[4]

	writer.StartArray();//[5]
	set<NODEINDEX>::iterator adjacentIt = incomingNeighbours.begin();
	for (; adjacentIt != incomingNeighbours.end(); ++adjacentIt)
		writer.Uint64(*adjacentIt);
	writer.EndArray();

	writer.StartArray();//[6]
	adjacentIt = outgoingNeighbours.begin();
	for (; adjacentIt != outgoingNeighbours.end(); ++adjacentIt)
		writer.Uint64(*adjacentIt);
	writer.EndArray();

	writer.Bool(external);//[7]

	if (!external)
		writer.Uint(ins->mutationIndex); //[8]
	else
	{
		writer.StartArray(); //[8] function calls as indexes into call records
		vector<unsigned long>::iterator callIt = callRecordsIndexs.begin();
		for (; callIt != callRecordsIndexs.end(); callIt++)
		{
			writer.Uint64(*callIt);
		}
		writer.EndArray(); //end list of calls for this node
	}

	writer.Bool(unreliableCount);

	if (label.size() > 0)
	{
		writer.String(label.toStdString().c_str());
		writer.Bool(placeholder);
	}

	writer.EndArray(); //end node

	return true;
}

bool errorAtIndex(int index)
{
	cerr << "[rgat]Warning: Bad node at index "<< index << endl; 
	return false;
}

int node_data::deserialise(const rapidjson::Value& nodeData, map <MEM_ADDRESS, INSLIST> &disassembly)
{
	using namespace rapidjson;

	if (!nodeData[0].IsUint64()) return errorAtIndex(0);
	index = nodeData[0].GetUint64();
	if (!nodeData[1].IsUint()) return errorAtIndex(1);
	conditional = nodeData[1].GetUint();
	if (!nodeData[2].IsUint()) return errorAtIndex(2);
	globalModID = nodeData[2].GetUint();
	if (!nodeData[3].IsUint64()) return errorAtIndex(3);
	address = nodeData[3].GetUint64();
	if (!nodeData[4].IsUint64()) return errorAtIndex(4);
	executionCount = nodeData[4].GetUint64();

	//execution comes from these nodes to this node
	if (!nodeData[5].IsArray()) return errorAtIndex(5);
	const Value& incomingEdges = nodeData[5];
	Value::ConstValueIterator incomingIt = incomingEdges.Begin();
	for (; incomingIt != incomingEdges.End(); incomingIt++)
	{
		if (!incomingIt->IsUint64()) return errorAtIndex(5);
		incomingNeighbours.insert(incomingIt->GetUint64());
	}

	//execution goes from this node to these nodes
	const Value& outgoingEdges = nodeData[6];
	if (!nodeData[6].IsArray())
	{
		cout << "type is " << nodeData[6].GetType() << " should be " << rapidjson::Type::kArrayType << endl;
		return errorAtIndex(6);
	}
	Value::ConstValueIterator outgoingIt = outgoingEdges.Begin();
	for (; outgoingIt != outgoingEdges.End(); outgoingIt++)
	{
		if (!outgoingIt->IsUint64()) return errorAtIndex(6);
		outgoingNeighbours.insert(outgoingIt->GetUint64());
	}

	if (!nodeData[7].IsBool()) return errorAtIndex(7);
	external = nodeData[7].GetBool();

	if (!external)
	{
		if (!nodeData[8].IsInt())	return errorAtIndex(8);
		blockID = nodeData[8].GetInt(); //todo: one is blockID other is mutation index. No problems noticed but check this.

		map<MEM_ADDRESS, INSLIST>::iterator addressIt = disassembly.find(address);
		if ((addressIt == disassembly.end()) || (blockID >= addressIt->second.size()))
		{
			cerr << "[rgat] Error. Failed to find address " << address << " in disassembly for node " << index << endl;
			return errorAtIndex(8);
		}
		ins = addressIt->second.at(blockID);
	}
	else
	{
		if (!nodeData[8].IsArray())	return errorAtIndex(8);
		const Value& functionCalls = nodeData[8];
		Value::ConstValueIterator callsIt = functionCalls.Begin();
		for (; callsIt != functionCalls.End(); callsIt++)
		{
			if (!callsIt->IsUint64())	return errorAtIndex(8);
			callRecordsIndexs.push_back(callsIt->GetUint64());
		}
	}

	if (!nodeData[9].IsBool()) return errorAtIndex(9);
	unreliableCount = nodeData[9].GetBool();

	if (nodeData.Capacity() > 10)
	{
		label = nodeData[10].GetString();
		placeholder = nodeData[11].GetBool();
		if (ins && !placeholder)
			ins->hasSymbol = true;
	}

	return true;
}

void node_data::setLabelFromNearestSymbol(TRACERECORDPTR traceRecPtr)
{

	traceRecord *runRecord = (traceRecord *)traceRecPtr;
	PROCESS_DATA *piddata = runRecord->get_piddata();

	ADDRESS_OFFSET offset = address - runRecord->get_piddata()->modBounds.at(globalModID)->first;
	string sym;
	//i haven't added a good way of looking up the nearest symbol. this requirement should be rare, but if not it's a todo
	bool foundsym = false;
	int symOffset;
	for (symOffset = 0; symOffset < 4096; symOffset++)
	{
		if (piddata->get_sym(globalModID, offset - symOffset, sym))
		{
			foundsym = true;
			break;
		}
	}

	if (foundsym)
		label = "<" + QString::fromStdString(sym) + "+ 0x" + QString::number(symOffset, 16) + ">";
	else
		label = "[Unknown Symbol]";
}