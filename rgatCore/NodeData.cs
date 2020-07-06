﻿using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;

namespace rgatCore
{
    class NodeData
    {

        public NodeData() { }

        //bool serialise(rapidjson::Writer<rapidjson::FileWriteStream>& writer, PROTOGRAPH_CASTPTR graphPtr);
        //takes a file with a pointer next to a node entry, loads it into the node

        public bool Deserialise(JArray nodeData, Dictionary<ulong, List<InstructionData>> disassembly)
        {

            if (nodeData[0].Type != JTokenType.Integer) return ErrorAtIndex(0);
            index = nodeData[0].ToObject<uint>();

            if (nodeData[1].Type != JTokenType.Integer) return ErrorAtIndex(1);
            conditional = (eConditionalType) nodeData[1].ToObject<int>();

            if (nodeData[2].Type != JTokenType.Integer) return ErrorAtIndex(2);
            GlobalModuleID = nodeData[2].ToObject<int>();

            if (nodeData[3].Type != JTokenType.Integer) return ErrorAtIndex(3);
            address = nodeData[3].ToObject<ulong>();

            if (nodeData[4].Type != JTokenType.Integer) return ErrorAtIndex(4);
            executionCount = nodeData[4].ToObject<ulong>();

            //execution comes from these nodes to this node
            if (nodeData[5].Type != JTokenType.Array) return ErrorAtIndex(5);
            JArray incomingEdges = (JArray)nodeData[5];

            foreach (JToken incomingIdx in incomingEdges)
            {
                if (incomingIdx.Type != JTokenType.Integer) return ErrorAtIndex(5);
                IncomingNeighboursSet.Add(incomingIdx.ToObject<uint>());
            }

            //execution goes from this node to these nodes
            if (nodeData[6].Type != JTokenType.Array) return ErrorAtIndex(6);
            JArray outgoingEdges = (JArray)nodeData[6];

            foreach (JToken outgoingIdx in outgoingEdges)
            {
                if (outgoingIdx.Type != JTokenType.Integer) return ErrorAtIndex(6);
                OutgoingNeighboursSet.Add(outgoingIdx.ToObject<uint>());
            }


            if (nodeData[7].Type != JTokenType.Boolean) return ErrorAtIndex(7);
            IsExternal = nodeData[7].ToObject<bool>();

            if (!IsExternal)
            {
                if (nodeData[8].Type != JTokenType.Integer) return ErrorAtIndex(8);
                int mutationIndex = nodeData[8].ToObject<int>();

                if (!disassembly.TryGetValue(address, out List<InstructionData> addrInstructions))
                {
                    Console.WriteLine("[rgat] Error. Failed to find address " + address + " in disassembly for node " + index);
                    return ErrorAtIndex(8);
                }
                ins = addrInstructions[mutationIndex];
            }
            else
            {
                if (nodeData[8].Type != JTokenType.Array) return ErrorAtIndex(8);
                JArray functionCalls = (JArray)nodeData[8];

                foreach (JToken callIdx in functionCalls)
                {
                    if (callIdx.Type != JTokenType.Integer) return ErrorAtIndex(8);
                    callRecordsIndexs.Add(callIdx.ToObject<ulong>());
                }
            }

            if (nodeData[9].Type != JTokenType.Boolean) return ErrorAtIndex(7);
            unreliableCount = nodeData[9].ToObject<bool>();

            if (nodeData.Count > 10)
            {
                label = nodeData[10].ToString();
                placeholder = nodeData[11].ToObject<bool>();
                if (!placeholder && !IsExternal)
                    ins.hasSymbol = true;
            }

            return true;
        }

        private bool ErrorAtIndex(int index)
        {
            Console.WriteLine("Error deserialising node at index " + index);
            return false;
        }
        /*
		void setLabelFromNearestSymbol(TRACERECORDPTR traceRecPtr)
        {
			traceRecord* runRecord = (traceRecord*)traceRecPtr;
			PROCESS_DATA* piddata = runRecord.get_piddata();

			ADDRESS_OFFSET offset = address - runRecord.get_piddata().modBounds.at(globalModID).first;
			string sym;
			//i haven't added a good way of looking up the nearest symbol. this requirement should be rare, but if not it's a todo
			bool foundsym = false;
			int symOffset;
			for (symOffset = 0; symOffset < 4096; symOffset++)
			{
				if (piddata.get_sym(globalModID, offset - symOffset, sym))
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
		*/



        public uint index = 0;

        public bool IsConditional() => conditional != eConditionalType.NOTCONDITIONAL;
        public eConditionalType conditional = eConditionalType.NOTCONDITIONAL;
        public InstructionData ins;
        public bool IsExternal { get; private set; } = false;
        bool unreliableCount = false; //external executions not directly tracked - estimated using heatmap solver
        public int GlobalModuleID;

        //ulong/int blockID;

        //an index used to lookup the caller/arguments of each instance of this being called
        List<ulong> callRecordsIndexs;
        ulong currentCallIndex = 1; //need to review how this works and if it achieves anything

        //number of external functions called
        public uint childexterns = 0;
        public ulong address = 0;
        uint parentIdx = 0;

        ulong executionCount = 0;
        ulong chain_remaining_in = 0;
        ulong chain_remaining_out = 0;

        ulong heat_run_marker;

        public List<uint> IncomingNeighboursSet = new List<uint>();
        public List<uint> OutgoingNeighboursSet = new List<uint>();

        public string label;
        public bool placeholder = false;
    }
}