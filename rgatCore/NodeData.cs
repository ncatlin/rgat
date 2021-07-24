using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace rgatCore
{
    public class NodeData
    {

        public NodeData() { }

        public JArray Serialise()
        {
            JArray nodearr = new JArray();

            nodearr.Add(index);
            nodearr.Add(BlockID);
            nodearr.Add(conditional);
            nodearr.Add(GlobalModuleID);
            nodearr.Add(address);
            nodearr.Add(executionCount);
            nodearr.Add(parentIdx);

            JArray incoming = new JArray();
            foreach (var nidx in IncomingNeighboursSet) incoming.Add(nidx);
            nodearr.Add(incoming);

            JArray outgoing = new JArray();
            foreach (var nidx in OutgoingNeighboursSet) outgoing.Add(nidx);
            nodearr.Add(outgoing);

            nodearr.Add(IsExternal);

            if (!IsExternal)
            {
                nodearr.Add(ins.mutationIndex);
            }
            else
            {
                JArray callRecIdxArr = new JArray();
                foreach (var idx in callRecordsIndexs) callRecIdxArr.Add(idx);
                nodearr.Add(callRecIdxArr);
            }

            nodearr.Add(unreliableCount);
            return nodearr;
        }

        //takes a file with a pointer next to a node entry, loads it into the node

        public bool Deserialise(JArray nodeData, Dictionary<ulong, List<InstructionData>> disassembly)
        {
            int jsnArrIdx = 0;
            if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
            index = nodeData[jsnArrIdx].ToObject<uint>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
            BlockID = nodeData[jsnArrIdx].ToObject<uint>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
            conditional = (eConditionalType)nodeData[jsnArrIdx].ToObject<int>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
            GlobalModuleID = nodeData[jsnArrIdx].ToObject<int>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
            address = nodeData[jsnArrIdx].ToObject<ulong>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
            executionCount = nodeData[jsnArrIdx].ToObject<ulong>();
            jsnArrIdx++;

            //execution comes from these nodes to this node
            if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
            parentIdx = nodeData[jsnArrIdx].ToObject<uint>();
            jsnArrIdx++;

            //execution comes from these nodes to this node
            if (nodeData[jsnArrIdx].Type != JTokenType.Array) return ErrorAtIndex(jsnArrIdx);
            JArray incomingEdges = (JArray)nodeData[jsnArrIdx];

            foreach (JToken incomingIdx in incomingEdges)
            {
                if (incomingIdx.Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
                IncomingNeighboursSet.Add(incomingIdx.ToObject<uint>());
            }
            jsnArrIdx++;

            //execution goes from this node to these nodes
            if (nodeData[jsnArrIdx].Type != JTokenType.Array) return ErrorAtIndex(jsnArrIdx);
            JArray outgoingEdges = (JArray)nodeData[jsnArrIdx];

            foreach (JToken outgoingIdx in outgoingEdges)
            {
                if (outgoingIdx.Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
                OutgoingNeighboursSet.Add(outgoingIdx.ToObject<uint>());
            }
            jsnArrIdx++;


            if (nodeData[jsnArrIdx].Type != JTokenType.Boolean) return ErrorAtIndex(jsnArrIdx);
            IsExternal = nodeData[jsnArrIdx].ToObject<bool>();
            jsnArrIdx++;

            if (!IsExternal)
            {
                if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
                int mutationIndex = nodeData[jsnArrIdx].ToObject<int>();

                if (!disassembly.TryGetValue(address, out List<InstructionData> addrInstructions))
                {
                    Console.WriteLine("[rgat] Error. Failed to find address " + address + " in disassembly for node " + jsnArrIdx);
                    return ErrorAtIndex(jsnArrIdx);
                }
                ins = addrInstructions[mutationIndex];
            }
            else
            {
                if (nodeData[jsnArrIdx].Type != JTokenType.Array) return ErrorAtIndex(jsnArrIdx);
                JArray functionCalls = (JArray)nodeData[jsnArrIdx];

                foreach (JToken callIdx in functionCalls)
                {
                    if (callIdx.Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
                    callRecordsIndexs.Add(callIdx.ToObject<ulong>());
                }
            }
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Boolean) return ErrorAtIndex(jsnArrIdx);
            unreliableCount = nodeData[jsnArrIdx].ToObject<bool>();

            return true;
        }

        static bool ErrorAtIndex(int index)
        {
            Console.WriteLine("Error deserialising node at index " + index);
            return false;
        }


        public eEdgeNodeType VertType()
        {
            if (_nodeType != eEdgeNodeType.eENLAST) return _nodeType;
            if (IsExternal) return eEdgeNodeType.eNodeExternal;
            switch (ins.itype)
            {
                case eNodeType.eInsUndefined:
                    {

                        if (ins.conditional) _nodeType = eEdgeNodeType.eNodeJump;
                        else _nodeType = eEdgeNodeType.eNodeNonFlow;
                        break;
                    }
                case eNodeType.eInsJump:
                    _nodeType = eEdgeNodeType.eNodeJump;
                    break;
                case eNodeType.eInsReturn:
                    _nodeType = eEdgeNodeType.eNodeReturn;
                    break;
                case eNodeType.eInsCall:
                    _nodeType = eEdgeNodeType.eNodeCall;
                    break;
                default:
                    Console.WriteLine("[rgat]Error: render_node unknown itype " + ins.itype);
                    System.Diagnostics.Debug.Assert(false);
                    break;
            }
            return _nodeType;
        }


        public void GenerateSymbolLabel(ProtoGraph graph, int specificCallIndex = -1)
        {
            string symbolText = "";
            bool found = false;
            if (graph.ProcessData.GetSymbol(GlobalModuleID, address, out symbolText))
            {
                found = true;
            }
            else
            {
                //search back from the instruction to try and find symbol of a function it may (or may not) be part of
                ulong searchLimit = Math.Min(GlobalConfig.SymbolSearchDistance, address);
                for (ulong symOffset = 0; symOffset < searchLimit; symOffset++)
                {
                    if (graph.ProcessData.GetSymbol(GlobalModuleID, address - symOffset, out symbolText))
                    {
                        symbolText += $"+0x{symOffset}";
                        found = true;
                        break;
                    }
                }
            }

            if (!found)
            {
                Label = $"[No Symbol]0x{address:x}";
                return;
            }


            if (callRecordsIndexs.Count == 0)
            {
                Label = $"{symbolText}() [x{executionCount}]";
                return;
            }

            EXTERNCALLDATA lastCall;
            if (specificCallIndex == -1)
            {
                lastCall = graph.ExternCallRecords[(int)callRecordsIndexs[^1]];
            }
            else
            {
                Debug.Assert(callRecordsIndexs.Count > specificCallIndex);
                lastCall = graph.ExternCallRecords[(int)callRecordsIndexs[specificCallIndex]];
            }

            string argstring = "";
            for (var i = 0; i < lastCall.argList.Count; i++)
            {
                Tuple<int, string> arg = lastCall.argList[i];
                argstring += $"{arg.Item1}:{arg.Item2}";
                if (i < (lastCall.argList.Count - 1)) argstring += ", ";
            }

            if (callRecordsIndexs.Count == 1)
            {
                Label = $"{symbolText}({argstring})";
            }
            else
            {
                Label = $"{symbolText}({argstring}) +{callRecordsIndexs.Count - 1} saved";
            }
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


        public bool Highlighted { get; private set; } = false;
        public bool SetHighlighted(bool state) => Highlighted = state;
        public uint index = 0;

        public bool IsConditional() => conditional != eConditionalType.NOTCONDITIONAL;
        public eConditionalType conditional = eConditionalType.NOTCONDITIONAL;
        public InstructionData ins;
        public bool IsExternal { get; set; } = false;
        public bool ThunkCaller = false;

        bool unreliableCount = false; //external executions not directly tracked - estimated using heatmap solver
        public int GlobalModuleID;

        public uint BlockID;

        //an index used to lookup the caller/arguments of each instance of this being called
        public List<ulong> callRecordsIndexs = new List<ulong>();
        public ulong currentCallIndex = 1; //need to review how this works and if it achieves anything
        public bool newArgsRecorded;

        //number of external functions called
        public uint childexterns = 0;
        public ulong address = 0;
        public uint parentIdx = 0;

        public ulong executionCount { get; private set; } = 0;
        public void SetExecutionCount(ulong value)
        {
            if (index == 4 && value > 33)
            {
                Console.WriteLine($"Node 4 exec count set to {value}");
            }
            executionCount = value;
        }
        public void IncreaseExecutionCount(ulong value)
        {
            SetExecutionCount(executionCount + value);
        }

        public float heatRank = 0; //0-9 least to most busy


        public List<uint> IncomingNeighboursSet = new List<uint>();
        public List<uint> OutgoingNeighboursSet = new List<uint>();
        eEdgeNodeType _nodeType = eEdgeNodeType.eENLAST;
        string _label;
        public string Label
        {
            get
            {
                return _label;
            }
            set
            {
                _label = value;
            }
        }
        public bool placeholder = false;
    }
}
