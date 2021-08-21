using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using static rgat.RGAT_CONSTANTS;

namespace rgat
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

        public bool Deserialise(JArray nodeData, ProcessRecord processinfo)
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

            if (IsExternal)
            {
                HasSymbol = true;
                //load arguments to the API call
                if (nodeData[jsnArrIdx].Type != JTokenType.Array) return ErrorAtIndex(jsnArrIdx);
                JArray functionCalls = (JArray)nodeData[jsnArrIdx];

                foreach (JToken callIdx in functionCalls)
                {
                    if (callIdx.Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
                    callRecordsIndexs.Add(callIdx.ToObject<ulong>());
                }
            }
            else
            {
                HasSymbol = processinfo.SymbolExists(GlobalModuleID, address);
                //load disassembly data of the instruction
                if (nodeData[jsnArrIdx].Type != JTokenType.Integer) return ErrorAtIndex(jsnArrIdx);
                int mutationIndex = nodeData[jsnArrIdx].ToObject<int>();

                if (!processinfo.disassembly.TryGetValue(address, out List<InstructionData> addrInstructions))
                {
                    Console.WriteLine("[rgat] Error. Failed to find address " + address + " in disassembly for node " + jsnArrIdx);
                    return ErrorAtIndex(jsnArrIdx);
                }
                ins = addrInstructions[mutationIndex];
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


        bool LabelVisible(PlottedGraph plot)
        {
            if (!plot.Opt_TextEnabled) return false;

            //always display node label on the active graph, unless text display is disabled entirely
            if (plot.IsAnimated && plot.InternalProtoGraph.ProtoLastVertID == index) return true;

            if (plot.Opt_TextEnabledSym && HasSymbol) return true;
            if (plot.Opt_TextEnabledIns && ins != null && ins.ins_text.Length > 0) return true;
            return false;

        }

        /// <summary>
        /// This creates the label drawn on the graph
        /// For symbol labels drawn in logs/analysis tabs see CreateColourisedSymbolCall
        /// </summary>
        /// <param name="plot"></param>
        /// <param name="specificCallIndex"></param>
        public void CreateLabel(PlottedGraph plot, int specificCallIndex = -1)
        {
            ProtoGraph graph = plot.InternalProtoGraph;

            if (!LabelVisible(plot))
            {
                Label = null;
                return;
            }

            Label = "";

            if (plot.Opt_ShowNodeIndexes) Label += $"{this.index}:";
            if (plot.Opt_ShowNodeAddresses) Label += $"0x{this.address:X}:";

            if (!IsExternal && ins.ins_text.Length > 0)
            {
                Label += $" {ins.ins_text}";
            }

            if (HasSymbol)
            {
                if (IsExternal)
                    Label += $" {CreateSymbolLabel(graph, specificCallIndex)}";
                else
                    Label += $" <{CreateSymbolLabel(graph, specificCallIndex)}>";

                newArgsRecorded = false;
            }

            if (!IsExternal)
            {
                if (plot != null && plot.RenderingMode == eRenderingMode.eHeatmap)
                {
                    Label += $" [x{executionCount}] ";
                    if (OutgoingNeighboursSet.Count > 1)
                    {
                        Label += "<";
                        foreach (int nidx in OutgoingNeighboursSet)
                        {
                            EdgeData targEdge = graph.GetEdge(index, (uint)nidx);
                            if (targEdge != null)
                                Label += $" {nidx}:{targEdge.executionCount}, ";
                        }
                        Label += ">";
                    }
                }
            }
        }

        public string CreateSymbolLabel(ProtoGraph graph, int specificCallIndex = -1)
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
                return $"[No Symbol]0x{address:x}";
            }


            if (callRecordsIndexs.Count == 0)
            {
                if (executionCount == 1) return $"{symbolText}()";
                else
                    return $"{symbolText}() [x{executionCount}]";
            }

            APICALLDATA lastCall;
            if (specificCallIndex == -1)
            {
                lastCall = graph.SymbolCallRecords[(int)callRecordsIndexs[^1]];
            }
            else
            {
                Debug.Assert(callRecordsIndexs.Count > specificCallIndex);
                lastCall = graph.SymbolCallRecords[(int)callRecordsIndexs[specificCallIndex]];
            }

            string argstring = "";
            for (var i = 0; i < lastCall.argList.Count; i++)
            {
                Tuple<int, string> arg = lastCall.argList[i];

                argstring += $"{arg.Item1}:{arg.Item2}";

                //if not last arg + next is not return val
                bool moreArgs = (i < (lastCall.argList.Count - 1) && (lastCall.argList[i + 1].Item1 != -1));
                if (moreArgs)
                {
                    argstring += ", "; 
                }
                else
                    break;
            }

            string result = $"{symbolText}({argstring})";

            //add return value, if it's there
            if (lastCall.argList.Count > 0 && lastCall.argList[^1].Item1 == -1)
            {
                result += " => " + lastCall.argList[^1].Item2;
            }
            
            if (callRecordsIndexs.Count > 1)
            {
                result += $" +{callRecordsIndexs.Count - 1} saved";
            }
            return result;
        }


        /// <summary>
        /// Produces a list of api string/colour tuples for displaying in trace analysis lists
        /// </summary>
        /// <param name="graph">The graph of the thread that made the call</param>
        /// <param name="specificCallIndex">The index of the call</param>
        /// <param name="colour1">The colour of the API text</param>
        /// <param name="colour2">The colour of the argument texts</param>
        /// <returns></returns>
        public List<Tuple<string, WritableRgbaFloat>> CreateColourisedSymbolCall(ProtoGraph graph, int specificCallIndex, WritableRgbaFloat colour1, WritableRgbaFloat colour2)
        {
            List<Tuple<string, WritableRgbaFloat>> result = new List<Tuple<string, WritableRgbaFloat>>();
            string symbolText = "";
            bool found = false;
            if (!graph.ProcessData.GetSymbol(GlobalModuleID, address, out symbolText))
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
                if (!found) return result;
            }

            if (callRecordsIndexs.Count == 0 || specificCallIndex >= callRecordsIndexs.Count)
            {
                result.Add(new Tuple<string, WritableRgbaFloat>($"{symbolText}()", colour1));
                return result;
            }

            APICALLDATA lastCall;

            Debug.Assert(callRecordsIndexs.Count > specificCallIndex);
            lastCall = graph.SymbolCallRecords[(int)callRecordsIndexs[specificCallIndex]]; //thread unsafe todo, when sandbox open while being filled

            result.Add(new Tuple<string, WritableRgbaFloat>($"{symbolText}(", colour1));

            for (var i = 0; i < lastCall.argList.Count; i++)
            {
                Tuple<int, string> arg = lastCall.argList[i];
                result.Add(new Tuple<string, WritableRgbaFloat>($"{arg.Item1}:", colour1));
                result.Add(new Tuple<string, WritableRgbaFloat>($"{arg.Item2}", colour2));

                bool moreArgs = (i < (lastCall.argList.Count - 1) && (lastCall.argList[i + 1].Item1 != -1));
                if (moreArgs)
                {
                    result.Add(new Tuple<string, WritableRgbaFloat>($", ", colour1));
                }
                else break;
            }

            if (lastCall.argList.Count > 0 && lastCall.argList[^1].Item1 == -1)
            {
                result.Add(new Tuple<string, WritableRgbaFloat>(") =", colour1));
                result.Add(new Tuple<string, WritableRgbaFloat>(lastCall.argList[^1].Item2, colour2));
            }
            else
            {
                result.Add(new Tuple<string, WritableRgbaFloat>(")", colour1));
            }

            return result;
        }

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
        public int currentCallIndex = 1; //need to review how this works and if it achieves anything
        public bool newArgsRecorded;

        //number of external functions called
        public uint childexterns = 0;
        public ulong address = 0;
        public uint parentIdx = 0;

        public ulong executionCount { get; private set; } = 0;
        public void SetExecutionCount(ulong value)
        {
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
        public bool HasSymbol;

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
