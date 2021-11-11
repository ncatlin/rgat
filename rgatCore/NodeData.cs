using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using static rgat.CONSTANTS;

namespace rgat
{
    /// <summary>
    /// An object representing an executed instruction on the graph
    /// </summary>
    public class NodeData
    {
        /// <summary>
        /// Serialise this node to JSON for saving
        /// </summary>
        /// <returns>A JArray of ndoe data</returns>
        public void Serialise(Newtonsoft.Json.JsonWriter writer)
        {
            JArray nodearr = new JArray();

            nodearr.Add(BlockID);
            nodearr.Add(conditional);
            nodearr.Add(GlobalModuleID);
            nodearr.Add(Address);
            nodearr.Add(ExecutionCount);
            nodearr.Add(ParentIdx);

            //this needs to be rebuilt from the edge list
            //restore if loaded saves have different neighbour counts
            /*
            JArray incoming = new JArray();
            foreach (var nidx in IncomingNeighboursSet)
            {
                incoming.Add(nidx);
            }

            nodearr.Add(incoming);

            JArray outgoing = new JArray();
            foreach (var nidx in OutgoingNeighboursSet)
            {
                outgoing.Add(nidx);
            }

            nodearr.Add(outgoing);
            */

            nodearr.Add(IsExternal ? 1 : 0);

            if (!IsExternal)
            {
                nodearr.Add(ins!.MutationIndex);
            }
            else
            {
                JArray callRecIdxArr = new JArray();
                foreach (var idx in callRecordsIndexs)
                {
                    callRecIdxArr.Add(idx);
                }

                nodearr.Add(callRecIdxArr);
            }

            nodearr.Add(BlockIndex);
            nodearr.WriteTo(writer);
        }


        /// <summary>
        /// Restore a node from JSON
        /// </summary>
        /// <param name="index">Index of the node being loaded</param>
        /// <param name="nodeData">JArray of node data</param>
        /// <param name="processinfo">The process record this node was generated with</param>
        /// <returns></returns>
        public bool Deserialise(int index, JArray nodeData, ProcessRecord processinfo)
        {
            Index = (uint)index;

            int jsnArrIdx = 0;
            if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            BlockID = nodeData[jsnArrIdx].ToObject<uint>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            conditional = (ConditionalType)nodeData[jsnArrIdx].ToObject<int>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            GlobalModuleID = nodeData[jsnArrIdx].ToObject<int>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            Address = nodeData[jsnArrIdx].ToObject<ulong>();
            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            ExecutionCount = nodeData[jsnArrIdx].ToObject<ulong>();
            jsnArrIdx++;

            //execution comes from these nodes to this node
            if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            ParentIdx = nodeData[jsnArrIdx].ToObject<uint>();
            jsnArrIdx++;

            /*
            //execution comes from these nodes to this node
            if (nodeData[jsnArrIdx].Type != JTokenType.Array)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            JArray incomingEdges = (JArray)nodeData[jsnArrIdx];

            foreach (JToken incomingIdx in incomingEdges)
            {
                if (incomingIdx.Type != JTokenType.Integer)
                {
                    return ErrorAtIndex(jsnArrIdx);
                }

                IncomingNeighboursSet.Add(incomingIdx.ToObject<uint>());
            }
            jsnArrIdx++;

            //execution goes from this node to these nodes
            if (nodeData[jsnArrIdx].Type != JTokenType.Array)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            JArray outgoingEdges = (JArray)nodeData[jsnArrIdx];

            foreach (JToken outgoingIdx in outgoingEdges)
            {
                if (outgoingIdx.Type != JTokenType.Integer)
                {
                    return ErrorAtIndex(jsnArrIdx);
                }
                OutgoingNeighboursSet.Add(outgoingIdx.ToObject<uint>());
            }
            jsnArrIdx++;
            
            */
            if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            IsExternal = nodeData[jsnArrIdx].ToObject<int>() == 0 ? false: true;
            jsnArrIdx++;

            if (IsExternal)
            {
                HasSymbol = true;
                //load arguments to the API call
                if (nodeData[jsnArrIdx].Type != JTokenType.Array)
                {
                    return ErrorAtIndex(jsnArrIdx);
                }

                JArray functionCalls = (JArray)nodeData[jsnArrIdx];

                foreach (JToken callIdx in functionCalls)
                {
                    if (callIdx.Type != JTokenType.Integer)
                    {
                        return ErrorAtIndex(jsnArrIdx);
                    }

                    callRecordsIndexs.Add(callIdx.ToObject<ulong>());
                }
            }
            else
            {
                HasSymbol = processinfo.SymbolExists(GlobalModuleID, Address);
                //load disassembly data of the instruction
                if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
                {
                    return ErrorAtIndex(jsnArrIdx);
                }

                int mutationIndex = nodeData[jsnArrIdx].ToObject<int>();

                if (!processinfo.disassembly.TryGetValue(Address, out List<InstructionData>? addrInstructions))
                {
                    Logging.WriteConsole("[rgat] Error. Failed to find address " + Address + " in disassembly for node " + jsnArrIdx);
                    return ErrorAtIndex(jsnArrIdx);
                }
                ins = addrInstructions[mutationIndex];
            }

            jsnArrIdx++;

            if (nodeData[jsnArrIdx].Type != JTokenType.Integer)
            {
                return ErrorAtIndex(jsnArrIdx);
            }

            BlockIndex = nodeData[jsnArrIdx].ToObject<int>();
            return true;
        }


        private static bool ErrorAtIndex(int index)
        {
            Logging.WriteConsole("Error deserialising node at index " + index);
            return false;
        }


        /// <summary>
        /// Mark this node as having caused an exception
        /// </summary>
        public void SetException()
        {
            CausedException = true;
            _nodeType = EdgeNodeType.eEdgeException;
        }

        /// <summary>
        /// The control flow type of this node
        /// </summary>
        /// <returns>An eEdgeNodeType value</returns>
        public EdgeNodeType VertType()
        {
            if (_nodeType != EdgeNodeType.eENLAST)
            {
                return _nodeType;
            }

            if (IsExternal)
            {
                return EdgeNodeType.eNodeExternal;
            }

            switch (ins!.itype)
            {
                case NodeType.eInsUndefined:
                    {

                        if (ins.conditional)
                        {
                            _nodeType = EdgeNodeType.eNodeJump;
                        }
                        else
                        {
                            _nodeType = EdgeNodeType.eNodeNonFlow;
                        }

                        break;
                    }
                case NodeType.eInsJump:
                    _nodeType = EdgeNodeType.eNodeJump;
                    break;
                case NodeType.eInsReturn:
                    _nodeType = EdgeNodeType.eNodeReturn;
                    break;
                case NodeType.eInsCall:
                    _nodeType = EdgeNodeType.eNodeCall;
                    break;
                default:
                    Logging.WriteConsole("[rgat]Error: render_node unknown itype " + ins.itype);
                    System.Diagnostics.Debug.Assert(false);
                    break;
            }
            return _nodeType;
        }

        private bool LabelVisible(PlottedGraph plot)
        {
            if (!plot.Opt_TextEnabled)
            {
                return false;
            }

            //always display node label on the active graph, unless text display is disabled entirely
            if (plot.IsAnimated && plot.InternalProtoGraph.ProtoLastVertID == Index)
            {
                return true;
            }

            if (plot.Opt_TextEnabledSym && HasSymbol)
            {
                return true;
            }

            if (plot.Opt_TextEnabledIns && ins != null && ins.InsText?.Length > 0)
            {
                return true;
            }

            return false;

        }


        /// <summary>
        /// This creates the label drawn on the graph
        /// For symbol labels drawn in logs/analysis tabs see CreateColourisedSymbolCall
        /// </summary>
        /// <param name="plot">Graph the label belongs to</param>
        /// <param name="specificCallIndex">Index of the APi call in the graph</param>
        public void CreateLabel(PlottedGraph plot, int specificCallIndex = -1)
        {
            ProtoGraph graph = plot.InternalProtoGraph;

            if (!LabelVisible(plot))
            {
                Label = null;
                return;
            }

            Dirty = false;
            Label = "";

            if (plot.Opt_ShowNodeIndexes)
            {
                Label += $"{this.Index}<{this.BlockID}>:";
            }

            if (plot.Opt_ShowNodeAddresses)
            {
                Label += $"0x{this.Address:X}:";
            }

            if (!IsExternal && ins!.InsText?.Length > 0)
            {
                Label += $" {ins.InsText}";
            }

            if (HasSymbol)
            {
                if (IsExternal)
                {
                    Label += $" {CreateSymbolLabel(plot, specificCallIndex)}";
                }
                else
                {
                    Label += $" <{CreateSymbolLabel(plot, specificCallIndex)}>";
                }
            }

            if (!IsExternal)
            {
                if (plot != null && plot.RenderingMode == eRenderingMode.eHeatmap)
                {
                    Label += $" [x{ExecutionCount}] ";
                    if (OutgoingNeighboursSet.Count > 1)
                    {
                        Label += "<";
                        int nCount = Math.Min(OutgoingNeighboursSet.Count, 3);
                        for (var i = 0; i < nCount; i++)
                        {
                            uint nidx = OutgoingNeighboursSet[i];
                              EdgeData? targEdge = graph.GetEdge(Index, nidx);
                            if (targEdge != null)
                            {
                                Label += $" {nidx}:{targEdge.ExecutionCount}{(i < (nCount-1)? "," : "")} ";
                            }
                        }
                        if (OutgoingNeighboursSet.Count > nCount)
                            Label += "...";
                        Label += ">";
                    }
                }
            }
        }

        /// <summary>
        /// Create a label for an API call with symbol + arguments
        /// </summary>
        /// <param name="plot">The graph for the thread the call was made in</param>
        /// <param name="specificCallIndex">The index of the API call in the graph</param>
        /// <returns>The generated label</returns>
        public string CreateSymbolLabel(PlottedGraph plot, int specificCallIndex = -1)
        {
            string? symbolText = "";
            bool found = false;
            ProtoGraph graph = plot.InternalProtoGraph;
            if (graph.ProcessData.GetSymbol(GlobalModuleID, Address, out symbolText))
            {
                found = true;
            }
            else
            {
                //search back from the instruction to try and find symbol of a function it may (or may not) be part of
                ulong searchLimit = Math.Min(GlobalConfig.Settings.Tracing.SymbolSearchDistance, Address);
                for (ulong symOffset = 0; symOffset < searchLimit; symOffset++)
                {
                    if (graph.ProcessData.GetSymbol(GlobalModuleID, Address - symOffset, out symbolText))
                    {
                        symbolText += $"+0x{symOffset}";
                        found = true;
                        break;
                    }
                }
            }

            if (!found)
            {
                return $"[No Symbol]0x{Address:x}";
            }


            if (plot.Opt_ShowSymbolModules)
            {
                string module = graph.ProcessData.GetModulePath(GlobalModuleID);
                if(plot.Opt_ShowSymbolModulePaths)
                {
                    symbolText = $"{module}:{symbolText}";
                }
                else
                {
                    try
                    {
                        string moduleName = System.IO.Path.GetFileName(module);
                        symbolText = $"{moduleName}:{symbolText}";
                    }
                    catch { }
                }
            }

            if (callRecordsIndexs.Count == 0)
            {
                if (ExecutionCount == 1)
                {
                    return $"{symbolText}()";
                }
                else
                {
                    return $"{symbolText}() [x{ExecutionCount}]";
                }
            }

            APICALLDATA lastCall;
            if (specificCallIndex == -1)
            {
                lastCall = graph.SymbolCallRecords[(int)callRecordsIndexs[^1]];
            }
            else
            {
                Debug.Assert(callRecordsIndexs.Count > specificCallIndex);
                int lastCallIndex = (int)callRecordsIndexs[specificCallIndex];
                lastCall = graph.SymbolCallRecords[lastCallIndex];
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
                {
                    break;
                }
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
            string? symbolText = "";
            bool found = false;
            if (!graph.ProcessData.GetSymbol(GlobalModuleID, Address, out symbolText))
            {
                //search back from the instruction to try and find symbol of a function it may (or may not) be part of
                ulong searchLimit = Math.Min(GlobalConfig.Settings.Tracing.SymbolSearchDistance, Address);
                for (ulong symOffset = 0; symOffset < searchLimit; symOffset++)
                {
                    if (graph.ProcessData.GetSymbol(GlobalModuleID, Address - symOffset, out symbolText))
                    {
                        symbolText += $"+0x{symOffset}";
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    return result;
                }
            }

            if (callRecordsIndexs.Count == 0 || specificCallIndex >= callRecordsIndexs.Count)
            {
                result.Add(new Tuple<string, WritableRgbaFloat>($"{symbolText}()", colour1));
                return result;
            }

            APICALLDATA lastCall;

            Debug.Assert(callRecordsIndexs.Count > specificCallIndex);
            int recordIndex = (int)callRecordsIndexs[specificCallIndex];
            lastCall = graph.SymbolCallRecords[recordIndex]; //thread unsafe todo, when sandbox open while being filled

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
                else
                {
                    break;
                }
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

        /// <summary>
        /// Is this node highlighted
        /// </summary>
        public bool Highlighted { get; private set; } = false;
        /// <summary>
        /// Mark this nodes highlight state
        /// </summary>
        /// <param name="state"></param>
        public void SetHighlighted(bool state) => Highlighted = state;

        /// <summary>
        /// The index of this node in the node array and various node collections
        /// </summary>
        public uint Index = 0;

        /// <summary>
        /// The node is a conditional jump instruction
        /// </summary>
        public bool IsConditional => conditional != ConditionalType.NOTCONDITIONAL;

        /// <summary>
        /// The conditional jump status (how it executed)
        /// </summary>
        public ConditionalType conditional = ConditionalType.NOTCONDITIONAL;

        /// <summary>
        /// The disassembled instruction
        /// </summary>
        public InstructionData? ins;

        /// <summary>
        /// The node is an entry to uninstrumented code
        /// </summary>
        public bool IsExternal { get; set; } = false;

        /// <summary>
        /// The node caused at least one exception
        /// </summary>
        public bool CausedException { get; private set; } = false;

        /// <summary>
        /// The node calls an API thunk
        /// </summary>
        public bool ThunkCaller = false;

        /// <summary>
        /// The module the node belongs to
        /// </summary>
        public int GlobalModuleID;

        /// <summary>
        /// The block the node belongs to
        /// </summary>
        public uint BlockID;

        /// <summary>
        /// The index of the node in its latest basic block
        /// </summary>
        public int BlockIndex; //maybe shouldn't have this here - time/space tradeoff. Alternative is block.findindexof on every metadata generation

        /// <summary>
        /// An index used to lookup the caller/arguments of each instance of this being called
        /// </summary>
        public List<ulong> callRecordsIndexs = new List<ulong>();

        /// <summary>
        /// The latest call index
        /// </summary>
        public int currentCallIndex = 1; //need to review how this works and if it achieves anything

        /// <summary>
        /// The node needs its label regenerating
        /// </summary>
        public bool Dirty;


        /// <summary>
        /// Number of external functions called
        /// Used by the cylinder layout
        /// </summary>
        public uint Childexterns = 0;

        /// <summary>
        /// Memory address of the node instruction
        /// </summary>
        public ulong Address = 0;

        /// <summary>
        /// Which instruction first lead to this node
        /// </summary>
        public uint ParentIdx = 0;

        /// <summary>
        /// How many times the instruction has been recorded executing
        /// </summary>
        public ulong ExecutionCount { get; private set; } = 0;

        /// <summary>
        /// Set the execution count
        /// </summary>
        /// <param name="value">How many times the instruction has been recorded executing</param>
        public void SetExecutionCount(ulong value)
        {
            ExecutionCount = value;
            Dirty = true;
        }

        /// <summary>
        /// Add a number to the execution count of this node
        /// </summary>
        /// <param name="value">Number of new executions recorded</param>
        public void IncreaseExecutionCount(ulong value)
        {
            SetExecutionCount(ExecutionCount + value);
        }

        /// <summary>
        /// How often the instruction is executed relative to other instuctions (0 [least] to 9 [most])
        /// </summary>
        public float HeatRank = 0;

        /// <summary>
        /// Sources for this node
        /// </summary>
        public List<uint> IncomingNeighboursSet = new List<uint>();

        /// <summary>
        /// Targets for this node
        /// </summary>
        public List<uint> OutgoingNeighboursSet = new List<uint>();


        /// <summary>
        /// The node has a symbol associated with it
        /// </summary>
        public bool HasSymbol;
        private EdgeNodeType _nodeType = EdgeNodeType.eENLAST;
        private string? _label;
        /// <summary>
        /// Get the node label text
        /// </summary>
        public string? Label
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
    }
}
