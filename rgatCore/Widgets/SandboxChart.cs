using GraphShape.Algorithms.Layout;
using ImGuiNET;
using QuikGraph;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace rgat.Widgets
{
    internal class SandboxChart
    {
        public class ItemNode
        {
            public ItemNode(string caption, Logging.eTimelineEvent eventType, object item)
            {
                label = caption;
                TLtype = eventType;
                reference = item;
            }
            public string label;
            public Logging.eTimelineEvent TLtype;
            public object reference;
        }

        //todo lock access to this
        private readonly QuikGraph.BidirectionalGraph<ItemNode, Edge<ItemNode>> sbgraph = new BidirectionalGraph<ItemNode, Edge<ItemNode>>();
        private readonly GraphShape.Algorithms.Layout.KKLayoutAlgorithm<ItemNode, Edge<ItemNode>, QuikGraph.BidirectionalGraph<ItemNode, Edge<ItemNode>>> layout;
        private Vector2 chartSize;
        private readonly float padding = 15;
        private double _scaleX = 1;
        private readonly float nodeSize = 8;
        private readonly ImFontPtr _fontptr;

        public SandboxChart(ImFontPtr font)
        {
            _fontptr = font;
            chartSize = new Vector2(300, 300);

            KKLayoutParameters layoutParams = new KKLayoutParameters()
            {
                Height = chartSize.Y - (2 * padding),
                Width = chartSize.X - (2 * padding),
                LengthFactor = 1,
                DisconnectedMultiplier = 2,
                ExchangeVertices = true
            };

            layout = new GraphShape.Algorithms.Layout.KKLayoutAlgorithm<ItemNode, Edge<ItemNode>, BidirectionalGraph<ItemNode, Edge<ItemNode>>>(sbgraph, parameters: layoutParams);
            layout.Compute();
        }

        private TraceRecord? _rootTrace = null;
        private int timelineItemsOnChartDraw = 0;
        public void InitChartFromTrace(TraceRecord trace)
        {
            lock (_lock)
            {
                if (trace != _rootTrace)
                {
                    sbgraph.Clear();
                    layout.VerticesPositions.Clear();
                    _rootTrace = trace;
                    addedNodes.Clear();
                }

                bool needLayout = trace.TimelineItemsCount != timelineItemsOnChartDraw || trace.TimelineItemsCount < this.layout.VerticesPositions.Count;
                if (needLayout && !_layoutActive)
                {

                    Logging.TIMELINE_EVENT[] entries = trace.GetTimeLineEntries();
                    timelineItemsOnChartDraw = entries.Length;
                    //StopLayout();
                    AddThreadItems(null, trace);
                    /*
                    KKLayoutParameters layoutParams = new KKLayoutParameters()
                    {
                        Height = chartSize.Y - (2 * padding),
                        Width = chartSize.X - (2 * padding),
                        LengthFactor = 1,
                        DisconnectedMultiplier = 2,
                        ExchangeVertices = true
                    };
                    layout = new GraphShape.Algorithms.Layout.KKLayoutAlgorithm<ItemNode, 
                        Edge<ItemNode>, BidirectionalGraph<ItemNode, Edge<ItemNode>>>(sbgraph, parameters: layoutParams);
                    */
                    FitNodesToChart();
                    _computeRequired = true;
                }
            }
        }

        private readonly Dictionary<string, ItemNode> addedNodes = new Dictionary<string, ItemNode>();
        private readonly object _lock = new object();
        private readonly Dictionary<APIDetailsWin.InteractionEntityType, Dictionary<string, ItemNode>> _interactionEntities = new Dictionary<APIDetailsWin.InteractionEntityType, Dictionary<string, ItemNode>>();
        private readonly Dictionary<APIDetailsWin.InteractionRawType, Dictionary<string, ItemNode>> _interactionEntityReferences = new Dictionary<APIDetailsWin.InteractionRawType, Dictionary<string, ItemNode>>();
        private readonly Dictionary<Logging.TIMELINE_EVENT, ItemNode> _timelineEventEntities = new Dictionary<Logging.TIMELINE_EVENT, ItemNode>();

        //set of action labels associateed with each edge. todo add as a property to edge/make new edge object?
        private readonly Dictionary<Tuple<ItemNode, ItemNode>, List<string>> _edgeLabels = new Dictionary<Tuple<ItemNode, ItemNode>, List<string>>();
        private readonly List<Tuple<ItemNode, ItemNode>> _addedEdges = new List<Tuple<ItemNode, ItemNode>>();
        private ItemNode? _selectedNode = null;
        public ItemNode? SelectedEntity { get; private set; }
        public ItemNode? GetSelectedNode => _selectedNode;
        public Logging.TIMELINE_EVENT? SelectedAPIEvent { get; private set; }

        private static Vector2 Point2Vec(GraphShape.Point point) => new Vector2((float)point.X, (float)point.Y);

        private Vector2 chartOffset = Vector2.Zero;


        public ItemNode GetInteractedEntity(Logging.TIMELINE_EVENT evt)
        {
            lock (_lock)
            {
                return _timelineEventEntities[evt];
            }
        }

        private void AddThreadItems(ItemNode? parentProcess, TraceRecord trace)
        {

            string nodeName = $"PROCNODE_{trace.PID}_{trace.LaunchedTime}";
            ItemNode? startProcess = null;
            lock (_lock)
            {
                
                if (!addedNodes.TryGetValue(nodeName, out startProcess))
                {
                    startProcess = new ItemNode(nodeName, Logging.eTimelineEvent.ProcessStart, trace);
                    sbgraph.AddVertex(startProcess);
                    addedNodes[nodeName] = startProcess;
                    if (parentProcess != null)
                    {
                        sbgraph.AddEdge(new Edge<ItemNode>(parentProcess, startProcess));
                    }
                }


                var threads = trace.ProtoGraphs;
                foreach (var thread in threads)
                {
                    string threadName = $"THREADNODE_{thread.TraceData.randID}_{thread.ThreadID}";
                    if (!addedNodes.ContainsKey(threadName))
                    {
                        ItemNode threadNode = new ItemNode(threadName, Logging.eTimelineEvent.ThreadStart, thread);
                        sbgraph.AddVertex(threadNode);
                        sbgraph.AddEdge(new Edge<ItemNode>(startProcess, threadNode));
                        addedNodes[threadName] = threadNode;
                    }
                }

                var timelineEntries = trace.GetTimeLineEntries();
                foreach (Logging.TIMELINE_EVENT timelineEvent in timelineEntries)
                {
                    if (timelineEvent.TimelineEventType == Logging.eTimelineEvent.APICall)
                    {
                        var call = (Logging.APICALL)(timelineEvent.Item);
                        if (call.APIDetails != null)
                        {
                            APIDetailsWin.API_ENTRY apiinfo = call.APIDetails.Value;
                            if (apiinfo.Effects != null)
                            {
                                ProtoGraph? caller = call.Graph;
                                if (caller is null || call.Node is null || call.Index >= call.Node.callRecordsIndexs.Count)
                                {
                                    Logging.RecordLogEvent($"Warning: Call {call.APIDetails.Value.ModuleName}:{call.APIDetails.Value.Symbol} tried to place call {call.Index} on timeline, but only {call.Node?.callRecordsIndexs.Count} recorded");
                                    continue;
                                }
                                int recordsIndex = (int)call.Node.callRecordsIndexs[call.Index];
                                if (recordsIndex >= caller.SymbolCallRecords.Count)
                                {
                                    Logging.RecordLogEvent($"Warning: Call {call.APIDetails.Value.ModuleName}:{call.APIDetails.Value.Symbol} tried to place record {recordsIndex} on timeline, but caller has only {caller.SymbolCallRecords} recorded");
                                    continue;
                                }
                                APICALLDATA APICallRecord = caller.SymbolCallRecords[recordsIndex];
                                string threadName = $"THREADNODE_{caller.TraceData.randID}_{caller.ThreadID}";
                                ItemNode threadNode = addedNodes[threadName];

                                foreach (APIDetailsWin.InteractionEffect effectBase in apiinfo.Effects)
                                {
                                    switch (effectBase)
                                    {
                                        case APIDetailsWin.LinkReferenceEffect linkEffect:
                                            {
                                                APIDetailsWin.API_PARAM_ENTRY entityParamRecord = apiinfo.LoggedParams[linkEffect.EntityIndex];
                                                APIDetailsWin.API_PARAM_ENTRY referenceParamRecord = apiinfo.LoggedParams[linkEffect.ReferenceIndex];

                                                int entityParamLoggedIndex = APICallRecord.argList.FindIndex(x => x.Item1 == entityParamRecord.Index);
                                                int referenceParamLoggedIndex = APICallRecord.argList.FindIndex(x => x.Item1 == referenceParamRecord.Index);

                                                if (entityParamLoggedIndex == -1 || referenceParamLoggedIndex == -1)
                                                {
                                                    string error = $"API call record for {apiinfo.ModuleName}:{apiinfo.Symbol} [LinkReference] didn't have correct parameters. The instrumentation library or apidata file may not match.";
                                                    timelineEvent.MetaError = error;
                                                    Logging.RecordLogEvent(error, Logging.LogFilterType.TextDebug);
                                                    break;
                                                }

                                                if (!_interactionEntities.TryGetValue(entityParamRecord.EntityType, out Dictionary<string, ItemNode>? entityDict))
                                                {
                                                    entityDict = new Dictionary<string, ItemNode>();
                                                    _interactionEntities.Add(entityParamRecord.EntityType, entityDict);
                                                }
                                                string entityString = APICallRecord.argList[entityParamLoggedIndex].Item2;

                                                ItemNode entityNode;
                                                if (!entityDict.ContainsKey(entityString))
                                                {
                                                    entityNode = new ItemNode(entityString, Logging.eTimelineEvent.APICall, timelineEvent);
                                                    entityDict.Add(entityString, entityNode);
                                                    sbgraph.AddVertex(entityNode);
                                                    addedNodes[entityString] = entityNode;
                                                }
                                                else
                                                {
                                                    entityNode = addedNodes[entityString];
                                                }
                                                AddAPIEdge(threadNode, entityNode, apiinfo.Label);

                                                if (!_timelineEventEntities.TryGetValue(timelineEvent, out ItemNode? existingEntity))
                                                {
                                                    _timelineEventEntities.Add(timelineEvent, entityNode);
                                                }
                                                Debug.Assert(existingEntity == null || existingEntity == entityNode);


                                                //link this entity to the reference the api all created (eg associate a file path with the file handle that 'CreateFile' created)
                                                string referenceString = APICallRecord.argList[referenceParamLoggedIndex].Item2;
                                                if (referenceParamRecord.NoCase)
                                                {
                                                    referenceString = referenceString.ToLower();
                                                }

                                                if (!_interactionEntityReferences.ContainsKey(referenceParamRecord.RawType))
                                                {
                                                    _interactionEntityReferences.Add(referenceParamRecord.RawType, new Dictionary<string, ItemNode>());
                                                }
                                                if (!_interactionEntityReferences[referenceParamRecord.RawType].ContainsKey(referenceString))
                                                {
                                                    _interactionEntityReferences[referenceParamRecord.RawType].Add(referenceString, entityNode);
                                                }

                                                break;
                                            }

                                        // this api performs some action on a refererence to an entity
                                        // record this as a label on the edge and link this event to the entity
                                        case APIDetailsWin.UseReferenceEffect useEffect:
                                            {
                                                APIDetailsWin.API_PARAM_ENTRY referenceParamRecord = apiinfo.LoggedParams[useEffect.ReferenceIndex];
                                                int referenceParamLoggedIndex = APICallRecord.argList.FindIndex(x => x.Item1 == referenceParamRecord.Index);
                                                if (referenceParamLoggedIndex == -1)
                                                {
                                                    timelineEvent.MetaError = $"API call record for {apiinfo.ModuleName}:{apiinfo.Symbol} [UseReference] didn't have correct parameters";
                                                    Logging.RecordLogEvent(timelineEvent.MetaError, Logging.LogFilterType.TextDebug);
                                                    break;
                                                }

                                                string referenceString = APICallRecord.argList[referenceParamLoggedIndex].Item2;
                                                if (referenceParamRecord.NoCase)
                                                {
                                                    referenceString = referenceString.ToLower();
                                                }

                                                bool resolvedReference = false;
                                                if (_interactionEntityReferences.TryGetValue(referenceParamRecord.RawType, out Dictionary<string, ItemNode>? typeEntityList))
                                                {
                                                    if (typeEntityList.TryGetValue(referenceString, out ItemNode? entityNode))
                                                    {
                                                        resolvedReference = true;
                                                        if (!_timelineEventEntities.ContainsKey(timelineEvent))
                                                        {
                                                            _timelineEventEntities.Add(timelineEvent, entityNode);
                                                        }

                                                        AddAPIEdge(threadNode, entityNode, apiinfo.Label);
                                                    }
                                                }
                                                if (!resolvedReference)
                                                {
                                                    timelineEvent.MetaError = $"API call record for {apiinfo.ModuleName}:{apiinfo.Symbol} [UseReference] reference was not linked to an entity ({referenceString})";
                                                    Logging.RecordLogEvent(timelineEvent.MetaError, Logging.LogFilterType.TextDebug);
                                                }
                                                break;
                                            }

                                        // this api invalidates a reference
                                        // remove the link between the reference and the entity it references
                                        case APIDetailsWin.DestroyReferenceEffect destroyEffect:
                                            {
                                                APIDetailsWin.API_PARAM_ENTRY referenceParamRecord = apiinfo.LoggedParams[destroyEffect.ReferenceIndex];
                                                int referenceParamLoggedIndex = APICallRecord.argList.FindIndex(x => x.Item1 == referenceParamRecord.Index);
                                                if (referenceParamLoggedIndex == -1)
                                                {
                                                    timelineEvent.MetaError = $"API call record for {apiinfo.ModuleName}:{apiinfo.Symbol} [DestroyReference] didn't have correct parameters";
                                                    Logging.RecordLogEvent(timelineEvent.MetaError, Logging.LogFilterType.TextDebug);
                                                    break;
                                                }

                                                string referenceString = APICallRecord.argList[referenceParamLoggedIndex].Item2;
                                                if (referenceParamRecord.NoCase)
                                                {
                                                    referenceString = referenceString.ToLower();
                                                }

                                                bool resolvedReference = false;
                                                if (_interactionEntityReferences.TryGetValue(referenceParamRecord.RawType, out Dictionary<string, ItemNode>? typeEntityList))
                                                {
                                                    if (typeEntityList.TryGetValue(referenceString, out ItemNode? entityNode))
                                                    {
                                                        resolvedReference = true;
                                                        if (!_timelineEventEntities.ContainsKey(timelineEvent))
                                                        {
                                                            _timelineEventEntities.Add(timelineEvent, entityNode);
                                                        }

                                                        AddAPIEdge(threadNode, entityNode, apiinfo.Label);
                                                        typeEntityList.Remove(referenceString);
                                                    }
                                                }
                                                if (!resolvedReference)
                                                {
                                                    timelineEvent.MetaError = $"API call record for {apiinfo.ModuleName}:{apiinfo.Symbol} [DestroyReference] reference was not linked to an entity ({referenceString})";
                                                    Logging.RecordLogEvent(timelineEvent.MetaError, Logging.LogFilterType.TextDebug);
                                                }

                                                break;
                                            }

                                        default:
                                            timelineEvent.MetaError = $"API call record for {apiinfo.ModuleName}:{apiinfo.Symbol}: had invalid effect {effectBase}";
                                            Logging.RecordLogEvent(timelineEvent.MetaError, Logging.LogFilterType.TextDebug);
                                            break;

                                    }
                                }
                            }

                        }
                    }

                }

                if (startProcess is not null)
                {
                    foreach (var child in trace.GetChildren())
                    {
                        string childName = $"PROCNODE_{child.PID}_{child.LaunchedTime}";
                        if (!addedNodes.TryGetValue(childName, out ItemNode? childProcess) || childProcess is null)
                        {
                            childProcess = new ItemNode(childName, Logging.eTimelineEvent.ProcessStart, child);
                            sbgraph.AddVertex(childProcess);
                            addedNodes[childName] = childProcess;

                            sbgraph.AddEdge(new Edge<ItemNode>(startProcess, childProcess));

                        }
                        AddThreadItems(parentProcess, child);
                    }
                }
            }
        }



        private void AddAPIEdge(ItemNode source, ItemNode dest, string? label = "")
        {
            Edge<ItemNode> edge = new Edge<ItemNode>(source, dest);
            Tuple<ItemNode, ItemNode> edgeTuple = new Tuple<ItemNode, ItemNode>(source, dest);
            if (!_addedEdges.Contains(edgeTuple))
            {
                sbgraph.AddEdge(edge);
                _addedEdges.Add(edgeTuple);
            }

            if (label is not null)
            {
                if (!_edgeLabels.TryGetValue(edgeTuple, out List<string>? thisEdgeLabels))
                {
                    _edgeLabels.Add(edgeTuple, new List<string>() { label });
                }
                else
                {
                    if (!thisEdgeLabels.Contains(label))
                    {
                        thisEdgeLabels.Add(label);
                    }
                }
            }
        }

        private bool _layoutActive = false;
        private bool _computeRequired = false;

        public void Draw()
        {
            Vector2 availArea = ImGui.GetContentRegionAvail();
            Vector2 targetSize = availArea - new Vector2(0, 6);
            if (targetSize != chartSize && targetSize.X > 50 && targetSize.Y > 50)
            {
                StopLayout();
                chartSize = targetSize;
                layout.Parameters.Width = targetSize.X;
                layout.Parameters.Height = targetSize.Y;
                FitNodesToChart();
            }
            if (_fittingActive)
            {
                DoLayoutFittingCycle();
            }
            if (_computeRequired && !_layoutActive)
            {
                _layoutActive = true;
                _computeRequired = false;
                Task.Run(() => { layout.Compute(); _layoutActive = false; });

            }

            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eSandboxChartBG));


            Vector2 cursorPos = ImGui.GetCursorScreenPos();
            Vector2 chartPos = cursorPos + chartOffset + new Vector2(padding, padding);
            if (ImGui.BeginChild("ChartFrame", chartSize, false, ImGuiWindowFlags.NoScrollbar))
            {
                MouseOverWidget = ImGui.IsMouseHoveringRect(cursorPos, cursorPos + chartSize);
                if (MouseOverWidget)
                {
                    HandleMouseInput();
                }

                var edges = sbgraph.Edges;
                List<Tuple<ItemNode, ItemNode>> drawnEdges = new List<Tuple<ItemNode, ItemNode>>();
                var positions = new Dictionary<ItemNode, GraphShape.Point>(layout.VerticesPositions);
                foreach (var edge in edges)
                {
                    if (positions.TryGetValue(edge.Source, out GraphShape.Point srcPoint) &&
                    positions.TryGetValue(edge.Target, out GraphShape.Point targPoint))
                    {
                        Vector2 sourcePos = chartPos + Point2Vec(srcPoint);
                        Vector2 targPos = chartPos + Point2Vec(targPoint);
                        Tuple<ItemNode, ItemNode> edgeTuple = new Tuple<ItemNode, ItemNode>(edge.Source, edge.Target);
                        if (drawnEdges.Contains(edgeTuple))
                        {
                            continue;
                        }

                        drawnEdges.Add(edgeTuple);

                        ImGui.GetWindowDrawList().AddLine(sourcePos, targPos, 0xffff00ff);
                        if (_edgeLabels.TryGetValue(edgeTuple, out List<string>? edgeLabels))
                        {
                            ImGui.GetWindowDrawList().AddText(Vector2.Lerp(sourcePos, targPos, 0.5f), 0xff000000, string.Join(",", edgeLabels));
                        }
                    }
                }


                foreach (var node in positions)
                {
                    Vector2 nCenter = chartPos + Point2Vec(node.Value);
                    DrawNode(node.Key, nCenter);
                }


                ImGui.SetCursorScreenPos(cursorPos + chartSize - new Vector2(30, 30));

                if (!_fittingActive)
                {
                    if (ImGui.Button("[C]"))
                    {
                        FitNodesToChart();
                    }
                    SmallWidgets.MouseoverText("Center graph");
                }
                ImGui.SetCursorScreenPos(cursorPos);
                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
        }

        private void DrawNode(ItemNode node, Vector2 position)
        {
            Vector2 cursor = ImGui.GetCursorScreenPos();
            if (!InFrame(position - cursor))
            {
                return;
            }

            var DrawList = ImGui.GetWindowDrawList();

            bool isSelected = node == _selectedNode;
            switch (node.TLtype)
            {
                case Logging.eTimelineEvent.ProcessStart:
                case Logging.eTimelineEvent.ProcessEnd:
                    {
                        TraceRecord trace = (TraceRecord)node.reference;
                        switch (trace.TraceState)
                        {
                            case TraceRecord.ProcessState.eTerminated:
                                DrawList.AddCircleFilled(position, 18, isSelected ? 0xffDDDDDD : 0xFFFFFFFF);
                                DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff0000ff, $"{ImGuiController.FA_ICON_COGS}");
                                DrawList.AddText(position + new Vector2(20, -14), 0xff000000, $"Process {trace.PID} (Exited)");
                                break;

                            case TraceRecord.ProcessState.eRunning:
                                DrawList.AddCircleFilled(position, 18, isSelected ? 0xffDDDDDD : 0xFFFFFFFF);
                                DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff00ff00, $"{ImGuiController.FA_ICON_COGS}");
                                DrawList.AddText(position + new Vector2(20, -14), 0xff000000, $"Process {trace.PID} (Running)");
                                break;

                            case TraceRecord.ProcessState.eSuspended:
                                DrawList.AddCircleFilled(position, 18, isSelected ? 0xffDDDDDD : 0xFFFFFFFF);
                                DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff00ffff, $"{ImGuiController.FA_ICON_COGS}");
                                DrawList.AddText(position + new Vector2(20, -14), 0xff000000, $"Process {trace.PID} (Suspended)");
                                break;
                            default:
                                Debug.Assert(false, "Bad trace state");
                                break;
                        }
                    }
                    break;
                case Logging.eTimelineEvent.ThreadStart:
                case Logging.eTimelineEvent.ThreadEnd:
                    {
                        ProtoGraph graph = (ProtoGraph)node.reference;
                        if (graph.Terminated)
                        {
                            DrawList.AddCircleFilled(position, 18, isSelected ? 0xffDDDDDD : 0xFFFFFFFF);
                            DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff0000ff, $"{ImGuiController.FA_ICON_COG}");
                            DrawList.AddText(position + new Vector2(20, -14), 0xff000000, $"Thread {graph.ThreadID} (Exited)");
                        }
                        else
                        {
                            DrawList.AddCircleFilled(position, 18, isSelected ? 0xffDDDDDD : 0xFFFFFFFF);
                            DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff00ff00, $"{ImGuiController.FA_ICON_COG}");
                            DrawList.AddText(position + new Vector2(20, -14), 0xff000000, $"Thread {graph.ThreadID} (Active)");
                        }
                    }
                    break;

                case Logging.eTimelineEvent.APICall:
                    Logging.TIMELINE_EVENT apiEvent = (Logging.TIMELINE_EVENT)node.reference;
                    Logging.APICALL apicall = (Logging.APICALL)apiEvent.Item;
                    if (!apicall.APIDetails.HasValue)
                    {
                        return;
                    }
                    APIDetailsWin.API_ENTRY details = apicall.APIDetails.Value;

                    DrawList.AddCircleFilled(position, 18, isSelected ? 0xffDDDDDD : 0xFFFFFFFF);
                    switch (details.FilterType)
                    {
                        case "File":
                            DrawList.AddText(_fontptr, 20, position - new Vector2(10f, 10f), 0xff000000, $"{ImGuiController.FA_ICON_FILECODE}");
                            DrawList.AddText(position + new Vector2(20, -15), 0xff000000, "File Interaction");
                            DrawList.AddText(position + new Vector2(20, 5), 0xff000000, node.label);
                            break;
                        case "Registry":
                            DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff000000, $"{ImGuiController.FA_ICON_SQUAREGRID}");
                            DrawList.AddText(position + new Vector2(20, -15), 0xff000000, "Registry Interaction");
                            DrawList.AddText(position + new Vector2(20, 5), 0xff000000, node.label);
                            break;
                        case "Process":
                            DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff000000, $"{ImGuiController.FA_ICON_COGS}");
                            DrawList.AddText(position + new Vector2(20, -15), 0xff000000, "Process Interaction");
                            DrawList.AddText(position + new Vector2(20, 5), 0xff000000, node.label);
                            break;
                        case "Network":
                            DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff000000, $"{ImGuiController.FA_ICON_NETWORK}");
                            DrawList.AddText(position + new Vector2(20, -15), 0xff000000, "Network Interaction");
                            DrawList.AddText(position + new Vector2(20, 5), 0xff000000, node.label);
                            break;
                        default:
                            DrawList.AddText(_fontptr, 25, position - new Vector2(12.5f, 12.5f), 0xff000000, $"{ImGuiController.FA_ICON_UP}");
                            DrawList.AddText(position + new Vector2(20, -15), 0xff000000, details.FilterType);
                            DrawList.AddText(position + new Vector2(20, 5), 0xff000000, node.label);
                            break;
                    }
                    break;


                default:
                    DrawList.AddCircleFilled(position, nodeSize, 0xff000000);
                    break;

            }


            if (node == _selectedNode)
            {
                DrawList.AddCircle(position, 18, 0xff222222);
            }
            ImGui.SetCursorScreenPos(position - new Vector2(12, 12));
            ImGui.InvisibleButton($"##{position.X}-{position.Y}", new Vector2(25, 25));
            if (ImGui.IsItemClicked())
            {
                _selectedNode = node;
                if (_selectedNode.TLtype == Logging.eTimelineEvent.APICall)
                {
                    SelectedEntity = node;
                    SelectedAPIEvent = (Logging.TIMELINE_EVENT)node.reference;
                }
                else
                {
                    SelectedEntity = null;
                    SelectedAPIEvent = null;
                }
            }

            //Vector2 labelSize = ImGui.CalcTextSize(node.label);
            //DrawList.AddRectFilled(position, position + labelSize, 0xddffffff);
            ImGui.SetCursorScreenPos(cursor);
        }

        private bool InFrame(Vector2 ScreenPosition)
        {
            return (ScreenPosition.X > 5 &&
                ScreenPosition.X < (chartSize.X + nodeSize) &&
                ScreenPosition.Y > 5 &&
                ScreenPosition.Y < (chartSize.Y + nodeSize));
        }


        public void SelectAPIEvent(Logging.TIMELINE_EVENT evt)
        {
            SelectedAPIEvent = null;
            SelectedEntity = null;
            _selectedNode = null;

            if (_rootTrace == null)
            {
                return;
            }

            switch (evt.TimelineEventType)
            {
                case Logging.eTimelineEvent.ProcessStart:
                case Logging.eTimelineEvent.ProcessEnd:
                    TraceRecord? trace = _rootTrace.GetTraceByID(evt.ID);
                    if (trace == null)
                    {
                        return;
                    }

                    foreach (var node in sbgraph.Vertices)
                    {
                        if (node.reference == trace)
                        {
                            _selectedNode = node;
                        }
                    }
                    break;
                case Logging.eTimelineEvent.ThreadStart:
                case Logging.eTimelineEvent.ThreadEnd:
                    ProtoGraph? graph = _rootTrace.GetProtoGraphByTID(evt.ID);
                    if (graph == null)
                    {
                        return;
                    }

                    foreach (var node in sbgraph.Vertices)
                    {
                        if (node.reference == graph)
                        {
                            _selectedNode = node;
                        }
                    }
                    break;

                case Logging.eTimelineEvent.APICall:
                    {
                        SelectedAPIEvent = evt;
                        if (_timelineEventEntities.TryGetValue(evt, out ItemNode? newSelectedEntity))
                        {
                            SelectedEntity = newSelectedEntity;
                            _selectedNode = newSelectedEntity;
                        }
                    }
                    break;
            }
        }

        private void HandleMouseInput()
        {
            /*
            Vector2 pos = ImGui.GetCursorScreenPos() + chartOffset;
            if (ImGui.IsMouseClicked(ImGuiMouseButton.Right))
            {

            }
            */
            if (ImGui.IsMouseClicked(ImGuiMouseButton.Middle))
            {
                if (_rootTrace != null)
                {
                    InitChartFromTrace(_rootTrace);//, force: true);
                }
            }
        }

        private void StopLayout()
        {
            if (layout.State == QuikGraph.Algorithms.ComputationState.Running)
            {
                layout.Abort();
            }
            while (LayoutRunning)
            {
                System.Threading.Thread.Sleep(5);
            }
            _layoutActive = false;
        }

        public void ApplyZoom(float delta)
        {
            if (!MouseOverWidget)
            {
                return;
            }

            double newScaleX = _scaleX + (delta / 25);

            if (newScaleX != _scaleX && newScaleX > 0)
            {
                _scaleX += (delta / 25);

                StopLayout();
                layout.Parameters.LengthFactor = _scaleX;
                _computeRequired = true;
            }
        }

        private bool _fittingActive = false;
        private int fittingAttempts = 0;
        public void FitNodesToChart()
        {
            fittingAttempts = 0;
            if (!_fittingActive)
            {
                _fittingActive = true;
            }
        }

        private void DoLayoutFittingCycle()
        {

            if (LayoutRunning || !_fittingActive)
            {
                return;
            }

            var positions = layout.VerticesPositions;
            if (positions.Count == 0 || layout.Parameters.Width == 0 || layout.Parameters.Height == 0)
            {
                return;
            }

            Logging.WriteConsole("fitting cycle start");
            //find the most extreme node positions, relative to the edges
            Vector2 firstNodePos = Point2Vec(positions[sbgraph.Vertices.First()]) + chartOffset;
            double Xleft = firstNodePos.X, Xright = Xleft, yTop = firstNodePos.Y, yBase = yTop;
            foreach (var node in positions)
            {
                Vector2 nCenter = Point2Vec(node.Value) + chartOffset;
                if (nCenter.X < Xleft)
                {
                    Xleft = nCenter.X;
                }

                if (nCenter.X > Xright)
                {
                    Xright = nCenter.X;
                }

                if (nCenter.Y < yTop)
                {
                    yTop = nCenter.Y;
                }

                if (nCenter.Y > yBase)
                {
                    yBase = nCenter.Y;
                }
            }

            //find how far we need to move them to fit - ideal is to make these all zero
            double leftDifference = Xleft;
            double rightDifference = layout.Parameters.Width - (Xright + padding * 2);
            double topDifference = yTop;
            double baseDifference = layout.Parameters.Height - (yBase + padding * 2);

            //first center the chart
            double XAdder = (rightDifference - leftDifference) / 2;
            double YAdder = (baseDifference - topDifference) / 2;

            chartOffset = chartOffset + new Vector2((float)XAdder, (float)YAdder);

            Xleft += XAdder;
            yTop += YAdder;

            //now zoom to fit
            leftDifference = Xleft;
            topDifference = yTop;

            double minvalue = Math.Min(leftDifference, topDifference);
            double zoomSizeRatio = minvalue / ((leftDifference < topDifference) ? layout.Parameters.Width : layout.Parameters.Height);

            if (Math.Abs(zoomSizeRatio) > 1)
            {
                //zoom/pan is way off, reset to sensible scale
                _scaleX = 1;
                layout.Parameters.LengthFactor = _scaleX;
                _computeRequired = true;
            }
            else if (minvalue < 50)
            {
                //zoom out by shrinking edges
                _scaleX = _scaleX - ((Math.Abs(zoomSizeRatio) > 0.1) ? 0.2 : 0.02);
                if (_scaleX < 0)
                {
                    _scaleX = 0.01;
                }

                layout.Parameters.LengthFactor = _scaleX;
                _computeRequired = true;
            }
            else if (minvalue > 75)
            {
                //zoom in by growing edges
                _scaleX = _scaleX + ((Math.Abs(zoomSizeRatio) > 0.1) ? 0.1 : 0.01);
                layout.Parameters.LengthFactor = _scaleX;
                _computeRequired = true;
            }
            else
            {
                _fittingActive = false;
            }

            Logging.WriteConsole("fitting cycle end");
            if (_fittingActive)
            {
                fittingAttempts += 1;
                if (fittingAttempts > 50)
                {
                    _fittingActive = false;
                    Logging.RecordLogEvent($"Ending chart zoom to frame after {fittingAttempts} cycles. XDifference: {Xleft}, YDifference: {yTop}", Logging.LogFilterType.TextDebug);
                }
            }
        }

        private bool LayoutRunning => layout.State == QuikGraph.Algorithms.ComputationState.Running ||
                layout.State == QuikGraph.Algorithms.ComputationState.PendingAbortion;

        private bool MouseOverWidget = false;
        public void ApplyMouseDrag(Vector2 delta)
        {
            if (MouseOverWidget)
            {
                chartOffset -= delta;
            }
        }


        public void AlertKeybindPressed(Tuple<Veldrid.Key, Veldrid.ModifierKeys> keyPressed, CONSTANTS.KeybindAction boundAction)
        {

            float shiftModifier = ImGui.GetIO().KeyShift ? 1 : 0;
            switch (boundAction)
            {
                case CONSTANTS.KeybindAction.CenterFrame:
                    //ResetLayout();
                    FitNodesToChart();
                    break;
                default:
                    break;
            }
        }


    }
}
