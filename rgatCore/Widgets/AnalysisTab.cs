using ImGuiNET;
using rgat.Widgets;
using System.IO;
using System.Numerics;
using static rgat.Logging;

namespace rgat
{
    internal partial class rgatUI
    {

        private void DrawAnalysisTab(TraceRecord? activeTrace)
        {
            if (activeTrace == null || !ImGui.BeginTabItem("Timeline") || chart is null)
            {
                return;
            }

            _currentTab = "Timeline";

            float height = ImGui.GetContentRegionAvail().Y;
            float width = ImGui.GetContentRegionAvail().X;
            float sidePaneWidth = 300;

            if (height < 50 || width < 50)
            {

                ImGui.EndTabItem();
                return;
            }

            chart!.InitChartFromTrace(activeTrace);

            SandboxChart.ItemNode? selectedNode = chart.GetSelectedNode;
            if (ImGui.BeginTable("#TaTTable", 2, ImGuiTableFlags.Resizable))
            {
                ImGui.TableSetupColumn("#TaTTEntryList", ImGuiTableColumnFlags.None | ImGuiTableColumnFlags.WidthFixed, sidePaneWidth * 2f);
                ImGui.TableSetupColumn("#TaTTChart");

                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    if (ImGui.BeginChild("#ijdcccfgo", ImGui.GetContentRegionAvail() - new Vector2(0, 5)))
                    {

                        TraceSelector.Draw(activeTrace);
                        ImGui.Separator();
                        ImGui.Text("Event Listing");

                        if (ImGui.BeginChild("#iosfjhvs", ImGui.GetContentRegionAvail() - new Vector2(0, selectedNode is null ? 0 : 250)))
                        {
                            DrawEventListTable(activeTrace, selectedNode);
                            ImGui.EndChild();
                        }


                        if (selectedNode is not null)
                        {
                            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.Frame));
                            if (ImGui.BeginChild(ImGui.GetID("#ijdcccfgo"), new Vector2(ImGui.GetContentRegionAvail().X, 245)))
                            {
                                DrawEventInfoPanel(height, activeTrace, selectedNode);
                                ImGui.EndChild();
                            }
                            ImGui.PopStyleColor();
                        }
                        ImGui.EndChild();
                    }
                }

                if (ImGui.TableNextColumn())
                {
                    chart.Draw(_controller!.UnicodeFont);
                }
                ImGui.EndTable();
            }


            ImGui.EndTabItem();
        }

        void DrawEventInfoPanel(float height, TraceRecord activeTrace, SandboxChart.ItemNode? selectedNode)
        {
            if (ImGui.BeginChild("#SandboxTabbaseRightPane", ImGui.GetContentRegionAvail() - new Vector2(0, 0), true))
            {

                if (!APIDetailsWin.Loaded)
                {
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x5f88705f);
                    if (ImGui.BeginChild("#SandboxTabtopRightPane", new Vector2(100, 100)))// new Vector2(ImGui.GetContentRegionAvail().X, tr_height)))
                    {
                        ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour));
                        if (ImGui.BeginChild("#LoadErrFrame", new Vector2(ImGui.GetContentRegionAvail().X - 2, 80)))
                        {
                            ImGui.Indent(5);
                            ImGui.TextWrapped("Error - No API datafile was loaded");
                            ImGui.TextWrapped("See error details in the logs tab");
                            ImGui.EndChild();
                        }
                        ImGui.PopStyleColor();
                    }

                    //ImGui.EndTable();
                    ImGui.EndChild();
                    ImGui.PopStyleColor();
                }


                //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x8f48009f);

                if (selectedNode != null)
                {
                    switch (selectedNode.TLtype)
                    {
                        case eTimelineEvent.ProcessStart:
                            DrawProcessNodeTable((TraceRecord)selectedNode.reference);
                            break;

                        case eTimelineEvent.ThreadStart:
                            DrawThreadNodeTable((ProtoGraph)selectedNode.reference);
                            break;

                        case eTimelineEvent.APICall:
                            DrawAPIInfoTable((Logging.TIMELINE_EVENT)selectedNode.reference);
                            break;
                        default:
                            ImGui.Text($"We don't do {selectedNode.TLtype} here");
                            break;
                    }
                }
                else
                {
                    if (chart!.SelectedAPIEvent != null)
                    {
                        DrawAPIInfoTable(chart.SelectedAPIEvent);
                    }
                }
                ImGui.EndChild();
            }

        }


        private void DrawEventListTable(TraceRecord trace, SandboxChart.ItemNode? selectedNode)
        {
            if (chart is null)
            {
                return;
            }

            ImGui.PushStyleColor(ImGuiCol.Header, Themes.GetThemeColourUINT(Themes.eThemeColour.Emphasis2, 40));
            TIMELINE_EVENT[] events = trace.GetTimeLineEntries();
            if (ImGui.BeginTable("#TaTTFullList", 4, ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY |
                ImGuiTableFlags.Resizable | ImGuiTableFlags.RowBg))
            {
                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableSetupColumn("#", ImGuiTableColumnFlags.WidthFixed, 50);
                ImGui.TableSetupColumn("Type", ImGuiTableColumnFlags.WidthFixed, 70);
                ImGui.TableSetupColumn("Module", ImGuiTableColumnFlags.WidthFixed, 70);
                ImGui.TableSetupColumn("Details", ImGuiTableColumnFlags.None);
                ImGui.TableHeadersRow();

                var SelectedEntity = chart.SelectedEntity;
                var SelectedAPIEvent = chart.SelectedAPIEvent;

                bool ThreadNodeSelected = selectedNode is not null && Equals(selectedNode.reference.GetType(), typeof(ProtoGraph));
                bool ProcessNodeSelected = selectedNode is not null && Equals(selectedNode.reference.GetType(), typeof(TraceRecord));


                int i = 0;
                foreach (TIMELINE_EVENT TLevent in events)
                {
                    i += 1;

                    ImGui.TableNextRow();
                    if (TLevent.MetaError != null)
                    {
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour));
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour));
                    }

                    bool selected = false;
                    string eventType = "";
                    string module = "";
                    if (ImGui.TableNextColumn())
                    {

                        switch (TLevent.TimelineEventType)
                        {
                            case eTimelineEvent.ProcessStart:
                            case eTimelineEvent.ProcessEnd:
                                eventType = "Process";

                                if (selectedNode != null)
                                {
                                    selected = (ProcessNodeSelected && TLevent.ID == ((TraceRecord)selectedNode.reference).PID);
                                }

                                break;
                            case eTimelineEvent.ThreadStart:
                            case eTimelineEvent.ThreadEnd:
                                eventType = "Thread";
                                if (selectedNode != null)
                                {
                                    ProtoGraph currentEntryGraph = (ProtoGraph)TLevent.Item;
                                    selected = (ThreadNodeSelected && currentEntryGraph.ThreadID == ((ProtoGraph)selectedNode.reference).ThreadID);
                                    selected = selected || (ProcessNodeSelected && currentEntryGraph.TraceData.PID == ((TraceRecord)(selectedNode.reference)).PID);
                                }
                                break;
                            case eTimelineEvent.APICall:
                                {
                                    Logging.APICALL call = (Logging.APICALL)(TLevent.Item);
                                    selected = TLevent == SelectedAPIEvent;

                                    if (call.Node!.IsExternal)
                                    {
                                        eventType = "API - " + call.APIType();
                                        module = Path.GetFileNameWithoutExtension(trace.DisassemblyData.GetModulePath(call.Node.GlobalModuleID));

                                        //api call is selected if it is either directly activated, or interacts with a reference to the active entity
                                        //eg: if the file.txt node is selected, writefile to the relevant handle will also be selected
                                        selected = selected || (SelectedEntity != null && SelectedEntity == chart.GetInteractedEntity(TLevent));
                                        if (!selected && selectedNode != null)
                                        {
                                            //select all apis called by selected thread node
                                            selected = selected || (ThreadNodeSelected && call.Graph!.ThreadID == ((ProtoGraph)selectedNode.reference).ThreadID);
                                            //select all apis called by selected process node
                                            selected = selected || (ProcessNodeSelected && call.Graph!.TraceData.PID == ((TraceRecord)selectedNode.reference).PID);
                                        }
                                        //WinAPIDetails.API_ENTRY = call.APIEntry;
                                    }
                                    else
                                    {
                                        eventType = "Internal";
                                    }
                                }
                                break;
                        }

                        if (ImGui.Selectable(i.ToString(), selected, ImGuiSelectableFlags.SpanAllColumns) && !selected)
                        {
                            chart.SelectAPIEvent(TLevent);
                        }
                    }
                    if (ImGui.TableNextColumn())
                    {
                        ImGui.Text(eventType);
                    }
                    if (ImGui.TableNextColumn())
                    {
                        ImGui.Text(module);
                    }
                    if (ImGui.TableNextColumn())
                    {
                        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(3, 3));

                        var labelComponents = TLevent.Label();
                        for (var labeli = 0; labeli < labelComponents.Count; labeli++)
                        {
                            var component = labelComponents[labeli];
                            ImGui.TextColored(component.Item2.ToVec4(), component.Item1);
                            if (labeli < labelComponents.Count - 1)
                            {
                                ImGui.SameLine();
                            }
                        }
                    }
                    ImGui.PopStyleVar();
                }

                ImGui.EndTable();
            }
            ImGui.PopStyleColor();
        }

        private static void DrawProcessNodeTable(TraceRecord trace)
        {
            if (ImGui.BeginTable("#ProcSelTl", 2))
            {
                ImGui.TableSetupColumn("#Field", ImGuiTableColumnFlags.WidthFixed, 80);

                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Process ID");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"{trace.PID}");
                }
                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Path");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.TextWrapped($"{trace.Target.FilePath}");
                }

                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"State");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"{trace.TraceState}");
                }

                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Started");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"{trace.LaunchedTime.ToLocalTime()}");
                }
                ImGui.EndTable();
            }
        }

        private static void DrawThreadNodeTable(ProtoGraph thread)
        {
            if (ImGui.BeginTable("#ThreadSelTl", 2))
            {
                ImGui.TableSetupColumn("#Field", ImGuiTableColumnFlags.WidthFixed, 80);

                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Thread ID");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"{thread.ThreadID}");
                }
                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Started");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"{thread.ConstructedTime}");
                }
                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Terminated");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"{thread.Terminated}");
                }
                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Instructions");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"{thread.TotalInstructions}");
                }
                ImGui.EndTable();
            }
        }

        public static void DrawAPIInfoTable(TIMELINE_EVENT evt)
        {
            if (ImGui.BeginTable("#ThreadSelTl", 2))
            {
                Logging.APICALL call = (Logging.APICALL)evt.Item;

                ImGui.TableSetupColumn("#Field", ImGuiTableColumnFlags.WidthFixed, 80);

                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Thread ID");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"{call.Graph!.ThreadID}");
                }

                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Library");
                }
                if (ImGui.TableNextColumn())
                {
                    ImGui.TextWrapped($"{call.Graph.TraceData.DisassemblyData.GetModulePath(call.Node!.GlobalModuleID)}");
                }

                ImGui.TableNextRow();
                if (ImGui.TableNextColumn())
                {
                    ImGui.Text($"Symbol");
                }
                if (ImGui.TableNextColumn())
                {
                    if (call.APIDetails.HasValue)
                    {
                        ImGui.TextWrapped($"{call.APIDetails.Value.Symbol}");
                    }
                    else
                    {
                        if (call.Node is not null)
                        {
                            if (call.Graph.TraceData.DisassemblyData.GetSymbol(call.Node.GlobalModuleID, call.Node.Address, out string? symbol))
                            {
                                ImGui.TextWrapped(symbol);
                            }
                            else
                            {
                                if (call.Node.Label is not null)
                                {
                                    ImGui.TextWrapped($"{call.Node.Label.Split(' ')[^1]}");
                                }
                            }
                        }
                    }
                }
                if (ImGui.TableNextColumn())
                {
                    if (evt.MetaError != null)
                    {
                        ImGui.TableNextRow();
                        if (ImGui.TableNextColumn())
                        {
                            ImGui.TextWrapped($"Processing Error");
                        }
                        if (ImGui.TableNextColumn())
                        {
                            ImGui.TextWrapped($"{evt.MetaError}");
                        }
                    }
                }
                ImGui.EndTable();
            }
        }



    }
}
