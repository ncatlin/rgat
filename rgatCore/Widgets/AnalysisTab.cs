﻿using ImGuiNET;
using rgat.Widgets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;
using static rgat.Logging;

namespace rgat
{
    partial class rgatUI
    {

        private void DrawAnalysisTab(TraceRecord activeTrace)
        {
            if (activeTrace == null || !ImGui.BeginTabItem("Timeline")) return;
            _currentTab = "Timeline";

            float height = ImGui.GetContentRegionAvail().Y;
            float width = ImGui.GetContentRegionAvail().X;
            float sidePaneWidth = 300;

            if (height < 50 || width < 50)
            {

                ImGui.EndTabItem();
                return;
            }

            chart.InitChartFromTrace(activeTrace);

            SandboxChart.ItemNode selectedNode = chart.GetSelectedNode;
            if (ImGui.BeginTable("#TaTTable", 3, ImGuiTableFlags.Resizable))
            {
                ImGui.TableSetupColumn("#TaTTEntryList", ImGuiTableColumnFlags.None, sidePaneWidth);
                ImGui.TableSetupColumn("#TaTTChart", ImGuiTableColumnFlags.NoDirectResize, width - 2 * sidePaneWidth);
                ImGui.TableSetupColumn("#TaTTControlsFocus", ImGuiTableColumnFlags.NoDirectResize, sidePaneWidth);

                ImGui.TableNextRow();

                ImGui.TableNextColumn();
                //ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, 0xff99ff77);
                ImGui.Text("Event Listing");


                TIMELINE_EVENT[] events = activeTrace.GetTimeLineEntries();
                if (ImGui.BeginTable("#TaTTFullList", 4, ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY | ImGuiTableFlags.Resizable | ImGuiTableFlags.RowBg))
                {
                    ImGui.TableSetupScrollFreeze(0, 1);
                    ImGui.TableSetupColumn("#", ImGuiTableColumnFlags.WidthFixed, 50);
                    ImGui.TableSetupColumn("Type", ImGuiTableColumnFlags.WidthFixed, 70);
                    ImGui.TableSetupColumn("Module", ImGuiTableColumnFlags.WidthFixed, 70);
                    ImGui.TableSetupColumn("Details", ImGuiTableColumnFlags.None);
                    ImGui.TableHeadersRow();

                    var SelectedEntity = chart.SelectedEntity;
                    var SelectedAPIEvent = chart.SelectedAPIEvent;


                    int i = 0;
                    foreach (TIMELINE_EVENT TLevent in events)
                    {
                        i += 1;

                        ImGui.TableNextRow();
                        if (TLevent.MetaError != null)
                        {
                            ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                            ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg1, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                        }

                        ImGui.TableNextColumn();

                        bool selected = false;
                        string eventType = "";
                        string module = "";
                        switch (TLevent.TimelineEventType)
                        {
                            case eTimelineEvent.ProcessStart:
                            case eTimelineEvent.ProcessEnd:
                                eventType = "Process";

                                if (selectedNode != null)
                                {
                                    selected = (Equals(selectedNode.reference.GetType(), typeof(TraceRecord)) && TLevent.ID == ((TraceRecord)selectedNode.reference).PID);
                                }

                                break;
                            case eTimelineEvent.ThreadStart:
                            case eTimelineEvent.ThreadEnd:
                                eventType = "Thread";
                                if (selectedNode != null)
                                {
                                    selected = (Equals(selectedNode.reference.GetType(), typeof(ProtoGraph)) && TLevent.ID == ((ProtoGraph)selectedNode.reference).ThreadID);
                                }
                                break;
                            case eTimelineEvent.APICall:
                                {
                                    Logging.APICALL call = (Logging.APICALL)(TLevent.Item);
                                    selected = TLevent == SelectedAPIEvent;

                                    if (call.node.IsExternal)
                                    {
                                        eventType = "API - " + call.APIType();
                                        module = Path.GetFileNameWithoutExtension(activeTrace.DisassemblyData.GetModulePath(call.node.GlobalModuleID));

                                        //api call is selected if it is either directly activated, or interacts with a reference to the active entity
                                        //eg: if the file.txt node is selected, writefile to the relevant handle will also be selected
                                        selected = selected || (SelectedEntity != null && SelectedEntity == chart.GetInteractedEntity(TLevent));
                                        if (!selected && selectedNode != null)
                                        {
                                            //select all apis called by selected thread node
                                            selected = selected || (Equals(selectedNode.reference.GetType(), typeof(ProtoGraph)) && call.graph.ThreadID == ((ProtoGraph)selectedNode.reference).ThreadID);
                                            //select all apis called by selected process node
                                            selected = selected || (Equals(selectedNode.reference.GetType(), typeof(TraceRecord)) && call.graph.TraceData.PID == ((TraceRecord)selectedNode.reference).PID);
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
                        ImGui.TableNextColumn();
                        ImGui.Text(eventType);
                        ImGui.TableNextColumn();
                        ImGui.Text(module);
                        ImGui.TableNextColumn();

                        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(3, 3));

                        var labelComponents = TLevent.Label();
                        for (var labeli = 0; labeli < labelComponents.Count; labeli++)
                        {
                            var component = labelComponents[labeli];
                            ImGui.TextColored(component.Item2.ToVec4(), component.Item1);
                            if (labeli < labelComponents.Count - 1)
                                ImGui.SameLine();
                        }
                        ImGui.PopStyleVar();
                    }
                    ImGui.EndTable();

                }


                ImGui.TableNextColumn();
                ImGui.Text("Sandbox View");

                chart.Draw();

                ImGui.TableNextColumn();
                float tr_height = (height / 2) - 4;
                float tb_height = (height / 2) - 4;
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x5f88705f);
                if (ImGui.BeginChild("#SandboxTabtopRightPane", new Vector2(sidePaneWidth, tr_height)))
                {
                    ImGui.Text("Filters");

                    if (!WinAPIDetails.Loaded)
                    {
                        ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                        if (ImGui.BeginChild("#LoadErrFrame", new Vector2(ImGui.GetContentRegionAvail().X - 2, 80)))
                        {
                            ImGui.Indent(5);
                            ImGui.TextWrapped("Error - No API datafile was loaded");
                            ImGui.TextWrapped("See error details in the logs tab");
                            ImGui.EndChild();
                        }
                        ImGui.PopStyleColor();
                    }

                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();

                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x8f48009f);
                if (ImGui.BeginChild("#SandboxTabbaseRightPane", new Vector2(sidePaneWidth, tb_height)))
                {

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
                        if (chart.SelectedAPIEvent != null)
                        {

                            DrawAPIInfoTable(chart.SelectedAPIEvent);
                        }
                    }
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();

                ImGui.EndTable();
            }

            ImGui.EndTabItem();
        }

        void DrawProcessNodeTable(TraceRecord trace)
        {
            if (ImGui.BeginTable("#ProcSelTl", 2))
            {
                ImGui.TableSetupColumn("#Field", ImGuiTableColumnFlags.WidthFixed, 80);

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Process ID");
                ImGui.TableNextColumn();
                ImGui.Text($"{trace.PID}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Path");
                ImGui.TableNextColumn();
                ImGui.TextWrapped($"{trace.binaryTarg.FilePath}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"State");
                ImGui.TableNextColumn();
                ImGui.Text($"{trace.TraceState}");
                ImGui.TableNextColumn();

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Started");
                ImGui.TableNextColumn();
                ImGui.Text($"{trace.launchedTime.ToLocalTime()}");
                ImGui.EndTable();
            }
        }


        void DrawThreadNodeTable(ProtoGraph thread)
        {
            if (ImGui.BeginTable("#ThreadSelTl", 2))
            {
                ImGui.TableSetupColumn("#Field", ImGuiTableColumnFlags.WidthFixed, 80);

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Thread ID");
                ImGui.TableNextColumn();
                ImGui.Text($"{thread.ThreadID}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Started");
                ImGui.TableNextColumn();
                ImGui.Text($"{thread.ConstructedTime}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Terminated");
                ImGui.TableNextColumn();
                ImGui.Text($"{thread.Terminated}");
                ImGui.TableNextColumn();

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Instructions");
                ImGui.TableNextColumn();
                ImGui.Text($"{thread.TotalInstructions}");

                ImGui.EndTable();
            }
        }

        public void DrawAPIInfoTable(TIMELINE_EVENT evt)
        {
            if (ImGui.BeginTable("#ThreadSelTl", 2))
            {
                Logging.APICALL call = (Logging.APICALL)evt.Item;

                ImGui.TableSetupColumn("#Field", ImGuiTableColumnFlags.WidthFixed, 80);

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Thread ID");
                ImGui.TableNextColumn();
                ImGui.Text($"{call.graph.ThreadID}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Library");
                ImGui.TableNextColumn();
                ImGui.TextWrapped($"{call.graph.TraceData.DisassemblyData.GetModulePath(call.node.GlobalModuleID)}");

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"Symbol");
                ImGui.TableNextColumn();
                if (call.APIDetails.HasValue)
                {
                    ImGui.TextWrapped($"{call.APIDetails.Value.Symbol}");
                }
                else
                {
                    call.graph.TraceData.DisassemblyData.GetSymbol(call.node.GlobalModuleID, call.node.address, out string symbol);
                    ImGui.TextWrapped(symbol);
                }
                ImGui.TableNextColumn();

                if (evt.MetaError != null)
                {
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.TextWrapped($"Processing Error");
                    ImGui.TableNextColumn();
                    ImGui.TextWrapped($"{evt.MetaError}");
                }
                ImGui.EndTable();
            }
        }



    }
}