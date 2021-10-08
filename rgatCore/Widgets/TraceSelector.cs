﻿using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace rgat.Widgets
{
    /// <summary>
    /// Double dropdown for selecting traces/graphs in the active target
    /// </summary>
    public class TraceSelector
    {
        /// <summary>
        /// Draw a trace selector
        /// </summary>
        /// <param name="trace">Parent trace</param>
        /// <returns>Selected graph or null</returns>
        public static PlottedGraph? Draw(TraceRecord? trace)
        {
            if (trace is null)
            {
                if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(ImGui.GetContentRegionAvail().X - 4, 52)))
                {
                    ImGui.Text($"No selected trace");
                    ImGui.EndChild();
                }
                return null;
            }

            PlottedGraph? selectedGraph = null;
            if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(ImGui.GetContentRegionAvail().X - 4, 52)))
            {
                ImGui.PushStyleVar(ImGuiStyleVar.CellPadding, new Vector2(1, 1));
                if (ImGui.BeginTable("#TraceSelectorTable",2))
                {
                    ImGui.TableSetupColumn("#IconsTraceSel", ImGuiTableColumnFlags.WidthFixed, 55);
                    ImGui.TableNextRow();
                    DrawTraceCombo(trace);

                    ImGui.TableNextRow();
                    DrawThreadSelectorCombo(trace, out selectedGraph);
                    ImGui.EndTable();
                }
                ImGui.PopStyleVar();
                ImGui.EndChild();
            }

            if (selectedGraph is not null)
                rgatState.SetActiveGraph(selectedGraph);
            return selectedGraph;
        }

        private static void DrawTraceCombo(TraceRecord trace)
        {
            ImGui.TableNextColumn();
            var tracelist = trace.Target.GetTracesUIList();
            string selString = "PID " + trace.PID;
            ImGui.AlignTextToFramePadding();
            ImGuiUtils.DrawHorizCenteredText($"{tracelist.Length}x {ImGuiController.FA_ICON_COGS}");
            SmallWidgets.MouseoverText($"This target binary has {tracelist.Length} loaded trace{(tracelist.Length != 1 ? 's' : "")} associated with it");

            ImGui.TableNextColumn();
            ImGui.SetNextItemWidth(ImGui.GetContentRegionAvail().X);
            if (ImGui.BeginCombo("##ProcessTraceCombo", selString))
            {
                foreach (var selectableTrace in tracelist)
                {
                    bool current = trace.PID == selectableTrace.PID && trace.randID == selectableTrace.randID;
                    string label = "PID " + selectableTrace.PID;
                    if (current is false)
                    {
                        label = "Parent: " + label + $" ({selectableTrace.Target.FileName})";
                    }
                    if (ImGui.Selectable(label, current))
                    {
                        rgatState.SelectActiveTrace(selectableTrace);
                    }
                    if (selectableTrace.Children.Length > 0)
                    {
                        CreateTracesDropdown(selectableTrace, 1);
                    }
                }
                ImGui.EndCombo();
            }
        }


        private static void CreateTracesDropdown(TraceRecord tr, int level)
        {
            foreach (TraceRecord child in tr.Children)
            {
                string tabs = new string("->");
                string moduleName = child.Target.FileName;
                if (ImGui.Selectable($"{tabs} Child {child.PID} ({moduleName})", rgatState.ActiveGraph?.PID == child.PID))
                {
                    rgatState.SelectActiveTrace(child);
                }
                if (child.Children.Length > 0)
                {
                    CreateTracesDropdown(tr, level + 1);
                }
            }
        }


        private static void DrawThreadSelectorCombo(TraceRecord? trace, out PlottedGraph? selectedGraph)
        {
            selectedGraph = null;
            ProtoGraph? graph = rgatState.ActiveGraph?.InternalProtoGraph;
            if (trace is not null && graph is not null)
            {
                ImGui.TableNextColumn();
                string selString = $"TID {graph.ThreadID}: {graph.FirstInstrumentedModuleName}";
                List<PlottedGraph> graphs = trace.GetPlottedGraphs();
                ImGuiUtils.DrawHorizCenteredText($"{graphs.Count}x {ImGuiController.FA_ICON_COG}");
                SmallWidgets.MouseoverText($"This trace has {graphs.Count} thread{(graphs.Count != 1 ? 's' : "")} with instrumented trace data");

                ImGui.TableNextColumn();
                ImGui.SetNextItemWidth(ImGui.GetContentRegionAvail().X);
                if (ImGui.BeginCombo("##SelectorThreadCombo", selString))
                {
                    foreach (PlottedGraph selectablegraph in graphs)
                    {
                        string caption = $"{selectablegraph.TID}: {selectablegraph.InternalProtoGraph.FirstInstrumentedModuleName}";
                        int nodeCount = selectablegraph.GraphNodeCount();
                        if (nodeCount == 0)
                        {
                            ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.TextDisabled));
                            caption += " [Uninstrumented]";
                        }
                        else
                        {
                            ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                            caption += $" [{nodeCount} nodes]";
                        }

                        if (ImGui.Selectable(caption, graph.ThreadID == selectablegraph.TID) && nodeCount > 0)
                        {
                            selectedGraph = selectablegraph;
                        }
                        if (ImGui.IsItemHovered())
                        {
                            ImGui.BeginTooltip();
                            ImGui.Text($"Thread Start: 0x{selectablegraph.InternalProtoGraph.StartAddress:X} [{selectablegraph.InternalProtoGraph.StartModuleName}]");
                            if (selectablegraph.InternalProtoGraph.NodeList.Count > 0)
                            {
                                NodeData? n = selectablegraph.InternalProtoGraph.GetNode(0);
                                if (n is not null)
                                {
                                    string insBase = System.IO.Path.GetFileName(graph.ProcessData.GetModulePath(n.GlobalModuleID));
                                    ImGui.Text($"First Instrumented: 0x{n.address:X} [{insBase}]");
                                }
                            }
                            ImGui.EndTooltip();
                        }
                        ImGui.PopStyleColor();
                    }
                    ImGui.EndCombo();
                }
            }
        }

    }
}
