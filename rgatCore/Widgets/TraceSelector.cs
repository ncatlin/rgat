using ImGuiNET;
using System.Collections.Generic;
using System.Numerics;

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
        /// <param name="abbreviate">Make the label a bit shorter to fit in the preview pane width</param>
        /// <returns>Selected graph or null</returns>
        public static PlottedGraph? Draw(TraceRecord? trace, bool abbreviate = false)
        {
            if (trace is null)
            {
                if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(ImGui.GetContentRegionAvail().X - 4, ImGui.GetContentRegionAvail().Y)))
                {
                    ImGuiUtils.DrawRegionCenteredText($"No selected trace");
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
                    ImGui.TableSetupColumn("#IconsTraceSel", ImGuiTableColumnFlags.WidthFixed, 35);
                    ImGui.TableNextRow();
                    DrawTraceCombo(trace, abbreviate);

                    ImGui.TableNextRow();
                    DrawThreadSelectorCombo(trace, out selectedGraph, abbreviate);
                    ImGui.EndTable();
                }
                ImGui.PopStyleVar();
                ImGui.EndChild();
            }

            if (selectedGraph is not null)
                rgatState.SetActiveGraph(selectedGraph);
            return selectedGraph;
        }

        private static void DrawTraceCombo(TraceRecord trace, bool abbreviate)
        {
            var tracelist = trace.Target.GetTracesUIList();
            string selString = (abbreviate ? "PID " : "Process ") + trace.PID;
            if (ImGui.TableNextColumn())
            {
                ImGui.AlignTextToFramePadding();
                ImGuiUtils.DrawHorizCenteredText($"{tracelist.Length}x");
                SmallWidgets.MouseoverText($"This target binary has {tracelist.Length} loaded trace{(tracelist.Length != 1 ? 's' : "")} associated with it");
            }

            if (ImGui.TableNextColumn())
            {
                ImGui.SetNextItemWidth(ImGui.GetContentRegionAvail().X - 35);
                if (ImGui.BeginCombo("##ProcessTraceCombo", selString))
                {
                    foreach (var selectableTrace in tracelist)
                    {
                        bool current = trace.PID == selectableTrace.PID && trace.randID == selectableTrace.randID;
                        string label = "PID " + selectableTrace.PID;
                        if (current is false)
                        {
                            //label = "Parent: " + label + $" ({selectableTrace.Target.FileName})";
                            label = label + $" ({selectableTrace.Target.FileName})";
                        }
                        if (selectableTrace.GraphCount == 0)
                        {
                            label = label + "[0 graphs]";
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
                ImGui.SameLine();
                ImGui.Text($"{ImGuiController.FA_ICON_COGS}");
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


        private static void DrawThreadSelectorCombo(TraceRecord? trace, out PlottedGraph? selectedGraph, bool abbreviate)
        {
            selectedGraph = null;
            ProtoGraph? graph = rgatState.ActiveGraph?.InternalProtoGraph;
            if (trace is not null && graph is not null)
            {
                string selString = $"{(abbreviate ? "TID" : "Thread")} {graph.ThreadID}: {graph.FirstInstrumentedModuleName}";
                if (graph.NodeCount == 0)
                    selString += " [Uninstrumented]";
                List<PlottedGraph> graphs = trace.GetPlottedGraphs();
                if (ImGui.TableNextColumn())
                {
                    ImGui.AlignTextToFramePadding();
                    ImGuiUtils.DrawHorizCenteredText($"{graphs.Count}x");
                    SmallWidgets.MouseoverText($"This trace has {graphs.Count} thread{(graphs.Count != 1 ? 's' : "")}");
                }

                if (ImGui.TableNextColumn())
                {
                    ImGui.SetNextItemWidth(ImGui.GetContentRegionAvail().X - 35);
                    if (ImGui.BeginCombo("##SelectorThreadCombo", selString))
                    {
                        foreach (PlottedGraph selectablegraph in graphs)
                        {
                            string caption = $"{selectablegraph.TID}: {selectablegraph.InternalProtoGraph.FirstInstrumentedModuleName}";
                            int nodeCount = selectablegraph.GraphNodeCount();
                            if (nodeCount == 0)
                            {
                                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.Dull1));
                                caption += " [Uninstrumented]";
                            }
                            else
                            {
                                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.WindowText));
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
                                        ImGui.Text($"First Instrumented: 0x{n.Address:X} [{insBase}]");
                                    }
                                }
                                ImGui.EndTooltip();
                            }
                            ImGui.PopStyleColor();
                        }
                        ImGui.EndCombo();
                    }
                    ImGui.SameLine();
                    ImGui.Text($"{ImGuiController.FA_ICON_COG}");
                }
            }
        }

    }
}
