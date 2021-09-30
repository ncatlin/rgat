using ImGuiNET;
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
                if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(ImGui.GetContentRegionAvail().X, 52)))
                {
                    ImGui.Text($"No selected trace");
                    ImGui.EndChild();
                }
                return null;
            }

            PlottedGraph? result = null;
            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xFF552120);
            if (ImGui.BeginChild(ImGui.GetID("TraceSelect"), new Vector2(ImGui.GetContentRegionAvail().X - 15, 52)))
            {
                var tracelist = trace.Target.GetTracesUIList();
                string selString = "PID " + trace.PID;
                if (ImGui.BeginCombo($"{tracelist.Count} Process{(tracelist.Count != 1 ? "es" : "")}", selString))
                {
                    foreach (var timepid in tracelist)
                    {
                        TraceRecord selectableTrace = timepid.Item2;
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
                DrawThreadSelectorCombo(trace, out result);


                ImGui.EndChild();
            }
            ImGui.PopStyleColor(1);
            return result;
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
                string selString = $"TID {graph.ThreadID}: {graph.FirstInstrumentedModuleName}";
                List<PlottedGraph> graphs = trace.GetPlottedGraphs();
                if (ImGui.BeginCombo($"{graphs.Count} Thread{(graphs.Count != 1 ? "s" : "")}", selString))
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
                            ImGui.Text($"Thread Start: 0x{graph.StartAddress:X} [{graph.StartModuleName}]");
                            if (graph.NodeList.Count > 0)
                            {
                                NodeData? n = graph.GetNode(0);
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
