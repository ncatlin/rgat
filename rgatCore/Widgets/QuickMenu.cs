using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace rgatCore.Widgets
{
    class QuickMenu
    {
        Vector2 _size;
        public QuickMenu(Vector2 size)
        {
            _size = size;
        }

        public void Draw(PlottedGraph activeGraph)
        {
            if (ImGui.BeginChildFrame(ImGui.GetID("QuickMenuMainFrame"), _size))
            {
                
                ImGui.Selectable("l1"); ImGui.SameLine();
                ImGui.Selectable("l2"); ImGui.SameLine();
                ImGui.Selectable("l3"); ImGui.SameLine();
                ImGui.Selectable("l4"); ImGui.SameLine();
                ImGui.Selectable("l5"); ImGui.SameLine();
                
                if (ImGui.BeginChild(ImGui.GetID("QuickMenuVisibility")))
                {
                    DrawMainFrame(activeGraph);
                    ImGui.EndChild();
                }

                ImGui.EndChildFrame();
            }
        }

        static void DrawMainFrame(PlottedGraph activeGraph)
        {
            ImGui.Text("Show Edges");
            ImGui.SameLine();
            if (SmallWidgets.ToggleButton("edgesToggle", activeGraph.EdgesVisible))
                activeGraph.EdgesVisible = !activeGraph.EdgesVisible;
            ImGui.Text("Show Nodes");
            ImGui.SameLine();
            if (SmallWidgets.ToggleButton("nodes", activeGraph.NodesVisible))
                activeGraph.NodesVisible = !activeGraph.NodesVisible;
            ImGui.Text("Enable Text");
            ImGui.SameLine();
            if (SmallWidgets.ToggleButton("textenable", activeGraph.TextEnabled))
                activeGraph.TextEnabled = !activeGraph.TextEnabled;
            ImGui.Text("Instruction Text");
            ImGui.SameLine();
            if (SmallWidgets.ToggleButton("textenable_ins", activeGraph.TextEnabledIns))
                activeGraph.TextEnabledIns = !activeGraph.TextEnabledIns;
        }
    }
}
