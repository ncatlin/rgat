using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace rgatCore.Widgets
{
    class HighlightDialog
    {
        public HighlightDialog(rgatState rgatstate) => _rgatstate = rgatstate;
        rgatState _rgatstate;

        struct symbolInfo
        {
            public string name;
            public List<uint> threadNodes;
            public ulong address;
            public bool selected;
            public int moduleID;
        };

        struct moduleEntry
        {
            public string path;
            public Dictionary<ulong, symbolInfo> symbols;
        };

        Dictionary<int, moduleEntry> displayedModules = new Dictionary<int, moduleEntry>();
        int LastExternNodeCount = 0;
        List<uint> SelectedSymbolNodes = new List<uint>();
        List<symbolInfo> SelectedSymbols = new List<symbolInfo>();
        List<uint> SelectedAddressNodes = new List<uint>();
        List<uint> SelectedExceptionNodes = new List<uint>();
        int selectedHighlightTab = 0;
        string SymFilterText = "";

        private void RefreshExternHighlightData(uint[] externNodes)
        {
            PlottedGraph ActiveGraph = _rgatstate.ActiveGraph;
            ProtoGraph protog = ActiveGraph?.internalProtoGraph;
            ProcessRecord processrec = protog?.ProcessData;

            if (processrec == null) return;

            foreach (uint nodeIdx in externNodes)
            {
                NodeData n = protog.safe_get_node(nodeIdx);

                if (!displayedModules.TryGetValue(n.GlobalModuleID, out moduleEntry modentry))
                {
                    modentry = new moduleEntry();
                    modentry.symbols = new Dictionary<ulong, symbolInfo>();
                    modentry.path = processrec.GetModulePath(n.GlobalModuleID);
                    displayedModules.Add(n.GlobalModuleID, modentry);
                }
                if (!modentry.symbols.TryGetValue(n.address, out symbolInfo symentry))
                {
                    symentry = new symbolInfo();
                    symentry.address = n.address;
                    symentry.selected = false;
                    symentry.moduleID = n.GlobalModuleID;
                    if (!processrec.GetSymbol(n.GlobalModuleID, n.address, out symentry.name))
                    {
                        symentry.name = "[No Symbol Name]";
                    }
                    symentry.threadNodes = new List<uint>();    //todo: set thread nodes

                    modentry.symbols.Add(n.address, symentry);
                }
                else
                {
                    //todo: update thread nodes
                }

            }
            LastExternNodeCount = externNodes.Length;
        }


        private void DrawSymbolsSelectBox()
        {
            PlottedGraph ActiveGraph = _rgatstate.ActiveGraph;
            ProtoGraph protog = ActiveGraph?.internalProtoGraph;
            ProcessRecord processrec = protog?.ProcessData;

            if (processrec == null) return;

            var externNodes = protog.copyExternalNodeList();
            if (LastExternNodeCount < protog.ExternalNodesCount)
            {
                RefreshExternHighlightData(externNodes);
            }

            ImGui.Text("Filter");
            ImGui.SameLine();
            if(ImGui.InputText("##SymFilter", ref SymFilterText, 255))
            {
                
            }
            ImGui.SameLine();
            if (ImGui.Button("x"))
            {
                SymFilterText = "";
            }
            ImGui.PushStyleColor(ImGuiCol.Text, 0xFF000000);
            ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xFFFFFFFF);
            if (ImGui.BeginChildFrame(ImGui.GetID("highlightSymsFrame"), new Vector2(ImGui.GetContentRegionAvail().X, 260)))
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xfff7f7f7);
                if (ImGui.BeginChild(ImGui.GetID("highlightSymsFrame2"), new Vector2(ImGui.GetContentRegionAvail().X, 20)))
                {
                    ImGui.SameLine(100);
                    ImGui.Text("Symbol");
                    ImGui.SameLine(300);
                    ImGui.Text("Address");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                string LowerFilterText = SymFilterText.ToLower();
                foreach (moduleEntry module_modentry in displayedModules.Values)
                {
                    var keyslist = module_modentry.symbols.Keys.ToArray();
                    bool hasFilterMatches = false;
                    bool moduleMatchesFilter = false;
                    if (SymFilterText.Length == 0)
                    {
                        hasFilterMatches = true;
                    }
                    else if (module_modentry.path.ToLower().Contains(LowerFilterText))
                    {
                        moduleMatchesFilter = true;
                        hasFilterMatches = true;
                    }
                    else
                    {
                        foreach (ulong symaddr in keyslist)
                        {
                            symbolInfo syminfo = module_modentry.symbols[symaddr];
                            if (syminfo.name.ToLower().Contains(LowerFilterText))
                            { 
                                hasFilterMatches = true;
                                break;
                            }
                        }
                    }
                    

                    if (hasFilterMatches && ImGui.TreeNode($"{module_modentry.path}"))
                    {
                        foreach (ulong symaddr in keyslist)
                        {
                            symbolInfo syminfo = module_modentry.symbols[symaddr];

                            if (SymFilterText.Length > 0 && 
                                !moduleMatchesFilter &&
                                !syminfo.name.ToLower().Contains(SymFilterText.ToLower()) 
                                )
                                continue;

                            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 75);
                            if (ImGui.Selectable($"{syminfo.name}", syminfo.selected))
                            {
                                syminfo.selected = !syminfo.selected;
                                module_modentry.symbols[symaddr] = syminfo;
                                if (syminfo.selected)
                                {
                                    if (!SelectedSymbolNodes.Contains(22))
                                    {
                                        SelectedSymbolNodes.Add(44); //todo symbol nodes
                                    }
                                    SelectedSymbols.Add(syminfo);
                                }
                                else
                                {
                                    SelectedSymbols = SelectedSymbols.Where(s => s.address != syminfo.address).ToList();
                                }
                            }
                            ImGui.SameLine(300);
                            ImGui.Text($"0x{syminfo.address:X}");
                        }
                        ImGui.TreePop();
                    }
                    //NodeData n = protog.safe_get_node(nodeIdx);
                    //DisplayModuleHighlightTreeNode(processrec, n.GlobalModuleID);
                }
                ImGui.EndChildFrame();
            }
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();
        }

        private void DrawSymbolsSelectControls()
        {
            if (selectedHighlightTab == 0)
            {
                if (ImGui.BeginChildFrame(ImGui.GetID("highlightSymsControls"), new Vector2(ImGui.GetContentRegionAvail().X, 40)))
                {
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"{SelectedSymbols.Count} highlighted symbols ({SelectedSymbolNodes.Count}) nodes");
                    ImGui.SameLine();
                    ImGui.Dummy(new Vector2(6, 10));
                    ImGui.SameLine();
                    if (ImGui.Button("Clear"))
                    {
                        foreach (var sym in SelectedSymbols)
                        {
                            symbolInfo symdat = displayedModules[sym.moduleID].symbols[sym.address];
                            symdat.selected = false;
                            displayedModules[sym.moduleID].symbols[sym.address] = symdat;
                        }
                        SelectedSymbolNodes.Clear();
                        SelectedSymbols.Clear();
                    }

                    ImGui.SameLine(ImGui.GetContentRegionAvail().X - 95);
                    ImGui.PushStyleColor(ImGuiCol.Button, 0xFF000000);
                    ImGui.PushStyleColor(ImGuiCol.Text, 0xFF0000ff);
                    if (ImGui.Button("Highlight Colour"))
                    {
                        //todo: higlight colour picker
                    }
                    ImGui.PopStyleColor();
                    ImGui.PopStyleColor();


                    ImGui.EndChildFrame();
                }
            }
        }


        public void Draw()
        {
            if (ImGui.BeginChild(ImGui.GetID("highlightControls"), new Vector2(600, 360)))
            {
                ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;
                if (ImGui.BeginTabBar("Highlights Tab Bar", tab_bar_flags))
                {
                    if (ImGui.BeginTabItem("Externals/Symbols"))
                    {
                        selectedHighlightTab = 0;
                        DrawSymbolsSelectBox();
                        DrawSymbolsSelectControls();
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Addresses"))
                    {
                        selectedHighlightTab = 1;
                        ImGui.Text("s");
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Exceptions"))
                    {
                        selectedHighlightTab = 2;
                        ImGui.Text("s");

                        ImGui.EndTabItem();
                    }
                    ImGui.EndTabBar();
                }

                ImGui.EndChild();
            }
        }
    }
}
