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

        class ThreadHighlightSettings
        {
            public Dictionary<int, moduleEntry> displayedModules = new Dictionary<int, moduleEntry>();
            public int LastExternNodeCount = 0;

            public List<symbolInfo> SelectedSymbols = new List<symbolInfo>();

            public int selectedHighlightTab = 0;
            public string SymFilterText = "";
        }

        Dictionary<PlottedGraph, ThreadHighlightSettings> graphSettings = new Dictionary<PlottedGraph, ThreadHighlightSettings>();
        PlottedGraph ActiveGraph = null;
        ThreadHighlightSettings settings = null;

        private void RefreshExternHighlightData(uint[] externNodes)
        {
            ProtoGraph protog = ActiveGraph?.internalProtoGraph;
            ProcessRecord processrec = protog?.ProcessData;

            if (processrec == null) return;

            foreach (uint nodeIdx in externNodes)
            {
                NodeData n = protog.safe_get_node(nodeIdx);

                if (!settings.displayedModules.TryGetValue(n.GlobalModuleID, out moduleEntry modentry))
                {
                    modentry = new moduleEntry();
                    modentry.symbols = new Dictionary<ulong, symbolInfo>();
                    modentry.path = processrec.GetModulePath(n.GlobalModuleID);
                    settings.displayedModules.Add(n.GlobalModuleID, modentry);
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
                    symentry.threadNodes = new List<uint>() { n.index}; 

                    modentry.symbols.Add(n.address, symentry);
                }
                else
                {
                    if(!symentry.threadNodes.Contains(n.index)) symentry.threadNodes.Add(n.index);
                }

            }
            settings.LastExternNodeCount = externNodes.Length;
        }


        private void DrawSymbolsSelectBox()
        {
            if (ActiveGraph == null) return;
            ProtoGraph protog = ActiveGraph.internalProtoGraph;
            ProcessRecord processrec = protog.ProcessData;

            


            if (settings.LastExternNodeCount < protog.ExternalNodesCount)
            { 
                RefreshExternHighlightData(protog.copyExternalNodeList());
            }

            ImGui.Text("Filter");
            ImGui.SameLine();
            if(ImGui.InputText("##SymFilter", ref settings.SymFilterText, 255))
            {
                
            }
            ImGui.SameLine();
            if (ImGui.Button("x"))
            {
                settings.SymFilterText = "";
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
                    ImGui.SameLine(450);
                    ImGui.Text("Unique Nodes");
                    ImGui.EndChild();
                }
                ImGui.PopStyleColor();
                string LowerFilterText = settings.SymFilterText.ToLower();
                foreach (moduleEntry module_modentry in settings.displayedModules.Values)
                {
                    var keyslist = module_modentry.symbols.Keys.ToArray();
                    bool hasFilterMatches = false;
                    bool moduleMatchesFilter = false;
                    if (settings.SymFilterText.Length == 0)
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

                            if (settings.SymFilterText.Length > 0 && 
                                !moduleMatchesFilter &&
                                !syminfo.name.ToLower().Contains(settings.SymFilterText.ToLower()) 
                                )
                                continue;

                            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 75);
                            if (ImGui.Selectable($"{syminfo.name}", syminfo.selected))
                            {
                                syminfo.selected = !syminfo.selected;
                                module_modentry.symbols[symaddr] = syminfo;
                                if (syminfo.selected)
                                {
                                    List<uint> SelectedSymbolNodes = ActiveGraph.HighlightedSymbolNodes.ToList();
                                    SelectedSymbolNodes.AddRange(syminfo.threadNodes.Where(n => !SelectedSymbolNodes.Contains(n)));
                                    settings.SelectedSymbols.Add(syminfo);
                                    ActiveGraph.HighlightedSymbolNodes = SelectedSymbolNodes;
                                }
                                else
                                {
                                    List<uint> SelectedSymbolNodes = ActiveGraph.HighlightedSymbolNodes.ToList();
                                    SelectedSymbolNodes = SelectedSymbolNodes.Where(n => !syminfo.threadNodes.Contains(n)).ToList();
                                    settings.SelectedSymbols = settings.SelectedSymbols.Where(s => s.address != syminfo.address).ToList();
                                    ActiveGraph.HighlightedSymbolNodes = SelectedSymbolNodes;
                                }

                            }
                            ImGui.SameLine(300);
                            ImGui.Text($"0x{syminfo.address:X}");
                            ImGui.SameLine(450);
                            ImGui.Text($"{syminfo.threadNodes.Count}");
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
            if (settings.selectedHighlightTab == 0)
            {
                if (ImGui.BeginChildFrame(ImGui.GetID("highlightSymsControls"), new Vector2(ImGui.GetContentRegionAvail().X, 40)))
                {
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"{settings.SelectedSymbols.Count} highlighted symbols ({ActiveGraph.HighlightedSymbolNodes.Count}) nodes");
                    ImGui.SameLine();
                    ImGui.Dummy(new Vector2(6, 10));
                    ImGui.SameLine();
                    if (ImGui.Button("Clear"))
                    {
                        foreach (var sym in settings.SelectedSymbols)
                        {
                            symbolInfo symdat = settings.displayedModules[sym.moduleID].symbols[sym.address];
                            symdat.selected = false;
                            settings.displayedModules[sym.moduleID].symbols[sym.address] = symdat;
                        }

                        ActiveGraph.HighlightedSymbolNodes.Clear();
                        settings.SelectedSymbols.Clear();
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
            PlottedGraph LatestActiveGraph = _rgatstate.ActiveGraph;
            if (LatestActiveGraph == null) return;
            if (ActiveGraph != LatestActiveGraph)
            {
                ActiveGraph = LatestActiveGraph;
                if (!graphSettings.TryGetValue(ActiveGraph, out settings))
                {
                    settings = new ThreadHighlightSettings();
                    graphSettings.Add(ActiveGraph, settings);
                }
            }

            if (ImGui.BeginChild(ImGui.GetID("highlightControls"), new Vector2(600, 360)))
            {
                ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;
                if (ImGui.BeginTabBar("Highlights Tab Bar", tab_bar_flags))
                {
                    if (ImGui.BeginTabItem("Externals/Symbols"))
                    {
                        settings.selectedHighlightTab = 0;
                        DrawSymbolsSelectBox();
                        DrawSymbolsSelectControls();
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Addresses"))
                    {
                        settings.selectedHighlightTab = 1;
                        ImGui.Text("s");
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Exceptions"))
                    {
                        settings.selectedHighlightTab = 2;
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
