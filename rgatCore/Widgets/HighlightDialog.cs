﻿using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;

namespace rgatCore.Widgets
{
    class HighlightDialog
    {
        public HighlightDialog() { }

        struct symbolInfo
        {
            public string name;
            public List<uint> threadNodes;
            public ulong address;
            public bool selected;
            public bool hovered;
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

            public List<ulong> SelectedAddresses = new List<ulong>();
            public string AddrEntryText = "";

            public List<uint> SelectedExceptionNodes = new List<uint>();
        }

        Dictionary<PlottedGraph, ThreadHighlightSettings> graphSettings = new Dictionary<PlottedGraph, ThreadHighlightSettings>();
        PlottedGraph _ActiveGraph = null;
        ThreadHighlightSettings _activeHighlights = null;
        public static Vector2 InitialSize = new Vector2(600, 400);

        private void RefreshExternHighlightData(uint[] externNodes)
        {
            ProtoGraph protog = _ActiveGraph?.internalProtoGraph;
            ProcessRecord processrec = protog?.ProcessData;

            if (processrec == null) return;

            foreach (uint nodeIdx in externNodes)
            {
                NodeData n = protog.safe_get_node(nodeIdx);

                if (!_activeHighlights.displayedModules.TryGetValue(n.GlobalModuleID, out moduleEntry modentry))
                {
                    modentry = new moduleEntry();
                    modentry.symbols = new Dictionary<ulong, symbolInfo>();
                    modentry.path = processrec.GetModulePath(n.GlobalModuleID);
                    _activeHighlights.displayedModules.Add(n.GlobalModuleID, modentry);
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
                    symentry.threadNodes = new List<uint>() { n.index };

                    modentry.symbols.Add(n.address, symentry);
                }
                else
                {
                    if (!symentry.threadNodes.Contains(n.index)) symentry.threadNodes.Add(n.index);
                }

            }
            _activeHighlights.LastExternNodeCount = externNodes.Length;
        }

        private void HandleSelectedSym(moduleEntry module_modentry, symbolInfo syminfo)
        {
            syminfo.selected = !syminfo.selected;
            module_modentry.symbols[syminfo.address] = syminfo;
            if (syminfo.selected)
            {
                _ActiveGraph.AddHighlightedNodes(syminfo.threadNodes, eHighlightType.eExternals);
                _activeHighlights.SelectedSymbols.Add(syminfo);

            }
            else
            {
                _ActiveGraph.RemoveHighlightedNodes(syminfo.threadNodes, eHighlightType.eExternals);
                _activeHighlights.SelectedSymbols = _activeHighlights.SelectedSymbols.Where(s => s.address != syminfo.address).ToList();

            }
        }


        private void HandleMouseoverSym(moduleEntry module_modentry, symbolInfo syminfo)
        {
            module_modentry.symbols[syminfo.address] = syminfo;
            if (syminfo.hovered)
            {
                _ActiveGraph.AddHighlightedNodes(syminfo.threadNodes, eHighlightType.eExternals);
            }
            else
            {
                _ActiveGraph.RemoveHighlightedNodes(syminfo.threadNodes, eHighlightType.eExternals);
            }

        }



        private void DrawModSymTreeNodes()
        {
            string LowerFilterText = _activeHighlights.SymFilterText.ToLower();
            foreach (moduleEntry module_modentry in _activeHighlights.displayedModules.Values)
            {
                var keyslist = module_modentry.symbols.Keys.ToArray();
                bool hasFilterMatches = false;
                bool moduleMatchesFilter = false;
                if (_activeHighlights.SymFilterText.Length == 0)
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

                if (hasFilterMatches)
                {
                    if (ImGui.TreeNode($"{module_modentry.path}"))
                    {
                        float cursX = ImGui.GetCursorPosX() + 75;
                        foreach (ulong symaddr in keyslist)
                        {
                            symbolInfo syminfo = module_modentry.symbols[symaddr];

                            if (_activeHighlights.SymFilterText.Length > 0 &&
                                !moduleMatchesFilter &&
                                !syminfo.name.ToLower().Contains(_activeHighlights.SymFilterText.ToLower())
                                )
                            {
                                continue;
                            }

                            ImGui.SetCursorPosX(cursX);
                            ImGui.BeginGroup();
                            if (ImGui.Selectable($"{syminfo.name}", syminfo.selected))
                            {
                                HandleSelectedSym(module_modentry, syminfo);
                            }
                            ImGui.SameLine(300);
                            ImGui.Text($"0x{syminfo.address:X}");
                            ImGui.SameLine(450);
                            ImGui.Text($"{syminfo.threadNodes.Count}");
                            ImGui.EndGroup();

                            if (!syminfo.selected)
                            {
                                if (ImGui.IsItemHovered(ImGuiHoveredFlags.None))
                                {
                                    Console.WriteLine($"hoverred {syminfo.name}");
                                    if (syminfo.hovered == false)
                                    {
                                        syminfo.hovered = true;
                                        HandleMouseoverSym(module_modentry, syminfo);
                                    }
                                }
                                else
                                {
                                    if (syminfo.hovered == true)
                                    {
                                        syminfo.hovered = false;
                                        HandleMouseoverSym(module_modentry, syminfo);
                                    }
                                }
                            }

                            ImGui.TreePop();
                        }
                    }
                }
            }
        }

        private void DrawSymbolsSelectBox(float height)
        {
            if (_ActiveGraph == null) return;
            if (_activeHighlights.LastExternNodeCount < _ActiveGraph.internalProtoGraph.ExternalNodesCount)
            {
                RefreshExternHighlightData(_ActiveGraph.internalProtoGraph.copyExternalNodeList());
            }

            ImGui.Text("Filter");
            ImGui.SameLine();
            ImGui.InputText("##SymFilter", ref _activeHighlights.SymFilterText, 255);

            ImGui.SameLine();
            if (ImGui.Button("X")) //todo: icon
            {
                _activeHighlights.SymFilterText = "";
            }

            ImGui.PushStyleColor(ImGuiCol.Text, 0xFF000000);

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xfff7f7f7);
            if (ImGui.BeginChild(ImGui.GetID("htSymsFrameHeader"), new Vector2(ImGui.GetContentRegionAvail().X, 20)))
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

            ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xffffffff);
            if (ImGui.BeginChild("htSymsFrame", new Vector2(ImGui.GetContentRegionAvail().X, height - 80)))
            {
                DrawModSymTreeNodes();
                ImGui.EndChild();
            }
            ImGui.PopStyleColor();

            ImGui.PopStyleColor();
        }

        private void DrawSymbolsSelectControls(float height)
        {
            if (_activeHighlights.selectedHighlightTab == 0)
            {
                if (ImGui.BeginChild(ImGui.GetID("highlightSymsControls"), new Vector2(ImGui.GetContentRegionAvail().X, height - 10)))
                {
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"{_activeHighlights.SelectedSymbols.Count} highlighted symbols ({_ActiveGraph.HighlightedSymbolNodes.Count} nodes)");
                    ImGui.SameLine();
                    ImGui.Dummy(new Vector2(6, 10));
                    ImGui.SameLine();
                    if (ImGui.Button("Clear"))
                    {
                        foreach (var sym in _activeHighlights.SelectedSymbols)
                        {
                            symbolInfo symdat = _activeHighlights.displayedModules[sym.moduleID].symbols[sym.address];
                            symdat.selected = false;
                            _activeHighlights.displayedModules[sym.moduleID].symbols[sym.address] = symdat;
                        }

                        _ActiveGraph.RemoveHighlightedNodes(_ActiveGraph.HighlightedSymbolNodes, eHighlightType.eExternals);
                        _activeHighlights.SelectedSymbols.Clear();
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


                    ImGui.EndChild();
                }
            }
        }

        static int selitem = 0;
        public void DrawAddressSelectBox(float height)
        {
            ImGui.ListBox("##AddrListbox", ref selitem,
                _activeHighlights.SelectedAddresses.Select(ad => $"0x{ad:X}").ToArray(),
                _activeHighlights.SelectedAddresses.Count);

        }

        public void DrawAddressSelectControls()
        {
            ImGui.Text("Address");
            ImGui.InputText("##AddressInput", ref _activeHighlights.AddrEntryText, 255);
            ImGui.SameLine();

            if (ImGui.Button("Add") ||
                ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.Enter)) ||
                ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.KeyPadEnter)))
            {
                string addrstring = _activeHighlights.AddrEntryText;
                if (addrstring.ToLower().StartsWith("0x")) addrstring = addrstring.Substring(2);
                bool success = ulong.TryParse(addrstring, NumberStyles.AllowHexSpecifier, CultureInfo.CurrentCulture, out ulong hexAddr);
                if (!success)
                    success = ulong.TryParse(addrstring, NumberStyles.Integer, CultureInfo.CurrentCulture, out hexAddr);
                if (success)
                {
                    _activeHighlights.AddrEntryText = "";
                    if (!_activeHighlights.SelectedAddresses.Contains(hexAddr))
                    {

                        _ActiveGraph.AddHighlightedAddress(hexAddr);
                        _activeHighlights.SelectedAddresses.Add(hexAddr);
                    }
                }
            }
        }


        public void DrawExceptionSelectBox(float height)
        {
            uint[] exceptionNodes = _ActiveGraph.internalProtoGraph.GetExceptionNodes();
            if (exceptionNodes.Length == 0)
            {
                string caption = $"No exceptions recorded in thread ID {_ActiveGraph.tid}";
                ImGui.SetCursorPosX(ImGui.GetContentRegionAvail().X / 2 - ImGui.CalcTextSize(caption).X / 2);
                ImGui.SetCursorPosY(ImGui.GetContentRegionAvail().Y / 2 - ImGui.CalcTextSize(caption).Y / 2);
                ImGui.Text(caption);
                return;
            }

            if (ImGui.ListBoxHeader("##ExceptionsListbox"))
            {
                foreach (uint nodeidx in exceptionNodes)
                {
                    if (ImGui.Selectable($"{nodeidx}", _activeHighlights.SelectedExceptionNodes.Contains(nodeidx)))
                    {
                        if (_activeHighlights.SelectedExceptionNodes.Contains(nodeidx))
                        {
                            _activeHighlights.SelectedExceptionNodes.Remove(nodeidx);
                            _ActiveGraph.RemoveHighlightedNodes(new List<uint> { nodeidx }, eHighlightType.eExceptions);
                        }
                        else
                        {
                            _activeHighlights.SelectedExceptionNodes.Add(nodeidx);
                            _ActiveGraph.AddHighlightedNodes(new List<uint> { nodeidx }, eHighlightType.eExceptions);
                        }

                    }
                }
            }
            ImGui.ListBoxFooter();
        }

        public void DrawExceptionSelectControls()
        {

        }

        public void Draw(PlottedGraph LatestActiveGraph)
        {
            if (LatestActiveGraph == null) return;
            if (_ActiveGraph != LatestActiveGraph)
            {
                _ActiveGraph = LatestActiveGraph;
                if (!graphSettings.TryGetValue(_ActiveGraph, out _activeHighlights))
                {
                    _activeHighlights = new ThreadHighlightSettings();
                    graphSettings.Add(_ActiveGraph, _activeHighlights);
                }
            }

            Vector2 Size = ImGui.GetContentRegionAvail();
            if (Size.X < InitialSize.X) Size.X = InitialSize.X;
            if (Size.Y < InitialSize.Y) Size.Y = InitialSize.Y;

            if (ImGui.BeginChildFrame(ImGui.GetID("highlightControls"), Size, ImGuiWindowFlags.AlwaysAutoResize))
            {
                ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;
                if (ImGui.BeginTabBar("Highlights Tab Bar", tab_bar_flags))
                {
                    if (ImGui.BeginTabItem("Externals/Symbols"))
                    {
                        _activeHighlights.selectedHighlightTab = 0;
                        DrawSymbolsSelectBox(Size.Y - 40); //todo: unbadify this height choice
                        DrawSymbolsSelectControls(40);
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Addresses"))
                    {
                        _activeHighlights.selectedHighlightTab = 1;
                        DrawAddressSelectBox(Size.Y - 80);
                        DrawAddressSelectControls();
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Exceptions"))
                    {
                        _activeHighlights.selectedHighlightTab = 2;
                        DrawExceptionSelectBox(Size.Y - 80);
                        DrawExceptionSelectControls();
                        ImGui.EndTabItem();
                    }
                    ImGui.EndTabBar();
                }

                ImGui.EndChildFrame();
            }
        }
    }
}
