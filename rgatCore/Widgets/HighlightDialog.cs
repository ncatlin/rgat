using ImGuiNET;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Numerics;

namespace rgat.Widgets
{
    internal class HighlightDialog
    {
        public HighlightDialog(Vector2 initialSize)
        {
            _initialSize = initialSize;
        }

        public HighlightDialog()
        {
            _initialSize = new Vector2(600, 300);
        }

        private struct symbolInfo
        {
            public string name;
            public List<uint> threadNodes;
            public ulong address;
            public bool selected;
            public bool hovered;
            public int moduleID;
        };

        private struct moduleEntry
        {
            public string path;
            public Dictionary<ulong, symbolInfo> symbols;
        };

        private class ThreadHighlightSettings
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

        private readonly Dictionary<PlottedGraph, ThreadHighlightSettings> graphSettings = new Dictionary<PlottedGraph, ThreadHighlightSettings>();
        private PlottedGraph? _ActiveGraph = null;
        private ThreadHighlightSettings _activeHighlights = new ThreadHighlightSettings();
        private Vector2 _initialSize = new Vector2(600, 300);

        private void RefreshExternHighlightData(System.ReadOnlySpan<uint> externNodes)
        {
            ProtoGraph? graph = _ActiveGraph?.InternalProtoGraph;
            ProcessRecord? processrec = graph?.ProcessData;

            if (processrec == null || graph is null)
            {
                return;
            }

            foreach (uint nodeIdx in externNodes)
            {
                NodeData? n = graph.GetNode(nodeIdx);
                System.Diagnostics.Debug.Assert(n is not null);
                if (!_activeHighlights.displayedModules.TryGetValue(n.GlobalModuleID, out moduleEntry modentry))
                {
                    modentry = new moduleEntry();
                    modentry.symbols = new Dictionary<ulong, symbolInfo>();
                    modentry.path = processrec.GetModulePath(n.GlobalModuleID);
                    _activeHighlights.displayedModules.Add(n.GlobalModuleID, modentry);
                }
                if (!modentry.symbols.TryGetValue(n.Address, out symbolInfo symentry))
                {
                    symentry = new symbolInfo();
                    symentry.address = n.Address;
                    symentry.selected = false;
                    symentry.moduleID = n.GlobalModuleID;

                    string? foundName;
                    if (processrec.GetSymbol(n.GlobalModuleID, n.Address, out foundName) && foundName is not null)
                    {
                        symentry.name = foundName;
                    }
                    else
                    {
                        symentry.name = "[No Symbol Name]";
                    }
                    symentry.threadNodes = new List<uint>() { n.Index };

                    modentry.symbols.Add(n.Address, symentry);
                }
                else
                {
                    if (!symentry.threadNodes.Contains(n.Index))
                    {
                        symentry.threadNodes.Add(n.Index);
                    }
                }

            }
            _activeHighlights.LastExternNodeCount = externNodes.Length;
        }

        private void HandleSelectedSym(PlottedGraph plot, moduleEntry module_modentry, symbolInfo syminfo)
        {
            syminfo.selected = !syminfo.selected;
            module_modentry.symbols[syminfo.address] = syminfo;

            plot.LayoutState.Lock.EnterUpgradeableReadLock();
            plot.LayoutState.GetAttributes(plot.ActiveLayoutStyle, out float[]? attribsArray);


            if (syminfo.selected)
            {
                plot.AddHighlightedNodes(syminfo.threadNodes, CONSTANTS.HighlightType.Externals);
                _activeHighlights.SelectedSymbols.Add(syminfo);

            }
            else
            {
                plot.RemoveHighlightedNodes(syminfo.threadNodes, CONSTANTS.HighlightType.Externals);
                _activeHighlights.SelectedSymbols = _activeHighlights.SelectedSymbols.Where(s => s.address != syminfo.address).ToList();

            }
            plot.LayoutState.Lock.ExitUpgradeableReadLock();
        }


        private static void HandleMouseoverSym(PlottedGraph plot, moduleEntry module_modentry, symbolInfo syminfo)
        {
            module_modentry.symbols[syminfo.address] = syminfo;
            if (syminfo.hovered)
            {
                plot.AddHighlightedNodes(syminfo.threadNodes, CONSTANTS.HighlightType.Externals);
            }
            else
            {
                plot.RemoveHighlightedNodes(syminfo.threadNodes, CONSTANTS.HighlightType.Externals);
            }

        }

        private Vector4 _activeColorPick1 = new WritableRgbaFloat(Color.Cyan).ToVec4();

        private void DrawModSymTreeNodes(PlottedGraph plot)
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

                            ImGui.SetCursorPosX(10);
                            ImGui.BeginGroup();
                            if (ImGui.Selectable($"{syminfo.name}", syminfo.selected))
                            {
                                HandleSelectedSym(plot, module_modentry, syminfo);
                            }
                            if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
                            {
                                ImGui.OpenPopup("HighlightColorPicker");
                            }
                            if (ImGui.BeginPopup("HighlightColorPicker"))
                            {
                                ImGui.PushStyleColor(ImGuiCol.Text, 0xffffffff);
                                ImGui.Text($"Configuring highlight colour for {syminfo.name} (0x{syminfo.address}:x)");
                                ImGuiColorEditFlags flags = ImGuiColorEditFlags.NoInputs;
                                flags |= ImGuiColorEditFlags.AlphaBar;
                                if (ImGui.ColorPicker4("Highlight Colour", ref _activeColorPick1, flags))
                                {
                                    foreach (uint node in syminfo.threadNodes)
                                    {
                                        plot.SetCustomHighlightColour((int)node, _activeColorPick1);
                                    }
                                }
                                ImGui.Text("Highlight active:");
                                ImGui.SameLine();
                                if (SmallWidgets.ToggleButton("NodeActiveHighlightToggle", syminfo.selected, "Node is highlighted"))
                                {
                                    HandleSelectedSym(plot, module_modentry, syminfo);
                                }
                                ImGui.PopStyleColor();
                                ImGui.EndPopup();
                            }

                            ImGui.SameLine(190);
                            ImGui.Text($"0x{syminfo.address:X}");
                            ImGui.SameLine(305);
                            ImGui.Text($"{syminfo.threadNodes.Count}");
                            ImGui.EndGroup();

                            if (!syminfo.selected)
                            {
                                if (ImGui.IsItemHovered(ImGuiHoveredFlags.None))
                                {
                                    if (syminfo.hovered == false)
                                    {
                                        syminfo.hovered = true;
                                        HandleMouseoverSym(plot, module_modentry, syminfo);
                                    }
                                }
                                else
                                {
                                    if (syminfo.hovered == true)
                                    {
                                        syminfo.hovered = false;
                                        HandleMouseoverSym(plot, module_modentry, syminfo);
                                    }
                                }
                            }
                        }

                        ImGui.TreePop();
                    }
                }
            }
        }

        private void DrawSymbolsSelectBox(float reserveSize)
        {
            PlottedGraph? graph = _ActiveGraph;
            if (graph == null)
            {
                return;
            }

            if (_activeHighlights.LastExternNodeCount < graph.InternalProtoGraph.ExternalNodesCount)
            {
                RefreshExternHighlightData(graph.InternalProtoGraph.copyExternalNodeList());
            }

            ImGui.Text("Filter");
            ImGui.SameLine();
            ImGui.InputText("##SymFilter", ref _activeHighlights.SymFilterText, 255);

            ImGui.SameLine();
            if (ImGui.Button($"{ImGuiController.FA_ICON_TRASHCAN}")) 
            {
                _activeHighlights.SymFilterText = "";
            }

            //ImGui.PushStyleColor(ImGuiCol.Text, 0xFF000000);

            ImGui.PushStyleColor(ImGuiCol.ChildBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eFrame));
            if (ImGui.BeginChild(ImGui.GetID("htSymsFrameHeader"), new Vector2(ImGui.GetContentRegionAvail().X - 3, 20)))
            {
                ImGui.SameLine(10);
                ImGui.Text("Symbol");
                ImGui.SameLine(200);
                ImGui.Text("Address");
                ImGui.SameLine(315);
                ImGui.Text("Unique Nodes");
                ImGui.EndChild();
            }
            //ImGui.PopStyleColor();

            //ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xffffffff);
            if (ImGui.BeginChild("htSymsFrame", new Vector2(ImGui.GetContentRegionAvail().X - 3, ImGui.GetContentRegionAvail().Y - reserveSize)))
            {
                DrawModSymTreeNodes(graph);
                ImGui.EndChild();
            }
            //ImGui.PopStyleColor();

            ImGui.PopStyleColor();
        }


        private void DrawSymbolsSelectControls(PlottedGraph plot)
        {
            float height = 30;
            if (_activeHighlights.selectedHighlightTab == 0)
            {
                if (ImGui.BeginChild(ImGui.GetID("highlightSymsControls"), new Vector2(ImGui.GetContentRegionAvail().X, height)))
                {
                    ImGui.AlignTextToFramePadding();
                    ImGui.Text($"{_activeHighlights.SelectedSymbols.Count} highlighted symbols ({plot.HighlightedSymbolNodes.Count} nodes)");
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

                        plot.LayoutState.Lock.EnterUpgradeableReadLock();
                        plot.RemoveHighlightedNodes(plot.HighlightedSymbolNodes, CONSTANTS.HighlightType.Externals);
                        plot.LayoutState.Lock.ExitUpgradeableReadLock();

                        _activeHighlights.SelectedSymbols.Clear();
                    }

                    /*
                    ImGui.SameLine(ImGui.GetContentRegionAvail().X - 100);
                    ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.GraphBackground));
                    ImGui.PushStyleColor(ImGuiCol.Text, WritableRgbaFloat.ToUint(Color.Cyan));
                    if (ImGui.Button("Highlight Colour"))
                    {
                        //todo: highlight colour picker
                    }
                    ImGui.PopStyleColor();
                    ImGui.PopStyleColor();
                    */

                    ImGui.EndChild();
                }
            }
        }

        private static int selitem = 0;
        public void DrawAddressSelectBox(PlottedGraph plot)
        {
            if (ImGui.ListBox("##AddrListbox", ref selitem,
                _activeHighlights.SelectedAddresses.Select(ad => $"0x{ad:X}").ToArray(),
                _activeHighlights.SelectedAddresses.Count))
            {
                ulong address = _activeHighlights.SelectedAddresses[selitem];
                _activeHighlights.SelectedAddresses.RemoveAt(selitem);
                plot.HighlightedAddresses.Remove(address);
                List<uint> nodes = plot.InternalProtoGraph.ProcessData.GetNodesAtAddress(address, plot.TID);

                plot.LayoutState.Lock.EnterUpgradeableReadLock();
                plot.RemoveHighlightedNodes(nodes, CONSTANTS.HighlightType.Addresses);
                plot.LayoutState.Lock.ExitUpgradeableReadLock();
            }


        }


        private void DrawAddressSelectControls(PlottedGraph plot)
        {
            ImGui.Text("Address");
            ImGui.InputText("##AddressInput", ref _activeHighlights.AddrEntryText, 255);
            ImGui.SameLine();

            if (ImGui.Button("Add") ||
                ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.Enter)) ||
                ImGui.IsKeyPressed(ImGui.GetKeyIndex(ImGuiKey.KeyPadEnter)))
            {
                string addrstring = _activeHighlights.AddrEntryText;
                addrstring = new string(addrstring.ToCharArray().Where(c => !char.IsWhiteSpace(c)).ToArray());

                if (addrstring.ToLower().StartsWith("0x"))
                {
                    addrstring = addrstring.Substring(2);
                }

                bool success = ulong.TryParse(addrstring, NumberStyles.AllowHexSpecifier, CultureInfo.CurrentCulture, out ulong hexAddr);
                if (!success)
                {
                    success = ulong.TryParse(addrstring, NumberStyles.Integer, CultureInfo.CurrentCulture, out hexAddr);
                }

                if (success)
                {
                    _activeHighlights.AddrEntryText = "";
                    if (!_activeHighlights.SelectedAddresses.Contains(hexAddr))
                    {

                        plot.AddHighlightedAddress(hexAddr);
                        _activeHighlights.SelectedAddresses.Add(hexAddr);
                    }
                }
            }
        }


        private void DrawExceptionSelectBox(PlottedGraph plot)
        {
            uint[]? exceptionNodes = plot.InternalProtoGraph.GetExceptionNodes();
            if (exceptionNodes is null || exceptionNodes.Length == 0)
            {
                string caption = $"No exceptions recorded in thread ID {_ActiveGraph?.TID}";
                ImGuiUtils.DrawRegionCenteredText(caption);
                return;
            }

            string[] labels = exceptionNodes.Select(x => x.ToString()).ToArray();
            if (ImGui.BeginTable("##ExceptionsTable", 2))
            {
                ImGui.TableSetupColumn("Address", ImGuiTableColumnFlags.WidthFixed, 160);
                ImGui.TableSetupColumn("Module");
                ImGui.TableHeadersRow();
                foreach (uint nodeidx in exceptionNodes)
                {
                    NodeData? n = plot.InternalProtoGraph.GetNode(nodeidx);

                    if (n is not null)
                    {

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        if(ImGui.Selectable($"0x{n.Address:X}", _activeHighlights.SelectedExceptionNodes.Contains(nodeidx), ImGuiSelectableFlags.SpanAllColumns))                        
                        {
                            if (_activeHighlights.SelectedExceptionNodes.Contains(nodeidx))
                            {
                                _activeHighlights.SelectedExceptionNodes.Remove(nodeidx);
                                plot.RemoveHighlightedNodes(new List<uint> { nodeidx }, CONSTANTS.HighlightType.Exceptions);
                            }
                            else
                            {
                                _activeHighlights.SelectedExceptionNodes.Add(nodeidx);
                                plot.AddHighlightedNodes(new List<uint> { nodeidx }, CONSTANTS.HighlightType.Exceptions);
                            }
                        }
                        ImGui.TableNextColumn();
                        ImGui.Text(System.IO.Path.GetFileName(plot.InternalProtoGraph.ProcessData.GetModulePath(n.GlobalModuleID)));
                        
                    }
                }
                ImGui.EndTable();


            }



        }

        public void DrawExceptionSelectControls()
        {

        }

        public bool PopoutHighlight = false;

        public void Draw(PlottedGraph LatestActiveGraph)
        {
            if (LatestActiveGraph == null)
            {
                return;
            }

            if (_ActiveGraph != LatestActiveGraph)
            {
                _ActiveGraph = LatestActiveGraph;
                ThreadHighlightSettings? foundHighlights;
                if (!graphSettings.TryGetValue(_ActiveGraph, out foundHighlights) || foundHighlights is null)
                {
                    foundHighlights = new ThreadHighlightSettings();
                    graphSettings.Add(_ActiveGraph, foundHighlights);
                }
                _activeHighlights = foundHighlights;
            }
            Vector2 Size = ImGui.GetWindowSize();
            Size.Y = ImGui.GetContentRegionAvail().Y;

            //ImGui.PushStyleColor(ImGuiCol.FrameBg, 0xff0000ff);
            if (ImGui.BeginChild("#highlightControls", Size))
            {
                if (!PopoutHighlight && ImGui.Button("Popout"))
                {
                    ImGui.SetCursorPosX(ImGui.GetContentRegionAvail().X - 50);
                    PopoutHighlight = true;
                }

                ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags.AutoSelectNewTabs;
                if (ImGui.BeginTabBar("Highlights Tab Bar", tab_bar_flags))
                {
                    if (ImGui.BeginTabItem("Externals/Symbols"))
                    {
                        _activeHighlights.selectedHighlightTab = 0;
                        DrawSymbolsSelectBox(reserveSize: 40); //todo: unbadify this height choice
                        DrawSymbolsSelectControls(_ActiveGraph);
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Addresses"))
                    {
                        _activeHighlights.selectedHighlightTab = 1;
                        DrawAddressSelectControls(_ActiveGraph);
                        if (_activeHighlights.SelectedAddresses.Any())
                            DrawAddressSelectBox(_ActiveGraph);
                        ImGui.EndTabItem();
                    }
                    if (ImGui.BeginTabItem("Exceptions"))
                    {
                        _activeHighlights.selectedHighlightTab = 2;
                        DrawExceptionSelectBox(_ActiveGraph);
                        DrawExceptionSelectControls();
                        ImGui.EndTabItem();
                    }
                    ImGui.EndTabBar();
                }
                ImGui.EndChildFrame();
            }
            //ImGui.PopStyleColor();
        }
    }
}
