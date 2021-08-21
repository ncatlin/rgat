using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Numerics;
using Veldrid;

namespace rgat.Widgets
{
    class QuickMenu
    {
        ImGuiController _controller;
        //true if menu is expanded or in the process of expanding.

        bool _expanded
        {
            get
            {
                return _baseMenuEntry.active;
            }
            set
            {
                _baseMenuEntry.active = value;
            }
        }
        bool _stayExpanded; //otherwise only expanded on mouse hover of button or child menus

        bool ExpansionFinished => Math.Floor(_expandProgress) == _baseMenuEntry.children.Count;
        public bool Expanded => _expanded;

        float _expandProgress = 0f;
        string _activeMenuPopupName;
        Vector2 _popupPos = Vector2.Zero;
        Vector2 _menuBase = Vector2.Zero;
        Vector2 _iconSize = Vector2.Zero;

        GraphicsDevice _gd;
        HighlightDialog HighlightDialogWidget = new HighlightDialog();
        MenuEntry _baseMenuEntry;

        class MenuEntry
        {
            public string Icon;
            public string Popup;
            public string ToolTip;
            public ActionName Action;
            public string Label;
            public bool CloseMenu;
            public Key Shortcut;
            public List<MenuEntry> children;
            bool _isActive;
            public bool active
            {
                get => _isActive;
                set
                {
                    if (value)
                    {
                        if (!_isActive) _isActive = true;
                    }
                    else
                    {
                        _isActive = false;
                        if (children != null)
                        {
                            foreach (var e in children)
                            {
                                if (e.active) e.active = false;
                            }
                        }
                    }
                }
            }
        }

        Dictionary<ActionName, MenuEntry> menuActions = new Dictionary<ActionName, MenuEntry>();

        enum ActionName
        {
            ToggleEdges, ToggleNodes, ToggleTextAll, ToggleTextInstructions, ToggleTextSymbols, ToggleTextSymbolsLive, ToggleNodeAddresses,
            ToggleNodeIndexes, ToggleSymbolModules, ToggleSymbolFullPaths, ToggleNodeTooltips, ToggleActiveHighlight,
            ToggleMenu, ToggleVisMenu, ToggleSearchMenu, ToggleLayoutMenu
        };

        public QuickMenu(GraphicsDevice gd, ImGuiController controller)
        {
            _gd = gd;
            _controller = controller;

            List<MenuEntry> baseEntries = new List<MenuEntry>();

            //menu button
            _baseMenuEntry = new MenuEntry() { Shortcut = Key.M, ToolTip = "Menu", Icon = "Menu2", Action = ActionName.ToggleMenu, children = baseEntries, };

            //visibility menu
            List<MenuEntry> visEntries = new List<MenuEntry>();
            baseEntries.Add(new MenuEntry { Shortcut = Key.V, ToolTip = "Visibility", Icon = "Eye", Action = ActionName.ToggleVisMenu, Popup = "VisibilityMenuPopup", children = visEntries });

            visEntries.Add(new MenuEntry { Shortcut = Key.E, CloseMenu = true, Action = ActionName.ToggleEdges, Label = "Edges", ToolTip = "Toggle display of graph edges" });
            visEntries.Add(new MenuEntry { Shortcut = Key.N, CloseMenu = true, Action = ActionName.ToggleNodes, Label = "Nodes", ToolTip = "Toggle display of graph nodes (instructions/API calls)" });
            visEntries.Add(new MenuEntry { Shortcut = Key.T, CloseMenu = true, Action = ActionName.ToggleTextAll, Label = "Labels", ToolTip = "Toggle display of any graph text" });
            visEntries.Add(new MenuEntry { Shortcut = Key.I, CloseMenu = true, Action = ActionName.ToggleTextInstructions, Label = "Instruction Labels", ToolTip = "Display instruction text next to nodes" });
            visEntries.Add(new MenuEntry { Shortcut = Key.S, CloseMenu = true, Action = ActionName.ToggleTextSymbols, Label = "Symbol Labels", ToolTip = "Display API information next to API calls" });
            visEntries.Add(new MenuEntry { Shortcut = Key.X, CloseMenu = true, Action = ActionName.ToggleNodeIndexes, Label = "Indexes", ToolTip = "Display of node indexes (the order nodes appeared on the graph)." });
            visEntries.Add(new MenuEntry { Shortcut = Key.A, CloseMenu = true, Action = ActionName.ToggleNodeAddresses, Label = "Addresses", ToolTip = "Display of the memory address of nodes" });
            visEntries.Add(new MenuEntry { Shortcut = Key.M, CloseMenu = true, Action = ActionName.ToggleSymbolModules, Label = "Modules", ToolTip = "Display of the module API nodes are located in"});
            visEntries.Add(new MenuEntry { Shortcut = Key.P, CloseMenu = true, Action = ActionName.ToggleSymbolFullPaths, Label = "Full Module Paths", ToolTip = "Display the full path on disk of API modules instead of just the filename" });
            visEntries.Add(new MenuEntry { Shortcut = Key.H, CloseMenu = true, Action = ActionName.ToggleActiveHighlight, Label = "Highlight Active", ToolTip = "Display a highlight line indicating the most recently executed instruction." });
            visEntries.Add(new MenuEntry { Shortcut = Key.O, CloseMenu = true, Action = ActionName.ToggleNodeTooltips, Label = "Node Tooltips", ToolTip = "Show information about a node on mouseover" });
            visEntries.Add(new MenuEntry { Shortcut = Key.R, CloseMenu = true, Action = ActionName.ToggleTextSymbolsLive, Label = "Rising API text", ToolTip = "Show animated API information when an API node is activated" });


            baseEntries.Add(new MenuEntry { Shortcut = Key.S, ToolTip = "Search/Highlighting", Action = ActionName.ToggleSearchMenu, Icon = "Search", Popup = "SearchMenuPopup" });
            baseEntries.Add(new MenuEntry { Shortcut = Key.G, ToolTip = "Graph Layout", Action = ActionName.ToggleLayoutMenu, Icon = "Force3D", Popup = "GraphLayoutMenu" });

            PopulateMenuActionsList(_baseMenuEntry);
        }




        void DrawVisibilityFrame()
        {

            if (ImGui.BeginTable("VisTable", 6, ImGuiTableFlags.BordersInnerV))
            {

                ImGui.Columns(6, "visselcolumns", false);
                ImGui.TableSetupColumn("VisColumn", ImGuiTableColumnFlags.None);
                ImGui.TableSetupColumn("VisColumnTog", ImGuiTableColumnFlags.WidthFixed, 35);
                ImGui.TableSetupColumn("TextColumn", ImGuiTableColumnFlags.None);
                ImGui.TableSetupColumn("TextColumnTog", ImGuiTableColumnFlags.WidthFixed, 35);
                ImGui.TableSetupColumn("OtherColumn", ImGuiTableColumnFlags.None);
                ImGui.TableSetupColumn("OtherColumnTog", ImGuiTableColumnFlags.WidthFixed, 35);


                ImGui.TableNextRow();
                if (ShowTooltipToggle(0, ActionName.ToggleEdges, _currentGraph.Opt_EdgesVisible)) ActivateAction(ActionName.ToggleEdges, hotKey: false);
                if (ShowTooltipToggle(2, ActionName.ToggleTextAll, _currentGraph.Opt_TextEnabled)) ActivateAction(ActionName.ToggleTextAll, hotKey: false);
                if (ShowTooltipToggle(4, ActionName.ToggleNodeTooltips, GlobalConfig.ShowNodeMouseoverTooltip)) ActivateAction(ActionName.ToggleNodeTooltips, hotKey: false);
                ImGui.TableNextRow();
                if (ShowTooltipToggle(0, ActionName.ToggleNodes, _currentGraph.Opt_NodesVisible))ActivateAction(ActionName.ToggleNodes, hotKey: false);
                if (ShowTooltipToggle(2, ActionName.ToggleTextInstructions, _currentGraph.Opt_TextEnabledIns))ActivateAction(ActionName.ToggleTextInstructions, hotKey: false);
                ImGui.TableNextRow();
                if (ShowTooltipToggle(0, ActionName.ToggleActiveHighlight, _currentGraph.Opt_LiveNodeEdgeEnabled))ActivateAction(ActionName.ToggleActiveHighlight, hotKey: false);
                if (ShowTooltipToggle(2, ActionName.ToggleTextSymbols, _currentGraph.Opt_TextEnabledSym))ActivateAction(ActionName.ToggleTextSymbols, hotKey: false);
                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleTextSymbolsLive, _currentGraph.Opt_TextEnabledLive))ActivateAction(ActionName.ToggleTextSymbolsLive, hotKey: false);
                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleNodeAddresses, _currentGraph.Opt_ShowNodeAddresses))ActivateAction(ActionName.ToggleNodeAddresses, hotKey: false);
                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleNodeIndexes, _currentGraph.Opt_ShowNodeIndexes))ActivateAction(ActionName.ToggleNodeIndexes, hotKey: false);
                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleSymbolModules, _currentGraph.Opt_ShowSymbolModules))ActivateAction(ActionName.ToggleSymbolModules, hotKey: false);
                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleSymbolFullPaths, _currentGraph.Opt_ShowSymbolModulePaths))ActivateAction(ActionName.ToggleSymbolFullPaths, hotKey: false);


                ImGui.EndTable();
            }

        }

        bool ShowTooltipToggle(int column, ActionName action, bool value)
        {
            MenuEntry menuitem = menuActions[action];
            ImGui.TableSetColumnIndex(column);

            bool clicked = false;
            if (ImGui.Selectable(menuitem.Label, false, ImGuiSelectableFlags.DontClosePopups))
            {
                clicked = true;
            }
            if (ImGui.IsItemHovered()) ImGui.SetTooltip($"{menuitem.ToolTip} [{menuitem.Shortcut}]");
            ImGui.TableNextColumn();
            return clicked || SmallWidgets.ToggleButton("##Toggle" + menuitem.Label, value, null);
        }

        bool ActivateAction(ActionName actionName, bool hotKey)
        {
            if (!menuActions.TryGetValue(actionName, out MenuEntry action))
            {
                Logging.RecordLogEvent("Bad quickmenu action:" + actionName);
                return false;
            }
            keyCombo.Add(action.Shortcut);

            switch (actionName)
            {
                case ActionName.ToggleNodes:
                    _currentGraph.Opt_NodesVisible = !_currentGraph.Opt_NodesVisible;
                    break;
                case ActionName.ToggleEdges:
                    _currentGraph.Opt_EdgesVisible = !_currentGraph.Opt_EdgesVisible;
                    break;
                case ActionName.ToggleTextAll:
                    _currentGraph.Opt_TextEnabled = !_currentGraph.Opt_TextEnabled;
                    break;
                case ActionName.ToggleTextInstructions:
                    _currentGraph.Opt_TextEnabledIns = !_currentGraph.Opt_TextEnabledIns;
                    break;
                case ActionName.ToggleTextSymbols:
                    _currentGraph.Opt_TextEnabledSym = !_currentGraph.Opt_TextEnabledSym;
                    break;
                case ActionName.ToggleTextSymbolsLive:
                    _currentGraph.Opt_TextEnabledLive = !_currentGraph.Opt_TextEnabledLive;
                    break;
                case ActionName.ToggleActiveHighlight:
                    _currentGraph.Opt_LiveNodeEdgeEnabled = !_currentGraph.Opt_LiveNodeEdgeEnabled;
                    break;
                case ActionName.ToggleNodeAddresses:
                    _currentGraph.Opt_ShowNodeAddresses = !_currentGraph.Opt_ShowNodeAddresses;
                    break;
                case ActionName.ToggleNodeIndexes:
                    _currentGraph.Opt_ShowNodeIndexes = !_currentGraph.Opt_ShowNodeIndexes;
                    break;
                case ActionName.ToggleSymbolModules:
                    _currentGraph.Opt_ShowSymbolModules = !_currentGraph.Opt_ShowSymbolModules;
                    break;
                case ActionName.ToggleSymbolFullPaths:
                    _currentGraph.Opt_ShowSymbolModulePaths = !_currentGraph.Opt_ShowSymbolModulePaths;
                    break;
                case ActionName.ToggleMenu:
                    MenuPressed();
                    break;
                case ActionName.ToggleNodeTooltips:
                    GlobalConfig.ShowNodeMouseoverTooltip = !GlobalConfig.ShowNodeMouseoverTooltip;
                    break;
                case ActionName.ToggleVisMenu:
                case ActionName.ToggleSearchMenu:
                case ActionName.ToggleLayoutMenu:
                    _activeEntry = action;
                    _activeMenuPopupName = action.Popup;
                    break;
                default:
                    Logging.RecordLogEvent("Unhandled quickmenu action: " + actionName);
                    break;
            }
            if (action.children == null)
            {
                if (hotKey && action.CloseMenu)
                {
                    MenuPressed();
                }
                return true;
            }
            return false;
        }


        void PopulateMenuActionsList(MenuEntry entry)
        {
            if (entry.Action != null)
            {
                menuActions[entry.Action] = entry;
            }
            if (entry.children?.Count > 0)
            {
                foreach (MenuEntry child in entry.children)
                {
                    PopulateMenuActionsList(child);
                }
            }
        }


        public void CancelPressed()
        {
            _expanded = false;
            if (_activeMenuPopupName != null)
            {
                ImGui.CloseCurrentPopup();
                _activeMenuPopupName = null;
            }
        }


        /// <summary>
        /// Take a keypress that might be dealt with by the open quickmenu
        /// Return true if the quickmenu swallows is (ie: not to be used for other graph actions)
        /// </summary>
        Tuple<Key, ModifierKeys> _RecentKeypress;
        public bool KeyPressed(Tuple<Key, ModifierKeys> keyModTuple, out Tuple<string, string> ComboAction)
        {
            ComboAction = null;
            if (!_expanded || _activeEntry == null) return false;

            _RecentKeypress = keyModTuple;

            for (var i = 0; i < _activeEntry.children?.Count; i++)
            {
                MenuEntry entry = _activeEntry.children[i];
                if (keyModTuple.Item1 == entry.Shortcut)
                {
                    if (entry.Action != null)
                    {
                        if (ActivateAction(entry.Action, hotKey: true))
                        {
                            string combo = String.Join("-", keyCombo.ToArray());
                            ComboAction = new Tuple<string, string>(combo, entry.Label);
                        }
                    }
                    return true;
                }

            }
            return true;
        }

        public void MenuPressed()
        {
            if (Expanded) Contract();
            else Expand(persistent: true);
        }

        List<Key> keyCombo = new List<Key>();

        public void Expand(bool persistent = false)
        {
            keyCombo.Clear();
            keyCombo.Add(_baseMenuEntry.Shortcut);

            if (_expanded == false && _expandProgress <= 0)
            {
                _expanded = true;
                _stayExpanded = persistent;
                _activeEntry = _baseMenuEntry;
                _baseMenuEntry.active = true;
            }
        }

        public void Contract()
        {

            if (ExpansionFinished)
            {
                _expanded = false;
                _stayExpanded = false;
                _activeMenuPopupName = null;
                HighlightDialogWidget.PopoutHighlight = false;
                _activeEntry = null;
            }

        }


        PlottedGraph _currentGraph;
        public void Draw(Vector2 position, float scale, PlottedGraph graph)
        {
            _currentGraph = graph;

            Texture btnIcon = _controller.GetImage("Menu");
            _iconSize = new Vector2(btnIcon.Width * scale, btnIcon.Height * scale);

            if (_expandProgress == 0)
            {
                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, btnIcon, "QuickMenuButton");
                Vector2 padding = new Vector2(16f, 6f);
                Vector2 mainIconPos = new Vector2((position.X) + padding.X, ((position.Y - _iconSize.Y) - 4) - padding.Y);
                ImGui.SetCursorScreenPos(mainIconPos);
                ImGui.Image(CPUframeBufferTextureId, _iconSize);
                if (ImGui.IsItemHovered(flags: ImGuiHoveredFlags.AllowWhenBlockedByPopup))
                {
                    Expand();
                }
            }

            if (_expanded || _expandProgress != 0)
            {
                DrawExpandedMenu(position);
            }

            if (_activeMenuPopupName != null)
            {
                ImGui.PushStyleColor(ImGuiCol.ModalWindowDimBg, 0x00000050);
                DrawPopups();
                ImGui.PopStyleColor();
            }

        }

        readonly float _menuYPad = 8;

        void DrawExpandedMenu(Vector2 position)
        {
            const float expansionPerFrame = 0.3f;
            Vector2 padding = new Vector2(16f, 6f);
            _menuBase = new Vector2((position.X) + padding.X, ((position.Y - _iconSize.Y) - 4) - padding.Y);

            float iconCount = _baseMenuEntry.children.Count + 1;
            float currentExpansion = (float)(_expandProgress / iconCount);

            float expandedHeight = iconCount * (_iconSize.Y + _menuYPad);
            Vector2 menuPos = new Vector2(position.X + padding.X, position.Y - (expandedHeight * currentExpansion + _menuYPad));

            ImGui.SetCursorScreenPos(menuPos);
            ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 5.0f);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.1f, 0.3f, 0.6f, 0.4f));
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.1f, 0.3f, 0.6f, 0.5f));
            ImGui.Button(" ", new Vector2(_iconSize.X, expandedHeight * currentExpansion));
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();
            ImGui.PopStyleVar();

            //close menu if menu fully expanded, no child popup and mouse is far enough away
            if (_expanded && _activeMenuPopupName == null && ExpansionFinished && !_stayExpanded)
            {
                float mouseDistance = Vector2.Distance(position, ImGui.GetMousePos());
                if (mouseDistance > 135)
                {
                    Contract();
                    return;
                }
            }

            //now draw the buttons, Y position proportional to the expansion progress
            float menuY = 0;

            for (var i = 0; i < iconCount; i++)
            {
                MenuEntry entry = i == 0 ? _baseMenuEntry : _baseMenuEntry.children[i - 1];

                float progressAdjustedY = menuY * currentExpansion;
                DrawMenuButton(entry, progressAdjustedY);
                menuY += (_iconSize.Y + _menuYPad);
                if (i >= _expandProgress) break;
            }
            //Console.WriteLine(_expanded);
            if (_expanded && !ExpansionFinished) _expandProgress += expansionPerFrame;
            if (!_expanded && _expandProgress > 0)
                _expandProgress -= expansionPerFrame;

            _expandProgress = Math.Min(_expandProgress, iconCount);
            _expandProgress = Math.Max(_expandProgress, 0);
        }

        MenuEntry? __activeEntry_; //todo wtf
        MenuEntry? _activeEntry
        {
            get { return __activeEntry_; }
            set
            {
                /*
                if (__activeEntry_ != null)
                {
                    MenuEntry oldval = __activeEntry_;
                    oldval.active = false;
                }*/
                if (value != null)
                    value.active = true;
                __activeEntry_ = value;
            }
        }




        void DrawMenuButton(MenuEntry entry, float Yoffset)
        {

            bool isActive = entry.Popup != null && ImGui.IsPopupOpen(entry.Popup);
            Texture btnIcon = _controller.GetImage(entry.Icon);
            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, btnIcon, "QuickMenuSubButton");
            ImGui.SetCursorScreenPos(new Vector2(_menuBase.X, _menuBase.Y - Yoffset));
            Vector4 border = isActive ? new Vector4(1f, 1f, 1f, 1f) : Vector4.Zero;
            ImGui.Image(CPUframeBufferTextureId, _iconSize, Vector2.Zero, Vector2.One, Vector4.One, border);

            if (!ExpansionFinished) return;

            ImGuiHoveredFlags flags = ImGuiHoveredFlags.AllowWhenBlockedByActiveItem |
                                      ImGuiHoveredFlags.AllowWhenOverlapped |
                                      ImGuiHoveredFlags.AllowWhenBlockedByPopup;
            if (ImGui.IsItemHovered(flags))
            {
                if (_activeEntry == null || _activeEntry != entry)
                {
                    if (_activeMenuPopupName != null)
                    {
                        _activeEntry.active = false;
                        ImGui.CloseCurrentPopup();
                        _activeMenuPopupName = null;
                    }
                    _activeEntry = entry;
                }
                ImGui.SetTooltip($"{entry.ToolTip} ({entry.Shortcut})");
            }
            else
            {
                if (_activeMenuPopupName == null &&
                    entry?.active == false &&
                    entry?.Popup != null &&
                    ImGui.IsPopupOpen(entry.Popup))
                {
                    ImGui.CloseCurrentPopup();
                }
            }
            if (entry.active && entry.Popup != null)
            {
                if (_activeMenuPopupName != entry.Popup)
                {
                    _popupPos = new Vector2(_menuBase.X + 50, _menuBase.Y - (Yoffset + 50));
                    ImGui.OpenPopup(entry.Popup);
                    _activeMenuPopupName = entry.Popup;
                }
            }

        }

        void DrawPopups()
        {
            ImGui.SetNextWindowPos(_popupPos, ImGuiCond.Appearing);

            if (_activeMenuPopupName == "VisibilityMenuPopup" && ImGui.BeginPopup("VisibilityMenuPopup"))
            {
                DrawVisibilityFrame();
                ImGui.EndPopup();
            }

            if (HighlightDialogWidget.PopoutHighlight)
            {
                bool ff = true;
                ImGui.SetNextWindowSize(new Vector2(500, 300), ImGuiCond.Appearing);
                ImGui.SetNextWindowSizeConstraints(new Vector2(500, 300), new Vector2(800, 700));
                if (ImGui.Begin("Search/Highlighting", ref HighlightDialogWidget.PopoutHighlight))
                {
                    DrawSearchHighlightFrame();
                    ImGui.End();
                }
                return;
            }
            else
            {
                if (_activeMenuPopupName == "SearchMenuPopup")
                {
                    ImGui.SetNextWindowSize(new Vector2(500, 300), ImGuiCond.Always);
                    ImGui.SetNextWindowPos(_popupPos, ImGuiCond.Appearing);
                    ImGuiWindowFlags flags = ImGuiWindowFlags.None;

                    if (ImGui.BeginPopup("SearchMenuPopup", flags))
                    {
                        DrawSearchHighlightFrame();
                        ImGui.EndPopup();
                    }
                }
            }

            if ((_activeMenuPopupName == "GraphLayoutMenu") && ImGui.BeginPopup("GraphLayoutMenu"))
            {
                DrawGraphLayoutFrame();
                ImGui.EndPopup();
            }


            if (_activeMenuPopupName != null && !ImGui.IsPopupOpen(_activeMenuPopupName))
            {
                _activeMenuPopupName = null;
            }
        }




        /*
private void DrawScalePopup()
{
    if (ImGui.BeginChild(ImGui.GetID("SizeControls"), new Vector2(200, 200)))
    {
        if (ImGui.DragFloat("Horizontal Stretch", ref _rgatstate._currentGraph.scalefactors.pix_per_A, 0.5f, 0.05f, 400f, "%f%%"))
        {
            InitGraphReplot();
            Console.WriteLine($"Needreplot { _rgatstate._currentGraph.scalefactors.pix_per_A}");
        };
        if (ImGui.DragFloat("Vertical Stretch", ref _rgatstate._currentGraph.scalefactors.pix_per_B, 0.5f, 0.1f, 400f, "%f%%"))
        {
            InitGraphReplot();
        };
        if (ImGui.DragFloat("Plot Size", ref _rgatstate._currentGraph.scalefactors.plotSize, 10.0f, 0.1f, 100000f, "%f%%"))
        {
            InitGraphReplot();
        };

        ImGui.EndChild();
    }
}
*/
        void DrawGraphLayoutFrame()
        {
            if (_currentGraph.ActiveLayoutStyle == RGAT_CONSTANTS.LayoutStyles.Style.Circle)
            {
                ImGui.Text("Circle Config Options");
            }

            if (_currentGraph.ActiveLayoutStyle == RGAT_CONSTANTS.LayoutStyles.Style.CylinderLayout)
            {
                ImGui.Text("Cylinder Config Options");
            }

            if (_currentGraph.ActiveLayoutStyle == RGAT_CONSTANTS.LayoutStyles.Style.ForceDirected3DBlocks)
            {
                ImGui.Text("ForceDirected3DBlocks Config Options");
            }

            if (_currentGraph.ActiveLayoutStyle == RGAT_CONSTANTS.LayoutStyles.Style.ForceDirected3DNodes)
            {
                ImGui.Text("eForceDirected3DNodes Config Options");
                if (ImGui.Button("Rerender"))
                {
                    InitGraphReplot();
                }

                if (ImGui.BeginTable("ComputationSelectNodes", 2))
                {
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();

                    ImGui.Text("All Computation:");
                    ImGui.TableNextColumn();
                    if (SmallWidgets.ToggleButton("#ComputeActive", GlobalConfig.LayoutAllComputeEnabled, "Computation active"))
                    {
                        GlobalConfig.LayoutAllComputeEnabled = !GlobalConfig.LayoutAllComputeEnabled;
                    }

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();

                    ImGui.Text("Attrib Computation:");
                    ImGui.TableNextColumn();
                    if (SmallWidgets.ToggleButton("#ComputeAttrib", GlobalConfig.LayoutAttribsActive, "Attrib Computation active"))
                    {
                        GlobalConfig.LayoutAttribsActive = !GlobalConfig.LayoutAttribsActive;
                    }

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();

                    ImGui.Text("Pos/Vel Computation:");
                    ImGui.TableNextColumn();
                    if (SmallWidgets.ToggleButton("#ComputePosVel", GlobalConfig.LayoutPositionsActive, "PosVel Computation active"))
                    {
                        GlobalConfig.LayoutPositionsActive = !GlobalConfig.LayoutPositionsActive;
                    }

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();

                    ImGui.Text("Max Node Speed");
                    ImGui.TableNextColumn();
                    ImGui.SetNextItemWidth(150);
                    ImGui.SliderFloat("##MaxNodeSpeed", ref GlobalConfig.NodeSoftSpeedLimit, 0, GlobalConfig.NodeHardSpeedLimit);



                    ImGui.EndTable();
                }
            }
        }


        private void InitGraphReplot()
        {
            Console.WriteLine("init graph replot called");
        }


        void DrawSearchHighlightFrame()
        {
            HighlightDialogWidget.Draw(_currentGraph);
        }
    }
}
