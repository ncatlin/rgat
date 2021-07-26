using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Numerics;
using Veldrid;

namespace rgatCore.Widgets
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
            public string Action;
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

        Dictionary<string, MenuEntry> menuActions = new Dictionary<string, MenuEntry>();

        public QuickMenu(GraphicsDevice gd, ImGuiController controller)
        {
            _gd = gd;
            _controller = controller;

            List<MenuEntry> baseEntries = new List<MenuEntry>();

            //menu button
            _baseMenuEntry = new MenuEntry() { Shortcut = Key.M, ToolTip = "Menu", Icon = "Menu2", Action = "Toggle Menu", children = baseEntries, };

            //visibility menu
            List<MenuEntry> visEntries = new List<MenuEntry>();
            baseEntries.Add(new MenuEntry { Shortcut = Key.V, ToolTip = "Visibility", Icon = "Eye", Action = "Show VisMenu", Popup = "VisibilityMenuPopup", children = visEntries });
            //visEntries.Add
            visEntries.Add(new MenuEntry { Shortcut = Key.E, CloseMenu = true, Action = "Toggle Edges", ToolTip = "Toggle display of graph edges." });
            visEntries.Add(new MenuEntry { Shortcut = Key.N, CloseMenu = true, Action = "Toggle Nodes", ToolTip = "Toggle display of instruction nodes." });
            visEntries.Add(new MenuEntry { Shortcut = Key.T, CloseMenu = true, Action = "Toggle Text", ToolTip = "Toggle display of all text." });
            visEntries.Add(new MenuEntry { Shortcut = Key.I, CloseMenu = true, Action = "Toggle Instruction Text", ToolTip = "Toggle display of instruction text." });
            visEntries.Add(new MenuEntry { Shortcut = Key.H, CloseMenu = true, Action = "Toggle Active Node Highlight", ToolTip = "Display a highlight line indicating the most recently executed instruction." });


            baseEntries.Add(new MenuEntry { Shortcut = Key.S, ToolTip = "Search/Highlighting", Action = "Show SearchMenu", Icon = "Search", Popup = "SearchMenuPopup" });
            baseEntries.Add(new MenuEntry { Shortcut = Key.G, ToolTip = "Graph Layout", Action = "Show LayoutMenu", Icon = "Force3D", Popup = "GraphLayoutMenu" });

            PopulateMenuActionsList(_baseMenuEntry);
        }


        bool ActivateAction(string actionName)
        {
            if (!menuActions.TryGetValue(actionName, out MenuEntry action))
            {
                Logging.RecordLogEvent("Bad quickmenu action:" + actionName);
                return false;
            }
            keyCombo.Add(action.Shortcut);

            switch (actionName)
            {
                case "Toggle Nodes":
                    _currentGraph.NodesVisible = !_currentGraph.NodesVisible;
                    break;
                case "Toggle Edges":
                    _currentGraph.EdgesVisible = !_currentGraph.EdgesVisible;
                    break;
                case "Toggle Text":
                    _currentGraph.TextEnabled = !_currentGraph.TextEnabled;
                    break;
                case "Toggle Instruction Text":
                    _currentGraph.TextEnabledIns = !_currentGraph.TextEnabledIns;
                    break;
                case "Toggle Active Node Highlight":
                    _currentGraph.LiveNodeEdgeEnabled = !_currentGraph.LiveNodeEdgeEnabled;
                    break;
                case "Toggle Menu":
                    MenuPressed();
                    break;
                case "Show SearchMenu":
                case "Show VisMenu":
                case "Show LayoutMenu":
                    _activeEntry = action;
                    _activeMenuPopupName = action.Popup;
                    break;
                default:
                    Logging.RecordLogEvent("Unhandled quickmenu action: " + actionName);
                    break;
            }
            if (action.children == null)
            {
                if (action.CloseMenu)
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
                        if (ActivateAction(entry.Action))
                        {
                            string combo = String.Join("-", keyCombo.ToArray());
                            ComboAction = new Tuple<string, string>(combo, entry.Action);
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

        void DrawVisibilityFrame()
        {

            if (ImGui.BeginChildFrame(324234, new Vector2(250, 160)))
            {

                ImGui.Columns(2, "visselcolumns", true);
                ImGui.SetColumnWidth(0, 180);
                ImGui.SetColumnWidth(1, 65);
                ShowTooltipToggle("Toggle Edges", _currentGraph.EdgesVisible);
                ShowTooltipToggle("Toggle Nodes", _currentGraph.NodesVisible);
                ShowTooltipToggle("Toggle Text", _currentGraph.TextEnabled);
                ShowTooltipToggle("Toggle Instruction Text", _currentGraph.TextEnabledIns);
                ShowTooltipToggle("Toggle Active Node Highlight", _currentGraph.LiveNodeEdgeEnabled);

                ImGui.Columns(1);
                ImGui.EndChildFrame();
            }

        }

        void ShowTooltipToggle(string actionName, bool value)
        {
            float width = ImGui.GetWindowContentRegionWidth();
            float rowHeight = 21;
            Vector2 selSize = new Vector2(width, rowHeight);
            if (ImGui.Selectable(actionName, false, ImGuiSelectableFlags.SpanAllColumns, selSize))
            {
                ActivateAction(actionName);
            }
            if (ImGui.IsItemHovered()) ImGui.SetTooltip(menuActions[actionName].ToolTip);
            ImGui.NextColumn();
            SmallWidgets.ToggleButton("##Toggle" + actionName, value, null);
            ImGui.NextColumn();
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
            if (_currentGraph.ActiveLayoutStyle == LayoutStyles.Style.Circle)
            {
                ImGui.Text("Circle Config Options");
            }

            if (_currentGraph.ActiveLayoutStyle == LayoutStyles.Style.CylinderLayout)
            {
                ImGui.Text("Cylinder Config Options");
            }

            if (_currentGraph.ActiveLayoutStyle == LayoutStyles.Style.ForceDirected3DBlocks)
            {
                ImGui.Text("ForceDirected3DBlocks Config Options");
            }

            if (_currentGraph.ActiveLayoutStyle == LayoutStyles.Style.ForceDirected3DNodes)
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
