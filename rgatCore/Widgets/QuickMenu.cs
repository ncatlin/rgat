﻿using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using Veldrid;

namespace rgat.Widgets
{
    /// <summary>
    /// An in-visualiser graph configuration menu
    /// </summary>
    internal class QuickMenu
    {
        private readonly ImGuiController _controller;

        //true if menu is expanded or in the process of expanding.

        private bool _expanded
        {
            get
            {
                return _baseMenuEntry.active;
            }
            set
            {
                if (value != _baseMenuEntry.active && stateChangeCallback != null)
                {
                    stateChangeCallback(value);
                }
                _baseMenuEntry.active = value;
            }
        }

        private bool _stayExpanded; //otherwise only expanded on mouse hover of button or child menus

        private bool ExpansionFinished => Math.Floor(_expandProgress) == _baseMenuEntry.children!.Count;
        public bool Expanded => _expanded;

        private float _expandProgress = 0f;
        private string? _activeMenuPopupName;
        private Vector2 _popupPos = Vector2.Zero;
        private Vector2 _menuBase = Vector2.Zero;
        private Vector2 _iconSize = Vector2.Zero;
        private GraphicsDevice? _gd;
        private readonly HighlightDialog HighlightDialogWidget = new HighlightDialog();
        private readonly MenuEntry _baseMenuEntry;

        private class MenuEntry
        {
            /// <summary>
            /// Icon name for the menu button
            /// </summary>
            public string? Icon;
            /// <summary>
            /// Popup window name for the menu button
            /// </summary>
            public string? Popup;
            /// <summary>
            /// Mouseover tooltip for the menu button
            /// </summary>
            public string? ToolTip;
            /// <summary>
            /// Action triggered on button activation
            /// </summary>
            public ActionName? Action;
            /// <summary>
            /// Text label for the button
            /// </summary>
            public string? Label;
            public bool CloseMenu;
            public Key Shortcut;
            public List<MenuEntry>? children;
            public MenuEntry? parent;
            private bool _isActive;
            public bool active
            {
                get => _isActive;
                set
                {
                    if (value)
                    {
                        if (!_isActive)
                        {
                            _isActive = true;
                        }

                        return;
                    }

                    _isActive = false;
                    if (children != null)
                    {
                        foreach (var e in children)
                        {
                            if (e.active)
                            {
                                e.active = false;
                            }
                        }
                    }

                }
            }
        }

        private readonly Dictionary<ActionName, MenuEntry> menuActions = new Dictionary<ActionName, MenuEntry>();

        private enum ActionName
        {
            ToggleEdges, ToggleNodes, ToggleTextAll, ToggleTextInstructions, ToggleTextSymbols, ToggleTextSymbolsLive, ToggleNodeAddresses,
            ToggleNodeIndexes, ToggleSymbolModules, ToggleSymbolFullPaths, ToggleNodeTooltips, ToggleActiveHighlight,
            ToggleMenu, ToggleVisMenu, ToggleSearchMenu, ToggleLayoutMenu
        };

        /// <summary>
        /// Create a quickmenu
        /// </summary>
        /// <param name="controller">ImguiController</param>
        public QuickMenu(ImGuiController controller)
        {
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
            visEntries.Add(new MenuEntry { Shortcut = Key.M, CloseMenu = true, Action = ActionName.ToggleSymbolModules, Label = "Modules", ToolTip = "Display of the module API nodes are located in" });
            visEntries.Add(new MenuEntry { Shortcut = Key.P, CloseMenu = true, Action = ActionName.ToggleSymbolFullPaths, Label = "Full Module Paths", ToolTip = "Display the full path on disk of API modules instead of just the filename" });
            visEntries.Add(new MenuEntry { Shortcut = Key.H, CloseMenu = true, Action = ActionName.ToggleActiveHighlight, Label = "Highlight Active", ToolTip = "Display a highlight line indicating the most recently executed instruction." });
            visEntries.Add(new MenuEntry { Shortcut = Key.O, CloseMenu = true, Action = ActionName.ToggleNodeTooltips, Label = "Node Tooltips", ToolTip = "Show information about a node on mouseover" });
            visEntries.Add(new MenuEntry { Shortcut = Key.R, CloseMenu = true, Action = ActionName.ToggleTextSymbolsLive, Label = "Rising API text", ToolTip = "Show animated API information when an API node is activated" });


            baseEntries.Add(new MenuEntry { Shortcut = Key.S, ToolTip = "Search/Highlighting", Action = ActionName.ToggleSearchMenu, Icon = "Search", Popup = "SearchMenuPopup" });
            baseEntries.Add(new MenuEntry { Shortcut = Key.G, ToolTip = "Graph Layout", Action = ActionName.ToggleLayoutMenu, Icon = "Force3D", Popup = "GraphLayoutMenu" });

            PopulateMenuActionsList(_baseMenuEntry);
        }

        /// <summary>
        /// Set the graphis device
        /// </summary>
        /// <param name="gd">GraphicsDevice to render it on</param>
        public void Init(GraphicsDevice gd) => _gd = gd;

        /// <summary>
        /// Called whenever the menu is opened/closed
        /// </summary>
        /// <param name="action">Function to call when opened/closed. Param is open/closed state.</param>
        public void SetStateChangeCallback(Action<bool> action) => stateChangeCallback = action;

        private Action<bool>? stateChangeCallback = null;

        private void DrawVisibilityFrame()
        {
            Debug.Assert(_currentGraph is not null);

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
                if (ShowTooltipToggle(0, ActionName.ToggleEdges, _currentGraph.Opt_EdgesVisible))
                {
                    ActivateAction(ActionName.ToggleEdges, hotKey: false);
                }

                if (ShowTooltipToggle(2, ActionName.ToggleTextAll, _currentGraph.Opt_TextEnabled))
                {
                    ActivateAction(ActionName.ToggleTextAll, hotKey: false);
                }

                if (ShowTooltipToggle(4, ActionName.ToggleNodeTooltips, GlobalConfig.ShowNodeMouseoverTooltip))
                {
                    ActivateAction(ActionName.ToggleNodeTooltips, hotKey: false);
                }

                ImGui.TableNextRow();
                if (ShowTooltipToggle(0, ActionName.ToggleNodes, _currentGraph.Opt_NodesVisible))
                {
                    ActivateAction(ActionName.ToggleNodes, hotKey: false);
                }

                if (ShowTooltipToggle(2, ActionName.ToggleTextInstructions, _currentGraph.Opt_TextEnabledIns))
                {
                    ActivateAction(ActionName.ToggleTextInstructions, hotKey: false);
                }

                ImGui.TableNextRow();
                if (ShowTooltipToggle(0, ActionName.ToggleActiveHighlight, _currentGraph.Opt_LiveNodeEdgeEnabled))
                {
                    ActivateAction(ActionName.ToggleActiveHighlight, hotKey: false);
                }

                if (ShowTooltipToggle(2, ActionName.ToggleTextSymbols, _currentGraph.Opt_TextEnabledSym))
                {
                    ActivateAction(ActionName.ToggleTextSymbols, hotKey: false);
                }

                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleTextSymbolsLive, _currentGraph.Opt_TextEnabledLive))
                {
                    ActivateAction(ActionName.ToggleTextSymbolsLive, hotKey: false);
                }

                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleNodeAddresses, _currentGraph.Opt_ShowNodeAddresses))
                {
                    ActivateAction(ActionName.ToggleNodeAddresses, hotKey: false);
                }

                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleNodeIndexes, _currentGraph.Opt_ShowNodeIndexes))
                {
                    ActivateAction(ActionName.ToggleNodeIndexes, hotKey: false);
                }

                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleSymbolModules, _currentGraph.Opt_ShowSymbolModules))
                {
                    ActivateAction(ActionName.ToggleSymbolModules, hotKey: false);
                }

                ImGui.TableNextRow();
                if (ShowTooltipToggle(2, ActionName.ToggleSymbolFullPaths, _currentGraph.Opt_ShowSymbolModulePaths))
                {
                    ActivateAction(ActionName.ToggleSymbolFullPaths, hotKey: false);
                }

                ImGui.EndTable();
            }

        }

        private bool ShowTooltipToggle(int column, ActionName action, bool value)
        {
            MenuEntry menuitem = menuActions[action];
            ImGui.TableSetColumnIndex(column);

            bool clicked = false;
            if (ImGui.Selectable(menuitem.Label, false, ImGuiSelectableFlags.DontClosePopups))
            {
                clicked = true;
            }
            if (ImGui.IsItemHovered())
            {
                ImGui.SetTooltip($"{menuitem.ToolTip} [{menuitem.Shortcut}]");
            }

            ImGui.TableNextColumn();
            return clicked || SmallWidgets.ToggleButton("##Toggle" + menuitem.Label, value, null);
        }

        /// <summary>
        /// Performs whatever action is assigned to a shortcut or button click
        /// </summary>
        /// <param name="actionName">Action associated with the icon or shortcut</param>
        /// <param name="hotKey">true if a keyboard shortcut, false if clicked</param>
        /// <param name="resultText">something to describe what happened on the key combo display</param>
        /// <returns>Whether the action was a non-menu 'action' which will trigger display of the keyboard combo used</returns>
        private bool ActivateAction(ActionName actionName, bool hotKey, out string? resultText)
        {
            resultText = null;
            if (!menuActions.TryGetValue(actionName, out MenuEntry? action))
            {
                Logging.RecordLogEvent("Bad quickmenu action:" + actionName);
                return false;
            }
            Debug.Assert(_currentGraph is not null);
            keyCombo.Add(action.Shortcut);

            switch (actionName)
            {
                case ActionName.ToggleNodes:
                    _currentGraph.Opt_NodesVisible = !_currentGraph.Opt_NodesVisible;
                    resultText = _currentGraph.Opt_NodesVisible ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleEdges:
                    _currentGraph.Opt_EdgesVisible = !_currentGraph.Opt_EdgesVisible;
                    resultText = _currentGraph.Opt_EdgesVisible ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleTextAll:
                    _currentGraph.Opt_TextEnabled = !_currentGraph.Opt_TextEnabled;
                    resultText = _currentGraph.Opt_TextEnabled ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleTextInstructions:
                    _currentGraph.Opt_TextEnabledIns = !_currentGraph.Opt_TextEnabledIns;
                    resultText = _currentGraph.Opt_TextEnabledIns ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleTextSymbols:
                    _currentGraph.Opt_TextEnabledSym = !_currentGraph.Opt_TextEnabledSym;
                    resultText = _currentGraph.Opt_TextEnabledSym ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleTextSymbolsLive:
                    _currentGraph.Opt_TextEnabledLive = !_currentGraph.Opt_TextEnabledLive;
                    resultText = _currentGraph.Opt_TextEnabledLive ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleActiveHighlight:
                    _currentGraph.Opt_LiveNodeEdgeEnabled = !_currentGraph.Opt_LiveNodeEdgeEnabled;
                    resultText = _currentGraph.Opt_LiveNodeEdgeEnabled ? "Active" : "Inactive";
                    break;
                case ActionName.ToggleNodeAddresses:
                    _currentGraph.Opt_ShowNodeAddresses = !_currentGraph.Opt_ShowNodeAddresses;
                    resultText = _currentGraph.Opt_ShowNodeAddresses ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleNodeIndexes:
                    _currentGraph.Opt_ShowNodeIndexes = !_currentGraph.Opt_ShowNodeIndexes;
                    resultText = _currentGraph.Opt_ShowNodeIndexes ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleSymbolModules:
                    _currentGraph.Opt_ShowSymbolModules = !_currentGraph.Opt_ShowSymbolModules;
                    resultText = _currentGraph.Opt_ShowSymbolModules ? "Visible" : "Hidden";
                    break;
                case ActionName.ToggleSymbolFullPaths:
                    _currentGraph.Opt_ShowSymbolModulePaths = !_currentGraph.Opt_ShowSymbolModulePaths;
                    resultText = _currentGraph.Opt_ShowSymbolModulePaths ? "Visible" : "Hidden";
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
                    action.parent = _activeEntry;
                    _activeEntry = action;
                    _activeMenuPopupName = action.Popup;
                    return false;
                default:
                    Logging.RecordLogEvent("Unhandled quickmenu action: " + actionName);
                    break;
            }

            if (action.children == null) //the menu button works on all leaf submenus
            {
                if (hotKey && action.CloseMenu)
                {
                    MenuPressed();
                }
                return true;
            }
            return false;
        }

        private bool ActivateAction(ActionName actionName, bool hotKey)
        {
            return ActivateAction(actionName, hotKey, out string? ignored);
        }

        private void PopulateMenuActionsList(MenuEntry entry)
        {
            Debug.Assert(entry.Action is not null);
            menuActions[entry.Action.Value] = entry;

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
        private Tuple<Key, ModifierKeys>? _RecentKeypress;
        public bool KeyPressed(Tuple<Key, ModifierKeys> keyModTuple, out Tuple<string, string>? ComboAction)
        {
            ComboAction = null;
            if (!_expanded || _activeEntry == null)
            {
                return false;
            }

            _RecentKeypress = keyModTuple;

            if (keyModTuple.Item1 == Key.Escape)
            {
                Contract();
                return true;
            }

            for (var i = 0; i < _activeEntry.children?.Count; i++)
            {
                MenuEntry entry = _activeEntry.children[i];
                if (keyModTuple.Item1 == entry.Shortcut)
                {
                    if (entry.Action != null)
                    {
                        if (ActivateAction(entry.Action.Value, hotKey: true, out string? resultText))
                        {
                            string combo = string.Join("-", keyCombo.ToArray());
                            string label = entry.Label!;
                            if (resultText != null)
                            {
                                label += $": {resultText}";
                            }

                            ComboAction = new Tuple<string, string>(combo, label);
                        }
                    }
                    return true;
                }
            }

            if (keyModTuple.Item1 == _activeEntry.Shortcut)
            {
                Logging.WriteConsole($"Closing menu {_activeEntry.Action} because it is the active entry");
                _activeEntry.active = false;
                _activeEntry = _activeEntry.parent;

                if (_activeEntry is not null && _activeEntry.Popup is not null)
                {
                    _activeMenuPopupName = _activeEntry.Popup;
                }

                if (keyCombo.Any() && keyCombo.Last() == keyModTuple.Item1)
                {
                    keyCombo.RemoveAt(keyCombo.Count - 1);
                }

                return true;
            }
            return true;
        }


        public void MenuPressed()
        {
            if (Expanded)
            {
                Contract();
            }
            else
            {
                Expand(persistent: true);
            }
        }

        private readonly List<Key> keyCombo = new List<Key>();

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

        private PlottedGraph? _currentGraph;
        public void Draw(Vector2 position, float scale, PlottedGraph graph)
        {
            _currentGraph = graph;

            Texture btnIcon = _controller.GetImage("Menu");
            _iconSize = new Vector2(btnIcon.Width * scale, btnIcon.Height * scale);

            if (_expandProgress == 0)
            {
                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd!.ResourceFactory, btnIcon, "QuickMenuButton");
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

        private readonly float _menuYPad = 8;

        private void DrawExpandedMenu(Vector2 position)
        {
            Debug.Assert(_baseMenuEntry.children is not null);

            const float expansionPerFrame = 0.3f;
            Vector2 padding = new Vector2(16f, 6f);
            _menuBase = new Vector2((position.X) + padding.X, ((position.Y - _iconSize.Y) - 4) - padding.Y);

            float iconCount = _baseMenuEntry.children.Where(x => x.Icon != null).Count() + 1;
            float currentExpansion = (float)(_expandProgress / iconCount);

            float expandedHeight = iconCount * (_iconSize.Y + _menuYPad);
            Vector2 menuPos = new Vector2(position.X + padding.X, position.Y - (expandedHeight * currentExpansion + _menuYPad));

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
                if (i >= _expandProgress)
                {
                    break;
                }
            }
            //Logging.WriteConsole(_expanded);
            if (_expanded && !ExpansionFinished)
            {
                _expandProgress += expansionPerFrame;
            }

            if (!_expanded && _expandProgress > 0)
            {
                _expandProgress -= expansionPerFrame;
            }

            _expandProgress = Math.Min(_expandProgress, iconCount);
            _expandProgress = Math.Max(_expandProgress, 0);
        }

        private MenuEntry? __activeEntry_; //todo wtf

        private MenuEntry? _activeEntry
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
                {
                    value.active = true;
                }

                __activeEntry_ = value;
            }
        }

        private void DrawMenuButton(MenuEntry entry, float Yoffset)
        {

            bool isActive = entry.Popup != null && ImGui.IsPopupOpen(entry.Popup);

            if (entry.Icon is not null)
            {
                Texture btnIcon = _controller.GetImage(entry.Icon);
                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd!.ResourceFactory, btnIcon, "QuickMenuSubButton");
                ImGui.SetCursorScreenPos(new Vector2(_menuBase.X, _menuBase.Y - Yoffset));
                Vector4 border = isActive ? new Vector4(1f, 1f, 1f, 1f) : Vector4.Zero;
                ImGui.Image(CPUframeBufferTextureId, _iconSize, Vector2.Zero, Vector2.One, Vector4.One, border);
            }

            if (!ExpansionFinished)
            {
                return;
            }

            ImGuiHoveredFlags flags = ImGuiHoveredFlags.AllowWhenBlockedByActiveItem |
                                      ImGuiHoveredFlags.AllowWhenOverlapped |
                                      ImGuiHoveredFlags.AllowWhenBlockedByPopup;
            if (ImGui.IsItemHovered(flags))
            {
                if (_activeEntry is null || _activeEntry != entry)
                {
                    if (_activeMenuPopupName != null)
                    {
                        if (_activeEntry is not null)
                        {
                            _activeEntry.active = false;
                        }

                        ImGui.CloseCurrentPopup();
                        _activeMenuPopupName = null;
                    }
                    entry.parent = _activeEntry;
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
            if (entry is not null && entry.active && entry.Popup != null)
            {
                if (_activeMenuPopupName != entry.Popup)
                {
                    _popupPos = new Vector2(_menuBase.X + 50, _menuBase.Y - (Yoffset + 50));
                    ImGui.OpenPopup(entry.Popup);
                    _activeMenuPopupName = entry.Popup;
                }
            }

        }

        private void DrawPopups()
        {
            ImGui.SetNextWindowPos(_popupPos, ImGuiCond.Appearing);

            if (_activeMenuPopupName == "VisibilityMenuPopup" && ImGui.BeginPopup("VisibilityMenuPopup"))
            {
                DrawVisibilityFrame();
                ImGui.EndPopup();
            }

            if (HighlightDialogWidget.PopoutHighlight)
            {
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
            Logging.WriteConsole($"Needreplot { _rgatstate._currentGraph.scalefactors.pix_per_A}");
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
        private float _replotSpread = 3;
        private void DrawGraphLayoutFrame()
        {
            Debug.Assert(_currentGraph is not null);
            if (_currentGraph.ActiveLayoutStyle == CONSTANTS.LayoutStyles.Style.Circle)
            {
                ImGui.Text("Circle Config Options");
            }

            if (_currentGraph.ActiveLayoutStyle == CONSTANTS.LayoutStyles.Style.CylinderLayout)
            {
                DrawCylinderOptions();
            }

            if (CONSTANTS.LayoutStyles.IsForceDirected(_currentGraph.ActiveLayoutStyle))
            {
                DrawForceDirectedOptions();
            }
        }

        private void DrawCylinderOptions()
        {
            ImGui.Text("Cylinder Layout Configuration");
            PlottedGraph? graph = this._currentGraph;
            if (graph is null) return;

            float radius = graph.OPT_CYLINDER_RADIUS;
            if (ImGui.DragFloat("Radius", ref radius, 200, 10, 100000))
            {
                graph.OPT_CYLINDER_RADIUS = radius;
                InitGraphCylinderLayoutReplot();
            }

            float APix = graph.OPT_CYLINDER_PIXELS_PER_A;
            if (ImGui.DragFloat("A Pix", ref APix, 1, 1, 10000))
            {
                graph.OPT_CYLINDER_PIXELS_PER_A = APix;
                InitGraphCylinderLayoutReplot();
            }

            float BPix = graph.OPT_CYLINDER_PIXELS_PER_B;
            if (ImGui.DragFloat("B Pix", ref BPix, 1, 1, 10000))
            {
                graph.OPT_CYLINDER_PIXELS_PER_B = BPix;
                InitGraphCylinderLayoutReplot();
            }

            float wfTransparen = 1 - graph.OPT_WIREFRAME_ALPHA;
            if (ImGui.DragFloat("Wireframe Transparency", ref wfTransparen, 0.01f, 0, 1))
            {
                graph.OPT_WIREFRAME_ALPHA = 1 - wfTransparen;
                InitGraphCylinderLayoutReplot();
            }
        }


        private void DrawForceDirectedOptions()
        {
            bool spreadHighlight = false;
            if (ImGui.Button("Rerender: Scatter"))
            {
                InitGraphForceLayoutReplot(resetStyle: GraphLayoutState.PositionResetStyle.Scatter, _replotSpread);
            }
            if (ImGui.IsItemHovered())
            {
                spreadHighlight = true;
                ImGui.SetTooltip("Scatter the nodes randomly. Control how far apart by adjusting the Replotting Spread");
            }
            ImGui.SameLine();
            if (ImGui.Button("Rerender: Explode"))
            {
                spreadHighlight = true;
                InitGraphForceLayoutReplot(resetStyle: GraphLayoutState.PositionResetStyle.Explode);
            }
            if (ImGui.IsItemHovered())
            {
                spreadHighlight = true;
                ImGui.SetTooltip("Scatter the nodes randomly. Control how far apart by adjusting the Replotting Spread");
            }
            ImGui.SameLine();
            if (ImGui.Button("Rerender: Implode"))
            {
                InitGraphForceLayoutReplot(resetStyle: GraphLayoutState.PositionResetStyle.Implode, _replotSpread);
            }
            if (ImGui.IsItemHovered())
            {
                spreadHighlight = true;
                ImGui.SetTooltip("Scatter the nodes randomly. Control how far apart by adjusting the Replotting Spread");
            }
            if (ImGui.Button("Rerender: Pillar"))
            {
                InitGraphForceLayoutReplot(resetStyle: GraphLayoutState.PositionResetStyle.Pillar, _replotSpread);
            }
            if (ImGui.IsItemHovered())
            {
                spreadHighlight = true;
                ImGui.SetTooltip("Scatter the nodes randomly. Control how far apart by adjusting the Replotting Spread");
            }


            if (ImGui.BeginTable("ComputationSelectNodes", 2, ImGuiTableFlags.RowBg))
            {
                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("All Computation:");
                ImGui.TableNextColumn();
                if (SmallWidgets.ToggleButton("#ComputeActive", GlobalConfig.LayoutAllComputeEnabled, "Toggle GPU-based plot updates"))
                {
                    GlobalConfig.LayoutAllComputeEnabled = !GlobalConfig.LayoutAllComputeEnabled;
                }

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Display Computation:");
                ImGui.TableNextColumn();
                if (SmallWidgets.ToggleButton("#ComputeAttrib", GlobalConfig.LayoutAttribsActive, "Toggle the computation of transparency and animation effects", isEnabled: GlobalConfig.LayoutAllComputeEnabled))
                {
                    GlobalConfig.LayoutAttribsActive = !GlobalConfig.LayoutAttribsActive;
                }

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Layout Computation:");
                ImGui.TableNextColumn();
                if (SmallWidgets.ToggleButton("#ComputePosVel", GlobalConfig.LayoutPositionsActive, "Toggle the computation of graph layout", isEnabled: GlobalConfig.LayoutAllComputeEnabled))
                {
                    GlobalConfig.LayoutPositionsActive = !GlobalConfig.LayoutPositionsActive;
                }

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Max Node Speed");
                ImGui.TableNextColumn();
                ImGui.SetNextItemWidth(150);
                ImGui.SliderFloat("##MaxNodeSpeed", ref GlobalConfig.NodeSoftSpeedLimit, 0, GlobalConfig.NodeHardSpeedLimit);

                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                if (spreadHighlight)
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.eTextEmphasis2));
                else
                    ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourImGui(ImGuiCol.Text));
                ImGui.Text("Replotting Spread");
                ImGui.PopStyleColor();
                ImGui.TableNextColumn();
                ImGui.SetNextItemWidth(150);
                ImGui.SliderFloat("##_replotSpread", ref _replotSpread, 0.001f, 5f);



                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Edge Attraction");
                ImGui.TableNextColumn();
                ImGui.SetNextItemWidth(150);
                ImGui.SliderFloat("##AttractionK", ref GlobalConfig.AttractionK, 0.001f, 1000);



                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text("Node Repulsion");
                ImGui.TableNextColumn();
                ImGui.SetNextItemWidth(150);
                ImGui.SliderFloat("##RepulsionK", ref GlobalConfig.RepulsionK, 0.001f, 1000);


                ImGui.EndTable();
            }
        }



        private void InitGraphForceLayoutReplot(GraphLayoutState.PositionResetStyle resetStyle, float spread = 2f)
        {
            if (_currentGraph is not null)
            {
                _currentGraph.LayoutState.ResetForceLayout(resetMethod: resetStyle, spread);
                _currentGraph.BeginNewLayout();
            }
        }


        private void InitGraphCylinderLayoutReplot()
        {
            if (_currentGraph is not null && _currentGraph.LayoutState.ActivatingPreset is false)
            {
                _currentGraph.LayoutState.TriggerLayoutChange(CONSTANTS.LayoutStyles.Style.CylinderLayout, forceSame: true);
            }
        }


        private void DrawSearchHighlightFrame()
        {
            if (_currentGraph is not null)
            {
                HighlightDialogWidget.Draw(_currentGraph);
            }
        }
    }
}
