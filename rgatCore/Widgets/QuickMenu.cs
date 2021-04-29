using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using Veldrid;

namespace rgatCore.Widgets
{
    class QuickMenu
    {
        ImGuiController _controller;
        bool _expanded; //true if menu is expanded or in the process of expanding.
        bool _stayExpanded; //otherwise only expanded on mouse hover of button or child menus

        bool ExpansionFinished => Math.Floor(_expandProgress) == _menuEntries.Count;
        public bool Expanded => _expanded;

        float _expandProgress = 0f;
        string _activeMenuPopupName;
        Vector2 _popupPos = Vector2.Zero;
        Vector2 _menuBase = Vector2.Zero;
        Vector2 _iconSize = Vector2.Zero;

        GraphicsDevice _gd;
        HighlightDialog HighlightDialogWidget = new HighlightDialog();
        List<MenuEntry> _menuEntries = new List<MenuEntry>();

        struct MenuEntry
        {
            public string IconName;
            public string PopupName;
            public string ToolTip;
        }

        public QuickMenu(GraphicsDevice gd, ImGuiController controller)
        {
            _gd = gd;
            _controller = controller;

            _menuEntries.Add(new MenuEntry
            {
                IconName = "Menu2",
                PopupName = null,
                ToolTip = "Menu (M)"
            });//todo - read keybind

            _menuEntries.Add(new MenuEntry
            {
                IconName = "Eye",
                PopupName = "VisibilityMenuPopup",
                ToolTip = "Visibility(V)"
            });

            _menuEntries.Add(new MenuEntry
            {
                IconName = "Search",
                PopupName = "SearchMenuPopup",
                ToolTip = "Search/Highlighting (S)"
            });

            _menuEntries.Add(new MenuEntry
            {
                IconName = "Force3D",
                PopupName = "GraphLayoutMenu",
                ToolTip = "Graph Layout (G)"
            });


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

        public void KeyPressed(Tuple<Key, ModifierKeys> keyModTuple)
        {

        }


        public void Expand(bool persistent = false)
        {
            if (_expanded == false && _expandProgress <= 0)
            {
                _expanded = true;
                _stayExpanded = persistent;
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
            }

        }



        public void Draw(Vector2 position, float scale, PlottedGraph graph)
        {
            Texture btnIcon = _controller.GetImage("Menu");
            _iconSize = new Vector2(btnIcon.Width * scale, btnIcon.Height * scale);

            if (_expandProgress == 0)
            {
                IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, btnIcon);
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
                DrawPopups(graph);
                ImGui.PopStyleColor();
            }

        }

        void DrawExpandedMenu(Vector2 position)
        {
            const float expansionPerFrame = 0.3f;
            Vector2 padding = new Vector2(16f, 6f);
            _menuBase = new Vector2((position.X) + padding.X, ((position.Y - _iconSize.Y) - 4) - padding.Y);

            float menuYPad = 8;
            float iconCount = _menuEntries.Count;
            float currentExpansion = (float)(_expandProgress / ((float)_menuEntries.Count));

            float expandedHeight = iconCount * (_iconSize.Y + menuYPad);
            Vector2 menuPos = new Vector2(position.X + padding.X, position.Y - (expandedHeight * currentExpansion + menuYPad));

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
            for (var i = 0; i < _menuEntries.Count; i++)
            {
                MenuEntry entry = _menuEntries[i];
                float progressAdjustedY = menuY * currentExpansion;
                DrawMenuButton(entry.IconName, entry.PopupName, entry.ToolTip, progressAdjustedY);
                menuY += (_iconSize.Y + menuYPad);
                if (i >= _expandProgress) break;
            }
            if (_expanded && !ExpansionFinished) _expandProgress += expansionPerFrame;
            if (!_expanded && _expandProgress > 0) _expandProgress -= expansionPerFrame;

            _expandProgress = Math.Min(_expandProgress, _menuEntries.Count);
            _expandProgress = Math.Max(_expandProgress, 0);
        }


        void DrawMenuButton(string iconName, string popupName, string tooltip, float Yoffset)
        {
            bool isActive = popupName != null && ImGui.IsPopupOpen(popupName);
            Texture btnIcon = _controller.GetImage(iconName);
            IntPtr CPUframeBufferTextureId = _controller.GetOrCreateImGuiBinding(_gd.ResourceFactory, btnIcon);
            ImGui.SetCursorScreenPos(new Vector2(_menuBase.X, _menuBase.Y - Yoffset));
            Vector4 border = isActive ? new Vector4(1f, 1f, 1f, 1f) : Vector4.Zero;
            ImGui.Image(CPUframeBufferTextureId, _iconSize, Vector2.Zero, Vector2.One, Vector4.One, border);

            if (!ExpansionFinished) return;

            ImGuiHoveredFlags flags = ImGuiHoveredFlags.AllowWhenBlockedByActiveItem |
                                      ImGuiHoveredFlags.AllowWhenOverlapped |
                                      ImGuiHoveredFlags.AllowWhenBlockedByPopup;
            if (ImGui.IsItemHovered(flags))
            {

                ImGui.BeginTooltip();
                ImGui.Text(tooltip);
                ImGui.EndTooltip();

                if (_activeMenuPopupName != popupName)
                {
                    if (popupName != null)
                    {
                        _popupPos = new Vector2(_menuBase.X + 50, _menuBase.Y - (Yoffset + 50));
                        ImGui.OpenPopup(popupName);
                    }
                    _activeMenuPopupName = popupName;
                }
            }

        }

        void DrawPopups(PlottedGraph graph)
        {
            ImGui.SetNextWindowPos(_popupPos, ImGuiCond.Appearing);

            if (ImGui.BeginPopup("VisibilityMenuPopup"))
            {
                DrawVisibilityFrame(graph);
                ImGui.EndPopup();
            }

            if (HighlightDialogWidget.PopoutHighlight)
            {
                bool ff = true;
                ImGui.SetNextWindowSize(new Vector2(500, 300), ImGuiCond.Appearing);
                ImGui.SetNextWindowSizeConstraints(new Vector2(500, 300), new Vector2(800, 700));
                if (ImGui.Begin("Search/Highlighting", ref HighlightDialogWidget.PopoutHighlight))
                {
                    DrawSearchHighlightFrame(graph);
                    ImGui.End();
                }
                return;
            }
            else
            {
                ImGui.SetNextWindowSize(new Vector2(500, 300), ImGuiCond.Always);
                ImGui.SetNextWindowPos(_popupPos, ImGuiCond.Appearing);
                ImGuiWindowFlags flags = ImGuiWindowFlags.None;
                if (ImGui.BeginPopup("SearchMenuPopup", flags))
                {
                    DrawSearchHighlightFrame(graph);
                    ImGui.EndPopup();
                }
            }

            if (ImGui.BeginPopup("GraphLayoutMenu"))
            {
                DrawGraphLayoutFrame(graph);
                ImGui.EndPopup();
            }


            if (_activeMenuPopupName != null && !ImGui.IsPopupOpen(_activeMenuPopupName))
            {
                _activeMenuPopupName = null;
            }
        }

        void DrawVisibilityFrame(PlottedGraph activeGraph)
        {

            if (ImGui.BeginChildFrame(324234, new Vector2(250, 160)))
            {

                ImGui.Columns(2, "visselcolumns", true);
                ImGui.SetColumnWidth(0, 180);
                ImGui.SetColumnWidth(1, 65);

                float width = ImGui.GetWindowContentRegionWidth();
                float rowHeight = 21;
                Vector2 selSize = new Vector2(width, rowHeight);

                string tooltip;
                tooltip = "Toggle display of graph edges.Current Keybind: [E]";
                if (ImGui.Selectable("Show Edges", false, ImGuiSelectableFlags.SpanAllColumns, selSize))
                {
                    activeGraph.EdgesVisible = !activeGraph.EdgesVisible;
                }
                if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
                ImGui.NextColumn();
                SmallWidgets.ToggleButton("edgesToggle", activeGraph.EdgesVisible, null);
                ImGui.NextColumn();

                tooltip = "Toggle display of graph instruction nodes. Current Keybind: [N]";
                if (ImGui.Selectable("Show Nodes", false, ImGuiSelectableFlags.SpanAllColumns, selSize))
                {
                    activeGraph.NodesVisible = !activeGraph.NodesVisible;
                }
                if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
                ImGui.NextColumn();
                SmallWidgets.ToggleButton("nodesToggle", activeGraph.NodesVisible, null);
                ImGui.NextColumn();

                tooltip = "Toggle display of all graph text. Current Keybind: [I]";
                if (ImGui.Selectable("Enable Text", false, ImGuiSelectableFlags.SpanAllColumns, selSize))
                {
                    activeGraph.TextEnabled = !activeGraph.TextEnabled;
                }
                if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
                ImGui.NextColumn();
                SmallWidgets.ToggleButton("textenable", activeGraph.TextEnabled, null);
                ImGui.NextColumn();

                tooltip = "Toggle display of graph node instruction text. Current Keybind: [Shift-I]";
                if (ImGui.Selectable("Instruction Text", false, ImGuiSelectableFlags.SpanAllColumns, selSize))
                {
                    activeGraph.TextEnabledIns = !activeGraph.TextEnabledIns;
                }
                if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
                ImGui.NextColumn();
                SmallWidgets.ToggleButton("textenable_ins", activeGraph.TextEnabledIns, null);
                ImGui.NextColumn();

                tooltip = "Display a highlight line indicating the most recently executed instruction";

                if (ImGui.Selectable("Active Node Highlight", false, ImGuiSelectableFlags.SpanAllColumns, selSize))
                {
                    activeGraph.LiveNodeEdgeEnabled = !activeGraph.LiveNodeEdgeEnabled;
                }
                if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
                ImGui.NextColumn();
                SmallWidgets.ToggleButton("livenodeedge_enabled", activeGraph.LiveNodeEdgeEnabled, null);

                ImGui.Columns(1);
                ImGui.EndChildFrame();
            }

        }


        void DrawGraphLayoutFrame(PlottedGraph activeGraph)
        {
            if (activeGraph.LayoutStyle == eGraphLayout.eCircle)
            {
                ImGui.Text("Circle Config Options");
            }

            if (activeGraph.LayoutStyle == eGraphLayout.eCylinderLayout)
            {
                ImGui.Text("Cylinder Config Options");
            }

            if (activeGraph.LayoutStyle == eGraphLayout.eForceDirected3DBlocks)
            {
                ImGui.Text("ForceDirected3DBlocks Config Options");
            }

            if (activeGraph.LayoutStyle == eGraphLayout.eForceDirected3DNodes)
            {
                ImGui.Text("eForceDirected3DNodes Config Options");
            }
        }

        void DrawSearchHighlightFrame(PlottedGraph activeGraph)
        {
            HighlightDialogWidget.Draw(activeGraph);
        }
    }
}
