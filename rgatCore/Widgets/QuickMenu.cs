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
        bool _expanded;
        bool _stayExpanded;

        bool ExpansionFinished => Math.Floor(_expandProgress) == _menuEntries.Count;
        public bool Expanded => _expanded;

        float _expandProgress = 0f;
        string _popupShown;
        Vector2 _popupPos = Vector2.Zero;
        Vector2 _menuBase = Vector2.Zero;
        Vector2 _iconSize = Vector2.Zero;

        GraphicsDevice _gd;
        HighlightDialog HighlightDialogWidget = null;
        List<MenuEntry> _menuEntries = new List<MenuEntry>();

        struct MenuEntry
        {
            public string IconName;
            public string PopupName;
            public string ToolTip;
        }

        public QuickMenu(Vector2 size, GraphicsDevice gd, ImGuiController controller)
        {
            _gd = gd;
            _controller = controller;
            HighlightDialogWidget = new HighlightDialog();

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
        }

        public void CancelPressed()
        {
            _expanded = false;
            if (_popupShown != null)
            {
                ImGui.CloseCurrentPopup();
                _popupShown = null;
            }
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
                _popupShown = null;
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

            if (_popupShown != null)
            {
                DrawPopups(graph);
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
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(0.1f, 0.3f, 0.6f, 0.5f));
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.1f, 0.3f, 0.6f, 0.5f));
            ImGui.Button(" ", new Vector2(_iconSize.X, expandedHeight * currentExpansion));
            ImGui.PopStyleColor();
            ImGui.PopStyleColor();
            ImGui.PopStyleVar();

            if (_expanded && _popupShown == null && !ImGui.IsItemHovered() && ExpansionFinished && !_stayExpanded)
            {
                Contract();
                return;
            }

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

                if (_popupShown != popupName)
                {
                    if (popupName != null)
                    {
                        _popupPos = new Vector2(_menuBase.X + 50, _menuBase.Y - Yoffset);
                        ImGui.OpenPopup(popupName);
                    }
                    _popupShown = popupName;
                }
            }

        }

        void DrawPopups(PlottedGraph graph)
        {
            ImGui.SetNextWindowPos(_popupPos);
            if (ImGui.BeginPopup("VisibilityMenuPopup", ImGuiWindowFlags.AlwaysAutoResize))
            {
                DrawVisibilityFrame(graph);
                ImGui.EndPopup();
            }

            ImGui.SetNextWindowPos(_popupPos);
            if (ImGui.BeginPopup("SearchMenuPopup", ImGuiWindowFlags.AlwaysAutoResize))
            {
                DrawSearchHighlightFrame(graph);
                ImGui.EndPopup();
            }

            if (_popupShown != null && !ImGui.IsPopupOpen(_popupShown))
            {
                _popupShown = null;
            }
        }

        void DrawVisibilityFrame(PlottedGraph activeGraph)
        {
            string tooltip = "Toggle display of graph edges.Current Keybind: [E]";
            ImGui.Text("Show Edges");
            if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
            ImGui.SameLine();
            if (SmallWidgets.ToggleButton("edgesToggle", activeGraph.EdgesVisible, tooltip))
                activeGraph.EdgesVisible = !activeGraph.EdgesVisible;

            tooltip = "Toggle display of graph instruction nodes. Current Keybind: [N]";
            ImGui.Text("Show Nodes");
            if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
            ImGui.SameLine();
            if (SmallWidgets.ToggleButton("nodes", activeGraph.NodesVisible, tooltip))
                activeGraph.NodesVisible = !activeGraph.NodesVisible;

            tooltip = "Toggle display of all graph text. Current Keybind: [I]";
            ImGui.Text("Enable Text");
            if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
            ImGui.SameLine();
            if (SmallWidgets.ToggleButton("textenable", activeGraph.TextEnabled, tooltip))
                activeGraph.TextEnabled = !activeGraph.TextEnabled;

            tooltip = "Toggle display of graph node instruction text. Current Keybind: [Shift-I]";
            ImGui.Text("Instruction Text");
            if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
            ImGui.SameLine();
            if (SmallWidgets.ToggleButton("textenable_ins", activeGraph.TextEnabledIns, tooltip))
                activeGraph.TextEnabledIns = !activeGraph.TextEnabledIns;
            //_size = ImGui.GetWindowSize();
        }


        void DrawSearchHighlightFrame(PlottedGraph activeGraph)
        {
            ImGui.SetNextWindowSizeConstraints(HighlightDialog.InitialSize, new Vector2(HighlightDialog.InitialSize.X + 400, HighlightDialog.InitialSize.Y + 500));
            HighlightDialogWidget.Draw(activeGraph);
        }
    }
}
