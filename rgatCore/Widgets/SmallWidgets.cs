using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using Veldrid;

namespace rgatCore.Widgets
{
    class SmallWidgets
    {
        public static void ProgressBar(string id, string caption, float progress, Vector2 barSize, uint barColour, uint BGColour)
        {

            ImGui.InvisibleButton(id, barSize);

            const float vertPadding = 2;
            Vector2 start = new Vector2(ImGui.GetCursorScreenPos().X, ImGui.GetCursorScreenPos().Y - barSize.Y - vertPadding * 2);
            Vector2 end = new Vector2(start.X + barSize.X, start.Y + barSize.Y);
            ImGui.GetWindowDrawList().AddRectFilled(start, end, BGColour);

            Vector2 startInner = new Vector2(start.X, start.Y + vertPadding);
            Vector2 endInner = new Vector2(startInner.X + (barSize.X * progress), startInner.Y + (barSize.Y - 2 * vertPadding));
            ImGui.GetWindowDrawList().AddRectFilled(startInner, endInner, barColour);


            Vector2 textSize = ImGui.CalcTextSize(caption);
            float halfCaptionWidth = textSize.X / 2;

            Vector2 textpos = new Vector2(startInner.X + barSize.X / 2 - halfCaptionWidth, startInner.Y);
            ImGui.GetWindowDrawList().AddText(textpos, 0xffffffff, caption);
        }


        static uint _lastActiveID;
        static DateTime _LastActiveIdTimer;
        static float ImSaturate(float f) { return (f < 0.0f) ? 0.0f : (f > 1.0f) ? 1.0f : f; }

        //adapted from code somewhere from imgui internal
        public static bool ToggleButton(string str_id, bool isToggled)
        {
            const uint TOGGLE_OFF_HOVER_COL = 0xff888888;
            const uint TOGGLE_ON_HOVER_COL = 0xff008800;
            const uint TOGGLE_OFF_NOHOVER_COL = 0xff686868;
            const uint TOGGLE_ON_NOHOVER_COL = 0xff005500;

            Vector2 p = ImGui.GetCursorScreenPos();
            ImDrawListPtr draw_list = ImGui.GetWindowDrawList();

            float height = ImGui.GetFrameHeight();
            float width = height * 1.55f;
            float radius = height * 0.50f;

            ImGui.InvisibleButton(str_id, new Vector2(width, height));
            bool changed = ImGui.IsItemClicked();
            if (changed)
            {
                _lastActiveID = ImGui.GetID(str_id);
                _LastActiveIdTimer = DateTime.UtcNow;
            }

            float t = isToggled ? 1.0f : 0.0f;

            float ANIM_SPEED = 0.08f;
            if (_lastActiveID == ImGui.GetID(str_id))
            {
                float t_anim = ImSaturate((float)(DateTime.UtcNow - _LastActiveIdTimer).TotalSeconds / ANIM_SPEED);
                t = isToggled ? (t_anim) : (1.0f - t_anim);
                if (t == 0f || t == 1.0f) { _lastActiveID = 0; }
            }

            uint col_bg;
            if (ImGui.IsItemHovered())
                col_bg = isToggled ? TOGGLE_ON_HOVER_COL : TOGGLE_OFF_HOVER_COL;
            else
                col_bg = isToggled ? TOGGLE_ON_NOHOVER_COL : TOGGLE_OFF_NOHOVER_COL;

            draw_list.AddRectFilled(p, new Vector2(p.X + width, p.Y + height), col_bg, height * 0.5f);
            draw_list.AddCircleFilled(new Vector2(p.X + radius + t * (width - radius * 2.0f), p.Y + radius), radius - 1.5f, 0xffffffff);
            return changed;
        }


        public static bool ImageCaptionButton(IntPtr TextureId, Vector2 iconsize, float width, string caption, bool isSelected)
        {
            
            bool isMouseHover = ImGui.IsMouseHoveringRect(ImGui.GetCursorScreenPos(), ImGui.GetCursorScreenPos() + new Vector2(width, iconsize.Y));
            if (isSelected)
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x45d5d5d5);
            else
            {
                if (isMouseHover)
                {
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff989898);
                }
                else
                {
                    ImGui.PushStyleColor(ImGuiCol.ChildBg, 0xff000000);
                }
            }

            bool clicked = false;
            Vector2 widgetSize = new Vector2(width, iconsize.Y + 4);
            if (ImGui.BeginChild(ImGui.GetID(caption + "ICB"), widgetSize, false, ImGuiWindowFlags.NoScrollbar))
            {
                Vector2 a = ImGui.GetCursorScreenPos() + new Vector2(5, 2);

                if (ImGui.InvisibleButton(caption + "IVB", widgetSize))
                {
                    clicked = true;
                }

                ImGui.SetCursorScreenPos(a);
                ImGui.Image(TextureId, iconsize);
                ImGui.SameLine(iconsize.X + 14);
                Vector2 iconPos = ImGui.GetCursorScreenPos();
                ImGui.SetCursorScreenPos(new Vector2(iconPos.X, iconPos.Y + 7));
                ImGui.Text(caption);
                ImGui.SetCursorScreenPos(iconPos);

                ImGui.EndChild();
            }
            ImGui.PopStyleColor();
            return clicked;
        }
    }
}
