﻿using ImGuiNET;
using System;
using System.Numerics;
using Veldrid;

namespace rgat.Widgets
{
    internal class SmallWidgets
    {

        //unmaintainable hellmess
        public static void ProgressBar(string id, string caption, float progress, Vector2 barSize, uint barColour, 
            uint BGColour = 0, uint textColour = 0xffffffff)
        {
            Vector2 origCursorPos = ImGui.GetCursorPos();
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 6));
            ImGui.InvisibleButton(id, barSize);
            ImGui.SetCursorScreenPos(new Vector2(ImGui.GetWindowPos().X + origCursorPos.X, ImGui.GetCursorScreenPos().Y));

            const float vertPadding = 3;
            Vector2 start = new Vector2(ImGui.GetCursorScreenPos().X, ImGui.GetCursorScreenPos().Y - barSize.Y - vertPadding * 2);
            Vector2 end = new Vector2(start.X + barSize.X, start.Y + barSize.Y);
            ImGui.GetWindowDrawList().AddRectFilled(start, end, BGColour);

            Vector2 startInner = new Vector2(start.X, start.Y + vertPadding);
            Vector2 endInner = new Vector2(startInner.X + (barSize.X * progress), startInner.Y + (barSize.Y - 2 * vertPadding));
            ImGui.GetWindowDrawList().AddRectFilled(startInner, endInner, barColour);

            Vector2 textSize = ImGui.CalcTextSize(caption);
            float halfCaptionWidth = textSize.X / 2;

            Vector2 textpos = new Vector2(startInner.X + barSize.X / 2 - halfCaptionWidth, startInner.Y + 1);
            ImGui.GetWindowDrawList().AddText(textpos, textColour, caption);
            ImGui.PopStyleVar();
        }

        private static uint _lastActiveID;
        private static DateTime _LastActiveIdTimer;

        private static float ImSaturate(float f) { return (f < 0.0f) ? 0.0f : (f > 1.0f) ? 1.0f : f; }

        //adapted from code somewhere from imgui internal
        public static bool ToggleButton(string str_id, bool isToggled, string? tooltip, bool isEnabled = true)
        {
            const uint TOGGLE_OFF_HOVER_COL = 0xff888888;
            const uint TOGGLE_ON_HOVER_COL = 0xff008800;
            const uint TOGGLE_OFF_NOHOVER_COL = 0xff686868;
            const uint TOGGLE_ON_NOHOVER_COL = 0xff005500;

            Vector2 p = ImGui.GetCursorScreenPos();
            ImDrawListPtr draw_list = ImGui.GetWindowDrawList();

            float height = ImGui.GetFrameHeight() - 2;
            float width = height * 1.55f;
            float radius = height * 0.50f;

            ImGui.InvisibleButton(str_id, new Vector2(width, height));
            bool changed = isEnabled && ImGui.IsItemClicked();
            if (changed)
            {
                _lastActiveID = ImGui.GetID(str_id);
                _LastActiveIdTimer = DateTime.UtcNow;
            }
            if (tooltip != null && ImGui.IsItemHovered())
            {
                ImGui.BeginTooltip();
                ImGui.Text(tooltip);
                ImGui.EndTooltip();
            }

            float t = isToggled ? 1.0f : 0.0f;

            float ANIM_SPEED = 0.08f;
            if (_lastActiveID == ImGui.GetID(str_id))
            {
                float t_anim = ImSaturate((float)(DateTime.UtcNow - _LastActiveIdTimer).TotalSeconds / ANIM_SPEED);
                t = isToggled ? (t_anim) : (1.0f - t_anim);
                if (t == 0f || t == 1.0f) { _lastActiveID = 0; }
            }

            uint col_bg, col_btn;
            if (isEnabled)
            {
                if (ImGui.IsItemHovered())
                {
                    col_bg = isToggled ? TOGGLE_ON_HOVER_COL : TOGGLE_OFF_HOVER_COL;
                }
                else
                {
                    col_bg = isToggled ? TOGGLE_ON_NOHOVER_COL : TOGGLE_OFF_NOHOVER_COL;
                }

                col_btn = 0xffffffff;
            }
            else
            {
                col_btn = 0xff909090;
                col_bg = 0xff454545;
            }
            draw_list.AddRectFilled(p, new Vector2(p.X + width, p.Y + height), col_bg, height * 0.5f);
            draw_list.AddCircleFilled(new Vector2(p.X + radius + t * (width - radius * 2.0f), p.Y + radius), radius - 1.5f, col_btn);

            return changed;
        }


        public static bool ImageCaptionButton(IntPtr TextureId, Vector2 iconsize, float width, string caption, bool isSelected)
        {

            bool isMouseHover = ImGui.IsMouseHoveringRect(ImGui.GetCursorScreenPos(), ImGui.GetCursorScreenPos() + new Vector2(width, iconsize.Y));
            if (isSelected)
            {
                ImGui.PushStyleColor(ImGuiCol.ChildBg, 0x45d5d5d5);
            }
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

        private static Vector2 ImRotate(Vector2 v, float cos_a, float sin_a)
        {
            return new Vector2(v.X * cos_a - v.Y * sin_a, v.X * sin_a + v.Y * cos_a);
        }


        public static void DrawSpinner(ImGuiController controller, int count, uint colour)
        {
            if (controller._fontTexture is null) return;

            ImFontGlyphPtr glyph = controller.UnicodeFont.FindGlyph(ImGuiController.FA_ICON_ROTATION);

            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, Vector2.Zero);
            IntPtr CPUframeBufferTextureId = controller.GetOrCreateImGuiBinding(controller.GraphicsDevice.ResourceFactory, controller._fontTexture, "Spinner");
            ImGui.SetCursorPos(ImGui.GetCursorPos() + new Vector2(3, 3));
            Vector2 size = new Vector2(18, 18);
            Vector2 corner = ImGui.GetCursorScreenPos() + new Vector2(0, size.Y);
            Vector2 center = corner + new Vector2(size.X * 0.5f, size.Y * -0.5f);

            float rotation = -1 * ((float)DateTime.Now.TimeOfDay.TotalMilliseconds / 360);
            float cos_a = (float)Math.Cos(rotation);
            float sin_a = (float)Math.Sin(rotation);

            Vector2[] pos = new Vector2[]
            {
                center + ImRotate(new Vector2(-size.X, -size.Y) * 0.5f, cos_a, sin_a),
                center + ImRotate(new Vector2(+size.X, -size.Y) * 0.5f, cos_a, sin_a),
                center + ImRotate(new Vector2(+size.X, +size.Y) * 0.5f, cos_a, sin_a),
                center + ImRotate(new Vector2(-size.X, +size.Y) * 0.5f, cos_a, sin_a)
            };

            ImGui.GetWindowDrawList().AddImageQuad(CPUframeBufferTextureId, pos[0], pos[1], pos[2], pos[3],
                new Vector2(glyph.U0, glyph.V0) , new Vector2(glyph.U1, glyph.V0), new Vector2(glyph.U1, glyph.V1), new Vector2(glyph.U0, glyph.V1), colour);
            if (count > 1)
            {
                ImGui.SetCursorPos(ImGui.GetCursorPos() + new Vector2(size.X, 4));
                ImGui.Text($"{count}");
                ImGui.SetCursorPosY(ImGui.GetCursorPosY() - size.Y);
                ImGui.InvisibleButton($"#invisBtn{rotation}", new Vector2(18, 18));
            }
            else
            {
                //tooltip hover target
                ImGui.InvisibleButton($"#invisBtn{rotation}", new Vector2(18, 24));
            }
           
            ImGui.PopStyleVar();
        }


        public static void DrawIcon(ImGuiController controller, string name, int countCaption = 1, Vector2? offset = null)
        {
            Texture btnIcon = controller.GetImage(name);
            IntPtr CPUframeBufferTextureId = controller.GetOrCreateImGuiBinding(controller.GraphicsDevice.ResourceFactory, btnIcon, $"Icon" + name);

            Vector2 size = new Vector2(btnIcon.Width, btnIcon.Height);
            Vector2 corner = ImGui.GetCursorScreenPos() + (offset ?? Vector2.Zero);

            ImGui.GetWindowDrawList().AddImage(CPUframeBufferTextureId, corner, corner + size, Vector2.Zero, Vector2.One);
            if (countCaption > 1)
            {
                ImGui.SetCursorScreenPos(corner + new Vector2(size.X * 0.8f, 5));
                ImGui.Text($"{countCaption}");
            }
        }

        public static void DrawIcon(string textIcon, uint colour, int countCaption = 1, Vector2? offset = null)
        {
            Vector2 start = ImGui.GetCursorPos();
            ImGui.SetCursorPos(start + new Vector2(4, 2));
            Vector2 corner = start + (offset ?? Vector2.Zero);

            ImGui.PushStyleColor(ImGuiCol.Text, colour);
            ImGui.Text(textIcon);
            ImGui.PopStyleColor();
            if (countCaption > 1)
            {
                ImGui.SetCursorPos(start + new Vector2(18, 10));
                ImGui.Text($"{countCaption}");
            }
        }

        //No longer used
        public static void DrawClickableIcon(ImGuiController controller, string name, int countCaption = 1, Vector2? offset = null)
        {
            Texture btnIcon = controller.GetImage(name);
            IntPtr CPUframeBufferTextureId = controller.GetOrCreateImGuiBinding(controller.GraphicsDevice.ResourceFactory, btnIcon, $"ClickIcon" + name);

            Vector2 size = new Vector2(btnIcon.Width, btnIcon.Height);
            Vector2 thispos = ImGui.GetCursorScreenPos();
            ImGui.InvisibleButton($"#{name + ImGui.GetCursorPosY()}", size + new Vector2(-2, -4));

            uint iconcol = ImGui.IsItemHovered() ? 0xaaafafaf : 0xffffffff;
            ImGui.SetCursorScreenPos(thispos);
            Vector2 corner = ImGui.GetCursorScreenPos() + offset ?? Vector2.Zero;
            ImGui.GetWindowDrawList().AddImage(CPUframeBufferTextureId, corner, corner + size, Vector2.Zero, Vector2.One, iconcol);
            if (countCaption > 1)
            {
                ImGui.SetCursorScreenPos(corner + new Vector2(size.X * 0.8f, 5));
                ImGui.Text($"{countCaption}");
            }
        }

        public static void MouseoverText(string? text)
        {

            if (text is not null && text.Length > 0 && ImGui.IsItemHovered())
            {
                ImGui.PushStyleColor(ImGuiCol.Text, Themes.GetThemeColourUINT(Themes.eThemeColour.WindowText));
                ImGui.PushStyleColor(ImGuiCol.FrameBg, Themes.GetThemeColourUINT(Themes.eThemeColour.Frame));
                ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(6, 5));
                ImGui.SetTooltip(text);
                ImGui.PopStyleVar();
                ImGui.PopStyleColor(2);
            }
        }

        public static bool DisableableButton(string text, bool enabled, Vector2? size = null)
        {
            bool activated = false;
            if (!enabled)
            {
                ImGui.PushStyleColor(ImGuiCol.Button, Themes.GetThemeColourUINT(Themes.eThemeColour.Dull2));
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, Themes.GetThemeColourUINT(Themes.eThemeColour.Dull2));
                ImGui.PushStyleColor(ImGuiCol.ButtonActive, Themes.GetThemeColourUINT(Themes.eThemeColour.Dull2));
            }

            activated = (size.HasValue) ? ImGui.Button(text, size.Value) : ImGui.Button(text);

            if (!enabled)
            {
                ImGui.PopStyleColor(3);
            }

            return enabled && activated;
        }
    }
}
