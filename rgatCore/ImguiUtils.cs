/*
 * 
 *Mostly taken from  https://github.com/ocornut/imgui/blob/master/imgui_demo.cpp
 *and https://github.com/ocornut/imgui/blob/fed80b95375f716536ceaa3c5e8b21c96e150bff/imgui_widgets.cpp
 */
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Numerics;
using System.Text;
using Veldrid;

namespace rgatCore
{
    class ImguiUtils
    {
        public static void DrawHorizCenteredText(String msg)
        {
            Vector2 textSize = ImGui.CalcTextSize(msg);
            
            ImGui.SetCursorPosX(ImGui.GetCursorPosX() + (ImGui.GetContentRegionAvail().X/2) - (textSize.X/2));
            ImGui.Text(msg);
        }

        public static void DrawRegionCenteredText(String msg)
        {
            ImGui.SetCursorPosX(ImGui.GetContentRegionAvail().X / 2 - ImGui.CalcTextSize(msg).X / 2);
            ImGui.SetCursorPosY(ImGui.GetContentRegionAvail().Y / 2 - ImGui.CalcTextSize(msg).Y / 2);
            ImGui.Text(msg);
        }


        public static void HelpMarker(string desc)
        {
            ImGui.TextDisabled("(?)");
            if (ImGui.IsItemHovered())
            {
                ImGui.BeginTooltip();
                ImGui.PushTextWrapPos(ImGui.GetFontSize() * 35.0f);
                ImGui.TextUnformatted(desc);
                ImGui.PopTextWrapPos();
                ImGui.EndTooltip();
            }
        }

        public static float ImSaturate(float f) { return (f < 0.0f) ? 0.0f : (f > 1.0f) ? 1.0f : f; }
        public static int IM_F32_TO_INT8_SAT(float _VAL) { return ((int)(ImSaturate(_VAL) * 255.0f + 0.5f)); }
        public static uint v4_to_uint(Vector4 _VAL) { return (uint)((uint)_VAL.W << 24) | ((uint)_VAL.X << 16) | ((uint)_VAL.Y << 8) | (uint)_VAL.Z; }

        public static unsafe void RenderArrowPointingAt(ImDrawListPtr draw_list, Vector2 pos, Vector2 half_sz, ImGuiDir direction, Vector4 col)
        {
            uint testcol = v4_to_uint(col);
            switch (direction)
            {
                case ImGuiDir.Left: draw_list.AddTriangleFilled(new Vector2(pos.X + half_sz.X, pos.Y - half_sz.Y), new Vector2(pos.X + half_sz.X, pos.Y + half_sz.Y), pos, v4_to_uint(col)); return;
                case ImGuiDir.Right: draw_list.AddTriangleFilled(new Vector2(pos.X - half_sz.X, pos.Y + half_sz.Y), new Vector2(pos.X - half_sz.X, pos.Y - half_sz.Y), pos, v4_to_uint(col)); return;
                case ImGuiDir.Up: draw_list.AddTriangleFilled(new Vector2(pos.X + half_sz.X, pos.Y + half_sz.Y), new Vector2(pos.X - half_sz.X, pos.Y + half_sz.Y), pos, v4_to_uint(col)); return;
                case ImGuiDir.Down: draw_list.AddTriangleFilled(new Vector2(pos.X - half_sz.X, pos.Y - half_sz.Y), new Vector2(pos.X + half_sz.X, pos.Y - half_sz.Y), pos, v4_to_uint(col)); return;
                case ImGuiDir.None: 
                case ImGuiDir.COUNT: 
                    break; // Fix warnings
            }
        }

        //made the colours gross for dev, fix as needed
        public static unsafe void RenderArrowsForVerticalBar(ImDrawListPtr draw_list, Vector2 pos, Vector2 half_sz, float bar_w, float alpha)
        {
            int alpha8 = IM_F32_TO_INT8_SAT(alpha);
            RenderArrowPointingAt(draw_list, new Vector2(pos.X + half_sz.X + 1, pos.Y), new Vector2(half_sz.X , half_sz.Y), ImGuiDir.Right, new Vector4(255, 255, 255, alpha8));
            RenderArrowPointingAt(draw_list, new Vector2(pos.X + half_sz.X, pos.Y), half_sz, ImGuiDir.Right, new Vector4(145, 0, 145, alpha8));

            RenderArrowPointingAt(draw_list, new Vector2(pos.X + bar_w - half_sz.X - 1, pos.Y), new Vector2(half_sz.X + 2, half_sz.Y + 1), ImGuiDir.Left, new Vector4(255f, 255f, 255f, alpha8));
            RenderArrowPointingAt(draw_list, new Vector2(pos.X + bar_w - half_sz.X, pos.Y),     half_sz,                                   ImGuiDir.Left, new Vector4(145f, 0, 145f, alpha8));
        }

        public static unsafe void RenderArrowsForHorizontalBar(ImDrawListPtr draw_list, Vector2 pos, Vector2 half_sz, float bar_w, float alpha)
        {
            Vector4 OuterColor = new Vector4(255f, 255f, 255f, alpha);
            Vector4 InnerColor = new Vector4(145f, 0f, 145f, alpha);

            RenderArrowPointingAt(draw_list, new Vector2(pos.X, pos.Y + half_sz.Y + 1),         half_sz, ImGuiDir.Down, OuterColor);
            RenderArrowPointingAt(draw_list, new Vector2(pos.X, pos.Y + half_sz.Y),             half_sz, ImGuiDir.Down, InnerColor);

            RenderArrowPointingAt(draw_list, new Vector2(pos.X, pos.Y + bar_w - 1), half_sz, ImGuiDir.Up, OuterColor);
            RenderArrowPointingAt(draw_list, new Vector2(pos.X, pos.Y + bar_w),     half_sz, ImGuiDir.Up, InnerColor);

            draw_list.AddLine(new Vector2(pos.X, pos.Y + half_sz.Y + 1), new Vector2(pos.X, pos.Y + bar_w + 1), 0xffffffff);
        }

        public static Veldrid.RgbaFloat ColToRgbaF(Color inColour)
        {
            return new Veldrid.RgbaFloat(inColour.R, inColour.G, inColour.G, inColour.A);
        }

    }
}
