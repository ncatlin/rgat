using ImGuiNET;
using SharpDX.D3DCompiler;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace rgatCore
{
    class ImguiUtils
    {
        //todo - might not be used anymore
        public static void DrawCenteredText(String msg)
        {
            Vector2 textSize = ImGui.CalcTextSize(msg);
            Vector2 textStart = new Vector2(ImGui.GetWindowSize().X * 0.5f, ImGui.GetCursorPosY());
            textStart.X -= textSize.X / 2;

            ImGui.SetCursorPos(textStart);

            ImGui.Text(msg);

            textStart = new Vector2(ImGui.GetCursorPosX(), ImGui.GetCursorPosY() + textSize.Y);
            ImGui.SetCursorPos(textStart);
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

    }
}
