using ImGuiNET;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace rgat
{
    /// <summary>
    /// User customisable themes
    /// </summary>
    public class Themes
    {

        /// <summary>
        /// UI and Graph properties that can have a custom theme colour
        /// </summary>
        public enum eThemeColour
        {   // ---------------
            //
            //Widget Colours
            //
            // ---------------

            /// <summary>
            /// The base background for the UI
            /// </summary>
            WindowBackground,
            /// <summary>
            /// Text on the background
            /// </summary>
            WindowText,
            /// <summary>
            /// A region on the base background which needs to contrast with it
            /// </summary>
            Frame,
            /// <summary>
            /// An interactable element
            /// </summary>
            Control,
            /// <summary>
            /// Text on a control
            /// </summary>
            ControlText,
            /// <summary>
            /// The top menu
            /// </summary>
            MenuBar,
            /// <summary>
            /// Text on the top menu
            /// </summary>
            MenuBarText,
            /// <summary>
            /// Table rows (alternate 1)
            /// </summary>
            TableRow,
            /// <summary>
            /// Table rows (alternate 2)
            /// </summary>
            TableRowAlt,

            /// <summary>
            /// Labels on preview graphs
            /// </summary>
            PreviewText,
            /// <summary>
            /// The background of text on preview graphs to provide contrast
            /// </summary>
            PreviewTextBackground,
            /// <summary>
            /// The border of the preview pane
            /// </summary>
            PreviewPaneBorder,
            /// <summary>
            /// The background of the preview pane
            /// </summary>
            PreviewPaneBackground,
            /// <summary>
            /// The box used to show the camera location in the preview pane
            /// </summary>
            PreviewZoomEnvelope,
            /// <summary>
            /// The background of running thread preview graphs
            /// </summary>
            PreviewBGRunning,
            /// <summary>
            /// The background of terminated thread preview graphs
            /// </summary>
            PreviewBGTerminated,
            /// <summary>
            /// The background of suspended thread preview graphs
            /// </summary>
            PreviewBGSuspended,
            /// <summary>
            /// Emphasised element style 1
            /// </summary>
            Emphasis1,
            /// <summary>
            /// Emphasised element style 2
            /// </summary>
            Emphasis2,
            /// <summary>
            /// Subtle/inactive element style 1
            /// </summary>
            Dull1,
            /// <summary>
            /// Subtle/inactive element style 2
            /// </summary>
            Dull2,            
            /// <summary>
            /// The background of the alert box
            /// </summary>
            AlertWindowBg,
            /// <summary>
            /// The border of the alert box
            /// </summary>
            AlertWindowBorder,
            /// <summary>
            /// Colour for bad events/errors
            /// </summary>
            BadStateColour,
            /// <summary>
            /// Colour for warnings
            /// </summary>
            WarnStateColour,
            /// <summary>
            /// Colour for successful events
            /// </summary>
            GoodStateColour,
            /// <summary>
            /// Background of the analysis chart
            /// </summary>
            SandboxChartBG,

            /// ---------------
            //
            //Graph/Rendered Colours
            //
            // ---------------
            /// <summary>
            /// The lowest 10% active instructions
            /// </summary>
            Heat0Lowest,
            /// <summary>
            /// 10-19% most active instructions
            /// </summary>
            Heat1,
            /// <summary>
            /// 20-29% most active instructions
            /// </summary>
            Heat2,
            /// <summary>
            /// 30-39% most active instructions
            /// </summary>
            Heat3,
            /// <summary>
            /// 40-49% most active instructions
            /// </summary>
            Heat4,
            /// <summary>
            /// 50-59% most active instructions
            /// </summary>
            Heat5,
            /// <summary>
            /// 60-69% most active instructions
            /// </summary>
            Heat6,
            /// <summary>
            /// 70-79% most active instructions
            /// </summary>
            Heat7,
            /// <summary>
            /// 80-89% most active instructions
            /// </summary>
            Heat8,
            /// <summary>
            /// The top 10% most active instructions
            /// </summary>
            Heat9Highest,
            /// <summary>
            /// The instruction count plot line on the visualisation bar
            /// </summary>
            VisBarPlotLine,
            /// <summary>
            /// The background of the visualiser bar
            /// </summary>
            VisBarBg,
            /// <summary>
            /// Background of the main graph visualiser
            /// </summary>
            GraphBackground,
            /// <summary>
            /// Colour of call edges
            /// </summary>
            edgeCall,
            /// <summary>
            /// Colour of edges to existing instructions
            /// </summary>
            edgeOld,
            /// <summary>
            /// Colour of return edges
            /// </summary>
            edgeRet,
            /// <summary>
            /// Colour of API call edges (to uninstrumented code)
            /// </summary>
            edgeLib,
            /// <summary>
            /// Colour of edges to new instructions
            /// </summary>
            edgeNew,
            /// <summary>
            /// Colour of exception edges
            /// </summary>
            edgeExcept,
            /// <summary>
            /// Colour of non-flow control nodes
            /// </summary>
            nodeStd,
            /// <summary>
            /// Colour of jump nodes
            /// </summary>
            nodeJump,
            /// <summary>
            /// Colour of call nodes
            /// </summary>
            nodeCall,
            /// <summary>
            /// Colour of return nodes
            /// </summary>
            nodeRet,
            /// <summary>
            /// Colour of API nodes
            /// </summary>
            nodeExtern,
            /// <summary>
            /// Colour of Exception nodes
            /// </summary>
            nodeExcept,
            /// <summary>
            /// Colour of API label captions
            /// </summary>
            SymbolText,
            /// <summary>
            /// Colour of animated rising API captions
            /// </summary>
            SymbolRising,
            /// <summary>
            /// Colour of internal symbol labels
            /// </summary>
            InternalSymbol,
            /// <summary>
            /// Colour of instruction text labels
            /// </summary>
            InstructionText,
            /// <summary>
            /// Colour of graph wireframes
            /// </summary>
            WireFrame,
            /// <summary>
            /// The number of available colours
            /// </summary>
            COUNT
        }

        /// <summary>
        /// Customisable size values
        /// </summary>
        public enum eThemeSize
        {
            /// <summary>
            /// The weight of the border of selected preview graphs
            /// </summary>
            PreviewSelectedBorder,
            /// <summary>
            /// The number of available sizes
            /// </summary>
            COUNT
        }

        //private static readonly Dictionary<ImGuiCol, uint> ThemeColoursStandard = new Dictionary<ImGuiCol, uint>();
        private static readonly Dictionary<eThemeColour, uint> ThemeColoursCustom = new Dictionary<eThemeColour, uint>();
        private static readonly Dictionary<eThemeSize, float> ThemeSizesCustom = new Dictionary<eThemeSize, float>();
        private static readonly Dictionary<eThemeSize, Vector2> ThemeSizeLimits = new Dictionary<eThemeSize, Vector2>();
        private static readonly Dictionary<string, string> ThemeMetadata = new Dictionary<string, string>();

        /// <summary>
        /// Theme is bundled with rgat
        /// </summary>
        public static bool IsBuiltinTheme = true;
        /// <summary>
        /// Theme has changes which have not been written to the config file
        /// </summary>
        public static bool UnsavedTheme = false;
        private static readonly object _lock = new object();
        private static int _appliedThemeCount = 0;

        static Dictionary<ImGuiCol, uint>? _frameUIColours = null;
        static ulong _frameTheme = 0;

        /// <summary>
        /// Set the UI element colours from the users theme
        /// Should be called before every frame
        /// Calling ResetThemeColours() at the end of every frame is mandatory
        /// </summary>
        public static void ApplyGeneralThemeColours()
        {
            uint windowBackground = Themes.GetThemeColourUINT(Themes.eThemeColour.WindowBackground);

            uint frameColour = Themes.GetThemeColourUINT(Themes.eThemeColour.Frame);
            uint frameHoverColour = WritableRgbaFloat.Brighten(frameColour, CONSTANTS.UI.THEME_COLOUR_HOVERED_MULTIPLIER);
            uint frameActiveColour = WritableRgbaFloat.Brighten(frameColour, CONSTANTS.UI.THEME_COLOUR_ACTIVE_MULTIPLIER);
            uint frameDullColour = WritableRgbaFloat.Brighten(frameColour, CONSTANTS.UI.THEME_COLOUR_DULL_MULTIPLIER);

            uint controlColour = Themes.GetThemeColourUINT(Themes.eThemeColour.Control);
            uint controlDullColour = WritableRgbaFloat.Brighten(controlColour, CONSTANTS.UI.THEME_COLOUR_DULL_MULTIPLIER);
            uint controlHoverColour = WritableRgbaFloat.Brighten(controlColour, CONSTANTS.UI.THEME_COLOUR_HOVERED_MULTIPLIER);
            uint controlActiveColour = WritableRgbaFloat.Brighten(controlColour, CONSTANTS.UI.THEME_COLOUR_ACTIVE_MULTIPLIER);

            if (_frameUIColours is null || _frameTheme != ThemeVariant)
            {
                _frameTheme = ThemeVariant;
                _frameUIColours = new Dictionary<ImGuiCol, uint>()
            {
            {ImGuiCol.Border, frameColour},
            {ImGuiCol.BorderShadow, frameDullColour},
            {ImGuiCol.Button, controlColour},
            {ImGuiCol.ButtonActive, controlActiveColour},
            {ImGuiCol.ButtonHovered, controlHoverColour},
            {ImGuiCol.CheckMark, controlActiveColour},
            {ImGuiCol.ChildBg, windowBackground},
            {ImGuiCol.FrameBg, frameColour},
            {ImGuiCol.FrameBgActive, frameActiveColour},
            {ImGuiCol.FrameBgHovered, frameHoverColour},
            {ImGuiCol.Header, controlColour},
            {ImGuiCol.HeaderActive, controlHoverColour},
            {ImGuiCol.HeaderHovered, controlHoverColour},
            {ImGuiCol.PopupBg, windowBackground},
            {ImGuiCol.ResizeGrip, frameColour},
            {ImGuiCol.ResizeGripActive, controlActiveColour},
            {ImGuiCol.ResizeGripHovered, controlHoverColour},
            {ImGuiCol.ScrollbarBg, windowBackground},
            {ImGuiCol.ScrollbarGrab, frameColour},
            {ImGuiCol.ScrollbarGrabActive, frameActiveColour},
            {ImGuiCol.ScrollbarGrabHovered, frameHoverColour},
            {ImGuiCol.Separator, frameColour},
            {ImGuiCol.SeparatorActive, frameActiveColour},
            {ImGuiCol.SeparatorHovered, frameHoverColour},
            {ImGuiCol.SliderGrab, controlColour},
            {ImGuiCol.SliderGrabActive,controlActiveColour  },
            {ImGuiCol.Tab, controlDullColour},
            {ImGuiCol.TabActive, controlHoverColour},
            {ImGuiCol.TabHovered, controlHoverColour},
            {ImGuiCol.TabUnfocused, controlColour},
            {ImGuiCol.TableBorderLight, frameDullColour},
            {ImGuiCol.TableBorderStrong, frameActiveColour},
            {ImGuiCol.TableHeaderBg, controlColour},
            {ImGuiCol.TableRowBg, GetThemeColourUINT(Themes.eThemeColour.TableRow)},
            {ImGuiCol.TableRowBgAlt, GetThemeColourUINT(Themes.eThemeColour.TableRowAlt)},
            {ImGuiCol.Text, GetThemeColourUINT(Themes.eThemeColour.WindowText)},
            {ImGuiCol.TitleBg, controlColour},
            {ImGuiCol.TitleBgActive, controlHoverColour},
            {ImGuiCol.TitleBgCollapsed, controlDullColour},
            {ImGuiCol.WindowBg, windowBackground }
        };
            }

            foreach (var itemCol in _frameUIColours) ImGui.PushStyleColor(itemCol.Key, itemCol.Value);
            _appliedThemeCount = _frameUIColours.Count;
        }

        /// <summary>
        /// Must be called every time the UI is drawn using ApplyThemeColours
        /// </summary>
        public static void ResetThemeColours()
        {
            ImGui.PopStyleColor(_appliedThemeCount);
        }


        /// <summary>
        /// Set any missing theme settings
        /// </summary>
        private static void InitUnsetCustomColours()
        {

            Dictionary<eThemeColour, uint> DefaultCustomColours = new Dictionary<eThemeColour, uint>
            {
                [eThemeColour.WindowBackground] = new WritableRgbaFloat(Af: 1f, Gf: 0, Bf: 0, Rf: 0).ToUint(),
                [eThemeColour.Control] = 0x650017ff,
                [eThemeColour.ControlText] = 0xffffffff,
                [eThemeColour.WindowText] = 0xffffffff,
                [eThemeColour.Frame] = 0x333333ff,




                [eThemeColour.PreviewText] = new WritableRgbaFloat(Af: 1f, Gf: 1, Bf: 1, Rf: 1).ToUint(),
                [eThemeColour.PreviewTextBackground] = new WritableRgbaFloat(Af: 0.3f, Gf: 0, Bf: 0, Rf: 0).ToUint(),
                [eThemeColour.PreviewPaneBorder] = new WritableRgbaFloat(Af: 1f, Gf: 0, Bf: 0, Rf: 1).ToUint(),
                [eThemeColour.PreviewPaneBackground] = new WritableRgbaFloat(Af: 1f, Gf: 0.05f, Bf: 0.05f, Rf: 0.05f).ToUint(),
                [eThemeColour.PreviewZoomEnvelope] = new WritableRgbaFloat(Af: 0.7f, Gf: 0.7f, Bf: 0.7f, Rf: 0.7f).ToUint(),
                [eThemeColour.PreviewBGRunning] = new WritableRgbaFloat(Color.FromArgb(180, 0, 42, 0)).ToUint(),
                [eThemeColour.PreviewBGSuspended] = new WritableRgbaFloat(Color.FromArgb(150, 245, 163, 71)).ToUint(),
                [eThemeColour.PreviewBGTerminated] = new WritableRgbaFloat(Color.FromArgb(180, 42, 0, 0)).ToUint(),

                [eThemeColour.Dull1] = new WritableRgbaFloat(Af: 1, Gf: 0.698f, Bf: 0.698f, Rf: 0.698f).ToUint(),
                [eThemeColour.Dull2] = new WritableRgbaFloat(Af: 1, Gf: 0.494f, Bf: 0.494f, Rf: 0.537f).ToUint(),
                [eThemeColour.Emphasis1] = new WritableRgbaFloat(Af: 1, Gf: 1f, Bf: 0.9f, Rf: 0.6f).ToUint(),
                [eThemeColour.Emphasis2] = new WritableRgbaFloat(Af: 1, Gf: 0.773f, Bf: 01, Rf: 1f).ToUint(),

                [eThemeColour.edgeCall] = new WritableRgbaFloat(Color.Purple).ToUint(),
                [eThemeColour.edgeOld] = new WritableRgbaFloat(Color.FromArgb(150, 150, 150, 150)).ToUint(),
                [eThemeColour.edgeRet] = new WritableRgbaFloat(Color.Orange).ToUint(),
                [eThemeColour.edgeLib] = new WritableRgbaFloat(Color.Green).ToUint(),
                [eThemeColour.edgeNew] = new WritableRgbaFloat(Color.Yellow).ToUint(),
                [eThemeColour.edgeExcept] = new WritableRgbaFloat(Color.Cyan).ToUint(),

                [eThemeColour.nodeStd] = new WritableRgbaFloat(Color.Yellow).ToUint(),
                [eThemeColour.nodeJump] = new WritableRgbaFloat(Color.Red).ToUint(),
                [eThemeColour.nodeCall] = new WritableRgbaFloat(Color.Purple).ToUint(),
                [eThemeColour.nodeRet] = new WritableRgbaFloat(Color.Orange).ToUint(),
                [eThemeColour.nodeExtern] = new WritableRgbaFloat(Color.FromArgb(255, 40, 255, 0)).ToUint(),
                [eThemeColour.nodeExcept] = new WritableRgbaFloat(Color.Cyan).ToUint(),

                [eThemeColour.SymbolText] = new WritableRgbaFloat(Color.SpringGreen).ToUint(),
                [eThemeColour.InternalSymbol] = new WritableRgbaFloat(Color.DarkGray).ToUint(),
                [eThemeColour.SymbolRising] = new WritableRgbaFloat(Color.ForestGreen).ToUint(),
                [eThemeColour.InstructionText] = new WritableRgbaFloat(Color.White).ToUint(),
                [eThemeColour.WireFrame] = new WritableRgbaFloat(180, 180, 180, 76).ToUint(),

                [eThemeColour.Heat0Lowest] = new WritableRgbaFloat(0, 0, 155, 178).ToUint(),
                [eThemeColour.Heat1] = new WritableRgbaFloat(46, 28, 155, 255).ToUint(),
                [eThemeColour.Heat2] = new WritableRgbaFloat(95, 104, 226, 255).ToUint(),
                [eThemeColour.Heat3] = new WritableRgbaFloat(117, 143, 223, 255).ToUint(),
                [eThemeColour.Heat4] = new WritableRgbaFloat(255, 255, 255, 255).ToUint(),
                [eThemeColour.Heat5] = new WritableRgbaFloat(252, 196, 180, 255).ToUint(),
                [eThemeColour.Heat6] = new WritableRgbaFloat(242, 152, 152, 255).ToUint(),
                [eThemeColour.Heat7] = new WritableRgbaFloat(249, 107, 107, 255).ToUint(),
                [eThemeColour.Heat8] = new WritableRgbaFloat(255, 64, 64, 255).ToUint(),
                [eThemeColour.Heat9Highest] = new WritableRgbaFloat(255, 0, 0, 255).ToUint(),

                [eThemeColour.VisBarPlotLine] = new WritableRgbaFloat(1f, 0f, 0f, 1f).ToUint(),
                [eThemeColour.VisBarBg] = new WritableRgbaFloat(Color.Black).ToUint(),
                [eThemeColour.AlertWindowBg] = new WritableRgbaFloat(Color.SlateBlue).ToUint(),
                [eThemeColour.AlertWindowBorder] = new WritableRgbaFloat(Color.GhostWhite).ToUint(),
                [eThemeColour.BadStateColour] = new WritableRgbaFloat(Color.Red).ToUint(),
                [eThemeColour.WarnStateColour] = new WritableRgbaFloat(Color.Yellow).ToUint(),
                [eThemeColour.GoodStateColour] = new WritableRgbaFloat(Color.Green).ToUint(),
                [eThemeColour.GraphBackground] = new WritableRgbaFloat(Color.Black).ToUint(),
                [eThemeColour.SandboxChartBG] = new WritableRgbaFloat(1f, 1f, 1f, 1f).ToUint()
            };


            foreach (eThemeColour themeStyle in DefaultCustomColours.Keys)
            {
                if (!ThemeColoursCustom.ContainsKey(themeStyle))
                {
                    ThemeColoursCustom.Add(themeStyle, DefaultCustomColours[themeStyle]);
                }
            }

            foreach (eThemeColour item in Enum.GetValues(typeof(eThemeColour)))
            {
                if (!DefaultCustomColours.ContainsKey(item))
                {
                    DefaultCustomColours[item] = new WritableRgbaFloat(Color.Red).ToUint();
                }
            }


            Dictionary<eThemeSize, float> DefaultCustomSizes = new Dictionary<eThemeSize, float>();

            DefaultCustomSizes[eThemeSize.PreviewSelectedBorder] = 1f;

            foreach (eThemeSize themeStyle in DefaultCustomSizes.Keys)
            {
                if (!ThemeSizesCustom.ContainsKey(themeStyle))
                {
                    ThemeSizesCustom.Add(themeStyle, DefaultCustomSizes[themeStyle]);
                }
            }


            Dictionary<eThemeSize, Vector2> DefaultSizeLimits = new Dictionary<eThemeSize, Vector2>
            {
                [eThemeSize.PreviewSelectedBorder] = new Vector2(0, 30)
            };
            foreach (eThemeSize themeStyle in DefaultSizeLimits.Keys)
            {
                if (!ThemeSizeLimits.ContainsKey(themeStyle))
                {
                    ThemeSizeLimits.Add(themeStyle, DefaultSizeLimits[themeStyle]);
                }
            }
        }


        /// <summary>
        /// Init a default theme if no valid custom one is found
        /// </summary>
        public static void InitFallbackTheme()
        {
            lock (_lock)
            {
                ThemeMetadata["Name"] = "Fallback";
                ThemeMetadata["Description"] = "Fallback theme for when preloaded and custom themes failed to load";
                ThemeMetadata["Author"] = "rgat fallback theme";
                ThemeMetadata["Author2"] = "https://github.com/ncatlin/rgat";

                InitUnsetCustomColours();
                IsBuiltinTheme = true;
            }
        }


        /// <summary>
        /// Get a uint colour value of a specified custom theme item
        /// </summary>
        /// <param name="item">A theme attribute</param>
        /// <returns>uint colour</returns>
        public static uint GetThemeColourUINT(eThemeColour item, uint? customAlpha = null)
        {
            lock (_lock)
            {
                if (!ThemeColoursCustom.ContainsKey(item) || ThemeColoursCustom.TryGetValue(item, out uint colResult) is false)
                {
                    return 0xff000000;
                }
                if (customAlpha is not null) return WritableRgbaFloat.ToUint(colResult, customAlpha.Value);
                return colResult;
            }
        }


        /// <summary>
        /// Get a WritableRgbaFloat colour value of a specified custom theme item
        /// </summary>
        /// <param name="item">A theme attribute</param>
        /// <returns>WritableRgbaFloat colour</returns>
        public static WritableRgbaFloat GetThemeColourWRF(eThemeColour item)
        {
            lock (_lock)
            {
                if (!ThemeColoursCustom.ContainsKey(item) || ((uint)item >= ThemeColoursCustom.Count))
                {
                    return new WritableRgbaFloat(0xffffffff);
                }

                return new WritableRgbaFloat(ThemeColoursCustom[item]);
            }
        }


        /// <summary>
        /// Version of the active theme
        /// </summary>
        public static ulong ThemeVersion { get; private set; } = 0;

        /// <summary>
        /// Get a custom theme size
        /// </summary>
        /// <param name="item">The size to retrieve</param>
        /// <returns>The float size value</returns>
        public static float GetThemeSize(eThemeSize item)
        {
            lock (_lock)
            {
                Debug.Assert(ThemeSizesCustom.ContainsKey(item));
                Debug.Assert((uint)item < ThemeSizesCustom.Count);
                return ThemeSizesCustom[item];
            }
        }

        static readonly Dictionary<eThemeColour, uint> _modifiedColoursCustom = new();

        /// <summary>
        /// Draw the theme colour customisation widget
        /// </summary>
        /// <returns>true if a setting was changed</returns>
        public unsafe static bool DrawColourSelectors()
        {
            bool changed = false;
            ImGuiTableFlags tableFlags = ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY | ImGuiTableFlags.ScrollX;
            float tableWidth = Math.Max(ImGui.GetContentRegionAvail().X, 650);
            Vector2 tableSize = new Vector2(tableWidth, 350);
            if (ImGui.BeginTable(str_id: "##SelectorsTable", column: 2, flags: tableFlags, outer_size: tableSize))
            {
                float halfWidth = Math.Max(300, tableWidth / 2.1f);
                ImGui.TableSetupColumn("UI Element Colours", ImGuiTableColumnFlags.WidthFixed, halfWidth);
                ImGui.TableSetupColumn("Graph Element Colours", ImGuiTableColumnFlags.WidthFixed, halfWidth);
                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableHeadersRow();

                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                for (int colI = 0; colI < (int)Themes.eThemeColour.Heat0Lowest; colI++)
                {
                    Themes.eThemeColour uiColour = (Themes.eThemeColour)colI;
                    Vector4 colval = new WritableRgbaFloat(Themes.GetThemeColourUINT(uiColour)).ToVec4();
                    ImGui.SetNextItemWidth(215);
                    if (ImGui.ColorEdit4(Enum.GetName(typeof(Themes.eThemeColour), colI), ref colval, ImGuiColorEditFlags.AlphaBar))
                    {
                        changed = true;
                        if (_modifiedColoursCustom.ContainsKey(uiColour) is false)
                        {
                            _modifiedColoursCustom[uiColour] = Themes.GetThemeColourUINT(uiColour);
                        }
                        Themes.ThemeColoursCustom[uiColour] = new WritableRgbaFloat(colval).ToUint();
                    }
                    if (_modifiedColoursCustom.ContainsKey(uiColour))
                    {
                        ImGui.SameLine();
                        if (ImGui.Button($"Revert##sc{colI}"))
                        {
                            Themes.ThemeColoursCustom[uiColour] = _modifiedColoursCustom[uiColour];
                            _modifiedColoursCustom.Remove(uiColour);
                        }
                    }
                }

                ImGui.TableSetColumnIndex(1);
                for (int colI = (int)Themes.eThemeColour.Heat0Lowest; colI < (int)Themes.eThemeColour.COUNT; colI++)
                {
                    Themes.eThemeColour customCol = (Themes.eThemeColour)colI;
                    Vector4 colval = new WritableRgbaFloat(Themes.GetThemeColourUINT(customCol)).ToVec4();
                    ImGui.SetNextItemWidth(215);
                    if (ImGui.ColorEdit4(Enum.GetName(typeof(Themes.eThemeColour), colI), ref colval, ImGuiColorEditFlags.AlphaBar))
                    {
                        changed = true;
                        if (_modifiedColoursCustom.ContainsKey(customCol) is false)
                        {
                            _modifiedColoursCustom[customCol] = Themes.GetThemeColourUINT(customCol);
                        }
                        Themes.ThemeColoursCustom[customCol] = new WritableRgbaFloat(colval).ToUint();
                    }
                    if (_modifiedColoursCustom.ContainsKey(customCol))
                    {
                        ImGui.SameLine();
                        if (ImGui.Button($"Revert##cc{colI}"))
                        {
                            Themes.ThemeColoursCustom[customCol] = _modifiedColoursCustom[customCol];
                            _modifiedColoursCustom.Remove(customCol);
                        }
                    }

                }
                ImGui.EndTable();
            }

            if (ImGui.TreeNode("Dimensions"))
            {
                for (int dimI = 0; dimI < Themes.ThemeSizesCustom.Count; dimI++)
                {
                    Themes.eThemeSize sizeEnum = (Themes.eThemeSize)dimI;
                    int size = (int)Themes.GetThemeSize(sizeEnum);
                    Vector2 sizelimit = Themes.ThemeSizeLimits[sizeEnum];
                    if (ImGui.SliderInt(Enum.GetName(typeof(Themes.eThemeColour), dimI), ref size, (int)sizelimit.X, (int)sizelimit.Y))
                    {
                        changed = true;
                        Themes.ThemeSizesCustom[sizeEnum] = size;
                    }

                }
                ImGui.TreePop();
            }

            if (ImGui.TreeNode("Metadata"))
            {
                Tuple<string, string>? changedVal = null;
                Dictionary<string, string> currentMetadata = new Dictionary<string, string>(Themes.ThemeMetadata);
                foreach (KeyValuePair<string, string> kvp in currentMetadata)
                {
                    string value = kvp.Value;
                    bool validValue = true;
                    if (badFields.Contains(kvp.Key))
                    {
                        validValue = false;
                    }

                    if (!validValue)
                    {
                        ImGui.PushStyleColor(ImGuiCol.FrameBg, Themes.GetThemeColourUINT(Themes.eThemeColour.BadStateColour));
                    }
                    IntPtr p = Marshal.StringToHGlobalUni(kvp.Key);
                    ImGuiInputTextFlags flags = ImGuiInputTextFlags.EnterReturnsTrue | ImGuiInputTextFlags.CallbackEdit;
                    ImGui.InputText(kvp.Key, ref value, 1024, flags, TextCheckValid, p);

                    if (!validValue)
                    {
                        ImGui.PopStyleColor();
                    }

                }
                if (changedVal != null)
                {
                    Themes.ThemeMetadata[changedVal.Item1] = changedVal.Item2;
                }
                ImGui.TreePop();
            }
            return changed;
        }

        /// <summary>
        /// Get a theme metadata value
        /// </summary>
        /// <param name="name">Value to retrieve</param>
        /// <param name="value">The value retrieved</param>
        /// <returns>true if succesful</returns>
        public static bool GetMetadataValue(string name, out string? value)
        {
            lock (_lock)
            {
                return ThemeMetadata.TryGetValue(name, out value);
            }
        }

        private static readonly List<string> badFields = new List<string>();

        //this is terrible
        private static unsafe int TextCheckValid(ImGuiInputTextCallbackData* p)
        {
            ImGuiInputTextCallbackData cb = *p;
            byte[] currentValue = new byte[cb.BufTextLen];
            Marshal.Copy((IntPtr)cb.Buf, currentValue, 0, p->BufTextLen);
            string actualCurrentValue = Encoding.ASCII.GetString(currentValue);

            string? keyname = Marshal.PtrToStringAuto((IntPtr)cb.UserData);
            if (keyname != null)
            {
                bool validValue = true;

                if (keyname == "Name" && Themes.BuiltinThemes.ContainsKey(actualCurrentValue))
                {
                    validValue = false;
                }

                if (actualCurrentValue.Contains('"'))
                {
                    validValue = true;
                }

                if (badFields.Contains(keyname) && validValue)
                {
                    badFields.Remove(keyname);
                }
                else if (!badFields.Contains(keyname) && !validValue)
                {
                    badFields.Add(keyname);
                }
                if (validValue)
                {
                    Themes.SaveMetadataChange(keyname, actualCurrentValue);
                }
            }

            Marshal.FreeHGlobal((IntPtr)cb.UserData);
            return 0;
        }


        /*
    * This will load valid but incomplete theme data into the existing theme, but not if there
    * is any invalid data
    */
        private static bool ActivateThemeObject(JObject theme)
        {
            lock (_lock)
            {
                ThemeVersion++;

                Dictionary<string, string> pendingMetadata = new Dictionary<string, string>();
                Dictionary<ImGuiCol, uint> pendingColsStd = new Dictionary<ImGuiCol, uint>();
                Dictionary<eThemeColour, uint> pendingColsCustom = new Dictionary<eThemeColour, uint>();
                Dictionary<eThemeSize, float> pendingSizes = new Dictionary<eThemeSize, float>();
                Dictionary<eThemeSize, Vector2> pendingLimits = new Dictionary<eThemeSize, Vector2>();

                if (!LoadMetadataStrings(theme, out pendingMetadata, out string? errorMsg))
                {
                    Logging.RecordError(errorMsg); return false;
                }

                if (theme.TryGetValue("CustomColours", out JToken? customColTok) && customColTok.Type == JTokenType.Object)
                {
                    JObject? custColsObj = customColTok.ToObject<JObject>();
                    if (custColsObj is null)
                    {
                        Logging.RecordError($"Theme has invalid CustomColours"); return false;
                    }
                    foreach (var item in custColsObj)
                    {
                        eThemeColour customcolType;
                        try
                        {
                            customcolType = (eThemeColour)Enum.Parse(typeof(eThemeColour), item.Key, true);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordException($"Theme has invalid custom colour type {item.Key}-{e.Message}", e);
                            continue;
                        }
                        if (customcolType >= eThemeColour.COUNT)
                        {
                            Logging.RecordError($"Theme has invalid custom colour type {item.Key}");
                            continue;
                        }
                        if (item.Value is null || item.Value.Type != JTokenType.Integer)
                        {
                            Logging.RecordError($"Theme has custom colour with non-integer colour entry {item.Key}");
                            continue;
                        }
                        Console.WriteLine($"Loading {customcolType} {item.Value}");
                        pendingColsCustom[customcolType] = item.Value.ToObject<uint>();
                    }
                }

                if (theme.TryGetValue("StandardColours", out JToken? stdColTok) && stdColTok.Type == JTokenType.Object)
                {
                    JObject? stdColObj = stdColTok.ToObject<JObject>();
                    if (stdColObj is null)
                    {
                        Logging.RecordError($"Theme has invalid StandardColours"); return false;
                    }
                    foreach (var item in stdColObj)
                    {
                        ImGuiCol stdcolType;
                        try
                        {
                            stdcolType = (ImGuiCol)Enum.Parse(typeof(ImGuiCol), item.Key, true);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordException($"Theme has invalid standard colour type {item.Key}", e); continue;
                        }
                        if (stdcolType >= ImGuiCol.COUNT)
                        {
                            Logging.RecordError($"Theme has invalid standard colour type {item.Key}"); continue;
                        }
                        if (item.Value is null || item.Value.Type != JTokenType.Integer)
                        {
                            Logging.RecordError($"Theme has custom colour with non-integer colour entry {item.Key}"); continue;
                        }
                        pendingColsStd[stdcolType] = item.Value.ToObject<uint>();
                    }
                }

                if (theme.TryGetValue("Sizes", out JToken? sizesTok) && sizesTok.Type == JTokenType.Object)
                {
                    JObject? sizesObj = sizesTok.ToObject<JObject>();
                    if (sizesObj is null)
                    {
                        Logging.RecordError($"Theme has invalid Sizes"); return false;
                    }
                    foreach (var item in sizesObj)
                    {
                        eThemeSize sizeType;
                        try
                        {
                            sizeType = (eThemeSize)Enum.Parse(typeof(eThemeSize), item.Key, true);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordException($"Theme has invalid size type {item.Key}", e); return false;
                        }
                        if (sizeType >= eThemeSize.COUNT)
                        {
                            Logging.RecordError($"Theme has invalid size type {item.Key}"); return false;
                        }
                        if (item.Value is null || item.Value.Type != JTokenType.Float)
                        {
                            Logging.RecordError($"Theme has size with non-float size entry {item.Key}"); return false;
                        }
                        ThemeSizesCustom[sizeType] = item.Value.ToObject<float>();
                    }
                }


                if (theme.TryGetValue("SizeLimits", out JToken? sizelimTok) && sizelimTok.Type == JTokenType.Object)
                {
                    JObject? sizeLimObj = sizelimTok.ToObject<JObject>();
                    if (sizeLimObj is null)
                    {
                        Logging.RecordError($"Theme has invalid SizeLimits"); return false;
                    }
                    foreach (var item in sizeLimObj)
                    {
                        eThemeSize sizeType;
                        try
                        {
                            sizeType = (eThemeSize)Enum.Parse(typeof(eThemeSize), item.Key, true);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordException($"Theme has invalid sizelimit type {item.Key}", e); return false;
                        }
                        if (sizeType >= eThemeSize.COUNT)
                        {
                            Logging.RecordLogEvent($"Theme has invalid sizelimit type {item.Key}"); return false;
                        }
                        if (item.Value is null || item.Value.Type != JTokenType.Array)
                        {
                            Logging.RecordError($"Theme has sizelimit with non-array entry {item.Key}"); return false;
                        }
                        JArray? limits = item.Value.ToObject<JArray>();
                        if (limits is null || limits.Count != 2 || limits[0].Type != JTokenType.Float || limits[1].Type != JTokenType.Float)
                        {
                            Logging.RecordError($"Theme has sizelimit with invalid array size or item types (should be 2 floats) {item.Key}"); return false;
                        }
                        pendingLimits[sizeType] = new Vector2(limits[0].ToObject<float>(), limits[1].ToObject<float>());
                    }
                }

                //all loaded and validated, load them into the UI
                foreach (var kvp in pendingMetadata)
                {
                    ThemeMetadata[kvp.Key] = kvp.Value;
                }

                foreach (var kvp in pendingColsCustom)
                {
                    ThemeColoursCustom[kvp.Key] = kvp.Value;
                }

                foreach (var kvp in pendingLimits)
                {
                    ThemeSizeLimits[kvp.Key] = kvp.Value;
                }

                foreach (var kvp in pendingSizes)
                {
                    ThemeSizesCustom[kvp.Key] = kvp.Value;
                }

                IsBuiltinTheme = BuiltinThemes.ContainsKey(ThemeMetadata["Name"]);

                InitUnsetCustomColours();

                RegenerateUIThemeJSON();
                return true;
            }
        }

        /// <summary>
        /// Change a theme metadata value
        /// </summary>
        /// <param name="key">The value to change</param>
        /// <param name="value">The new value</param>
        public static void SaveMetadataChange(string key, string value)
        {
            ThemeMetadata[key] = value;
            if (currentThemeJSON is not null &&
                currentThemeJSON.TryGetValue("MetaData", out JToken? mdTok) &&
                mdTok.Type is JTokenType.Object)
            {
                mdTok.ToObject<JObject>()![key] = value;
                UnsavedTheme = true;
                IsBuiltinTheme = BuiltinThemes.ContainsKey(ThemeMetadata["Name"]);
            }
        }


        /// <summary>
        /// Delete a theme
        /// </summary>
        /// <param name="name">Name of the theme to delete</param>
        public static void DeleteTheme(string name)
        {
            if (ThemeMetadata["Name"] != name && !BuiltinThemes.ContainsKey(name))
            {
                if (ThemesMetadataCatalogue.ContainsKey(name))
                {
                    ThemesMetadataCatalogue.Remove(name);
                }

                if (CustomThemes.ContainsKey(name))
                {
                    CustomThemes.Remove(name);
                }

                WriteCustomThemesToConfig();
            }
        }


        /// <summary>
        /// Store the current theme as a preset
        /// </summary>
        /// <param name="name">The name to store the theme as</param>
        /// <param name="setAsDefault">if true, this theme will be loaded on rgat start</param>
        public static void SavePresetTheme(string name, bool setAsDefault)
        {
            if (name.Length == 0 || BuiltinThemes.ContainsKey(name))
            {
                return;
            }

            if (name != ThemeMetadata["Name"])
            {
                SaveMetadataChange("Name", name);
            }

            RegenerateUIThemeJSON();
            CustomThemes[name] = currentThemeJSON!;
            ThemesMetadataCatalogue[name] = ThemeMetadata;
            UnsavedTheme = false;
            WriteCustomThemesToConfig();

            if (setAsDefault)
            {
                GlobalConfig.Settings.Themes.DefaultTheme = ThemeMetadata["Name"];
            }
        }

        private static JObject? currentThemeJSON;

        /// <summary>
        /// Controls can compare this value with a cached value to see if the theme has changed
        /// </summary>
        public static ulong ThemeVariant { get; private set; } = 0;

        /// <summary>
        /// Some UI/Graph items regenerate if the theme is changed, this triggers that event
        /// </summary>
        public static void DeclareThemeChanged() => ThemeVariant += 1;

        /// <summary>
        /// Write all the current theme attributes into a JSON object
        /// Updates the ThemeVariant value
        /// </summary>
        /// <returns>The JSON serialised theme</returns>
        public static string RegenerateUIThemeJSON()
        {
            lock (_lock)
            {
                JObject themeJsnObj = new JObject();

                JObject themeCustom = new JObject();
                foreach (var kvp in ThemeColoursCustom)
                {
                    themeCustom.Add(kvp.Key.ToString(), kvp.Value);
                }

                themeJsnObj.Add("CustomColours", themeCustom);

                JObject sizesObj = new JObject();
                foreach (var kvp in ThemeSizesCustom)
                {
                    sizesObj.Add(kvp.Key.ToString(), kvp.Value);
                }

                themeJsnObj.Add("Sizes", sizesObj);

                JObject sizeLimitsObj = new JObject();
                foreach (var kvp in ThemeSizeLimits)
                {
                    sizeLimitsObj.Add(kvp.Key.ToString(), new JArray(new List<float>() { kvp.Value.X, kvp.Value.Y }));
                }

                themeJsnObj.Add("SizeLimits", sizeLimitsObj);

                JObject metadObj = new JObject();

                foreach (var kvp in ThemeMetadata)
                {
                    metadObj.Add(kvp.Key.ToString(), kvp.Value.ToString());
                }
                themeJsnObj.Add("Metadata", metadObj);

                currentThemeJSON = themeJsnObj;

                ThemeVariant += 1;

                return themeJsnObj.ToString();
            };
        }


        /// <summary>
        /// Load and apply a JSON serialised theme
        /// </summary>
        /// <param name="themeJSON">JSON theme</param>
        /// <param name="error">Set to any error encountered while loading it</param>
        /// <returns>success if the theme was loaded</returns>
        public static bool ActivateThemeObject(string themeJSON, out string error)
        {
            JObject? themeJson = null;
            try
            {
                themeJson = Newtonsoft.Json.Linq.JObject.Parse(themeJSON);
            }
            catch (Exception e)
            {
                Logging.RecordException($"Error restoring theme from JSON: {e.Message}", e);
                error = "Error parsing JSON";
                return false;
            }

            if (ActivateThemeObject(themeJson))
            {
                error = "Success";
                UnsavedTheme = true;
                return true;
            }

            error = "Load of parsed JSON failed";
            return false;
        }

        private static bool LoadMetadataStrings(JObject themeObj, out Dictionary<string, string> result, out string error)
        {
            result = new Dictionary<string, string>();

            JObject? metadataObj = null;
            if (themeObj.TryGetValue("Metadata", out JToken? mdTok) && mdTok.Type == JTokenType.Object)
            {
                metadataObj = mdTok.ToObject<JObject>();
            }

            if (metadataObj is null)
            {
                error = "Unable to find \"Metadata\" object in theme";
                return false;
            }

            foreach (var item in metadataObj)
            {
                if (item.Value is null)
                {
                    continue;
                }

                if (item.Key.Length > 255)
                {
                    error = $"Theme has metadata key with excessive length {item.Key.Length}"; return false;
                }
                if (item.Value.Type != JTokenType.String)
                {
                    error = $"Theme has non-string metadata item {item.Key}"; return false;
                }
                string? mdvalue = item.Value.ToObject<string>();
                if (mdvalue is null || mdvalue.Length > 4096)
                {
                    error = $"Skipping Theme metadata value with bad length {mdvalue?.Length}"; return false;
                }
                result[item.Key] = mdvalue;
            }
            error = "Success";
            return true;
        }


        /// <summary>
        /// Activate a theme by name
        /// </summary>
        /// <param name="themename">Name of the theme to activate</param>
        public static void LoadTheme(string themename)
        {
            if (ThemeMetadata.TryGetValue("Name", out string? currentTheme) && currentTheme == themename)
            {
                return;
            }

            if (BuiltinThemes.ContainsKey(themename))
            {
                Logging.RecordLogEvent($"LoadTheme Loading builtin theme {themename}");
                ActivateThemeObject(BuiltinThemes[themename]);

                return;
            }
            if (CustomThemes.ContainsKey(themename))
            {
                Logging.RecordLogEvent($"Loading custom theme {themename}");
                ActivateThemeObject(CustomThemes[themename]);
                return;
            }
            Logging.RecordLogEvent($"Tried to load unknown theme {themename}", Logging.LogFilterType.Error);
        }


        /// <summary>
        /// Custom themes
        /// </summary>
        public static Dictionary<string, JObject> CustomThemes = new Dictionary<string, JObject>();
        /// <summary>
        /// Builtin themes
        /// </summary>
        public static Dictionary<string, JObject> BuiltinThemes = new Dictionary<string, JObject>();
        /// <summary>
        /// Metadata for all available themes
        /// </summary>
        public static Dictionary<string, Dictionary<string, string>> ThemesMetadataCatalogue = new Dictionary<string, Dictionary<string, string>>();


        /// <summary>
        /// Load the builtin rgat themes to make them available for activation
        /// </summary>
        /// <param name="themesArray">JArray of builtin themes</param>
        public static void LoadBuiltinThemes(JArray themesArray)
        {
            Logging.RecordLogEvent($"Loading {themesArray.Count} builtin themes", Logging.LogFilterType.Debug);
            for (var i = 0; i < themesArray.Count; i++)
            {
                JObject? theme = themesArray[i].Value<JObject>();
                string? error = null;
                if (theme is null || !LoadMetadataStrings(theme, out Dictionary<string, string> metadata, out error))
                {
                    Logging.RecordLogEvent($"Error loading metadata for preloaded theme {i}: {(error is not null ? error : "Bad Object")}");
                    continue;
                }

                if (!metadata.TryGetValue("Name", out string? themeName))
                {
                    Logging.RecordLogEvent($"Skipping load for preloaded theme {i} (no 'Name' in metadata)");
                    continue;
                }

                Logging.RecordLogEvent($"Loaded builtin theme " + themeName, Logging.LogFilterType.Debug);
                BuiltinThemes[themeName] = theme;
                ThemesMetadataCatalogue[themeName] = metadata;
            }
        }

        private static void WriteCustomThemesToConfig()
        {
            Dictionary<string, string> savedata = new Dictionary<string, string>();

            foreach (KeyValuePair<string, JObject> theme in CustomThemes)
            {
                savedata.Add(theme.Key, theme.Value.ToString());
            }
            GlobalConfig.Settings.Themes.SetCustomThemes(savedata);

        }

        /// <summary>
        /// Activate the default theme
        /// </summary>
        public static void LoadCustomThemes()
        {
            if (CustomThemes.Count != GlobalConfig.Settings.Themes.CustomThemes.Count)
            {
                Dictionary<string, string> _customThemes = GlobalConfig.Settings.Themes.CustomThemes;
                foreach (KeyValuePair<string, string> item in _customThemes)
                {
                    try
                    {
                        JObject themeObj = JObject.Parse(item.Value);
                        if (themeObj.TryGetValue("Metadata", out JToken? mdtok) && mdtok is not null)
                        {
                            if (!LoadMetadataStrings(themeObj, out Dictionary<string, string> md, out string error))
                            {
                                Logging.RecordError($"Failed to load custom theme {item.Key}: {error}");
                            }
                            else
                            {
                                CustomThemes[item.Key] = themeObj;
                                ThemesMetadataCatalogue[item.Key] = md;
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.RecordException($"Failed to load custom theme {item.Key}: {e.Message}", e);
                    }
                }
            }
            
            string defaultTheme = GlobalConfig.Settings.Themes.DefaultTheme;
            if (defaultTheme.Length > 0)
            {
                if (CustomThemes.TryGetValue(defaultTheme, out JObject? themeObj))
                {
                    ActivateThemeObject(themeObj);
                    return;
                }
                else if (BuiltinThemes.TryGetValue(defaultTheme, out themeObj))
                {
                    ActivateThemeObject(themeObj);
                    return;
                }
                Logging.RecordError($"Default theme {defaultTheme} is unavailable");
            }
            
            if (BuiltinThemes.Count > 0)
            {
                LoadTheme(BuiltinThemes.Keys.First());
                return;
            }

            if (CustomThemes.Count > 0)
            {
                LoadTheme(CustomThemes.Keys.First());
                return;
            }

            if (ThemeColoursCustom.Count == 0)
            {
               InitFallbackTheme();
            }
            InitUnsetCustomColours(); 
            RegenerateUIThemeJSON();
        }

    }
}
