using ImGuiNET;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace rgat
{
    public class Themes
    {

        //todo should be lists not dicts
        public enum eThemeColour
        {
            ePreviewText, ePreviewTextBackground, ePreviewPaneBorder, ePreviewPaneBackground,
            ePreviewZoomEnvelope,
            eTextEmphasis1, eTextEmphasis2, eTextDull1, eTextDull2,
            eHeat0Lowest, eHeat1, eHeat2, eHeat3, eHeat4, eHeat5, eHeat6, eHeat7, eHeat8, eHeat9Highest,
            eVisBarPlotLine, eVisBarBg, eAlertWindowBg, eAlertWindowBorder,
            eBadStateColour, eWarnStateColour, eGoodStateColour,
            GraphBackground,
            COUNT
        }
        public enum eThemeSize
        {
            ePreviewSelectedBorder,
            COUNT
        }

        static Dictionary<ImGuiCol, uint> ThemeColoursStandard = new Dictionary<ImGuiCol, uint>();
        static Dictionary<eThemeColour, uint> ThemeColoursCustom = new Dictionary<eThemeColour, uint>();
        static Dictionary<eThemeSize, float> ThemeSizesCustom = new Dictionary<eThemeSize, float>();
        static Dictionary<eThemeSize, Vector2> ThemeSizeLimits = new Dictionary<eThemeSize, Vector2>();
        static Dictionary<string, string> ThemeMetadata = new Dictionary<string, string>();

        public static bool IsBuiltinTheme = true;
        public static bool UnsavedTheme = false;
        static string _defaultTheme = "";
        static readonly object _lock = new object();

        static int _appliedThemeCount = 0;
        public static void ApplyThemeColours()
        {
            lock (_lock)
            {

                var themes = Themes.ThemeColoursStandard.ToList();
                foreach (KeyValuePair<ImGuiCol, uint> kvp in themes)
                {
                    ImGui.PushStyleColor(kvp.Key, kvp.Value);
                }
                _appliedThemeCount = themes.Count;
            }
        }

        public static void ResetThemeColours()
        {
            ImGui.PopStyleColor(_appliedThemeCount);
        }


        public static string DefaultTheme
        {
            get => _defaultTheme;
            set
            {
                if (ThemesMetadataCatalogue.ContainsKey(value))
                {
                    _defaultTheme = value;
                    GlobalConfig.AddUpdateAppSettings("DefaultTheme", value);
                }
            }
        }

        /// <summary>
        /// Set any missing theme settings
        /// </summary>
        static void InitUnsetCustomColours()
        {
            Dictionary<eThemeColour, uint> DefaultCustomColours = new Dictionary<eThemeColour, uint>();

            DefaultCustomColours[eThemeColour.ePreviewText] = new WritableRgbaFloat(Af: 1f, Gf: 1, Bf: 1, Rf: 1).ToUint();
            DefaultCustomColours[eThemeColour.ePreviewTextBackground] = new WritableRgbaFloat(Af: 0.3f, Gf: 0, Bf: 0, Rf: 0).ToUint();
            DefaultCustomColours[eThemeColour.ePreviewPaneBorder] = new WritableRgbaFloat(Af: 1f, Gf: 0, Bf: 0, Rf: 1).ToUint();
            DefaultCustomColours[eThemeColour.ePreviewPaneBackground] = new WritableRgbaFloat(Af: 1f, Gf: 0.05f, Bf: 0.05f, Rf: 0.05f).ToUint();
            DefaultCustomColours[eThemeColour.ePreviewZoomEnvelope] = new WritableRgbaFloat(Af: 0.7f, Gf: 0.7f, Bf: 0.7f, Rf: 0.7f).ToUint();

            DefaultCustomColours[eThemeColour.eTextDull1] = new WritableRgbaFloat(Af: 1, Gf: 0.698f, Bf: 0.698f, Rf: 0.698f).ToUint();
            DefaultCustomColours[eThemeColour.eTextDull2] = new WritableRgbaFloat(Af: 1, Gf: 0.494f, Bf: 0.494f, Rf: 0.537f).ToUint();
            DefaultCustomColours[eThemeColour.eTextEmphasis1] = new WritableRgbaFloat(Af: 1, Gf: 1f, Bf: 0.9f, Rf: 0.6f).ToUint();
            DefaultCustomColours[eThemeColour.eTextEmphasis2] = new WritableRgbaFloat(Af: 1, Gf: 0.773f, Bf:01, Rf: 1f).ToUint();

            DefaultCustomColours[eThemeColour.eHeat0Lowest] = new WritableRgbaFloat(0, 0, 155f / 255f, 0.7f).ToUint();
            DefaultCustomColours[eThemeColour.eHeat1] = new WritableRgbaFloat(46f / 255f, 28f / 255f, 155f / 255f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eHeat2] = new WritableRgbaFloat(95f / 255f, 104f / 255f, 226f / 255f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eHeat3] = new WritableRgbaFloat(117f / 255f, 143f / 255f, 223f / 255f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eHeat4] = new WritableRgbaFloat(255f / 255f, 255f / 225f, 255f / 255f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eHeat5] = new WritableRgbaFloat(252f / 255f, 196f / 255f, 180f / 255f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eHeat6] = new WritableRgbaFloat(242f / 255f, 152f / 255f, 152f / 255f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eHeat7] = new WritableRgbaFloat(249f / 255f, 107f / 255f, 107f / 255f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eHeat8] = new WritableRgbaFloat(255f / 255f, 64f / 255f, 64f / 255f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eHeat9Highest] = new WritableRgbaFloat(1, 0f, 0f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eVisBarPlotLine] = new WritableRgbaFloat(1, 0f, 0f, 1).ToUint();
            DefaultCustomColours[eThemeColour.eVisBarBg] = new WritableRgbaFloat(Color.Black).ToUint();
            DefaultCustomColours[eThemeColour.eAlertWindowBg] = new WritableRgbaFloat(Color.SlateBlue).ToUint();
            DefaultCustomColours[eThemeColour.eAlertWindowBorder] = new WritableRgbaFloat(Color.GhostWhite).ToUint();
            DefaultCustomColours[eThemeColour.eBadStateColour] = new WritableRgbaFloat(Color.Red).ToUint();
            DefaultCustomColours[eThemeColour.eWarnStateColour] = new WritableRgbaFloat(Color.Yellow).ToUint();
            DefaultCustomColours[eThemeColour.eGoodStateColour] = new WritableRgbaFloat(Color.Green).ToUint();
            DefaultCustomColours[eThemeColour.GraphBackground] = new WritableRgbaFloat(Color.Black).ToUint();

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

            DefaultCustomSizes[eThemeSize.ePreviewSelectedBorder] = 1f;

            foreach (eThemeSize themeStyle in DefaultCustomSizes.Keys)
            {
                if (!ThemeSizesCustom.ContainsKey(themeStyle))
                {
                    ThemeSizesCustom.Add(themeStyle, DefaultCustomSizes[themeStyle]);
                }
            }


            Dictionary<eThemeSize, Vector2> DefaultSizeLimits = new Dictionary<eThemeSize, Vector2>();
            DefaultSizeLimits[eThemeSize.ePreviewSelectedBorder] = new Vector2(0, 30);
            foreach (eThemeSize themeStyle in DefaultSizeLimits.Keys)
            {
                if (!ThemeSizeLimits.ContainsKey(themeStyle))
                {
                    ThemeSizeLimits.Add(themeStyle, DefaultSizeLimits[themeStyle]);
                }
            }
        }



        public static void InitFallbackTheme()
        {
            InitDefaultImGuiColours();

            ThemeMetadata["Name"] = "Fallback";
            ThemeMetadata["Description"] = "Fallback theme for when preloaded and custom themes failed to load";
            ThemeMetadata["Author"] = "rgat fallback theme";
            ThemeMetadata["Author2"] = "https://github.com/ncatlin/rgat";

            InitUnsetCustomColours();
            IsBuiltinTheme = true;
        }


        static unsafe void InitDefaultImGuiColours()
        {
            lock (_lock)
            {
                for (int colI = 0; colI < (int)ImGuiCol.COUNT; colI++)
                {
                    ImGuiCol col = (ImGuiCol)colI;
                    Vector4 ced4vec = *ImGui.GetStyleColorVec4(col);
                    if (ced4vec.W < 0.3) ced4vec.W = 0.7f;

                    ThemeColoursStandard[col] = new WritableRgbaFloat(ced4vec).ToUint();
                }
            }
        }



        public static uint GetThemeColourUINT(eThemeColour item)
        {
            Debug.Assert(ThemeColoursCustom.ContainsKey(item));
            Debug.Assert((uint)item < ThemeColoursCustom.Count);
            return ThemeColoursCustom[item];
        }

        public static WritableRgbaFloat GetThemeColourWRF(eThemeColour item)
        {
            Debug.Assert(ThemeColoursCustom.ContainsKey(item));
            Debug.Assert((uint)item < ThemeColoursCustom.Count);
            return new WritableRgbaFloat(ThemeColoursCustom[item]);
        }

        public static uint GetThemeColourImGui(ImGuiCol item)
        {
            Debug.Assert(ThemeColoursStandard.ContainsKey(item));
            Debug.Assert((uint)item < ThemeColoursStandard.Count);
            lock (_lock) { return ThemeColoursStandard[item]; }
        }

        public static void SetThemeColourImGui(ImGuiCol item, uint color)
        {
            lock (_lock) { ThemeColoursStandard[item] = color; }
        }

        public static float GetThemeSize(eThemeSize item)
        {
            lock (_lock)
            {
                Debug.Assert(ThemeSizesCustom.ContainsKey(item));
                Debug.Assert((uint)item < ThemeSizesCustom.Count);
                return ThemeSizesCustom[item];
            }
        }

        public unsafe static bool DrawColourSelectors()
        {
            bool changed = false;

            ImGuiTableFlags tableFlags = ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY;
            Vector2 tableSize = new Vector2(ImGui.GetContentRegionAvail().X, 350);
            if (ImGui.BeginTable(str_id: "##SelectorsTable", column: 2, flags: tableFlags, outer_size: tableSize))
            {
                float halfWidth = ImGui.GetContentRegionAvail().X / 2;
                ImGui.TableSetupColumn("General Widget Colours", ImGuiTableColumnFlags.WidthFixed, halfWidth);
                ImGui.TableSetupColumn("Custom Widget Colours", ImGuiTableColumnFlags.WidthFixed, halfWidth);
                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableHeadersRow();

                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                for (int colI = 0; colI < (int)ImGuiCol.COUNT; colI++)
                {
                    ImGuiCol stdCol = (ImGuiCol)colI;
                    Vector4 colval = new WritableRgbaFloat(Themes.GetThemeColourImGui(stdCol)).ToVec4();
                    if (ImGui.ColorEdit4(Enum.GetName(typeof(ImGuiCol), colI), ref colval, ImGuiColorEditFlags.AlphaBar))
                    {
                        changed = true;
                        Themes.SetThemeColourImGui(stdCol, new WritableRgbaFloat(colval).ToUint());
                    }

                }

                ImGui.TableSetColumnIndex(1);
                for (int colI = 0; colI < (int)(Themes.ThemeColoursCustom.Count); colI++)
                {
                    Themes.eThemeColour customCol = (Themes.eThemeColour)colI;
                    Vector4 colval = new WritableRgbaFloat(Themes.GetThemeColourUINT(customCol)).ToVec4();
                    if (ImGui.ColorEdit4(Enum.GetName(typeof(Themes.eThemeColour), colI), ref colval, ImGuiColorEditFlags.AlphaBar))
                    {
                        changed = true;
                        Themes.ThemeColoursCustom[customCol] = new WritableRgbaFloat(colval).ToUint();
                    }

                }
                ImGui.EndTable();
            }

            if (ImGui.TreeNode("Dimensions"))
            {
                for (int dimI = 0; dimI < (int)(Themes.ThemeSizesCustom.Count); dimI++)
                {
                    Themes.eThemeSize sizeEnum = (Themes.eThemeSize)dimI;
                    int size = (int)Themes.GetThemeSize(sizeEnum);
                    Vector2 sizelimit = Themes.ThemeSizeLimits[sizeEnum];
                    if (ImGui.SliderInt(Enum.GetName(typeof(Themes.eThemeColour), dimI), ref size, (int)sizelimit.X, (int)sizelimit.Y))
                    {
                        changed = true;
                        Themes.ThemeSizesCustom[sizeEnum] = (float)size;
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
                        validValue = false;

                    if (!validValue)
                    {
                        ImGui.PushStyleColor(ImGuiCol.FrameBg, Themes.GetThemeColourUINT(Themes.eThemeColour.eBadStateColour));
                    }
                    IntPtr p = Marshal.StringToHGlobalUni(kvp.Key);
                    ImGuiInputTextFlags flags = ImGuiInputTextFlags.EnterReturnsTrue | ImGuiInputTextFlags.CallbackEdit;
                    ImGui.InputText(kvp.Key, ref value, 1024, flags, (ImGuiInputTextCallback)TextCheckValid, p);

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

        public static bool GetMetadataValue(string name, out string value)
        {
            lock (_lock)
            {
                return ThemeMetadata.TryGetValue(name, out value);
            }
        }


        static List<string> badFields = new List<string>();

        //this is terrible
        static unsafe int TextCheckValid(ImGuiInputTextCallbackData* p)
        {
            ImGuiInputTextCallbackData cb = *p;
            byte[] currentValue = new byte[cb.BufTextLen];
            Marshal.Copy((IntPtr)cb.Buf, currentValue, 0, p->BufTextLen);
            string actualCurrentValue = Encoding.ASCII.GetString(currentValue);

            string? keyname = Marshal.PtrToStringAuto((IntPtr)cb.UserData);
            if (keyname != null)
            {
                bool validValue = true;

                if (keyname == "Name" && Themes.BuiltinThemes.ContainsKey(actualCurrentValue)) validValue = false;
                if (actualCurrentValue.Contains('"')) validValue = true;

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
        static bool ActivateThemeObject(JObject theme)
        {
            lock (_lock)
            {
                Dictionary<string, string> pendingMetadata = new Dictionary<string, string>();
                Dictionary<ImGuiCol, uint> pendingColsStd = new Dictionary<ImGuiCol, uint>();
                Dictionary<eThemeColour, uint> pendingColsCustom = new Dictionary<eThemeColour, uint>();
                Dictionary<eThemeSize, float> pendingSizes = new Dictionary<eThemeSize, float>();
                Dictionary<eThemeSize, Vector2> pendingLimits = new Dictionary<eThemeSize, Vector2>();

                if (!LoadMetadataStrings(theme, out pendingMetadata, out string errorMsg))
                {
                    Logging.RecordLogEvent(errorMsg); return false;
                }

                if (theme.TryGetValue("CustomColours", out JToken customColTok) && customColTok.Type == JTokenType.Object)
                {
                    foreach (var item in customColTok.ToObject<JObject>())
                    {
                        eThemeColour customcolType;
                        try
                        {
                            customcolType = (eThemeColour)Enum.Parse(typeof(eThemeColour), item.Key, true);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordLogEvent($"Theme has invalid custom colour type {item.Key}-{e.Message}"); return false;
                        }
                        if (customcolType >= eThemeColour.COUNT)
                        {
                            Logging.RecordLogEvent($"Theme has invalid custom colour type {item.Key}"); return false;
                        }
                        if (item.Value.Type != JTokenType.Integer)
                        {
                            Logging.RecordLogEvent($"Theme has custom colour with non-integer colour entry {item.Key}"); return false;
                        }
                        pendingColsCustom[customcolType] = item.Value.ToObject<uint>();
                    }
                }

                if (theme.TryGetValue("StandardColours", out JToken stdColTok) && stdColTok.Type == JTokenType.Object)
                {
                    foreach (var item in stdColTok.ToObject<JObject>())
                    {
                        ImGuiCol stdcolType;
                        try
                        {
                            stdcolType = (ImGuiCol)Enum.Parse(typeof(ImGuiCol), item.Key, true);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordLogEvent($"Theme has invalid standard colour type {item.Key.ToString()}"); return false;
                        }
                        if (stdcolType >= ImGuiCol.COUNT)
                        {
                            Logging.RecordLogEvent($"Theme has invalid standard colour type {item.Key}"); return false;
                        }
                        if (item.Value.Type != JTokenType.Integer)
                        {
                            Logging.RecordLogEvent($"Theme has custom colour with non-integer colour entry {item.Key}"); return false;
                        }
                        pendingColsStd[stdcolType] = item.Value.ToObject<uint>();
                    }
                }

                if (theme.TryGetValue("Sizes", out JToken sizesTok) && sizesTok.Type == JTokenType.Object)
                {
                    foreach (var item in sizesTok.ToObject<JObject>())
                    {
                        eThemeSize sizeType;
                        try
                        {
                            sizeType = (eThemeSize)Enum.Parse(typeof(eThemeSize), item.Key, true);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordLogEvent($"Theme has invalid size type {item.Key}"); return false;
                        }
                        if (sizeType >= eThemeSize.COUNT)
                        {
                            Logging.RecordLogEvent($"Theme has invalid size type {item.Key}"); return false;
                        }
                        if (item.Value.Type != JTokenType.Float)
                        {
                            Logging.RecordLogEvent($"Theme has size with non-float size entry {item.Key}"); return false;
                        }
                        ThemeSizesCustom[sizeType] = item.Value.ToObject<float>();
                    }
                }


                if (theme.TryGetValue("SizeLimits", out JToken sizelimTok) && sizesTok.Type == JTokenType.Object)
                {
                    foreach (var item in sizelimTok.ToObject<JObject>())
                    {
                        eThemeSize sizeType;
                        try
                        {
                            sizeType = (eThemeSize)Enum.Parse(typeof(eThemeSize), item.Key, true);
                        }
                        catch (Exception e)
                        {
                            Logging.RecordLogEvent($"Theme has invalid sizelimit type {item.Key}"); return false;
                        }
                        if (sizeType >= eThemeSize.COUNT)
                        {
                            Logging.RecordLogEvent($"Theme has invalid sizelimit type {item.Key}"); return false;
                        }
                        if (item.Value.Type != JTokenType.Array)
                        {
                            Logging.RecordLogEvent($"Theme has sizelimit with non-array entry {item.Key}"); return false;
                        }
                        JArray limits = item.Value.ToObject<JArray>();
                        if (limits.Count != 2 || limits[0].Type != JTokenType.Float || limits[1].Type != JTokenType.Float)
                        {
                            Logging.RecordLogEvent($"Theme has sizelimit with invalid array size or item types (should be 2 floats) {item.Key}"); return false;
                        }
                        pendingLimits[sizeType] = new Vector2(limits[0].ToObject<float>(), limits[1].ToObject<float>());
                    }
                }

                //all loaded and validated, load them into the UI
                foreach (var kvp in pendingMetadata) ThemeMetadata[kvp.Key] = kvp.Value;
                foreach (var kvp in pendingColsCustom) ThemeColoursCustom[kvp.Key] = kvp.Value;
                foreach (var kvp in pendingColsStd) ThemeColoursStandard[kvp.Key] = kvp.Value;
                foreach (var kvp in pendingLimits) ThemeSizeLimits[kvp.Key] = kvp.Value;
                foreach (var kvp in pendingSizes) ThemeSizesCustom[kvp.Key] = kvp.Value;

                IsBuiltinTheme = BuiltinThemes.ContainsKey(ThemeMetadata["Name"]);

                InitUnsetCustomColours();

                return true;
            }
        }

        public static void SaveMetadataChange(string key, string value)
        {
            ThemeMetadata[key] = value;
            currentThemeJSON["Metadata"][key] = value;
            UnsavedTheme = true;
            IsBuiltinTheme = BuiltinThemes.ContainsKey(ThemeMetadata["Name"]);
        }


        public static void DeleteTheme(string name)
        {
            if (ThemeMetadata["Name"] != name && !BuiltinThemes.ContainsKey(name))
            {
                if (ThemesMetadataCatalogue.ContainsKey(name)) ThemesMetadataCatalogue.Remove(name);
                if (CustomThemes.ContainsKey(name)) CustomThemes.Remove(name);
                WriteCustomThemesToConfig();
            }
        }


        public static void SavePresetTheme(string name, bool setAsDefault)
        {
            if (name.Length == 0 || BuiltinThemes.ContainsKey(name)) return;

            if (name != ThemeMetadata["Name"])
            {
                SaveMetadataChange("Name", name);
            }


            CustomThemes[name] = currentThemeJSON;
            ThemesMetadataCatalogue[name] = ThemeMetadata;
            UnsavedTheme = false;
            WriteCustomThemesToConfig();

            if (setAsDefault)
                DefaultTheme = ThemeMetadata["Name"];

        }

        static JObject currentThemeJSON;
        //controls can check this value to see if the theme has changed
        public static ulong ThemeVariant { get; private set; } = 0;

        public static string RegenerateUIThemeJSON()
        {
            lock (_lock)
            {
                JObject themeJsnObj = new JObject();

                JObject themeCustom = new JObject();
                foreach (var kvp in ThemeColoursCustom) themeCustom.Add(kvp.Key.ToString(), kvp.Value);
                themeJsnObj.Add("CustomColours", themeCustom);

                JObject themeImgui = new JObject();
                foreach (var kvp in ThemeColoursStandard) themeImgui.Add(kvp.Key.ToString(), kvp.Value);
                themeJsnObj.Add("StandardColours", themeImgui);

                JObject sizesObj = new JObject();
                foreach (var kvp in ThemeSizesCustom) sizesObj.Add(kvp.Key.ToString(), kvp.Value);
                themeJsnObj.Add("Sizes", sizesObj);

                JObject sizeLimitsObj = new JObject();
                foreach (var kvp in ThemeSizeLimits) sizeLimitsObj.Add(kvp.Key.ToString(), new JArray(new List<float>() { kvp.Value.X, kvp.Value.Y }));
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


        public static bool ActivateThemeObject(string themeJSON, out string error)
        {
            JObject themeJson = null;
            try
            {
                themeJson = Newtonsoft.Json.Linq.JObject.Parse(themeJSON);
            }
            catch (Exception e)
            {
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


        static bool LoadMetadataStrings(JObject themeObj, out Dictionary<string, string> result, out string error)
        {
            result = new Dictionary<string, string>();

            JObject metadataObj;
            if (themeObj.TryGetValue("Metadata", out JToken mdTok) && mdTok.Type == JTokenType.Object)
            {
                metadataObj = mdTok.ToObject<JObject>();
            }
            else
            {
                error = "Unable to find \"Metadata\" object in theme";
                return false;
            }

            foreach (var item in metadataObj)
            {
                if (item.Key.Length > 255)
                {
                    error = $"Theme has metadata key with excessive length {item.Key.Length}"; return false;
                }
                if (item.Value.Type != JTokenType.String)
                {
                    error = $"Theme has non-string metadata item {item.Key}"; return false;
                }
                string mdvalue = item.Value.ToObject<string>();
                if (mdvalue.Length > 4096)
                {
                    error = $"Skipping Theme metadata value with excessive length {mdvalue.Length}"; return false;
                }
                result[item.Key] = mdvalue;
            }
            error = "Success";
            return true;
        }


        public static void LoadTheme(string themename)
        {
            if (ThemeMetadata.TryGetValue("Name", out string currentTheme) && currentTheme == themename)
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
            Logging.RecordLogEvent($"Tried to load unknown theme {themename}", Logging.LogFilterType.TextError);
        }


        public static Dictionary<string, JObject> CustomThemes = new Dictionary<string, JObject>();
        public static Dictionary<string, JObject> BuiltinThemes = new Dictionary<string, JObject>();
        public static Dictionary<string, Dictionary<string, string>> ThemesMetadataCatalogue = new Dictionary<string, Dictionary<string, string>>();

        public static void LoadPresetThemes(JArray themesArray)
        {
            Logging.RecordLogEvent($"Loading {themesArray.Count} builtin themes", Logging.LogFilterType.TextDebug);
            for (var i = 0; i < themesArray.Count; i++)
            {
                JObject theme = themesArray[i].Value<JObject>();
                if (!LoadMetadataStrings(theme, out Dictionary<string, string> metadata, out string error))
                {
                    Logging.RecordLogEvent($"Error loading metadata for preloaded theme {i}: {error}");
                    continue;
                }

                if (!metadata.TryGetValue("Name", out string themeName))
                {
                    Logging.RecordLogEvent($"Skipping load for preloaded theme {i} (no 'Name' in metadata)");
                    continue;
                }

                Logging.RecordLogEvent($"Loaded builtin theme " + themeName, Logging.LogFilterType.TextDebug);
                BuiltinThemes[themeName] = theme;
                ThemesMetadataCatalogue[themeName] = metadata;
            }
        }


        public sealed class ThemesSection : ConfigurationSection
        {

            private static ConfigurationPropertyCollection _Properties;
            private static readonly ConfigurationProperty _customThemeJSONs2 = new ConfigurationProperty(
                "CustomThemes",
                typeof(JObject),
                new JObject(),
                new GlobalConfig.JSONBlobConverter(),
                null,
                ConfigurationPropertyOptions.IsRequired);

            private static readonly ConfigurationProperty _MaxUsers =
                new ConfigurationProperty("maxUsers", typeof(long), (long)1000, ConfigurationPropertyOptions.None);


            public ThemesSection()
            {
                _Properties = new ConfigurationPropertyCollection();
                _Properties.Add(_MaxUsers);
                _Properties.Add(_customThemeJSONs2);
            }

            protected override object GetRuntimeObject() => base.GetRuntimeObject();

            protected override ConfigurationPropertyCollection Properties => _Properties;

            public JObject CustomThemes
            {
                get => (JObject)this["CustomThemes"];
                set
                {
                    this["CustomThemes"] = value;
                }
            }

            [LongValidator(MinValue = 1, MaxValue = 1000000, ExcludeRange = false)]
            public long MaxUsers
            {
                get => (long)this["maxUsers"];

                set
                {
                    this["maxUsers"] = value;
                }
            }

        }


        static void WriteCustomThemesToConfig()
        {
            var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            ThemesSection sec = (ThemesSection)configFile.GetSection("CustomThemes");
            if (sec == null)
            {
                sec = new ThemesSection();
                configFile.Sections.Add("CustomThemes", sec);
            }

            JObject themesObj = new JObject();
            foreach (KeyValuePair<string, JObject> theme in CustomThemes)
            {
                themesObj.Add(theme.Key, theme.Value);
            }

            sec.CustomThemes = themesObj;
            sec.SectionInformation.ForceSave = true;
            configFile.Save();
        }




        public static void LoadCustomThemes()
        {
            var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            ThemesSection sec = (ThemesSection)configFile.GetSection("CustomThemes");
            if (sec != null)
            {
                JObject themes = sec.CustomThemes;
                foreach (var kvp in themes)
                {
                    if (kvp.Value.Type == JTokenType.Object)
                    {
                        JObject themeData = kvp.Value.ToObject<JObject>();
                        if (themeData.ContainsKey("Metadata") && themeData.TryGetValue("Metadata", out JToken mdTok) && mdTok.Type == JTokenType.Object)
                        {
                            JObject mdobj = (JObject)mdTok;
                            Dictionary<string, string> mdDict = new Dictionary<string, string>();
                            foreach (var mditem in mdobj)
                            {
                                if (mditem.Value.Type == JTokenType.String)
                                {
                                    mdDict[mditem.Key] = mditem.Value.ToString();
                                }
                            }
                            if (mdDict.TryGetValue("Name", out string themeName) && themeName.Length > 0)
                            {

                                ThemesMetadataCatalogue[themeName] = mdDict;
                                CustomThemes[themeName] = themeData;
                            }
                        }

                    }
                }
            }

            KeyValueConfigurationElement userDefaultTheme = configFile.AppSettings.Settings["DefaultTheme"];
            if (userDefaultTheme != null)
                DefaultTheme = userDefaultTheme.Value;
        }


        public static void ActivateDefaultTheme()
        {
            if (DefaultTheme.Length > 0)
            {
                if (CustomThemes.TryGetValue(DefaultTheme, out JObject themeObj))
                {
                    ActivateThemeObject(themeObj);
                    return;
                }
                else if (BuiltinThemes.TryGetValue(DefaultTheme, out themeObj))
                {
                    ActivateThemeObject(themeObj);
                    return;
                }
                Logging.RecordLogEvent($"Could not find default theme {DefaultTheme}");
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

            if (ThemeColoursStandard.Count == 0)
            {
                InitFallbackTheme();
                InitUnsetCustomColours();
            }
        }

    }
}
