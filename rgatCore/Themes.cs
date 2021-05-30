﻿using ImGuiNET;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;

namespace rgatCore
{
    class Themes
    {

        /*
 * Theme - probably going to put in own class
 */
        //todo should be lists not dicts
        public enum eThemeColour
        {
            ePreviewText, ePreviewTextBackground, ePreviewPaneBorder, ePreviewPaneBackground,
            ePreviewZoomEnvelope,
            eHeat0Lowest, eHeat1, eHeat2, eHeat3, eHeat4, eHeat5, eHeat6, eHeat7, eHeat8, eHeat9Highest,
            eVisBarPlotLine, eVisBarBg, eAlertWindowBg, eAlertWindowBorder,
            COUNT
        }
        public enum eThemeSize
        {
            ePreviewSelectedBorder,
            COUNT
        }

        public static Dictionary<ImGuiCol, uint> ThemeColoursStandard = new Dictionary<ImGuiCol, uint>();
        public static Dictionary<eThemeColour, uint> ThemeColoursCustom = new Dictionary<eThemeColour, uint>();
        public static Dictionary<eThemeSize, float> ThemeSizesCustom = new Dictionary<eThemeSize, float>();
        public static Dictionary<eThemeSize, Vector2> ThemeSizeLimits = new Dictionary<eThemeSize, Vector2>();
        public static Dictionary<string, string> ThemeMetadata = new Dictionary<string, string>();
        public static bool IsBuiltinTheme = true;
        public static bool UnsavedTheme = false;
        static string _defaultTheme = "";
        public static string DefaultTheme
        {
            get => _defaultTheme;
            set
            {
                if (ThemesMetadataCatalogue.ContainsKey(value))
                {
                    _defaultTheme = value;
                    Threads.GlobalConfig.AddUpdateAppSettings("DefaultTheme", value);
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

            ThemeColoursCustom[eThemeColour.ePreviewText] = new WritableRgbaFloat(Af: 1f, Gf: 1, Bf: 1, Rf: 1).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewTextBackground] = new WritableRgbaFloat(Af: 0.3f, Gf: 0, Bf: 0, Rf: 0).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewPaneBorder] = new WritableRgbaFloat(Af: 1f, Gf: 0, Bf: 0, Rf: 1).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewPaneBackground] = new WritableRgbaFloat(Af: 1f, Gf: 0.05f, Bf: 0.05f, Rf: 0.05f).ToUint();
            ThemeColoursCustom[eThemeColour.ePreviewZoomEnvelope] = new WritableRgbaFloat(Af: 0.7f, Gf: 0.7f, Bf: 0.7f, Rf: 0.7f).ToUint();

            ThemeColoursCustom[eThemeColour.eHeat0Lowest] = new WritableRgbaFloat(0, 0, 155f / 255f, 0.7f).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat1] = new WritableRgbaFloat(46f / 255f, 28f / 255f, 155f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat2] = new WritableRgbaFloat(95f / 255f, 104f / 255f, 226f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat3] = new WritableRgbaFloat(117f / 255f, 143f / 255f, 223f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat4] = new WritableRgbaFloat(255f / 255f, 255f / 225f, 255f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat5] = new WritableRgbaFloat(252f / 255f, 196f / 255f, 180f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat6] = new WritableRgbaFloat(242f / 255f, 152f / 255f, 152f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat7] = new WritableRgbaFloat(249f / 255f, 107f / 255f, 107f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat8] = new WritableRgbaFloat(255f / 255f, 64f / 255f, 64f / 255f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eHeat9Highest] = new WritableRgbaFloat(1, 0f, 0f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eVisBarPlotLine] = new WritableRgbaFloat(1, 0f, 0f, 1).ToUint();
            ThemeColoursCustom[eThemeColour.eVisBarBg] = new WritableRgbaFloat(Color.Black).ToUint();
            ThemeColoursCustom[eThemeColour.eAlertWindowBg] = new WritableRgbaFloat(Color.SlateBlue).ToUint();
            ThemeColoursCustom[eThemeColour.eAlertWindowBorder] = new WritableRgbaFloat(Color.GhostWhite).ToUint();


            ThemeSizesCustom[eThemeSize.ePreviewSelectedBorder] = 1f;
            ThemeSizeLimits[eThemeSize.ePreviewSelectedBorder] = new Vector2(0, 30);
            IsBuiltinTheme = true;
        }


        static unsafe void InitDefaultImGuiColours()
        {
            for (int colI = 0; colI < (int)ImGuiCol.COUNT; colI++)
            {
                ImGuiCol col = (ImGuiCol)colI;
                Vector4 ced4vec = *ImGui.GetStyleColorVec4(col);
                if (ced4vec.W < 0.3) ced4vec.W = 0.7f;

                ThemeColoursStandard[col] = new WritableRgbaFloat(ced4vec).ToUint();
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
            return ThemeColoursStandard[item];
        }

        public static float GetThemeSize(eThemeSize item)
        {
            Debug.Assert(ThemeSizesCustom.ContainsKey(item));
            Debug.Assert((uint)item < ThemeSizesCustom.Count);
            return ThemeSizesCustom[item];
        }

        /*
 * This will load valid but incomplete theme data into the existing theme, but not if there
 * is any invalid data
 */
        static bool ActivateThemeObject(JObject theme)
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
                        Logging.RecordLogEvent($"Theme has invalid custom colour type {item.Key.ToString()}"); return false;
                    }
                    if (customcolType >= eThemeColour.COUNT)
                    {
                        Logging.RecordLogEvent($"Theme has invalid custom colour type {item.Key.ToString()}"); return false;
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
                        Logging.RecordLogEvent($"Theme has invalid standard colour type {item.Key.ToString()}"); return false;
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
                        Logging.RecordLogEvent($"Theme has invalid size type {item.Key.ToString()}"); return false;
                    }
                    if (sizeType >= eThemeSize.COUNT)
                    {
                        Logging.RecordLogEvent($"Theme has invalid size type {item.Key.ToString()}"); return false;
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

            return true;
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


        public static void SavePresetTheme(string name)
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

        }

        static JObject currentThemeJSON;

        public static string RegenerateUIThemeJSON()
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
            return themeJsnObj.ToString();
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
            private static bool _ReadOnly;

            /*
            [TypeConverter(typeof(JSONBlobConverter))]
            private readonly ConfigurationProperty _customThemeJSONs = new ConfigurationProperty("customThemeJSONs", 
                typeof(Dictionary<string, string>), new Dictionary<string, string>(), ConfigurationPropertyOptions.IsRequired);
            */

            //[TypeConverter(typeof(JSONBlobConverter))]
            private static readonly ConfigurationProperty _customThemeJSONs2 = new ConfigurationProperty(
                "CustomThemes",
                typeof(JObject),
                new JObject(),
                new JSONBlobConverter(),
                null,
                ConfigurationPropertyOptions.IsRequired);


            private static readonly ConfigurationProperty _MaxUsers =
                new ConfigurationProperty("maxUsers", typeof(long), (long)1000, ConfigurationPropertyOptions.None);

            public class JSONBlobConverter : TypeConverter
            {
                public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
                {
                    return (sourceType == typeof(JObject)) || (sourceType == typeof(string));
                }
                public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
                {
                    if (value.GetType() != typeof(string))
                    {
                        throw new NotImplementedException($"JSONBlobConverter can only convert from string");
                    }

                    try
                    {
                        JObject result = JObject.Parse((String)value);
                        return result;
                    }
                    catch
                    {
                        throw new DataException($"JSONBlobConverter ConvertFrom Bad json value {value}");
                    }
                }

                public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
                {
                    return (destinationType == typeof(JObject)) || (destinationType == typeof(string));
                }
                public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType)
                {
                    if (destinationType == typeof(string))
                    {
                        if (value.GetType() == typeof(JObject))
                        {
                            return value.ToString();
                        }
                    }
                    throw new NotImplementedException($"ConvertTo can't convert type {value.GetType()} to {destinationType}");
                    return null;
                }
            }



            public ThemesSection()
            {
                _Properties = new ConfigurationPropertyCollection();
                //_Properties.Add(_customThemeJSONs);
                _Properties.Add(_MaxUsers);
                _Properties.Add(_customThemeJSONs2);
            }
            protected override object GetRuntimeObject()
            {
                // To enable property setting just assign true to
                // the following flag.
                _ReadOnly = true;
                return base.GetRuntimeObject();
            }

            protected override ConfigurationPropertyCollection Properties
            {
                get
                {
                    return _Properties;
                }
            }

            public JObject CustomThemes
            {
                get
                {
                    return (JObject)this["CustomThemes"];
                }
                set
                {
                    this["CustomThemes"] = value;
                }
            }

            [LongValidator(MinValue = 1, MaxValue = 1000000, ExcludeRange = false)]
            public long MaxUsers
            {
                get
                {
                    return (long)this["maxUsers"];
                }
                set
                {
                    this["maxUsers"] = value;
                }
            }

        }

        static void WriteCustomThemesToConfig()
        {
            var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            //ThemesSection sec = (ThemesSection)configFile.Sections.Get("CustomThemes");
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
            }
        }

    }
}
