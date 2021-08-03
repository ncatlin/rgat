using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json.Linq;

namespace rgatCore
{
    public class WinAPIDetails
    {
        public static bool Loaded { get; private set; }
        public static void Load(string datapath)
        {
            if (!File.Exists(datapath))
            {
                Logging.RecordLogEvent($"Windows API datafile {datapath} did not exist");
                return;
            }

            StreamReader file;
            try
            {
                file = File.OpenText(datapath);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Windows API datafile {datapath} could not be opened: {e.Message}");
                return;
            }

            Newtonsoft.Json.Linq.JArray apiDataJSON = null;

            string jsnfile = file.ReadToEnd();
            try
            {
                apiDataJSON = Newtonsoft.Json.Linq.JArray.Parse(jsnfile);
            }
            catch (Newtonsoft.Json.JsonReaderException e)
            {
                Logging.RecordLogEvent($"Failed to parse Windows API datafile JSON {datapath}: {e.Message}");
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Failed to load Windows API datafile {datapath}: {e.Message}");
            }

            if (apiDataJSON != null)
            {
                LoadJSON(apiDataJSON);
                Loaded = true;
            }


            file.Close();
        }




        static Dictionary<string, int> _configuredModules = new Dictionary<string, int>();
        static Dictionary<int, string> _defaultFilters = new Dictionary<int, string>();
        static Dictionary<int, Dictionary<string, API_ENTRY>> _configuredSymbols = new Dictionary<int, Dictionary<string, API_ENTRY>>();

        static void LoadJSON(Newtonsoft.Json.Linq.JArray JItems)
        {
            foreach (JToken moduleEntryTok in JItems)
            {

                if (moduleEntryTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent("API Data JSON has a library entry which is not an object. Abandoning Load.", Logging.LogFilterType.TextError);
                    return;
                }

                JObject moduleEntry = moduleEntryTok.ToObject<JObject>();
                if (!moduleEntry.TryGetValue("Library", out JToken libnameTok) || libnameTok.Type != JTokenType.String)
                {
                    Logging.RecordLogEvent("API Data library entry has no 'Library' name string. Abandoning Load.", Logging.LogFilterType.TextError);
                    return;
                }

                string libname = libnameTok.ToString().ToLower();
                if (_configuredModules.ContainsKey(libname))
                {
                    continue;
                }

                int moduleReference = _configuredModules.Count;
                _configuredModules.Add(libname, moduleReference);


                string moduleFilter;
                if (moduleEntry.TryGetValue("DefaultFilter", out JToken filterTok) && filterTok.Type == JTokenType.String)
                {
                    moduleFilter = filterTok.ToString();
                }
                else
                {
                    moduleFilter = "Other";
                }

                _defaultFilters.Add(moduleReference, moduleFilter);

                if (moduleEntry.TryGetValue("Interfaces", out JToken ifTok) && ifTok.Type == JTokenType.Object)
                {
                    Dictionary<string, API_ENTRY> moduleSyms = new Dictionary<string, API_ENTRY>();

                    JObject APIs = ifTok.ToObject<JObject>();
                    foreach (var API in APIs)
                    {
                        if (API.Value.Type != JTokenType.Object)
                        {
                            Logging.RecordLogEvent($"API data entry {libname}:{API.Key} is not an object");
                            continue;
                        }
                        string apiname = API.Key;
                        JObject APIJsn = API.Value.ToObject<JObject>();

                        API_ENTRY APIItem = new API_ENTRY();

                        if (APIJsn.TryGetValue("Filter", out filterTok) && filterTok.Type == JTokenType.String)
                        {
                            APIItem.FilterType = filterTok.ToString();
                        }
                        else
                        {
                            APIItem.FilterType = moduleFilter;
                        }

                        if (APIJsn.TryGetValue("Parameters", out JToken paramsTok) && paramsTok.Type == JTokenType.Array)
                        {
                            JArray callParams = paramsTok.ToObject<JArray>();
                            APIItem.LoggedParams = ExtractParameters(callParams, libname, apiname);
                        }

                        if (APIJsn.TryGetValue("KeyParam", out JToken keyParamTok) && keyParamTok.Type == JTokenType.Integer)
                        {
                            APIItem.KeyParameter = keyParamTok.ToObject<int>();
                        }
                        else
                        {
                            APIItem.KeyParameter = int.MinValue;
                        }

                        if (APIJsn.TryGetValue("Interaction", out JToken interactionTok) && interactionTok.Type == JTokenType.String)
                        {
                            APIItem.InteractionType = interactionTok.ToObject<string>();
                        }



                        moduleSyms.Add(apiname, APIItem);
                    }
                    _configuredSymbols.Add(moduleReference, moduleSyms);
                }


            }
        }

        static List<API_PARAM_ENTRY> ExtractParameters(JArray callParams, string libname, string apiname)
        {
            List<API_PARAM_ENTRY> result = new List<API_PARAM_ENTRY>();
            foreach (JToken callParamTok in callParams)
            {
                if (callParamTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a non-object parameter");
                    continue;
                }

                JObject callParam = callParamTok.ToObject<JObject>();
                if (!callParam.TryGetValue("Index", out JToken paramIndexTok) || paramIndexTok.Type != JTokenType.Integer)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter with no valid index");
                    continue;
                }
                if (!callParam.TryGetValue("Name", out JToken paramNameTok) || paramNameTok.Type != JTokenType.String)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter with no valid name");
                    continue;
                }

                API_PARAM_ENTRY param = new API_PARAM_ENTRY();
                param.index = paramIndexTok.ToObject<int>();
                param.name = paramNameTok.ToObject<string>();

                if (callParam.TryGetValue("Type", out JToken paramTypeTok) && paramTypeTok.Type == JTokenType.String)
                {
                    if (Enum.TryParse(typeof(APIParamType), paramTypeTok.ToObject<string>(), ignoreCase: true, out object paramtype))
                    {
                        param.paramType = (APIParamType)paramtype;
                    }
                    else
                    {
                        param.paramType = APIParamType.InfoString;
                    }
                    continue;
                }
                result.Add(param);
            }
            return result;
        }



        public enum APIParamType { InfoString, PathString, FileReference, RegistryReference, NetworkReference }
        //enum APIInteractionType { None, Open, Close, Read, Write, Delete, Query, Lock, Unlock }

        public struct API_PARAM_ENTRY
        {
            public int index;
            public string name;
            public APIParamType paramType;
        }
        public struct API_ENTRY
        {
            public string FilterType;
            public List<API_PARAM_ENTRY> LoggedParams;
            public string InteractionType;
            public int KeyParameter;
        }

        public static int ResolveModuleEnum(string path)
        {
            string fname = System.IO.Path.GetFileName(path).ToLower();
            if (_configuredModules.TryGetValue(fname, out int moduleEnum))
                return moduleEnum;
            return -1;
        }

        public static string ResolveAPIFilterType(int moduleReference, string symbolname)
        {

            if (_configuredSymbols.ContainsKey(moduleReference) && _configuredSymbols[moduleReference].TryGetValue(symbolname, out API_ENTRY value)) return value.FilterType;
            if (moduleReference < _defaultFilters.Count) return _defaultFilters[moduleReference];
            return "Other";

        }

        public static API_ENTRY? GetAPIInfo(int moduleReference, string symbolname)
        {
            if (_configuredSymbols.ContainsKey(moduleReference) && _configuredSymbols[moduleReference].TryGetValue(symbolname, out API_ENTRY value)) return value;
            return null;
        }
    }
}