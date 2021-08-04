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
                Logging.RecordLogEvent($"Windows API datafile {datapath} could not be opened: {e.Message}", Logging.LogFilterType.TextError);
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
                Logging.RecordLogEvent($"Failed to parse Windows API datafile JSON {datapath}: {e.Message}", Logging.LogFilterType.TextError);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Failed to load Windows API datafile {datapath}: {e.Message}", Logging.LogFilterType.TextError);
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

        public class InteractionEffect
        {

        }

        public class LinkReferenceEffect : InteractionEffect
        {
            public int referenceIndex;
            public int entityIndex;
        }

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
                            Logging.RecordLogEvent($"API data entry {libname}:{API.Key} is not an object", Logging.LogFilterType.TextError);
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

                            if (APIItem.LoggedParams != null && APIItem.LoggedParams.Count > 0)
                            {
                                if (APIJsn.TryGetValue("Effects", out JToken effectsTok) && effectsTok.Type == JTokenType.Array)
                                {
                                    APIItem.Effects = ExtractEffects(effectsTok.ToObject<JArray>(), libname, apiname, APIItem.LoggedParams);
                                } 
                            }

                        }

                        if (APIJsn.TryGetValue("Label", out JToken interactionTok) && interactionTok.Type == JTokenType.String)
                        {
                            APIItem.Label = interactionTok.ToObject<string>();
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
            int paramsOffset = -1;
            foreach (JToken callParamTok in callParams)
            {
                paramsOffset += 1;

                if (callParamTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a non-object parameter", Logging.LogFilterType.TextError);
                    return null;
                }

                JObject callParam = callParamTok.ToObject<JObject>();
                if (!callParam.TryGetValue("Index", out JToken paramIndexTok) || paramIndexTok.Type != JTokenType.Integer)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter with no valid index", Logging.LogFilterType.TextError);
                    return null;
                }
                if (!callParam.TryGetValue("Name", out JToken paramNameTok) || paramNameTok.Type != JTokenType.String)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter with no valid name", Logging.LogFilterType.TextError);
                    return null;
                }

                API_PARAM_ENTRY param = new API_PARAM_ENTRY();
                param.index = paramIndexTok.ToObject<int>();
                param.name = paramNameTok.ToObject<string>();

                if (callParam.TryGetValue("Type", out JToken paramTypeTok) && paramTypeTok.Type == JTokenType.String)
                {
                    if (Enum.TryParse(typeof(APIParamType), paramTypeTok.ToObject<string>(), ignoreCase: true, out object paramtype))
                    {
                        param.paramType = (APIParamType)paramtype;

                        if (param.paramType != APIParamType.Info)
                        {
                            if (!callParam.TryGetValue("Category", out JToken catTok) ||
                                catTok.Type != JTokenType.String ||
                                !Enum.TryParse(typeof(InteractionEntityType), catTok.ToString(), out object categoryEnum))
                            {
                                Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter ({param.name}) with no valid Category", Logging.LogFilterType.TextError);
                                return null;
                            }

                            param.Category = (InteractionEntityType)categoryEnum;


                            if (!callParam.TryGetValue("RawType", out JToken rawTypeTok) ||
                                rawTypeTok.Type != JTokenType.String ||
                                !Enum.TryParse(typeof(InteractionRawType), rawTypeTok.ToString(), out object rawtypeEnum))
                            {
                                Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter ({param.name}) with no valid RawType", Logging.LogFilterType.TextError);
                                return null;
                            }
                            param.RawType = (InteractionRawType)rawtypeEnum;
                        }
                    }
                    else
                    {
                        param.paramType = APIParamType.Info;
                    }
                }
                result.Add(param);
            }
            return result;
        }


        static List<InteractionEffect> ExtractEffects(JArray effectToks, string libname, string apiname, List<API_PARAM_ENTRY> callparams)
        {
            List<InteractionEffect> result = new List<InteractionEffect>();

            foreach (JToken effectTok in effectToks)
            {
                if (effectTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a non-object interaction effect", Logging.LogFilterType.TextError);
                    break;
                }
                JObject effectJsn = effectTok.ToObject<JObject>();
                if (!effectJsn.TryGetValue("Type", out JToken typetok) || typetok.Type != JTokenType.String)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has an untyped interaction effect", Logging.LogFilterType.TextError);
                    break;
                }
                bool valid = false;
                switch (typetok.ToString())
                {
                    case "LinkReference":
                        if (effectJsn.TryGetValue("EntityIndex", out JToken entidx) &&
                            effectJsn.TryGetValue("ReferenceIndex", out JToken refidx) &&
                            entidx.Type == JTokenType.Integer &&
                            refidx.Type == JTokenType.Integer)
                        {
                            int entityParamCallIndex = entidx.ToObject<int>();
                            int entityParamListIndex = callparams.FindIndex(x => x.index == entityParamCallIndex);

                            int refParamCallIndex = refidx.ToObject<int>();
                            int refParamListIndex = callparams.FindIndex(x => x.index == refParamCallIndex);


                            if (refParamListIndex != -1 && entityParamListIndex != -1)
                            {
                                LinkReferenceEffect effect = new LinkReferenceEffect() { entityIndex = entityParamListIndex, referenceIndex = refParamListIndex };
                                result.Add(effect);
                                valid = true;
                            }
                        }
                        break;
                    default:
                        Logging.RecordLogEvent($"API data entry {libname}:{apiname} has an unknown interaction effect {typetok}", Logging.LogFilterType.TextError);
                        break;
                }
                if (!valid)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has an effect ({typetok}) with invalid parameters", Logging.LogFilterType.TextError);
                }
            }
            return result;
        }



        public enum APIParamType { Info, Entity, Reference }
        public enum InteractionEntityType { File, Host }
        public enum InteractionRawType { Handle, Path, Domain }
        //enum APIInteractionType { None, Open, Close, Read, Write, Delete, Query, Lock, Unlock }

        /// <summary>
        /// Describes certain interesting parameters of an API call which we can link together to describe program behaviour
        /// </summary>
        public struct API_PARAM_ENTRY
        {
            public int index;
            public string name;
            public APIParamType paramType;
            public InteractionEntityType Category;
            public InteractionRawType RawType;
        }

        /// <summary>
        /// Describes the effects of an API call we have recorded
        /// </summary>
        public struct API_ENTRY
        {
            /// <summary>
            /// A category this API falls into, for UI filtering. This might become a list of strings/tags later.
            /// </summary>
            public string FilterType;
            /// <summary>
            /// A list of parameters/return results from the API call. Used to map their interaction with targets for plotting on the analysis chart.
            /// </summary>
            public List<API_PARAM_ENTRY> LoggedParams;
            /// <summary>
            /// How the API call interacted with the entity. Used as a label in the analysis chart.
            /// </summary>
            public string Label;

            //how this api call affects our tracking of interaction targets
            public List<InteractionEffect> Effects;
        }

        /// <summary>
        /// Lookup a system library by path and get a reference that can be used to index internal library metadata (filter types, symbol info)
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public static int ResolveModuleEnum(string path)
        {
            string fname = System.IO.Path.GetFileName(path).ToLower();
            if (_configuredModules.TryGetValue(fname, out int moduleEnum))
                return moduleEnum;
            return -1;
        }

        /*
        public static string ResolveAPIFilterType(int moduleReference, string symbolname)
        {

            if (_configuredSymbols.ContainsKey(moduleReference) && _configuredSymbols[moduleReference].TryGetValue(symbolname, out API_ENTRY value)) return value.FilterType;
            if (moduleReference < _defaultFilters.Count) return _defaultFilters[moduleReference];
            return "Other";

        }*/

        /// <summary>
        /// Get loaded API info for a symbol
        /// </summary>
        /// <param name="moduleReference">Internal library reference from ResolveModuleEnum </param>
        /// <param name="symbolname">Case sensitive API name (ie: a library export like you would pass to GetProcAddress)</param>
        /// <returns>API_ENTRY struct for the symbol if we have metadata for it, otherwise null</returns>
        public static API_ENTRY? GetAPIInfo(int moduleReference, string symbolname)
        {
            if (_configuredSymbols.ContainsKey(moduleReference) && _configuredSymbols[moduleReference].TryGetValue(symbolname, out API_ENTRY value)) return value;
            return null;
        }
    }
}