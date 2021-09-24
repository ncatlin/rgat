using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;

namespace rgat
{
    /// <summary>
    /// Handles loading and interaction with an API data file, for use 
    /// in the analysis tab to so how the trace interacted with the system
    /// </summary>
    public class APIDetailsWin
    {
        /// <summary>
        /// True if the API data file was loaded
        /// </summary>
        public static bool Loaded { get; private set; }


        /// <summary>
        /// Load an API data file
        /// </summary>
        /// <param name="datapath">Fileystem path of the file</param>
        /// <param name="progress">Optional IProgress for file loading</param>
        public static void Load(string datapath, IProgress<float>? progress = null)
        {
            if (!File.Exists(datapath))
            {
                Logging.RecordError($"Windows API datafile {datapath} did not exist");
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

            Newtonsoft.Json.Linq.JArray? apiDataJSON = null;

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
                LoadJSON(apiDataJSON, progress);
                Loaded = true;
            }


            file.Close();
        }

        /// <summary>
        /// Search for the API Data file
        /// </summary>
        /// <returns>Path of the file if found, otherwise null</returns>
        public static string? FindAPIDatafile()
        {
            try
            {
                string candidate = System.IO.Path.Combine(GlobalConfig.BaseDirectory, "APIDataWin.json");
                if (File.Exists(candidate))
                {
                    return candidate;
                }

                candidate = System.IO.Path.Combine(AppContext.BaseDirectory, "APIDataWin.json");
                if (File.Exists(candidate))
                {
                    return candidate;
                }

                byte[]? apiFileBytes = rgatState.ReadBinaryResource("APIDataWin");
                if (apiFileBytes != null)
                {
                    File.WriteAllBytes(candidate, apiFileBytes);
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
            catch (Exception e)
            {
                Logging.RecordError($"Error loading api data file: {e.Message}");
            }
            return null;
        }


        static readonly Dictionary<string, int> _configuredModules = new Dictionary<string, int>();
        static readonly Dictionary<int, string> _defaultFilters = new Dictionary<int, string>();
        static readonly Dictionary<int, Dictionary<string, API_ENTRY>> _configuredSymbols = new Dictionary<int, Dictionary<string, API_ENTRY>>();

        /// <summary>
        /// A base class for API interaction effects
        /// </summary>
        public class InteractionEffect
        {
            /// <summary>
            /// Needed for deserialisation
            /// </summary>
            public string? TypeName;
        }

        /// <summary>
        /// The effect of this API is to create a reference to an entity
        /// Eg: Opening a file creates a handle which refers to a filepath
        /// </summary>
        public class LinkReferenceEffect : InteractionEffect
        {
            /// <summary>
            /// Create a link reference effect for an API call
            /// </summary>
            /// <param name="entityIdx">Position of the entity parameter (-1 = return val, 0 = first param)</param>
            /// <param name="refIdx">Position of the reference parameter  (-1 = return val, 0 = first param)</param>
            public LinkReferenceEffect(int entityIdx, int refIdx) { base.TypeName = "Link"; ReferenceIndex = refIdx; EntityIndex = entityIdx; }
            /// <summary>
            /// The position of the parameter which is a reference to an entity
            /// </summary>
            public int ReferenceIndex { get; private set; }
            /// <summary>
            /// The position of the parameter which is the entity that the reference will linked to
            /// </summary>
            public int EntityIndex { get; private set; }
        }


        /// <summary>
        /// The effect of this API is to actually interact with an entity
        /// Eg: Writing to a file, sending network data to an IP address
        /// </summary>
        public class UseReferenceEffect : InteractionEffect
        {
            /// <summary>
            /// Create a reference usage effect
            /// </summary>
            /// <param name="refIdx">Position of the reference parameter  (-1 = return val, 0 = first param)</param>
            public UseReferenceEffect(int refIdx) { base.TypeName = "Use"; ReferenceIndex = refIdx; }
            /// <summary>
            /// The parameter index of the entity reference that is interacted with (-1 = return val, 0 = first param)
            /// </summary>
            public int ReferenceIndex { get; private set; }
        }


        /// <summary>
        /// The effect of this API is to destroy a reference to an entity (eg: CloseHandle destroys a HANDLE)
        /// </summary>
        public class DestroyReferenceEffect : InteractionEffect
        {
            /// <summary>
            /// Create a reference destruction effect
            /// </summary>
            /// <param name="refIdx">Position of the reference parameter  (-1 = return val, 0 = first param)</param>
            public DestroyReferenceEffect(int refIdx) { base.TypeName = "Destroy"; ReferenceIndex = refIdx; }
            /// <summary>
            /// The parameter index of the entity reference that is destroyed (-1 = return val, 0 = first param)
            /// </summary>
            public int ReferenceIndex { get; private set; }
        }


        static void LoadJSON(Newtonsoft.Json.Linq.JArray JItems, IProgress<float>? progress = null)
        {
            float moduleCount = JItems.Count;

            for (var moduleI = 0; moduleI < moduleCount; moduleI++)
            {
                JToken moduleEntryTok = JItems[moduleI];

                if (moduleEntryTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent("API Data JSON has a library entry which is not an object. Abandoning Load.", Logging.LogFilterType.TextError);
                    return;
                }

                JObject? moduleEntry = moduleEntryTok.ToObject<JObject>();
                if (moduleEntry is null ||
                    !moduleEntry.TryGetValue("Library", out JToken? libnameTok) ||
                    libnameTok.Type != JTokenType.String)
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
                if (moduleEntry.TryGetValue("DefaultFilter", out JToken? filterTok) && filterTok.Type == JTokenType.String)
                {
                    moduleFilter = filterTok.ToString();
                }
                else
                {
                    moduleFilter = "Other";
                }

                _defaultFilters.Add(moduleReference, moduleFilter);

                if (moduleEntry.TryGetValue("Interfaces", out JToken? ifTok) && ifTok.Type == JTokenType.Object)
                {
                    Dictionary<string, API_ENTRY> moduleSyms = new Dictionary<string, API_ENTRY>();

                    JObject? APIs = ifTok.ToObject<JObject>();
                    if (APIs is null)
                    {
                        continue;
                    }

                    foreach (var API in APIs)
                    {
                        if (API.Value is null || API.Value.Type != JTokenType.Object)
                        {
                            Logging.RecordLogEvent($"API data entry {libname}:{API.Key} is not an object", Logging.LogFilterType.TextError);
                            continue;
                        }
                        JObject? APIJsn = API.Value.ToObject<JObject>();
                        if (APIJsn is null)
                        {
                            continue;
                        }

                        string apiname = API.Key;

                        API_ENTRY APIItem = new API_ENTRY();
                        APIItem.ModuleName = libname;
                        APIItem.Symbol = apiname;

                        if (APIJsn.TryGetValue("Filter", out filterTok) && filterTok.Type == JTokenType.String)
                        {
                            APIItem.FilterType = filterTok.ToString();
                        }
                        else
                        {
                            APIItem.FilterType = moduleFilter;
                        }

                        if (APIJsn.TryGetValue("Parameters", out JToken? paramsTok) && paramsTok is not null && paramsTok.Type == JTokenType.Array)
                        {
                            JArray? callParams = paramsTok.ToObject<JArray>();
                            if (callParams is not null)
                            {
                                List<API_PARAM_ENTRY>? loggedParams = ExtractParameters(callParams, libname, apiname);
                                if (loggedParams != null && loggedParams.Count > 0)
                                {
                                    APIItem.LoggedParams = loggedParams;
                                    if (APIJsn.TryGetValue("Effects", out JToken? effectsTok) && effectsTok.Type == JTokenType.Array)
                                    {
                                        JArray? effectsArr = effectsTok.ToObject<JArray>();
                                        if (effectsArr is not null)
                                        {
                                            APIItem.Effects = ExtractEffects(effectsArr, libname, apiname, APIItem.LoggedParams);
                                        }
                                    }
                                }
                            }

                        }

                        if (APIJsn.TryGetValue("Label", out JToken? interactionTok) && interactionTok.Type == JTokenType.String)
                        {
                            APIItem.Label = interactionTok.ToObject<string>();
                        }

                        moduleSyms.Add(apiname, APIItem);
                    }
                    _configuredSymbols.Add(moduleReference, moduleSyms);
                }

                progress?.Report(moduleCount / moduleI);
            }
        }


        static List<API_PARAM_ENTRY>? ExtractParameters(JArray callParams, string libname, string apiname)
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

                JObject? callParam = callParamTok.ToObject<JObject>();
                if (callParam is null ||
                    !callParam.TryGetValue("Index", out JToken? paramIndexTok) ||
                    paramIndexTok.Type != JTokenType.Integer)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter with no valid index", Logging.LogFilterType.TextError);
                    return null;
                }
                if (!callParam.TryGetValue("Name", out JToken? paramNameTok) || paramNameTok.Type != JTokenType.String)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter with no valid name", Logging.LogFilterType.TextError);
                    return null;
                }

                API_PARAM_ENTRY param = new API_PARAM_ENTRY();
                param.Index = paramIndexTok.ToObject<int>();
                param.name = paramNameTok.ToObject<string>() ?? "null";

                if (callParam.TryGetValue("Type", out JToken? paramTypeTok) && paramTypeTok.Type == JTokenType.String)
                {
                    if (Enum.TryParse(typeof(APIParamType), paramTypeTok.ToObject<string>(), ignoreCase: true, out object? paramtype) && paramtype is not null)
                    {
                        param.paramType = (APIParamType)paramtype;

                        if (param.paramType != APIParamType.Info)
                        {
                            if (!callParam.TryGetValue("EntityType", out JToken? catTok) ||
                                catTok.Type != JTokenType.String ||
                                !Enum.TryParse(typeof(InteractionEntityType), catTok.ToString(), out object? categoryEnum) ||
                                categoryEnum is null)
                            {
                                Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter ({param.name}) with no valid Category", Logging.LogFilterType.TextError);
                                return null;
                            }

                            param.EntityType = (InteractionEntityType)categoryEnum;


                            if (!callParam.TryGetValue("RawType", out JToken? rawTypeTok) ||
                                rawTypeTok.Type != JTokenType.String ||
                                !Enum.TryParse(typeof(InteractionRawType), rawTypeTok.ToString(), out object? rawtypeEnum) ||
                                rawtypeEnum is null)
                            {
                                Logging.RecordLogEvent($"API data entry {libname}:{apiname} has a parameter ({param.name}) with no valid RawType", Logging.LogFilterType.TextError);
                                return null;
                            }
                            param.RawType = (InteractionRawType)rawtypeEnum;
                            if (param.RawType == InteractionRawType.Handle)
                            {
                                param.NoCase = true;
                            }


                        }
                    }
                    else
                    {
                        param.paramType = APIParamType.Info;
                    }

                    if (callParam.TryGetValue("Conditional", out JToken? condTok) && condTok.Type == JTokenType.Boolean)
                    {
                        param.IsConditional = condTok.ToObject<bool>();
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
                JObject? effectJsn = effectTok.ToObject<JObject>();
                if (effectJsn is null ||
                    !effectJsn.TryGetValue("Type", out JToken? typetok) ||
                    typetok.Type != JTokenType.String)
                {
                    Logging.RecordLogEvent($"API data entry {libname}:{apiname} has an untyped interaction effect", Logging.LogFilterType.TextError);
                    break;
                }
                bool valid = false;
                switch (typetok.ToString())
                {
                    case "LinkReference":
                        if (effectJsn.TryGetValue("EntityIndex", out JToken? entidx) &&
                            effectJsn.TryGetValue("ReferenceIndex", out JToken? refidx) &&
                            entidx.Type == JTokenType.Integer &&
                            refidx.Type == JTokenType.Integer)
                        {
                            int entityParamCallIndex = entidx.ToObject<int>();
                            int entityParamListIndex = callparams.FindIndex(x => x.Index == entityParamCallIndex);

                            int refParamCallIndex = refidx.ToObject<int>();
                            int refParamListIndex = callparams.FindIndex(x => x.Index == refParamCallIndex);

                            if (refParamListIndex != -1 && entityParamListIndex != -1)
                            {
                                LinkReferenceEffect effect = new LinkReferenceEffect(entityIdx: entityParamListIndex, refIdx: refParamListIndex);
                                result.Add(effect);
                                valid = true;
                            }
                        }
                        break;

                    case "UseReference":
                        if (effectJsn.TryGetValue("ReferenceIndex", out refidx) && refidx.Type == JTokenType.Integer)
                        {
                            int refParamCallIndex = refidx.ToObject<int>();
                            int refParamListIndex = callparams.FindIndex(x => x.Index == refParamCallIndex);

                            if (refParamListIndex != -1)
                            {
                                UseReferenceEffect effect = new UseReferenceEffect(refIdx: refParamListIndex);
                                result.Add(effect);
                                valid = true;
                            }
                        }
                        break;

                    case "DestroyReference":
                        if (effectJsn.TryGetValue("ReferenceIndex", out refidx) && refidx.Type == JTokenType.Integer)
                        {
                            int refParamCallIndex = refidx.ToObject<int>();
                            int refParamListIndex = callparams.FindIndex(x => x.Index == refParamCallIndex);
                            if (refParamListIndex != -1)
                            {
                                DestroyReferenceEffect effect = new DestroyReferenceEffect(refIdx: refParamListIndex);
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


        /// <summary>
        /// How we deal with API call parameters
        /// </summary>
        public enum APIParamType
        {
            /// <summary>
            /// The parameter is informational only
            /// </summary>
            Info,
            /// <summary>
            /// The parameter describes an interesting system object (file path, network address, etc)
            /// </summary>
            Entity,
            /// <summary>
            /// The parameter is a reference to an entity (HANDLE to a file, socket to a network address, etc)
            /// </summary>
            Reference
        }


        /// <summary>
        /// The category of the entity
        /// </summary>
        public enum InteractionEntityType
        {
            /// <summary>
            /// Filesystem path
            /// </summary>
            File,
            /// <summary>
            /// Network address
            /// </summary>
            Host,
            /// <summary>
            /// Windows registry path
            /// </summary>
            Registry
        }


        /// <summary>
        /// A specific type for a parameter
        /// </summary>
        public enum InteractionRawType
        {
            /// <summary>
            /// HANDLE reference
            /// </summary>
            Handle,
            /// <summary>
            /// Filesystem path
            /// </summary>
            Path,
            /// <summary>
            /// DNS domain
            /// </summary>
            Domain,
            /// <summary>
            /// Registry HKEY
            /// </summary>
            HKEY
        }


        //enum APIInteractionType { None, Open, Close, Read, Write, Delete, Query, Lock, Unlock }

        /// <summary>
        /// Describes certain interesting parameters of an API call which we can link together to describe program behaviour
        /// </summary>
        public struct API_PARAM_ENTRY
        {
            /// <summary>
            /// The position of the parameter in the function call. 0 => first param. -1 => return value
            /// </summary>
            public int Index;
            /// <summary>
            /// The name of the parameter
            /// </summary>
            public string name;
            /// <summary>
            /// How we use the parameter
            /// </summary>
            public APIParamType paramType;
            /// <summary>
            /// The category of activity the parameter belongs to
            /// </summary>
            public InteractionEntityType EntityType;
            /// <summary>
            /// The actual raw type of parameter (HANDLE, domain, etc)
            /// </summary>
            public InteractionRawType RawType;
            /// <summary>
            /// May not receive this parameter (eg: failed registry key open -> no registry key handle)
            /// </summary>
            public bool IsConditional;
            /// <summary>
            /// Comparisons are case insensitive, particularly numbers such as handles which get represented as hex strings
            /// </summary>
            public bool NoCase;
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
            public string? Label;

            /// <summary>
            /// How this api call affects our tracking of interaction targets
            /// </summary>
            public List<InteractionEffect>? Effects;

            /// <summary>
            /// the filename of the library
            /// </summary>
            public string ModuleName;
            /// <summary>
            /// the case-sensitive API name
            /// </summary>
            public string Symbol;
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
            {
                return moduleEnum;
            }

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
            if (_configuredSymbols.ContainsKey(moduleReference) && _configuredSymbols[moduleReference].TryGetValue(symbolname, out API_ENTRY value))
            {
                return value;
            }

            return null;
        }
    }
}