using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace rgat
{
    /// <summary>
    /// Class for managing logs and messages
    /// </summary>
    public class Logging
    {
        /// <summary>
        /// A base category of this log
        /// </summary>
        public enum eLogFilterBaseType
        {
            /// <summary>
            /// An event
            /// </summary>
            TimeLine,
            /// <summary>
            /// A message
            /// </summary>
            Text
        }

        /// <summary>
        /// Base event log class
        /// </summary>
        public class LOG_EVENT
        {
            /// <summary>
            /// Create a log entry
            /// </summary>
            /// <param name="type">The base type of log</param>
            public LOG_EVENT(eLogFilterBaseType type)
            {
                _eventTime = DateTimeOffset.Now;
                _type = type;
            }
            /// <summary>
            /// When the event was recorded
            /// </summary>
            public long EventTimeMS
            {
                get
                {
                    if (_eventTimeMS is null)
                        _eventTimeMS = _eventTime.ToUnixTimeMilliseconds();
                    return _eventTimeMS.Value;
                }
            }


            long? _eventTimeMS;

            private DateTimeOffset _eventTime;

            /// <summary>
            /// The base type of log
            /// </summary>
            public eLogFilterBaseType LogType => _type;

            private readonly eLogFilterBaseType _type;
            /// <summary>
            /// How this log is handled
            /// </summary>
            public LogFilterType Filter;
            /// <summary>
            /// The graph that generated the log
            /// </summary>
            public ProtoGraph? Graph;
            /// <summary>
            /// The trace that generated the log
            /// </summary>
            public TraceRecord? Trace;
        }


        /// <summary>
        /// Record of an API call
        /// </summary>
        public class APICALL
        {
            /// <summary>
            /// Create an APi call
            /// </summary>
            /// <param name="graph">The graph of the thread that called it</param>
            public APICALL(ProtoGraph graph) { Graph = graph; }

            /// <summary>
            /// The node associated with this call
            /// </summary>
            public NodeData? Node;
            /// <summary>
            /// The index of the call in the call list
            /// </summary>
            public int Index;
            /// <summary>
            /// How many times this was repeated
            /// </summary>
            public ulong Repeats;
            /// <summary>
            /// The unique ID of the call
            /// </summary>
            public ulong UniqID;
            /// <summary>
            /// The graph associated with the call
            /// </summary>
            public ProtoGraph Graph;

            /// <summary>
            /// The actual API call ingformation
            /// </summary>
            public APIDetailsWin.API_ENTRY? APIDetails;

            /// <summary>
            /// The API category
            /// </summary>
            /// <returns>The name of the category</returns>
            public string APIType()
            {
                if (APIDetails == null)
                {
                    return "Other";
                }

                return APIDetails.Value.FilterType;
            }


            /// <summary>
            /// Deserialise an API call from JSON
            /// </summary>
            /// <param name="apiArr">The serialised call data</param>
            /// <param name="trace">The trace the call belongs to</param>
            /// <param name="apiObj">The resulting API object</param>
            /// <returns></returns>
            public static bool TryDeserialise(JArray apiArr, TraceRecord trace, out APICALL? apiObj)
            {
                apiObj = null;

                if (apiArr[0].Type is not JTokenType.Date)
                {
                    return false;
                }
                DateTime graphConstructed = apiArr[0].ToObject<DateTime>();

                ProtoGraph? graph = trace.GetProtoGraphByTime(graphConstructed);
                if (graph is null)
                {
                    return false;
                }

                apiObj = new APICALL(graph)
                {
                    Node = graph.NodeList[apiArr[1].ToObject<int>()],
                    Index = apiArr[2].ToObject<int>(),
                    Repeats = apiArr[3].ToObject<ulong>(),
                    UniqID = apiArr[4].ToObject<uint>()
                };

                if (apiArr[5] is not null)
                {
                    if (!DeserialiseEffects(apiArr[5], apiObj))
                    {
                        return false;
                    }
                }

                return true;
            }


            /// <summary>
            /// Implementing effects as derived classes means safe deserialisation is quite clunky
            /// </summary>
            /// <param name="deTok">JToken of the APICALL details</param>
            /// <param name="apiObj">APICALL being deserialised</param>
            /// <returns>success</returns>
            private static bool DeserialiseEffects(JToken deTok, APICALL apiObj)
            {
                try
                {
                    JObject? deJObj = deTok.ToObject<JObject>();
                    if (deJObj is null)
                    {
                        return false;
                    }

                    apiObj.APIDetails = deTok.ToObject<APIDetailsWin.API_ENTRY>();
                    if (apiObj.APIDetails is not null &&
                        deJObj.TryGetValue("Effects", out JToken? effTok) &&
                        apiObj.APIDetails.Value.Effects is not null &&
                        effTok.Type is JTokenType.Array)
                    {
                        JArray? effArray = effTok.ToObject<JArray>();
                        for (int effecti = 0; effecti < effArray?.Count; effecti++)
                        {
                            JToken effItem = effArray[effecti];
                            JObject? effectObj = effItem.ToObject<JObject>();
                            if (effectObj is null)
                            {
                                return false;
                            }

                            if (effectObj.TryGetValue("TypeName", out JToken? nameTok) && nameTok is not null)
                            {
                                switch (nameTok.ToString())
                                {
                                    case "Link":
                                        {
                                            JToken? entityIdx = effectObj["EntityIndex"];
                                            JToken? refIdx = effectObj["ReferenceIndex"];
                                            if (entityIdx is null || refIdx is null)
                                            {
                                                return false;
                                            }

                                            int entityIndex = entityIdx.ToObject<int>();
                                            int referenceIndex = refIdx.ToObject<int>();
                                            APIDetailsWin.LinkReferenceEffect linkEff = new APIDetailsWin.LinkReferenceEffect(entityIndex, referenceIndex);

                                            apiObj.APIDetails.Value.Effects[effecti] = linkEff;
                                            break;
                                        }
                                    case "Use":
                                        {
                                            JToken? refIdx = effectObj["ReferenceIndex"];
                                            if (refIdx is null)
                                            {
                                                return false;
                                            }

                                            apiObj.APIDetails.Value.Effects[effecti] = new APIDetailsWin.UseReferenceEffect(refIdx.ToObject<int>());
                                            break;
                                        }
                                    case "Destroy":
                                        {
                                            JToken? refIdx = effectObj["ReferenceIndex"];
                                            if (refIdx is null)
                                            {
                                                return false;
                                            }

                                            apiObj.APIDetails.Value.Effects[effecti] = new APIDetailsWin.DestroyReferenceEffect(refIdx.ToObject<int>());
                                            break;
                                        }
                                }

                            }
                        }
                    }
                    return true;
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Failed to load API call details: {e.Message}");
                    return false;
                }
            }

            /// <summary>
            /// Serialise an API event to JSON
            /// </summary>
            /// <returns>JObject of the event</returns>
            public void Serialise(Newtonsoft.Json.JsonWriter writer, Newtonsoft.Json.JsonSerializer serializer)
            {
                writer.WriteStartArray();

                writer.WriteValue(Graph!.ConstructedTime);
                writer.WriteValue(Node!.Index);
                writer.WriteValue(Index);
                writer.WriteValue(Repeats);
                writer.WriteValue(UniqID);

                if (APIDetails.HasValue)
                {
                    serializer.Serialize(writer, APIDetails);
                }
                else
                {
                    writer.WriteNull();
                }
                writer.WriteEndArray();
            }

        }

        /// <summary>
        /// Timeline event types
        /// </summary>
        public enum eTimelineEvent
        {
            /// <summary>
            /// A process started
            /// </summary>
            ProcessStart,
            /// <summary>
            /// A process stopped
            /// </summary>
            ProcessEnd,
            /// <summary>
            /// A thread started
            /// </summary>
            ThreadStart,
            /// <summary>
            /// A thread stopped
            /// </summary>
            ThreadEnd,
            /// <summary>
            /// An API call was recorded
            /// </summary>
            APICall
        }


        /// <summary>
        /// A timeline event
        /// </summary>
        public class TIMELINE_EVENT : LOG_EVENT
        {
            /// <summary>
            /// Create a timeline event
            /// </summary>
            /// <param name="timelineEventType">The base category</param>
            /// <param name="item">The event data</param>
            public TIMELINE_EVENT(eTimelineEvent timelineEventType, object item) : base(eLogFilterBaseType.TimeLine)
            {
                _eventType = timelineEventType;
                _item = item;
                switch (timelineEventType)
                {
                    case eTimelineEvent.ProcessStart:
                    case eTimelineEvent.ProcessEnd:
                        {
                            TraceRecord process = (TraceRecord)item;
                            SetIDs(ID: process.PID);
                            break;
                        }
                    case eTimelineEvent.ThreadStart:
                    case eTimelineEvent.ThreadEnd:
                        {
                            ProtoGraph thread = (ProtoGraph)item;
                            SetIDs(ID: thread.ThreadID);
                            break;
                        }
                    case eTimelineEvent.APICall:
                        {
                            TraceRecord process = ((APICALL)item).Graph!.TraceData;
                            SetIDs(process.PID);
                            break;
                        }
                    default:
                        Debug.Assert(false, "Bad timeline event");
                        break;
                }
                Inited = true;
            }


            /// <summary>
            /// Deserialise a timeline event from JSON
            /// </summary>
            /// <param name="jsnReader">A JsonReader for the trace file</param>
            /// <param name="serializer">A JsonSerializer</param>
            /// <param name="trace">The trace assocated with the timeline event</param>
            public TIMELINE_EVENT(JsonReader jsnReader, JsonSerializer serializer, TraceRecord trace) : base(eLogFilterBaseType.TimeLine)
            {
                jsnReader.Read();
                JArray? itemMeta = serializer.Deserialize<JArray>(jsnReader);
                if (itemMeta is null || itemMeta.Count != 3) return;

                _eventType = itemMeta[0].ToObject<eTimelineEvent>();
                JToken idTok = itemMeta[1];
                JToken pIdTok = itemMeta[2];


                //_item = item;
                switch (_eventType)
                {
                    case eTimelineEvent.ProcessStart:
                    case eTimelineEvent.ProcessEnd:
                        SetIDs(ID: idTok.ToObject<ulong>(), parentID: pIdTok.ToObject<ulong>());
                        _item = trace.GetTraceByID(ID)!;
                        Inited = true;
                        break;

                    case eTimelineEvent.ThreadStart:
                    case eTimelineEvent.ThreadEnd:
                        Debug.Assert(trace.ParentTrace == null || idTok.ToObject<ulong>() == trace.ParentTrace.PID);
                        SetIDs(ID: idTok.ToObject<ulong>());
                        _item = trace.GetProtoGraphByTID(ID)!;
                        Inited = true;
                        break;

                    case eTimelineEvent.APICall:

                        jsnReader.Read();
                        JArray? apiArr = serializer.Deserialize<JArray>(jsnReader);
                        if (apiArr is null)
                        {
                            Logging.RecordError("No APICALL data in timeline api event");
                            return;
                        }
                        if (!APICALL.TryDeserialise(apiArr, trace, out APICALL? apiObj) || apiObj is null)
                        {
                            Logging.RecordError("Bad APICALL data in timeline api event");
                            return;
                        }

                        SetIDs(ID: idTok.ToObject<ulong>(), parentID: pIdTok.ToObject<ulong>());
                        _item = apiObj;
                        Inited = true;
                        break;

                    default:
                        Debug.Assert(false, "Bad timeline event");
                        break;
                }

            }

            /// <summary>
            /// Serialise the timeline event to JSON
            /// </summary>
            public void Serialise(Newtonsoft.Json.JsonWriter writer, Newtonsoft.Json.JsonSerializer serializer)
            {
                Debug.Assert(_item is not null);
                JArray meta = new JArray
                {
                   TimelineEventType,
                   ID,
                   Parent
                };
                meta.WriteTo(writer);

                if (TimelineEventType == eTimelineEvent.APICall)
                {
                    APICALL apic = (Logging.APICALL)_item;
                    apic.Serialise(writer, serializer);
                }
            }






            private List<Tuple<string, WritableRgbaFloat>>? _cachedLabel = null;
            private ulong _cachedLabelTheme = 0;
            /// <summary>
            /// Get the label of the timeline event
            /// </summary>
            /// <returns>The list of strings and colours which need to be joined to make a label</returns>
            public List<Tuple<string, WritableRgbaFloat>> Label()
            {
                Debug.Assert(_item is not null);
                if (_cachedLabel != null && _cachedLabelTheme == Themes.ThemeVariant)
                {
                    return _cachedLabel;
                }

                _cachedLabel = new List<Tuple<string, WritableRgbaFloat>>();
                _cachedLabelTheme = Themes.ThemeVariant;

                WritableRgbaFloat textColour = new WritableRgbaFloat(Themes.GetThemeColourImGui(ImGuiNET.ImGuiCol.Text));
                switch (_eventType)
                {
                    case eTimelineEvent.ProcessStart:
                        {
                            TraceRecord trace = (TraceRecord)_item;
                            _cachedLabel.Add(new Tuple<string, WritableRgbaFloat>($"Process ({trace.PID}) Started", textColour));
                            break;
                        }
                    case eTimelineEvent.ProcessEnd:
                        {
                            TraceRecord trace = (TraceRecord)_item;
                            _cachedLabel.Add(new Tuple<string, WritableRgbaFloat>($"Process ({trace.PID}) Ended", textColour));
                            break;
                        }
                    case eTimelineEvent.ThreadStart:
                        {
                            ProtoGraph graph = (ProtoGraph)_item;
                            _cachedLabel.Add(new Tuple<string, WritableRgbaFloat>($"Thread ({graph.ThreadID}) Started", textColour));
                            break;
                        }
                    case eTimelineEvent.ThreadEnd:
                        {
                            ProtoGraph graph = (ProtoGraph)_item;
                            _cachedLabel.Add(new Tuple<string, WritableRgbaFloat>($"Thread ({graph.ThreadID}) Ended", textColour));
                            break;
                        }
                    case eTimelineEvent.APICall:
                        {
                            Logging.APICALL call = (Logging.APICALL)_item;
                            NodeData n = call.Node!;
                            var labelitems = n.CreateColourisedSymbolCall(call.Graph, call.Index, textColour, Themes.GetThemeColourWRF(Themes.eThemeColour.eTextEmphasis1));
                            _cachedLabel.AddRange(labelitems);
                            break;
                        }
                    default:
                        _cachedLabel.Add(new Tuple<string, WritableRgbaFloat>($"Bad timeline event: ", textColour));
                        Debug.Assert(false, $"Bad timeline event: {_eventType}");
                        return _cachedLabel;
                }
                return _cachedLabel;

            }



            /// <summary>
            /// process/thread ID of event source. parent ID optional, depending on context
            /// </summary>
            /// <param name="ID">process/thread ID of event source</param>
            /// <param name="parentID">parent ID. optional.</param>
            public void SetIDs(ulong ID, ulong parentID = ulong.MaxValue) { _ID = ID; _parentID = parentID; }
            /// <summary>
            /// The type of timeline event
            /// </summary>
            public eTimelineEvent TimelineEventType => _eventType;
            /// <summary>
            /// The event-type dependant ID of the event
            /// </summary>
            public ulong ID => _ID;
            /// <summary>
            /// The event-type dependant parent of the event
            /// </summary>
            public ulong Parent => _parentID;
            /// <summary>
            /// The underlying event data
            /// </summary>
            public object Item => _item!;

            /// <summary>
            /// an error was encountered processing this event, usually on the timeline chart
            /// this does not indicate an error with the actual API
            /// </summary>
            public string? MetaError = null;

            /// <summary>
            /// The event has been inted
            /// </summary>
            public bool Inited { get; private set; }

            private readonly eTimelineEvent _eventType;
            private ulong _ID;
            private ulong _parentID;
            private object? _item;
        }


        /// <summary>
        /// Categories of log event
        /// </summary>
        public enum LogFilterType
        {
            /// <summary>
            /// Uninteresting events which may be useful for debugging
            /// </summary>
            Debug,
            /// <summary>
            /// Events a user might want to know about if they check the logs
            /// </summary>
            Info,
            /// <summary>
            /// Something bad happened. Alert the user
            /// </summary>
            Error,
            /// <summary>
            /// Something interesting happened. Alert the user
            /// </summary>
            Alert,
            /// <summary>
            /// Something very common and routine happened. Log it to a file if bulk debug logging is enabled.
            /// </summary>
            BulkDebugLogFile,
            /// <summary>
            /// The number of available log types
            /// </summary>
            COUNT
        };

        private static readonly int[] MessageCounts = new int[(int)LogFilterType.COUNT];
        private static readonly List<LOG_EVENT> _logMessages = new List<LOG_EVENT>();
        private static readonly List<LOG_EVENT> _alertNotifications = new List<LOG_EVENT>();
        private static readonly object _messagesLock = new object();


        /// <summary>
        /// Get the number of log messages recorded for each filter
        /// </summary>
        /// <returns> A dictionary of filter/count values</returns>
        public static Dictionary<LogFilterType, int> GetTextFilterCounts()
        {
            Dictionary<LogFilterType, int> result = new Dictionary<LogFilterType, int>();
            lock (_messagesLock)
            {
                result[LogFilterType.Error] = MessageCounts[(int)LogFilterType.Error];
                result[LogFilterType.Alert] = MessageCounts[(int)LogFilterType.Alert];
                result[LogFilterType.Debug] = MessageCounts[(int)LogFilterType.Debug];
                result[LogFilterType.Info] = MessageCounts[(int)LogFilterType.Info];
                return result;
            }
        }


        /// <summary>
        /// Get the most recent alerts/errors to inform the user about
        /// </summary>
        /// <param name="max">Maximum number to retrieve</param>
        /// <param name="alerts">An output array of alert events</param>
        /// <returns>The number of events returned</returns>
        public static int GetAlerts(int max, out LOG_EVENT[] alerts)
        {
            lock (_messagesLock)
            {
                alerts = _alertNotifications.TakeLast(Math.Min(max, _alertNotifications.Count)).ToArray();
                return _alertNotifications.Count;
            }
        }

        /// <summary>
        /// Acknowledge the latest alerts, stop displaying them on the UI
        /// </summary>
        public static void ClearAlertsBox()
        {
            lock (_messagesLock)
            {
                UnseenAlerts = 0;
                _alertNotifications.Clear();
            }
        }

        /// <summary>
        /// A text log event
        /// </summary>
        public class TEXT_LOG_EVENT : LOG_EVENT
        {
            /// <summary>
            /// Create a text log event
            /// </summary>
            /// <param name="filter">How this log is handled</param>
            /// <param name="text">The log entry</param>
            public TEXT_LOG_EVENT(LogFilterType filter, string text) : base(eLogFilterBaseType.Text)
            {
                Text = text;
                Filter = filter;
            }

            /// <summary>
            /// Set the graph (ie: thread) that generated this log
            /// </summary>
            /// <param name="graph">A ProtoGraph</param>
            public void SetAssociatedGraph(ProtoGraph graph)
            {
                Graph = graph;
                Trace = graph.TraceData;
            }

            /// <summary>
            /// Set the trace (ie: process) that generated this log
            /// </summary>
            /// <param name="trace"></param>
            public void SetAssociatedTrace(TraceRecord trace) => Trace = trace;

            /// <summary>
            /// The text of the log
            /// </summary>
            public string Text;
        }



        /// <summary>      
        /// Display a message in the logfile/message window.
        /// Will also be shown on the UI alert pane with the Alert/Error options
        /// </summary>
        /// <param name="text">Message to display</param>
        /// <param name="filter">The LogFilterType category of the log entry
        /// </param>
        /// <param name="graph">Graph this applies to. If aimed at a trace, just use any graph of the trace</param>
        /// <param name="trace">Process this applies to</param>     

        public static void RecordLogEvent(string text, LogFilterType filter = LogFilterType.Info, ProtoGraph? graph = null, TraceRecord? trace = null)
        {
            TEXT_LOG_EVENT log = new TEXT_LOG_EVENT(filter: filter, text: text);
            if (graph != null) { log.SetAssociatedGraph(graph); }
            if (trace != null) { log.SetAssociatedTrace(trace); }

            lock (_messagesLock)
            {
                //write all logs to the logfile in bulk logging mode
                if (GlobalConfig.Settings.Logs.BulkLogging)
                {
                    try
                    {
                        WriteToDebugFile(log);
                    }
                    catch (Exception e)
                    {
                        GlobalConfig.Settings.Logs.BulkLogging = false;
                        Logging.RecordLogEvent($"Error: Not able to write to bulk log file {e.Message}. Another rgat may be using it. Disabling bulk logging.");
                    }
                }

                //write non-bulklog files to the UI log pane
                if (filter != LogFilterType.BulkDebugLogFile)
                {
                    _logMessages.Add(log);
                    if (log.Filter == LogFilterType.Alert || log.Filter == LogFilterType.Error)
                    {
                        UnseenAlerts += 1;
                        _alertNotifications.Add(log);
                        _lastAlert = DateTime.Now;
                    }
                    MessageCounts[(int)filter] += 1;

                }
            }

            //todo remove after debug done
            if (filter == LogFilterType.Error)
            {
                WriteConsole(text, ConsoleColor.Yellow);
            }
        }


        /// <summary>
        /// Output to console, disregarding any exceptions
        /// </summary>
        /// <param name="text">Text to write</param>
        /// <param name="colour">Colour</param>
        public static void WriteConsole(string? text = "", ConsoleColor colour = ConsoleColor.White)
        {
            if (text is null) return;
            try
            {
                lock (_messagesLock) //Console is threadsafe but the colour is not
                {
                    Console.ForegroundColor = colour;
                    Console.WriteLine(text);
                    Console.ForegroundColor = ConsoleColor.White;
                }
            }
            catch { }
        }


        /// <summary>
        /// This is just an alias for  RecordLogEvent( filter: TextError);
        /// </summary>
        /// <param name="text">Error text</param>
        /// <param name="graph">Graph the error applies to (optional)</param>
        /// <param name="trace">Trace the error applies to (optional)</param>
        public static void RecordError(string text, ProtoGraph? graph = null, TraceRecord? trace = null)
        {
            if (rgatState.NetworkBridge.Connected)
            {
                rgatState.NetworkBridge.SendLog(text, LogFilterType.Error);
            }
            RecordLogEvent(text: text, graph: graph, trace: trace, filter: LogFilterType.Error);
        }

        private static System.IO.StreamWriter? _logFile = null;

        private static void WriteToDebugFile(TEXT_LOG_EVENT log)
        {
            if (System.Threading.Thread.CurrentThread.Name != null && System.Threading.Thread.CurrentThread.Name.Contains("TracePro"))
            {
                return;
            }

            if (_logFile == null)
            {
                try
                {
                    _logFile = System.IO.File.CreateText(System.IO.Path.Join(GlobalConfig.GetSettingPath(CONSTANTS.PathKey.TraceSaveDirectory), "DebugLog.txt"));
                    _logFile.WriteLine($"Opened new rgat debug logfile at {DateTime.Now.ToLocalTime().ToLongDateString()}");
                    _logFile.WriteLine($"Uncheck bulk logging in settings->misc to disable this");
                }
                catch (Exception e)
                {
                    Logging.RecordError($"Bulk log file cannot be created ({e}). Ensure Trace Save Directory is writable.");
                    GlobalConfig.Settings.Logs.BulkLogging = false;
                }
            }
            if (_logFile != null)
            {
                _logFile.WriteLine($"{System.Threading.Thread.CurrentThread.Name}:{log.Trace?.PID}:{log.Graph?.ThreadID}:{log.Text}");
                _logFile.Flush();
            }
        }

        /*
        public static LOG_EVENT[] GetErrorMessages()
        {
            lock (_messagesLock)
            {
                UnseenAlerts = 0;
                return _logMessages.Where(x => x.LogType == eLogFilterBaseType.Text && x.Filter == LogFilterType.TextError).ToArray();

            }
        }*/

        /// <summary>
        /// Fetch messages for a filter and clear pending alerts
        /// </summary>
        /// <param name="trace">Specific trace to getch messages for</param>
        /// <param name="filters">Filters to match</param>
        /// <returns>Array of log events</returns>
        public static LOG_EVENT[] GetLogMessages(TraceRecord? trace, bool[] filters)
        {
            lock (_messagesLock)
            {
                UnseenAlerts = 0;
                if (trace == null)
                {
                    return _logMessages.Where(x => filters[(int)x.Filter] == true).ToArray();
                }
                else
                {
                    return _logMessages.Where(x => x.Trace == trace).Where(x => filters[(int)x.Filter] == true).ToArray();
                }
            }
        }

        /// <summary>
        /// Alerts awaiting viewing
        /// </summary>
        public static int UnseenAlerts { get; set; } = 0;

        private static DateTime _lastAlert = DateTime.MinValue;
        /// <summary>
        /// How fresh the latest alert is
        /// </summary>
        public static TimeSpan TimeSinceLastAlert => DateTime.Now - _lastAlert;


        /*
        public int LogMessageCount(TraceRecord? trace = null, ulong? PID = null, ulong? TID = null, eMessageType? typeFilter = null)
        {
            if (trace == null && typeFilter == null) return LogMessages.Count;

            List<LOG_ENTRY> candidates;
            lock (_messagesLock)
            {
                candidates = LogMessages.ToList();
            }
            if (graph != null)
            {
                candidates = candidates.Where(l => l.graph == graph).ToList();
            }
            if (typeFilter != null)
            {
                candidates = candidates.Where(l => l.t == graph).ToList();
            }


        }
        */
    }

}
