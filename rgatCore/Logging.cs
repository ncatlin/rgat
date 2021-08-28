using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace rgat
{
    public class Logging
    {

        public enum eLogFilterBaseType { TimeLine, Text }
        public class LOG_EVENT
        {
            public LOG_EVENT(eLogFilterBaseType type)
            {
                _eventTimeMS = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                _type = type;
            }
            public long EventTimeMS => _eventTimeMS;
            public eLogFilterBaseType LogType => _type;
            long _eventTimeMS;
            eLogFilterBaseType _type;
            public LogFilterType Filter;
            public ProtoGraph _graph;
            public TraceRecord Trace;
        }

        public class APICALL
        {
            public APICALL() { APIDetails = null; }
            public NodeData node;
            public int index;
            public ulong repeats;
            public ulong uniqID;
            public ProtoGraph graph;

            public WinAPIDetails.API_ENTRY? APIDetails;
            public string APIType()
            {
                if (APIDetails == null) return "Other";
                return APIDetails.Value.FilterType;
            }

        }


        public enum eTimelineEvent { ProcessStart, ProcessEnd, ThreadStart, ThreadEnd, APICall }

        public class TIMELINE_EVENT : LOG_EVENT
        {
            public TIMELINE_EVENT(eTimelineEvent timelineEventType, object item) : base(eLogFilterBaseType.TimeLine)
            {
                _eventType = timelineEventType;
                _item = item;
                switch (timelineEventType)
                {
                    case eTimelineEvent.ProcessStart:
                    case eTimelineEvent.ProcessEnd:
                        SetIDs(ID: ((TraceRecord)item).PID);
                        break;
                    case eTimelineEvent.ThreadStart:
                    case eTimelineEvent.ThreadEnd:
                        SetIDs(ID: ((ProtoGraph)item).ThreadID);
                        break;
                    case eTimelineEvent.APICall:
                        //todo
                        break;
                    default:
                        Debug.Assert(false, "Bad timeline event");
                        break;
                }
                Inited = true;
            }


            public TIMELINE_EVENT(JObject jobj, TraceRecord trace) : base(eLogFilterBaseType.TimeLine)
            {
                if (!jobj.TryGetValue("EvtType", out JToken evtType) || evtType.Type != JTokenType.Integer)
                {
                    Logging.RecordError("Bad timeline event type in saved timeline");
                    return;
                }

                _eventType = evtType.ToObject<eTimelineEvent>();

                JToken idtok, pidtok;
                if (!jobj.TryGetValue("ID", out idtok) || idtok.Type != JTokenType.Integer ||
                    !jobj.TryGetValue("PID", out pidtok) || pidtok.Type != JTokenType.Integer)
                {
                    Logging.RecordError("Bad timeline id/parent id in saved timeline");
                    return;
                }

                //_item = item;
                switch (_eventType)
                {
                    case eTimelineEvent.ProcessStart:
                    case eTimelineEvent.ProcessEnd:
                        SetIDs(ID: idtok.ToObject<ulong>(), parentID: pidtok.ToObject<ulong>());
                        _item = trace.GetTraceByID(ID);
                        Inited = true;
                        break;
                    case eTimelineEvent.ThreadStart:
                    case eTimelineEvent.ThreadEnd:
                        SetIDs(ID: idtok.ToObject<ulong>());
                        _item = trace.GetProtoGraphByID(ID);
                        Inited = true;
                        break;
                    default:
                        Debug.Assert(false, "Bad timeline event");
                        break;
                }

            }

            public JObject Serialise()
            {
                JObject obj = new JObject();
                obj.Add("EvtType", (int)TimelineEventType);

                if (_eventType == eTimelineEvent.APICall)
                {
                    APICALL apic = (Logging.APICALL)_item;
                    obj.Add("Node", apic.node.index);
                    obj.Add("Idx", apic.index);
                    obj.Add("Repeats", apic.repeats);
                    obj.Add("uniqID", apic.uniqID);
                    obj.Add("Graph", apic.graph.ConstructedTime);
                    //obj.Add("Filter", apic.APIType());
                }
                else
                {
                    obj.Add("ID", ID);
                    obj.Add("PID", Parent);
                }
                return obj;
            }


            List<Tuple<string, WritableRgbaFloat>> _cachedLabel = null;
            ulong _cachedLabelTheme = 0;
            public List<Tuple<string, WritableRgbaFloat>> Label()
            {
                if (_cachedLabel != null && _cachedLabelTheme == Themes.ThemeVariant) return _cachedLabel;
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
                            NodeData n = call.node;
                            var labelitems = n.CreateColourisedSymbolCall(call.graph, call.index, textColour, Themes.GetThemeColourWRF(Themes.eThemeColour.eTextEmphasis1));
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

            public void ReplaceItem(object newitem)
            {
                Debug.Assert(newitem.GetType() == _item.GetType());
                _item = newitem;
            }

            //process/thread ID of event source. parent ID optional, depending on context
            public void SetIDs(ulong ID, ulong parentID = ulong.MaxValue) { _ID = ID; _parentID = parentID; }
            public eTimelineEvent TimelineEventType => _eventType;
            public ulong ID => _ID;
            public ulong Parent => _parentID;
            public object Item => _item;

            //an error was encountered processing this event, usually on the timeline chart
            //this does not indicate an error with the actual API
            public string MetaError = null;
            public bool Inited { get; private set; }

            eTimelineEvent _eventType;
            ulong _ID;
            ulong _parentID;
            object _item;
            bool _inited;
        }


        public enum LogFilterType
        {
            //Uninteresting events which may be useful for debugging
            TextDebug, 
            //Events a user might want to know about if they check the logs
            TextInfo, 
            //Something bad happened. Alert the user
            TextError, 
            //Something interesting happened. Alert the user
            TextAlert, 
            //Something very common and routine happened. Log it to a file if bulk debug logging is enabled.
            BulkDebugLogFile, COUNT
        };
        static int[] MessageCounts = new int[(int)LogFilterType.COUNT];

        static List<LOG_EVENT> _logMessages = new List<LOG_EVENT>();
        static List<LOG_EVENT> _alertNotifications = new List<LOG_EVENT>();
        readonly static object _messagesLock = new object();


        /// <summary>
        /// Get the number of log messages recorded for each filter
        /// </summary>
        /// <returns> A dictionary of filter/count values</returns>
        public static Dictionary<LogFilterType, int> GetTextFilterCounts()
        {
            Dictionary<LogFilterType, int> result = new Dictionary<LogFilterType, int>();
            lock (_messagesLock)
            {
                result[LogFilterType.TextError] = MessageCounts[(int)LogFilterType.TextError];
                result[LogFilterType.TextAlert] = MessageCounts[(int)LogFilterType.TextAlert];
                result[LogFilterType.TextDebug] = MessageCounts[(int)LogFilterType.TextDebug];
                result[LogFilterType.TextInfo] = MessageCounts[(int)LogFilterType.TextInfo];
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
                alerts = _alertNotifications.Take(Math.Min(max, _alertNotifications.Count)).ToArray();
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

        public class TEXT_LOG_EVENT : LOG_EVENT
        {
            public TEXT_LOG_EVENT(LogFilterType filter, string text) : base(eLogFilterBaseType.Text)
            {
                _filter = filter;
                _text = text;
                Filter = filter;
            }

            public void SetAssociatedGraph(ProtoGraph graph)
            {
                _graph = graph;
                Trace = graph.TraceData;
            }


            public void SetAssociatedTrace(TraceRecord trace) => Trace = trace;
            public LogFilterType _filter;
            public string _text;
            //public uint? colour;
        }



        /// <summary>      
        /// Display a message in the logfile/message window.
        /// Will also be shown on the UI alert pane with the Alert/Error options
        /// </summary>
        /// <param name="message">Message to display</param>
        /// <param name="visibility">The LogFilterType category of the log entry
        /// </param>
        /// <param name="graph">Graph this applies to. If aimed at a trace, just use any graph of the trace</param>
        /// <param name="colour">Optional colour, otherwise default will be used</param>

        public static void RecordLogEvent(string text, LogFilterType filter = LogFilterType.TextInfo,
            ProtoGraph graph = null, TraceRecord trace = null, WritableRgbaFloat? colour = null, Logging.APICALL? apicall = null)
        {
            TEXT_LOG_EVENT log = new TEXT_LOG_EVENT(filter: filter, text: text);
            if (graph != null) { log.SetAssociatedGraph(graph); }
            if (trace != null) { log.SetAssociatedTrace(trace); }

            lock (_messagesLock)
            {
                if (GlobalConfig.BulkLogging)
                {
                    try
                    {
                        WriteToDebugFile(log);
                    }
                    catch (Exception e)
                    {
                        GlobalConfig.BulkLogging = false;
                        Logging.RecordLogEvent($"Error: Not able to write to bulk log file {e.Message}. Another rgat may be using it. Disabling bulk logging.");
                    }
                }

                if (filter != LogFilterType.BulkDebugLogFile)
                {
                    _logMessages.Add(log);
                    if (log._filter == LogFilterType.TextAlert || log.Filter == LogFilterType.TextError)
                    {
                        UnseenAlerts += 1;
                        _alertNotifications.Add(log);
                        _lastAlert = DateTime.Now;
                    }
                    MessageCounts[(int)filter] += 1;
                }
            }

            //todo remove after debug done
            if (filter == LogFilterType.TextError)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(text);
                Console.ForegroundColor = ConsoleColor.White;
            }
        }


        /// <summary>
        /// This is just an alias for  RecordLogEvent( filter: TextError);
        /// </summary>
        /// <param name="text">Error text</param>
        /// <param name="graph">Graph the error applies to (optional)</param>
        /// <param name="trace">Trace the error applies to (optional)</param>
        public static void RecordError(string text, ProtoGraph graph = null, TraceRecord trace = null)
        {
            RecordLogEvent(text: text, graph: graph, trace: trace, filter: LogFilterType.TextError);
        }


        static System.IO.StreamWriter _logFile = null;
        static void WriteToDebugFile(TEXT_LOG_EVENT log)
        {
            if (System.Threading.Thread.CurrentThread.Name != null && System.Threading.Thread.CurrentThread.Name.Contains("TracePro")) return;

            if (_logFile == null)
            {
                _logFile = System.IO.File.CreateText(System.IO.Path.Join(GlobalConfig.TraceSaveDirectory, "DebugLog.txt"));
                _logFile.WriteLine($"Opened new rgat debug logfile at {DateTime.Now.ToLocalTime().ToLongDateString()}");
                _logFile.WriteLine($"Uncheck bulk logging in settings->misc to disable this");
            }
            _logFile.WriteLine($"{System.Threading.Thread.CurrentThread.Name}:{log.Trace?.PID}:{log._graph?.ThreadID}:{log._text}");
            _logFile.Flush();

        }

        public static LOG_EVENT[] GetErrorMessages()
        {
            lock (_messagesLock)
            {
                UnseenAlerts = 0;
                return _logMessages.Where(x => x.LogType == eLogFilterBaseType.Text && x.Filter == LogFilterType.TextError).ToArray();

            }
        }

        public static LOG_EVENT[] GetLogMessages(TraceRecord trace, bool[] filters)
        {
            lock (_messagesLock)
            {
                UnseenAlerts = 0;
                if (trace == null) return _logMessages.Where(x => filters[(int)x.Filter] == true).ToArray();
                else
                {
                    return _logMessages.Where(x => x.Trace == trace).Where(x => filters[(int)x.Filter] == true).ToArray();
                }
            }
        }

        public static int UnseenAlerts { get; set; } = 0;

        static DateTime _lastAlert = DateTime.MinValue;
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
