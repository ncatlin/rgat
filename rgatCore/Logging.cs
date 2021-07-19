using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace rgatCore
{
    public class Logging
    {

        public enum eLogType { TimeLine, API, Text }
        public class LOG_EVENT
        {
            public LOG_EVENT(eLogType type)
            {
                _eventTimeMS = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                _type = type;
            }
            public long EventTimeMS => _eventTimeMS;
            public eLogType LogType => _type;
            long _eventTimeMS;
            eLogType _type;
            public LogFilterType Filter;
            public ProtoGraph _graph;
            public TraceRecord Trace;
        }

        public struct APICALL
        {
            public NodeData node;
            public ulong index;
            public ulong repeats;
            public ulong uniqID;
            public ProtoGraph graph;
            public LogFilterType ApiType;
        }


        public enum eTimelineEvent { ProcessStart, ProcessEnd, ThreadStart, ThreadEnd, APICall }

        public class TIMELINE_EVENT : LOG_EVENT
        {
            public TIMELINE_EVENT(eTimelineEvent timelineEventType, object item) : base(eLogType.TimeLine)
            {
                _eventType = timelineEventType;
                _item = item;
                switch (timelineEventType)
                {
                    case eTimelineEvent.ProcessStart:
                    case eTimelineEvent.ProcessEnd:
                        SetIDs(ID: ((TraceRecord)item).PID);
                        Filter = LogFilterType.TimelineProcess;
                        break;
                    case eTimelineEvent.ThreadStart:
                    case eTimelineEvent.ThreadEnd:
                        SetIDs(ID: ((ProtoGraph)item).ThreadID);
                        Filter = LogFilterType.TimelineThread;
                        break;
                    case eTimelineEvent.APICall:
                        Filter = ((APICALL)(item)).ApiType;
                        break;
                    default:
                        Debug.Assert(false, "Bad timeline event");
                        break;
                }
                Inited = true;
            }


            public TIMELINE_EVENT(JObject jobj, TraceRecord trace) : base(eLogType.TimeLine)
            {
                if (!jobj.TryGetValue("EvtType", out JToken evtType) || evtType.Type != JTokenType.Integer)
                {
                    Logging.RecordLogEvent("Bad timeline event type in saved timeline");
                    return;
                }

                _eventType = evtType.ToObject<eTimelineEvent>();

                if (_eventType == eTimelineEvent.APICall)
                {
                    JToken tok;
                    APICALL apic = new APICALL();
                    if (jobj.TryGetValue("Graph", out tok) && tok.Type == JTokenType.Date)
                    {
                        apic.graph = trace.GetProtoGraphByTime(tok.ToObject<DateTime>());
                        if (apic.graph == null) return;
                    }
                    if (jobj.TryGetValue("Node", out tok) && tok.Type == JTokenType.Integer)
                    {
                        int idx = tok.ToObject<int>();
                        if (idx >= apic.graph.NodeList.Count) return;
                        apic.node = apic.graph.NodeList[idx];
                    }
                    if (jobj.TryGetValue("Idx", out tok) && tok.Type == JTokenType.Integer)
                    {
                        apic.index = tok.ToObject<ulong>();
                    }
                    if (jobj.TryGetValue("Repeats", out tok) && tok.Type == JTokenType.Integer)
                    {
                        apic.repeats = tok.ToObject<ulong>();
                    }
                    if (jobj.TryGetValue("uniqID", out tok) && tok.Type == JTokenType.Integer)
                    {
                        apic.uniqID = tok.ToObject<ulong>();
                    }
                    if (jobj.TryGetValue("Filter", out tok) && tok.Type == JTokenType.Integer)
                    {
                        apic.ApiType = (LogFilterType)tok.ToObject<int>();
                        this.Filter = apic.ApiType;
                    }
                    _item = apic;

                    Inited = true;
                    return;
                }

                JToken idtok, pidtok;
                if (!jobj.TryGetValue("ID", out idtok) || idtok.Type != JTokenType.Integer ||
                    !jobj.TryGetValue("PID", out pidtok) || pidtok.Type != JTokenType.Integer)
                {
                    Logging.RecordLogEvent("Bad timeline id/parent id in saved timeline");
                    return;
                }

                //_item = item;
                switch (_eventType)
                {
                    case eTimelineEvent.ProcessStart:
                    case eTimelineEvent.ProcessEnd:
                        SetIDs(ID: idtok.ToObject<ulong>(), parentID: pidtok.ToObject<ulong>());
                        Filter = LogFilterType.TimelineProcess;
                        _item = trace.GetTraceByID(ID);
                        Inited = true;
                        break;
                    case eTimelineEvent.ThreadStart:
                    case eTimelineEvent.ThreadEnd:
                        SetIDs(ID: idtok.ToObject<ulong>());
                        Filter = LogFilterType.TimelineThread;
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
                    obj.Add("Filter", (int)apic.ApiType);
                }
                else
                {
                    obj.Add("ID", ID);
                    obj.Add("PID", Parent);
                }
                return obj;
            }


            public string Label()
            {
                switch (_eventType)
                {
                    case eTimelineEvent.ProcessStart:
                        {
                            TraceRecord trace = (TraceRecord)_item;
                            return $"Process ({trace.PID}) Started";
                        }
                    case eTimelineEvent.ProcessEnd:
                        {
                            TraceRecord trace = (TraceRecord)_item;
                            return $"Process ({trace.PID}) Ended";
                        }
                    case eTimelineEvent.ThreadStart:
                        {
                            ProtoGraph graph = (ProtoGraph)_item;
                            return $"Thread ({graph.ThreadID}) Started";
                        }
                    case eTimelineEvent.ThreadEnd:
                        {
                            ProtoGraph graph = (ProtoGraph)_item;
                            return $"Thread ({graph.ThreadID}) Ended";
                        }
                    case eTimelineEvent.APICall:
                        {
                            Logging.APICALL call = (Logging.APICALL)_item;
                            NodeData n = call.node;
                            if (n.Label == null)
                            {
                                n.GenerateSymbolLabel(call.graph, (int)call.index);
                            }
                            return $"API call: ({n.Label})";
                        }
                    default:
                        Debug.Assert(false, "Bad timeline event");
                        return "Bad event";
                }

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

            public bool Inited { get; private set; }

            eTimelineEvent _eventType;
            ulong _ID;
            ulong _parentID;
            object _item;
            bool _inited;
        }


        public enum LogFilterType
        {
            TextDebug, TextInfo, TextError, TextAlert, TimelineProcess, TimelineThread,
            APIFile, APIReg, APINetwork, APIProcess, APIAlgos, APIOther, BulkDebugLogFile, COUNT
        };
        static int[] MessageCounts = new int[(int)LogFilterType.COUNT];

        static List<LOG_EVENT> _logMessages = new List<LOG_EVENT>();
        static List<LOG_EVENT> _alertNotifications = new List<LOG_EVENT>();
        readonly static object _messagesLock = new object();


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



        public static int GetAlerts(int max, out LOG_EVENT[] alerts)
        {
            lock (_messagesLock)
            {
                alerts = _alertNotifications.Take(Math.Min(max, _alertNotifications.Count)).ToArray();
                return _alertNotifications.Count;
            }
        }

        public static void ClearAlertsBox()
        {
            lock (_messagesLock)
            {
                _alertNotifications.Clear();
            }
        }

        public class TEXT_LOG_EVENT : LOG_EVENT
        {
            public TEXT_LOG_EVENT(LogFilterType filter, string text) : base(eLogType.Text)
            {
                _filter = filter;
                _text = text;
                Filter = filter;
                /*

                switch (filter)
                {
                    case LogFilterType.TextDebug:
                        Filter = LogFilterType.TextDebug;
                        break;
                    case LogFilterType.TextInfo:
                        Filter = LogFilterType.TextInfo;
                        break;
                    case LogFilterType.TextAlert:
                        Filter = LogFilterType.TextAlert;
                        break;
                    case LogFilterType.TextError:
                        Filter = LogFilterType.TextError;
                        break;
                    default:
                        Debug.Assert(false, "Bad text log event");
                        break;
                }
                */
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
        /// Display a message in the logfile/message window
        /// Also will show on the UI alert pane with the Alert option
        /// </summary>
        /// <param name="message">Message to display</param>
        /// <param name="visibility">    
        /// Debug -     Diagnostic debug log visible messages generally uninteresting to users
        /// Log -       Information messages users might want to seek out
        /// Alert -     Information the user needs to see to enable proper functionality. Will be shown somewhere prominent.
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
                    WriteToDebugFile(log);
                }

                if (filter != LogFilterType.BulkDebugLogFile)
                {
                    _logMessages.Add(log);
                    if (log._filter == LogFilterType.TextAlert) _alertNotifications.Add(log);
                    MessageCounts[(int)filter] += 1;
                }
            }

            //todo remove after debug done
            if (filter == LogFilterType.TextError)
            {
                Console.WriteLine(text);
            }
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

        public static LOG_EVENT[] GetLogMessages(TraceRecord trace, bool[] filters)
        {
            lock (_messagesLock)
            {
                if (trace == null) return _logMessages.Where(x => filters[(int)x.Filter] == true).ToArray();
                else
                {
                    return _logMessages.Where(x => x.Trace == trace).Where(x => filters[(int)x.Filter] == true).ToArray();
                }
            }
        }


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
