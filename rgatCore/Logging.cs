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
        }


        public enum eTimelineEvent { ProcessStart, ProcessEnd, ThreadStart, ThreadEnd }
        public class TIMELINE_EVENT : LOG_EVENT
        {
            public TIMELINE_EVENT(eTimelineEvent timelineEventType) : base(eLogType.TimeLine)
            {
                _eventType = timelineEventType;
                switch (_eventType)
                {
                    case eTimelineEvent.ProcessStart:
                    case eTimelineEvent.ProcessEnd:
                        Filter = LogFilterType.TimelineProcess;
                        break;
                    case eTimelineEvent.ThreadStart:
                    case eTimelineEvent.ThreadEnd:
                        Filter = LogFilterType.TimelineThread;
                        break;
                    default:
                        Debug.Assert(false, "Bad timeline event");
                        break;
                }
            }

            //process/thread ID of event source. parent ID optional, depending on context
            public void SetIDs(ulong ID, ulong parentID = ulong.MaxValue) { _ID = ID; _parentID = parentID; }
            public eTimelineEvent TimelineEventType => _eventType;
            public ulong ID => _ID;
            public ulong Parent => _parentID;

            eTimelineEvent _eventType;
            ulong _ID;
            ulong _parentID;
        }


        public enum LogFilterType
        {
            TextDebug, TextInfo, TextError, TextAlert, TimelineProcess, TimelineThread,
            APIFile, APIReg, APINetwork, APIProcess, APIOther, COUNT
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
            }

            public void SetAssociatedGraph(ProtoGraph graph)
            {
                _graph = graph;
                _trace = graph.TraceData;
            }
            public void SetAssociatedTrace(TraceRecord trace) => _trace = trace;
            public LogFilterType _filter;
            public string _text;
            //public uint? colour;
            public ProtoGraph _graph;
            public TraceRecord _trace;
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
            ProtoGraph graph = null, TraceRecord trace = null, WritableRgbaFloat? colour = null)
        {
            TEXT_LOG_EVENT log = new TEXT_LOG_EVENT(filter: filter, text: text);
            if (graph != null) { log.SetAssociatedGraph(graph); }
            if (trace != null) { log.SetAssociatedTrace(trace); }
            lock (_messagesLock)
            {
                _logMessages.Add(log);
                if (log._filter == LogFilterType.TextAlert) _alertNotifications.Add(log);
                MessageCounts[(int)filter] += 1;
            }

            //todo remove after debug done
            if (filter == LogFilterType.TextError)
            {
                Console.WriteLine(text);
            }
        }

        public static LOG_EVENT[] GetLogMessages(bool[] filters)
        {
            lock (_messagesLock)
            {
                return _logMessages.Where(x => filters[(int)x.Filter] == true).ToArray();
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
