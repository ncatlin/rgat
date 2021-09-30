using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using static rgat.CONSTANTS;
using static rgat.Logging;

namespace rgat
{
    internal partial class LogsWindow
    {
        public LogsWindow(rgatState _state)
        {
            _rgatState = _state;
            _LogFilters[(int)Logging.LogFilterType.TextDebug] = true;
            _LogFilters[(int)Logging.LogFilterType.TextInfo] = true;
            _LogFilters[(int)Logging.LogFilterType.TextError] = true;
            _LogFilters[(int)Logging.LogFilterType.TextAlert] = true;

            _refreshTimer = new System.Timers.Timer(750);
            _refreshTimer.Elapsed += FireTimer;
            _refreshTimer.AutoReset = false;
            _refreshTimer.Start();
        }

        private readonly rgatState _rgatState;
        private static bool[] _LogFilters = new bool[(int)LogFilterType.COUNT];
        private static readonly bool[] rowLastSelected = new bool[3];
        private static byte[] textFilterValue = new byte[500];
        private readonly System.Timers.Timer _refreshTimer;
        private bool _refreshTimerFired = false;
        private void FireTimer(object sender, System.Timers.ElapsedEventArgs e) { _refreshTimerFired = true; }

        private List<LOG_EVENT> _sortedMsgs = new List<LOG_EVENT>();



        public void Draw(ref bool show)
        {
            ImGui.SetNextWindowSize(new Vector2(800, 500), ImGuiCond.Appearing);
            if (ImGui.Begin("logtableframe", ref show))
            {
                //string label = $"{msgs.Length} log entries displayed from ({activeCount}/{_LogFilters.Length}) sources";

                Vector2 boxSize = new Vector2(75, 40);
                Vector2 marginSize = new Vector2(70, 40);
                ImGuiSelectableFlags flags = ImGuiSelectableFlags.DontClosePopups;
                uint tableHdrBG = 0xff333333;

                var textFilterCounts = Logging.GetTextFilterCounts();
                List<Tuple<string, LogFilterType>> filters = new List<Tuple<string, LogFilterType>>(){
                        new Tuple<string, LogFilterType>("Debug", LogFilterType.TextDebug),
                        new Tuple<string, LogFilterType>("Info", LogFilterType.TextInfo),
                        new Tuple<string, LogFilterType>("Alert", LogFilterType.TextAlert),
                        new Tuple<string, LogFilterType>("Error", LogFilterType.TextError)
                    };

                if (ImGui.BeginTable("LogFilterTable", filters.Count + 1, ImGuiTableFlags.Borders, new Vector2(boxSize.X * (filters.Count + 1), 41)))
                {
                    ImGui.TableNextRow();
                    ImGui.TableSetColumnIndex(0);
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, tableHdrBG);
                    if (ImGui.Selectable("Message", false, flags, marginSize))
                    {
                        rowLastSelected[0] = !rowLastSelected[0];
                        filters.ForEach((filter) => { _LogFilters[(int)filter.Item2] = rowLastSelected[0]; });
                    }
                    foreach (var filter in filters)
                    {
                        ImGui.TableNextColumn();
                        ImGui.Selectable($"{filter.Item1} ({textFilterCounts[filter.Item2]})", ref _LogFilters[(int)filter.Item2], flags, boxSize);
                    }
                    ImGui.EndTable();


                    if (ImGui.BeginPopupContextItem("FlterTableRightCtx", ImGuiPopupFlags.MouseButtonRight))
                    {
                        if (ImGui.MenuItem("Clear All Source Filters"))
                        {
                            Array.Clear(_LogFilters, 0, _LogFilters.Length);
                        }
                        if (ImGui.MenuItem("Apply All Source Filters"))
                        {
                            _LogFilters = Enumerable.Repeat(true, _LogFilters.Length).ToArray();
                        }
                        ImGui.EndPopup();
                    }
                    ImGui.SameLine();

                    ImGui.BeginGroup(); //filter text box
                    {
                        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 4);
                        ImGui.Indent(8);
                        ImGui.Text("Log Text Filter");
                        ImGui.SameLine();
                        ImGui.SetNextItemWidth(Math.Min(ImGui.GetContentRegionAvail().X - 50, 350));
                        ImGui.InputText("##IT1", textFilterValue, (uint)textFilterValue.Length);

                        ImGui.SameLine();
                        if (ImGui.Button("Clear"))
                        {
                            textFilterValue = new byte[textFilterValue.Length];
                        }

                        ImGui.EndGroup();
                    }
                    WriteLogContentTable();
                }
                ImGui.End();
            }
        }

        private void WriteLogContentTable()
        {
            Logging.LOG_EVENT[] msgs = Logging.GetLogMessages(null, _LogFilters);
            int activeCount = _LogFilters.Where(x => x == true).Count();

            int filterLen = Array.FindIndex(textFilterValue, x => x == '\0');
            string textFilterString = Encoding.ASCII.GetString(textFilterValue, 0, filterLen);

            ImGuiTableFlags tableFlags =
                ImGuiTableFlags.SizingStretchProp |
                ImGuiTableFlags.RowBg |
                ImGuiTableFlags.Borders |
                ImGuiTableFlags.Resizable |
                ImGuiTableFlags.Reorderable |
                ImGuiTableFlags.ScrollY |
                ImGuiTableFlags.ScrollX;
            //this is causing issues with the last column. using 4 columns makes it a bit better
            //tableFlags |= ImGuiTableFlags.Sortable;
            //tableFlags |= ImGuiTableFlags.SortMulti;

            if (ImGui.BeginTable("LogsTableContent", 3, tableFlags))
            {
                var ss = ImGui.TableGetSortSpecs();
                //if (ss.SpecsDirty || _refreshTimerFired)
                if (_refreshTimerFired)
                {
                    RegenerateRows(new List<LOG_EVENT>(msgs));
                    _refreshTimerFired = false;
                    _refreshTimer.Start();
                }

                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 150);// | ImGuiTableColumnFlags.DefaultSort | ImGuiTableColumnFlags.PreferSortDescending);
                ImGui.TableSetupColumn("Source", ImGuiTableColumnFlags.WidthFixed, 200);//;//", ImGuiTableColumnFlags.WidthFixed);
                ImGui.TableSetupColumn("Details");//, ImGuiTableColumnFlags.WidthStretch | ImGuiTableColumnFlags.NoSort);
                ImGui.TableHeadersRow();

                foreach (LOG_EVENT msg in _sortedMsgs)
                {
                    DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeMilliseconds(msg.EventTimeMS);
                    string timeString = dateTimeOffset.ToString("HH:mm:ss:ff");

                    string msgString;
                    string sourceString;
                    switch (msg.LogType)
                    {
                        case eLogFilterBaseType.Text:
                            {
                                Logging.TEXT_LOG_EVENT text_evt = (Logging.TEXT_LOG_EVENT)msg;
                                sourceString = $"{msg.LogType} - {text_evt.Filter}";
                                msgString = text_evt.Text;
                                break;
                            }
                        case eLogFilterBaseType.TimeLine:
                            {
                                Logging.TIMELINE_EVENT tl_evt = (Logging.TIMELINE_EVENT)msg;
                                sourceString = $"{tl_evt.Filter}";
                                msgString = string.Join("", tl_evt.Label().Select(l => l.Item1));
                                break;
                            }
                        default:
                            sourceString = "";
                            msgString = "Other event type " + msg.LogType.ToString();
                            break;
                    }

                    if (filterLen > 0)
                    {
                        string lowerFilter = textFilterString.ToLowerInvariant();
                        if (!msgString.ToLowerInvariant().Contains(textFilterString) &&
                            !sourceString.ToLowerInvariant().Contains(textFilterString) &&
                            !timeString.Contains(textFilterString))
                        {
                            continue;
                        }
                    }

                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text(timeString);
                    ImGui.TableNextColumn();
                    ImGui.Text(sourceString);
                    ImGui.TableNextColumn();
                    ImGui.TextWrapped(msgString);
                }
                ImGui.EndTable();
            }
        }

        private void RegenerateRows(List<LOG_EVENT> shownMsgs)
        {
            _sortedMsgs.Clear();
            if (_LogFilters.Any(f => f == true))
            {
                var TLmsgs = rgatState.ActiveTrace?.GetTimeLineEntries();
                if (TLmsgs != null)
                {
                    foreach (TIMELINE_EVENT ev in TLmsgs)
                    {
                        if (_LogFilters[(int)ev.Filter])
                        {
                            shownMsgs.Add(ev);
                        }
                    }
                }
            }

            _sortedMsgs = shownMsgs.OrderBy(o => o.EventTimeMS).ToList();
            /*
            var ss = ImGui.TableGetSortSpecs();

            switch (ss.Specs.ColumnIndex)
            {
                case 0:
                    if (ss.Specs.SortDirection == ImGuiSortDirection.Ascending)
                        _sortedMsgs = shownMsgs.OrderBy(o => o.EventTimeMS).ToList();
                    else
                        _sortedMsgs = shownMsgs.OrderByDescending(o => o.EventTimeMS).ToList();
                    break;
                case 1:
                    if (ss.Specs.SortDirection == ImGuiSortDirection.Ascending)
                        _sortedMsgs = shownMsgs.OrderBy(o => o.Filter).ToList();
                    else
                        _sortedMsgs = shownMsgs.OrderByDescending(o => o.Filter).ToList();
                    break;
                case 2:
                default:
                    _sortedMsgs = shownMsgs.ToList();
                    break;
            }
            ss.SpecsDirty = false;
            */
        }

        public static void ShowAlerts()
        {
            //select only the alerts filter
            Array.Clear(_LogFilters, 0, _LogFilters.Length);
            _LogFilters[(int)LogFilterType.TextAlert] = true;
            _LogFilters[(int)LogFilterType.TextError] = true;
        }


        public static bool RecentAlert()
        {
            const double lingerTime = UI.ALERT_TEXT_LINGER_TIME;
            double timeSinceLast = Logging.TimeSinceLastAlert.TotalMilliseconds;
            return (timeSinceLast < lingerTime);
        }
    }
}
