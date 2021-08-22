using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using static rgat.Logging;

namespace rgat
{
    partial class rgatUI
    {
        static bool[] _LogFilters = new bool[(int)LogFilterType.COUNT];
        static bool[] rowLastSelected = new bool[3];
        static byte[] textFilterValue = new byte[500];
        static string _logSort = "Time<";
        private void DrawLogsTab()
        {
            if (ImGui.BeginChildFrame(ImGui.GetID("logtableframe"), ImGui.GetContentRegionAvail()))
            {
                Logging.LOG_EVENT[] msgs = Logging.GetLogMessages(null, _LogFilters);
                int activeCount = _LogFilters.Where(x => x == true).Count();

                string label = $"{msgs.Length} log entries displayed from ({activeCount}/{_LogFilters.Length}) sources";

                ImGui.SetNextItemOpen(true);
                bool isOpen = ImGui.TreeNode("##FiltersTree", label);
                if (isOpen)
                {
                    Vector2 boxSize = new Vector2(75, 40);
                    Vector2 marginSize = new Vector2(70, 40);

                    ImGuiSelectableFlags flags = ImGuiSelectableFlags.DontClosePopups;
                    uint tableHdrBG = 0xff333333;


                    var textFilterCounts = Logging.GetTextFilterCounts();

                    if (ImGui.BeginTable("LogFilterTable", 7, ImGuiTableFlags.Borders, new Vector2(boxSize.X * 7, 41)))
                    {
                        ImGui.TableNextRow();

                        ImGui.TableSetColumnIndex(0);
                        ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg, tableHdrBG);
                        if (ImGui.Selectable("Message", false, flags, marginSize))
                        {
                            rowLastSelected[0] = !rowLastSelected[0];
                            _LogFilters[(int)LogFilterType.TextDebug] = rowLastSelected[0];
                            _LogFilters[(int)LogFilterType.TextInfo] = rowLastSelected[0];
                            _LogFilters[(int)LogFilterType.TextAlert] = rowLastSelected[0];
                            _LogFilters[(int)LogFilterType.TextError] = rowLastSelected[0];
                        }


                        ImGui.TableNextColumn();
                        ImGui.Selectable($"Debug ({textFilterCounts[LogFilterType.TextDebug]})",
                            ref _LogFilters[(int)LogFilterType.TextDebug], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable($"Info ({textFilterCounts[LogFilterType.TextInfo]})",
                            ref _LogFilters[(int)LogFilterType.TextInfo], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable($"Alert ({textFilterCounts[LogFilterType.TextAlert]})",
                            ref _LogFilters[(int)LogFilterType.TextAlert], flags, boxSize);

                        ImGui.TableNextColumn();
                        ImGui.Selectable($"Error ({textFilterCounts[LogFilterType.TextError]})",
                            ref _LogFilters[(int)LogFilterType.TextError], flags, boxSize);

                        ImGui.EndTable();
                    }

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


                    ImGui.BeginGroup();
                    {
                        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 4);
                        ImGui.Indent(8);
                        ImGui.Text("Log Text Filter");
                        ImGui.SameLine();
                        ImGui.SetNextItemWidth(280);
                        ImGui.InputText("##IT1", textFilterValue, (uint)textFilterValue.Length);

                        ImGui.SameLine();
                        if (ImGui.Button("Clear")) textFilterValue = new byte[textFilterValue.Length];

                        ImGui.EndGroup();
                    }


                    ImGui.TreePop();
                }



                List<LOG_EVENT> shownMsgs = new List<LOG_EVENT>(msgs);
                if (_LogFilters.Any(f => f == true))
                {
                    var TLmsgs = _rgatState.ActiveTrace?.GetTimeLineEntries();
                    if (TLmsgs != null)
                    {
                        foreach (TIMELINE_EVENT ev in TLmsgs)
                        {
                            if (_LogFilters[(int)ev.Filter])
                                shownMsgs.Add(ev);
                        }
                    }
                }

                List<LOG_EVENT> sortedMsgs = shownMsgs;

                int filterLen = Array.FindIndex(textFilterValue, x => x == '\0');
                string textFilterString = Encoding.ASCII.GetString(textFilterValue, 0, filterLen);

                ImGuiTableFlags tableFlags = ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY | ImGuiTableFlags.Sortable | ImGuiTableFlags.SortMulti;
                if (ImGui.BeginTable("LogsTable", 3, tableFlags, ImGui.GetContentRegionAvail()))
                {
                    var ss = ImGui.TableGetSortSpecs();
                    //if (ss.SpecsDirty) //todo - caching
                    {
                        switch (ss.Specs.ColumnIndex)
                        {
                            case 0:
                                if (ss.Specs.SortDirection == ImGuiSortDirection.Ascending)
                                    sortedMsgs = shownMsgs.OrderBy(o => o.EventTimeMS).ToList();
                                else
                                    sortedMsgs = shownMsgs.OrderByDescending(o => o.EventTimeMS).ToList();
                                break;
                            case 1:
                                if (ss.Specs.SortDirection == ImGuiSortDirection.Ascending)
                                    sortedMsgs = shownMsgs.OrderBy(o => o.Filter).ToList();
                                else
                                    sortedMsgs = shownMsgs.OrderByDescending(o => o.Filter).ToList();
                                break;
                            case 2:
                                //todo - caching
                                break;
                        }
                        ss.SpecsDirty = false;
                    }

                    ImGui.TableSetupScrollFreeze(0, 1);
                    ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 90);
                    ImGui.TableSetupColumn("Source", ImGuiTableColumnFlags.WidthFixed, 100);
                    ImGui.TableSetupColumn("Details");
                    ImGui.TableHeadersRow();

                    foreach (LOG_EVENT msg in sortedMsgs)
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
                                    sourceString = $"{msg.LogType} - {text_evt._filter}";
                                    msgString = text_evt._text;
                                    break;
                                }

                            case eLogFilterBaseType.TimeLine:
                                {
                                    Logging.TIMELINE_EVENT tl_evt = (Logging.TIMELINE_EVENT)msg;
                                    sourceString = $"{tl_evt.Filter}";
                                    msgString = String.Join("", tl_evt.Label().Select(l => l.Item1));
                                    break;
                                }
                            default:
                                sourceString = "";
                                msgString = "Other event type " + msg.LogType.ToString();
                                break;

                        }



                        if (filterLen > 0)
                        {
                            if (!msgString.Contains(textFilterString) &&
                                !sourceString.Contains(textFilterString) &&
                                !timeString.Contains(textFilterString))
                                continue;
                        }

                        ImGui.TableNextRow();
                        ImGui.TableNextColumn();
                        ImGui.Text(timeString);
                        ImGui.TableNextColumn();
                        ImGui.Text(sourceString);
                        ImGui.TableNextColumn();
                        ImGui.TextWrapped(msgString);
                    }
                    ImGui.EndTable(); ;
                }
                ImGui.EndChildFrame();
            }
            ImGui.EndTabItem();
        }

    }
}
