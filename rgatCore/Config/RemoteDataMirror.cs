using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using static rgat.Config.rgatSettings;

namespace rgat.Config
{
    public class RemoteDataMirror
    {
        static readonly object _lock = new object();

        public enum ResponseStatus { eNoRecord, eWaiting, eDelivered, eError };
        public delegate bool ProcessResponseCallback(JToken response);

        static readonly Dictionary<int, ProcessResponseCallback> _pendingCommandCallbacks = new Dictionary<int, ProcessResponseCallback>();


        static readonly Dictionary<string, int> _pendingEvents = new Dictionary<string, int>();
        static readonly Dictionary<int, string> _pendingEventsReverse = new Dictionary<int, string>();

        static readonly Dictionary<string, uint> _pipeIDDictionary = new Dictionary<string, uint>();


        public delegate void ProcessIncomingWorkerData(byte[] arg);

        static readonly Dictionary<uint, Threads.TraceProcessorWorker> _remoteDataWorkers = new Dictionary<uint, Threads.TraceProcessorWorker>();
        static readonly Dictionary<uint, ProcessIncomingWorkerData?> _pipeInterfaces = new Dictionary<uint, ProcessIncomingWorkerData?>();

        public static void RegisterRemotePipe(uint pipeID, Threads.TraceProcessorWorker worker, ProcessIncomingWorkerData? func)
        {
            lock (_lock)
            {
                _remoteDataWorkers.Add(pipeID, worker);
                _pipeInterfaces.Add(pipeID, func);
            }
        }

        public static bool GetPipeWorker(uint pipeID, out Threads.TraceProcessorWorker? worker)
        {
            lock (_lock)
            {
                return _remoteDataWorkers.TryGetValue(pipeID, out worker);
            }
        }

        public static bool GetPipeInterface(uint pipeID, out ProcessIncomingWorkerData? func)
        {
            lock (_lock)
            {
                return _pipeInterfaces.TryGetValue(pipeID, out func);
            }
        }


        static uint pipeCount = 0;
        public static uint RegisterPipe(string pipename)
        {
            lock (_lock)
            {
                pipeCount++;
                _pipeIDDictionary[pipename] = pipeCount;
                return pipeCount;
            }
        }

        public static void RegisterPendingResponse(int commandID, string cmd, string recipient, ProcessResponseCallback? callback = null)
        {
            string addressedCmd = cmd + recipient;
            lock (_lock)
            {
                Debug.Assert(!_pendingEvents.ContainsKey(addressedCmd));
                Debug.Assert(!_pendingEventsReverse.ContainsKey(commandID));
                _pendingEvents.Add(addressedCmd, commandID);
                _pendingEventsReverse.Add(commandID, addressedCmd);

                Debug.Assert(!_pendingCommandCallbacks.ContainsKey(commandID));
                _pendingCommandCallbacks.Add(commandID, callback);

            }
        }

        public static ResponseStatus CheckTaskStatus(string command, string recipient)
        {
            string addressedCmd = command + recipient;
            lock (_lock)
            {
                if (!_pendingEvents.TryGetValue(addressedCmd, out int cmdID)) return ResponseStatus.eNoRecord;
                if (_pendingCommandCallbacks.ContainsKey(cmdID)) return ResponseStatus.eWaiting;
                return ResponseStatus.eError;
            }
        }


        public static void DeliverResponse(int commandID, JToken response)
        {
            lock (_lock)
            {

                if (_pendingCommandCallbacks.TryGetValue(commandID, out ProcessResponseCallback? cb) && cb is not null)
                {
                    string cmdref = _pendingEventsReverse[commandID];
                    bool success = false;
                    try
                    {
                        success = cb(response);
                        if (!success)
                        {
                            Logging.RecordLogEvent($"Invocation of callback for request {commandID} ({cmdref}) failed", Logging.LogFilterType.TextError);
                        }
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Exception invoking callback for request {commandID} ({cmdref}): {e}", Logging.LogFilterType.TextError);
                    }
                    if (!success)
                    {
                        rgatState.NetworkBridge.Teardown($"Command failed: {commandID}:{cmdref}");
                    }
                    _pendingCommandCallbacks.Remove(commandID);
                    _pendingEvents.Remove(_pendingEventsReverse[commandID]);
                    _pendingEventsReverse.Remove(commandID);

                }
            }
        }



        // file info

        static List<PathRecord> _cachedRecentBins = new List<PathRecord>();
        public static void SetRecentPaths(List<PathRecord> entries)
        {
            lock (_lock)
            {
                _cachedRecentBins = entries;
            }
        }

        public static bool HandleRecentBinariesList(JToken dataTok)
        {
            if (dataTok.Type != JTokenType.Array)
            {
                Logging.RecordLogEvent($"HandleRecentBinariesList: Non-array recent binaries list", Logging.LogFilterType.TextError);
                return false;
            }

            JArray? bintoks = dataTok.ToObject<JArray>();
            if (bintoks is null)
            {
                Logging.RecordLogEvent($"HandleRecentBinariesList: Bad recent binaries list", Logging.LogFilterType.TextError);
                return false;
            }

            List<PathRecord> recentbins = new List<PathRecord>();

            foreach (JToken recentbinTok in bintoks)
            {
                if (recentbinTok is null || recentbinTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent("HandleRecentBinariesList: Bad PathRecord", Logging.LogFilterType.TextError);
                    return false;
                }
                JObject? binJsn = recentbinTok.ToObject<JObject>();
                JToken? prop1 = null, prop2 = null, prop3 = null, prop4 = null;
                bool success = binJsn is not null && binJsn.TryGetValue("Path", out prop1) && prop1 is not null && prop1.Type == JTokenType.String;
                success = success && binJsn!.TryGetValue("FirstOpen", out prop2) && prop2 is not null && prop2.Type == JTokenType.Date;
                success = success && binJsn!.TryGetValue("LastOpen", out prop3) && prop3 is not null && prop3.Type == JTokenType.Date;
                success = success && binJsn!.TryGetValue("OpenCount", out prop4) && prop4 is not null && prop4.Type == JTokenType.Integer;

                if (!success)
                {
                    Logging.RecordLogEvent($"HandleRecentBinariesList: Bad property in cached path item. {recentbinTok.ToString()}");
                    return false;
                }

                PathRecord newEntry = new PathRecord();
                newEntry.Path = prop1!.ToString();
                newEntry.FirstOpen = prop2!.ToObject<DateTime>();
                newEntry.LastOpen = prop3!.ToObject<DateTime>();
                newEntry.OpenCount = prop4!.ToObject<uint>();
                recentbins.Add(newEntry);
            }

            recentbins.Sort(new rgatSettings.PathRecord.SortLatestAccess());
            RemoteDataMirror.SetRecentPaths(recentbins);
            return true;
        }



        public static PathRecord[] GetRecentBins()
        {
            lock (_lock)
            {
                return _cachedRecentBins.ToArray();
            }
        }

        public static string RootDirectory;
    }
}
