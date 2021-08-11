using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using static rgat.GlobalConfig;

namespace rgat.Config
{
    public class RemoteDataMirror
    {
        static readonly object _lock = new object();

        public enum ResponseStatus { eNoRecord, eWaiting, eDelivered, eError };
        public delegate bool ProcessResponseCallback(JToken response);

        static Dictionary<int, ProcessResponseCallback> _pendingCommandCallbacks = new Dictionary<int, ProcessResponseCallback>();


        static Dictionary<string, int> _pendingEvents = new Dictionary<string, int>();
        static Dictionary<int, string> _pendingEventsReverse = new Dictionary<int, string>();
        public static void RegisterPendingResponse(int commandID, string cmd, string recipient, ProcessResponseCallback callback = null)
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
 
                if (_pendingCommandCallbacks.TryGetValue(commandID, out ProcessResponseCallback cb))
                {

                    bool success = false;
                    try
                    {
                        success = cb(response);
                    }
                    catch (Exception e)
                    {
                        Logging.RecordLogEvent($"Exception invoking callback for command {commandID}: {e}", Logging.LogFilterType.TextError);
                    }
                    _pendingCommandCallbacks.Remove(commandID);
                    _pendingEvents.Remove(_pendingEventsReverse[commandID]);
                    _pendingEventsReverse.Remove(commandID);
                    if (!success)
                    {
                        Logging.RecordLogEvent($"Invocation of callback for {commandID} failed", Logging.LogFilterType.TextError);

                    }
                }
            }
        }




        // file info

        static List<CachedPathData> _cachedRecentBins = new List<CachedPathData>();
        public static void SetRecentPaths(List<CachedPathData> entries)
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

            List<GlobalConfig.CachedPathData> recentbins = new List<GlobalConfig.CachedPathData>();

            JArray bintoks = dataTok.ToObject<JArray>();
            foreach (JToken recentbinTok in bintoks)
            {
                if (recentbinTok.Type != JTokenType.Object)
                {
                    Logging.RecordLogEvent("HandleRecentBinariesList: Bad CachedPathData", Logging.LogFilterType.TextError);
                    return false;
                }
                JObject binJsn = recentbinTok.ToObject<JObject>();
                JToken prop1, prop2 = null, prop3 = null, prop4 = null;
                bool success = binJsn.TryGetValue("path", out prop1) && prop1.Type == JTokenType.String;
                success = success && binJsn.TryGetValue("firstSeen", out prop2) && prop2.Type == JTokenType.Date;
                success = success && binJsn.TryGetValue("lastSeen", out prop3) && prop3.Type == JTokenType.Date;
                success = success && binJsn.TryGetValue("count", out prop4) && prop4.Type == JTokenType.Integer;

                if (!success)
                {
                    Logging.RecordLogEvent($"HandleRecentBinariesList: Bad property in cached path item. {recentbinTok.ToString()}");
                    return false;
                }

                GlobalConfig.CachedPathData newEntry = new GlobalConfig.CachedPathData();
                newEntry.path = prop1.ToString();
                newEntry.firstSeen = prop2.ToObject<DateTime>();
                newEntry.lastSeen = prop3.ToObject<DateTime>();
                newEntry.count = prop4.ToObject<uint>();
                recentbins.Add(newEntry);
            }

            RemoteDataMirror.SetRecentPaths(recentbins);
            return true;
        }



        public static List<CachedPathData> GetRecentBins()
        {
            lock (_lock)
            {
                return new List<CachedPathData>(_cachedRecentBins);
            }
        }

        public static string RootDirectory;
    }
}
