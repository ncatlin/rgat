using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using static rgat.Config.rgatSettings;

namespace rgat.Config
{
    /// <summary>
    /// A storage class for data from the remote rgat session
    /// </summary>
    public class RemoteDataMirror
    {
        static readonly object _lock = new object();

        /// <summary>
        /// Status of a command
        /// </summary>
        public enum ResponseStatus { 
            /// <summary>
            /// No record of it
            /// </summary>
            eNoRecord,
            /// <summary>
            /// Waiting for a response
            /// </summary>
            eWaiting,
            /// <summary>
            /// The response has arrived
            /// </summary>
            eDelivered,
            /// <summary>
            /// Error
            /// </summary>
            eError
        };

        /// <summary>
        /// A callback to a command response being delivered
        /// </summary>
        /// <param name="response">JSON of the reponse</param>
        /// <returns></returns>
        public delegate bool ProcessResponseCallback(JToken response);

        static readonly Dictionary<int, ProcessResponseCallback> _pendingCommandCallbacks = new Dictionary<int, ProcessResponseCallback>();


        static readonly Dictionary<string, int> _pendingEvents = new Dictionary<string, int>();
        static readonly Dictionary<int, string> _pendingEventsReverse = new Dictionary<int, string>();

        static readonly Dictionary<string, uint> _pipeIDDictionary = new Dictionary<string, uint>();

        /// <summary>
        /// Callback to process incoming trace data
        /// </summary>
        /// <param name="arg">trace data</param>
        public delegate void ProcessIncomingWorkerData(byte[] arg);

        static readonly Dictionary<uint, Threads.TraceProcessorWorker> _remoteDataWorkers = new Dictionary<uint, Threads.TraceProcessorWorker>();
        static readonly Dictionary<uint, ProcessIncomingWorkerData?> _pipeInterfaces = new Dictionary<uint, ProcessIncomingWorkerData?>();


        /// <summary>
        /// Associate a remote named pipe with a Trace processor worker
        /// </summary>
        /// <param name="pipeID">Remote pipe ID</param>
        /// <param name="worker">Trace proessor worker</param>
        /// <param name="func">Callback function for incoming worker data</param>
        public static void RegisterRemotePipe(uint pipeID, Threads.TraceProcessorWorker worker, ProcessIncomingWorkerData? func)
        {
            lock (_lock)
            {
                _remoteDataWorkers.Add(pipeID, worker);
                _pipeInterfaces.Add(pipeID, func);
            }
        }

        /// <summary>
        /// Get the worker for a remote pipe
        /// </summary>
        /// <param name="pipeID">Remote pipe ID</param>
        /// <param name="worker">Worker</param>
        /// <returns>Found a worker</returns>
        public static bool GetPipeWorker(uint pipeID, out Threads.TraceProcessorWorker? worker)
        {
            lock (_lock)
            {
                return _remoteDataWorkers.TryGetValue(pipeID, out worker);
            }
        }

        /// <summary>
        /// Get the incoming data callback for a remote network tracing pipe
        /// </summary>
        /// <param name="pipeID">Remote pipe ID</param>
        /// <param name="func">callback function</param>
        /// <returns>found</returns>
        public static bool GetPipeInterface(uint pipeID, out ProcessIncomingWorkerData? func)
        {
            lock (_lock)
            {
                return _pipeInterfaces.TryGetValue(pipeID, out func);
            }
        }


        static uint pipeCount = 0;
        /// <summary>
        /// Register a local pipe for linking to a remote trace data stream
        /// </summary>
        /// <param name="pipename">Name of the pipe</param>
        /// <returns>The ID of the registered pipe</returns>
        public static uint RegisterPipe(string pipename)
        {
            lock (_lock)
            {
                pipeCount++;
                _pipeIDDictionary[pipename] = pipeCount;
                return pipeCount;
            }
        }


        /// <summary>
        /// Register a recipient and optional callback for a command response
        /// </summary>
        /// <param name="commandID">ID of the command</param>
        /// <param name="cmd">Command text</param>
        /// <param name="recipient">Recipient for responses</param>
        /// <param name="callback">Callback to handle the response (otherwise it will have to be fetched)</param>
        public static void RegisterPendingResponse(int commandID, string cmd, string recipient, ProcessResponseCallback? callback = null)
        {
            string addressedCmd = cmd + recipient;
            lock (_lock)
            {
                if (callback is not null)
                {
                    Debug.Assert(!_pendingEvents.ContainsKey(addressedCmd));
                    Debug.Assert(!_pendingEventsReverse.ContainsKey(commandID));
                    _pendingEvents.Add(addressedCmd, commandID);
                    _pendingEventsReverse.Add(commandID, addressedCmd);

                    Debug.Assert(!_pendingCommandCallbacks.ContainsKey(commandID));
                    _pendingCommandCallbacks.Add(commandID, callback!);
                }
            }
        }

        /// <summary>
        /// Check if a response has been received
        /// </summary>
        /// <param name="command">A command</param>
        /// <param name="recipient">A recipient waiting for a response to it</param>
        /// <returns></returns>
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

        /// <summary>
        /// Deliver a response to a command
        /// </summary>
        /// <param name="commandID">The ID of the command</param>
        /// <param name="response">JSON reponse data</param>
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
        /// <summary>
        /// Record recent path data from the remote host
        /// </summary>
        /// <param name="entries">Pathrecord entries</param>
        public static void SetRecentPaths(List<PathRecord> entries)
        {
            lock (_lock)
            {
                _cachedRecentBins = entries;
            }
        }

        /// <summary>
        /// Store a list of recent binaries sent by the headless rgat instance
        /// </summary>
        /// <param name="dataTok">JToken of recent paths</param>
        /// <returns>Successful deserialising</returns>
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

                PathRecord newEntry = new PathRecord()
                {
                    Path = prop1!.ToString(),
                    FirstOpen = prop2!.ToObject<DateTime>(),
                    LastOpen = prop3!.ToObject<DateTime>(),
                    OpenCount = prop4!.ToObject<uint>()
                };
                recentbins.Add(newEntry);
            }

            recentbins.Sort(new rgatSettings.PathRecord.SortLatestAccess());
            RemoteDataMirror.SetRecentPaths(recentbins);
            return true;
        }


        /// <summary>
        /// Fetch recently executed binaries
        /// </summary>
        /// <returns>Array of path records</returns>
        public static PathRecord[] GetRecentBins()
        {
            lock (_lock)
            {
                return _cachedRecentBins.ToArray();
            }
        }

        /// <summary>
        /// Root directory of the remote host session
        /// </summary>
        public static string RootDirectory = "";
    }
}
