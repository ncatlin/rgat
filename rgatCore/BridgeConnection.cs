using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using rgat.Config;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace rgat
{
    public class BridgeConnection
    {
        public enum emsgType { Meta, Command, CommandResponse, TraceMeta, TraceData, TraceCommand, Log, BAD };

        public delegate void OnGotDataCallback(NETWORK_MSG data);
        public delegate void OnConnectSuccessCallback();

        public bool Connected => BridgeState == eBridgeState.Connected;
        public string LastAddress { get; private set; } = "";
        public bool ActiveNetworking => BridgeState == eBridgeState.Connected || BridgeState == eBridgeState.Listening || BridgeState == eBridgeState.Connecting;

        //public IPEndPoint ConnectedEndpoint = null;
        public enum eBridgeState { Inactive, Connecting, Listening, Connected, Errored, Teardown };
        public eBridgeState BridgeState
        {
            get => _bridgeState;
            private set
            {
                _bridgeState = value;
            }
        }
        eBridgeState _bridgeState = eBridgeState.Inactive;


        readonly object _messagesLock = new object();
        List<Tuple<string, Themes.eThemeColour?>> _displayLogMessages = new List<Tuple<string, Themes.eThemeColour?>>();

        /// <summary>
        /// Whether this instance is the GUI.
        /// The GUI sends tracing commands and recieves trace data and associated metadata (available files to execute, signature hits, etc)
        /// It does not do the opposite. Ever.
        /// </summary>
        public bool GUIMode { get; private set; }
        public bool HeadlessMode => !GUIMode;

        public struct NETWORK_MSG
        {
            public emsgType msgType;
            public uint destinationID;
            public byte[] data;
        }
        Queue<NETWORK_MSG> _OutDataQueue = new Queue<NETWORK_MSG>();
        ManualResetEventSlim NewOutDataEvent = new ManualResetEventSlim(false);

        CancellationTokenSource cancelTokens;
        public CancellationToken CancelToken => cancelTokens.Token;
        readonly object _sendQueueLock = new object();

        TcpClient _ActiveClient;
        TcpListener _ActiveListener;
        OnGotDataCallback _registeredIncomingDataCallback;
        public IPEndPoint RemoteEndPoint;


        const string connectPreludeGUI = "rgat connect GUI prelude";
        const string connectPreludeHeadless = "rgat connect headless prelude";
        const string connectResponseGUI = "rgat accept GUI prelude";
        const string connectResponseHeadless = "rgat accept headless prelude";

        public BridgeConnection(bool isgui)
        {
            GUIMode = isgui;
        }

        /// <summary>
        /// Initiate a bridge connection in remote mode
        /// This will be complete when it connects to another rgat instance with the right network key
        /// </summary>
        /// <param name="localBindAddress">The local ip address to connect from</param>
        /// <param name="remoteConnectAddress">The remote ip address or domain to connect to</param>
        /// <param name="remoteConnectPort">The remote TCP port to connect to</param>
        /// <returns></returns>
        public void Start(IPAddress localBindAddress, string remoteConnectAddress, int remoteConnectPort, OnGotDataCallback datacallback, BridgeConnection.OnConnectSuccessCallback connectCallback)
        {
            Reset();
            BridgeState = eBridgeState.Connecting;
            _ActiveClient = new TcpClient(new IPEndPoint(localBindAddress, 0));
            _registeredIncomingDataCallback = datacallback;
            Task.Run(() => StartConnectOut(_ActiveClient, remoteConnectAddress, remoteConnectPort, connectCallback));
        }

        void StartConnectOut(TcpClient client, string remoteConnectAddress, int remoteConnectPort, BridgeConnection.OnConnectSuccessCallback connectCallback)
        {
            Task connect;
            try
            {
                AddDisplayLogMessage($"Connecting from {((IPEndPoint)client.Client.LocalEndPoint).Address} to {remoteConnectAddress}:{remoteConnectPort}", null);
                connect = _ActiveClient.ConnectAsync(remoteConnectAddress, remoteConnectPort);
                Task.WaitAny(new Task[] { connect }, CancelToken);
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode == SocketError.AddressNotAvailable)
                {
                    AddDisplayLogMessage($"Remote Address unavailable. Wrong interface?", Themes.eThemeColour.eWarnStateColour);
                }
                else
                {
                    AddDisplayLogMessage($"Connection Failed: {e.SocketErrorCode}", Themes.eThemeColour.eWarnStateColour);
                }
                Teardown();
                return;
            }
            catch (OperationCanceledException e)
            {
                Logging.RecordLogEvent($"User cancelled connection attempt", Logging.LogFilterType.TextDebug);
                Teardown();
                return;
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Exception {e} in StartConnectOut", Logging.LogFilterType.TextError);
                Teardown();
                return;
            }

            if (client.Connected)
            {

                if (AuthenticateOutgoingConnection(client, client.GetStream()))
                {
                    AddDisplayLogMessage($"Connected to {remoteConnectAddress}:{remoteConnectPort}", Themes.eThemeColour.eGoodStateColour);
                    ServeAuthenticatedConnection(client, connectCallback);
                    return;
                }
            }
            else
            {
                if (connect.Status == TaskStatus.Faulted)
                {
                    switch (connect.Exception.InnerException)
                    {
                        case SocketException sockExcep:
                            {
                                AddDisplayLogMessage($"Connection Failed: {sockExcep.SocketErrorCode}", Themes.eThemeColour.eWarnStateColour);
                                break;
                            }
                        default:
                            AddDisplayLogMessage($"Connection Failed (Fault)", Themes.eThemeColour.eWarnStateColour);
                            break;
                    }
                }
                else
                {
                    AddDisplayLogMessage($"Connection Failed (NoFault)", Themes.eThemeColour.eWarnStateColour);
                }
            }
            Teardown("Connect Mode Finished");
        }

        void AddDisplayLogMessage(string msg, Themes.eThemeColour? colour)
        {
            if (GUIMode)
            {
                lock (_messagesLock)
                {
                    _displayLogMessages.Add(new Tuple<string, Themes.eThemeColour?>(msg, colour));
                    if (_displayLogMessages.Count > 10)
                    {
                        _displayLogMessages = _displayLogMessages.TakeLast(10).ToList();
                    }
                }
            }
            else
            {
                Console.WriteLine(msg);
            }
        }

        public List<Tuple<string, Themes.eThemeColour?>> GetRecentConnectEvents()
        {
            lock (_messagesLock)
            {
                return _displayLogMessages;
            }
        }

        /// <summary>
        /// Initiate a bridge connection in listener mode
        /// This will be complete when another rgat instance connects to it with the right network key
        /// </summary>
        /// <param name="localBindAddress">The local ip address to bind to</param>
        /// <param name="localBindPort">The local TCP port to listen on</param>
        /// <returns></returns>
        public Task Start(IPAddress localBindAddress, int localBindPort, OnGotDataCallback dataCallback, OnConnectSuccessCallback connectCallback)
        {
            Reset();

            try
            {
                _ActiveListener = new TcpListener(localBindAddress, localBindPort);
                _ActiveListener.ExclusiveAddressUse = true;
                _ActiveListener.Start();
                BridgeState = eBridgeState.Listening;
            }
            catch (SocketException e)
            {
                AddDisplayLogMessage($"Listen Failed: {e.SocketErrorCode}", Themes.eThemeColour.eWarnStateColour);
                Teardown();
            }
            catch (Exception e)
            {
                AddDisplayLogMessage($"Listen Failed", Themes.eThemeColour.eWarnStateColour);
                Teardown();
            }

            _registeredIncomingDataCallback = dataCallback;
            return Task.Run(() => StartListenForConnection(_ActiveListener, connectCallback));
        }

        void StartListenForConnection(TcpListener listener, OnConnectSuccessCallback connectCallback)
        {
            if (BridgeState != eBridgeState.Listening) return;

            AddDisplayLogMessage($"Listening on {(IPEndPoint)listener.Server.LocalEndPoint}", null);
            try
            {
                _ActiveClient = listener.AcceptTcpClient();
            }
            catch (SocketException e)
            {
                if (!cancelTokens.IsCancellationRequested)
                {
                    AddDisplayLogMessage($"Failed Accept: {e.SocketErrorCode}", Themes.eThemeColour.eWarnStateColour);
                }
                Teardown();
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception {e} in StartConnectOut");
                Teardown();
                return;
            }

            if (_ActiveClient != null && _ActiveClient.Connected)
            {

                IPEndPoint clientEndpoint = (IPEndPoint)_ActiveClient.Client.RemoteEndPoint;
                AddDisplayLogMessage($"Incoming connection from {clientEndpoint}", null);
                if (AuthenticateIncomingConnection(_ActiveClient, _ActiveClient.GetStream()))
                {
                    AddDisplayLogMessage("Connected to rgat", Themes.eThemeColour.eGoodStateColour);
                    Logging.RecordLogEvent($"New connection from {clientEndpoint}", Logging.LogFilterType.TextAlert);
                    ServeAuthenticatedConnection(_ActiveClient, connectCallback);
                }
                else
                {
                    Teardown();
                    Logging.RecordLogEvent($"Failed connection from {clientEndpoint}", Logging.LogFilterType.TextAlert);
                    _ActiveClient = null;
                    BridgeState = eBridgeState.Errored;
                    return;
                }
            }
            else
            {
                Teardown();
                Console.WriteLine($"StartListenForConnection not connected");
                BridgeState = eBridgeState.Errored;
            }
        }


        public void Reset()
        {
            if (cancelTokens != null)
            {
                cancelTokens.Cancel();
            }
            lock (_sendQueueLock)
            {
                _OutDataQueue.Clear();
                NewOutDataEvent.Reset();
            }
            RemoteEndPoint = null;
            cancelTokens = new CancellationTokenSource();
            _ActiveClient = null;
        }


        void ServeAuthenticatedConnection(TcpClient client, OnConnectSuccessCallback connectedCallback)
        {
            RemoteEndPoint = (IPEndPoint)client.Client.RemoteEndPoint;
            LastAddress = RemoteEndPoint.Address.ToString();
            BridgeState = eBridgeState.Connected;
            Console.WriteLine("Invoking connected callback");
            Task.Run(() => connectedCallback());
            StartConnectionDataHandlers(client);
        }

        void StartConnectionDataHandlers(TcpClient client)
        {

            // Get a stream object for reading and writing
            NetworkStream stream = client.GetStream();

            Console.WriteLine($"Client {client} authenticated, serving...");

            Task reader = Task.Run(() => ReceiveIncomingTraffic(client));
            Task sender = Task.Run(() => SendOutgoingTraffic(client));
        }

        /*
        public void SendOutgoingData(Tuple<emsgType, byte[]> data)
        {
            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(data);
                NewOutDataEvent.Set();
            }
        }*/


        static int commandCount = 0;
        /// <summary>
        /// Send a command to the remote instance of rgat (which is in commandline tracing mode)
        /// The handling of the response (a JToken) depends on the arguments
        ///     If a callback is specified, it will be executed with the response as a parameter
        ///     Otherwise it will be stored for the requestor to pick up later
        /// </summary>
        /// <param name="command">The task to perform</param>
        /// <param name="recipientID">The intended recipient of the task, eg a certain file picker requested the directory they are in</param>
        /// <param name="callback">A callback to be performed with the response</param>
        public int SendCommand(string command, string recipientID, RemoteDataMirror.ProcessResponseCallback callback, string param = null)
        {
            Debug.Assert(!command.Contains('&'));

            lock (_sendQueueLock)
            {
                commandCount += 1;
                string fulltext = $"{command}&{commandCount}";
                if (param != null)
                    fulltext += "&" + param;
                fulltext += '&';
                Console.WriteLine("Send cmd  " + fulltext);
                if (callback != null)
                {
                    Debug.Assert(recipientID != null);
                    RemoteDataMirror.RegisterPendingResponse(commandCount, command, recipientID, callback);
                }
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = emsgType.Command, destinationID = 0, data = Encoding.ASCII.GetBytes(fulltext) });
                NewOutDataEvent.Set();
                return commandCount;
            }
        }


        public void SendTraceCommand(uint pipe, string message)
        {
            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = emsgType.TraceCommand, destinationID = pipe, data = Encoding.ASCII.GetBytes(message) });
                NewOutDataEvent.Set();
            }
        }


        public void SendLog(string message, Logging.LogFilterType msgType)
        {
            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = emsgType.Log, destinationID = (uint)msgType, data = Encoding.ASCII.GetBytes(message) });
                NewOutDataEvent.Set();
            }

        }


        public void SendRawTraceData(uint pipeID, byte[] buf, int bufSize)
        {
            Debug.Assert(rgatState.NetworkBridge.HeadlessMode);
            byte[] data;
            if (bufSize != buf.Length)
            {
                data = new byte[bufSize];
                Array.Copy(buf, data, bufSize);
            }
            else
            {
                data = buf;
            }


            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = emsgType.TraceData, destinationID = pipeID, data = data });
                NewOutDataEvent.Set();
            }
        }


        public void SendTraceMeta(TraceRecord trace, string info)
        {
            Debug.Assert(rgatState.ConnectedToRemote && rgatState.NetworkBridge.HeadlessMode);
            lock (_sendQueueLock)
            {
                Console.WriteLine($"SendTraceMeta message {info}");
                byte[] Jsnbytes = Encoding.ASCII.GetBytes($"{trace.binaryTarg.GetSHA1Hash()},{trace.PID},{trace.randID},{info}");
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = emsgType.TraceMeta, destinationID = 0, data = Jsnbytes });
                NewOutDataEvent.Set();
            }
        }




        //https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2328
        readonly Newtonsoft.Json.JsonSerializer serialiserIn = Newtonsoft.Json.JsonSerializer.Create(new JsonSerializerSettings()
        {
            TypeNameHandling = TypeNameHandling.None,
        });
        readonly Newtonsoft.Json.JsonSerializer serialiserOut = Newtonsoft.Json.JsonSerializer.Create(new JsonSerializerSettings()
        {
            TypeNameHandling = TypeNameHandling.None,
        });

        /// <summary>
        /// Used to send raw .net data types (serialised as JSON) as command responses
        /// Useful for when the GUI just wants a copy of some pre-existing data
        /// </summary>
        /// <param name="command"></param>
        /// <param name="response"></param>
        public void SendResponseObject(int commandID, object response)
        {
            lock (_sendQueueLock)
            {
                StringBuilder sb = new StringBuilder();
                StringWriter sw = new StringWriter(sb);
                JsonWriter writer = new JsonTextWriter(sw);

                serialiserOut.Serialize(writer, response);
                JObject responseObj = new JObject() { new JProperty("CommandID", commandID), new JProperty("Response", JToken.Parse(sb.ToString())) };

                byte[] Jsnbytes = Encoding.ASCII.GetBytes(responseObj.ToString(formatting: Formatting.None));
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = emsgType.CommandResponse, destinationID = 0, data = Jsnbytes });
                NewOutDataEvent.Set();
            }
        }


        /// <summary>
        /// Send pre-built json objects as a command response
        /// This is usually for when the gui needs some API output, rather than neatly packaged data that we already have
        /// </summary>
        /// <param name="command"></param>
        /// <param name="response"></param>
        public void SendResponseJSON(int commandID, JObject response)
        {
            lock (_sendQueueLock)
            {
                JObject responseObj = new JObject() { new JProperty("CommandID", commandID), new JProperty("Response", response) };
                byte[] Jsnbytes = Encoding.ASCII.GetBytes(responseObj.ToString(formatting: Formatting.None));
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = emsgType.CommandResponse, destinationID = 0, data = Jsnbytes });
                NewOutDataEvent.Set();
            }
        }


        public void Teardown(string reason = "")
        {
            lock (_lock)
            {
                if (BridgeState != eBridgeState.Teardown)
                {
                    if (_ActiveClient != null && _ActiveClient.Connected)
                    {
                        RawSendData(new BinaryWriter(_ActiveClient.GetStream()), emsgType.Meta, "Teardown:" + reason);
                        AddDisplayLogMessage($"Disconnected{(reason.Length > 0 ? $": {reason}" : "")}", Themes.eThemeColour.eWarnStateColour);
                    }
                    else
                        AddDisplayLogMessage($"Connection Disabled{(reason.Length > 0 ? $": {reason}" : "")}", null);

                    Thread.Sleep(250); //give the UI a chance to close the connection gracefully so the right error message appears first. 
                    BridgeState = eBridgeState.Teardown;
                    cancelTokens.Cancel();
                    if (_ActiveClient != null && _ActiveClient.Connected) _ActiveClient.Close();
                    if (_ActiveListener != null) _ActiveListener.Stop();
                }
            }
        }



        void ReceiveIncomingTraffic(TcpClient client)
        {
            Console.WriteLine("ReceiveIncomingTraffic started");
            NetworkStream stream = client.GetStream();
            BinaryReader reader = new BinaryReader(stream);
            while (client.Connected && !cancelTokens.IsCancellationRequested)
            {
                bool success = ReadData(reader, out NETWORK_MSG? newdata);
                if (!success || newdata == null)
                {
                    if (!cancelTokens.IsCancellationRequested)
                        AddDisplayLogMessage("Connection terminated unexpectedly", Themes.eThemeColour.eWarnStateColour);
                    break;
                }
                _registeredIncomingDataCallback(newdata.Value);

            }
            Logging.RecordLogEvent("ReceiveIncomingTraffic ServeClientIncoming dropout", filter: Logging.LogFilterType.TextError);
            Teardown("ReceiveIncomingTraffic dropout");
        }

        void SendOutgoingTraffic(TcpClient client)
        {
            NetworkStream stream = client.GetStream();
            BinaryWriter writer = new BinaryWriter(stream);
            while (client.Connected && !cancelTokens.IsCancellationRequested)
            {
                try
                {
                    bool waitResult = NewOutDataEvent.Wait(-1, cancellationToken: CancelToken);
                }
                catch (System.OperationCanceledException e)
                {
                    break;
                }
                catch (Exception e)
                {
                    AddDisplayLogMessage($"Exception {e.Message}-{e.GetType()} in send outgoing", Themes.eThemeColour.eBadStateColour);
                    break;
                }

                NETWORK_MSG[] items = null;
                lock (_sendQueueLock)
                {
                    items = _OutDataQueue.ToArray();
                    _OutDataQueue.Clear();
                    NewOutDataEvent.Reset();
                }

                foreach (var item in items)
                {
                    if (!RawSendData(writer, item))
                    {
                        Teardown("Send outgoing loop failed");
                        break;
                    }
                }
            }

            Teardown("Send outgoing failed");
        }


        public bool AuthenticateOutgoingConnection(TcpClient client, NetworkStream stream)
        {
            Console.WriteLine($"AuthenticateOutgoingConnection Sending prelude '{(GUIMode ? connectPreludeGUI : connectPreludeHeadless)}'");
            if (!RawSendData(new BinaryWriter(stream), emsgType.Meta, GUIMode ? connectPreludeGUI : connectPreludeHeadless))
            {
                Console.WriteLine($"Failed to send prelude using {client}");
                return false;
            }


            bool success = ReadData(new BinaryReader(stream), out NETWORK_MSG? response) && response != null;
            if (!success || response.Value.data == null || response.Value.msgType != emsgType.Meta) return false;
            string authString;

            try
            {
                authString = ASCIIEncoding.ASCII.GetString(response.Value.data);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Exception {e} parsing auth response", Logging.LogFilterType.TextError);
                return false;
            }
            string expectedConnectResponse = GUIMode ? connectResponseHeadless : connectResponseGUI;

            Console.WriteLine($"AuthenticateOutgoingConnection Comparing response '{response}' to gui:{GUIMode} expected '{expectedConnectResponse}'");
            if (authString == expectedConnectResponse)
            {
                Console.WriteLine($"Auth succeeded");
                return true;
            }
            else
            {
                if (authString == (GUIMode ? connectResponseGUI : connectResponseHeadless) || authString == "Bad Mode")
                {
                    if (GUIMode)
                        AddDisplayLogMessage("GUI<->GUI Connection Unsupported", Themes.eThemeColour.eWarnStateColour);
                    else
                        AddDisplayLogMessage("Cmdline<->Cmdline Connection Unsupported", Themes.eThemeColour.eWarnStateColour);
                    Logging.RecordLogEvent($"Bad prelude response. Connection can only be made between rgat in GUI and command-line modes", Logging.LogFilterType.TextError);
                }
                else
                {
                    Logging.RecordLogEvent($"Authentication failed for {(IPEndPoint)(client.Client.RemoteEndPoint)} - response did not decrypt to the expected value", Logging.LogFilterType.TextError);
                    AddDisplayLogMessage("Authentication failed - Bad Key", Themes.eThemeColour.eAlertWindowBg);
                }
                return false;
            }

        }

        public bool AuthenticateIncomingConnection(TcpClient client, NetworkStream stream)
        {
            NETWORK_MSG? recvd;
            BinaryReader reader = null;
            try
            {
                reader = new BinaryReader(stream);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent("Failed to create reader for stream", Logging.LogFilterType.TextError);
                return false;
            }

            if (!ReadData(reader, out recvd) || recvd == null) return false;
            NETWORK_MSG msg = recvd.Value;
            string authString = ASCIIEncoding.ASCII.GetString(recvd.Value.data);

            if (recvd == null || msg.msgType != emsgType.Meta || msg.data.Length == 0)
            {
                AddDisplayLogMessage("Authentication failed - no vald data", Themes.eThemeColour.eBadStateColour);
                Console.WriteLine($"AuthenticateIncomingConnection No prelude from {client}, ignoring");
                Logging.RecordLogEvent($"No prelude from {client}, ignoring", Logging.LogFilterType.TextDebug);
                return false;
            }

            string connectPrelude = GUIMode ? connectPreludeHeadless : connectPreludeGUI;
            if (authString == connectPrelude && RawSendData(new BinaryWriter(stream), emsgType.Meta, GUIMode ? connectResponseGUI : connectResponseHeadless))
            {
                Console.WriteLine($"Auth succeeded");
                return true;
            }
            else
            {
                if (authString == (GUIMode ? connectPreludeGUI : connectPreludeHeadless))
                {
                    if (GUIMode)
                        AddDisplayLogMessage("GUI<->GUI Connection Unsupported", Themes.eThemeColour.eWarnStateColour);
                    else
                        AddDisplayLogMessage("Cmdline<->Cmdline Connection Unsupported", Themes.eThemeColour.eWarnStateColour);
                    Logging.RecordLogEvent($"Connection refused - Connection can only be made between rgat in GUI and command-line modes", Logging.LogFilterType.TextError);
                    RawSendData(new BinaryWriter(stream), emsgType.Meta, "Bad Mode");
                }
                else
                {
                    AddDisplayLogMessage("Authentication failed - Bad Key", Themes.eThemeColour.eAlertWindowBg);
                    Logging.RecordLogEvent($"Authentication failed for {(IPEndPoint)(client.Client.RemoteEndPoint)} - prelude did not decrypt to the expected value", Logging.LogFilterType.TextError);
                }
                return false;
            }

        }

        Queue<byte[]> _incomingData = new Queue<byte[]>();

        readonly object _lock = new object();

        ManualResetEventSlim NewDataEvent = new ManualResetEventSlim(false);


        bool ReadData(BinaryReader reader, out NETWORK_MSG? data)
        {
            try
            {
                emsgType msgType = (emsgType)reader.ReadByte();
                uint destination = reader.ReadUInt32();
                int count = reader.ReadInt32();
                data = new NETWORK_MSG() { msgType = msgType, destinationID = destination, data = reader.ReadBytes(count) };
                return true;
            }
            catch (System.IO.IOException IOExcep)
            {
                data = null;
                if (cancelTokens.IsCancellationRequested) return false;
                if (IOExcep.InnerException != null && IOExcep.InnerException.GetType() == typeof(SocketException))
                {
                    if (cancelTokens.IsCancellationRequested) return false;
                    SocketException innerE = (SocketException)IOExcep.InnerException;
                    switch (innerE.SocketErrorCode)
                    {
                        case SocketError.ConnectionReset:
                            AddDisplayLogMessage($"Receive Failed: The connection was reset ({innerE.ErrorCode})", Themes.eThemeColour.eWarnStateColour);
                            break;
                        default:
                            AddDisplayLogMessage($"Receive Failed: {innerE.SocketErrorCode} ({innerE.ErrorCode})", Themes.eThemeColour.eWarnStateColour);
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("Readddata io excep");
                    AddDisplayLogMessage($"Receive Failed: {IOExcep.Message}", Themes.eThemeColour.eWarnStateColour);
                }
            }
            catch (Exception e)
            {
                data = null;
                if (cancelTokens.IsCancellationRequested) return false;
                Console.WriteLine($"ReadData Exception {e}, {e.GetType()}");
            }
            Teardown("Read failed");
            data = null;
            return false;
        }



        bool RawSendData(BinaryWriter writer, emsgType msgtype, string textdata)
        {
            return RawSendData(writer, new NETWORK_MSG() { msgType = msgtype, destinationID = 0, data = Encoding.ASCII.GetBytes(textdata) });
        }

        bool RawSendData(BinaryWriter writer, NETWORK_MSG msg)
        {
            Task write = null;
            try
            {
                writer.Write((byte)msg.msgType);
                writer.Write(msg.destinationID);
                writer.Write(msg.data.Length);
                writer.Write(msg.data);
                return !cancelTokens.IsCancellationRequested;
            }
            catch (System.IO.IOException e)
            {
                Logging.RecordLogEvent($"\t! IO exception reading from client\n {e.InnerException}\n {e.Message}", Logging.LogFilterType.TextError);
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Exception during send: {e.Message}", Logging.LogFilterType.TextError);
                if (write != null && write.IsCanceled)
                {
                    Console.WriteLine("Cancellation during send data");
                }
                else
                {
                    if (write.Status == TaskStatus.Faulted)
                    {
                        switch (write.Exception.InnerException)
                        {
                            case SocketException sockExcep:
                                {
                                    AddDisplayLogMessage($"Send Failed: {sockExcep.SocketErrorCode}", Themes.eThemeColour.eWarnStateColour);
                                    break;
                                }
                            default:
                                break;
                        }
                    }
                }
            }
            Teardown("Send failed");
            return false;
        }

    }
}
