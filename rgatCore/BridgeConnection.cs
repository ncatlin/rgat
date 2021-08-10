﻿using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
        public enum emsgType { Meta, Command, Response, Data };

        public delegate void OnGotDataCallback(Tuple<emsgType, string> data);
        public delegate void OnConnectSuccessCallback();

        public bool Connected => BridgeState == eBridgeState.Connected;
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

        Queue<Tuple<emsgType, string>> _OutDataQueue = new Queue<Tuple<emsgType, string>>();
        ManualResetEventSlim NewOutDataEvent = new ManualResetEventSlim(false);

        CancellationTokenSource cancelTokens;
        CancellationToken CancelToken => cancelTokens.Token;
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
            Teardown();
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
                    ServeAuthenticatedConnection(_ActiveClient, connectCallback);
                }
                else
                {
                    Teardown();
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


        public void SendOutgoingData(Tuple<emsgType, string> data)
        {
            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(data);
                NewOutDataEvent.Set();
            }
        }

        public void SendCommand(string text)
        {
            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(new Tuple<emsgType, string>(emsgType.Command, text));
                NewOutDataEvent.Set();
            }
        }

        //https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2328
        Newtonsoft.Json.JsonSerializer serialiserIn = Newtonsoft.Json.JsonSerializer.Create(new JsonSerializerSettings()
        {
            TypeNameHandling = TypeNameHandling.None,
        }); 
        Newtonsoft.Json.JsonSerializer serialiserOut = Newtonsoft.Json.JsonSerializer.Create(new JsonSerializerSettings()
        {
            TypeNameHandling = TypeNameHandling.None,
        });


        public void SendResponse(string command, object response)
        {
            lock (_sendQueueLock)
            {
                StringBuilder sb = new StringBuilder();
                StringWriter sw = new StringWriter(sb);
                JsonWriter writer = new JsonTextWriter(sw);

                serialiserOut.Serialize(writer, response);
                JObject responseObj = new JObject() { new JProperty("Command", command), new JProperty("Response", sb.ToString()) };
                
                _OutDataQueue.Enqueue(new Tuple<emsgType, string>(emsgType.Response, responseObj.ToString()));
                NewOutDataEvent.Set();
            }
        }


        public void Teardown()
        {
            if (BridgeState != eBridgeState.Teardown)
            {
                if (Connected)
                    AddDisplayLogMessage("Disconnected", null);
                else
                    AddDisplayLogMessage("Connection Disabled", null);

                BridgeState = eBridgeState.Teardown;
                cancelTokens.Cancel();
                if (_ActiveClient != null && _ActiveClient.Connected) _ActiveClient.Close();
                if (_ActiveListener != null) _ActiveListener.Stop();
            }
        }



        void ReceiveIncomingTraffic(TcpClient client)
        {
            Console.WriteLine("ReceiveIncomingTraffic started");
            NetworkStream stream = client.GetStream();
            BinaryReader reader = new BinaryReader(stream);
            while (client.Connected && !cancelTokens.IsCancellationRequested)
            {
                bool success = ReadData(reader, out Tuple<emsgType, string> newdata);
                if (!success || newdata == null)
                {
                    if (!cancelTokens.IsCancellationRequested)
                        AddDisplayLogMessage("Connection terminated unexpectedly", Themes.eThemeColour.eWarnStateColour);
                    break;
                }
                _registeredIncomingDataCallback(newdata);

            }
            Console.WriteLine("ReceiveIncomingTraffic ServeClientIncoming dropout");
            Teardown();
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

                Tuple<emsgType, string>[] items = null;
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
                        Teardown();
                        break;
                    }
                }
            }

            Teardown();
        }


        public bool AuthenticateOutgoingConnection(TcpClient client, NetworkStream stream)
        {
            Console.WriteLine($"AuthenticateOutgoingConnection Sending prelude '{(GUIMode ? connectPreludeGUI : connectPreludeHeadless)}'");
            if (!RawSendData(new BinaryWriter(stream), new Tuple<emsgType, string>(emsgType.Meta, GUIMode ? connectPreludeGUI : connectPreludeHeadless)))
            {
                Console.WriteLine($"Failed to send prelude using {client}");
                return false;
            }


            bool success = ReadData(new BinaryReader(stream), out Tuple<emsgType, string> response);
            if (!success || response.Item2 == null || response.Item1 != emsgType.Meta) return false;

            string expectedConnectResponse = GUIMode ? connectResponseHeadless : connectResponseGUI;

            Console.WriteLine($"AuthenticateOutgoingConnection Comparing response '{response}' to gui:{GUIMode} expected '{expectedConnectResponse}'");
            if (response.Item2 == expectedConnectResponse)
            {
                Console.WriteLine($"Auth succeeded");
                return true;
            }
            else
            {
                if (response.Item2 == (GUIMode ? connectResponseGUI : connectResponseHeadless) || response.Item2 == "Bad Mode")
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


            Tuple<emsgType, string> recvd;
            while (!ReadData(new BinaryReader(stream), out recvd))
            {
                continue;
            }

            if (recvd == null) return false;

            if (recvd == null || recvd.Item1 != emsgType.Meta || recvd.Item2.Length == 0)
            {
                AddDisplayLogMessage("Authentication failed - no vald data", Themes.eThemeColour.eBadStateColour);
                Console.WriteLine($"AuthenticateIncomingConnection No prelude from {client}, ignoring");
                Logging.RecordLogEvent($"No prelude from {client}, ignoring", Logging.LogFilterType.TextDebug);
                return false;
            }

            string connectPrelude = GUIMode ? connectPreludeHeadless : connectPreludeGUI;
            if (recvd.Item2 == connectPrelude && RawSendData(new BinaryWriter(stream), new Tuple<emsgType, string>(emsgType.Meta, GUIMode ? connectResponseGUI : connectResponseHeadless)))
            {
                Console.WriteLine($"Auth succeeded");
                return true;
            }
            else
            {
                if (recvd.Item2 == (GUIMode ? connectPreludeGUI : connectPreludeHeadless))
                {
                    if (GUIMode)
                        AddDisplayLogMessage("GUI<->GUI Connection Unsupported", Themes.eThemeColour.eWarnStateColour);
                    else
                        AddDisplayLogMessage("Cmdline<->Cmdline Connection Unsupported", Themes.eThemeColour.eWarnStateColour);
                    Logging.RecordLogEvent($"Connection refused - Connection can only be made between rgat in GUI and command-line modes", Logging.LogFilterType.TextError);
                    RawSendData(new BinaryWriter(stream), new Tuple<emsgType, string>(emsgType.Meta, "Bad Mode"));
                }
                else
                {
                    AddDisplayLogMessage("Authentication failed - Bad Key", Themes.eThemeColour.eAlertWindowBg);
                    Logging.RecordLogEvent($"Authentication failed for {(IPEndPoint)(client.Client.RemoteEndPoint)} - prelude did not decrypt to the expected value", Logging.LogFilterType.TextError);
                }
                return false;
            }

        }


        int fragmentIndex = -1;
        byte[] assembledMessage;

        Queue<byte[]> _incomingData = new Queue<byte[]>();

        readonly object _lock = new object();

        ManualResetEventSlim NewDataEvent = new ManualResetEventSlim(false);


        bool ReadData(BinaryReader reader, out Tuple<emsgType, string> data)
        {
            try
            {
                emsgType msgType = (emsgType)reader.ReadByte();
                data = new Tuple<emsgType, string>(msgType, reader.ReadString());
                return true;
            }
            catch (System.IO.IOException IOExcep)
            {
                data = null;
                if (cancelTokens.IsCancellationRequested) return false;
                if (IOExcep.InnerException != null && IOExcep.InnerException.GetType() == typeof(SocketException))
                {
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
                    AddDisplayLogMessage($"Receive Failed: {IOExcep.Message}", Themes.eThemeColour.eWarnStateColour);
                }
            }
            catch (Exception e)
            {
                data = null;
                if (cancelTokens.IsCancellationRequested) return false;
                Console.WriteLine($"ReadData Exception {e}, {e.GetType()}");
                /*
                Logging.RecordLogEvent($"Exception during receive: {e.Message}");
                if (read != null && read.IsCanceled)
                {
                    Console.WriteLine("Cancellation during read of incoming data");
                }
                else
                {
                    if (read.Status == TaskStatus.Faulted && !cancelTokens.IsCancellationRequested)
                    {
                        switch (read.Exception.InnerException)
                        {
                            case SocketException sockExcep:
                                {
                                    AddDisplayLogMessage($"Receive Failed: {sockExcep.SocketErrorCode}", Themes.eThemeColour.eWarnStateColour);
                                    break;
                                }
                            case System.IO.IOException IOExcep:
                                {
                                    if (IOExcep.InnerException.GetType() == typeof(SocketException))
                                    {
                                        SocketException innerE = (SocketException)IOExcep.InnerException;
                                        AddDisplayLogMessage($"Receive Failed: {innerE.SocketErrorCode}", Themes.eThemeColour.eWarnStateColour);
                                    }
                                    else
                                    {
                                        AddDisplayLogMessage($"Receive Failed: {IOExcep.Message}", Themes.eThemeColour.eWarnStateColour);
                                    }
                                    break;
                                }
                            default:
                                AddDisplayLogMessage($"Receive Failure", Themes.eThemeColour.eWarnStateColour);
                                break;
                        }
                    }
                }
                */
            }
            Teardown();
            data = null;
            return false;
        }



        bool RawSendData(BinaryWriter writer, Tuple<emsgType, string> data)
        {
            Task write = null;
            try
            {
                writer.Write((byte)data.Item1);
                writer.Write(data.Item2);
                writer.Flush();
                return !cancelTokens.IsCancellationRequested;
            }
            catch (System.IO.IOException e)
            {
                Console.WriteLine($"\t! IO exception reading from client");
                Console.WriteLine($"\t! {e.InnerException}");
                Console.WriteLine($"\t! {e.Message}");
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Exception during send: {e.Message}");
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
            Teardown();
            return false;
        }

    }
}
