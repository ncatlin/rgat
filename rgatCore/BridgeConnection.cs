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
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgat
{
    /// <summary>
    /// Manages the remote tracing connection to another rgat instance
    /// </summary>
    public class BridgeConnection
    {


        private readonly object _lock = new object();

        /// <summary>
        /// A handler for a network message
        /// </summary>
        /// <param name="data">Decrypted data from the network</param>
        public delegate void OnGotDataCallback(NETWORK_MSG data);
        /// <summary>
        /// An event called when a connection is established
        /// </summary>
        public delegate void OnConnectSuccessCallback();

        /// <summary>
        /// Is there an established connection
        /// </summary>
        public bool Connected => ConnectionState == BridgeState.Connected;

        /// <summary>
        /// The most recently connected host
        /// </summary>
        public string LastAddress { get; private set; } = "";

        /// <summary>
        /// Are we either listening, connecting or connected
        /// </summary>
        public bool ActiveNetworking => ConnectionState == BridgeState.Connected || ConnectionState == BridgeState.Listening || ConnectionState == BridgeState.Connecting;


        /// <summary>
        /// The state of the connection
        /// </summary>
        public BridgeState ConnectionState
        {
            get => _bridgeState;
            private set
            {
                _bridgeState = value;
            }
        }

        private BridgeState _bridgeState = BridgeState.Inactive;

        //nacl.core doesn't mention thread safety anywhere so have one for each direction
        private NetworkStream? _networkStream;
        private NaCl.Core.ChaCha20Poly1305? _encryptor;
        private BinaryWriter? _writer;
        private NaCl.Core.ChaCha20Poly1305? _decryptor;
        private BinaryReader? _reader;
        private BigInteger _sendIV;
        private readonly object _messagesLock = new object();
        private List<Tuple<string, Themes.eThemeColour?>> _displayLogMessages = new List<Tuple<string, Themes.eThemeColour?>>();

        public string ConnectedHostID { get; private set; } = "";
        public void SetConnectedHostID(string ID) => ConnectedHostID = ID; 

        /// <summary>
        /// Whether this instance is the GUI.
        /// The GUI sends tracing commands and recieves trace data and associated metadata (available files to execute, signature hits, etc)
        /// It does not do the opposite. Ever.
        /// This state must be set at startup and cannot be changed
        /// </summary>
        public bool GUIMode
        {
            get => _guiMode;
            set
            {
                if (_inited)
                {
                    throw new InvalidOperationException("Cant change mode of the network bridge");
                }

                _inited = true;
                _guiMode = value;
            }
        }

        private bool _guiMode = true;

        /// <summary>
        /// Is rgat running in non-GUI mode
        /// </summary>
        public bool HeadlessMode => !GUIMode;

        /// <summary>
        /// A network message
        /// </summary>
        public struct NETWORK_MSG
        {
            /// <summary>
            /// The message type
            /// </summary>
            public MsgType msgType;
            /// <summary>
            /// The intended recipient of the message
            /// </summary>
            public uint destinationID;
            /// <summary>
            /// The content of the message
            /// </summary>
            public byte[] data;
        }

        private readonly Queue<NETWORK_MSG> _OutDataQueue = new Queue<NETWORK_MSG>();
        private readonly ManualResetEventSlim NewOutDataEvent = new ManualResetEventSlim(false);
        private CancellationTokenSource cancelTokens = new CancellationTokenSource();

        /// <summary>
        /// Get a cancellation token. This will be cancelled if the connection is torn down
        /// All blocking operations should respect it
        /// </summary>
        public CancellationToken CancelToken => cancelTokens.Token;

        private readonly object _sendQueueLock = new object();
        private TcpClient? _ActiveClient;
        private TcpListener? _ActiveListener;
        private OnGotDataCallback? _registeredIncomingDataCallback;
        /// <summary>
        /// An IPEndPoint for the host we are connected to
        /// </summary>
        public IPEndPoint? RemoteEndPoint;
        private const string connectPreludeGUI = "rgat connect GUI prelude";
        private const string connectPreludeHeadless = "rgat connect headless prelude";
        private const string connectResponseGUI = "rgat accept GUI prelude";
        private const string connectResponseHeadless = "rgat accept headless prelude";
        private bool _inited = false;

        /// <summary>
        /// Initiate a bridge connection in remote mode
        /// This will be complete when it connects to another rgat instance with the right network key
        /// </summary>
        /// <param name="localBindAddress">The local ip address to connect from</param>
        /// <param name="remoteConnectAddress">The remote ip address or domain to connect to</param>
        /// <param name="remoteConnectPort">The remote TCP port to connect to</param>
        /// <param name="datacallback">The event for data being received</param>
        /// <param name="connectCallback">The main connection handler which will serve the connection</param>
        /// <returns></returns>
        public void Start(IPAddress localBindAddress, string remoteConnectAddress, int remoteConnectPort, OnGotDataCallback datacallback, BridgeConnection.OnConnectSuccessCallback connectCallback)
        {
            Reset();
            ConnectionState = BridgeState.Connecting;
            _ActiveClient = new TcpClient(new IPEndPoint(localBindAddress, 0));
            _registeredIncomingDataCallback = datacallback;
            Task.Run(() => StartConnectOut(_ActiveClient, remoteConnectAddress, remoteConnectPort, connectCallback));
        }


        /// <summary>
        /// Establish a connection to a listening rgat instance
        /// </summary>
        /// <param name="client">The TcpClient object for the connection</param>
        /// <param name="remoteConnectAddress">Host address of the remote party</param>
        /// <param name="remoteConnectPort">Port the remote party is listening on</param>
        /// <param name="connectCallback">The main connection handler which will serve the connection</param>
        private void StartConnectOut(TcpClient client, string remoteConnectAddress, int remoteConnectPort, BridgeConnection.OnConnectSuccessCallback connectCallback)
        {
            Task connect;
            try
            {
                AddNetworkDisplayLogMessage($"Connecting from {((IPEndPoint)client.Client.LocalEndPoint!).Address} to {remoteConnectAddress}:{remoteConnectPort}", null);

                connect = client.ConnectAsync(remoteConnectAddress, remoteConnectPort);
                Task.WaitAny(new Task[] { connect }, CancelToken);

            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode == SocketError.AddressNotAvailable)
                {
                    AddNetworkDisplayLogMessage($"Remote Address unavailable. Wrong interface?", Themes.eThemeColour.WarnStateColour);
                }
                else
                {
                    AddNetworkDisplayLogMessage($"Connection Failed: {e.SocketErrorCode}", Themes.eThemeColour.WarnStateColour);
                }
                Teardown();
                return;
            }
            catch (OperationCanceledException)
            {
                Logging.RecordLogEvent($"User cancelled connection attempt", Logging.LogFilterType.Debug);
                Teardown();
                return;
            }
            catch (Exception e)
            {
                Logging.RecordException($"Exception {e} in StartConnectOut", e);
                Teardown();
                return;
            }

            if (client.Connected)
            {
                AddNetworkDisplayLogMessage($"Connected to {remoteConnectAddress}:{remoteConnectPort}", null);

                if (!TryCreateCryptoStream(client, isServer: false))
                {
                    Teardown();
                    return;
                }

                if (AuthenticateOutgoingConnection(client))
                {
                    AddNetworkDisplayLogMessage($"Authenticated to {remoteConnectAddress}:{remoteConnectPort}", Themes.eThemeColour.GoodStateColour);
                    ServeAuthenticatedConnection(connectCallback);
                    return;
                }
            }
            else
            {
                if (connect.Status == TaskStatus.Faulted && connect.Exception is not null)
                {
                    switch (connect.Exception.InnerException)
                    {
                        case SocketException sockExcep:
                            {
                                AddNetworkDisplayLogMessage($"Connection Failed: {sockExcep.SocketErrorCode}", Themes.eThemeColour.WarnStateColour);
                                break;
                            }
                        default:
                            AddNetworkDisplayLogMessage($"Connection Failed (Fault)", Themes.eThemeColour.WarnStateColour);
                            break;
                    }
                }
                else
                {
                    AddNetworkDisplayLogMessage($"Connection Failed (NoFault)", Themes.eThemeColour.WarnStateColour);
                }
            }
            Teardown("Connect Mode Finished");
        }




        /// <summary>
        /// A task that exchanges and verifies the initial handshake messages
        /// </summary>
        /// <param name="isServer">true if the other party initiated the connection, false if we did</param>
        /// <returns>true if the handshake succeeded and both parties have the same key</returns>
        private bool AuthenticateConnectionTask(bool isServer)
        {
            try
            {
                Random rnd = new Random();
                byte[] IV = new byte[12];
                rnd.NextBytes(IV);
                _sendIV = new BigInteger(IV);

                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(GlobalConfig.StartOptions.NetworkKey, Encoding.ASCII.GetBytes("rgat nwk key salt"));

                byte[] keybytes = key.GetBytes(32);

                byte[] buf = Encoding.ASCII.GetBytes(isServer ? "rgat_server" : "rgat_client");
                byte[] tag = new byte[16];
                _encryptor = new NaCl.Core.ChaCha20Poly1305(keybytes);
                _decryptor = new NaCl.Core.ChaCha20Poly1305(keybytes);
                _encryptor.Encrypt(IV, buf, buf, tag);

                _writer!.Write(IV);
                _writer.Write(tag);
                _writer.Write((ushort)buf.Length);
                _writer.Write(buf);

                string expectedPT = isServer ? "rgat_client" : "rgat_server";

                _reader!.Read(IV, 0, 12);
                _reader.Read(tag, 0, 16);
                ushort ctsize = _reader.ReadUInt16();
                buf = _reader.ReadBytes(ctsize);

                try
                {
                    _decryptor.Decrypt(IV, buf, tag, buf);
                }
                catch (CryptographicException)
                {
                    AddNetworkDisplayLogMessage("Bad network key", Themes.eThemeColour.BadStateColour);
                    return false;
                }

                return ASCIIEncoding.ASCII.GetString(buf) == expectedPT;
            }
            catch (Exception e)
            {
                Logging.RecordException($"Failed to authenticate connection: {e.Message}", e);
                AddNetworkDisplayLogMessage("Authentication Error", Themes.eThemeColour.BadStateColour);
                return false;
            }
        }


        /// <summary>
        /// Ensure the other end of the connection knows our key
        /// </summary>
        /// <param name="client">The TcpClient for the connection</param>
        /// <param name="isServer">true if the other party initiated the connection, false if we did</param>
        /// <returns></returns>
        private bool TryCreateCryptoStream(TcpClient client, bool isServer)
        {

            try
            {
                _networkStream = client.GetStream();
                _reader = new BinaryReader(_networkStream);
                _writer = new BinaryWriter(_networkStream);
                Task<bool> authenticate = Task<bool>.Run(() => AuthenticateConnectionTask(isServer));
                Task.WaitAny(new Task[] { authenticate }, 2500, CancelToken); //wait on delay because a bad size field will hang the read() operation
                return authenticate.IsCompleted && authenticate.Result is true;
            }
            catch (Exception e)
            {
                AddNetworkDisplayLogMessage($"Failed to authenticate connection: {e}", Themes.eThemeColour.BadStateColour);
                Logging.RecordException($"Failed to authenticate connection: {e}", e);
            }
            return false;
        }

        private readonly byte[] _readIV = new byte[12];
        private readonly byte[] _readTag = new byte[16];

        /// <summary>
        /// Read the next message from the conencted party
        /// </summary>
        /// <param name="data">A NETWORK_MSG object</param>
        /// <returns>If successful</returns>
        private bool ReadData(out NETWORK_MSG? data)
        {
            try
            {
                _reader!.Read(_readIV, 0, 12);
                _reader.Read(_readTag, 0, 16);
                int ctsize = _reader.ReadInt32();
                byte[] buf = _reader.ReadBytes(ctsize);

                try
                {
                    _decryptor!.Decrypt(_readIV, buf, _readTag, buf);
                }
                catch (CryptographicException e)
                {
                    Logging.RecordError($"Network decryption failed ({e.Message})");
                    Teardown();
                    data = null;
                    return false;
                }

                using (var plaintextStream = new MemoryStream(buf))
                {
                    using var plaintextReader = new BinaryReader(plaintextStream);
                    MsgType msgType = (MsgType)plaintextReader.ReadByte();
                    uint destination = plaintextReader.ReadUInt32();
                    int count = plaintextReader.ReadInt32();
                    data = new NETWORK_MSG() { msgType = msgType, destinationID = destination, data = plaintextReader.ReadBytes(count) };
                }
                return true;
            }
            catch (System.IO.IOException IOExcep)
            {
                data = null;
                if (cancelTokens.IsCancellationRequested || rgatState.rgatIsExiting)
                {
                    return false;
                }

                if (IOExcep.InnerException != null && IOExcep.InnerException.GetType() == typeof(SocketException))
                {
                    if (cancelTokens.IsCancellationRequested)
                    {
                        return false;
                    }

                    SocketException innerE = (SocketException)IOExcep.InnerException;
                    switch (innerE.SocketErrorCode)
                    {
                        case SocketError.ConnectionReset:
                            AddNetworkDisplayLogMessage($"Receive Failed: The connection was reset ({innerE.ErrorCode})", Themes.eThemeColour.WarnStateColour);
                            break;
                        default:
                            AddNetworkDisplayLogMessage($"Receive Failed: {innerE.SocketErrorCode} ({innerE.ErrorCode})", Themes.eThemeColour.WarnStateColour);
                            break;
                    }
                }
                else
                {
                    if (rgatState.rgatIsExiting is false)
                    {
                        Logging.RecordError($"Receive Failed: {IOExcep.Message}");
                        AddNetworkDisplayLogMessage($"Receive Failed: {IOExcep.Message}", Themes.eThemeColour.WarnStateColour);
                    }
                }
            }
            catch (Exception e)
            {
                data = null;
                if (cancelTokens.IsCancellationRequested)
                {
                    return false;
                }

                Logging.RecordException($"ReadData Exception: {e.Message}", e);
            }
            Teardown("Read failed");
            data = null;
            return false;
        }


        /// <summary>
        /// Encrypt and send a message to the connected party
        /// </summary>
        /// <param name="msgtype">Message Type</param>
        /// <param name="textdata">Message string</param>
        /// <returns>If successful</returns>
        private bool RawSendData(MsgType msgtype, string textdata)
        {
            return RawSendData(new NETWORK_MSG() { msgType = msgtype, destinationID = 0, data = Encoding.ASCII.GetBytes(textdata) });
        }


        /// <summary>
        /// Encrypt and send a message to the connected party
        /// </summary>
        /// <param name="msg">A NETWORK_MSG object containing the message</param>
        /// <returns>If successful</returns>
        private bool RawSendData(NETWORK_MSG msg)
        {
            Task? write = null;
            try
            {
                Span<byte> plaintext;
                using (var msgBufStream = new MemoryStream())
                {
                    using var msgBufWriter = new BinaryWriter(msgBufStream);
                    msgBufWriter.Write((byte)msg.msgType);
                    msgBufWriter.Write(msg.destinationID);
                    msgBufWriter.Write(msg.data.Length);
                    msgBufWriter.Write(msg.data);
                    plaintext = msgBufStream.ToArray();
                }

                _sendIV += 1;
                Span<byte> IV = _sendIV.ToByteArray();
                _encryptor!.Encrypt(IV, plaintext, plaintext, _sendTag);

                _writer!.Write(IV);
                _writer.Write(_sendTag);
                _writer.Write(plaintext.Length);
                _writer.Write(plaintext);

                return !cancelTokens.IsCancellationRequested;
            }
            catch (System.IO.IOException e)
            {
                Logging.RecordLogEvent($"\t! IO exception reading from client\n {e.InnerException}\n {e.Message}", Logging.LogFilterType.Error);
            }
            catch (Exception e)
            {
                Logging.RecordException($"Exception during send: {e.Message}", e);
                if (write != null && write.IsCanceled)
                {
                    Logging.WriteConsole("Cancellation during send data");
                }
                else
                {
                    if (write is not null && write.Status == TaskStatus.Faulted && write.Exception is not null)
                    {
                        switch (write.Exception.InnerException)
                        {
                            case SocketException sockExcep:
                                {
                                    AddNetworkDisplayLogMessage($"Send Failed: {sockExcep.SocketErrorCode}", Themes.eThemeColour.WarnStateColour);
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

        private readonly byte[] _sendTag = new byte[16];

        /// <summary>
        /// Add a message to the remote tracing dialog log panel
        /// </summary>
        /// <param name="msg">Text of the message to add</param>
        /// <param name="colour">Colour of the message, or null for default</param>
        public void AddNetworkDisplayLogMessage(string msg, Themes.eThemeColour? colour)
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
                Logging.WriteConsole(msg);
            }
        }

        /// <summary>
        /// Get recent connection event messages
        /// </summary>
        /// <returns>List of messages and their colours</returns>
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
        /// <param name="dataCallback">Event called when data is received</param>
        /// <param name="connectCallback">Event called when the connection is established</param>
        /// <returns></returns>
        public Task? Start(IPAddress localBindAddress, int localBindPort, OnGotDataCallback dataCallback, OnConnectSuccessCallback connectCallback)
        {
            Reset();

            try
            {
                _ActiveListener = new TcpListener(localBindAddress, localBindPort)
                {
                    ExclusiveAddressUse = true
                };
                _ActiveListener.Start();
                ConnectionState = BridgeState.Listening;
            }
            catch (SocketException e)
            {
                AddNetworkDisplayLogMessage($"Listen Failed: {e.SocketErrorCode}", Themes.eThemeColour.WarnStateColour);
                Teardown();

            }
            catch (Exception e)
            {
                AddNetworkDisplayLogMessage($"Listen Failed: {e.Message}", Themes.eThemeColour.WarnStateColour);
                Teardown();
            }

            if (ConnectionState is BridgeState.Listening)
            {
                _registeredIncomingDataCallback = dataCallback;
                return Task.Run(() => StartListenForConnection(_ActiveListener!, connectCallback));
            }
            else
            {
                return null;
            }
        }

        private void StartListenForConnection(TcpListener listener, OnConnectSuccessCallback connectCallback)
        {
            if (ConnectionState is not BridgeState.Listening)
            {
                return;
            }

            IPEndPoint listenerEndpoint = (IPEndPoint)listener.LocalEndpoint;
            AddNetworkDisplayLogMessage($"Listening on {listenerEndpoint.Address}:{listenerEndpoint.Port}", null);
            try
            {
                _ActiveClient = listener.AcceptTcpClient();
            }
            catch (SocketException e)
            {
                if (!cancelTokens.IsCancellationRequested)
                {
                    AddNetworkDisplayLogMessage($"Failed Accept: {e.SocketErrorCode}", Themes.eThemeColour.WarnStateColour);
                }
                Teardown();
                return;
            }
            catch (Exception e)
            {
                Logging.RecordException($"Exception '{e.Message}' in StartConnectOut", e);
                Teardown();
                return;
            }


            TcpClient? client = _ActiveClient;
            if (client != null && client.Connected)
            {

                IPEndPoint? clientEndpoint = (IPEndPoint?)client.Client?.RemoteEndPoint;
                AddNetworkDisplayLogMessage($"Incoming connection from {clientEndpoint}", null);

                if (!TryCreateCryptoStream(client, isServer: true))
                {
                    Teardown();
                    return;
                }

                if (AuthenticateIncomingConnection(client))
                {
                    AddNetworkDisplayLogMessage("Connected to rgat", Themes.eThemeColour.GoodStateColour);
                    Logging.RecordLogEvent($"New connection from {clientEndpoint}", Logging.LogFilterType.Alert);
                    ServeAuthenticatedConnection(connectCallback);
                }
                else
                {
                    Teardown();
                    Logging.RecordLogEvent($"Failed connection from {clientEndpoint}", Logging.LogFilterType.Alert);
                    _ActiveClient = null;
                    return;
                }
            }
            else
            {
                Teardown();
                Logging.WriteConsole($"StartListenForConnection not connected");
            }
        }

        /// <summary>
        /// Reset the connection state
        /// </summary>
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

        private void ServeAuthenticatedConnection(OnConnectSuccessCallback connectedCallback)
        {
            if (_ActiveClient is null || _ActiveClient.Client.RemoteEndPoint is null)
            {
                Teardown();
                Logging.RecordError($"ServeAuthenticatedConnection got null remote endpoint");
                return;
            }

            RemoteEndPoint = (IPEndPoint)_ActiveClient.Client.RemoteEndPoint;
            LastAddress = RemoteEndPoint.Address.ToString();
            ConnectionState = BridgeState.Connected;
            Logging.WriteConsole("Invoking connected callback");
            Task.Run(() => connectedCallback());
            StartConnectionDataHandlers();
        }

        private void StartConnectionDataHandlers()
        {
            if (_ActiveClient is not null)
            {
                Logging.WriteConsole($"Client {_ActiveClient.Client.RemoteEndPoint} authenticated, serving...");
            }
            Task reader = Task.Run(() => ReceiveIncomingTraffic());
            Task sender = Task.Run(() => SendOutgoingTraffic());
        }

        private static int commandCount = 0;
        /// <summary>
        /// Send a command to the remote instance of rgat (which is in commandline tracing mode)
        /// The handling of the response (a JToken) depends on the arguments
        ///     If a callback is specified, it will be executed with the response as a parameter
        ///     Otherwise it will be stored for the requestor to pick up later
        /// </summary>
        /// <param name="command">The task to perform</param>
        /// <param name="recipientID">The intended recipient of the task, eg a certain file picker requested the directory they are in</param>
        /// <param name="callback">A callback to be performed with the response</param>
        /// <param name="param">Optional parameters JSON for the command</param>
        public int SendCommand(string command, string? recipientID, RemoteDataMirror.ProcessResponseCallback? callback, JToken? param = null)
        {
            lock (_sendQueueLock)
            {
                commandCount += 1;

                JObject item = new JObject
                {
                    { "Name", command },
                    { "CmdID", commandCount }
                };
                if (param != null)
                {
                    item.Add("Paramfield", param);
                }

                if (callback != null)
                {
                    Debug.Assert(recipientID != null);
                    RemoteDataMirror.RegisterPendingResponse(commandCount, command, recipientID, callback);
                }
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = MsgType.Command, destinationID = 0, data = Encoding.ASCII.GetBytes(item.ToString()) });
                NewOutDataEvent.Set();
                return commandCount;
            }
        }


        /// <summary>
        /// Send a trace command to the headless tracing instance
        /// </summary>
        /// <param name="pipe">The remote pipe reference</param>
        /// <param name="message">Command to send</param>
        public void SendTraceCommand(uint pipe, string message)
        {
            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = MsgType.TraceCommand, destinationID = pipe, data = Encoding.ASCII.GetBytes(message) });
                NewOutDataEvent.Set();
            }
        }


        /// <summary>
        /// Send a log entry to the GUI
        /// </summary>
        /// <param name="message">Message to send</param>
        /// <param name="msgType">Message type</param>
        public void SendLog(string message, Logging.LogFilterType msgType)
        {
            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = MsgType.Log, destinationID = (uint)msgType, data = Encoding.ASCII.GetBytes(message) });
                NewOutDataEvent.Set();
            }

        }


        /// <summary>
        /// Sends trace data to be processed by the GUI
        /// </summary>
        /// <param name="pipeID">The worker pipe reference</param>
        /// <param name="buf">Data to send</param>
        /// <param name="bufSize">Data size</param>
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
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = MsgType.TraceData, destinationID = pipeID, data = data });
                NewOutDataEvent.Set();
            }
        }


        /// <summary>
        /// Send trace metadata to the GUI
        /// </summary>
        /// <param name="trace">The tracerecord the metadata applies to</param>
        /// <param name="info">The data</param>
        public void SendTraceMeta(TraceRecord trace, string info)
        {
            Debug.Assert(rgatState.ConnectedToRemote && rgatState.NetworkBridge.HeadlessMode);
            lock (_sendQueueLock)
            {
                byte[] Jsnbytes = Encoding.ASCII.GetBytes($"{trace.Target.GetSHA1Hash()},{trace.PID},{trace.randID},{info}");
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = MsgType.TraceMeta, destinationID = 0, data = Jsnbytes });
                NewOutDataEvent.Set();
            }
        }


        //https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2328
        private readonly Newtonsoft.Json.JsonSerializer serialiserOut = Newtonsoft.Json.JsonSerializer.Create(new JsonSerializerSettings()
        {
            TypeNameHandling = TypeNameHandling.None,
        });


        /// <summary>
        /// Used to send raw .net data types (serialised as JSON) as command responses
        /// Useful for when the GUI just wants a copy of some pre-existing data
        /// </summary>
        /// <param name="commandID">ID of the command being responsded to</param>
        /// <param name="response">Command-specific response</param>
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
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = MsgType.CommandResponse, destinationID = 0, data = Jsnbytes });
                NewOutDataEvent.Set();
            }
        }


        /// <summary>
        /// Send pre-built json objects as a command response
        /// This is usually for when the gui needs some API output, rather than neatly packaged data that we already have
        /// </summary>
        /// <param name="commandID">ID of command being responded to</param>
        /// <param name="response">JSON response object</param>
        public void SendResponseJSON(int commandID, JObject response)
        {
            lock (_sendQueueLock)
            {
                JObject responseObj = new JObject() { new JProperty("CommandID", commandID), new JProperty("Response", response) };
                byte[] Jsnbytes = Encoding.ASCII.GetBytes(responseObj.ToString(formatting: Formatting.None));
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = MsgType.CommandResponse, destinationID = 0, data = Jsnbytes });
                NewOutDataEvent.Set();
            }
        }


        /// <summary>
        /// Send unexpected events to the GUI (eg signature hits)
        /// </summary>
        /// <param name="dataName">Type of event</param>
        /// <param name="data">JSON event data</param>
        public void SendAsyncData(string dataName, JObject data)
        {
            lock (_sendQueueLock)
            {
                JObject responseObj = new JObject() { new JProperty("Name", dataName), new JProperty("Data", data) };
                byte[] Jsnbytes = Encoding.ASCII.GetBytes(responseObj.ToString(formatting: Formatting.None));
                _OutDataQueue.Enqueue(new NETWORK_MSG() { msgType = MsgType.AsyncData, destinationID = 0, data = Jsnbytes });
                NewOutDataEvent.Set();
            }
        }


        /// <summary>
        /// Destroy the connection
        /// </summary>
        /// <param name="reason">Why the connection was torn down</param>
        public void Teardown(string reason = "")
        {
            lock (_lock)
            {
                if (ConnectionState is not BridgeState.Teardown)
                {
                    try
                    {
                        try
                        {
                            if (_ActiveClient != null && _ActiveClient.Connected)
                            {
                                AddNetworkDisplayLogMessage($"Disconnected{(reason.Length > 0 ? $": {reason}" : "")}", Themes.eThemeColour.WarnStateColour);
                                RawSendData(MsgType.Meta, "Teardown:" + reason);
                            }
                            else
                            {
                                AddNetworkDisplayLogMessage($"Connection Disabled{(reason.Length > 0 ? $": {reason}" : "")}", null);
                            }
                        }
                        catch { } //avoid recursive exceptions caused by rawsend failing again

                        Thread.Sleep(250); //give the UI a chance to close the connection gracefully so the right error message appears first. 
                        ConnectionState = BridgeState.Teardown;
                        if (_reader != null)
                        {
                            _reader.Dispose();
                        }

                        if (_writer != null)
                        {
                            _writer.Dispose();
                        }
                    }
                    catch (Exception e)
                    {
                        AddNetworkDisplayLogMessage($"Teardown warning: {e.Message}", Themes.eThemeColour.WarnStateColour);
                    }
                    cancelTokens.Cancel();
                    if (_ActiveClient != null && _ActiveClient.Connected)
                    {
                        _ActiveClient.Close();
                    }

                    if (_ActiveListener != null)
                    {
                        _ActiveListener.Stop();
                    }
                }

                RemoteDataMirror.PurgeConnectionData();
            }
        }

        private void ReceiveIncomingTraffic()
        {
            Logging.WriteConsole("ReceiveIncomingTraffic started");
            Debug.Assert(_registeredIncomingDataCallback is not null);
            while (_ActiveClient is not null && _ActiveClient.Connected && !cancelTokens.IsCancellationRequested)
            {
                bool success = ReadData(out NETWORK_MSG? newdata);
                if (!success || newdata == null)
                {
                    if (!cancelTokens.IsCancellationRequested)
                    {
                        AddNetworkDisplayLogMessage("Connection terminated unexpectedly", Themes.eThemeColour.WarnStateColour);
                    }

                    break;
                }
                _registeredIncomingDataCallback(newdata.Value);

            }
            Logging.RecordLogEvent("ReceiveIncomingTraffic ServeClientIncoming dropout", filter: Logging.LogFilterType.Error);
            Teardown("ReceiveIncomingTraffic dropout");
        }

        private void SendOutgoingTraffic()
        {
            while (_ActiveClient is not null && _ActiveClient.Connected && !cancelTokens.IsCancellationRequested)
            {
                try
                {
                    bool waitResult = NewOutDataEvent.Wait(-1, cancellationToken: CancelToken);
                }
                catch (System.OperationCanceledException)
                {
                    break;
                }
                catch (Exception e)
                {
                    AddNetworkDisplayLogMessage($"Exception {e.Message}-{e.GetType()} in send outgoing", Themes.eThemeColour.BadStateColour);
                    break;
                }

                NETWORK_MSG[]? items = null;
                lock (_sendQueueLock)
                {
                    items = _OutDataQueue.ToArray();
                    _OutDataQueue.Clear();
                    NewOutDataEvent.Reset();
                }

                foreach (var item in items)
                {
                    if (!RawSendData(item))
                    {
                        Teardown("Send outgoing loop failed");
                        break;
                    }
                }
            }

            Teardown("Send outgoing failed");
        }


        /// <summary>
        /// Ensure the rgat server we are connecting to knows our network key and is running in the opposite mode type (GUI/Headless) 
        /// </summary>
        /// <param name="client">The endpoint</param>
        /// <returns>Authenticated</returns>
        public bool AuthenticateOutgoingConnection(TcpClient client)
        {
            Logging.WriteConsole($"AuthenticateOutgoingConnection Sending prelude '{(GUIMode ? connectPreludeGUI : connectPreludeHeadless)}'");


            if (!RawSendData(MsgType.Meta, GUIMode ? connectPreludeGUI : connectPreludeHeadless))
            {
                Logging.WriteConsole($"Failed to send prelude using {client}");
                return false;
            }


            bool success = ReadData(out NETWORK_MSG? response) && response != null;
            if (!success || response!.Value.data == null || response.Value.msgType != MsgType.Meta)
            {
                return false;
            }

            string authString;

            try
            {
                authString = ASCIIEncoding.ASCII.GetString(response.Value.data);
            }
            catch (Exception e)
            {
                Logging.RecordException($"Exception '{e}' parsing auth response", e);
                return false;
            }
            string expectedConnectResponse = GUIMode ? connectResponseHeadless : connectResponseGUI;

            if (authString == expectedConnectResponse)
            {
                SendInitialConnectData();
                return true;
            }
            else
            {
                if (authString == (GUIMode ? connectResponseGUI : connectResponseHeadless) || authString == "Bad Mode")
                {
                    if (GUIMode)
                    {
                        AddNetworkDisplayLogMessage("GUI<->GUI Connection Unsupported", Themes.eThemeColour.WarnStateColour);
                    }
                    else
                    {
                        AddNetworkDisplayLogMessage("Cmdline<->Cmdline Connection Unsupported", Themes.eThemeColour.WarnStateColour);
                    }

                    Logging.RecordLogEvent($"Bad prelude response. Connection can only be made between rgat in GUI and command-line modes", Logging.LogFilterType.Error);
                }
                else
                {
                    if (client.Client.RemoteEndPoint is not null)
                    {
                        Logging.RecordLogEvent($"Authentication failed for {(IPEndPoint)(client.Client.RemoteEndPoint)} - response did not decrypt to the expected value",
                            Logging.LogFilterType.Error);
                    }
                    AddNetworkDisplayLogMessage("Authentication failed - Bad Key", Themes.eThemeColour.AlertWindowBg);
                }
                return false;
            }

        }

        void SendInitialConnectData()
        {
            Logging.WriteConsole("Auth succeeded");
            if (!GUIMode)
            {
                Newtonsoft.Json.Linq.JObject newTarget = new();
                newTarget.Add("HostID", GlobalConfig.Settings.Network.HostID);
                SendAsyncData("InitialConnectData", newTarget);
            }
        }


        /// <summary>
        /// Ensure the rgat client connecting to us knows our network key and is running in the opposite mode type (GUI/Headless) 
        /// </summary>
        /// <param name="client">The endpoint</param>
        /// <returns>Authenticated</returns>
        public bool AuthenticateIncomingConnection(TcpClient client)
        {
            if (!ReadData(out NETWORK_MSG? recvd) || recvd == null)
            {
                return false;
            }

            NETWORK_MSG msg = recvd.Value;
            string authString = ASCIIEncoding.ASCII.GetString(recvd.Value.data);

            if (recvd == null || msg.msgType != MsgType.Meta || msg.data.Length == 0)
            {
                AddNetworkDisplayLogMessage("Authentication failed - no vald data", Themes.eThemeColour.BadStateColour);
                Logging.WriteConsole($"AuthenticateIncomingConnection No prelude from {client}, ignoring");
                Logging.RecordLogEvent($"No prelude from {client}, ignoring", Logging.LogFilterType.Debug);
                return false;
            }

            string connectPrelude = GUIMode ? connectPreludeHeadless : connectPreludeGUI;
            if (authString == connectPrelude && RawSendData(MsgType.Meta, GUIMode ? connectResponseGUI : connectResponseHeadless))
            {
                SendInitialConnectData();
                return true;
            }
            else
            {
                if (authString == (GUIMode ? connectPreludeGUI : connectPreludeHeadless))
                {
                    if (GUIMode)
                    {
                        AddNetworkDisplayLogMessage("GUI<->GUI Connection Unsupported", Themes.eThemeColour.WarnStateColour);
                    }
                    else
                    {
                        AddNetworkDisplayLogMessage("Cmdline<->Cmdline Connection Unsupported", Themes.eThemeColour.WarnStateColour);
                    }

                    Logging.RecordLogEvent($"Connection refused - Connection can only be made between rgat in GUI and command-line modes", Logging.LogFilterType.Error);
                    RawSendData(MsgType.Meta, "Bad Mode");
                }
                else
                {
                    AddNetworkDisplayLogMessage("Authentication failed - Bad Key", Themes.eThemeColour.AlertWindowBg);

                    if (client.Client.RemoteEndPoint is not null)
                    {
                        Logging.RecordLogEvent($"Authentication failed for {(IPEndPoint)(client.Client.RemoteEndPoint)} - prelude did not decrypt to the expected value", Logging.LogFilterType.Error);
                    }
                }
                return false;
            }

        }

        /// <summary>
        /// Message types
        /// </summary>
        public enum MsgType
        {
            /// <summary>
            /// Involved in the management of the connection
            /// </summary>
            Meta,
            /// <summary>
            /// A GUI-issued command
            /// </summary>
            Command,
            /// <summary>
            /// A response to the GUI
            /// </summary>
            CommandResponse,
            /// <summary>
            /// Involved in managing the transfer of trace data
            /// </summary>
            TraceMeta,
            /// <summary>
            /// Trace data from an instrumented process
            /// </summary>
            TraceData,
            /// <summary>
            /// A trace command
            /// </summary>
            TraceCommand,
            /// <summary>
            /// A log event
            /// </summary>
            Log,
            /// <summary>
            /// Non-trace related data sent without requiring a command to generate it (eg: result of signature scanning)
            /// </summary>
            AsyncData,
            /// <summary>
            /// No
            /// </summary>
            BAD
        };

        /// <summary>
        /// Connection activity
        /// </summary>
        public enum BridgeState
        {
            /// <summary>
            /// There is no network activity
            /// </summary>
            Inactive,
            /// <summary>
            /// rgat is connecting out
            /// </summary>
            Connecting,
            /// <summary>
            /// rgat is waiting for an incoming connection
            /// </summary>
            Listening,
            /// <summary>
            /// rgat is connected
            /// </summary>
            Connected,
            /// <summary>
            /// The connecton has been torn down
            /// </summary>
            Teardown
        };

    }
}
