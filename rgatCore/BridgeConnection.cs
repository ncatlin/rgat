using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace rgat
{
   public class BridgeConnection
    {

        public delegate void OnGotDataCallback(byte[] data);
        public delegate void OnConnectSuccessCallback();

        public bool Connected => BridgeState == eBridgeState.Connected;
        public bool ActiveNetworking => BridgeState == eBridgeState.Connected || BridgeState == eBridgeState.Listening || BridgeState == eBridgeState.Connecting;

        //public IPEndPoint ConnectedEndpoint = null;
        public  enum eBridgeState { Inactive, Connecting, Listening, Connected, Errored, Teardown };
        public eBridgeState BridgeState 
        { 
            get => _bridgeState;
            private set
            {
                Console.WriteLine($"Setting bridgestate to {value}");
                _bridgeState = value;
            }
        }
        eBridgeState _bridgeState = eBridgeState.Inactive;


        /// <summary>
        /// Whether this instance is the GUI.
        /// The GUI sends tracing commands and recieves trace data and associated metadata (available files to execute, signature hits, etc)
        /// It does not do the opposite. Ever.
        /// </summary>
        public bool GUIMode { get; private set; }

        Queue<byte[]> _OutDataQueue = new Queue<byte[]>();
        ManualResetEventSlim NewOutDataEvent = new ManualResetEventSlim(false);

        CancellationTokenSource cancelTokens;
        CancellationToken CancelToken => cancelTokens.Token;
        readonly object _sendQueueLock = new object();
        readonly object _recvQueueLock = new object();

        TcpClient _ActiveClient;
        TcpListener _ActiveListener;
        OnGotDataCallback _registeredIncomingDataCallback;
        public IPEndPoint RemoteEndPoint;


        const string connectPreludeGUI = "rgat connect prelude";
        const string connectPreludeHeadless = "rgat connect prelude";
        const string connectResponseGUI = "accept rgat prelude";
        const string connectResponseHeadless = "accept rgat prelude connect";

       public  BridgeConnection(bool isgui)
        {
            GUIMode = GUIMode;
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
            try
            {
                Console.WriteLine("StartConnectOut begin");
                Task connect = _ActiveClient.ConnectAsync(remoteConnectAddress, remoteConnectPort);
                Console.WriteLine("StartConnectOut waiting");
                Task.WaitAny(new Task[] { connect }, CancelToken);
                Console.WriteLine("StartConnectOut waited");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception {e} in StartConnectOut");
                _ActiveClient = null;
                BridgeState = eBridgeState.Errored;
                return;
            }
            Thread.Sleep(1000);
            if (client.Connected)
            {
                Console.WriteLine($"in StartConnectOut connected");

                if (AuthenticateOutgoingConnection(client, client.GetStream()))
                {
                    Console.WriteLine($"in StartConnectOut auth succeed");

                    ServeAuthenticatedConnection(client, connectCallback);
                }
                else
                {
                    Console.WriteLine($"in StartConnectOut auth fail");
                    BridgeState = eBridgeState.Errored;
                }
            }
            else
            {
                Console.WriteLine($"in StartConnectOut not connected");
                BridgeState = eBridgeState.Inactive;
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

            _ActiveListener = new TcpListener(localBindAddress, localBindPort);
            _ActiveListener.ExclusiveAddressUse = true;
            _ActiveListener.Start();

            _registeredIncomingDataCallback = dataCallback;
            BridgeState = eBridgeState.Listening;
            return Task.Run(() => StartListenForConnection(_ActiveListener, connectCallback));
        }

        void StartListenForConnection(TcpListener listener, OnConnectSuccessCallback connectCallback)
        {
            Console.WriteLine("StartListenForConnection begin");
            try
            {
                _ActiveClient = listener.AcceptTcpClient();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception {e} in StartConnectOut");
                Teardown();
                _ActiveClient = null;
                BridgeState = eBridgeState.Errored;
                return;
            }

            if (_ActiveClient != null && _ActiveClient.Connected)
            {
                IPEndPoint clientEndpoint = (IPEndPoint)_ActiveClient.Client.RemoteEndPoint;
                Console.WriteLine($"StartListenForConnection Got {clientEndpoint.AddressFamily} connection from {clientEndpoint.Address}:{clientEndpoint.Port}");
                if (AuthenticateIncomingConnection(_ActiveClient, _ActiveClient.GetStream()))
                {
                    Console.WriteLine("StartListenForConnection authenticate success, handling incoming");

                    ServeAuthenticatedConnection(_ActiveClient, connectCallback);
                }
                else
                {
                    Console.WriteLine("StartListenForConnection authenticate failed");
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
                lock (_recvQueueLock)
                {
                    _OutDataQueue.Clear();
                    NewOutDataEvent.Reset();
                }
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

        public static bool EstablishConnection(TcpClient client, string remoteAddress, int port)
        {
            try
            {
                client.Connect(remoteAddress, port);

            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception {e} connecting to {remoteAddress}:{port}");
            }

            return false;
        }


       public void SendOutgoingData(byte[] data)
        {
            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(data);
                NewOutDataEvent.Set();
            }
        }

        public void SendCommand(string text)
        {
            Console.WriteLine("Doing sendcommand: " + text);

            lock (_sendQueueLock)
            {
                _OutDataQueue.Enqueue(Encoding.ASCII.GetBytes(text));
                NewOutDataEvent.Set();
            }
        }



        public void Teardown()
        {
            if (BridgeState != eBridgeState.Teardown)
            {
                Console.WriteLine("Teardown called");
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
            while (client.Connected && !cancelTokens.IsCancellationRequested)
            {
                int i = ReadData(stream, out byte[] newdata);
                if (i == 0)
                {
                    Console.WriteLine("ReceiveIncomingTraffic Client Disconnected during read");
                    break;
                }

                lock (_recvQueueLock)
                {
                    Console.WriteLine($"ReceiveIncomingTraffic ServeClientIncoming newdata: Got {ASCIIEncoding.ASCII.GetString(newdata)}");
                    _registeredIncomingDataCallback(newdata);
                }
            }
            Console.WriteLine("ReceiveIncomingTraffic ServeClientIncoming dropout");
            Teardown();
        }

        void SendOutgoingTraffic(TcpClient client)
        {
            NetworkStream stream = client.GetStream();
            Console.WriteLine("Serve outgoing started");
            while (client.Connected && !cancelTokens.IsCancellationRequested)
            {
                try
                {
                   bool waitResult = NewOutDataEvent.Wait(-1, cancellationToken: CancelToken);
                    Console.WriteLine($"Waitrs {waitResult}");
                }
                catch (System.OperationCanceledException e)
                {
                    Console.WriteLine("Cancellation during wait for outgoing data");
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Exception waiting for new data event: {e}");
                    break;
                }

                Console.WriteLine("Serveout got");
                byte[][] items = null;
                lock (_sendQueueLock)
                {
                    items = _OutDataQueue.ToArray();
                    _OutDataQueue.Clear();
                    NewOutDataEvent.Reset();
                }

                foreach (var item in items)
                {
                    if (RawSendData(stream, item))
                    {
                        Console.WriteLine($"Sent: {ASCIIEncoding.ASCII.GetString(item)}");
                    }
                    else
                    {
                        Console.WriteLine($"\tFailed sending item '{item}' sending to client");
                        Teardown();
                        break;
                    }
                }
            }

            Console.WriteLine("Serveout dropped");
            Teardown();
        }


        public bool AuthenticateOutgoingConnection(TcpClient client, NetworkStream stream)
        {

            if (!RawSendData(stream, Encoding.ASCII.GetBytes(GUIMode ? connectPreludeGUI : connectPreludeHeadless)))
            {
                Console.WriteLine($"Failed to send prelude using {client}");
                return false;
            }

            int count = ReadData(stream, out byte[] recvd);
            string connectResponse = GUIMode ? connectPreludeHeadless : connectPreludeGUI;
            if (count == connectResponse.Length && ASCIIEncoding.ASCII.GetString(recvd, 0, Math.Min(count, connectResponse.Length)) == connectResponse)
            {
                Console.WriteLine($"Auth succeeded");
                return true;
            }
            else
            {
                Console.WriteLine($"Bad prelude response {ASCIIEncoding.ASCII.GetString(recvd)}, ignoring");
                return false;
            }

        }

        public bool AuthenticateIncomingConnection(TcpClient client, NetworkStream stream)
        {

            int readCount = ReadData(stream, out byte[] bytes);
            if (readCount == 0)
            {
                Console.WriteLine($"AuthenticateIncomingConnection No prelude from {client}, ignoring");
                Logging.RecordLogEvent($"No prelude from {client}, ignoring", Logging.LogFilterType.TextDebug);
                return false;
            }

            string connectPrelude = GUIMode ? connectPreludeHeadless : connectPreludeGUI;
            string recvd;
            try
            {
                recvd = System.Text.Encoding.ASCII.GetString(bytes, 0, Math.Min(bytes.Length, connectPrelude.Length));
            }
            catch (Exception e)
            {
                Console.WriteLine($"AuthenticateIncomingConnection Exception {e} decoding prelude, ignoring");
                return false;
            }

            if (recvd == connectPrelude && RawSendData(stream, ASCIIEncoding.ASCII.GetBytes(connectPrelude)))
            {
                Console.WriteLine($"Auth succeeded");
                return true;
            }
            else
            {
                Console.WriteLine($"Bad prelude {recvd}, ignoring");
                return false;
            }

        }

        int ReadData(NetworkStream stream, out byte[] bytes)
        {
            bytes = new byte[255];
            Task<int> read = null;
            try
            {
                read = stream.ReadAsync(bytes, 0, bytes.Length, CancelToken);
                if (read.IsCanceled)
                {
                    Console.WriteLine("Cancellation during read of incoming data");
                    return 0;
                }
                Console.WriteLine($"Readdata {read.Result} bytes");
                return read.Result;
            }
            catch (System.OperationCanceledException e)
            {
                Console.WriteLine("Cancellation during read of incoming data");
            }
            catch (System.Net.Sockets.SocketException e)
            {
                Console.WriteLine($"\t! Socket exception {e.SocketErrorCode} reading from client");
                Console.WriteLine($"\t! {e.InnerException}");
                Console.WriteLine($"\t! {e.Message}");
            }
            catch (System.IO.IOException e)
            {
                Console.WriteLine($"\t! IO exception reading from client");
                Console.WriteLine($"\t! {e.InnerException}");
                Console.WriteLine($"\t! {e.Message}");
            }
            catch (Exception e)
            {
                if (read != null && read.IsCanceled)
                {
                    Console.WriteLine("Cancellation during read of incoming data");
                }
                else
                {
                    Console.WriteLine($"\t! ReadData Generic Exception '{e.Message}' reading from client");
                }
            }
            return 0;
        }

        bool RawSendData(NetworkStream stream, byte[] bytes)
        {
            try
            {
                Console.WriteLine($"Doing writeasync of {bytes.Length} bytes");
                Task write = stream.WriteAsync(bytes, 0, bytes.Length, CancelToken);
                write.Wait();
                return !cancelTokens.IsCancellationRequested;
            }
            catch (System.OperationCanceledException e)
            {
                Console.WriteLine("Cancellation during send of outgoing data");
            }
            catch (System.Net.Sockets.SocketException e)
            {
                Console.WriteLine($"\t! Socket exception {e.SocketErrorCode} reading from client");
                Console.WriteLine($"\t! {e.InnerException}");
                Console.WriteLine($"\t! {e.Message}");
            }
            catch (System.IO.IOException e)
            {
                Console.WriteLine($"\t! IO exception reading from client");
                Console.WriteLine($"\t! {e.InnerException}");
                Console.WriteLine($"\t! {e.Message}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"\t! RawSendData Generic Exception '{e.Message}' reading from client");
            }
            return false;
        }

    }
}
