using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace rgat.OperationModes

{    /// <summary>
     /// Runs rgat as a headless proxy which allows an rgat instance on a remote machine to control tracing and receive raw trace data
     /// This does not require access to a GPU
     /// </summary>
    class BridgedRunner
    {
        rgatState _rgatState;
        public BridgedRunner(rgatState state)
        {
            _rgatState = state;
        }

        public void Run()
        {

            if (GlobalConfig.StartOptions.ListenPort != null)
            {
                Console.WriteLine("Starting headless listen mode");
                WaitForConnection();
            }

            if (GlobalConfig.StartOptions.ConnectModeAddress != null)
            {
                Console.WriteLine("Starting headless conenct mode");
                ConnectToListener();
            }
        }


        void WaitForConnection()
        {


            IPAddress localAddr;
            if (GlobalConfig.StartOptions.ActiveNetworkInterface == null) //user didn't pass a param, or 
            {
                if (IPAddress.TryParse(GlobalConfig.StartOptions.Interface, out IPAddress address))
                {
                    localAddr = address;
                }
                else
                {
                    localAddr = IPAddress.Parse("0.0.0.0");
                }
            }
            else
            {

                //int index = GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().GetIPv4Properties().Index;
                try
                {
                    if (GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.Any(x => x.Address.ToString() == GlobalConfig.StartOptions.Interface))
                    {
                        localAddr = GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.First(x => x.Address.ToString() == GlobalConfig.StartOptions.Interface).Address;
                    }
                    else if (GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.Any(x => x.Address.AddressFamily == AddressFamily.InterNetwork))
                    {
                        localAddr = GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.First(x => x.Address.AddressFamily == AddressFamily.InterNetwork).Address;
                    }
                    else if (GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.Any(x => x.Address.AddressFamily == AddressFamily.InterNetworkV6))
                    {
                        localAddr = GlobalConfig.StartOptions.ActiveNetworkInterface.GetIPProperties().UnicastAddresses.First(x => x.Address.AddressFamily == AddressFamily.InterNetworkV6).Address;
                    }
                    else
                    {
                        Console.WriteLine($"Error: Failed to find any ipv4 or ipv6 addresses for the specified interface");
                        return;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error: Exception '{e.Message}' trying to find any ipv4 or ipv6 addresses for the specified interface");
                    return;
                }

            }


            Int32 port;
            if (GlobalConfig.StartOptions.ListenPort != null && GlobalConfig.StartOptions.ListenPort.Value > 0)
            {
                port = GlobalConfig.StartOptions.ListenPort.Value;
                Console.WriteLine($"Starting TCP server on {localAddr.ToString()}:{port}");
            }
            else
            {
                Console.WriteLine($"Starting TCP server on {localAddr.ToString()}:[next free port]");
                port = 0; //i'm feeling lucky
            }

            TcpListener server;
            try
            {
                server = new TcpListener(localAddr, port);
                server.Start();
            }
            catch (Exception e)
            {
                Logging.RecordLogEvent($"Failed to start server: {e.Message}", Logging.LogFilterType.TextError);
                return;
            }


            if (server.Server.IsBound)
            {
                IPEndPoint local = (IPEndPoint)server.Server.LocalEndPoint;
                Console.WriteLine($"Started server on port:  {local.Address}:{local.Port}");
            }
            else
            {
                Console.WriteLine($"Error: Failed to secure a port");
                return;
            }


            TcpClient client = server.AcceptTcpClient();
            Console.WriteLine("Connected!");

            NetworkStream stream = client.GetStream();
            byte[] msg = System.Text.Encoding.ASCII.GetBytes("doifjhgiue");
            stream.Write(msg);
        }


        void ConnectToListener()
        {
            //try to connect
        }

    }
}
