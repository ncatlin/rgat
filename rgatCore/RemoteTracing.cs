using System;
using System.Collections.Generic;
using System.Text;
using System.Net.NetworkInformation;
using System.Linq;

namespace rgat
{
    class RemoteTracing
    {
        public static void PrintInterfaces(bool PrintInvalid = false)
        {
            NetworkInterface[] interfaces = GetInterfaces(PrintInvalid);

            if (PrintInvalid)
            {
                Console.WriteLine($"Listing {interfaces.Length} known network interfaces");
            }
            else
            {
                Console.WriteLine($"Listing {interfaces.Length} valid network interfaces. You can specify an interface using its name, ID or address"); //or index, but not a good idea
            }


            if (interfaces.Length == 0)
            {
                bool available = NetworkInterface.GetIsNetworkAvailable();
                if (available)
                {
                    //I don't know if this would ever happen and am totally guessing about what might cause it
                    Console.WriteLine("\tA network connection is available but no network interfaces could be found. Try running rgat with higher privilege");
                }
                else
                {
                    Console.WriteLine("\tNo network connection is available and no network interfaces could be detected.");
                }
                return;
            }

            for (var i = 0; i < interfaces.Length; i++)
            {
                NetworkInterface iface = interfaces[i];
                PrintInterfaceInformation(iface, i);
            }
        }

        public static void PrintInterfaceInformation(NetworkInterface iface, int index = -1)
        {
            if (index != -1)
            {
                Console.WriteLine($"\t{index}: {iface.Name} - \"{iface.Description}\" [{iface.OperationalStatus}]");
            }
            else
            {
                Console.WriteLine($"\t{iface.Name} - \"{iface.Description}\" [{iface.OperationalStatus}]");
            }

            var addresses = iface.GetIPProperties().UnicastAddresses;
            if (addresses.Count > 0)
            {
                Console.WriteLine($"\t\tAddresses:");
                foreach (var addr in addresses.Reverse())
                    Console.WriteLine($"\t\t\t{addr.Address}");
            }
            else
            {
                Console.WriteLine("\t\tInterface has no addresses");
            }
            Console.WriteLine($"\t\tMAC: {iface.GetPhysicalAddress().ToString()}");
            Console.WriteLine($"\t\tType: {iface.NetworkInterfaceType}");
            Console.WriteLine($"\t\tID: {iface.Id}");
            Console.WriteLine("");
        }

        static NetworkInterface[] GetInterfaces(bool IncludeInvalid = false)
        {
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
            if (IncludeInvalid) return interfaces;

            List<NetworkInterface> result = new List<NetworkInterface>();
            foreach (var iface in interfaces)
            {
                if (iface.OperationalStatus != OperationalStatus.Up) continue;
                if (iface.IsReceiveOnly) continue;
                if (iface.GetIPProperties().UnicastAddresses.Count == 0) continue;
                result.Add(iface);
            }
            return result.ToArray();
        }

        public static NetworkInterface ValidateNetworkInterface(string interfaceCmdlineString)
        {
            if (interfaceCmdlineString == null) return null;

            NetworkInterface matchedInterface = null;
            NetworkInterface[] validInterfaces = GetInterfaces();

            string comparer = interfaceCmdlineString.ToLower();

            foreach (NetworkInterface iface in validInterfaces)
            {
                if (iface.Name.ToLower() == comparer)
                {
                    matchedInterface = iface;
                    break;
                }
                if (iface.Id.ToLower() == comparer || iface.Id.ToLower() == "{" + comparer + "}")
                {
                    matchedInterface = iface;
                    break;
                }
                if (iface.Description.ToLower() == comparer)
                {
                    matchedInterface = iface;
                    break;
                }

                foreach (var addr in iface.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.ToString() == comparer)
                    {
                        matchedInterface = iface;
                        break;
                    }
                }
                
            }

            return matchedInterface;
        }
    }
}
