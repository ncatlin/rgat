using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;

namespace rgat
{
    internal class NetworkUtilities
    {
        public static void PrintInterfaces(bool PrintInvalid = false)
        {
            NetworkInterface[] interfaces = GetInterfaces(PrintInvalid);

            if (PrintInvalid)
            {
                Logging.WriteConsole($"Listing {interfaces.Length} known network interfaces");
            }
            else
            {
                Logging.WriteConsole($"Listing {interfaces.Length} valid network interfaces. You can specify an interface using its name, ID, MAC or address"); //or index, but not a good idea
            }


            if (interfaces.Length == 0)
            {
                bool available = NetworkInterface.GetIsNetworkAvailable();
                if (available)
                {
                    //I don't know if this would ever happen and am totally guessing about what might cause it
                    Logging.WriteConsole("\tA network connection is available but no network interfaces could be found. Try running rgat with higher privilege");
                }
                else
                {
                    Logging.WriteConsole("\tNo network connection is available and no network interfaces could be detected.");
                }
                return;
            }

            for (var i = 0; i < interfaces.Length; i++)
            {
                NetworkInterface iface = interfaces[i];
                PrintInterfaceInformation(iface, i + 1); //start index from 1. 0 == 0.0.0.0
            }
        }

        public static string hexMAC(PhysicalAddress addr)
        {
            string result = "";
            var bytes = addr.GetAddressBytes();
            for (int i = 0; i < bytes.Length; i++)
            {
                result += bytes[i].ToString("X2");
                if (i != bytes.Length - 1)
                {
                    result += "-";
                }
            }
            return result;
        }

        public static void PrintInterfaceInformation(NetworkInterface iface, int index = -1)
        {
            if (index != -1)
            {
                Logging.WriteConsole($"\t{index}: \"{iface.Name}\" <Description: {iface.Description} [{iface.OperationalStatus}]>");
            }
            else
            {
                Logging.WriteConsole($"\t\"{iface.Name}\" <Description: {iface.Description} [{iface.OperationalStatus}]>");
            }

            var addresses = iface.GetIPProperties().UnicastAddresses;
            if (addresses.Count > 0)
            {
                Logging.WriteConsole($"\t\tAddresses:");
                foreach (var addr in addresses.Reverse())
                {
                    Logging.WriteConsole($"\t\t\t{addr.Address}");
                }
            }
            else
            {
                Logging.WriteConsole("\t\tInterface has no addresses");
            }
            string MAC = NetworkUtilities.hexMAC(iface.GetPhysicalAddress());
            if (MAC.Length > 0)
            {
                Logging.WriteConsole($"\t\tMAC: {MAC}");
            }

            Logging.WriteConsole($"\t\tType: {iface.NetworkInterfaceType}");
            Logging.WriteConsole($"\t\tID: {iface.Id}");
            Logging.WriteConsole("");
        }

        public static NetworkInterface[] GetInterfaces(bool IncludeInvalid = false)
        {
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
            if (IncludeInvalid)
            {
                return interfaces;
            }

            List<NetworkInterface> result = new List<NetworkInterface>();
            foreach (var iface in interfaces)
            {
                if (iface.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                if (iface.IsReceiveOnly)
                {
                    continue;
                }

                if (iface.GetIPProperties().UnicastAddresses.Count == 0)
                {
                    continue;
                }

                result.Add(iface);
            }
            return result.ToArray();
        }


        public static NetworkInterface? ValidateNetworkInterface(string interfaceCmdlineString)
        {
            if (interfaceCmdlineString == null)
            {
                return null;
            }

            NetworkInterface? matchedInterface = null;
            NetworkInterface[] validInterfaces = GetInterfaces();

            string comparer = interfaceCmdlineString.ToLower();


            if (int.TryParse(comparer, out int indexInt))
            {
                indexInt -= 1;
                if (indexInt >= 0 && indexInt < validInterfaces.Length)
                {
                    return validInterfaces[indexInt];
                }
            }


            int index = 1;
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

                string hexmac = NetworkUtilities.hexMAC(iface.GetPhysicalAddress()).ToLower();
                if (hexmac.Length > 0 && comparer.Contains(hexmac))
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

                index += 1;
            }

            return matchedInterface;
        }



    }
}
