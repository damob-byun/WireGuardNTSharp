using CommandLine.Text;
using CommandLine;
using System;
using System.Diagnostics;
using System.Net;
using Vanara.PInvoke;
using WireGuardNT_PInvoke;
using WireGuardNT_PInvoke.WireGuard;
using static Vanara.PInvoke.IpHlpApi;

namespace Example // Note: actual namespace depends on the project name.
{

    internal class Program
    {
        private static Adapter? _adapter = null;
        private static Guid _adapterGuid;
        private static NET_LUID _adapterLuid;



        private static WgConfig WgConfig = new WgConfig();


        public static void AddArch()
        {
            string[] first = new string[1]
            {
                Environment.GetEnvironmentVariable("PATH") ?? string.Empty
            };
            string[] second = new string[2]
            {
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "x86"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "x64")
            };
            Environment.SetEnvironmentVariable("PATH", string.Join(Path.PathSeparator.ToString(), ((IEnumerable<string>)first).Concat<string>((IEnumerable<string>)second)));

        }
        public class Options
        {
            [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
            public bool Verbose { get; set; }
            [Option('c', "config", Required = false, HelpText = "ConfigFile path.")]
            public string? ConfigPath { get; set; }

            [Option('n', "name", Required = false, HelpText = "Adapter Name.")]
            public string? AdapterName { get; set; }

            [Option('t', "tunnelType", Required = false, HelpText = "Adapter Name.")]
            public string? TunnelType { get; set; }
        }
        static void Main(string[] args)
        {
            Win32Error lastError;

            AddArch();

            var configPath = "client.conf";
            var adapterName = "client";
            var tunnelType = "client";

            Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(o =>
                   {
                       if (o.Verbose)
                       {
                           Console.WriteLine($"Verbose output enabled. Current Arguments: -v {o.Verbose}");
                           Console.WriteLine("1.0.0");
                           return;
                       }
                       if (o.ConfigPath != null && !o.ConfigPath.Equals(""))
                       {
                           configPath = o.ConfigPath;
                       }

                       if (o.AdapterName != null && !o.AdapterName.Equals(""))
                       {
                           adapterName = o.AdapterName;
                       }

                       if (o.TunnelType != null && !o.TunnelType.Equals(""))
                       {
                           tunnelType = o.TunnelType;
                       }
                   });

            if (!System.IO.Path.IsPathRooted(configPath))
            {
                var baseName = System.IO.Path.GetDirectoryName(Environment.ProcessPath);
                configPath = System.IO.Path.Combine(baseName, configPath);
            }

            if (!File.Exists(configPath))
            {
                Console.WriteLine("Not Found : Config File");
                return;
            }

            //Get Conf File


            _adapterGuid = Guid.Parse("{0xdeadc001,0xbeef,0xbabe,{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}}");

            _adapter = new Adapter(adapterName, tunnelType);
            _adapter.EventInfoMessage += (sender, arg) =>
            {
                Console.WriteLine(arg.Message);
            };
            _adapter.EventErrorMessage += (sender, arg) =>
            {
                Console.WriteLine(arg.Message + arg.Win32ErrorNum);
            };
            _adapter.Init(ref _adapterGuid, out _adapterLuid);

            //Read all line from config file
            var configAllLinesLine = File.ReadAllLines(configPath);
            _adapter.ParseConfFile(configAllLinesLine, out WgConfig);


            //MIB_IPFORWARD_TABLE2 table;
            lastError = GetIpForwardTable2(Ws2_32.ADDRESS_FAMILY.AF_INET, out MIB_IPFORWARD_TABLE2 table);
            if (lastError.Failed)
            {
                //Failed to get default route
                Console.WriteLine("GetIpForwardTable2 " + lastError.ToString());
            }

            //for(var i=0; T)
            for (var i = 0; i < table.NumEntries; i++)
            {
                var row = table.Table[i];
                if (row.InterfaceLuid.Equals(_adapterLuid))
                {
                    Console.WriteLine("Start Delete Row [" + i + "] - Metric " + row.Metric);
                    DeleteIpForwardEntry2(ref table.Table[i]);
                }

            }

            for (var i = 0; i < WgConfig.LoctlWireGuardConfig.WgPeerConfigs.Length; i++)
            {
                var peerConfig = WgConfig.LoctlWireGuardConfig.WgPeerConfigs[i];
                MIB_IPFORWARD_ROW2 row;
                InitializeIpForwardEntry(out row);
                row.InterfaceLuid = _adapterLuid;

                row.Metric = 1;

                var maskedIp = IPNetwork.Parse("" + peerConfig.allowdIp.V4.Addr, peerConfig.allowdIp.Cidr);

                row.DestinationPrefix.Prefix.Ipv4.sin_addr = new Ws2_32.IN_ADDR(maskedIp.Network.GetAddressBytes());
                //row.DestinationPrefix.Prefix.Ipv4.sin_addr = Ws2_32.IN_ADDR.INADDR_ANY;
                row.DestinationPrefix.Prefix.si_family = Ws2_32.ADDRESS_FAMILY.AF_INET;
                row.DestinationPrefix.PrefixLength = maskedIp.Cidr;

                row.Protocol = MIB_IPFORWARD_PROTO.MIB_IPPROTO_LOCAL;
                row.NextHop.Ipv4.sin_addr = Ws2_32.IN_ADDR.INADDR_ANY;
                row.NextHop.si_family = Ws2_32.ADDRESS_FAMILY.AF_INET;

                lastError = CreateIpForwardEntry2(ref row);
                if (lastError.Failed)
                {
                    //Failed to set default route
                    Console.WriteLine("CreateIpForwardEntry2 [" + i + "] " + lastError.ToString());
                }
                else
                {
                    Console.WriteLine("Set default route [" + i + "] " + lastError.ToString());
                }

            }


            
            //MIB_UNICASTIPADDRESS_ROW unicastIpAddressRow;
            InitializeUnicastIpAddressEntry(out MIB_UNICASTIPADDRESS_ROW unicastIpAddressRow);
            unicastIpAddressRow.InterfaceLuid = _adapterLuid;
            unicastIpAddressRow.Address.Ipv4.sin_addr = new Ws2_32.IN_ADDR(WgConfig.InterfaceAddress.GetAddressBytes());
            unicastIpAddressRow.Address.Ipv4.sin_family = Ws2_32.ADDRESS_FAMILY.AF_INET;
            unicastIpAddressRow.OnLinkPrefixLength = WgConfig.InterfaceNetwork.Cidr;
            unicastIpAddressRow.DadState = NL_DAD_STATE.IpDadStatePreferred;

            lastError = CreateUnicastIpAddressEntry(ref unicastIpAddressRow);
            if (lastError.Failed)
            {
                //Failed to set IP address
                Console.WriteLine("CreateUnicastIpAddressEntry " + lastError.ToString());
            }
            else
            {
                Console.WriteLine("Set Ip address " + lastError.ToString());
            }
            //MIB_IPINTERFACE_ROW ipInterfaceRow;
            InitializeIpInterfaceEntry(out MIB_IPINTERFACE_ROW ipInterfaceRow);
            ipInterfaceRow.InterfaceLuid = _adapterLuid;
            ipInterfaceRow.Family = Ws2_32.ADDRESS_FAMILY.AF_INET;

            lastError = GetIpInterfaceEntry(ref ipInterfaceRow);

            if (lastError.Failed)
            {
                //Failed to get IP interface
                Console.WriteLine("GetIpInterfaceEntry " + lastError.ToString());
            }
            else
            {
                Console.WriteLine("Set Ip address " + lastError.ToString());
            }

            ipInterfaceRow.ForwardingEnabled = true;

            ipInterfaceRow.UseAutomaticMetric = false;
            ipInterfaceRow.Metric = 0;
            ipInterfaceRow.NlMtu = WgConfig.InterfaceMtu;
            ipInterfaceRow.SitePrefixLength = 0;

            lastError = SetIpInterfaceEntry(ipInterfaceRow);

            if (lastError.Failed)
            {
                //Failed to set metric and MTU
                Console.WriteLine("SetIpInterfaceEntry " + lastError.ToString());
            }
            else
            {
                Console.WriteLine("Set Metric and MTU " + lastError.ToString());
            }

            foreach (var dnsAddress in WgConfig.DnsAddresses)
            {
                Process.Start("netsh.exe", String.Format("interface ipv4 add dnsservers name={0} address={1} validate=no", adapterName, dnsAddress));
            }

            _adapter.SetConfiguration(WgConfig);
            _adapter.SetStateUp();


            while (true)
            {
                ulong rx = 0, tx = 0;

                var config = _adapter.GetConfiguration();
                foreach (var peer in config.Peers)
                {
                    rx += peer.RxBytes;
                    tx += peer.TxBytes;

                }
                Console.WriteLine("rx :" + rx);
                Console.WriteLine("tx :" + tx);

                var state = _adapter.GetAdapterState();
                Console.WriteLine("state :" + state);
                Thread.Sleep(1000);
            }
        }
    }
}