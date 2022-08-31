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

        private static Vanara.PInvoke.IpHlpApi.MIB_IPINTERFACE_ROW _IpInterfaceRow;
        private static Vanara.PInvoke.IpHlpApi.MIB_UNICASTIPADDRESS_ROW _unicastipaddressRow;
        private static Vanara.PInvoke.IpHlpApi.MIB_IPFORWARD_ROW2 _ipforwardRow2;

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
                       }
                       if(o.ConfigPath != null && !o.ConfigPath.Equals(""))
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

            
            MIB_IPFORWARD_TABLE2 table;
            lastError = Vanara.PInvoke.IpHlpApi.GetIpForwardTable2(Ws2_32.ADDRESS_FAMILY.AF_INET, out table);
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
                    Vanara.PInvoke.IpHlpApi.DeleteIpForwardEntry2(ref table.Table[i]);
                }
                
            }

            //TODO: Endpoint Start
            Vanara.PInvoke.IpHlpApi.InitializeIpForwardEntry(out _ipforwardRow2);
            _ipforwardRow2.InterfaceLuid = _adapterLuid;
            _ipforwardRow2.NextHop.Ipv4.sin_addr = Ws2_32.IN_ADDR.INADDR_ANY;
            _ipforwardRow2.NextHop.si_family = Ws2_32.ADDRESS_FAMILY.AF_INET;
            _ipforwardRow2.Metric = 0;
            _ipforwardRow2.Protocol = MIB_IPFORWARD_PROTO.MIB_IPPROTO_LOCAL;
            _ipforwardRow2.DestinationPrefix.Prefix.Ipv4.sin_addr = Ws2_32.IN_ADDR.INADDR_ANY;
            _ipforwardRow2.DestinationPrefix.Prefix.si_family = Ws2_32.ADDRESS_FAMILY.AF_INET;

            lastError = Vanara.PInvoke.IpHlpApi.CreateIpForwardEntry2(ref _ipforwardRow2);
            
            if (lastError.Failed)
            {
                //Failed to set default route
                Console.WriteLine("CreateIpForwardEntry2 " + lastError.ToString());
            }
            else
            {
                Console.WriteLine("Set default route" + lastError.ToString());
            }

            Vanara.PInvoke.IpHlpApi.InitializeUnicastIpAddressEntry(out _unicastipaddressRow);
            _unicastipaddressRow.InterfaceLuid = _adapterLuid;
            _unicastipaddressRow.Address.Ipv4.sin_addr = new Ws2_32.IN_ADDR(WgConfig.InterfaceAddress.GetAddressBytes());
            _unicastipaddressRow.Address.Ipv4.sin_family = Ws2_32.ADDRESS_FAMILY.AF_INET;
            _unicastipaddressRow.OnLinkPrefixLength = WgConfig.InterfaceNetwork.Cidr;
            _unicastipaddressRow.DadState = NL_DAD_STATE.IpDadStatePreferred;

            lastError = Vanara.PInvoke.IpHlpApi.CreateUnicastIpAddressEntry(ref _unicastipaddressRow);
            if (lastError.Failed)
            {
                //Failed to set IP address
                Console.WriteLine("CreateUnicastIpAddressEntry " + lastError.ToString());
            }
            else
            {
                Console.WriteLine("Set Ip address " + lastError.ToString());
            }

            Vanara.PInvoke.IpHlpApi.InitializeIpInterfaceEntry(out _IpInterfaceRow);
            _IpInterfaceRow.InterfaceLuid = _adapterLuid;
            _IpInterfaceRow.Family = Ws2_32.ADDRESS_FAMILY.AF_INET;

            lastError = Vanara.PInvoke.IpHlpApi.GetIpInterfaceEntry(ref _IpInterfaceRow);

            if (lastError.Failed)
            {
                //Failed to get IP interface
                Console.WriteLine("GetIpInterfaceEntry " + lastError.ToString());
            }
            else
            {
                Console.WriteLine("Set Ip address " + lastError.ToString());
            }

            _IpInterfaceRow.ForwardingEnabled = true;

            _IpInterfaceRow.UseAutomaticMetric = false;
            _IpInterfaceRow.Metric = 0;
            _IpInterfaceRow.NlMtu = WgConfig.InterfaceMtu;
            _IpInterfaceRow.SitePrefixLength = 0;
            
            lastError = Vanara.PInvoke.IpHlpApi.SetIpInterfaceEntry(_IpInterfaceRow);

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