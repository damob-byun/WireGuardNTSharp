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
        static void Main(string[] args)
        {
            Win32Error lastError;

            AddArch();

            var baseName = System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName); 
            var configFile = System.IO.Path.Combine(baseName, "client.conf");
            //Get Conf File
            var adapterName = "client";
            var tunnelType = "client";

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
            var configAllLinesLine = File.ReadAllLines(configFile);
            _adapter.ParseConfFile(configAllLinesLine, out WgConfig);

            Vanara.PInvoke.IpHlpApi.InitializeIpForwardEntry(out _ipforwardRow2);
            _ipforwardRow2.InterfaceLuid = _adapterLuid;
            _ipforwardRow2.NextHop.Ipv4.sin_addr = Ws2_32.IN_ADDR.INADDR_ANY;
            _ipforwardRow2.NextHop.si_family = Ws2_32.ADDRESS_FAMILY.AF_INET;
            _ipforwardRow2.Metric = 0;
            _ipforwardRow2.DestinationPrefix.Prefix.Ipv4.sin_addr = Ws2_32.IN_ADDR.INADDR_ANY;
            _ipforwardRow2.DestinationPrefix.Prefix.si_family = Ws2_32.ADDRESS_FAMILY.AF_INET;
            
            lastError = Vanara.PInvoke.IpHlpApi.CreateIpForwardEntry2(ref _ipforwardRow2);
            if (lastError.Failed)
            {
                //Failed to set default route
                Console.WriteLine("CreateIpForwardEntry2 " + lastError.ToString());
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

            Vanara.PInvoke.IpHlpApi.InitializeIpInterfaceEntry(out _IpInterfaceRow);
            _IpInterfaceRow.InterfaceLuid = _adapterLuid;
            _IpInterfaceRow.Family = Ws2_32.ADDRESS_FAMILY.AF_INET;
            _IpInterfaceRow.InterfaceIndex = 0;


            lastError = Vanara.PInvoke.IpHlpApi.GetIpInterfaceEntry(ref _IpInterfaceRow);

            if (lastError.Failed)
            {
                //Failed to get IP interface
                Console.WriteLine("GetIpInterfaceEntry " + lastError.ToString());
            }

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