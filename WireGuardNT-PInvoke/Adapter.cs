using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using Vanara.PInvoke;
using WireGuardNT_PInvoke.WireGuard;
using static Vanara.PInvoke.IpHlpApi;

namespace WireGuardNT_PInvoke
{
    public unsafe class Adapter : IDisposable
    {
        private bool _disposedValue;
        private IntPtr _handle;
        private uint _lastGetGuess;
        public string Name { get; set; }
        public string TunnelType { get; set; }

        public event EventHandler<WireGuardErrorEventArg> EventErrorMessage;
        public event EventHandler<WireGuardInfoEventArg> EventInfoMessage;

        public Adapter(string name, string tunnelType)
        {
            Name = name;
            TunnelType = tunnelType;
            _lastGetGuess = 1024;
            
        }

        public void Init(ref Guid guid, out IpHlpApi.NET_LUID luid)
        {
            _handle = NativeFunctions.openAdapter(Name);
            if (_handle == IntPtr.Zero)
            {
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("OpenAdapter Fail And Now Start Create... : ", Marshal.GetLastWin32Error()));
                _handle = NativeFunctions.createAdapter(Name, TunnelType, out guid);
                if (_handle == IntPtr.Zero)
                {
                    var errorCode = Marshal.GetLastWin32Error();
                    OnEvent(EventErrorMessage, new WireGuardErrorEventArg("CreateAdapter Fail : ", errorCode));
                    throw new Win32Exception(errorCode);
                }
            }

            var version = GetRunningDriverVersion();
            if (version == 0)
            {
                var errorCode = Marshal.GetLastWin32Error();
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("Version Read Fail : ", Marshal.GetLastWin32Error()));

                if (errorCode == 2)
                {
                    OnEvent(EventErrorMessage, new WireGuardErrorEventArg("ERROR_FILE_NOT_FOUND : ", errorCode));
                    throw new Win32Exception(errorCode);
                }
            }
            
            NativeFunctions.getAdapterLUID(_handle, out luid.Value);

            if (!NativeFunctions.setAdapterLogging(_handle,WireGuardAdapterLoggerLevel.WIREGUARD_LOG_ON))
            {
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("Fail to set adapter logging : ", Marshal.GetLastWin32Error()));

            }
        }
        public int GetRunningDriverVersion()
        {

            return NativeFunctions.getRunningDriverVersion();
        }

        /*public void LoggerFunc()
        {
            OnEvent(EventInfoMessage, new WireGuardInfoEventArg(string.Format("ParseConfFile Ignore and Not append {0}:{1} \n line :{2}", key, value, lineNum)));
        }*/
        private void OnEvent<T>(EventHandler<T> handler, T args)
        {
            if (handler != null) handler(this, args);
        }
        public WireGuardAdapterState GetAdapterState()
        {
            NativeFunctions.getAdapterState(_handle, out WireGuardAdapterState wireGuardAdapterState);
            return wireGuardAdapterState;
        }

        public bool ParseConfFile(string[] lines, out WgConfig wgConfig )
        {
            //TODO: Resolve EndPoint, Set DNS
            //Dns.GetHostEntry(host).AddressList.First(addr => addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            //loctlWireGuardConfig _loctlWireGuardConfig = wgConfig.LoctlWireGuardConfig;
            wgConfig = new WgConfig();
            var IsInterFaceSection = false;
            var IsPeerSection = false;
            var peerCount = 0;
            var peerSize = 0;
            var lineNum = 0;
            
            foreach (var line in lines)
            {
                var lineLower = line.Trim().ToLower();
                if (lineLower == "[peer]")
                {
                    peerSize++;
                }
                if (lineLower.StartsWith("endpoint"))
                {
                    //TODO: support endpoints
                    //List<IPNetwork> allowedIps = new List<IPNetwork>();
                }
            }


            wgConfig.LoctlWireGuardConfig.WgPeerConfigs = new loctlWgPeerConfig[peerSize];

            foreach (var line in lines)
            {
                lineNum++;
                
                if (line.StartsWith("#"))
                {
                    continue; ;
                }
                var lineLower = line.Trim().ToLower();
                if (lineLower.Length == 0)
                {
                    continue;
                }
                
                if (lineLower == "[interface]")
                {
                    IsInterFaceSection = true;
                    IsPeerSection = false;
                    continue;
                }
                if (lineLower == "[peer]")
                {
                    IsPeerSection = true;
                    IsInterFaceSection = false;
                    peerCount++;
                    continue;
                }

                if (!IsPeerSection && !IsInterFaceSection)
                {
                    OnEvent(EventErrorMessage, new WireGuardErrorEventArg("ParseConfFile Error : No Section In conf File \n line :", lineNum));
                    
                }

                var confArray = line.Split('=').Select(s => s.Trim()).ToArray();

                if (confArray.Length < 1)
                {
                    
                    OnEvent(EventErrorMessage, new WireGuardErrorEventArg("ParseConfFile Error : No = Separator \n line :", lineNum));
                    continue;
                    //return false;
                }

                var key = confArray[0].ToLower();
                //etc join value
                var value = string.Join("=", confArray.Skip(1)).Trim();
                //Console.WriteLine("key " + key);
                //Console.WriteLine("value " + value);
                if (IsInterFaceSection)
                {
                    switch (key)
                    {
                        case "privatekey":
                            wgConfig.LoctlWireGuardConfig.Interfaze.Flags |= IoctlInterfaceFlags.HasPrivateKey;
                            var privateKey = Convert.FromBase64String(value);
                            fixed (byte* p = wgConfig.LoctlWireGuardConfig.Interfaze.PrivateKey)
                            {
                                Marshal.Copy(privateKey, 0, (IntPtr) p, 32);
                            }
                            continue;
                        case "listenport":
                            wgConfig.LoctlWireGuardConfig.Interfaze.Flags |= IoctlInterfaceFlags.HasListenPort;
                            wgConfig.InterfaceListenPort = Convert.ToUInt16(value);
                            wgConfig.LoctlWireGuardConfig.Interfaze.ListenPort = wgConfig.InterfaceListenPort;
                            continue;
                        case "mtu":
                            wgConfig.InterfaceMtu = Convert.ToUInt16(value);
                            continue;
                        case "address":
                            wgConfig.InterfaceNetwork = IPNetwork.Parse(value);
                            var ipStr = value.Split('/').First().Trim();
                            wgConfig.InterfaceAddress = IPAddress.Parse(ipStr);
                            continue;
                        case "dns":
                            wgConfig.DnsAddresses = value.Split(',').Select(dns => dns.Trim()).Select(dns => IPAddress.Parse(dns)).ToArray();
                            continue;
                        default:
                            OnEvent(EventInfoMessage, new WireGuardInfoEventArg(string.Format("ParseConfFile Ignore and Not append {0}:{1} \n line :{2}", key, value, lineNum)));
                            continue;
                    }

                }

                if (IsPeerSection)
                {
                    switch (key)
                    {
                        case "publickey":
                            wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Flags |= IoctlPeerFlags.HasPublicKey;
                            var publicKey = Convert.FromBase64String(value);
                            
                            fixed (byte* p = wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.PublicKey)
                            {
                                Marshal.Copy(publicKey, 0, (IntPtr)p, 32);
                            }
                            continue;
                        case "presharedkey":
                            wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Flags |= IoctlPeerFlags.HasPresharedKey;
                            var presharedKey = Convert.FromBase64String(value);
                            fixed (byte* p = wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.PresharedKey)
                            {
                                Marshal.Copy(presharedKey, 0, (IntPtr)p, 32);
                            }
                            continue;
                        case "allowedips":

                            var allowedIpTopStr = value.Split(',').First().Trim();
                            var allowTopIp = IPNetwork.Parse(allowedIpTopStr);
                            
                            if (allowTopIp.AddressFamily == AddressFamily.InterNetworkV6)
                            {
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].allowdIp.AddressFamily = Win32.ADDRESS_FAMILY.AF_INET6;
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].allowdIp.Cidr = allowTopIp.Cidr;

                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].allowdIp.V6.Addr = allowTopIp.Network;
                            }
                            else if (allowTopIp.AddressFamily == AddressFamily.InterNetwork)
                            {
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].allowdIp.AddressFamily = Win32.ADDRESS_FAMILY.AF_INET;
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].allowdIp.Cidr = allowTopIp.Cidr;
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].allowdIp.V4.Addr = allowTopIp.Network;
                            }

                            wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.AllowedIPsCount = 1;

                            continue;
                        case "persistentkeepalive":
                            wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.PersistentKeepalive = Convert.ToUInt16(value);
                            wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Flags |= IoctlPeerFlags.HasPersistentKeepalive;
                            continue;

                        case "endpoint":
                            var addrs = value.Split(':');
                            //check dns
                            IPEndPoint endPoint;
                            try
                            {
                                var ipEntry = Dns.GetHostEntry(addrs[0]);
                                endPoint = new IPEndPoint(ipEntry.AddressList[0], Convert.ToInt32(addrs[1]));
                            }
                            catch
                            {
                                endPoint = new IPEndPoint(IPAddress.Parse(addrs[0]), Convert.ToInt32(addrs[1]));
                            }
                            if (endPoint.AddressFamily == AddressFamily.InterNetworkV6)
                            {
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Endpoint.Ipv6.sin6_family = Win32.ADDRESS_FAMILY.AF_INET6;
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Endpoint.Ipv6.sin6_port = BitConverter.IsLittleEndian ? (ushort)BinaryPrimitives.ReverseEndianness((short)endPoint.Port) : (ushort)endPoint.Port;
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Endpoint.Ipv6.sin6_addr.Addr = endPoint.Address;
                                //Marshal.Copy(endPoint.Address.GetAddressBytes(), 0, (IntPtr)_loctlWgPeerConfig.client.Endpoint.Ipv6.sin6_addr.bytes, 16);
                            }
                            if (endPoint.AddressFamily == AddressFamily.InterNetwork)
                            {
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Endpoint.Ipv4.sin_family = Win32.ADDRESS_FAMILY.AF_INET;
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Endpoint.Ipv4.sin_port = BitConverter.IsLittleEndian ? (ushort)BinaryPrimitives.ReverseEndianness((short)endPoint.Port) : (ushort)endPoint.Port;
                                wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Endpoint.Ipv4.sin_addr.Addr = endPoint.Address;
                                
                            }
                            wgConfig.LoctlWireGuardConfig.WgPeerConfigs[peerCount - 1].client.Flags |= IoctlPeerFlags.HasEndpoint;
                            continue;

                        default:
                            OnEvent(EventInfoMessage, new WireGuardInfoEventArg(string.Format("ParseConfFile Ignore and Not append {0}:{1} \n line :{2}", key, value, lineNum)));
                            continue;
                    }
                }
                


            }

            if (IoctlInterfaceFlags.HasPrivateKey != (wgConfig.LoctlWireGuardConfig.Interfaze.Flags & IoctlInterfaceFlags.HasPrivateKey))
            {
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("Interface must have a private key", 0));
            }
            if (peerCount == 0)
            {
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("peerCount is zero", 0));
            }
            else
            {
                wgConfig.LoctlWireGuardConfig.Interfaze.PeersCount = (uint)peerCount;
            }
            for (var i = 0; i < wgConfig.LoctlWireGuardConfig.WgPeerConfigs.Length; i++)
            {
                if (IoctlPeerFlags.HasPublicKey != (wgConfig.LoctlWireGuardConfig.WgPeerConfigs[i].client.Flags & IoctlPeerFlags.HasPublicKey))
                {
                    OnEvent(EventErrorMessage, new WireGuardErrorEventArg("Peer must have a public key index: ", i));
                }

            }
            return true;
        }
        
        public void SetConfiguration(WgConfig wgConfig)
        {
            var _loctlWireGuardConfig = wgConfig.LoctlWireGuardConfig;

            var totalSize = 0;
            var byteCursor = 0;
            var interfaze = _loctlWireGuardConfig.Interfaze;
            var interfazeSize = Marshal.SizeOf(interfaze);
            

            totalSize += interfazeSize;
            for (var i = 0; i < _loctlWireGuardConfig.WgPeerConfigs.Length; i++)
            {
                var wgPeerConfig = _loctlWireGuardConfig.WgPeerConfigs[i];
                var configSize = Marshal.SizeOf(wgPeerConfig);
                totalSize += configSize;
            }
            

            wgConfig.ConfigBuffer = new ConfigBuffer(totalSize);

            IntPtr interfazePtr = Marshal.AllocHGlobal(interfazeSize);
            Marshal.StructureToPtr(interfaze, interfazePtr, true);
            Marshal.Copy(interfazePtr, wgConfig.ConfigBuffer.Buffer, 0, interfazeSize);
            Marshal.FreeHGlobal(interfazePtr);
            byteCursor += interfazeSize;

            for (var i = 0; i < _loctlWireGuardConfig.WgPeerConfigs.Length; i++)
            {
                var wgPeerConfig = _loctlWireGuardConfig.WgPeerConfigs[i];
                var configSize = Marshal.SizeOf(wgPeerConfig);
                IntPtr wgPeerConfigPtr = Marshal.AllocHGlobal(configSize);
                Marshal.StructureToPtr(wgPeerConfig, wgPeerConfigPtr, true);
                Marshal.Copy(wgPeerConfigPtr, wgConfig.ConfigBuffer.Buffer, byteCursor, configSize);
                Marshal.FreeHGlobal(wgPeerConfigPtr);
                byteCursor += configSize;

            }
            //Marshal.Copy((IntPtr)_loctlWireGuardConfig.Interfaze, 0, wgConfig.ConfigBuffer.BufferPointer,interfazeSize);
            var result = SetConfiguration(wgConfig.ConfigBuffer, totalSize);

            if (!result)
            {
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("SetConfiguration Fail : ", Marshal.GetLastWin32Error()));
            }
        }
        private bool SetConfiguration(ConfigBuffer wireGuardConfig, int totalSize)
        {
            

            var setConfigResult = NativeFunctions.setConfiguration(_handle, wireGuardConfig.BufferPointer, (uint)totalSize);
            if (!setConfigResult)
            {
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("SetConfiguration Fail : ", Marshal.GetLastWin32Error()));

            }

            return setConfigResult;
        }

        public bool SetStateUp()
        {
            var setStateResult = NativeFunctions.setAdapterState(_handle, WireGuardAdapterState.WIREGUARD_ADAPTER_STATE_UP);
            if (!setStateResult)
            {
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("SetAdapterStateResult Fail : ", Marshal.GetLastWin32Error()));
            }

            return setStateResult;
        }
        public bool SetStateDown()
        {
            var setStateResult = NativeFunctions.setAdapterState(_handle, WireGuardAdapterState.WIREGUARD_ADAPTER_STATE_DOWN);
            if (!setStateResult)
            {
                OnEvent(EventErrorMessage, new WireGuardErrorEventArg("SetAdapterStateResult Fail : ", Marshal.GetLastWin32Error()));
            }

            return setStateResult;
        }



        public unsafe WGInterface GetConfiguration()
        {
            var iface = new WGInterface();
            byte[] bytes;
            for (; ; )
            {
                bytes = new byte[_lastGetGuess];
                if (NativeFunctions.getConfiguration(_handle, bytes, ref _lastGetGuess))
                    break;
                if (Marshal.GetLastWin32Error() != 234 /* ERROR_MORE_DATA */)
                    throw new Win32Exception();
            }
            fixed (void* start = bytes)
            {
                var ioctlIface = (IoctlInterface*)start;
                if ((ioctlIface->Flags & IoctlInterfaceFlags.HasPublicKey) != 0)
                    iface.PublicKey = new Key(ioctlIface->PublicKey);
                if ((ioctlIface->Flags & IoctlInterfaceFlags.HasPrivateKey) != 0)
                    iface.PrivateKey = new Key(ioctlIface->PrivateKey);
                if ((ioctlIface->Flags & IoctlInterfaceFlags.HasListenPort) != 0)
                    iface.ListenPort = ioctlIface->ListenPort;
                var peers = new WGPeer[ioctlIface->PeersCount];
                var ioctlPeer = (IoctlPeer*)((byte*)ioctlIface + sizeof(IoctlInterface));
                for (uint i = 0; i < peers.Length; ++i)
                {
                    var peer = new WGPeer();
                    if ((ioctlPeer->Flags & IoctlPeerFlags.HasPublicKey) != 0)
                        peer.PublicKey = new Key(ioctlPeer->PublicKey);
                    if ((ioctlPeer->Flags & IoctlPeerFlags.HasPresharedKey) != 0)
                        peer.PresharedKey = new Key(ioctlPeer->PresharedKey);
                    if ((ioctlPeer->Flags & IoctlPeerFlags.HasPersistentKeepalive) != 0)
                        peer.PersistentKeepalive = ioctlPeer->PersistentKeepalive;
                    if ((ioctlPeer->Flags & IoctlPeerFlags.HasEndpoint) != 0)
                    {
                        if (ioctlPeer->Endpoint.si_family == Win32.ADDRESS_FAMILY.AF_INET)
                        {
                            peer.Endpoint = new IPEndPoint(ioctlPeer->Endpoint.Ipv4.sin_addr.Addr, (ushort)IPAddress.NetworkToHostOrder((short)ioctlPeer->Endpoint.Ipv4.sin_port));
                        }
                        else if (ioctlPeer->Endpoint.si_family == Win32.ADDRESS_FAMILY.AF_INET6)
                        {
                            //var ip = new byte[16];
                            //Marshal.Copy((IntPtr)ioctlPeer->Endpoint.Ipv6.sin6_addr.bytes, ip, 0, 16);
                            peer.Endpoint = new IPEndPoint(ioctlPeer->Endpoint.Ipv6.sin6_addr.Addr, (ushort)IPAddress.NetworkToHostOrder((short)ioctlPeer->Endpoint.Ipv6.sin6_port));
                        }
                    }
                    peer.TxBytes = ioctlPeer->TxBytes;
                    peer.RxBytes = ioctlPeer->RxBytes;
                    if (ioctlPeer->LastHandshake != 0)
                        peer.LastHandshake = DateTime.FromFileTimeUtc((long)ioctlPeer->LastHandshake);
                    var allowedIPs = new AllowedIP[ioctlPeer->AllowedIPsCount];
                    var ioctlAllowedIP = (IoctlAllowedIP*)((byte*)ioctlPeer + sizeof(IoctlPeer));
                    for (uint j = 0; j < allowedIPs.Length; ++j)
                    {
                        var allowedIP = new AllowedIP();
                        if (ioctlAllowedIP->AddressFamily == Win32.ADDRESS_FAMILY.AF_INET)
                        {
                            //Marshal.Copy((IntPtr)ioctlAllowedIP->V4.bytes, ip, 0, 4);
                            allowedIP.Address = ioctlAllowedIP->V4.Addr;
                        }
                        else if (ioctlAllowedIP->AddressFamily == Win32.ADDRESS_FAMILY.AF_INET6)
                        {
                           
                            //Marshal.Copy((IntPtr)ioctlAllowedIP->V6.bytes, ip, 0, 16);
                            allowedIP.Address = ioctlAllowedIP->V6.Addr;
                        }
                        allowedIP.Cidr = ioctlAllowedIP->Cidr;
                        allowedIPs[j] = allowedIP;
                        ioctlAllowedIP = (IoctlAllowedIP*)((byte*)ioctlAllowedIP + sizeof(IoctlAllowedIP));
                    }
                    peer.AllowedIPs = allowedIPs;
                    peers[i] = peer;
                    ioctlPeer = (IoctlPeer*)ioctlAllowedIP;
                }
                iface.Peers = peers;
            }
            return iface;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    NativeFunctions.freeAdapter(_handle);
                }

                _disposedValue = true;
            }
        }

        ~Adapter()
        {
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
