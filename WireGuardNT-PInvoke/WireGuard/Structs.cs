using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WireGuardNT_PInvoke.WireGuard
{
    public class Key
    {
        private byte[] _bytes;
        public byte[] Bytes
        {
            get
            {
                return _bytes;
            }
            set
            {
                if (value == null || value.Length != 32)
                    throw new ArgumentException("Keys must be 32 bytes");
                _bytes = value;
            }
        }
        public Key(byte[] bytes)
        {
            Bytes = bytes;
        }
        public unsafe Key(byte* bytes)
        {
            _bytes = new byte[32];
            Marshal.Copy((IntPtr)bytes, _bytes, 0, 32);
        }
        public override String ToString()
        {
            return Convert.ToBase64String(_bytes);
        }
    }

    public class WGInterface
    {
        public UInt16 ListenPort { get; set; }
        public Key PrivateKey { get; set; }
        public Key PublicKey { get; set; }
        public WGPeer[] Peers { get; set; }
    }
    
    public class WGPeer
    {
        public Key PublicKey { get; set; }
        public Key PresharedKey { get; set; }
        public UInt16 PersistentKeepalive { get; set; }
        public IPEndPoint Endpoint { get; set; }
        public UInt64 TxBytes { get; set; }
        public UInt64 RxBytes { get; set; }
        public DateTime LastHandshake { get; set; }
        public AllowedIP[] AllowedIPs { get; set; }
    }

    public class AllowedIP
    {
        public IPAddress Address { get; set; }
        public byte Cidr { get; set; }
    }

    public enum IoctlInterfaceFlags : UInt32
    {
        Default = 0,
        HasPublicKey = 1 << 0,
        HasPrivateKey = 1 << 1,
        HasListenPort = 1 << 2,
        ReplacePeers = 1 << 3
    };

    [StructLayout(LayoutKind.Sequential, Pack = 8, Size = 80)]
    public unsafe struct IoctlInterface
    {
        public IoctlInterfaceFlags Flags;
        public UInt16 ListenPort;
        public fixed byte PrivateKey[32];
        public fixed byte PublicKey[32];
        public UInt32 PeersCount;
        
    }
    public enum IoctlPeerFlags : UInt32
    {
        Default = 0,
        HasPublicKey = 1 << 0,
        HasPresharedKey = 1 << 1,
        HasPersistentKeepalive = 1 << 2,
        HasEndpoint = 1 << 3,
        ReplaceAllowedIPs = 1 << 5,
        Remove = 1 << 6,
        UpdateOnly = 1 << 7
    };

    [StructLayout(LayoutKind.Sequential, Pack = 8, Size = 136)]
    public unsafe struct IoctlPeer
    {
        public IoctlPeerFlags Flags;
        public UInt32 Reserved;

        public fixed byte PublicKey[32];
        public fixed byte PresharedKey[32];
        public UInt16 PersistentKeepalive;
        public Win32.SOCKADDR_INET Endpoint;
        public UInt64 TxBytes, RxBytes;
        public UInt64 LastHandshake;
        public UInt32 AllowedIPsCount;
    };

    [StructLayout(LayoutKind.Explicit, Pack = 8, Size = 24)]
    public unsafe struct IoctlAllowedIP
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.Struct)]
        public Win32.IN_ADDR V4;
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.Struct)]
        public Win32.IN6_ADDR V6;
        [FieldOffset(16)]
        public Win32.ADDRESS_FAMILY AddressFamily;
        [FieldOffset(20)]
        public byte Cidr;
    }
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct loctlWireGuardConfig
    {
        public IoctlInterface Interfaze;
        public loctlWgPeerConfig[] WgPeerConfigs;
    }
    [StructLayout(LayoutKind.Sequential, Pack = 8, Size = 160)]
    public unsafe struct loctlWgPeerConfig
    {
        public IoctlPeer client;
        public IoctlAllowedIP allowdIp;
    }

    public enum WireGuardAdapterState : UInt32
    {
        WIREGUARD_ADAPTER_STATE_DOWN,
        WIREGUARD_ADAPTER_STATE_UP,
    };

    public enum WireGuardLoggerLevel : UInt32
    {
        WIREGUARD_LOG_INFO,
        WIREGUARD_LOG_WARN,
        WIREGUARD_WIREGUARD_LOG_ERRLOG_WARN,
    };
    public enum WireGuardAdapterLoggerLevel : UInt32
    {
        WIREGUARD_LOG_OFF,
        WIREGUARD_LOG_ON,
        WIREGUARD_LOG_ON_PREFIX,
    };


}
