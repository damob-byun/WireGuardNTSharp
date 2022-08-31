using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WireGuardNT_PInvoke.WireGuard
{
    internal class NativeFunctions
    {
        [DllImport("wireguard.dll", EntryPoint = "WireGuardCreateAdapter", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern IntPtr createAdapter(
            [MarshalAs(UnmanagedType.LPWStr)] string name,
            [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
            out Guid guid
        );

        [DllImport("wireguard.dll", EntryPoint = "WireGuardOpenAdapter", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern IntPtr openAdapter([MarshalAs(UnmanagedType.LPWStr)] string name);
        [DllImport("wireguard.dll", EntryPoint = "WireGuardCloseAdapter", CallingConvention = CallingConvention.StdCall)]
        internal static extern void freeAdapter(IntPtr adapter);


        [DllImport("wireguard.dll", EntryPoint = "WireGuardGetAdapterLUID", CallingConvention = CallingConvention.StdCall)]
        internal static extern void getAdapterLUID(IntPtr adapter, out ulong luid);

        [DllImport("wireguard.dll", EntryPoint = "WireGuardGetConfiguration", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern bool getConfiguration(IntPtr adapter, byte[] iface, ref UInt32 bytes);

        [DllImport("wireguard.dll", EntryPoint = "WireGuardSetConfiguration", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern bool setConfiguration(IntPtr adapter, IntPtr wireGuardConfig, UInt32 bytes);

        [DllImport("wireguard.dll", EntryPoint = "WireGuardSetAdapterState", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern bool setAdapterState(IntPtr adapter, WireGuardAdapterState wireGuardAdapterState);

        [DllImport("wireguard.dll", EntryPoint = "WireGuardGetAdapterState", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern bool getAdapterState(IntPtr adapter, out WireGuardAdapterState wireGuardAdapterState);


        [DllImport("wireguard.dll", CharSet = CharSet.Auto, EntryPoint = "WireGuardGetRunningDriverVersion", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern int getRunningDriverVersion();
        
        [DllImport("wireguard.dll", CharSet = CharSet.Auto, EntryPoint = "WireGuardSetAdapterLogging", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern bool setAdapterLogging(IntPtr adapter, WireGuardAdapterLoggerLevel loggingLevel);
    }
}
