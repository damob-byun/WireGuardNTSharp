using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace WireGuardNT_PInvoke.WireGuard
{
    public class WireGuardErrorEventArg : EventArgs
    {
        public WireGuardErrorEventArg(string message, int win32ErrorNum)
        {
            this.Message = message;
            this.Win32ErrorNum = win32ErrorNum;
        }

        public string Message { get; }
        public int Win32ErrorNum { get; }
    }
    public class WireGuardInfoEventArg : EventArgs
    {
        public WireGuardInfoEventArg(string message)
        {
            this.Message = message;
        }

        public string Message { get; }
    }
}
