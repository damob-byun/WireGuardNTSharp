using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WireGuardNT_PInvoke.WireGuard
{
    public class ConfigBuffer : IDisposable
    {
        private byte[] _buffer;
        internal IntPtr BufferPointer;
        private GCHandle _bufferHandle;
        private bool _disposedValue;
        
        public ConfigBuffer()
          : this(65536)
        {
        }

        public ConfigBuffer(byte[] bufferData)
        {
            this._buffer = bufferData;
            this._bufferHandle = GCHandle.Alloc((object)this._buffer, GCHandleType.Pinned);
            this.BufferPointer = this._bufferHandle.AddrOfPinnedObject();
        }
        
        public ConfigBuffer(int bufferSize)
        {
            this._buffer = new byte[bufferSize];
            this._bufferHandle = GCHandle.Alloc((object)this._buffer, GCHandleType.Pinned);
            this.BufferPointer = this._bufferHandle.AddrOfPinnedObject();
        }
        public byte this[int index]
        {
            get => this._buffer[index];
            set => this._buffer[index] = value;
        }

       
        public byte this[uint index]
        {
            get => this._buffer[(int)index];
            set => this._buffer[(int)index] = value;
        }

        
        public uint Length => (uint)this._buffer.Length;

        public byte[] Buffer => this._buffer;

        protected virtual void Dispose(bool disposing)
        {
            if (this._disposedValue)
                return;
            if (disposing && this._buffer != null)
            {
                this._bufferHandle.Free();
                this.BufferPointer = IntPtr.Zero;
                Array.Clear((Array)this._buffer, 0, this._buffer.Length);
                this._buffer = (byte[])null;
            }
            this._disposedValue = true;
        }
        
        public void Dispose() => this.Dispose(true);
    }
}
