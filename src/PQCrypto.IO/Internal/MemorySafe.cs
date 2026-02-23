namespace PQCrypto.IO.Internal;

public sealed unsafe class MemorySafe : IDisposable
{
    private bool disposed;
    private bool isLocked;
    private int length;
    private ProtectMemory owner;
    internal IntPtr ptr;
    private object synch = new();

    public int Length
    {
        get
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException(nameof(MemorySafe));
            }

            return this.length;
        }
    }

    public IntPtr Pointer
    {
        get
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException(nameof(MemorySafe));
            }

            if (this.isLocked is false)
            {
                throw new InvalidOperationException("The correct usage is Lock() or LockWait() try { call Pointer;} finally { Unlock(); }");
            }

            return this.ptr;
        }
    }

    internal MemorySafe(IntPtr ptr, int length, ProtectMemory owner)
    {
        this.ptr = ptr;
        this.length = length;
        this.owner = owner;
    }

    public void Dispose()
    {
        if (this.disposed)
        {
            return;
        }

        this.disposed = true;
        this.Unlock();
        this.owner?.Free(this);
        this.ptr = IntPtr.Zero;
        this.length = 0;
        this.owner = null;
    }

    public IDisposable Acquire()
    {
        this.LockWait();

        return new Releaser(this);
    }

    public Span<byte> AsSpan()
    {
        if (this.disposed)
        {
            throw new ObjectDisposedException(nameof(MemorySafe));
        }

        if (this.isLocked is false)
        {
            throw new InvalidOperationException("The correct usage is Lock() or LockWait() try { call AsSpan();} finally { Unlock(); }");
        }

        return new Span<byte>((void*)this.ptr, this.length);
    }

    public bool Lock()
    {
        lock (this.synch)
        {
            if (this.isLocked)
            {
                return false;
            }

            this.isLocked = true;

            return true;
        }
    }

    public void LockWait()
    {
        Monitor.Enter(this.synch);

        try
        {
            while (this.isLocked)
                Monitor.Wait(this.synch);

            this.isLocked = true;
        }
        finally
        {
            Monitor.Exit(this.synch);
        }
    }

    public void Unlock()
    {
        lock (this.synch)
        {
            this.isLocked = false;
            Monitor.PulseAll(this.synch);
        }
    }

    private sealed class Releaser : IDisposable
    {
        private MemorySafe owner;

        public Releaser(MemorySafe owner)
        {
            this.owner = owner;
        }

        public void Dispose()
        {
            this.owner?.Unlock();
            this.owner = null;
        }
    }
}
