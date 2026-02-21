namespace PQCrypto.IO;

using System.Runtime.InteropServices;
using PQCrypto.IO.Extensions;

public abstract record class AMemoryLocked : IDisposable
{
    private bool disposed = false;
    private GCHandle? handle = null;
    private byte[]? value = null;

    public byte[] Value
    {
        get => this.value;
        set
        {
            if (this.value is not null)
            {
                throw new ArgumentException("Value reassignment not permitted");
            }

            this.value = value;
            this.handle = value.LockInRam();
        }
    }

    protected AMemoryLocked()
    {
    }

    protected AMemoryLocked(AMemoryLocked original)
    {
        throw new NotSupportedException($"{nameof(AMemoryLocked)} contains unmanaged memory locks and cannot be copied using 'with'.");
    }

    public void Dispose()
    {
        if (this.disposed is false && this.value is not null)
        {
            Array.Clear(this.value, index: 0, this.value.Length);

            this.value.UnlockFromRam(this.handle);
            this.handle = null;
        }

        this.disposed = true;
        GC.SuppressFinalize(this);
    }

    ~AMemoryLocked()
    {
        this.Dispose();
    }
}
