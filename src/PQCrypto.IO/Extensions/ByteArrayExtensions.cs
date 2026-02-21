namespace PQCrypto.IO.Extensions;

using System.Diagnostics;
using System.Runtime.InteropServices;
using PQCrypto.IO.Internal;

internal static class ByteArrayExtensions
{
    [StackTraceHidden]
    public static void RequireExactLength(this byte[] value, string field, int expectedLength)
    {
        if (value.Length == expectedLength)
        {
            return;
        }

        throw new WrongByteArrayLengthException(field, expectedLength);
    }

    #region locking and unlocking for byte arrays

    public static GCHandle? LockInRam(this byte[] data)
    {
        var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        var addr = handle.AddrOfPinnedObject();
        var size = (UIntPtr)data.Length;

        var success = false;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            success = VirtualLock(addr, size);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            success = mlock(addr, size) == 0;
        }
        else
        {
            return null;
        }

        if (!success)
        {
            handle.Free();

            return null;

            //throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to lock memory in RAM.");
        }

        return handle;
    }

    public static void UnlockFromRam(this byte[] data, GCHandle? handle)
    {
        if (handle == null)
        {
            return;
        }

        if (!handle.Value.IsAllocated)
        {
            return;
        }

        var addr = handle.Value.AddrOfPinnedObject();
        var size = (UIntPtr)data.Length;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            VirtualUnlock(addr, size);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            munlock(addr, size);
        }

        handle.Value.Free();
    }

    #endregion

    #region native methods for memory locking

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);

    [DllImport("libc", SetLastError = true)]
    private static extern int mlock(IntPtr addr, UIntPtr len);

    [DllImport("libc", SetLastError = true)]
    private static extern int munlock(IntPtr addr, UIntPtr len);

    #endregion
}
