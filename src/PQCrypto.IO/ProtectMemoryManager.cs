namespace PQCrypto.IO;

using System.ComponentModel;
using System.Runtime.InteropServices;

public static class ProtectMemoryManager
{
    private static ProtectMemory? instance;

    private static int size = 8_388_608;
    private static readonly object synch = new();

    public static ProtectMemory Instance
    {
        get
        {
            if (instance is not null)
            {
                return instance;
            }
            else
            {
                lock (synch)
                {
                    WorkingSet();

                    if (instance is null)
                    {
                        instance = new ProtectMemory(size);
                    }

                    return instance;
                }
            }
        }
    }

    public static int Size
    {
        get => size;
        set { size = value; }
    }

    public static void ClearAllBuffers()
    {
        Instance.ClearAllBuffers();
    }

    public static (ulong Min, ulong Max) GetWorkingSet()
    {
        var handle = GetCurrentProcess();

        if (!GetProcessWorkingSetSize(
                handle,
                out var min,
                out var max))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return (min.ToUInt64(), max.ToUInt64());
    }

    public static MemorySafe Rent(Span<byte> buffer)
    {
        var memorySafe = Instance.Rent(buffer);

        return memorySafe;
    }

    public static MemorySafe Rent(int size)
    {
        var bytes = new byte[size];

        return Rent(bytes);
    }

    public static MemorySafe Rent(byte[] buffer)
    {
        return Rent(new Span<byte>(buffer));
    }

    public static void SetWorkingSet(ulong minBytes, ulong maxBytes)
    {
        var handle = GetCurrentProcess();

        if (!SetProcessWorkingSetSize(
                handle,
                (nuint)minBytes,
                (nuint)maxBytes))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessWorkingSetSize(
        nint hProcess,
        out nuint lpMinimumWorkingSetSize,
        out nuint lpMaximumWorkingSetSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessWorkingSetSize(
        nint hProcess,
        nuint dwMinimumWorkingSetSize,
        nuint dwMaximumWorkingSetSize);

    private static void WorkingSet()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) is false)
        {
            return;
        }

        SetWorkingSet(
            16UL * 1024 * 1024,
            32UL * 1024 * 1024);

        var (min, max) = GetWorkingSet();

        var intMin = Convert.ToInt32(min);

        if (intMin < size)
        {
            size = intMin;
        }
    }
}
